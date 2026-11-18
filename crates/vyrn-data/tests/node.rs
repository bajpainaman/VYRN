//! A data box end to end over vyrn-nic's `sim` backend: client copies in, `DATA` frames out to
//! every destination, heartbeats, dedupe, copy conflicts, and the three fetches, the BLOCK and
//! KEY ones read from a `MemStore` through `BlockStore`.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use core::net::{Ipv4Addr, SocketAddrV4};
use std::collections::BTreeMap;

use vyrn_data::frame::{self, Fetch, Kind, RedirectBatch, key_seq};
use vyrn_data::redirect::Redirect;
use vyrn_data::{DataNode, Event, HomeConfig, Mode, NodeConfig};
use vyrn_log::block::{order_root, sign_header};
use vyrn_log::{Block, BlockKind, BlockStore, MemStore};
use vyrn_nic::frame::{Endpoint, FrameHdr, build, parse};
use vyrn_nic::sim::{SimRx, SimTx};
use vyrn_nic::{BackendKind, NicBackend, NicConfig, PortConfig, PortId, RxBind, SimNic, TxClass};
use vyrn_types::{
    BlockHeader, BookId, Epoch, Hash, Height, LaneId, MAX_REQ_PAYLOAD, Nanos, SessionId, StepId,
};
use vyrn_wire::{Msg, RX_BURST, ReqHeader, RxPkt, RxRing, encode_request};

const K: [u8; 16] = [7; 16];
const BOOK: BookId = BookId(3);

fn ep(last: u8, port: u16) -> Endpoint {
    Endpoint {
        mac: [2, 0, 0, 0, 0, last],
        ip: Ipv4Addr::new(10, 0, 0, last),
        port,
    }
}

fn req(session: u32, pkt_seq: u32, msgs: &[Msg], key: &[u8; 16]) -> Vec<u8> {
    let mut out = [0u8; MAX_REQ_PAYLOAD];
    let h = ReqHeader::new(SessionId(session), pkt_seq, 9, BOOK, false);
    let n = encode_request(&mut out, h, msgs, key, None).unwrap();
    out[..n].to_vec()
}

fn wire(src: Endpoint, dst: Endpoint, payload: &[u8]) -> Vec<u8> {
    let mut b = [0u8; 1514];
    let n = build(&FrameHdr { src, dst }, payload, &mut b).unwrap();
    b[..n].to_vec()
}

fn addr(e: Endpoint) -> SocketAddrV4 {
    SocketAddrV4::new(e.ip, e.port)
}

struct Rig {
    nic: SimNic,
    node: DataNode<SimRx, SimRx, SimTx, MemStore>,
    replicas: Vec<SimRx>,
    me_ingest: Endpoint,
    me_fetch: Endpoint,
    client: Endpoint,
}

fn rig(store: MemStore) -> Rig {
    rig_with(store, |_| {})
}

fn rig_with(store: MemStore, tweak: impl FnOnce(&mut NodeConfig)) -> Rig {
    let mut ports = vec![];
    for i in 0..6u8 {
        ports.push(PortConfig {
            id: PortId(i),
            ip: Ipv4Addr::new(10, 0, 0, i + 1),
        });
    }
    let mut nic = SimNic::open(&NicConfig::new(BackendKind::Sim, ports)).unwrap();
    let bind = |e: Endpoint, port: u8| RxBind {
        lane: LaneId(0),
        port: PortId(port),
        ip: e.ip,
        udp_port: e.port,
    };
    let me_ingest = ep(1, 19998);
    let me_fetch = ep(1, 19997);
    let dests = vec![ep(2, 20000), ep(3, 20000)];
    let ingest = nic.rx_ring(&bind(me_ingest, 0)).unwrap();
    let fetch = nic.rx_ring(&bind(me_fetch, 0)).unwrap();
    let replicas = dests
        .iter()
        .enumerate()
        .map(|(i, &d)| nic.rx_ring(&bind(d, i as u8 + 1)).unwrap())
        .collect();
    let tx = nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
    let home = HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys: BTreeMap::from([(SessionId(5), K), (SessionId(6), K)]),
        ring_slots: 64,
        index_key: [0x42; 16],
    };
    let mut cfg = NodeConfig::new(home, 1, me_ingest, dests);
    tweak(&mut cfg);
    let node = DataNode::new(cfg, ingest, fetch, tx, store);
    Rig {
        nic,
        node,
        replicas,
        me_ingest,
        me_fetch,
        client: ep(9, 4000),
    }
}

impl Rig {
    fn send(&self, payload: &[u8], ts: u64) {
        let f = wire(self.client, self.me_ingest, payload);
        assert!(self.nic.inject(addr(self.me_ingest), &f, Nanos(ts)));
    }

    fn fetch(&self, q: Fetch) {
        let f = wire(self.client, self.me_fetch, &q.encode());
        assert!(self.nic.inject(addr(self.me_fetch), &f, Nanos(0)));
    }

    /// Every UDP payload waiting at replica `i`.
    fn drain(&mut self, i: usize) -> Vec<Vec<u8>> {
        let rx = &mut self.replicas[i];
        let mut out = vec![];
        let mut burst = [RxPkt::empty(); RX_BURST];
        loop {
            let n = rx.poll(&mut burst);
            if n == 0 {
                return out;
            }
            for p in &burst[..n] {
                out.push(parse(rx.bytes(p)).unwrap().payload.to_vec());
            }
            rx.release(n);
        }
    }
}

#[test]
fn ingest_fans_out_dedupes_and_heartbeats() {
    let mut r = rig(MemStore::default());
    let p1 = req(5, 1, &[Msg::Heartbeat], &K);
    let p2 = req(5, 2, &[Msg::Heartbeat, Msg::Heartbeat], &K);
    let p3 = req(6, 1, &[Msg::Heartbeat], &K);
    for p in [&p1, &p2, &p1, &p3] {
        r.send(p, 100);
    }
    // Wrong key: dropped and reported. Unknown session: dropped.
    r.send(&req(5, 3, &[Msg::Heartbeat], &[1; 16]), 100);
    r.send(&req(99, 1, &[Msg::Heartbeat], &K), 100);
    r.node.poll(Nanos(1_000));
    // Younger than REP_DATA_BATCH_US: nothing on the wire yet.
    assert!(r.drain(0).is_empty());
    r.node.poll(Nanos(6_000));
    for i in 0..2 {
        let frames = r.drain(i);
        assert_eq!(frames.len(), 1, "one DATA frame per destination");
        let d = frame::decode(&frames[0]).unwrap();
        assert_eq!(
            (
                d.hdr.kind,
                d.hdr.book,
                d.hdr.epoch16,
                d.hdr.data_seq,
                d.hdr.src
            ),
            (Kind::Data, BOOK, 9, 1, 1)
        );
        let pkts: Vec<&[u8]> = d.packets().collect();
        assert_eq!(
            pkts,
            vec![&p1[..], &p2[..], &p3[..]],
            "store order, no duplicate"
        );
    }
    let c = *r.node.counters();
    assert_eq!(
        (c.stored, c.duplicate, c.bad_mac, c.unknown_session),
        (3, 1, 1, 1)
    );
    let ev: Vec<Event> = r.node.drain_events().collect();
    assert_eq!(
        ev,
        vec![Event::BadMac {
            session: SessionId(5),
            pkt_seq: 3
        }]
    );
    // Idle for hb_ns: a heartbeat naming the last DATA frame.
    r.node.poll(Nanos(6_000 + 100_000));
    let hb = r.drain(1);
    assert_eq!(hb.len(), 1);
    let h = frame::decode(&hb[0]).unwrap();
    assert_eq!((h.hdr.kind, h.hdr.data_seq, h.n_pkts), (Kind::DataHb, 1, 0));
}

#[test]
fn a_conflicting_copy_is_evidence_and_never_forwarded() {
    let mut r = rig(MemStore::default());
    let a = req(5, 1, &[Msg::Heartbeat], &K);
    let b = req(5, 1, &[Msg::Heartbeat, Msg::Heartbeat], &K);
    r.send(&a, 0);
    r.send(&b, 0);
    r.node.poll(Nanos(0));
    r.node.flush(Nanos(0));
    let d = r.drain(0);
    let f = frame::decode(&d[0]).unwrap();
    assert_eq!(f.packets().collect::<Vec<_>>(), vec![&a[..]]);
    let ev: Vec<Event> = r.node.drain_events().collect();
    match ev[..] {
        [
            Event::CopyConflict {
                session,
                pkt_seq,
                h1,
                h2,
                first,
                second,
            },
        ] => {
            assert_eq!((session, pkt_seq), (SessionId(5), 1));
            assert_eq!(h1, vyrn_crypto::hash::hash(&a[..a.len() - 16]));
            assert_eq!(h2, vyrn_crypto::hash::hash(&b[..b.len() - 16]));
            assert_eq!((first.bytes(), second.bytes()), (&a[..], &b[..]));
        }
        _ => panic!("{ev:?}"),
    }
    // The fetch serves the first copy.
    r.fetch(Fetch::Key {
        session: SessionId(5),
        pkt_seq: 1,
    });
    r.node.poll(Nanos(1));
    assert_eq!(r.node.counters().fetch_ring_hit, 1);
}

/// A logged block whose data region holds `pkts`.
fn store_with(pkts: &[Vec<u8>]) -> MemStore {
    let header = BlockHeader {
        height: Height(4),
        epoch: Epoch(1),
        book: BOOK,
        first_step: StepId(1),
        last_step: StepId(1),
        prev: Hash([0; 32]),
        order_root: order_root(&[], &[]),
        data_root: Hash([0; 32]),
        seq_sig: [0; 64],
    };
    let mut s = MemStore::default();
    s.put(&Block {
        header: sign_header(&header, &[1; 32]),
        tenure: 0,
        kind: BlockKind::Normal,
        order_a: vec![],
        order_b: vec![],
        pkt_hashes: vec![],
        data: pkts.concat(),
        unavailable: vec![],
    })
    .unwrap();
    s
}

/// The client's fetch replies come back to its address, which no queue is bound to in the
/// rig, so the test binds one.
fn client_rx(r: &mut Rig) -> SimRx {
    r.nic
        .rx_ring(&RxBind {
            lane: LaneId(0),
            port: PortId(5),
            ip: r.client.ip,
            udp_port: r.client.port,
        })
        .unwrap()
}

fn drain_rx(rx: &mut SimRx) -> Vec<Vec<u8>> {
    let mut out = vec![];
    let mut burst = [RxPkt::empty(); RX_BURST];
    loop {
        let n = rx.poll(&mut burst);
        if n == 0 {
            return out;
        }
        for p in &burst[..n] {
            out.push(parse(rx.bytes(p)).unwrap().payload.to_vec());
        }
        rx.release(n);
    }
}

#[test]
fn fetches_serve_ring_log_and_resends() {
    let old = vec![
        req(6, 40, &[Msg::Heartbeat], &K),
        req(6, 41, &[Msg::Heartbeat, Msg::Heartbeat, Msg::Heartbeat], &K),
    ];
    let mut r = rig(store_with(&old));
    let mut c = client_rx(&mut r);
    let p1 = req(5, 1, &[Msg::Heartbeat], &K);
    r.send(&p1, 0);
    r.node.poll(Nanos(0));
    r.node.flush(Nanos(0));
    let first = r.drain(0);

    // KEY from the ring, KEY from the log, KEY missing.
    for (s, q) in [(5, 1), (6, 41), (6, 99)] {
        r.fetch(Fetch::Key {
            session: SessionId(s),
            pkt_seq: q,
        });
    }
    // BLOCK 4 and a block that is not stored.
    r.fetch(Fetch::Block { height: Height(4) });
    r.fetch(Fetch::Block { height: Height(9) });
    // RANGE: DATA frame 1 to destination 0, resent byte for byte to it.
    r.fetch(Fetch::Range {
        dst: 0,
        from: 1,
        to: 1,
    });
    // Malformed.
    let bad = wire(r.client, r.me_fetch, &[0u8; 31]);
    assert!(r.nic.inject(addr(r.me_fetch), &bad, Nanos(0)));
    r.node.poll(Nanos(1));

    let got = drain_rx(&mut c);
    let dec: Vec<_> = got.iter().map(|g| frame::decode(g).unwrap()).collect();
    let summary: Vec<(Kind, u64, Vec<&[u8]>)> = dec
        .iter()
        .map(|d| (d.hdr.kind, d.hdr.data_seq, d.packets().collect()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (Kind::FetchResp, key_seq(SessionId(5), 1), vec![&p1[..]]),
            (
                Kind::FetchResp,
                key_seq(SessionId(6), 41),
                vec![&old[1][..]]
            ),
            (Kind::FetchResp, key_seq(SessionId(6), 99), vec![]),
            (Kind::FetchResp, 4, vec![&old[0][..], &old[1][..]]),
            (Kind::FetchResp, 9, vec![]),
        ]
    );
    assert_eq!(r.drain(0), first, "RANGE resends the stored frame");
    let k = *r.node.counters();
    assert_eq!(
        (
            k.fetch_ring_hit,
            k.fetch_log_hit,
            k.fetch_miss,
            k.fetch_resent,
            k.fetch_bad
        ),
        (1, 2, 2, 1, 1)
    );
}

#[test]
fn kernel_udp_loopback_serves_a_replica() {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};
    use vyrn_nic::KernelUdp;

    let cfg = NicConfig::new(
        BackendKind::Kernel,
        vec![PortConfig {
            id: PortId(0),
            ip: Ipv4Addr::LOCALHOST,
        }],
    );
    let mut nic = KernelUdp::open(&cfg).unwrap();
    let bind = RxBind {
        lane: LaneId(0),
        port: PortId(0),
        ip: Ipv4Addr::LOCALHOST,
        udp_port: 0,
    };
    let ingest = nic.rx_ring(&bind).unwrap();
    let fetch = nic.rx_ring(&bind).unwrap();
    let tx = nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let std::net::SocketAddr::V4(raddr) = replica.local_addr().unwrap() else {
        unreachable!()
    };
    let lo = |a: SocketAddrV4| Endpoint {
        mac: [0; 6],
        ip: *a.ip(),
        port: a.port(),
    };
    let (in_addr, fetch_addr) = (ingest.local_addr(), fetch.local_addr());
    let home = HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys: BTreeMap::from([(SessionId(5), K)]),
        ring_slots: 8,
        index_key: [0x42; 16],
    };
    let mut node = DataNode::new(
        NodeConfig::new(home, 0, lo(in_addr), vec![lo(raddr)]),
        ingest,
        fetch,
        tx,
        MemStore::default(),
    );
    let p = req(5, 1, &[Msg::Heartbeat], &K);
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(&p, in_addr).unwrap();
    let t = Instant::now();
    while node.counters().stored == 0 {
        node.poll(Nanos(0));
        assert!(t.elapsed() < Duration::from_secs(5), "nothing ingested");
        std::thread::yield_now();
    }
    node.flush(Nanos(0));
    let mut buf = [0u8; 2048];
    let n = replica.recv(&mut buf).unwrap();
    let d = frame::decode(&buf[..n]).unwrap();
    assert_eq!(d.packets().collect::<Vec<_>>(), vec![&p[..]]);
    // A KEY fetch from the replica's socket is answered at its address.
    let q = Fetch::Key {
        session: SessionId(5),
        pkt_seq: 1,
    };
    replica.send_to(&q.encode(), fetch_addr).unwrap();
    let t = Instant::now();
    while node.counters().fetch_ring_hit == 0 {
        node.poll(Nanos(1));
        assert!(t.elapsed() < Duration::from_secs(5), "no fetch");
        std::thread::yield_now();
    }
    let n = replica.recv(&mut buf).unwrap();
    let d = frame::decode(&buf[..n]).unwrap();
    assert_eq!(d.hdr.kind, Kind::FetchResp);
    assert_eq!(d.packets().collect::<Vec<_>>(), vec![&p[..]]);
}

/// 04 D3: a resend may change `flags` bit 0 and `epoch16` (and so the tags and the full hash)
/// without changing the logical content. It is not equivocation, and because the sequencer may
/// accept its exact bytes, it is stored and forwarded as a second variant; an identical copy of
/// it is a duplicate, and a KEY fetch returns both variants.
#[test]
fn a_resend_with_new_flags_and_epoch_is_a_forwarded_variant() {
    let mut r = rig(MemStore::default());
    let mut c = client_rx(&mut r);
    let a = req(5, 1, &[Msg::Heartbeat], &K);
    let mut out = [0u8; MAX_REQ_PAYLOAD];
    let h = ReqHeader::new(SessionId(5), 1, 10, BOOK, true);
    let n = encode_request(&mut out, h, &[Msg::Heartbeat], &K, None).unwrap();
    let resend = out[..n].to_vec();
    assert_ne!(
        vyrn_crypto::hash::hash(&a[..32]),
        vyrn_crypto::hash::hash(&resend[..32])
    );
    r.send(&a, 0);
    r.send(&resend, 0);
    r.send(&resend, 0);
    r.node.poll(Nanos(0));
    r.node.flush(Nanos(0));
    let k = *r.node.counters();
    assert_eq!((k.stored, k.duplicate, k.conflicts), (2, 1, 0));
    assert_eq!(r.node.drain_events().count(), 0);
    // epoch16 differs, so each variant goes out in its own DATA frame, in arrival order.
    let frames: Vec<Vec<u8>> = r.drain(0);
    let pkts: Vec<Vec<u8>> = frames
        .iter()
        .flat_map(|f| {
            frame::decode(f)
                .unwrap()
                .packets()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(pkts, vec![a.clone(), resend.clone()]);
    r.fetch(Fetch::Key {
        session: SessionId(5),
        pkt_seq: 1,
    });
    r.node.poll(Nanos(1));
    let got = drain_rx(&mut c);
    let d = frame::decode(&got[0]).unwrap();
    let mut v: Vec<&[u8]> = d.packets().collect();
    v.sort();
    let mut want = vec![&a[..], &resend[..]];
    want.sort();
    assert_eq!(v, want);
}

/// A keyed node serves only sealed fetches from keyed sources, and each source within its own
/// rate: a forged tag, a plain fetch and a stranger are refused before any bucket is charged.
#[test]
fn authenticated_fetches_and_the_per_source_rate_limit() {
    const KF: [u8; 16] = [0x33; 16];
    let stranger = ep(8, 4000);
    let mut r = rig_with(MemStore::default(), |c| {
        c.fetch_keys = BTreeMap::from([(ep(9, 4000).ip, KF)]);
        (c.fetch_rate, c.fetch_burst) = (1_000, 2);
    });
    let mut c = client_rx(&mut r);
    let q = Fetch::Key {
        session: SessionId(5),
        pkt_seq: 1,
    };
    let inject = |r: &Rig, from: Endpoint, b: &[u8], ts: u64| {
        let f = wire(from, r.me_fetch, b);
        assert!(r.nic.inject(addr(r.me_fetch), &f, Nanos(ts)));
    };
    let mut forged = q.seal(&KF);
    forged[39] ^= 1;
    inject(&r, r.client, &forged, 0);
    inject(&r, r.client, &q.encode(), 0);
    inject(&r, stranger, &q.seal(&KF), 0);
    // Burst 2: two pass, the third is limited.
    for _ in 0..3 {
        inject(&r, r.client, &q.seal(&KF), 0);
    }
    r.node.poll(Nanos(0));
    let k = *r.node.counters();
    assert_eq!(
        (k.fetch_unauth, k.fetch_bad, k.fetch_limited, k.fetch_miss),
        (2, 1, 1, 2)
    );
    assert_eq!(drain_rx(&mut c).len(), 2);
    // 1,000/s: one token back after 1 ms, not before.
    inject(&r, r.client, &q.seal(&KF), 0);
    r.node.poll(Nanos(999_999));
    inject(&r, r.client, &q.seal(&KF), 0);
    r.node.poll(Nanos(1_000_000));
    let k = *r.node.counters();
    assert_eq!((k.fetch_limited, k.fetch_miss), (2, 3));
}

/// 07 §5.7 step 3: a redirect goes to the address of the session's newest new copy, tagged
/// under its key. A replay of those bytes from another address does not move it, and a session
/// the box never heard from is counted, not sent.
#[test]
fn redirects_go_to_the_sessions_address_and_replays_do_not_move_it() {
    let mut r = rig(MemStore::default());
    let mut c = client_rx(&mut r);
    let p1 = req(5, 1, &[Msg::Heartbeat], &K);
    r.send(&p1, 0);
    // The same bytes replayed from another address: a duplicate, so the address stays.
    let f = wire(ep(8, 4000), r.me_ingest, &p1);
    assert!(r.nic.inject(addr(r.me_ingest), &f, Nanos(0)));
    r.node.poll(Nanos(0));
    assert_eq!(r.node.counters().duplicate, 1);
    r.node
        .redirect(1, 3, &[(SessionId(5), 1), (SessionId(6), 1)]);
    let got = drain_rx(&mut c);
    assert_eq!(got.len(), 1, "one redirect, to the client's address");
    assert_eq!(
        Redirect::open(&got[0], &K).unwrap(),
        Redirect {
            down: 1,
            to: 3,
            session: SessionId(5),
            resend_from: 1
        }
    );
    let k = *r.node.counters();
    assert_eq!((k.redirects, k.redirect_unknown), (1, 1));

    // The same redirect from a replica's REDIRECT fetch (07 §5.7 step 3, reading): sent to the
    // client's address under the session's key; one for an unknown session is only counted.
    r.fetch(Fetch::Redirect {
        session: SessionId(5),
        resend_from: 4,
        down: 0,
        to: 2,
    });
    r.fetch(Fetch::Redirect {
        session: SessionId(6),
        resend_from: 1,
        down: 0,
        to: 2,
    });
    r.node.poll(Nanos(1));
    let got = drain_rx(&mut c);
    assert_eq!(got.len(), 1);
    assert_eq!(
        Redirect::open(&got[0], &K).unwrap(),
        Redirect {
            down: 0,
            to: 2,
            session: SessionId(5),
            resend_from: 4
        }
    );
    let k = *r.node.counters();
    assert_eq!((k.redirects, k.redirect_unknown), (2, 2));
}

/// REDIRECT_BATCH (kind 5): every entry is handled as a kind-4 REDIRECT (a redirect to the
/// session's address, or `redirect_unknown`), and the whole message costs one token. A forged
/// batch is `fetch_unauth`, a malformed one `fetch_bad`, both before any token is charged.
#[test]
fn a_redirect_batch_redirects_each_entry_for_one_token() {
    const KF: [u8; 16] = [0x33; 16];
    let mut r = rig_with(MemStore::default(), |c| {
        c.fetch_keys = BTreeMap::from([(ep(9, 4000).ip, KF)]);
        (c.fetch_rate, c.fetch_burst) = (1_000, 1);
    });
    let mut c = client_rx(&mut r);
    r.send(&req(5, 1, &[Msg::Heartbeat], &K), 0);
    r.send(&req(6, 1, &[Msg::Heartbeat], &K), 0);
    r.node.poll(Nanos(0));
    let inject = |r: &Rig, b: &[u8]| {
        let f = wire(r.client, r.me_fetch, b);
        assert!(r.nic.inject(addr(r.me_fetch), &f, Nanos(0)));
    };
    let entries = [(SessionId(5), 4), (SessionId(6), 1), (SessionId(9), 9)];
    let good = RedirectBatch::seal(&KF, 0, 2, &entries).unwrap();
    let mut forged = good.clone();
    *forged.last_mut().unwrap() ^= 1;
    inject(&r, &forged);
    // Sessions out of order: refused by the codec, so a hand-built one.
    let mut bad = RedirectBatch::encode(0, 2, &entries).unwrap();
    bad[16..24].swap_with_slice(&mut [9, 0, 0, 0, 9, 0, 0, 0]);
    bad[32..40].swap_with_slice(&mut [5, 0, 0, 0, 4, 0, 0, 0]);
    let tag = vyrn_crypto::siphash24(&KF, &bad).0;
    bad.extend_from_slice(&tag.to_le_bytes());
    inject(&r, &bad);
    // Burst 1: the three-entry batch passes on one token; the next fetch is limited.
    inject(&r, &good);
    inject(&r, &good);
    r.node.poll(Nanos(1));
    let k = *r.node.counters();
    assert_eq!((k.fetch_unauth, k.fetch_bad, k.fetch_limited), (1, 1, 1));
    assert_eq!((k.redirects, k.redirect_unknown), (2, 1));
    let mut got: Vec<Redirect> = drain_rx(&mut c)
        .iter()
        .map(|b| Redirect::open(b, &K).unwrap())
        .collect();
    got.sort_by_key(|r| r.session.0);
    let r = |s: u32, from: u32| Redirect {
        down: 0,
        to: 2,
        session: SessionId(s),
        resend_from: from,
    };
    assert_eq!(got, vec![r(5, 4), r(6, 1)]);
}

/// 08 §4.6: from T the home also takes epoch e + 1 under its own keys. `epoch16` picks the key
/// table; a copy of neither epoch is dropped before its MAC, with no `DataBadMac` (F5, P8); a
/// resend under e + 1 of a packet first sent under e is a D3 variant; once e is retired its
/// copies are dropped the same way, and the redirect key is e + 1's.
#[test]
fn the_two_epoch_boundary_keys_copies_by_epoch16() {
    const K2: [u8; 16] = [8; 16];
    let pkt = |seq: u32, e16: u16, key: &[u8; 16], resend: bool| {
        let mut out = [0u8; MAX_REQ_PAYLOAD];
        let h = ReqHeader::new(SessionId(5), seq, e16, BOOK, resend);
        let n = encode_request(&mut out, h, &[Msg::Heartbeat], key, None).unwrap();
        out[..n].to_vec()
    };
    let mut r = rig(MemStore::default());
    // One table, as built: every epoch16 is taken under it (07 §5.4 filters none).
    r.send(&pkt(1, 9, &K, false), 0);
    r.send(&pkt(2, 77, &K, false), 0);
    r.node.poll(Nanos(0));
    assert_eq!(r.node.counters().stored, 2);

    // A skipped number: the held table is named, not taken as next − 1.
    r.node
        .add_epoch(9, 12, BTreeMap::from([(SessionId(5), K2)]));
    let serves = |r: &Rig, e: u16| r.node.home().serves(e);
    assert!(serves(&r, 9) && serves(&r, 12) && !serves(&r, 10) && !serves(&r, 77));
    assert_eq!(r.node.home().key(SessionId(5)), Some(&K2));
    r.send(&pkt(3, 9, &K, false), 1); // epoch e, its key
    r.send(&pkt(4, 12, &K2, false), 1); // the next epoch, its key
    r.send(&pkt(3, 12, &K2, true), 1); // resend of 3 under the next epoch: a variant
    r.send(&pkt(5, 10, &K2, false), 1); // neither epoch
    r.send(&pkt(6, 77, &K, false), 1); // the old table no longer takes any epoch16
    r.send(&pkt(7, 12, &K, false), 1); // the next epoch under e's key: a real bad MAC
    r.node.poll(Nanos(1));
    let k = *r.node.counters();
    assert_eq!((k.stored, k.epoch, k.bad_mac, k.conflicts), (5, 2, 1, 0));
    let ev: Vec<Event> = r.node.drain_events().collect();
    assert_eq!(
        ev,
        vec![Event::BadMac {
            session: SessionId(5),
            pkt_seq: 7
        }]
    );

    r.node.retire_epoch(9);
    assert!(!serves(&r, 9) && serves(&r, 12));
    r.send(&pkt(8, 9, &K, false), 2);
    r.send(&pkt(9, 12, &K2, false), 2);
    r.node.poll(Nanos(2));
    let k = *r.node.counters();
    assert_eq!((k.stored, k.epoch, k.bad_mac), (6, 3, 1));

    r.node.retire_epoch(12);
    assert!(!serves(&r, 12));
    r.send(&pkt(10, 12, &K2, false), 3);
    r.node.poll(Nanos(3));
    assert_eq!(r.node.counters().epoch, 4);
}

/// #183 (a): a redirect the TX queue refuses waits and is sent after the next turn's reap, in
/// order, behind the earlier ones; past the retry queue's two kind-5 batches it is dropped and
/// counted. Every redirect is sent once or counted dropped.
#[test]
fn redirects_a_full_tx_queue_refuses_are_retried_next_turn_in_order() {
    let mut r = rig(MemStore::default());
    let mut c = client_rx(&mut r);
    r.send(&req(5, 1, &[Msg::Heartbeat], &K), 0);
    r.node.poll(Nanos(0));
    let n = 4000u64;
    let asked: Vec<(SessionId, u32)> = (0..n as u32).map(|i| (SessionId(5), i)).collect();
    // No reap between sends: the 512-slot queue fills, then the retry queue (one fetch burst
    // of kind-5 batches).
    r.node.redirect(0, 2, &asked);
    let k = *r.node.counters();
    let cap = (RX_BURST * frame::MAX_BATCH) as u64;
    assert_eq!(k.redirect_retried, cap, "the retry queue fills");
    assert_eq!(k.redirects + k.redirect_retried + k.redirect_dropped, n);
    assert!(k.redirect_dropped > 0);
    // A session the box never heard from is counted unknown, never queued (Vercel on #194).
    r.node.redirect(0, 2, &[(SessionId(9), 1)]);
    let k2 = *r.node.counters();
    assert_eq!(k2.redirect_unknown, k.redirect_unknown + 1);
    assert_eq!(k2.redirect_dropped, k.redirect_dropped);
    let mut got = drain_rx(&mut c);
    let sent_now = got.len() as u64;
    assert_eq!(sent_now, k.redirects);
    // Each turn reaps, then sends what the queue takes.
    for t in 1..20 {
        r.node.poll(Nanos(t));
        got.extend(drain_rx(&mut c));
    }
    let k = *r.node.counters();
    assert_eq!(
        k.redirects,
        sent_now + cap,
        "every queued one sent after reaps"
    );
    let from: Vec<u32> = got
        .iter()
        .map(|b| Redirect::open(b, &K).unwrap().resend_from)
        .collect();
    let want: Vec<u32> = (0..(sent_now + cap) as u32).collect();
    assert_eq!(from, want, "in order, the dropped ones the newest");
    // The queue is empty again: a new redirect goes out at once.
    r.node.redirect(0, 2, &[(SessionId(5), 7)]);
    assert_eq!(drain_rx(&mut c).len(), 1);
    assert_eq!(r.node.counters().redirect_retried, cap);
}
