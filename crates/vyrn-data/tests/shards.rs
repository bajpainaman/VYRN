//! The sharded box (`vyrn_data::shards`) end to end over vyrn-nic's `sim` backend, its cores
//! polled in turn on one thread: packets of sessions on different shards reach every
//! destination with one `data_seq` sequence per destination, a KEY fetch is answered from the
//! ring of the shard that owns the session, and a RANGE fetch resends from the sender's history.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use core::net::{Ipv4Addr, SocketAddrV4};
use std::collections::BTreeMap;

use vyrn_cut::Hw;
use vyrn_data::frame::{self, Fetch, Kind, key_seq};
use vyrn_data::redirect::Redirect;
use vyrn_data::shards::{self, SenderRing, ShardRing};
use vyrn_data::spread::shard_of;
use vyrn_data::{HomeConfig, Mode, NodeConfig};
use vyrn_log::MemStore;
use vyrn_nic::frame::{Endpoint, FrameHdr, build, parse};
use vyrn_nic::sim::SimRx;
use vyrn_nic::{BackendKind, NicBackend, NicConfig, PortConfig, PortId, RxBind, SimNic, TxClass};
use vyrn_types::{BookId, LaneId, MAX_REQ_PAYLOAD, Nanos, SessionId};
use vyrn_wire::{Msg, RX_BURST, ReqHeader, RxPkt, RxRing, encode_request};

const BOOK: BookId = BookId(3);
const N: usize = 2;

fn key(s: u32) -> [u8; 16] {
    [s as u8; 16]
}

fn ep(last: u8, port: u16) -> Endpoint {
    Endpoint {
        mac: [2, 0, 0, 0, 0, last],
        ip: Ipv4Addr::new(10, 0, 0, last),
        port,
    }
}

fn req(session: u32, pkt_seq: u32) -> Vec<u8> {
    let mut out = [0u8; MAX_REQ_PAYLOAD];
    let h = ReqHeader::new(SessionId(session), pkt_seq, 9, BOOK, false);
    let m = [Msg::Heartbeat];
    let n = encode_request(&mut out, h, &m, &key(session), None).unwrap();
    out[..n].to_vec()
}

fn inject(nic: &SimNic, from: Endpoint, to: Endpoint, payload: &[u8]) {
    let mut b = [0u8; 1514];
    let n = build(&FrameHdr { src: from, dst: to }, payload, &mut b).unwrap();
    assert!(nic.inject(SocketAddrV4::new(to.ip, to.port), &b[..n], Nanos(0)));
}

fn drain(rx: &mut SimRx) -> Vec<Vec<u8>> {
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
fn shards_forward_one_data_seq_per_dest_and_answer_key_fetches_from_the_owner() {
    let ports = (0..5u8)
        .map(|i| PortConfig {
            id: PortId(i),
            ip: Ipv4Addr::new(10, 0, 0, i + 1),
        })
        .collect();
    let mut nic = SimNic::open(&NicConfig::new(BackendKind::Sim, ports)).unwrap();
    let bind = |e: Endpoint, port: u8| RxBind {
        lane: LaneId(0),
        port: PortId(port),
        ip: e.ip,
        udp_port: e.port,
    };
    let (me_in, me_fetch, client) = (ep(1, 19998), ep(1, 19997), ep(4, 4000));
    let dests = vec![ep(2, 20000), ep(3, 20000)];
    let ingest = nic.rx_ring(&bind(me_in, 0)).unwrap();
    let fetch = nic.rx_ring(&bind(me_fetch, 0)).unwrap();
    let mut replicas: Vec<SimRx> = dests
        .iter()
        .enumerate()
        .map(|(i, &d)| nic.rx_ring(&bind(d, i as u8 + 1)).unwrap())
        .collect();
    let mut client_rx = nic.rx_ring(&bind(client, 3)).unwrap();
    let mut txq = || nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
    let shard_tx = (0..N).map(|_| txq()).collect();
    let tx = txq();

    let sessions: Vec<u32> = (1..=8).collect();
    let owners: Vec<usize> = sessions
        .iter()
        .map(|&s| shard_of(SessionId(s), N))
        .collect();
    assert!(owners.contains(&0) && owners.contains(&1), "{owners:?}");
    let home = HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys: sessions
            .iter()
            .map(|&s| (SessionId(s), key(s)))
            .collect::<BTreeMap<_, _>>(),
        ring_slots: 64,
        index_key: [0x42; 16],
    };
    let cfg = NodeConfig::new(home, 1, me_in, dests);
    let (mut rx, mut cores, mut sender) = shards::split(&cfg, ingest, fetch, shard_tx, tx);
    let store = MemStore::default();

    let mut shard_rings: Vec<ShardRing> = (0..N).map(|_| ShardRing::new(&Hw)).collect();
    let mut sender_rings: Vec<SenderRing> = (0..=N).map(|_| SenderRing::new(&Hw)).collect();
    let (mut to_shard, mut shard_in): (Vec<_>, Vec<_>) = shard_rings
        .iter_mut()
        .map(|r| {
            let (p, [c]) = r.split().unwrap();
            (p, c)
        })
        .unzip();
    let (mut to_sender, mut sender_in): (Vec<_>, Vec<_>) = sender_rings
        .iter_mut()
        .map(|r| {
            let (p, [c]) = r.split().unwrap();
            (p, c)
        })
        .unzip();
    // Producer N is the RX core's (RANGE fetches); 0..N are the shards'.
    let (shard_out, rx_out) = to_sender.split_at_mut(N);
    macro_rules! turn {
        ($now:expr) => {{
            rx.poll(Nanos($now), &mut to_shard, &mut rx_out[0]);
            for ((c, i), o) in cores
                .iter_mut()
                .zip(&mut shard_in)
                .zip(shard_out.iter_mut())
            {
                c.poll(i, o, &store);
            }
            sender.poll(Nanos($now), &mut sender_in);
        }};
    }

    let pkts: Vec<Vec<u8>> = sessions.iter().map(|&s| req(s, 1)).collect();
    for p in &pkts {
        inject(&nic, client, me_in, p);
    }
    turn!(0);
    sender.flush(Nanos(1));

    // Every shard stored its own sessions, and nothing else.
    for (i, c) in cores.iter().enumerate() {
        let mine = owners.iter().filter(|&&o| o == i).count() as u64;
        assert_eq!(c.counters().stored, mine, "shard {i}");
    }
    // Each destination gets every packet, in DATA frames numbered 1, 2, … by one sender.
    let mut firsts = vec![];
    for r in &mut replicas {
        let frames = drain(r);
        let mut got = vec![];
        for (k, f) in frames.iter().enumerate() {
            let d = frame::decode(f).unwrap();
            assert_eq!((d.hdr.kind, d.hdr.data_seq), (Kind::Data, k as u64 + 1));
            got.extend(d.packets().map(<[u8]>::to_vec));
        }
        got.sort();
        let mut want = pkts.clone();
        want.sort();
        assert_eq!(got, want);
        firsts.push(frames);
    }

    // KEY fetches: each answered with its packet from the owning shard's ring.
    for &s in &sessions {
        let q = Fetch::Key {
            session: SessionId(s),
            pkt_seq: 1,
        };
        inject(&nic, client, me_fetch, &q.encode());
    }
    turn!(10);
    let resp = drain(&mut client_rx);
    assert_eq!(resp.len(), sessions.len());
    // Answers leave each shard's own TX queue, so they come back in shard order.
    let mut got: Vec<(u64, Vec<Vec<u8>>)> = resp
        .iter()
        .map(|r| {
            let d = frame::decode(r).unwrap();
            assert_eq!(d.hdr.kind, Kind::FetchResp);
            (d.hdr.data_seq, d.packets().map(<[u8]>::to_vec).collect())
        })
        .collect();
    got.sort();
    let mut want: Vec<(u64, Vec<Vec<u8>>)> = sessions
        .iter()
        .map(|&s| (key_seq(SessionId(s), 1), vec![req(s, 1)]))
        .collect();
    want.sort();
    assert_eq!(got, want);
    let hits: u64 = cores.iter().map(|c| c.counters().fetch_ring_hit).sum();
    assert_eq!(hits, sessions.len() as u64);

    // RANGE: destination 1's frames resent byte for byte to it.
    let last = firsts[1].len() as u64;
    inject(
        &nic,
        client,
        me_fetch,
        &Fetch::Range {
            dst: 1,
            from: 1,
            to: last,
        }
        .encode(),
    );
    turn!(20);
    assert_eq!(drain(&mut replicas[1]), firsts[1]);
    assert_eq!(sender.counters().fetch_resent, last);
    assert_eq!(rx.counters().hop_full, 0);

    // 07 §5.7 step 3: each session's owner seals its redirect under the session key and sends
    // it to the client; a session nobody owns is counted, not sent.
    let mut asked: Vec<(SessionId, u32)> =
        sessions.iter().map(|&s| (SessionId(s), s + 10)).collect();
    asked.push((SessionId(99), 1));
    assert_eq!(rx.redirect(1, 3, &asked, &mut to_shard), asked.len());
    turn!(30);
    let mut got: Vec<Redirect> = drain(&mut client_rx)
        .iter()
        .map(|b| {
            let s = u32::from_le_bytes(b[8..12].try_into().unwrap());
            Redirect::open(b, &key(s)).unwrap()
        })
        .collect();
    got.sort_by_key(|r| r.session.0);
    let want: Vec<Redirect> = sessions
        .iter()
        .map(|&s| Redirect {
            down: 1,
            to: 3,
            session: SessionId(s),
            resend_from: s + 10,
        })
        .collect();
    assert_eq!(got, want);
    let sum =
        |f: fn(&vyrn_data::Counters) -> u64| cores.iter().map(|c| f(c.counters())).sum::<u64>();
    assert_eq!(sum(|c| c.redirects), sessions.len() as u64);
    assert_eq!(sum(|c| c.redirect_unknown), 1);
}
