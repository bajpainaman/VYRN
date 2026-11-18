//! #183 (b): the failover redirect burst of a 2,000-session box on one shard. Four validators
//! each send 12 REDIRECT_BATCHes covering every session at once (8,000 redirects, about twice
//! the shard's hop ring), with a lagging replica's KEY-fetch flood behind them. The RX core
//! paces the burst against the full ring: every redirect reaches the client and none is dropped.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use core::net::{Ipv4Addr, SocketAddrV4};
use std::collections::BTreeMap;

use vyrn_cut::Hw;
use vyrn_data::frame::{Fetch, RedirectBatch};
use vyrn_data::shards::{self, SenderRing, ShardRing};
use vyrn_data::{HomeConfig, Mode, NodeConfig};
use vyrn_log::MemStore;
use vyrn_nic::frame::{Endpoint, FrameHdr, build};
use vyrn_nic::sim::SimRx;
use vyrn_nic::{BackendKind, NicBackend, NicConfig, PortConfig, PortId, RxBind, SimNic, TxClass};
use vyrn_types::{BookId, LaneId, MAX_REQ_PAYLOAD, Nanos, SessionId};
use vyrn_wire::{Msg, RX_BURST, ReqHeader, RxPkt, RxRing, encode_request};

const BOOK: BookId = BookId(3);
const SESSIONS: u32 = 2000;

fn key(s: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(&s.to_le_bytes());
    k
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
    let n = encode_request(&mut out, h, &[Msg::Heartbeat], &key(session), None).unwrap();
    out[..n].to_vec()
}
fn inject(nic: &SimNic, from: Endpoint, to: Endpoint, payload: &[u8]) -> bool {
    let mut b = [0u8; 1514];
    let n = build(&FrameHdr { src: from, dst: to }, payload, &mut b).unwrap();
    nic.inject(SocketAddrV4::new(to.ip, to.port), &b[..n], Nanos(0))
}
fn count(rx: &mut SimRx) -> usize {
    let mut out = 0;
    let mut burst = [RxPkt::empty(); RX_BURST];
    loop {
        let n = rx.poll(&mut burst);
        if n == 0 {
            return out;
        }
        out += n;
        rx.release(n);
    }
}

#[test]
fn a_failover_burst_twice_the_hop_ring_is_paced_not_dropped() {
    let ports = (0..5u8)
        .map(|i| PortConfig {
            id: PortId(i),
            ip: Ipv4Addr::new(10, 0, 0, i + 1),
        })
        .collect();
    let mut nc = NicConfig::new(BackendKind::Sim, ports);
    nc.rx_slots = 4096;
    let mut nic = SimNic::open(&nc).unwrap();
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
    let mut flood_rx = nic.rx_ring(&bind(ep(2, 4001), 1)).unwrap();
    let mut txq = || nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
    let shard_tx = vec![txq()];
    let tx = txq();
    let home = HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys: (1..=SESSIONS)
            .map(|s| (SessionId(s), key(s)))
            .collect::<BTreeMap<_, _>>(),
        ring_slots: 8192,
        index_key: [0x42; 16],
    };
    let mut cfg = NodeConfig::new(home, 1, me_in, dests);
    cfg.fetch_burst = 1 << 20;
    cfg.fetch_rate = 1 << 30;
    let (mut rx, mut cores, mut sender) = shards::split(&cfg, ingest, fetch, shard_tx, tx);
    let store = MemStore::default();
    let mut shard_rings: Vec<ShardRing> = (0..1).map(|_| ShardRing::new(&Hw)).collect();
    let mut sender_rings: Vec<SenderRing> = (0..=1).map(|_| SenderRing::new(&Hw)).collect();
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
    let (shard_out, rx_out) = to_sender.split_at_mut(1);
    let mut got = 0usize;
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
            got += count(&mut client_rx);
            for r in replicas.iter_mut() {
                count(r);
            }
            count(&mut flood_rx);
        }};
    }
    // Every session's first copy, so the box knows its address.
    for s in 1..=SESSIONS {
        assert!(inject(&nic, client, me_in, &req(s, 1)));
        if s % 1000 == 0 {
            for t in 0..200 {
                turn!(t);
            }
        }
    }
    for t in 0..200 {
        turn!(t);
    }
    assert_eq!(cores[0].counters().stored, SESSIONS as u64);
    let base = got;
    // The burst: 4 validators × 12 batches, plus a KEY-fetch flood from a lagging replica.
    let sessions: Vec<(SessionId, u32)> = (1..=SESSIONS).map(|s| (SessionId(s), 2)).collect();
    for v in 0..4u8 {
        for chunk in sessions.chunks(181) {
            let b = RedirectBatch::encode(0, 1, chunk).unwrap();
            assert!(inject(&nic, ep(10 + v, 4100), me_fetch, &b));
        }
    }
    for i in 0..2000u32 {
        let q = Fetch::Key {
            session: SessionId(1 + i % SESSIONS),
            pkt_seq: 99,
        }
        .encode();
        inject(&nic, ep(2, 4001), me_fetch, &q);
    }
    for t in 0..2000u64 {
        turn!(1000 + t);
        if got - base == 4 * SESSIONS as usize {
            break;
        }
    }
    let k = *rx.counters();
    assert_eq!(
        got - base,
        4 * SESSIONS as usize,
        "every redirect delivered: {k:?}"
    );
    assert!(k.redirect_retried > 0, "the burst overran the ring: {k:?}");
    assert_eq!(k.redirect_dropped, 0);
    assert_eq!(cores[0].counters().redirects, 4 * u64::from(SESSIONS));
}
