//! `vyrn-data` ingest (07 §5.2 steps 1–5) on one core: ns per packet and the allocations the
//! measured loop makes, counted by the sealing allocator (11 §3.5).
//!
//! `cargo bench --locked -p vyrn-bench --bench data_ingest`. The ring is full and evicting while
//! measured, every session already has its dedupe window, and every packet is new, so each one
//! runs the whole pipeline: parse, SipHash MAC, dedupe, BLAKE3, store and index.
//!
//! `spread N` runs the same packets over N session shards (`vyrn_data::spread`), one thread
//! each, every packet already on its shard's queue: total Mpps across the shards and the speedup
//! over one. The orb has 2 cores, so N stops there.
//!
//! `pipeline N` runs the sharded box (`vyrn_data::shards`) as the binary does: an RX core, N
//! shard cores and one sender core, each on its own thread, over vyrn-nic's `sim` backend with
//! every frame already on the ingest queue. It reports Mpps from the first poll until the
//! sender has drained, and the speedup over N = 1. With N + 2 threads on a 2-core orb the cores
//! share CPUs, so N = 2 measures the hop overhead, not the scaling a REF box would show.
//!
//! DEV numbers: an orb or a laptop is not the REF box (06 §1); compare before and after on one
//! machine only.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::float_arithmetic,
    clippy::cast_precision_loss
)]

use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Barrier;
use std::time::Instant;

use vyrn_data::ring::Ring;
use vyrn_data::{DataHome, HomeConfig, Mode, Spread};
use vyrn_engine::alloc::{SealingAlloc, seal_counting, unseal, violations};
use vyrn_types::{BookId, Hash, MAX_REQ_PAYLOAD, Nanos, SessionId};
use vyrn_wire::{Msg, ReqHeader, encode_request};

#[global_allocator]
static A: SealingAlloc = SealingAlloc;

const SESSIONS: u32 = 4096;
const RING: usize = 1 << 16;
const ROUNDS: usize = 5;
const BOOK: BookId = BookId(1);

fn key(s: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..4].copy_from_slice(&s.to_le_bytes());
    k[4] = 0x5a;
    k
}

fn cfg() -> HomeConfig {
    HomeConfig {
        mode: Mode::Base,
        books: vec![BOOK],
        keys: (1..=SESSIONS)
            .map(|s| (SessionId(s), key(s)))
            .collect::<BTreeMap<_, _>>(),
        ring_slots: RING,
        index_key: [0x11; 16],
    }
}

/// `n` packets, sessions round-robin, each session's `pkt_seq` gapless from 1.
fn packets(n: usize) -> Vec<(u8, [u8; MAX_REQ_PAYLOAD])> {
    let msgs = [Msg::Heartbeat, Msg::Heartbeat];
    (0..n)
        .map(|i| {
            let s = (i as u32 % SESSIONS) + 1;
            let q = i as u32 / SESSIONS + 1;
            let mut out = [0u8; MAX_REQ_PAYLOAD];
            let h = ReqHeader::new(SessionId(s), q, 9, BOOK, false);
            let len = encode_request(&mut out, h, &msgs, &key(s), None).unwrap();
            (len as u8, out)
        })
        .collect()
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn main() {
    let pkts = packets(3 * RING);
    let (warm, hot) = pkts.split_at(RING);

    let mut ns = Vec::new();
    let mut allocs = 0u64;
    for _ in 0..ROUNDS {
        let mut home = DataHome::new(cfg());
        let mut ev = None;
        for (len, p) in warm {
            home.ingest(&p[..usize::from(*len)], Nanos(0), &mut ev)
                .unwrap();
        }
        seal_counting();
        let before = violations();
        let t = Instant::now();
        for (i, (len, p)) in hot.iter().enumerate() {
            let r = home.ingest(&p[..usize::from(*len)], Nanos(i as u64), &mut ev);
            black_box(r).unwrap();
        }
        let dt = t.elapsed();
        allocs += violations() - before;
        unseal();
        ns.push(dt.as_nanos() as f64 / hot.len() as f64);
    }
    println!(
        "ingest      {:>7.1} ns/pkt  (median of {ROUNDS}, {} pkts each, {SESSIONS} sessions, ring {RING})  allocs {allocs}",
        median(ns),
        hot.len()
    );

    // RSS spread: N shards, one thread each, packets pre-routed by session.
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut base = 0.0;
    for n in (1..=cores.min(4)).filter(|n| n.is_power_of_two()) {
        let mut mpps = Vec::new();
        let mut allocs = 0u64;
        for _ in 0..ROUNDS {
            let mut spread = Spread::new(&cfg(), n);
            let mut ev = None;
            let mut queues: Vec<Vec<&[u8]>> = vec![Vec::new(); n];
            for (len, p) in warm {
                spread
                    .ingest_from(&p[..usize::from(*len)], None, Nanos(0), &mut ev)
                    .unwrap();
            }
            for (len, p) in hot {
                let p = &p[..usize::from(*len)];
                queues[spread.route(p).unwrap()].push(p);
            }
            let shards = spread.into_shards();
            let go = Barrier::new(n + 1);
            let mut secs = 0.0f64;
            let mut violations_run = 0;
            std::thread::scope(|sc| {
                let hs: Vec<_> = shards
                    .into_iter()
                    .zip(&queues)
                    .map(|(mut home, q)| {
                        let go = &go;
                        sc.spawn(move || {
                            let mut ev = None;
                            go.wait();
                            // The allocator counts per thread, so each shard counts its own loop.
                            seal_counting();
                            let before = violations();
                            let t = Instant::now();
                            for (i, p) in q.iter().enumerate() {
                                black_box(home.ingest(p, Nanos(i as u64), &mut ev)).unwrap();
                            }
                            let dt = t.elapsed().as_secs_f64();
                            let a = violations() - before;
                            unseal();
                            (dt, a)
                        })
                    })
                    .collect();
                go.wait();
                for h in hs {
                    let (dt, a) = h.join().unwrap();
                    secs = secs.max(dt);
                    violations_run += a;
                }
            });
            allocs += violations_run;
            mpps.push(hot.len() as f64 / secs / 1e6);
        }
        let m = median(mpps);
        if n == 1 {
            base = m;
        }
        println!(
            "spread {n}    {m:>7.2} Mpps total  ({:.2}x one shard, {cores} cores)  allocs {allocs}",
            m / base
        );
    }

    pipeline(hot);

    // The ring and its index alone: store one packet and look its key up, ring full.
    let mut ns = Vec::new();
    let mut allocs = 0u64;
    let pkt = &pkts[0].1[..usize::from(pkts[0].0)];
    for _ in 0..ROUNDS {
        let mut ring = Ring::new(RING, [0x11; 16]);
        for i in 0..RING as u32 {
            ring.put(
                SessionId(i % SESSIONS + 1),
                i / SESSIONS + 1,
                Hash([i as u8; 32]),
                Nanos(0),
                pkt,
                true,
            );
        }
        seal_counting();
        let before = violations();
        let t = Instant::now();
        for i in RING as u32..3 * RING as u32 {
            let (s, q) = (SessionId(i % SESSIONS + 1), i / SESSIONS + 1);
            ring.put(s, q, Hash([i as u8; 32]), Nanos(0), pkt, true);
            black_box(ring.get(s, q).is_some());
        }
        let dt = t.elapsed();
        allocs += violations() - before;
        unseal();
        ns.push(dt.as_nanos() as f64 / (2 * RING) as f64);
    }
    println!(
        "ring put+get {:>6.1} ns/op   (median of {ROUNDS}, {} ops each)  allocs {allocs}",
        median(ns),
        2 * RING
    );
}

/// Frames on the sim ingest queue per `pipeline` round.
const PIPE: usize = 1 << 15;

fn pipeline(pkts: &[(u8, [u8; MAX_REQ_PAYLOAD])]) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use vyrn_cut::Hw;
    use vyrn_data::NodeConfig;
    use vyrn_data::shards::{self, SenderRing, ShardRing};
    use vyrn_log::MemStore;
    use vyrn_nic::frame::{Endpoint, FrameHdr, build};
    use vyrn_nic::{
        BackendKind, NicBackend, NicConfig, PortConfig, PortId, RxBind, SimNic, TxClass,
    };
    use vyrn_types::LaneId;

    let ep = |last: u8, port: u16| Endpoint {
        mac: [2, 0, 0, 0, 0, last],
        ip: std::net::Ipv4Addr::new(10, 0, 0, last),
        port,
    };
    let (me, client) = (ep(1, 19998), ep(9, 4000));
    let frames: Vec<Vec<u8>> = pkts[..PIPE]
        .iter()
        .map(|(len, p)| {
            let mut b = [0u8; 1514];
            let n = build(
                &FrameHdr {
                    src: client,
                    dst: me,
                },
                &p[..usize::from(*len)],
                &mut b,
            )
            .unwrap();
            b[..n].to_vec()
        })
        .collect();
    let mut base = 0.0;
    for n in [1usize, 2] {
        let mut mpps = Vec::new();
        let (mut allocs, mut drops) = (0u64, 0u64);
        for _ in 0..ROUNDS {
            let mut ncfg = NicConfig::new(
                BackendKind::Sim,
                vec![PortConfig {
                    id: PortId(0),
                    ip: me.ip,
                }],
            );
            ncfg.rx_slots = PIPE;
            let mut nic = SimNic::open(&ncfg).unwrap();
            let bind = |e: Endpoint| RxBind {
                lane: LaneId(0),
                port: PortId(0),
                ip: e.ip,
                udp_port: e.port,
            };
            let ingest = nic.rx_ring(&bind(me)).unwrap();
            let fetch = nic.rx_ring(&bind(ep(1, 19997))).unwrap();
            let mut txq = || nic.tx_ring(PortId(0), TxClass::OrderStream).unwrap();
            let shard_tx = (0..n).map(|_| txq()).collect();
            let tx = txq();
            // Two destinations nobody listens on: the sim sends and loses their frames.
            let dests = vec![ep(2, 20000), ep(3, 20000)];
            let mut home = cfg();
            home.ring_slots = PIPE;
            let node = NodeConfig::new(home, 1, me, dests);
            let (mut rx, cores, mut sender) = shards::split(&node, ingest, fetch, shard_tx, tx);
            let addr = std::net::SocketAddrV4::new(me.ip, me.port);
            for f in &frames {
                assert!(nic.inject(addr, f, Nanos(0)));
            }
            let store = MemStore::default();
            let mut shard_rings: Vec<ShardRing> = (0..n).map(|_| ShardRing::new(&Hw)).collect();
            let mut sender_rings: Vec<SenderRing> = (0..=n).map(|_| SenderRing::new(&Hw)).collect();
            let (mut to_shard, shard_in): (Vec<_>, Vec<_>) = shard_rings
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
            let mut rx_out = to_sender.pop().unwrap();
            let (rx_done, shards_done) = (AtomicBool::new(false), AtomicUsize::new(0));
            let go = Barrier::new(n + 2);
            let drain = |done: &dyn Fn() -> bool, work: &mut dyn FnMut() -> usize| {
                let mut last = false;
                loop {
                    if work() == 0 {
                        if last {
                            return;
                        }
                        last = done();
                        std::thread::yield_now();
                    }
                }
            };
            let (secs, a, stored, dropped) = std::thread::scope(|sc| {
                let (go, store, rx_done, shards_done) = (&go, &store, &rx_done, &shards_done);
                let h_rx = sc.spawn(move || {
                    go.wait();
                    seal_counting();
                    let before = violations();
                    while (rx.counters().rx_pkts as usize) < PIPE {
                        if rx.poll(Nanos(0), &mut to_shard, &mut rx_out) == 0 {
                            std::thread::yield_now();
                        }
                    }
                    let a = violations() - before;
                    unseal();
                    rx_done.store(true, Ordering::Release);
                    (a, rx.counters().hop_full)
                });
                let hs: Vec<_> = cores
                    .into_iter()
                    .zip(shard_in)
                    .zip(to_sender)
                    .map(|((mut core, mut input), mut out)| {
                        sc.spawn(move || {
                            go.wait();
                            seal_counting();
                            let before = violations();
                            drain(&|| rx_done.load(Ordering::Acquire), &mut || {
                                let w = core.poll(&mut input, &mut out, store);
                                core.drain_events().for_each(drop);
                                w
                            });
                            let a = violations() - before;
                            unseal();
                            shards_done.fetch_add(1, Ordering::AcqRel);
                            (a, core.counters().stored)
                        })
                    })
                    .collect();
                go.wait();
                let t = Instant::now();
                seal_counting();
                let before = violations();
                drain(&|| shards_done.load(Ordering::Acquire) == n, &mut || {
                    sender.poll(Nanos(t.elapsed().as_nanos() as u64), &mut sender_in)
                });
                let secs = t.elapsed().as_secs_f64();
                let mut a = violations() - before;
                unseal();
                let (ra, dropped) = h_rx.join().unwrap();
                a += ra;
                let mut stored = 0;
                for h in hs {
                    let (x, s) = h.join().unwrap();
                    a += x;
                    stored += s;
                }
                // A full shard ring drops at the RX core (shards.rs reading), as a full NIC queue would.
                assert_eq!(
                    stored + dropped,
                    PIPE as u64,
                    "every packet stored or counted"
                );
                (secs, a, stored, dropped)
            });
            allocs += a;
            drops += dropped;
            mpps.push(stored as f64 / secs / 1e6);
        }
        let m = median(mpps);
        if n == 1 {
            base = m;
        }
        println!(
            "pipeline {n}  {m:>7.2} Mpps stored  ({:.2}x n = 1, {} threads, median of {ROUNDS}, {PIPE} pkts)  hop_full {}  allocs {allocs}",
            m / base,
            n + 2,
            drops / ROUNDS as u64
        );
    }
}
