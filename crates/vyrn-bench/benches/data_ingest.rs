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
