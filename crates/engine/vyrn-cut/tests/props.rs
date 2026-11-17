//! Property tests: rings against a queue model, encodings round-trip, `Sim` visibility is a
//! delayed prefix, the token's `ver` is gapless.
// Proptest persists failures through the filesystem, which Miri isolates; Miri covers the
// unit, conformance and thread tests (11 §6.1).
#![cfg(not(any(loom, miri)))]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::VecDeque;

use proptest::prelude::*;
use vyrn_cut::*;
use vyrn_types::{LaneId, LaneSeq, StepId, Tick};

#[derive(Clone, Debug)]
enum Op {
    Push(Vec<u16>),
    Pop(usize),
    Advance(u64),
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(
        prop_oneof![
            prop::collection::vec(any::<u16>(), 1..4).prop_map(Op::Push),
            (0usize..2).prop_map(Op::Pop),
            (0u64..3_000).prop_map(Op::Advance),
        ],
        0..200,
    )
}

/// A broadcast ring of 8 with two consumers equals two queues bounded by the slower reader;
/// with `Sim` a pop may see less, but never a wrong or reordered entry, and nothing is lost.
fn ring_model<V: Visibility>(vis: &V, advance: impl Fn(u64), ops: &[Op]) {
    let mut ring = Ring::<u16, 8, 2, V>::new(vis);
    let (mut p, mut cs) = ring.split().unwrap();
    let mut model: [VecDeque<u16>; 2] = Default::default();
    for op in ops {
        match op {
            Op::Push(vals) => {
                let room = 8 - model.iter().map(VecDeque::len).max().unwrap();
                let ok = p.push_all(vis, vals);
                if ok {
                    assert!(vals.len() <= room, "pushed past the slowest consumer");
                    for q in &mut model {
                        q.extend(vals);
                    }
                }
            }
            Op::Pop(i) => {
                if let Some(v) = cs[*i].pop(vis) {
                    assert_eq!(Some(v), model[*i].pop_front());
                }
            }
            Op::Advance(dt) => advance(*dt),
        }
    }
    advance(1_000_000);
    for (c, q) in cs.iter_mut().zip(&mut model) {
        while let Some(v) = c.pop(vis) {
            assert_eq!(Some(v), q.pop_front());
        }
        assert!(q.is_empty(), "entry lost");
    }
}

proptest! {
    #[test]
    fn hw_ring_matches_model(ops in ops()) {
        ring_model(&Hw, |_| {}, &ops);
    }

    #[test]
    fn sim_ring_matches_model(seed: u64, ops in ops()) {
        let sim = Sim::new(seed, 2_000);
        ring_model(&sim, |dt| sim.advance_to(sim.virtual_ns() + dt), &ops);
    }

    #[test]
    fn counter_round_trips(seq: u64, sv: u32, f: u32, fp: u64, n: u32, d: u8, s: u8,
                           ev in prop::array::uniform3((any::<u32>(), any::<u16>(), any::<u16>()))) {
        let c = Counter {
            seq: LaneSeq(seq), snap_ver: sv, f_lo: f, fwd_pend: LaneSeq(fp), n_ev: n,
            dir_sel: d, state: s,
            ev: ev.map(|(t, b, x)| OccEvent { tick: Tick(t), back: b, bits: x }),
        };
        prop_assert_eq!(Counter::from_words(c.to_words()), c);
    }

    #[test]
    fn snapshot_round_trips(v: u64, b: u32, a: u32, d: u64, c: u32, p: u8, f: u8) {
        let s = Snapshot { version: v, bid: Tick(b), ask: Tick(a), done_step: StepId(d),
                           win_center: Tick(c), phase: p, flags: f };
        prop_assert_eq!(Snapshot::from_words(s.to_words()), s);
    }

    #[test]
    fn half_cut_round_trips(id: u64, wild: u32, c: u32,
                            e in prop::collection::vec((any::<u64>(), any::<u32>(), any::<u32>()), 25)) {
        let mut v = HalfCutVal { pub_id: id, wild, occ_center: Tick(c), ..Default::default() };
        for (dst, (s, sv, f)) in v.entries.iter_mut().zip(e) {
            *dst = CutEntry { seq: LaneSeq(s), snap_ver: sv, f_lo: f };
        }
        prop_assert_eq!(HalfCutVal::from_words(v.to_words()), v);
    }

    /// Reads of one line are a non-decreasing subsequence of its publications, and the newest is
    /// visible after `max_delay_ns`.
    #[test]
    fn sim_reads_are_a_delayed_prefix(seed: u64, max in 0u64..5_000,
                                      steps in prop::collection::vec(0u64..2_000, 1..100)) {
        let sim = Sim::new(seed, max);
        let line: Published<u64, 1, Sim> = Published::new(&sim, &0);
        let mut last = 0;
        for (k, dt) in (1u64..).zip(&steps) {
            line.publish(&sim, &k);
            sim.advance_to(sim.virtual_ns() + dt);
            let r = line.try_read(&sim).unwrap();
            prop_assert!(r >= last && r <= k);
            last = r;
        }
        sim.advance_to(sim.virtual_ns() + max);
        prop_assert_eq!(line.try_read(&sim), Some(steps.len() as u64));
    }

    /// Takes by any lanes in any order return 1, 2, 3, … (`AcctTake.ver`, 01 §14.17.4).
    #[test]
    fn token_ver_is_gapless(lanes in prop::collection::vec(42u8..49, 1..50)) {
        let t = PoolTok::new();
        for (k, l) in (1u32..).zip(&lanes) {
            prop_assert_eq!(t.try_take(LaneId(*l)), Ok(k));
            prop_assert_eq!(t.try_take(LaneId(*l)), Err(TakeError::Held(LaneId(*l))));
            prop_assert_eq!(t.release(LaneId(*l)), Ok(k));
        }
    }

    /// Publications on several lines, any number in flight: what a reader sees is always a prefix
    /// of the global publication order (each line's value is its newest publication in the prefix).
    #[test]
    fn sim_visibility_is_a_global_prefix(seed: u64, max in 0u64..3_000,
                                         ops in prop::collection::vec((0usize..3, 0u64..400), 1..120)) {
        let sim = Sim::new(seed, max);
        let lines: [Published<u64, 1, Sim>; 3] = core::array::from_fn(|_| Published::new(&sim, &0));
        // Value = global publication index, from 1.
        let mut log: Vec<usize> = Vec::new();
        for (g, (l, dt)) in (1u64..).zip(&ops) {
            lines[*l].publish(&sim, &g);
            log.push(*l);
            sim.advance_to(sim.virtual_ns() + dt);
            let seen: Vec<u64> = lines.iter().map(|x| x.try_read(&sim).unwrap()).collect();
            let p = *seen.iter().max().unwrap();
            for (i, v) in seen.iter().enumerate() {
                let want = (1..=p).rev().find(|k| log[(*k - 1) as usize] == i).unwrap_or(0);
                prop_assert_eq!(*v, want, "line {} not the prefix {}", i, p);
            }
        }
    }

    /// `CutWriter` publishes exactly the pointwise-monotone sequences.
    #[test]
    fn cut_writer_rejects_exactly_the_non_monotone(seqs in prop::collection::vec(0u64..4, 1..20)) {
        let half: HalfCut<Hw> = HalfCut::new(&Hw, &HalfCutVal::default());
        let mut w = CutWriter::new();
        let mut hi = 0;
        let mut v = HalfCutVal::default();
        for s in seqs {
            v.entries[7].seq = LaneSeq(s);
            let r = w.publish(&half, &Hw, &v);
            prop_assert_eq!(r.is_ok(), s >= hi);
            hi = hi.max(s);
        }
    }
}
