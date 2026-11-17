//! Conformance suite. Part 1: byte-offset vectors from the 05 §4 tables, which any other
//! implementation of these lines (the Vx client, a C reader) can check against. Part 2: the
//! `Visibility` contract, run on every backend.
#![cfg(not(loom))]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use vyrn_cut::*;
use vyrn_types::{LaneSeq, StepId, Tick};

/// The line's bytes as 05 lays them out: the seqlock word at 0, then the words.
fn image<const W: usize>(words: [u64; W]) -> Vec<u8> {
    let mut out = vec![0u8; 8];
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn at(img: &[u8], off: usize, len: usize) -> &[u8] {
    &img[off..off + len]
}

#[test]
fn counter_line_offsets_are_05_4_10() {
    let c = Counter {
        seq: LaneSeq(0x1112_1314_1516_1718),
        snap_ver: 0x2122_2324,
        f_lo: 0x3132_3334,
        fwd_pend: LaneSeq(0x4142_4344_4546_4748),
        n_ev: 0x5152_5354,
        dir_sel: 1,
        state: 2,
        ev: [
            OccEvent {
                tick: Tick(0x6162_6364),
                back: 0x6566,
                bits: 0x0003,
            },
            OccEvent {
                tick: Tick(7),
                back: 8,
                bits: 1,
            },
            OccEvent {
                tick: Tick(0x7172_7374),
                back: 0x7576,
                bits: 0x0002,
            },
        ],
    };
    let img = image(c.to_words());
    assert_eq!(img.len(), 64);
    assert_eq!(at(&img, 8, 8), 0x1112_1314_1516_1718u64.to_le_bytes());
    assert_eq!(at(&img, 16, 4), 0x2122_2324u32.to_le_bytes());
    assert_eq!(at(&img, 20, 4), 0x3132_3334u32.to_le_bytes());
    assert_eq!(at(&img, 24, 8), 0x4142_4344_4546_4748u64.to_le_bytes());
    assert_eq!(at(&img, 32, 4), 0x5152_5354u32.to_le_bytes());
    assert_eq!(img[36], 1, "dir_sel");
    assert_eq!(img[37], 2, "state");
    assert_eq!(at(&img, 38, 2), [0, 0], "rsv");
    // ev[0] at 40: tick, back, bits.
    assert_eq!(
        at(&img, 40, 8),
        [0x64, 0x63, 0x62, 0x61, 0x66, 0x65, 0x03, 0x00]
    );
    // ev[2], the newest, at 56.
    assert_eq!(at(&img, 56, 4), 0x7172_7374u32.to_le_bytes());
    assert_eq!(Counter::from_words(c.to_words()), c);
}

#[test]
fn snapshot_line_offsets_are_05_4_14() {
    let s = Snapshot {
        version: 0x0102_0304_0506_0708,
        bid: Tick(0x1112_1314),
        ask: Tick(u32::MAX),
        done_step: StepId(0x2122_2324_2526_2728),
        win_center: Tick(0x3132_3334),
        phase: 2,
        flags: 1,
    };
    let img = image(s.to_words());
    assert_eq!(at(&img, 8, 8), 0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(at(&img, 16, 4), 0x1112_1314u32.to_le_bytes());
    assert_eq!(at(&img, 20, 4), [0xFF; 4]);
    assert_eq!(at(&img, 24, 8), 0x2122_2324_2526_2728u64.to_le_bytes());
    assert_eq!(at(&img, 32, 4), 0x3132_3334u32.to_le_bytes());
    assert_eq!((img[36], img[37]), (2, 1), "phase, flags");
    assert_eq!(Snapshot::from_words(s.to_words()), s);
}

#[test]
fn half_cut_offsets_are_05_4_13() {
    let mut v = HalfCutVal {
        pub_id: 9,
        wild: 0x0100_0001,
        occ_center: Tick(0x3132_3334),
        ..Default::default()
    };
    v.entries[0] = CutEntry {
        seq: LaneSeq(0xA1),
        snap_ver: 0xB1,
        f_lo: 0xC1,
    };
    v.entries[24] = CutEntry {
        seq: LaneSeq(0xA2),
        snap_ver: 0xB2,
        f_lo: 0xC2,
    };
    let img = image(v.to_words());
    // Line 0, then 25 entries of 16 B in lines 1-7 (the last 48 B of line 7 unused).
    assert_eq!(img.len(), 64 + LANES_PER_HALF * 16);
    assert_eq!(at(&img, 8, 8), 9u64.to_le_bytes(), "pub_id");
    assert_eq!(at(&img, 16, 4), 0x0100_0001u32.to_le_bytes(), "wild");
    assert_eq!(at(&img, 20, 4), 0x3132_3334u32.to_le_bytes(), "occ_center");
    assert!(at(&img, 24, 40).iter().all(|b| *b == 0), "newest and rsv");
    // entry[l] at 64 + 16 l: seq, snap_ver, f_lo.
    assert_eq!(at(&img, 64, 8), 0xA1u64.to_le_bytes());
    assert_eq!(at(&img, 72, 4), 0xB1u32.to_le_bytes());
    assert_eq!(at(&img, 76, 4), 0xC1u32.to_le_bytes());
    assert_eq!(at(&img, 64 + 16 * 24, 8), 0xA2u64.to_le_bytes());
    assert_eq!(at(&img, 76 + 16 * 24, 4), 0xC2u32.to_le_bytes());
    assert_eq!(HalfCutVal::from_words(v.to_words()), v);
}

#[test]
fn lane_cut_is_step_then_cut() {
    let e = LaneCutEntry {
        step: StepId(3),
        cut: LaneSeq(4),
    };
    assert_eq!(e.to_words(), [3, 4]);
}

#[test]
fn shared_lines_are_padded_on_every_target() {
    assert_eq!(SHARED_ALIGN, 128);
    assert_eq!(align_of::<CounterLine<Hw>>(), 128);
    assert_eq!(align_of::<SnapshotLine<Sim>>(), 128);
    assert_eq!(align_of::<StealLock>(), 128);
    assert_eq!(size_of::<PoolTok>(), 16);
}

// Part 2: the Visibility contract. `settle` makes every publication made so far visible.

trait Backend: Visibility {
    fn settle(&self);
}

impl Backend for Hw {
    fn settle(&self) {}
}

impl Backend for Sim {
    fn settle(&self) {
        self.advance_to(self.virtual_ns().saturating_add(1_000_000));
    }
}

/// A reader sees a whole publication, eventually the newest, and never goes back.
fn contract<V: Backend>(vis: &V) {
    let line: Published<LaneCutEntry, 2, V> = Published::new(vis, &LaneCutEntry::default());
    let mut seen = 0u64;
    for k in 1..=200u64 {
        line.publish(
            vis,
            &LaneCutEntry {
                step: StepId(k),
                cut: LaneSeq(k * 10),
            },
        );
        if let Some(r) = line.try_read(vis) {
            assert_eq!(r.cut.0, r.step.0 * 10, "torn");
            assert!(r.step.0 >= seen, "went back");
            seen = r.step.0;
        }
    }
    vis.settle();
    assert_eq!(line.try_read(vis).map(|r| r.step), Some(StepId(200)));
}

/// Two lines published in order: seeing the second's new value implies seeing the first's.
fn causal<V: Backend>(vis: &V) {
    let a: Published<u64, 1, V> = Published::new(vis, &0);
    let b: Published<u64, 1, V> = Published::new(vis, &0);
    for k in 1..=200u64 {
        a.publish(vis, &k);
        b.publish(vis, &k);
        let rb = b.try_read(vis).unwrap();
        let ra = a.try_read(vis).unwrap();
        assert!(ra >= rb, "b={rb} visible before a={ra}");
    }
}

#[test]
fn hw_meets_the_contract() {
    contract(&Hw);
    causal(&Hw);
}

#[test]
fn sim_meets_the_contract() {
    for seed in 0..32 {
        let sim = Sim::new(seed, 2_000);
        contract(&sim);
        causal(&sim);
    }
}

#[test]
fn sim_shows_stale_values_and_replays_by_seed() {
    let trace = |seed| {
        let sim = Sim::new(seed, 2_000);
        let line: Published<u64, 1, Sim> = Published::new(&sim, &0);
        (1..=100u64)
            .map(|k| {
                sim.advance_to(k * 50);
                line.publish(&sim, &k);
                line.try_read(&sim).unwrap()
            })
            .collect::<Vec<_>>()
    };
    let t = trace(42);
    assert_eq!(t, trace(42), "same seed, same visibility");
    assert!(
        t.iter().zip(1..).any(|(seen, k)| *seen < k),
        "no stale read: SF-13 untestable"
    );
    assert_ne!(t, trace(43));
}

#[test]
fn sim_zero_delay_is_immediate() {
    let sim = Sim::new(1, 0);
    let line: Published<u64, 1, Sim> = Published::new(&sim, &0);
    line.publish(&sim, &5);
    assert_eq!(line.try_read(&sim), Some(5));
}

#[test]
fn half_cut_ring_reads_newest_and_rejects_going_back() {
    let half: HalfCut<Hw> = HalfCut::new(&Hw, &HalfCutVal::default());
    assert_eq!(half.try_read_newest(&Hw).map(|(id, _)| id), Some(0));
    let mut w = CutWriter::new();
    let mut v = HalfCutVal::default();
    for k in 1..=6u64 {
        v.entries[3].seq = LaneSeq(k);
        assert_eq!(w.publish(&half, &Hw, &v), Ok(k));
        let (id, got) = half.try_read_newest(&Hw).unwrap();
        assert_eq!((id, got.pub_id, got.entries[3].seq), (k, k, LaneSeq(k)));
    }
    v.entries[3].seq = LaneSeq(5);
    assert_eq!(
        w.publish(&half, &Hw, &v),
        Err(CutNotMonotone { lane_ix: 3 })
    );
    assert_eq!(
        half.try_read_newest(&Hw).map(|(id, _)| id),
        Some(6),
        "not published"
    );
}
