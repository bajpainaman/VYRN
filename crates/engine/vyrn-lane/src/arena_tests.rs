//! Unit tests of `arena` (kept outside `arena.rs`, whose line budget is 300). Run under Miri:
//! `MIRIFLAGS=-Zmiri-strict-provenance cargo +nightly miri test -p vyrn-lane arena`.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use vyrn_types::{LaneSeq, Nanos, Tick};

use crate::arena::{Arena, ArenaConfig};
use crate::layout::join;

fn cfg() -> ArenaConfig {
    ArenaConfig {
        slot_cap: 8,
        seg_cap: 4,
        tick_min: Tick(10),
        tick_max: Tick(140),
        accounts: 4,
        journal: 4,
    }
}

#[test]
fn arena_splits_once() {
    let mut a = Arena::new(cfg());
    assert!(a.split().is_some());
    assert!(a.split().is_none(), "exactly one writer (INV-WRITER)");
}

#[test]
fn arena_slot_words_and_tombstone() {
    let mut a = Arena::new(cfg());
    let (w, v) = a.split().unwrap();
    let words: [u64; 8] = core::array::from_fn(|k| 100 + u64::try_from(k).unwrap());
    w.slot_words(3, words);
    assert_eq!(v.slot_words(3), Some(words));
    w.tombstone(3, LaneSeq(42), Nanos(7));
    let got = v.slot_words(3).unwrap();
    assert_eq!(
        (got[3], got[4]),
        (42, 7),
        "tomb_seq is word 3, tomb_ts word 4"
    );
    assert_eq!(got[0], 100, "other words unchanged");
    // Slot 0 is null; the last slot is cap − 1.
    assert_eq!(v.slot_words(0), None);
    assert!(v.slot_words(7).is_some());
    assert_eq!(v.slot_words(8), None);
}

#[test]
fn arena_segment_words_head_and_bounds() {
    let mut a = Arena::new(cfg());
    let (w, v) = a.split().unwrap();
    w.seg_word(2, 0, 0xAB);
    w.seg_mask(2, join(0x0001_0002, 1));
    w.seg_succ(2, join(3, 140));
    let s = v.seg_words(2).unwrap();
    assert_eq!(
        (s[0], s[16], s[17]),
        (0xAB, join(0x0001_0002, 1), join(3, 140))
    );
    assert_eq!(w.seg_word_own(2, 0), 0xAB);
    assert_eq!(v.seg_words(0), None);
    assert_eq!(v.seg_words(4), None);
    // Ladder edges: 10 and 140 are in, 9 and 141 are out; sides are separate.
    assert!(w.head(0, Tick(10), 1));
    assert!(w.head(1, Tick(140), 2));
    assert!(!w.head(0, Tick(9), 3));
    assert!(!w.head(1, Tick(141), 3));
    assert_eq!((v.head(0, Tick(10)), v.head(1, Tick(10))), (1, 0));
    assert_eq!((v.head(1, Tick(140)), v.head(0, Tick(140))), (2, 0));
    assert_eq!(v.head(0, Tick(9)), 0);
}

#[test]
fn arena_occupancy_bits_at_word_edges() {
    let mut a = Arena::new(cfg());
    let (w, v) = a.split().unwrap();
    // Offsets 63 and 64 straddle a bitmap word; 130 is the last tick (offset 130).
    for t in [73, 74, 140] {
        w.occ_set(0, Tick(t));
    }
    w.occ_set(1, Tick(10));
    w.occ_set(0, Tick(141)); // outside: ignored
    let on: Vec<u32> = (9..=141).filter(|t| v.occ(0, Tick(*t))).collect();
    assert_eq!(on, vec![73, 74, 140]);
    assert!(v.occ(1, Tick(10)) && !v.occ(0, Tick(10)));
}

#[test]
fn arena_acct_kill_owner_and_journal_ring() {
    let mut a = Arena::new(cfg());
    let (w, v) = a.split().unwrap();
    w.acct_kill(2, LaneSeq(9), Nanos(5));
    assert_eq!((v.acct_kill(2), v.acct_kill(1)), ((9, 5), (0, 0)));
    w.owner(4, join(77, 88));
    assert_eq!(v.owner(4), join(77, 88));
    assert_eq!(v.journal_len(), 4);
    for p in 0..6u64 {
        w.journal(p, [p, p + 10]);
    }
    // Positions wrap modulo 4: 4 and 5 overwrite 0 and 1.
    assert_eq!(
        (v.journal(0), v.journal(1), v.journal(2)),
        ([4, 14], [5, 15], [2, 12])
    );
    assert_eq!(v.journal(5), v.journal(1));
}
