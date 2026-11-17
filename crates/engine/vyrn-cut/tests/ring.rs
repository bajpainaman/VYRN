//! Ring unit tests: FIFO order, back-pressure, all-or-nothing batches, broadcast (05 §4.12).
#![cfg(not(loom))]
#![allow(clippy::unwrap_used)]

use vyrn_cut::{Hw, Ring, Sim};

type R = Ring<u32, 4, 1, Hw>;

#[test]
fn fifo_full_and_empty() {
    let mut ring = R::new(&Hw);
    let Some((mut p, [mut c])) = ring.split() else {
        panic!("first split")
    };
    assert_eq!(c.pop(&Hw), None);
    for v in 0..4 {
        assert_eq!(p.push(&Hw, v), Ok(()));
    }
    assert_eq!(p.push(&Hw, 9), Err(9), "full is back-pressure");
    assert_eq!(c.pop(&Hw), Some(0));
    assert_eq!(p.push(&Hw, 4), Ok(()));
    for v in 1..5 {
        assert_eq!(c.pop(&Hw), Some(v));
    }
    assert_eq!(c.pop(&Hw), None);
}

#[test]
fn split_runs_once() {
    let mut ring = R::new(&Hw);
    assert!(ring.split().is_some());
    assert!(ring.split().is_none());
}

#[test]
fn push_all_is_all_or_nothing() {
    let mut ring = R::new(&Hw);
    let Some((mut p, [mut c])) = ring.split() else {
        panic!("first split")
    };
    assert!(p.push_all(&Hw, &[1, 2, 3]));
    assert!(!p.push_all(&Hw, &[4, 5]), "only one slot is free");
    assert_eq!(p.pushed(), 3);
    assert!(p.push_all(&Hw, &[4]));
    assert_eq!([c.pop(&Hw), c.pop(&Hw)], [Some(1), Some(2)]);
}

#[test]
fn broadcast_frees_a_slot_only_when_every_consumer_passed_it() {
    let mut ring = Ring::<u8, 2, 2, Hw>::new(&Hw);
    let Some((mut p, [mut a, mut b])) = ring.split() else {
        panic!("first split")
    };
    assert!(p.push_all(&Hw, &[1, 2]));
    assert_eq!(a.pop(&Hw), Some(1));
    assert_eq!(p.push(&Hw, 3), Err(3), "consumer b still holds entry 0");
    assert_eq!(b.pop(&Hw), Some(1));
    assert_eq!(p.push(&Hw, 3), Ok(()));
    assert_eq!(
        [a.pop(&Hw), a.pop(&Hw), a.pop(&Hw)],
        [Some(2), Some(3), None]
    );
    assert_eq!([b.pop(&Hw), b.pop(&Hw)], [Some(2), Some(3)]);
}

#[test]
fn sim_delays_the_tail_but_never_loses_an_entry() {
    let sim = Sim::new(7, 100);
    let mut ring = Ring::<u32, 4, 1, Sim>::new(&sim);
    let Some((mut p, [mut c])) = ring.split() else {
        panic!("first split")
    };
    assert_eq!(p.push(&sim, 5), Ok(()));
    let early = c.pop(&sim);
    sim.advance_to(100);
    let late = if early.is_none() { c.pop(&sim) } else { early };
    assert_eq!(late, Some(5));
    assert_eq!(c.popped(), 1);
}
