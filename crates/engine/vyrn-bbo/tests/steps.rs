//! Conformance scenarios for the BBO core (05 §3.3, §5, §8; 01 §14.10). Every expected value is
//! worked out by hand from the spec rules quoted in each test, not read back from the code.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_arguments
)]

mod harness;

use harness::*;
use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::*;
use vyrn_types::*;

const CLK: NeverLate = NeverLate;

/// Forward a `New` that rests (an Improve step), then let its lane write the position (B1).
fn rest(
    x: &mut Lanes<'_>,
    bbo: &mut Bbo,
    l: usize,
    ts: u64,
    side: Side,
    tick: u32,
    qty: u32,
    acct: u32,
) -> u32 {
    let (_, slot) = x.forward(l, ts, day(side), tick, qty, acct, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s = x.step(bbo, &CLK);
    assert_eq!(
        s.kind(),
        StepKind::Improve,
        "a resting order is an Improve step"
    );
    x.apply_events();
    x.publish_cut();
    slot
}

/// Steps until one has `lane` as its source (a Rescan or Depletion may come first).
fn step_src(x: &mut Lanes<'_>, bbo: &mut Bbo, lane: usize) -> Seen {
    for _ in 0..8 {
        let s = x.step(bbo, &CLK);
        if s.entry.src_lane_seq.0 != 0 && usize::from(s.entry.src_lane.0) == lane {
            return s;
        }
    }
    panic!("source never ran")
}

fn setup(epoch: u32) -> (Bbo, Box<World>) {
    let mut c = cfg();
    c.epoch = Epoch(epoch);
    let bbo = Bbo::new(c);
    let w = World::new(&bbo.initial_snapshot());
    (bbo, w)
}

#[test]
fn makers_fill_in_key_order_whatever_the_arrival_order() {
    // 05 §5.4: the level FIFO is ordered by (prio_ts, rank_e(lane)). Lane 2's ask (ts 5) is older
    // than lane 0's (ts 10), so a buy of 5 takes 4 from lane 2 first, then 1 from lane 0, in
    // both arrival orders.
    for lane0_first in [true, false] {
        let (mut bbo, mut w) = setup(0);
        let mut x = w.lanes();
        let (a, b) = ((0, 10, 3), (2, 5, 4));
        for (l, ts, q) in if lane0_first { [a, b] } else { [b, a] } {
            rest(&mut x, &mut bbo, l, ts, Side::Sell, 102, q, 1);
        }
        x.forward(1, 20, day(Side::Buy), 102, 5, 1, 0, &[], BIG_DEADLINE);
        x.publish_cut();
        let s = step_src(&mut x, &mut bbo, 1);
        assert_eq!(s.kind(), StepKind::Cross);
        assert_eq!(
            s.fills(),
            vec![
                (2, LIQ_MAKER, 102, 4),
                (0, LIQ_MAKER, 102, 1),
                (1, LIQ_TAKER, 102, 5)
            ]
        );
        let ords: Vec<u32> = s
            .of(FillKind::Fill)
            .iter()
            .map(|(_, e)| e.ordinal)
            .collect();
        assert_eq!(
            ords,
            vec![0, 1, 1],
            "makers 0, 1; the taker's level record carries the last ordinal"
        );
        assert_eq!(bbo.bounds().1, Tick(102), "lane 0 keeps 2 at 102");
    }
}

#[test]
fn equal_timestamps_break_on_rank_e() {
    // 05 §3.2: rank_e(l) = (l + e) mod N_LANES, N = 3. Epoch 0: lane 0 rank 0 < lane 2 rank 2.
    // Epoch 1: lane 0 rank 1 > lane 2 rank 0.
    for (epoch, first) in [(0u32, 0usize), (1, 2)] {
        let (mut bbo, mut w) = setup(epoch);
        let mut x = w.lanes();
        rest(&mut x, &mut bbo, 0, 7, Side::Sell, 102, 1, 1);
        rest(&mut x, &mut bbo, 2, 7, Side::Sell, 102, 1, 1);
        x.forward(1, 9, day(Side::Buy), 102, 1, 1, 0, &[], BIG_DEADLINE);
        x.publish_cut();
        let s = step_src(&mut x, &mut bbo, 1);
        assert_eq!(s.fills()[0].0, first, "epoch {epoch}");
    }
}

#[test]
fn a_sweep_stops_at_the_level_boundary_and_continues() {
    // D14: one level per step. Asks 2 @ 102 and 2 @ 103; a buy of 3 @ 104 fills 2 @ 102 in
    // step s, then 1 @ 103 in step s + 1 with the CONT flag and the same source.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    rest(&mut x, &mut bbo, 0, 1, Side::Sell, 102, 2, 1);
    rest(&mut x, &mut bbo, 0, 2, Side::Sell, 103, 2, 1);
    let (q, _) = x.forward(1, 5, day(Side::Buy), 104, 3, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s1 = step_src(&mut x, &mut bbo, 1);
    assert_eq!(
        s1.fills(),
        vec![(0, LIQ_MAKER, 102, 2), (1, LIQ_TAKER, 102, 2)]
    );
    assert_eq!(s1.entry.flags & STEP_CONT, 0);
    let s2 = x.step(&mut bbo, &CLK);
    assert_eq!(s2.kind(), StepKind::Cross);
    assert_eq!(s2.entry.flags & STEP_CONT, STEP_CONT);
    assert_eq!(s2.entry.src_lane_seq, LaneSeq(q));
    assert_eq!(
        s2.entry.step.0,
        s1.entry.step.0 + 1,
        "no other step between continuations"
    );
    assert_eq!(
        s2.fills(),
        vec![(0, LIQ_MAKER, 103, 1), (1, LIQ_TAKER, 103, 1)]
    );
    assert!(s2.of(FillKind::Rested).is_empty(), "fully filled");
}

#[test]
fn a_sweep_stops_after_eight_fills() {
    // ENG_STEP_FILLS = 8: nine 1-lot asks at one level; the ninth fill is in the continuation.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    for i in 0..9u64 {
        rest(
            &mut x,
            &mut bbo,
            usize::try_from(i % 2).unwrap() * 2,
            i + 1,
            Side::Sell,
            102,
            1,
            1,
        );
    }
    x.forward(1, 50, day(Side::Buy), 102, 9, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s1 = step_src(&mut x, &mut bbo, 1);
    let makers = s1.fills().iter().filter(|f| f.1 == LIQ_MAKER).count();
    assert_eq!(makers, 8);
    assert_eq!(s1.entry.n_fills, 8);
    let s2 = x.step(&mut bbo, &CLK);
    assert_eq!(s2.entry.flags & STEP_CONT, STEP_CONT);
    assert_eq!(
        s2.fills(),
        vec![(0, LIQ_MAKER, 102, 1), (1, LIQ_TAKER, 102, 1)]
    );
}

#[test]
fn shed_at_deadline_plus_one_not_at_deadline() {
    // 05 §8.2: late iff (now − deadline) as i32 > 0. Equal is on time.
    assert!(!admit::is_late(100, 100));
    assert!(admit::is_late(101, 100));
    assert!(!admit::is_late(99, 100));
    assert!(admit::is_late(4, u32::MAX - 5), "wraps across 2^32");
    for (now, shed) in [(100u64, false), (101, true)] {
        let (mut bbo, mut w) = setup(0);
        let mut x = w.lanes();
        x.forward(1, 1, day(Side::Buy), 100, 1, 1, 3, &[], 100);
        x.publish_cut();
        let s = x.step(&mut bbo, &FixedClock(now));
        if shed {
            assert_eq!(s.kind(), StepKind::Shed);
            let recs = s.role(ROLE_TAKER);
            assert!(matches!(
                recs[0][0],
                Record::Reject {
                    index: 3,
                    reason: RejectReason::Busy,
                    ..
                }
            ));
            assert_eq!(bbo.bounds().0, NO_BID, "nothing applied");
        } else {
            assert_eq!(s.kind(), StepKind::Improve);
            assert_eq!(bbo.bounds().0, Tick(100));
        }
    }
}

#[test]
fn dependency_record_index_is_source_index_minus_back() {
    // Pinned behaviour (spec follow-up F2): FwdDep has no message index, so the dependency's
    // record uses source index − back. Packet A: [join ask 102, buy 103] → dep index 1 − 1 = 0
    // (right). Packet B: [join ask 102, heartbeat, buy 103]: the heartbeat takes no LaneSeq, so
    // back is still 1 and the record says index 2 − 1 = 1, the heartbeat's index (wrong until
    // 05 adds the index to FwdDep).
    for (src_index, want) in [(1u8, 0u8), (2, 1)] {
        let (mut bbo, mut w) = setup(0);
        let mut x = w.lanes();
        let d = x.dep_join(0, 3, day(Side::Sell), 102, 1, 1, 1);
        x.forward(
            0,
            3,
            day(Side::Buy),
            103,
            1,
            1,
            src_index,
            &[d],
            BIG_DEADLINE,
        );
        x.publish_cut();
        let s = step_src(&mut x, &mut bbo, 0);
        let deps = s.role(ROLE_DEPS);
        assert_eq!(deps.len(), 1);
        assert!(
            matches!(deps[0][0], Record::Ack { index, tick: Tick(102), .. } if index == want),
            "{:?}",
            deps[0]
        );
        // STP none: the source trades with its own dependency, a Pend leaf (05 §3.7 (4)).
        assert_eq!(
            s.fills(),
            vec![(0, LIQ_MAKER, 102, 1), (0, LIQ_TAKER, 102, 1)]
        );
        assert!(
            matches!(
                deps[0][1],
                Record::Fill {
                    index: INDEX_MAKER,
                    ..
                }
            ),
            "maker fill follows the Ack"
        );
    }
}

#[test]
fn seventeen_reductions_leave_the_order_tradable() {
    // 05 §4.4: each Reduce writes a KeepPrio version at the same position. 100 − 17 = 83 open.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    let mut v = rest(&mut x, &mut bbo, 0, 1, Side::Sell, 102, 100, 1);
    for i in 0..17u64 {
        x.seq[0] += 1;
        let q = LaneSeq(x.seq[0]);
        v = x.book.reduce(lid(0), v, 1, q, Nanos(10 + i));
    }
    x.publish_cut();
    x.forward(1, 100, day(Side::Buy), 102, 100, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s = step_src(&mut x, &mut bbo, 1);
    assert_eq!(
        s.fills(),
        vec![(0, LIQ_MAKER, 102, 83), (1, LIQ_TAKER, 102, 83)]
    );
    assert_eq!(
        s.of(FillKind::Fill)[0].1.vslot,
        v,
        "the newest version traded"
    );
}

#[test]
fn a_refused_replace_stays_refused_through_its_reductions() {
    // 05 §8.5 replace_ok: a NewPrio version whose predecessor had open 0 never rests. Lane 0's
    // ask of 10 is filled by the BBO before lane 0 learns it; lane 0 then replaces it to 20 and
    // reduces by 1. The order must not trade 19 (or 9) again.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    let old = rest(&mut x, &mut bbo, 0, 1, Side::Sell, 102, 10, 1);
    x.forward(1, 2, day(Side::Buy), 102, 10, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    assert_eq!(step_src(&mut x, &mut bbo, 1).fills().len(), 2);
    // Lane 0, not yet applying those fills: Replace (new priority) at op q, then Reduce.
    x.seq[0] += 1;
    let q = LaneSeq(x.seq[0]);
    let nv = x.book.replace_slot(lid(0), old, q, Nanos(3), Tick(102), 20);
    x.book.tombstone(lid(0), old, q, Nanos(3));
    x.book.place(lid(0), nv);
    x.book.push_journal(
        lid(0),
        JEnt {
            seq: q,
            tick: Tick(102),
            slot: nv,
            kind: JKind::NewPrio,
        },
    );
    x.seq[0] += 1;
    x.book.reduce(lid(0), nv, 1, LaneSeq(x.seq[0]), Nanos(4));
    x.publish_cut();
    x.forward(1, 9, day(Side::Buy), 102, 20, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s = step_src(&mut x, &mut bbo, 1);
    assert!(s.fills().is_empty(), "{:?}", s.fills());
    assert_eq!(s.kind(), StepKind::Improve);
    assert_eq!(s.of(FillKind::Rested).len(), 1);
}

#[test]
fn stp_cancel_oldest_without_trades_logs_only_published_packets() {
    // Eight own asks, a CancelOldest buy: eight STP kills fill the step cap (follow-up F3), no
    // trade, so the source packet is empty. n_tx must count exactly what reaches the TxRings.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    for i in 0..8 {
        rest(&mut x, &mut bbo, 0, i + 1, Side::Sell, 102, 1, 1);
    }
    let f = OrderFlags::new(Side::Buy, Tif::Day, false, Stp::CancelOldest);
    x.forward(0, 20, f, 102, 1, 1, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    let s = step_src(&mut x, &mut bbo, 0);
    assert_eq!(s.of(FillKind::Out).len(), 8);
    assert!(s.fills().is_empty());
    assert_eq!(usize::from(s.entry.n_tx), s.tx.len());
    assert_eq!(s.tx.len(), 1, "one maker packet for the one session");
    let c = x.step(&mut bbo, &CLK);
    assert_eq!(c.entry.flags & STEP_CONT, STEP_CONT);
    assert_eq!(
        c.of(FillKind::Rested).len(),
        1,
        "nothing left to cross: it rests"
    );
    assert_eq!(bbo.bounds().0, Tick(102));
}

/// Lane 2 rests a bid at 105 and cancels it; the BBO depletes the bound. Lane 1 loaded the
/// bid-105 snapshot and never refreshes it, so every later op of lane 1 is suspect at
/// [min ask, 105] (05 §8.6).
fn stale_bid_105(x: &mut Lanes<'_>, bbo: &mut Bbo) {
    let b = rest(x, bbo, 2, 1, Side::Buy, 105, 1, 1);
    x.snap_ver[1] = Some(u32::try_from(x.snapshot().version).unwrap());
    x.cancel(2, b, 2);
    x.publish_cut();
    let d = x.step(bbo, &CLK);
    assert_eq!(d.kind(), StepKind::Depletion);
    assert_eq!(bbo.bounds().0, NO_BID);
}

#[test]
fn a_rescan_stp_tells_the_batch_taker_from_the_maker_it_kills() {
    // Lane 1, account 1: an ask of 1 @ 102 rests; then a local CancelBoth join buys 1 @ 102
    // against the stale snapshot. The Rescan meets its own ask: both end with Out STP (05 §2.4)
    // on the same lane and account. The lane emits the batch taker's record itself and must
    // not emit the maker's (the fill TX core sent it), so the events differ in `liq`.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    stale_bid_105(&mut x, &mut bbo);
    let maker = rest(&mut x, &mut bbo, 1, 10, Side::Sell, 102, 1, 1);
    let f = OrderFlags::new(Side::Buy, Tif::Day, false, Stp::CancelBoth);
    let taker = x.join(1, 20, f, 102, 1, 1);
    x.publish_cut();
    let r = x.step(&mut bbo, &CLK);
    assert_eq!(r.kind(), StepKind::Rescan);
    let outs: Vec<(usize, u32, u8, u16)> = r
        .of(FillKind::Out)
        .iter()
        .map(|(l, e)| (*l, e.vslot, e.liq, e.cause))
        .collect();
    assert_eq!(
        outs,
        vec![
            (1, maker, LIQ_MAKER, OUT_STP),
            (1, taker, LIQ_TAKER, OUT_STP)
        ]
    );
    assert!(r.fills().is_empty());
    let maker_recs = r.role(ROLE_MAKER);
    assert_eq!(
        maker_recs.len(),
        1,
        "only the maker's Out goes to the TX core"
    );
    assert!(matches!(
        maker_recs[0][..],
        [Record::Out {
            index: INDEX_MAKER,
            cause: OUT_STP,
            ..
        }]
    ));
}

#[test]
fn a_rescan_taker_against_thirteen_sessions_is_capped_not_a_fault() {
    // A lane that classified against an old snapshot (bid 105) joins a buy of 13 @ 102 locally.
    // The band test sees max bid 105 ≥ min ask 102 and runs a Rescan (05 §8.6). The batch
    // taker meets 13 one-lot asks of 13 sessions: 8 fills, then 5 in a continuation.
    let (mut bbo, mut w) = setup(0);
    let mut x = w.lanes();
    stale_bid_105(&mut x, &mut bbo);
    for acct in 1..=13u32 {
        rest(
            &mut x,
            &mut bbo,
            0,
            u64::from(acct) + 10,
            Side::Sell,
            102,
            1,
            acct,
        );
    }
    x.join(1, 100, day(Side::Buy), 102, 13, 1);
    x.publish_cut();
    let r1 = x.step(&mut bbo, &CLK);
    assert_eq!(r1.kind(), StepKind::Rescan);
    assert_eq!((r1.entry.band_lo, r1.entry.band_hi), (Tick(102), Tick(105)));
    let m1 = r1.fills().iter().filter(|f| f.1 == LIQ_MAKER).count();
    assert_eq!(m1, 8);
    assert!(r1.fills().contains(&(1, LIQ_TAKER, 102, 8)));
    let r2 = x.step(&mut bbo, &CLK);
    assert_eq!(r2.kind(), StepKind::Rescan);
    assert_eq!(r2.entry.flags & STEP_CONT, STEP_CONT);
    assert!(r2.fills().contains(&(1, LIQ_TAKER, 102, 5)));
    assert_eq!(
        bbo.bounds(),
        (NO_BID, NO_ASK),
        "both sides empty after 13 fills"
    );
}

#[test]
fn step_cut_follows_05_3_3() {
    // 05 §3.5: K = {3: 42, 7: 91}, source (3, 43), h[3] = 43, h' = ∞, a = 42 → C[3] = 42,
    // C[7] = 91.
    let mut k = [LaneSeq(0); MAX_LANES];
    k[3] = LaneSeq(42);
    k[7] = LaneSeq(91);
    let mut floor = [None; MAX_LANES];
    floor[3] = Some(LaneSeq(43));
    let src = SrcRule {
        lane: 3,
        q: LaneSeq(43),
        a: LaneSeq(42),
        next_floor: None,
    };
    let c = step_cut(&[LaneSeq(0); MAX_LANES], &k, &floor, Some(src));
    assert_eq!((c[3], c[7]), (LaneSeq(42), LaneSeq(91)));
    // Non-source lane, floor 43, K 50: clamped to h − 1 = 42 (not 43).
    let mut k2 = k;
    k2[3] = LaneSeq(50);
    let c2 = step_cut(&[LaneSeq(0); MAX_LANES], &k2, &floor, None);
    assert_eq!(c2[3], LaneSeq(42));
    // Monotone: a lower K never lowers the cut.
    let mut prev = [LaneSeq(0); MAX_LANES];
    prev[7] = LaneSeq(95);
    assert_eq!(step_cut(&prev, &k, &floor, None)[7], LaneSeq(95));
    // Source rule: a above K lets the pass barriers in (min(max(40, 42), ∞, 43) = 42); h' = 42
    // clamps to 41.
    k[3] = LaneSeq(40);
    assert_eq!(
        step_cut(&[LaneSeq(0); MAX_LANES], &k, &floor, Some(src))[3],
        LaneSeq(42)
    );
    let src2 = SrcRule {
        next_floor: Some(LaneSeq(42)),
        ..src
    };
    assert_eq!(
        step_cut(&[LaneSeq(0); MAX_LANES], &k, &floor, Some(src2))[3],
        LaneSeq(41)
    );
}
