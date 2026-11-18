//! `Bbo::replay_step` (05 §10 rows 4–5): a logged step is executed with the record's cut,
//! source, kind, `CONT` flag and `Rescan` band, and no clock. Expected values are worked out
//! by hand from 05 §8, or are the live run's own outputs (round trips).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_arguments
)]

mod harness;

use harness::*;
use vyrn_bbo::admit::FixedClock;
use vyrn_bbo::*;
use vyrn_types::*;

/// Live at now = 0: `BIG_DEADLINE` is on time, `LATE` is late by 16 ns (05 §8.2).
const LIVE: FixedClock = FixedClock(0);
const LATE: u32 = 0xFFFF_FFF0;

/// Runs steps live (logging each as a `ReplayStep`) or replays a log.
struct Drive {
    log: Vec<ReplayStep>,
    replay: bool,
    i: usize,
    prev: Cut,
}

impl Drive {
    fn live() -> Self {
        Self {
            log: Vec::new(),
            replay: false,
            i: 0,
            prev: [LaneSeq(0); MAX_LANES],
        }
    }
    fn replay(log: Vec<ReplayStep>) -> Self {
        Self {
            log,
            replay: true,
            i: 0,
            prev: [LaneSeq(0); MAX_LANES],
        }
    }
    fn step(&mut self, x: &mut Lanes<'_>, bbo: &mut Bbo) -> Seen {
        if self.replay {
            let rec = self.log[self.i];
            self.i += 1;
            return x.replay_ok(bbo, &rec);
        }
        let s = x.step(bbo, &LIVE);
        let rec = ReplayStep::from_log(&self.prev, &s.entry, &s.deltas).unwrap();
        assert_eq!(&rec.cut, bbo.cut(), "from_log rebuilds C_s from the deltas");
        self.prev = rec.cut;
        self.log.push(rec);
        s
    }
}

fn setup() -> (Bbo, Box<World>) {
    let bbo = Bbo::new(cfg());
    let w = World::new(&bbo.initial_snapshot());
    (bbo, w)
}

fn rest(
    d: &mut Drive,
    x: &mut Lanes<'_>,
    bbo: &mut Bbo,
    l: usize,
    ts: u64,
    side: Side,
    tick: u32,
    acct: u32,
) -> u32 {
    let (q, slot) = x.forward(l, ts, day(side), tick, 1, acct, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    // Earlier ops (a clamped cancel, a depletion) may take steps first.
    for _ in 0..4 {
        let s = d.step(x, bbo);
        if s.entry.src_lane_seq == LaneSeq(q) && usize::from(s.entry.src_lane.0) == l {
            assert_eq!(s.kind(), StepKind::Improve);
            x.apply_events();
            x.publish_cut();
            return slot;
        }
        x.apply_events();
        x.publish_cut();
    }
    panic!("source never ran")
}

/// Every step kind the live path decides on its own: Depletion, a Rescan capped twice
/// (CONT, CONT, rests), a Rescan whose cut is clamped after the taker's key, a forwarded Cross
/// with a CONT step, and a Shed.
fn scenario(d: &mut Drive) -> Vec<Seen> {
    let (mut bbo, mut w) = setup();
    let mut x = w.lanes();
    let bbo = &mut bbo;
    // Depletion: a bid of lane 2 rests, lane 1 keeps that snapshot, lane 2 cancels it.
    let b = rest(d, &mut x, bbo, 2, 1, Side::Buy, 105, 1);
    x.snap_ver[1] = Some(u32::try_from(x.snapshot().version).unwrap());
    x.cancel(2, b, 2);
    x.publish_cut();
    assert_eq!(d.step(&mut x, bbo).kind(), StepKind::Depletion);
    // 9 asks @ 102 and one @ 103; a stale batch buy of 20 @ 103 and a later cancel of the
    // ninth ask (key after the taker: clamped out of the Rescan's cut).
    let mut last = 0;
    for acct in 1..=9u32 {
        last = rest(
            d,
            &mut x,
            bbo,
            0,
            u64::from(acct) + 10,
            Side::Sell,
            102,
            acct,
        );
    }
    rest(d, &mut x, bbo, 0, 30, Side::Sell, 103, 10);
    x.join(1, 100, day(Side::Buy), 103, 20, 1);
    x.cancel(0, last, 200);
    x.publish_cut();
    for _ in 0..4 {
        d.step(&mut x, bbo);
        x.apply_events();
        x.publish_cut();
    }
    // Asks of 2 @ 110 and 2 @ 111; a forwarded buy of 3 @ 111: Cross, then CONT.
    for (ts, t) in [(300, 110), (301, 110), (302, 111), (303, 111)] {
        rest(d, &mut x, bbo, 0, ts, Side::Sell, t, 20);
    }
    x.forward(2, 400, day(Side::Buy), 111, 3, 2, 0, &[], BIG_DEADLINE);
    x.publish_cut();
    for _ in 0..2 {
        d.step(&mut x, bbo);
    }
    x.apply_events();
    x.publish_cut();
    // A late op: Shed live; replay sheds it from the record alone.
    x.forward(2, 500, day(Side::Sell), 90, 1, 2, 4, &[], LATE);
    x.publish_cut();
    d.step(&mut x, bbo);
    x.seen.clone()
}

#[test]
fn replaying_a_live_log_gives_the_same_bytes() {
    let mut live = Drive::live();
    let a = scenario(&mut live);
    let kinds: Vec<(StepKind, bool)> = live.log.iter().map(|r| (r.kind, r.cont)).collect();
    for want in [
        (StepKind::Depletion, false),
        (StepKind::Rescan, false),
        (StepKind::Rescan, true),
        (StepKind::Cross, false),
        (StepKind::Cross, true),
        (StepKind::Shed, false),
    ] {
        assert!(kinds.contains(&want), "scenario covers {want:?}: {kinds:?}");
    }
    let mut rp = Drive::replay(live.log.clone());
    let b = scenario(&mut rp);
    assert_eq!(rp.i, live.log.len());
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "step {i}: entry, deltas, events and TX packets");
    }
}

/// Lane 1 forwards a buy 1 @ 100 at ts 5, lane 2 a buy 1 @ 101 at ts 3.
fn two_bids(x: &mut Lanes<'_>) {
    x.forward(1, 5, day(Side::Buy), 100, 1, 1, 0, &[], BIG_DEADLINE);
    x.forward(2, 3, day(Side::Buy), 101, 1, 2, 0, &[], BIG_DEADLINE);
    x.publish_cut();
}

fn cut_of(v: &[u64]) -> Cut {
    let mut c = [LaneSeq(0); MAX_LANES];
    for (x, s) in c.iter_mut().zip(v) {
        *x = LaneSeq(*s);
    }
    c
}

fn fwd(kind: StepKind, lane: u8, q: u64, cont: bool, cut: &[u64]) -> ReplayStep {
    ReplayStep {
        kind,
        src: Some((LaneId(lane), LaneSeq(q))),
        cont,
        band: (Tick(0), Tick(0)),
        cut: cut_of(cut),
    }
}

#[test]
fn replay_takes_the_source_from_the_record_not_pick_source() {
    // Live, pick_source takes the smaller key: lane 2 (ts 3). A log from another schedule
    // names lane 1 first; replay follows it.
    let (mut bbo, mut w) = setup();
    let mut x = w.lanes();
    two_bids(&mut x);
    assert_eq!(x.step(&mut bbo, &LIVE).entry.src_lane, LaneId(2));

    let (mut bbo, mut w) = setup();
    let mut x = w.lanes();
    two_bids(&mut x);
    let s1 = x.replay_ok(&mut bbo, &fwd(StepKind::Improve, 1, 1, false, &[0, 1, 0]));
    assert_eq!(
        (s1.entry.src_lane, s1.entry.src_lane_seq),
        (LaneId(1), LaneSeq(1))
    );
    let rested: Vec<(usize, u32)> = s1
        .of(FillKind::Rested)
        .iter()
        .map(|(l, e)| (*l, e.tick.0))
        .collect();
    assert_eq!(rested, vec![(1, 100)]);
    assert_eq!(bbo.bounds(), (Tick(100), NO_ASK));
    let s2 = x.replay_ok(&mut bbo, &fwd(StepKind::Improve, 2, 1, false, &[0, 1, 1]));
    assert_eq!(s2.entry.src_lane, LaneId(2));
    assert_eq!(bbo.bounds(), (Tick(101), NO_ASK));
    assert_eq!(s2.entry.step, StepId(2));
}

#[test]
fn replay_takes_the_cut_from_the_record_not_step_cut() {
    // Lane 0 forwards an ask 1 @ 102 (rests). Lane 2 joins an ask 1 @ 103 behind it (local).
    // Lane 1 forwards a buy 2 @ 103. One level per step (D14): step 2 fills 1 @ 102 and the
    // buy is in flight; its CONT step 3 takes the next level. Live, step 3's cut holds lane
    // 2's join, so it fills 1 @ 103. A log whose step-3 cut leaves lane 2 at 0 hides that ask:
    // no level within 103, so the buy rests 1 @ 103: bid bound 103, and advance_bound raises
    // the ask bound past the limit to 104 (05 §8.5).
    let run = |replay: bool| {
        let (mut bbo, mut w) = setup();
        let mut x = w.lanes();
        let go = |x: &mut Lanes<'_>, bbo: &mut Bbo, r: ReplayStep| {
            if replay {
                x.replay_ok(bbo, &r)
            } else {
                x.step(bbo, &LIVE)
            }
        };
        x.forward(0, 1, day(Side::Sell), 102, 1, 1, 0, &[], BIG_DEADLINE);
        x.publish_cut();
        let s1 = go(
            &mut x,
            &mut bbo,
            fwd(StepKind::Improve, 0, 1, false, &[1, 0, 0]),
        );
        assert_eq!(s1.kind(), StepKind::Improve);
        x.apply_events();
        x.join(2, 10, day(Side::Sell), 103, 1, 2);
        x.forward(1, 20, day(Side::Buy), 103, 2, 1, 0, &[], BIG_DEADLINE);
        x.publish_cut();
        let s2 = go(
            &mut x,
            &mut bbo,
            fwd(StepKind::Cross, 1, 1, false, &[1, 1, 0]),
        );
        assert_eq!(
            s2.fills(),
            vec![(0, LIQ_MAKER, 102, 1), (1, LIQ_TAKER, 102, 1)]
        );
        assert!(s2.of(FillKind::Rested).is_empty(), "in flight");
        let s3 = go(
            &mut x,
            &mut bbo,
            fwd(StepKind::Cross, 1, 1, true, &[1, 1, 0]),
        );
        assert_eq!(s3.entry.flags & STEP_CONT, STEP_CONT);
        (bbo.bounds(), s3)
    };
    let (_, live) = run(false);
    assert_eq!(
        live.fills(),
        vec![(2, LIQ_MAKER, 103, 1), (1, LIQ_TAKER, 103, 1)]
    );
    assert_eq!(live.entry.n_delta, 1, "live cut moved lane 2 to its join");

    let (bounds, s) = run(true);
    assert_eq!(s.kind(), StepKind::Cross);
    assert!(s.fills().is_empty());
    let rested: Vec<(usize, u32, u32)> = s
        .of(FillKind::Rested)
        .iter()
        .map(|(l, e)| (*l, e.tick.0, e.qty))
        .collect();
    assert_eq!(rested, vec![(1, 103, 1)]);
    assert_eq!(s.entry.n_delta, 0, "the record's cut, not step_cut's");
    assert_eq!(bounds, (Tick(103), Tick(104)));
}

#[test]
fn replay_sheds_from_the_record_without_a_clock() {
    // The op is on time at any clock (deadline far ahead); the record says Shed: Reject BUSY,
    // nothing applied (05 §10: SHED is read, the clock is not).
    let (mut bbo, mut w) = setup();
    let mut x = w.lanes();
    x.forward(1, 1, day(Side::Buy), 100, 1, 1, 3, &[], BIG_DEADLINE);
    x.publish_cut();
    let s = x.replay_ok(&mut bbo, &fwd(StepKind::Shed, 1, 1, false, &[0, 0, 0]));
    assert_eq!(s.kind(), StepKind::Shed);
    assert!(matches!(
        s.role(ROLE_TAKER)[0][0],
        Record::Reject {
            index: 3,
            reason: RejectReason::Busy,
            ..
        }
    ));
    assert_eq!(bbo.bounds(), (NO_BID, NO_ASK));
}

#[test]
fn replay_refuses_records_that_cannot_come_next() {
    let refuse = |recs: &[ReplayStep], want: Diverge| {
        let (mut bbo, mut w) = setup();
        let mut x = w.lanes();
        two_bids(&mut x);
        let (last, ok) = recs.split_last().unwrap();
        for r in ok {
            x.replay_ok(&mut bbo, r);
        }
        assert_eq!(x.replay(&mut bbo, last), Err(want), "{last:?}");
        assert_eq!(
            x.replay(&mut bbo, last),
            Ok(Poll::Fault),
            "a refused record faults the core"
        );
    };
    let first = fwd(StepKind::Improve, 1, 1, false, &[0, 1, 0]);
    // Lane 1's head is seq 1, not 2; lane 0 forwarded nothing.
    refuse(
        &[fwd(StepKind::Improve, 1, 2, false, &[0, 2, 0])],
        Diverge::Source,
    );
    refuse(
        &[fwd(StepKind::Improve, 0, 1, false, &[1, 0, 0])],
        Diverge::Source,
    );
    // A cut below C_{s−1}, and a cut entry for lane 3 of a 3-lane book.
    refuse(
        &[first, fwd(StepKind::Improve, 2, 1, false, &[0, 0, 1])],
        Diverge::Cut,
    );
    refuse(
        &[fwd(StepKind::Improve, 1, 1, false, &[0, 1, 0, 1])],
        Diverge::Cut,
    );
    // Logged Cross, decided Improve (the buy rests); a CONT step with nothing in flight; a
    // Control step with no command queued; a Rescan with a source.
    refuse(
        &[fwd(StepKind::Cross, 1, 1, false, &[0, 1, 0])],
        Diverge::Kind,
    );
    refuse(
        &[fwd(StepKind::Improve, 1, 1, true, &[0, 1, 0])],
        Diverge::Source,
    );
    let none = |kind| ReplayStep {
        kind,
        src: None,
        cont: false,
        band: (Tick(1), Tick(200)),
        cut: cut_of(&[0, 1, 0]),
    };
    refuse(&[none(StepKind::Control)], Diverge::Kind);
    refuse(
        &[fwd(StepKind::Rescan, 1, 1, false, &[0, 1, 0])],
        Diverge::Kind,
    );
    // from_log: unknown kind, wrong delta count, a delta lane ≥ MAX_LANES.
    let prev = [LaneSeq(0); MAX_LANES];
    let e = StepEntry {
        kind: 1,
        n_delta: 1,
        ..StepEntry::default()
    };
    let d = CutDelta {
        lane: LaneId(1),
        seq: LaneSeq(4),
    };
    assert_eq!(
        ReplayStep::from_log(&prev, &e, &[d]).unwrap().cut[1],
        LaneSeq(4)
    );
    assert!(ReplayStep::from_log(&prev, &StepEntry { kind: 10, ..e }, &[d]).is_none());
    assert!(ReplayStep::from_log(&prev, &e, &[]).is_none());
    let far = CutDelta {
        lane: LaneId(64),
        ..d
    };
    assert!(ReplayStep::from_log(&prev, &e, &[far]).is_none());
}

#[test]
fn replay_keeps_the_bounds_the_band_test_sets() {
    // Lane 2 rests a bid 105; lane 1 keeps that snapshot; lane 2 cancels it (Depletion: B =
    // NO_BID). Lane 1, stale, joins a bid 1 @ 104 locally (behind its 105). The next step's
    // envelope over lane 1's versions raises B to 105 (05 §8.6), so lane 0's forwarded sell 1
    // @ 100 searches down from 105 and fills the 104 bid. A replay that kept B = NO_BID would
    // find no bid and rest the sell at 100, crossed.
    let run = |d: &mut Drive| {
        let (mut bbo, mut w) = setup();
        let mut x = w.lanes();
        let b = rest(d, &mut x, &mut bbo, 2, 1, Side::Buy, 105, 1);
        x.snap_ver[1] = Some(u32::try_from(x.snapshot().version).unwrap());
        x.cancel(2, b, 2);
        x.publish_cut();
        assert_eq!(d.step(&mut x, &mut bbo).kind(), StepKind::Depletion);
        assert_eq!(bbo.bounds().0, NO_BID);
        x.join(1, 3, day(Side::Buy), 104, 1, 1);
        x.forward(0, 4, day(Side::Sell), 100, 1, 2, 0, &[], BIG_DEADLINE);
        x.publish_cut();
        let s = d.step(&mut x, &mut bbo);
        (s, bbo.bounds())
    };
    let mut live = Drive::live();
    let (a, ab) = run(&mut live);
    let (b, bb) = run(&mut Drive::replay(live.log.clone()));
    for (s, bounds) in [(&a, ab), (&b, bb)] {
        assert_eq!(s.kind(), StepKind::Cross);
        assert_eq!(
            s.fills(),
            vec![(1, LIQ_MAKER, 104, 1), (0, LIQ_TAKER, 104, 1)]
        );
        assert!(s.of(FillKind::Rested).is_empty());
        assert_eq!(bounds, (Tick(104), NO_ASK));
    }
    assert_eq!(a, b);
}
