//! Conformance suite for vyrn-risk. Every expected value is derived from the spec text
//! (spec/10-accounts-risk-md.md, spec/04-protocol.md), by hand or with the arithmetic quoted in
//! the comment, never from the implementation. Each reject path is tested on both sides of its
//! boundary.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use vyrn_risk::consts::*;
use vyrn_risk::{
    AcctRisk, AcctState, BookAcc, BookBal, BookSpec, CancelKind, Fault, FeeRates, FillKind, Gcra,
    LaneBuckets, NewOrder, OrderRisk, Phase, Reject, Risk, Route, SessionBuckets, Settle, Side,
    Snapshot, Tif, ctl,
};
use vyrn_types::{AccountId, Nanos, Qty, RejectReason as R, Tick};

/// One account in one book of one lane, with the defaults of 10 §3.4, §3.8 and tier 1 of §5.2.
struct Fx {
    acct: AcctRisk,
    sess: SessionBuckets,
    bal: BookBal,
    lane: LaneBuckets,
    book: BookAcc,
    spec: BookSpec,
    snap: Snapshot,
    now: Nanos,
    slot_free: bool,
}

/// Tier 1 of 10 §5.2 (taker 300, maker 50), auction 100, message fees 8 and 15 (10 §5.3).
fn tier1() -> FeeRates {
    FeeRates::new(300, 50, 100, 8, 15).unwrap()
}

impl Fx {
    fn new() -> Self {
        let mut acct = AcctRisk::new(AccountId(7), AccountId(7));
        acct.fees = tier1();
        Self {
            acct,
            sess: SessionBuckets::default(),
            bal: BookBal {
                quote_free: 1_000_000_000_000_000,
                base_free: 1_000_000,
                ..BookBal::default()
            },
            lane: LaneBuckets::dedicated(),
            book: BookAcc::default(),
            // µUSD book of the 10 §5.4 worked example: tick_size 10, band 500 bps.
            spec: BookSpec::new(10, Tick(1), Tick(1_000_000), 500).unwrap(),
            snap: Snapshot {
                halted: false,
                phase: Phase::Continuous,
                bid: Tick(99_000),
                ask: Tick(100_000),
                ref_tick: Tick(99_500),
            },
            now: Nanos(1_000_000_000),
            slot_free: true,
        }
    }

    fn risk(&mut self) -> Risk<'_> {
        Risk {
            acct: &mut self.acct,
            sess: &mut self.sess,
            bal: &mut self.bal,
            lane: &mut self.lane,
            book: &mut self.book,
            spec: &self.spec,
            snap: &self.snap,
            now: self.now,
            slot_free: self.slot_free,
        }
    }

    fn new_order(&mut self, m: NewOrder, route: Route) -> Result<OrderRisk, Reject> {
        self.risk().check_new(&m, route)
    }

    fn settle(&mut self) -> Settle<'_> {
        Settle {
            fees: &self.acct.fees,
            bal: &mut self.bal,
            book: &mut self.book,
            tick_size: self.spec.tick_size,
        }
    }
}

fn day(side: Side, tick: u32, qty: u32) -> NewOrder {
    NewOrder {
        side,
        tif: Tif::Day,
        post_only: false,
        tick: Tick(tick),
        qty: Qty(qty),
    }
}

fn buy(tick: u32, qty: u32) -> NewOrder {
    day(Side::Buy, tick, qty)
}

fn sell(tick: u32, qty: u32) -> NewOrder {
    day(Side::Sell, tick, qty)
}

fn rj(reason: R, detail: u32) -> Result<OrderRisk, Reject> {
    Err(Reject { reason, detail })
}

fn reason(r: Result<OrderRisk, Reject>) -> Option<(R, u32)> {
    r.err().map(|e| (e.reason, e.detail))
}

// ---------------------------------------------------------------- M1: MSG buckets (04 §9.1)

#[test]
fn m1_session_msg_bucket_keeps_a_quarter_for_cancels() {
    let mut f = Fx::new();
    // Burst 8, keep 2: a New may take 6 tokens at one instant, the 7th is RATE_LIMIT 2.
    f.sess.msg = Gcra::new(100, 8);
    for _ in 0..6 {
        assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
    }
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RateLimit, 2))
    );
    // The reserve is the cancels': two more cancels pass, a third does not.
    assert_eq!(f.risk().check_cancel(CancelKind::Cancel), Ok(()));
    assert_eq!(f.risk().check_cancel(CancelKind::Reduce), Ok(()));
    assert_eq!(
        f.risk().check_cancel(CancelKind::Cancel),
        Err(Reject {
            reason: R::RateLimit,
            detail: 2
        })
    );
    // One period later one token is back.
    f.now = Nanos(f.now.0 + 100);
    assert_eq!(f.risk().check_cancel(CancelKind::Cancel), Ok(()));
}

#[test]
fn m1_account_msg_bucket_is_detail_5_and_charges_neither_on_refusal() {
    let mut f = Fx::new();
    f.acct.buckets.msg = Gcra::new(100, 4); // keep 1: three News.
    for _ in 0..3 {
        assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
    }
    let sess_before = f.sess.msg;
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RateLimit, 5))
    );
    assert_eq!(f.sess.msg, sess_before, "both or neither");
}

#[test]
fn cancel_all_costs_sixteen_msg_tokens() {
    let mut f = Fx::new();
    f.sess.msg = Gcra::new(100, 16);
    assert_eq!(f.risk().check_cancel(CancelKind::CancelAll), Ok(()));
    let mut g = Fx::new();
    g.sess.msg = Gcra::new(100, 15);
    assert_eq!(
        g.risk().check_cancel(CancelKind::CancelAll),
        Err(Reject {
            reason: R::RateLimit,
            detail: 2
        })
    );
}

#[test]
fn cancels_pass_halts_kills_and_empty_balances() {
    // 10 §3.7 decision 1: cancels are always accepted.
    let mut f = Fx::new();
    f.acct.state = AcctState::Killed;
    f.snap.halted = true;
    f.bal = BookBal::default();
    assert_eq!(f.risk().check_cancel(CancelKind::Cancel), Ok(()));
    assert_eq!(f.risk().check_cancel(CancelKind::CancelAll), Ok(()));
}

// ---------------------------------------------------------------- V10: PKT buckets

#[test]
fn v10_packet_bucket_session_then_account() {
    let mut f = Fx::new();
    f.sess.pkt = Gcra::new(1_000, 2);
    assert_eq!(f.risk().check_packet(), Ok(()));
    assert_eq!(f.risk().check_packet(), Ok(()));
    assert_eq!(
        f.risk().check_packet(),
        Err(Reject {
            reason: R::RateLimit,
            detail: 1
        })
    );
    let mut g = Fx::new();
    g.acct.buckets.pkt = Gcra::new(1_000, 1);
    assert_eq!(g.risk().check_packet(), Ok(()));
    let s = g.sess.pkt;
    assert_eq!(
        g.risk().check_packet(),
        Err(Reject {
            reason: R::RateLimit,
            detail: 4
        })
    );
    assert_eq!(g.sess.pkt, s);
}

// ---------------------------------------------------------------- M4, M5: state, halt, phase

#[test]
fn m4_killed_or_closed_account_is_account_killed() {
    for st in [AcctState::Killed, AcctState::Closed] {
        let mut f = Fx::new();
        f.acct.state = st;
        let msg = f.acct.buckets.msg;
        assert_eq!(
            f.new_order(buy(99_000, 1), Route::Join),
            rj(R::AccountKilled, 0)
        );
        assert_ne!(f.acct.buckets.msg, msg, "M1 ran before M4 and consumed");
        assert_eq!(f.bal.quote_resv, 0);
    }
    assert!(Fx::new().new_order(buy(99_000, 1), Route::Join).is_ok());
}

#[test]
fn m5_halt_rejects_new_before_phase() {
    let mut f = Fx::new();
    f.snap.halted = true;
    f.snap.phase = Phase::Auction;
    let mut m = buy(99_000, 1);
    m.tif = Tif::Ioc;
    assert_eq!(f.new_order(m, Route::Join), rj(R::BookHalted, 0));
}

#[test]
fn m5_phase_table_of_04_6_9() {
    let cases = [
        (Phase::Continuous, Tif::Day, false, None),
        (Phase::Continuous, Tif::Ioc, false, None),
        (Phase::Continuous, Tif::Fok, false, None),
        (Phase::Continuous, Tif::Day, true, None),
        (Phase::Continuous, Tif::AuctionOnly, false, Some(1)),
        (Phase::Auction, Tif::Day, false, None),
        (Phase::Auction, Tif::AuctionOnly, false, None),
        (Phase::Auction, Tif::Ioc, false, Some(2)),
        (Phase::Auction, Tif::Fok, false, Some(2)),
        (Phase::Auction, Tif::Day, true, Some(2)),
    ];
    for (phase, tif, post_only, want) in cases {
        let mut f = Fx::new();
        f.snap.phase = phase;
        let mut m = buy(99_000, 1);
        m.tif = tif;
        m.post_only = post_only;
        let got = reason(f.new_order(m, Route::Join));
        assert_eq!(
            got,
            want.map(|d| (R::AuctionPhase, d)),
            "{phase:?} {tif:?} {post_only}"
        );
    }
}

// ---------------------------------------------------------------- 10 #5: new_bucket

#[test]
fn new_bucket_is_detail_8_and_later_rejects_still_consume_it() {
    let mut f = Fx::new();
    f.acct.buckets.new = Gcra::new(1_000, 2);
    // Decision 2 of 10 §3.1: a BAD_QTY after the new_bucket still costs its token.
    assert_eq!(
        reason(f.new_order(buy(99_000, 0), Route::Join)),
        Some((R::BadQty, RSK_D_QTY_ZERO))
    );
    assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RateLimit, 8)) // RSK_BUCKET_NEW, 04 §9.1
    );
    // Decision 1: checks 1–4 consume no new_bucket token.
    let mut g = Fx::new();
    g.acct.buckets.new = Gcra::new(1_000, 1);
    g.snap.halted = true;
    assert!(g.new_order(buy(99_000, 1), Route::Join).is_err());
    g.snap.halted = false;
    assert!(g.new_order(buy(99_000, 1), Route::Join).is_ok());
}

// ---------------------------------------------------------------- M6: qty, tick, notional

#[test]
fn m6_qty_bounds() {
    let mut f = Fx::new();
    f.acct.max_order_qty = Qty(50);
    assert_eq!(
        reason(f.new_order(buy(99_000, 0), Route::Join)),
        Some((R::BadQty, RSK_D_QTY_ZERO))
    );
    assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
    assert!(f.new_order(buy(99_000, 50), Route::Join).is_ok());
    assert_eq!(
        reason(f.new_order(buy(99_000, 51), Route::Join)),
        Some((R::BadQty, RSK_D_QTY_MAX))
    );
}

#[test]
fn m6_tick_range() {
    let mut f = Fx::new();
    f.spec = BookSpec::new(10, Tick(90_000), Tick(110_000), 10_000).unwrap();
    assert_eq!(
        reason(f.new_order(buy(0, 1), Route::Join)),
        Some((R::BadTick, 90_000))
    );
    assert_eq!(
        reason(f.new_order(buy(89_999, 1), Route::Join)),
        Some((R::BadTick, 90_000))
    );
    assert!(f.new_order(buy(90_000, 1), Route::Join).is_ok());
    assert!(f.new_order(sell(110_000, 1), Route::Join).is_ok());
    assert_eq!(
        reason(f.new_order(sell(110_001, 1), Route::Join)),
        Some((R::BadTick, 110_000))
    );
}

#[test]
fn m6_band_edges_of_10_3_5() {
    // band_mul = floor(500 × 2^32 / 10_000) = 214_748_364.
    // Buy: w(100_000) = (100_000 × 214_748_364) >> 32 = 4_999 (floor), edge 104_999.
    let mut f = Fx::new();
    assert!(f.new_order(buy(104_999, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(f.new_order(buy(105_000, 1), Route::Cross)),
        Some((R::BadTick, 104_999))
    );
    // Sell: w(99_000) = 4_949, edge 94_051.
    assert!(f.new_order(sell(94_051, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(f.new_order(sell(94_050, 1), Route::Cross)),
        Some((R::BadTick, 94_051))
    );
    // The passive side is never out of band.
    assert!(f.new_order(buy(1, 1), Route::Join).is_ok());
    assert!(f.new_order(sell(1_000_000, 1), Route::Join).is_ok());
}

#[test]
fn m6_band_floor_and_empty_side_use_ref_tick() {
    // w(100) = max(16, 4) = 16: an ask at 100 allows buys up to 116.
    let mut f = Fx::new();
    f.snap.ask = Tick(100);
    assert!(f.new_order(buy(116, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(f.new_order(buy(117, 1), Route::Cross)),
        Some((R::BadTick, 116))
    );
    // An empty ask side uses ref_tick = 100_000: edge 104_999 again.
    let mut g = Fx::new();
    g.snap.ask = Tick(0);
    g.snap.ref_tick = Tick(100_000);
    assert!(g.new_order(buy(104_999, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(g.new_order(buy(105_000, 1), Route::Cross)),
        Some((R::BadTick, 104_999))
    );
    // Sell edge saturates at min_tick: bid 10, w = 16, edge max(0, min_tick) = 1.
    let mut h = Fx::new();
    h.snap.bid = Tick(10);
    assert!(h.new_order(sell(1, 1), Route::Cross).is_ok());
}

#[test]
fn m6_notional_limit() {
    // N(7, 100_000) = 7 × 100_000 × 10 = 7_000_000.
    let mut f = Fx::new();
    f.acct.max_notional = 7_000_000;
    assert!(f.new_order(buy(100_000, 7), Route::Cross).is_ok());
    f.acct.max_notional = 6_999_999;
    assert_eq!(
        reason(f.new_order(buy(100_000, 7), Route::Cross)),
        Some((R::BadQty, RSK_D_NOTIONAL))
    );
}

// ---------------------------------------------------------------- M7: count, slot pool, credit

#[test]
fn m7_open_order_count() {
    let mut f = Fx::new();
    f.acct.max_open_orders = 3;
    f.bal.open_orders = 2;
    assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
    assert_eq!(f.bal.open_orders, 3);
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RiskOrderCount, 3))
    );
}

#[test]
fn m7_full_lane_pool() {
    let mut f = Fx::new();
    f.slot_free = false;
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RiskOrderCount, RSK_D_LANE_FULL))
    );
}

#[test]
fn m7_buy_credit_boundary_is_r_buy_plus_message_fee() {
    // 10 §5.4: R_buy(7, 100_000) = 7_000_000 + 2_108 = 7_002_108; a cross adds 15 (§5.3).
    let need = 7_002_108 + 15;
    let mut f = Fx::new();
    f.bal.quote_free = need - 1;
    let before = f.bal;
    assert_eq!(
        reason(f.new_order(buy(100_000, 7), Route::Cross)),
        Some((R::RiskCredit, 1))
    );
    assert_eq!(f.bal, before, "a reject reserves nothing");
    assert_eq!(f.book.fee_acc, 0, "a reject pays no message fee");
    f.bal.quote_free = need;
    let o = f.new_order(buy(100_000, 7), Route::Cross).unwrap();
    assert_eq!(f.bal.quote_free, 0);
    assert_eq!(f.bal.quote_resv, 7_002_108);
    assert_eq!(f.book.fee_acc, 15);
    assert_eq!(o.route, Route::Cross);
}

#[test]
fn m7_sell_credit_base_then_quote_for_the_fee() {
    let mut f = Fx::new();
    f.bal.base_free = 4;
    assert_eq!(
        reason(f.new_order(sell(99_500, 5), Route::Improve)),
        Some((R::RiskCredit, 2))
    );
    f.bal.quote_free = 7; // improve fee is 8
    assert_eq!(
        reason(f.new_order(sell(99_500, 4), Route::Improve)),
        Some((R::RiskCredit, 1))
    );
    f.bal.quote_free = 8;
    assert!(f.new_order(sell(99_500, 4), Route::Improve).is_ok());
    assert_eq!(
        (f.bal.base_free, f.bal.base_resv, f.bal.quote_free),
        (0, 4, 0)
    );
    assert_eq!(f.book.fee_acc, 8);
}

#[test]
fn m7_runs_count_before_credit() {
    let mut f = Fx::new();
    f.acct.max_open_orders = 0;
    f.bal.quote_free = 0;
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::RiskOrderCount, 0))
    );
}

// ---------------------------------------------------------------- M8: post-only, BBO buckets

#[test]
fn m8_post_only_cross_rejects_with_the_opposite_best() {
    let mut f = Fx::new();
    let mut m = buy(100_000, 1);
    m.post_only = true;
    assert_eq!(
        reason(f.new_order(m, Route::Cross)),
        Some((R::PostOnlyWouldCross, 100_000))
    );
    let mut s = sell(99_000, 1);
    s.post_only = true;
    assert_eq!(
        reason(f.new_order(s, Route::Cross)),
        Some((R::PostOnlyWouldCross, 99_000))
    );
    m.tick = Tick(99_999);
    assert!(f.new_order(m, Route::Improve).is_ok());
}

#[test]
fn m8_lane_cross_shortage_costs_the_account_no_token() {
    // 10 §3.1 decision 3: both tokens or neither.
    let mut f = Fx::new();
    f.lane.cross = Gcra::new(1_000, 1);
    assert!(f.new_order(buy(100_000, 1), Route::Cross).is_ok());
    let acct_cross = f.acct.buckets.cross;
    let bbo = f.sess.bbo;
    let bal = f.bal;
    assert_eq!(
        reason(f.new_order(buy(100_000, 1), Route::Cross)),
        Some((R::RateLimit, 10)) // RSK_BUCKET_LANE_CROSS, 04 §9.1
    );
    assert_eq!(f.acct.buckets.cross, acct_cross);
    assert_eq!(f.sess.bbo, bbo);
    assert_eq!(f.bal, bal);
    // A join needs no BBO token.
    assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
}

#[test]
fn m8_account_cross_and_lane_improve_buckets() {
    let mut f = Fx::new();
    f.acct.buckets.cross = Gcra::new(1_000, 1);
    assert!(f.new_order(buy(100_000, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(f.new_order(buy(100_000, 1), Route::Cross)),
        Some((R::RateLimit, 9)) // RSK_BUCKET_CROSS, 04 §9.1
    );
    let mut g = Fx::new();
    g.lane.improve = Gcra::new(1_000, 1);
    assert!(g.new_order(buy(99_500, 1), Route::Improve).is_ok());
    assert_eq!(
        reason(g.new_order(buy(99_500, 1), Route::Improve)),
        Some((R::RateLimit, 11)) // RSK_BUCKET_LANE_IMPROVE, 04 §9.1
    );
}

#[test]
fn m8_bbo_units_are_five_per_cross_and_one_per_improve() {
    // 04 §9.1: burst 5 units holds one cross, or five improves.
    let mut f = Fx::new();
    f.sess.bbo = Gcra::new(1_000, 5);
    assert!(f.new_order(buy(100_000, 1), Route::Cross).is_ok());
    assert_eq!(
        reason(f.new_order(buy(99_500, 1), Route::Improve)),
        Some((R::RateLimit, 3))
    );
    let mut g = Fx::new();
    g.acct.buckets.bbo = Gcra::new(1_000, 5);
    for _ in 0..5 {
        assert!(g.new_order(buy(99_500, 1), Route::Improve).is_ok());
    }
    assert_eq!(
        reason(g.new_order(buy(99_500, 1), Route::Improve)),
        Some((R::RateLimit, 6))
    );
}

#[test]
fn ioc_and_fok_are_charged_as_crosses() {
    for tif in [Tif::Ioc, Tif::Fok] {
        let mut f = Fx::new();
        let mut m = buy(99_000, 1);
        m.tif = tif;
        let o = f.new_order(m, Route::Join).unwrap();
        assert_eq!(o.route, Route::Cross);
        assert_eq!(f.book.fee_acc, 15);
    }
}

// ---------------------------------------------------------------- Settlement (10 §4, §5.4)

#[test]
fn worked_example_of_10_5_4_settles_exactly() {
    let mut f = Fx::new();
    let q0 = f.bal.quote_free;
    let mut o = f.new_order(buy(100_000, 7), Route::Cross).unwrap();
    f.settle()
        .fill(&mut o, FillKind::Taker, Qty(3), Tick(99_998))
        .unwrap();
    f.settle()
        .fill(&mut o, FillKind::Taker, Qty(4), Tick(99_999))
        .unwrap();
    f.settle().taker_end(&mut o, true).unwrap();
    // Paid 6_999_900 notional + 2_100 taker fee + 15 cross fee; 108 returned to quote_free.
    assert_eq!(q0 - f.bal.quote_free, 6_999_900 + 2_100 + 15);
    assert_eq!(f.bal.quote_resv, 0);
    assert_eq!(f.bal.base_free, 1_000_000 + 7);
    assert_eq!(f.book.fee_acc, 2_100 + 15);
    assert_eq!(f.book.taker_notional, 0);
    assert!(o.closed);
    assert_eq!(f.bal.open_orders, 0);
}

#[test]
fn maker_sell_pays_fee_and_maker_rebate_rounds_down() {
    // Maker 50 ppm on 3 × 99_998 × 10 = 2_999_940: ceil(149.997) = 150.
    let mut f = Fx::new();
    let q0 = f.bal.quote_free;
    let mut o = f.new_order(sell(99_998, 3), Route::Join).unwrap();
    f.settle()
        .fill(&mut o, FillKind::Maker, Qty(3), Tick(99_998))
        .unwrap();
    assert_eq!(f.bal.quote_free - q0, 2_999_940 - 150);
    assert_eq!((f.bal.base_resv, f.bal.base_free), (0, 1_000_000 - 3));
    assert_eq!(f.book.fee_acc, 150);
    // Tier 3 (taker 200, maker −20): rebate floor(59.9988) = 59.
    let mut g = Fx::new();
    g.acct.fees = FeeRates::new(200, -20, 100, 8, 15).unwrap();
    let q0 = g.bal.quote_free;
    let mut o = g.new_order(sell(99_998, 3), Route::Join).unwrap();
    g.settle()
        .fill(&mut o, FillKind::Maker, Qty(3), Tick(99_998))
        .unwrap();
    assert_eq!(g.bal.quote_free - q0, 2_999_940 + 59);
    assert_eq!(g.book.fee_acc, -59);
}

#[test]
fn cancel_after_partial_fill_releases_exactly_the_rest() {
    let mut f = Fx::new();
    let mut o = f.new_order(buy(99_000, 10), Route::Join).unwrap();
    f.settle()
        .fill(&mut o, FillKind::Maker, Qty(4), Tick(99_000))
        .unwrap();
    f.settle().release(&mut o, Qty(4)).unwrap();
    assert_eq!(f.bal.quote_resv, 0);
    assert_eq!(f.bal.open_orders, 0);
    // A second release of a closed order is an engine fault.
    assert_eq!(f.settle().release(&mut o, Qty(4)), Err(Fault::BadEvent));
}

#[test]
fn shed_is_as_if_the_op_never_arrived() {
    let mut f = Fx::new();
    let (bal, acct, sess, lane) = (f.bal, f.acct, f.sess, f.lane);
    let mut o = f.new_order(buy(100_000, 7), Route::Cross).unwrap();
    f.settle().shed(&mut o).unwrap();
    f.risk().refund_shed_tokens(&o);
    assert_eq!(f.bal.quote_free, bal.quote_free);
    assert_eq!(f.bal.quote_resv, 0);
    assert_eq!(f.bal.open_orders, 0);
    assert_eq!(f.book.fee_acc, 0);
    // A GCRA with tat ≤ now is full; compare every bucket as "full at now".
    let full = |g: Gcra| Gcra {
        tat: Nanos(g.tat.0.max(f.now.0)),
        ..g
    };
    let a = (f.acct.buckets, acct.buckets);
    for (x, y) in [
        (a.0.msg, a.1.msg),
        (a.0.bbo, a.1.bbo),
        (a.0.new, a.1.new),
        (a.0.cross, a.1.cross),
    ] {
        assert_eq!(full(x), full(y));
    }
    for (x, y) in [
        (f.sess.msg, sess.msg),
        (f.sess.bbo, sess.bbo),
        (f.lane.cross, lane.cross),
    ] {
        assert_eq!(full(x), full(y));
    }
    assert_eq!(full(f.lane.improve), full(lane.improve));
}

#[test]
fn reduce_keeps_the_order_live_and_releases_the_removed_lots() {
    let mut f = Fx::new();
    let mut o = f.new_order(buy(100_000, 7), Route::Join).unwrap();
    f.settle().reduce(&mut o, Qty(3)).unwrap();
    // R_buy(4, 100_000) at 300 ppm: 4_000_000 + 1_200 + 1 + 4.
    assert_eq!(f.bal.quote_resv, 4_001_205);
    assert_eq!(o.qty, Qty(4));
    assert!(!o.closed);
    assert_eq!(f.settle().reduce(&mut o, Qty(4)), Err(Fault::BadEvent));
    assert_eq!(f.settle().reduce(&mut o, Qty(0)), Err(Fault::BadEvent));
}

#[test]
fn impossible_events_fault_and_change_nothing() {
    let mut f = Fx::new();
    let mut o = f.new_order(buy(100_000, 2), Route::Join).unwrap();
    let (bal, book, ord) = (f.bal, f.book, o);
    assert_eq!(
        f.settle()
            .fill(&mut o, FillKind::Maker, Qty(3), Tick(100_000)),
        Err(Fault::BadEvent)
    );
    assert_eq!(
        f.settle()
            .fill(&mut o, FillKind::Maker, Qty(1), Tick(100_001)),
        Err(Fault::BadEvent)
    );
    assert_eq!(
        f.settle()
            .fill(&mut o, FillKind::Maker, Qty(0), Tick(100_000)),
        Err(Fault::BadEvent)
    );
    assert_eq!((f.bal, f.book, o), (bal, book, ord));
}

#[test]
fn ioc_remainder_leaves_at_taker_end() {
    let mut f = Fx::new();
    let mut m = buy(100_000, 5);
    m.tif = Tif::Ioc;
    let mut o = f.new_order(m, Route::Cross).unwrap();
    f.settle()
        .fill(&mut o, FillKind::Taker, Qty(2), Tick(100_000))
        .unwrap();
    f.settle().taker_end(&mut o, false).unwrap();
    assert!(o.closed);
    assert_eq!(f.bal.quote_resv, 0);
    // ceil(2_000_000 × 300 / 10^6) = 600, plus the 15 cross fee.
    assert_eq!(f.book.fee_acc, 615);
}

// ---------------------------------------------------------------- Control ops (10 §2.4–§5.2)

#[test]
fn credit_overflows_reject_and_debit_takes_only_free() {
    let mut b = BookBal::default();
    assert_eq!(ctl::credit(&mut b, ctl::Asset::Base, u64::MAX), Ok(()));
    assert_eq!(
        ctl::credit(&mut b, ctl::Asset::Base, 1),
        Err(Reject {
            reason: R::BadQty,
            detail: RSK_D_OVERFLOW
        })
    );
    b.quote_free = 10;
    b.quote_resv = 100;
    assert_eq!(ctl::debit_free(&mut b, ctl::Asset::Quote, 25), 10);
    assert_eq!((b.quote_free, b.quote_resv), (0, 100));
    assert_eq!(ctl::debit_free(&mut b, ctl::Asset::Base, 5), 5);
}

#[test]
fn set_limit_bounds_of_10_3_4() {
    let mut f = Fx::new();
    let bad = |id: u32| {
        Err(Reject {
            reason: R::BadQty,
            detail: id,
        })
    };
    let mut set = |id: u8, v: u64| ctl::set_limit(&mut f.acct, &mut f.spec, id, v);
    assert_eq!(set(1, 1_048_576), Ok(()));
    assert_eq!(set(1, 1_048_577), bad(1));
    assert_eq!(set(2, u64::from(u32::MAX)), Ok(()));
    assert_eq!(set(2, u64::from(u32::MAX) + 1), bad(2));
    assert_eq!(set(4, 10_000), Ok(()));
    assert_eq!(set(4, 10_001), bad(4));
    assert_eq!(set(5, 0), bad(5));
    assert_eq!(set(6, 220_000), Ok(()));
    assert_eq!(set(6, 220_001), bad(6));
    assert_eq!(set(7, 0), Ok(()));
    assert_eq!(set(7, 999_999), bad(7));
    assert_eq!(set(7, 1_000_000), Ok(()));
    assert_eq!(set(8, 0), bad(8));
    assert_eq!(set(8, 3), Ok(()));
    assert_eq!(set(8, 4), bad(8));
    assert_eq!(
        set(9, 1),
        Err(Reject {
            reason: R::BadType,
            detail: PROTO_D_UNKNOWN_TYPE
        })
    );
}

#[test]
fn kill_then_unkill() {
    let mut f = Fx::new();
    ctl::kill(&mut f.acct, true);
    assert_eq!(
        reason(f.new_order(buy(99_000, 1), Route::Join)),
        Some((R::AccountKilled, 0))
    );
    ctl::kill(&mut f.acct, false);
    assert!(f.new_order(buy(99_000, 1), Route::Join).is_ok());
}

#[test]
fn set_fees_may_not_raise_fee_mul_under_a_buy_reservation() {
    let mut f = Fx::new();
    let mut o = f.new_order(buy(99_000, 1), Route::Join).unwrap();
    let up = FeeRates::new(400, 100, 100, 8, 15).unwrap();
    let down = FeeRates::new(200, 0, 100, 8, 15).unwrap();
    assert_eq!(
        ctl::set_fees(&mut f.acct, &f.bal, up),
        Err(Reject {
            reason: R::RiskOrderCount,
            detail: 1
        })
    );
    assert_eq!(ctl::set_fees(&mut f.acct, &f.bal, down), Ok(()));
    // The resting order still releases what it reserved under 300 ppm.
    f.settle().release(&mut o, Qty(0)).unwrap();
    assert_eq!(f.bal.quote_resv, 0);
    assert_eq!(ctl::set_fees(&mut f.acct, &f.bal, up), Ok(()));
}

#[test]
fn fee_schedule_rules_of_10_5_2() {
    assert!(FeeRates::new(400, -400, 100, 0, 0).is_some());
    assert!(FeeRates::new(400, -401, 100, 0, 0).is_none());
    assert!(FeeRates::new(10_000, 0, 0, 0, 0).is_some());
    assert!(FeeRates::new(10_001, 0, 0, 0, 0).is_none());
    assert!(FeeRates::new(-1, 0, 0, 0, 0).is_none());
    assert!(FeeRates::new(0, 0, -1, 0, 0).is_none());
}
