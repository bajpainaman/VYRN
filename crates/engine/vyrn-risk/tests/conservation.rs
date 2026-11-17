//! Property tests: balances are conserved across reserve, settle and release (10 §2.7 INV-ACC-1
//! to INV-ACC-3), and settlement never faults on a valid event stream (10 §4.5, the release lemma
//! of §3.2).
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use proptest::prelude::*;
use vyrn_risk::{
    AcctRisk, BookAcc, BookBal, BookSpec, FeeRates, FillKind, LaneBuckets, NewOrder, OrderRisk,
    Phase, Risk, Route, SessionBuckets, Settle, Side, Snapshot, Tif, fee,
};
use vyrn_types::{AccountId, Nanos, Qty, Tick};

const Q0: u128 = 1 << 100;
const B0: u64 = 1 << 40;

struct Party {
    acct: AcctRisk,
    sess: SessionBuckets,
    bal: BookBal,
}

impl Party {
    fn new(id: u32, fees: FeeRates) -> Self {
        let mut acct = AcctRisk::new(AccountId(id), AccountId(id));
        acct.fees = fees;
        acct.max_notional = u64::MAX;
        Self {
            acct,
            sess: SessionBuckets::default(),
            bal: BookBal {
                quote_free: Q0,
                base_free: B0,
                ..BookBal::default()
            },
        }
    }

    fn enter(
        &mut self,
        lane: &mut LaneBuckets,
        book: &mut BookAcc,
        spec: &BookSpec,
        m: NewOrder,
        route: Route,
    ) -> OrderRisk {
        // No band: both sides empty and no ref_tick.
        let snap = Snapshot {
            halted: false,
            phase: Phase::Continuous,
            bid: Tick(0),
            ask: Tick(0),
            ref_tick: Tick(0),
        };
        Risk {
            acct: &mut self.acct,
            sess: &mut self.sess,
            bal: &mut self.bal,
            lane,
            book,
            spec,
            snap: &snap,
            now: Nanos(1_000_000_000),
            slot_free: true,
        }
        .check_new(&m, route)
        .unwrap()
    }

    fn settle<'a>(&'a mut self, book: &'a mut BookAcc, ts: u64) -> Settle<'a> {
        Settle {
            fees: &self.acct.fees,
            bal: &mut self.bal,
            book,
            tick_size: ts,
        }
    }
}

/// INV-ACC-1 for one order: `quote_resv = R_buy(rem_u)` of an open buy, `base_resv = rem_u` of an
/// open sell, and zero once closed with every fill settled.
fn resv_matches(p: &Party, o: &OrderRisk, ts: u64) -> bool {
    let rem_u = Qty(o.qty.0 - o.settled.0);
    let open = if o.closed { Qty(0) } else { rem_u };
    match o.side {
        Side::Buy => p.bal.quote_resv == fee::r_buy(open, o.tick, ts, o.fee_mul).unwrap(),
        Side::Sell => p.bal.base_resv == u64::from(open.0),
    }
}

fn rates() -> impl Strategy<Value = FeeRates> {
    (
        0i32..=10_000,
        -10_000i32..=10_000,
        0i32..=10_000,
        0u32..=100,
        0u32..=100,
    )
        .prop_filter_map("10 §5.2 rule 1", |(t, m, a, i, c)| {
            FeeRates::new(t, m, a, i, c)
        })
}

fn order(side: Side, tick: u32, qty: u32) -> NewOrder {
    NewOrder {
        side,
        tif: Tif::Day,
        post_only: false,
        tick: Tick(tick),
        qty: Qty(qty),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A buyer and a seller trade fills at prices between their limits, in any maker/taker role,
    /// then cancel their remainders. At every step: Σ quote + fee_acc and Σ base are unchanged,
    /// INV-ACC-1 holds for both orders, and no settlement faults.
    #[test]
    fn reserve_settle_release_conserves(
        buy_rates in rates(),
        sell_rates in rates(),
        ts in 1u64..=1_000_000,
        buy_tick in 1u32..=1_000_000,
        sell_frac in 0u32..=1_000,
        buy_qty in 1u32..=100_000,
        sell_qty in 1u32..=100_000,
        fills in prop::collection::vec((1u32..=50_000, 0u32..=1_000, any::<bool>(), 1u8..=3), 0..12),
        buy_route in prop_oneof![Just(Route::Join), Just(Route::Improve), Just(Route::Cross)],
    ) {
        let spec = BookSpec::new(ts, Tick(1), Tick(1_000_000), 500).unwrap();
        let mut lane = LaneBuckets::dedicated();
        let mut book = BookAcc::default();
        let mut b = Party::new(1, buy_rates);
        let mut s = Party::new(2, sell_rates);
        let sell_tick = (buy_tick - 1) * sell_frac / 1_000 + 1;
        let total = |b: &Party, s: &Party, book: &BookAcc| {
            let q = b.bal.quote_free + b.bal.quote_resv + s.bal.quote_free + s.bal.quote_resv;
            let base = b.bal.base_free + b.bal.base_resv + s.bal.base_free + s.bal.base_resv;
            (i128::try_from(q).unwrap() + book.fee_acc, base)
        };
        let start = total(&b, &s, &book);

        let mut ob = b.enter(&mut lane, &mut book, &spec, order(Side::Buy, buy_tick, buy_qty), buy_route);
        let mut os = s.enter(&mut lane, &mut book, &spec, order(Side::Sell, sell_tick, sell_qty), Route::Join);
        prop_assert_eq!(total(&b, &s, &book), start);
        prop_assert!(resv_matches(&b, &ob, ts) && resv_matches(&s, &os, ts));

        for (q, pfrac, buyer_takes, kind) in fills {
            let left = (ob.qty.0 - ob.settled.0).min(os.qty.0 - os.settled.0);
            if left == 0 { break; }
            let q = Qty(q.min(left));
            let p = Tick(sell_tick + (buy_tick - sell_tick) * pfrac / 1_000);
            if kind == 3 {
                // Auction fill: both sides pay the auction fee.
                b.settle(&mut book, ts).fill(&mut ob, FillKind::Auction, q, p).unwrap();
                s.settle(&mut book, ts).fill(&mut os, FillKind::Auction, q, p).unwrap();
            } else if buyer_takes {
                b.settle(&mut book, ts).fill(&mut ob, FillKind::Taker, q, p).unwrap();
                s.settle(&mut book, ts).fill(&mut os, FillKind::Maker, q, p).unwrap();
                b.settle(&mut book, ts).taker_end(&mut ob, true).unwrap();
            } else {
                s.settle(&mut book, ts).fill(&mut os, FillKind::Taker, q, p).unwrap();
                b.settle(&mut book, ts).fill(&mut ob, FillKind::Maker, q, p).unwrap();
                s.settle(&mut book, ts).taker_end(&mut os, true).unwrap();
            }
            prop_assert_eq!(total(&b, &s, &book), start);
            prop_assert!(resv_matches(&b, &ob, ts) && resv_matches(&s, &os, ts));
            prop_assert_eq!(book.taker_notional, 0);
        }

        if !ob.closed { let f = ob.settled; b.settle(&mut book, ts).release(&mut ob, f).unwrap(); }
        if !os.closed { let f = os.settled; s.settle(&mut book, ts).release(&mut os, f).unwrap(); }
        prop_assert_eq!(total(&b, &s, &book), start);
        prop_assert_eq!((b.bal.quote_resv, b.bal.base_resv, s.bal.quote_resv, s.bal.base_resv), (0, 0, 0, 0));
        prop_assert_eq!((b.bal.open_orders, s.bal.open_orders), (0, 0));
        // Lots move one for one.
        prop_assert_eq!(b.bal.base_free - B0, B0 - s.bal.base_free);
    }

    /// A taker buy swept over several price levels at or below its limit, at the worst fee rate,
    /// always pays its notional and its one taker fee out of the released reservation.
    #[test]
    fn release_lemma_covers_any_sweep(
        r in rates(),
        ts in 1u64..=1_000_000,
        tick in 1u32..=1_000_000,
        qty in 1u32..=100_000,
        levels in prop::collection::vec((1u32..=100_000, 0u32..=1_000), 1..10),
    ) {
        let spec = BookSpec::new(ts, Tick(1), Tick(1_000_000), 500).unwrap();
        let mut lane = LaneBuckets::dedicated();
        let mut book = BookAcc::default();
        let mut b = Party::new(1, r);
        let mut o = b.enter(&mut lane, &mut book, &spec, order(Side::Buy, tick, qty), Route::Cross);
        let free_after_entry = b.bal.quote_free;
        let mut paid = 0u128;
        for (q, pf) in levels {
            let left = o.qty.0 - o.settled.0;
            if left == 0 { break; }
            let q = Qty(q.min(left));
            let p = Tick(1 + (tick - 1) * pf / 1_000);
            paid += fee::notional(q, p, ts).unwrap();
            b.settle(&mut book, ts).fill(&mut o, FillKind::Taker, q, p).unwrap();
        }
        let taker_fee = fee::fill_fee(paid, r.taker_ppm).unwrap().unsigned_abs();
        b.settle(&mut book, ts).taker_end(&mut o, false).unwrap();
        prop_assert!(o.closed);
        prop_assert_eq!(b.bal.quote_resv, 0);
        // Everything reserved came back except the notional and the taker fee.
        let r_full = fee::r_buy(Qty(qty), Tick(tick), ts, o.fee_mul).unwrap();
        prop_assert_eq!(b.bal.quote_free, free_after_entry + r_full - paid - taker_fee);
    }

    /// Reserve then cancel, or reserve then shed, restores the balance exactly; a shed also returns
    /// the message fee (10 §3.11).
    #[test]
    fn cancel_and_shed_restore(
        r in rates(),
        ts in 1u64..=1_000_000,
        tick in 1u32..=1_000_000,
        qty in 1u32..=100_000,
        is_buy in any::<bool>(),
        shed in any::<bool>(),
    ) {
        let spec = BookSpec::new(ts, Tick(1), Tick(1_000_000), 500).unwrap();
        let mut lane = LaneBuckets::dedicated();
        let mut book = BookAcc::default();
        let mut p = Party::new(1, r);
        let before = p.bal;
        let side = if is_buy { Side::Buy } else { Side::Sell };
        let mut o = p.enter(&mut lane, &mut book, &spec, order(side, tick, qty), Route::Cross);
        prop_assert_eq!(book.fee_acc, i128::from(r.msg_fee_cross));
        if shed {
            p.settle(&mut book, ts).shed(&mut o).unwrap();
            prop_assert_eq!(p.bal, before);
            prop_assert_eq!(book.fee_acc, 0);
        } else {
            p.settle(&mut book, ts).release(&mut o, Qty(0)).unwrap();
            let mut want = before;
            want.quote_free -= u128::from(r.msg_fee_cross);
            prop_assert_eq!(p.bal, want);
        }
    }
}
