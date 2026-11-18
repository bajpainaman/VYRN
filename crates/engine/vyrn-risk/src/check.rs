//! Pre-trade checks in the lane (10 §3, 04 §3.1 V10 and §3.3 M1–M8). Each check is a pure test
//! followed by a commit, so a reject changes only what its contract says it consumes.

use vyrn_types::{Nanos, RejectReason};

use crate::account::{
    AcctRisk, AcctState, BookAcc, BookBal, BookSpec, LaneBuckets, SessionBuckets,
};
use crate::consts::{
    PROTO_BBO_UNITS_CROSS, PROTO_BBO_UNITS_IMPROVE, PROTO_BUCKET_BBO, PROTO_BUCKET_BBO_ACCOUNT,
    PROTO_BUCKET_MSG, PROTO_BUCKET_MSG_ACCOUNT, PROTO_BUCKET_PKT, PROTO_BUCKET_PKT_ACCOUNT,
    PROTO_CANCELALL_TOKENS, PROTO_PHASE_AUCTION, PROTO_PHASE_CONTINUOUS, RSK_BUCKET_CROSS,
    RSK_BUCKET_LANE_CROSS, RSK_BUCKET_LANE_IMPROVE, RSK_BUCKET_NEW, RSK_CREDIT_BASE,
    RSK_CREDIT_QUOTE, RSK_D_LANE_FULL, RSK_D_NOTIONAL, RSK_D_OVERFLOW, RSK_D_QTY_MAX,
    RSK_D_QTY_ZERO,
};
use crate::fee;
use crate::gcra::Gcra;
use crate::order::{NewOrder, OrderRisk, Phase, Route, Side, Snapshot, Tif};
use crate::reject::{Reject, rej};

/// The message kinds that only reduce risk (10 §3.1, last paragraph).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelKind {
    Cancel,
    Reduce,
    CancelAll,
}

/// Everything one check reads and writes: the account, its session, its balance in the packet's
/// book, the lane (or pool) buckets, the book's accumulators and config, the packet's snapshot,
/// and the packet's `rx_ts`.
pub struct Risk<'a> {
    pub acct: &'a mut AcctRisk,
    pub sess: &'a mut SessionBuckets,
    pub bal: &'a mut BookBal,
    pub lane: &'a mut LaneBuckets,
    pub book: &'a mut BookAcc,
    pub spec: &'a BookSpec,
    pub snap: &'a Snapshot,
    pub now: Nanos,
    /// The lane's order-slot pool for this book has a free slot (10 §3.4).
    pub slot_free: bool,
}

/// The cancel reserve of 04 §9.1: a quarter of the burst, kept by `New` and `Replace` only.
fn keep(g: &Gcra, reserve: bool) -> u64 {
    if reserve {
        g.burst.checked_div(4).unwrap_or(0)
    } else {
        0
    }
}

/// Takes `cost` from a session bucket and its account twin, both or neither. The first bucket that
/// cannot pay names the reject.
fn take_pair(
    now: Nanos,
    s: &mut Gcra,
    s_id: u32,
    a: &mut Gcra,
    a_id: u32,
    cost: u64,
    reserve: bool,
) -> Result<(), Reject> {
    let ts = s
        .next_tat(now, cost, keep(s, reserve))
        .ok_or(rej(RejectReason::RateLimit, s_id))?;
    let ta = a
        .next_tat(now, cost, keep(a, reserve))
        .ok_or(rej(RejectReason::RateLimit, a_id))?;
    s.tat = ts;
    a.tat = ta;
    Ok(())
}

/// One bucket's next `tat`, or the `RATE_LIMIT` reject with `id`.
fn next(g: &Gcra, now: Nanos, cost: u64, id: u32) -> Result<Nanos, Reject> {
    g.next_tat(now, cost, 0)
        .ok_or(rej(RejectReason::RateLimit, id))
}

/// 04 §6.9 for a new order, outside a halt. The detail is the current phase.
fn phase_allows(phase: Phase, m: &NewOrder) -> Result<(), Reject> {
    let (ok, code) = match phase {
        Phase::Continuous => (m.tif != Tif::AuctionOnly, PROTO_PHASE_CONTINUOUS),
        Phase::Auction => (
            matches!(m.tif, Tif::Day | Tif::AuctionOnly) && !m.post_only,
            PROTO_PHASE_AUCTION,
        ),
    };
    if ok {
        Ok(())
    } else {
        Err(rej(RejectReason::AuctionPhase, code))
    }
}

/// The balance after reserving `m` (10 §3.2), or the reject. Pure.
///
/// - Buy: `need = R_buy(qty, tick) + msg_fee` must be ≤ `quote_free`, else `RISK_CREDIT` 1.
///   `quote_free −= need`, `quote_resv += R_buy`.
/// - Sell: `qty ≤ base_free`, else `RISK_CREDIT` 2; then `msg_fee ≤ quote_free`, else
///   `RISK_CREDIT` 1. `base_free −= qty`, `base_resv += qty`, `quote_free −= msg_fee`.
/// - Either: `open_orders += 1`. Any overflow is `BAD_QTY` / `RSK_D_OVERFLOW` (01 §11 rule 4).
fn reserved(
    bal: &BookBal,
    m: &NewOrder,
    n: u128,
    fee_mul: u64,
    msg_fee: u128,
) -> Result<BookBal, Reject> {
    let over = rej(RejectReason::BadQty, RSK_D_OVERFLOW);
    let short_quote = rej(RejectReason::RiskCredit, RSK_CREDIT_QUOTE);
    let mut b = *bal;
    match m.side {
        Side::Buy => {
            let cap = fee::fee_cap(n, m.qty, fee_mul).ok_or(over)?;
            let r = n.checked_add(cap).ok_or(over)?;
            let need = r.checked_add(msg_fee).ok_or(over)?;
            b.quote_free = b.quote_free.checked_sub(need).ok_or(short_quote)?;
            b.quote_resv = b.quote_resv.checked_add(r).ok_or(over)?;
        }
        Side::Sell => {
            let q = u64::from(m.qty.0);
            b.base_free = b
                .base_free
                .checked_sub(q)
                .ok_or(rej(RejectReason::RiskCredit, RSK_CREDIT_BASE))?;
            b.quote_free = b.quote_free.checked_sub(msg_fee).ok_or(short_quote)?;
            b.base_resv = b.base_resv.checked_add(q).ok_or(over)?;
        }
    }
    b.open_orders = b.open_orders.checked_add(1).ok_or(over)?;
    Ok(b)
}

/// The route an order is charged as: `IOC` and `FOK` always go to the BBO core and are charged as
/// crosses (04 §6.2, §9.2), whatever the snapshot says.
#[inline]
pub fn charged_route(tif: Tif, route: Route) -> Route {
    match tif {
        Tif::Ioc | Tif::Fok => Route::Cross,
        Tif::Day | Tif::AuctionOnly => route,
    }
}

/// 04 §9.1 `BBO` units of a charged route.
const fn bbo_units(route: Route) -> u64 {
    match route {
        Route::Join => 0,
        Route::Improve => PROTO_BBO_UNITS_IMPROVE,
        Route::Cross => PROTO_BBO_UNITS_CROSS,
    }
}

impl Risk<'_> {
    /// **V10** (04 §3.1): the `PKT` buckets of the session (id 1) and the account (id 4), one
    /// token each, both or neither, once per accepted packet.
    ///
    /// Reject: `RATE_LIMIT`, detail 1 if the session bucket is empty, else 4. The lane then
    /// rejects every message of the packet with it.
    pub fn check_packet(&mut self) -> Result<(), Reject> {
        take_pair(
            self.now,
            &mut self.sess.pkt,
            PROTO_BUCKET_PKT,
            &mut self.acct.buckets.pkt,
            PROTO_BUCKET_PKT_ACCOUNT,
            1,
            false,
        )
    }

    /// **M1** for `Cancel`, `Reduce` and `CancelAll` (04 §3.3, 10 §3.1): the `MSG` buckets of the
    /// session (id 2) and account (id 5), both or neither, with `keep = 0`, so the cancel reserve
    /// is theirs. Cost 1, or `PROTO_CANCELALL_TOKENS` (16) for `CancelAll`.
    ///
    /// Reject: `RATE_LIMIT`, detail 2 or 5. Nothing else is checked: halts, kills, bands and
    /// balances never block risk reduction (10 §3.7 decision 1).
    pub fn check_cancel(&mut self, kind: CancelKind) -> Result<(), Reject> {
        let cost = match kind {
            CancelKind::Cancel | CancelKind::Reduce => 1,
            CancelKind::CancelAll => PROTO_CANCELALL_TOKENS,
        };
        take_pair(
            self.now,
            &mut self.sess.msg,
            PROTO_BUCKET_MSG,
            &mut self.acct.buckets.msg,
            PROTO_BUCKET_MSG_ACCOUNT,
            cost,
            false,
        )
    }

    /// Every check of a `New`, or of the new order of a priority-losing `Replace` (10 §3.9), and
    /// the reservation. `route` is 05's classification against `snap` (`Join` in the auction).
    ///
    /// Order (04 §3.3 M1–M8, with 10 §3.1 for the checks 04 leaves to it). The first failure is
    /// the reject; later checks do not run.
    ///
    /// | # | Check | Reject, detail | Consumes on reject |
    /// |---|---|---|---|
    /// | M1 | `MSG` session (2) then account (5), cost 1, keeping the cancel reserve (¼ burst) | `RATE_LIMIT` 2 / 5 | nothing |
    /// | M4 | account `Active` | `ACCOUNT_KILLED` 0 | `MSG` |
    /// | M5 | snapshot not `halted` | `BOOK_HALTED` 0 | `MSG` |
    /// | M5 | phase allows the TIF and post-only (04 §6.9) | `AUCTION_PHASE` phase | `MSG` |
    /// | 10 #5 | account `new_bucket`, cost 1 | `RATE_LIMIT` `RSK_BUCKET_NEW` (8) | `MSG` |
    /// | M6 | `qty ≥ 1` | `BAD_QTY` `RSK_D_QTY_ZERO` | `MSG`, `new` |
    /// | M6 | `qty ≤ max_order_qty` | `BAD_QTY` `RSK_D_QTY_MAX` | `MSG`, `new` |
    /// | M6 | tick range and band ([`BookSpec::check_tick`]) | `BAD_TICK` edge | `MSG`, `new` |
    /// | M6 | `N(qty, tick) ≤ max_notional` | `BAD_QTY` `RSK_D_NOTIONAL` | `MSG`, `new` |
    /// | M7 | `open_orders < max_open_orders` | `RISK_ORDER_COUNT` limit | `MSG`, `new` |
    /// | M7 | a free order slot in the lane's pool | `RISK_ORDER_COUNT` `RSK_D_LANE_FULL` | `MSG`, `new` |
    /// | M7 | balance covers reservation + message fee | `RISK_CREDIT` 1 quote / 2 base | `MSG`, `new` |
    /// | M8 | not post-only with `route == Cross` | `POST_ONLY_WOULD_CROSS` opposite best | `MSG`, `new` |
    /// | M8 | `BBO` session (3), account (6); cross: `cross_bucket` (9), `lane_cross` (10); improve: `lane_improve` (11) | `RATE_LIMIT` id | `MSG`, `new` |
    ///
    /// M7 has no exposure check (`RISK_POSITION`) in v1 spot; it is the v2 perps limit (10 §6).
    /// The M8 buckets are taken all or none (10 §3.1 decision 3). `IOC` and `FOK` are charged as
    /// crosses ([`charged_route`]); the post-only test uses the classification itself.
    ///
    /// On accept: the M8 tokens are taken, the balance is reserved, `open_orders += 1`, and the
    /// message fee moves from `quote_free` to `fee_acc`. A reject pays no message fee and reserves
    /// nothing. Returns the order record for settlement.
    pub fn check_new(&mut self, m: &NewOrder, route: Route) -> Result<OrderRisk, Reject> {
        let now = self.now;
        take_pair(
            now,
            &mut self.sess.msg,
            PROTO_BUCKET_MSG,
            &mut self.acct.buckets.msg,
            PROTO_BUCKET_MSG_ACCOUNT,
            1,
            true,
        )?;
        if self.acct.state != AcctState::Active {
            return Err(rej(RejectReason::AccountKilled, 0));
        }
        if self.snap.halted {
            return Err(rej(RejectReason::BookHalted, 0));
        }
        phase_allows(self.snap.phase, m)?;
        if !self.acct.buckets.new.take(now, 1, 0) {
            return Err(rej(RejectReason::RateLimit, RSK_BUCKET_NEW));
        }
        // From here on the `new_bucket` token is consumed (10 §3.1 decision 2).
        if m.qty.0 == 0 {
            return Err(rej(RejectReason::BadQty, RSK_D_QTY_ZERO));
        }
        if m.qty > self.acct.max_order_qty {
            return Err(rej(RejectReason::BadQty, RSK_D_QTY_MAX));
        }
        self.spec.check_tick(self.snap, m.side, m.tick)?;
        let n = fee::notional(m.qty, m.tick, self.spec.tick_size)
            .ok_or(rej(RejectReason::BadQty, RSK_D_OVERFLOW))?;
        if n > u128::from(self.acct.max_notional) {
            return Err(rej(RejectReason::BadQty, RSK_D_NOTIONAL));
        }
        if self.bal.open_orders >= self.acct.max_open_orders {
            return Err(rej(RejectReason::RiskOrderCount, self.acct.max_open_orders));
        }
        if !self.slot_free {
            return Err(rej(RejectReason::RiskOrderCount, RSK_D_LANE_FULL));
        }
        let charge = charged_route(m.tif, route);
        let msg_fee = self.acct.fees.msg_fee(charge);
        let fee_mul = self.acct.fees.fee_mul;
        let bal = reserved(self.bal, m, n, fee_mul, u128::from(msg_fee))?;
        if m.post_only && route == Route::Cross {
            let opp = match m.side {
                Side::Buy => self.snap.ask,
                Side::Sell => self.snap.bid,
            };
            return Err(rej(RejectReason::PostOnlyWouldCross, opp.0));
        }
        let fee_acc = self
            .book
            .fee_acc
            .checked_add(i128::from(msg_fee))
            .ok_or(rej(RejectReason::BadQty, RSK_D_OVERFLOW))?;
        self.take_bbo(charge)?;
        *self.bal = bal;
        self.book.fee_acc = fee_acc;
        Ok(OrderRisk {
            side: m.side,
            tick: m.tick,
            qty: m.qty,
            settled: vyrn_types::Qty(0),
            closed: false,
            route: charge,
            fee_mul,
            msg_fee,
        })
    }

    /// The M8 buckets of a charged route, all or none, in the order of [`Risk::check_new`].
    fn take_bbo(&mut self, charge: Route) -> Result<(), Reject> {
        let now = self.now;
        let units = bbo_units(charge);
        if units == 0 {
            return Ok(());
        }
        let s = next(&self.sess.bbo, now, units, PROTO_BUCKET_BBO)?;
        let a = next(&self.acct.buckets.bbo, now, units, PROTO_BUCKET_BBO_ACCOUNT)?;
        match charge {
            Route::Cross => {
                let xa = next(&self.acct.buckets.cross, now, 1, RSK_BUCKET_CROSS)?;
                let xl = next(&self.lane.cross, now, 1, RSK_BUCKET_LANE_CROSS)?;
                self.acct.buckets.cross.tat = xa;
                self.lane.cross.tat = xl;
            }
            Route::Improve => {
                self.lane.improve.tat = next(&self.lane.improve, now, 1, RSK_BUCKET_LANE_IMPROVE)?;
            }
            Route::Join => {}
        }
        self.sess.bbo.tat = s;
        self.acct.buckets.bbo.tat = a;
        Ok(())
    }

    /// The token half of a `Shed` (10 §3.11): returns every token `check_new` took for `o`, each
    /// bucket capped at its burst. Its money half is [`crate::Settle::shed`].
    pub fn refund_shed_tokens(&mut self, o: &OrderRisk) {
        let now = self.now;
        self.sess.msg.refund(now, 1);
        self.acct.buckets.msg.refund(now, 1);
        self.acct.buckets.new.refund(now, 1);
        let units = bbo_units(o.route);
        if units != 0 {
            self.sess.bbo.refund(now, units);
            self.acct.buckets.bbo.refund(now, units);
        }
        match o.route {
            Route::Cross => {
                self.acct.buckets.cross.refund(now, 1);
                self.lane.cross.refund(now, 1);
            }
            Route::Improve => self.lane.improve.refund(now, 1),
            Route::Join => {}
        }
    }
}
