//! Settlement on fill events and releases (10 §3.9, §4.4, §4.5). Settlement never rejects: a fill
//! is final when the BBO core writes it. A failed checked operation is an engine bug, returned as
//! a [`Fault`] for the lane to turn into `engine_fault` (halt the book, keep serving cancels).
//! Every function here is atomic: on a fault, nothing it was given has changed.

use vyrn_types::{Qty, Tick};

use crate::account::{BookAcc, BookBal, FeeRates};
use crate::fee;
use crate::order::{OrderRisk, Side};

/// An engine fault in settlement (10 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A balance or accumulator would overflow.
    Overflow,
    /// A balance would go negative (`INV-ACC-3`).
    Underflow,
    /// The event contradicts the order: zero qty, more lots than remain, a fill beyond the limit,
    /// or a release of a closed order.
    BadEvent,
}

/// The kind of a fill event that moves lots (10 §4.1 kinds 1, 2, 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillKind {
    Maker,
    Taker,
    Auction,
}

/// Settlement context of one account in one book.
pub struct Settle<'a> {
    /// The account's current rates. The reservation multiplier comes from the order.
    pub fees: &'a FeeRates,
    pub bal: &'a mut BookBal,
    pub book: &'a mut BookAcc,
    pub tick_size: u64,
}

fn add128(a: u128, b: u128) -> Result<u128, Fault> {
    a.checked_add(b).ok_or(Fault::Overflow)
}
fn sub128(a: u128, b: u128) -> Result<u128, Fault> {
    a.checked_sub(b).ok_or(Fault::Underflow)
}
fn add64(a: u64, b: u64) -> Result<u64, Fault> {
    a.checked_add(b).ok_or(Fault::Overflow)
}
fn sub64(a: u64, b: u64) -> Result<u64, Fault> {
    a.checked_sub(b).ok_or(Fault::Underflow)
}

/// `R_buy(qty, tick)` with the order's own `fee_mul`.
fn r_buy(o: &OrderRisk, lots: Qty, tick_size: u64) -> Result<u128, Fault> {
    fee::r_buy(lots, o.tick, tick_size, o.fee_mul).ok_or(Fault::Overflow)
}

/// Charges `ppm` on notional `n`: a fee moves from `quote_free` to `fee_acc`, a rebate the other
/// way (10 §4.4 `apply_fee`). `Δquote_free + Δfee_acc = 0`.
fn charge(b: &mut BookBal, acc: &mut BookAcc, n: u128, ppm: i32) -> Result<(), Fault> {
    let f = fee::fill_fee(n, ppm).ok_or(Fault::Overflow)?;
    let mag = f.unsigned_abs();
    b.quote_free = if f >= 0 {
        sub128(b.quote_free, mag)?
    } else {
        add128(b.quote_free, mag)?
    };
    acc.fee_acc = acc.fee_acc.checked_add(f).ok_or(Fault::Overflow)?;
    Ok(())
}

/// Marks the order closed and frees its `open_orders` count.
fn close(b: &mut BookBal, o: &mut OrderRisk) -> Result<(), Fault> {
    o.closed = true;
    b.open_orders = b.open_orders.checked_sub(1).ok_or(Fault::Underflow)?;
    Ok(())
}

/// Releases the lots that will never fill: `qty − filled_final` (10 §3.9 `risk_release_open`).
/// Buy: `R_buy(qty − filled_final)` from reserved to free; sell: those lots of base.
/// Filled-but-unsettled lots keep their share until their events settle. Faults unless the order
/// is open and `settled ≤ filled_final ≤ qty`.
fn release_open(
    b: &mut BookBal,
    o: &mut OrderRisk,
    filled_final: Qty,
    tick_size: u64,
) -> Result<(), Fault> {
    if o.closed || filled_final < o.settled || filled_final > o.qty {
        return Err(Fault::BadEvent);
    }
    let open = o.qty.checked_sub(filled_final).ok_or(Fault::BadEvent)?;
    match o.side {
        Side::Buy => {
            let r = r_buy(o, open, tick_size)?;
            b.quote_resv = sub128(b.quote_resv, r)?;
            b.quote_free = add128(b.quote_free, r)?;
        }
        Side::Sell => {
            let q = u64::from(open.0);
            b.base_resv = sub64(b.base_resv, q)?;
            b.base_free = add64(b.base_free, q)?;
        }
    }
    close(b, o)
}

impl Settle<'_> {
    /// Runs `f` on copies and commits only if it succeeds.
    fn atomic(
        &mut self,
        o: &mut OrderRisk,
        f: impl FnOnce(&mut BookBal, &mut BookAcc, &mut OrderRisk, &FeeRates, u64) -> Result<(), Fault>,
    ) -> Result<(), Fault> {
        let (mut b, mut acc, mut ord) = (*self.bal, *self.book, *o);
        f(&mut b, &mut acc, &mut ord, self.fees, self.tick_size)?;
        *self.bal = b;
        *self.book = acc;
        *o = ord;
        Ok(())
    }

    /// A `MakerFill`, `TakerFill` or `AuctionFill` of `q` lots at `tick` (10 §4.4).
    ///
    /// Let `rem_u = qty − settled` and `n = N(q, tick)`.
    /// - Buy: `rel = R_buy(rem_u) − R_buy(rem_u − q)` leaves `quote_resv`; `rel − n` goes to
    ///   `quote_free` (the release lemma, 10 §3.2, makes it cover the fee); `base_free += q`.
    /// - Sell: `base_resv −= q`; `quote_free += n`.
    /// - Fee: maker and auction fills pay their rate now; a taker fill adds `n` to the step's
    ///   taker notional, charged at `TakerEnd`.
    /// - `settled += q`; a fully settled open order closes.
    ///
    /// Faults: `q = 0` or `q > rem_u`; a buy filled above its limit or a sell below it.
    pub fn fill(
        &mut self,
        o: &mut OrderRisk,
        kind: FillKind,
        q: Qty,
        tick: Tick,
    ) -> Result<(), Fault> {
        self.atomic(o, |b, acc, o, fees, ts| {
            let rem_u = o.qty.checked_sub(o.settled).ok_or(Fault::BadEvent)?;
            let after = rem_u.checked_sub(q).ok_or(Fault::BadEvent)?;
            let beyond = match o.side {
                Side::Buy => tick > o.tick,
                Side::Sell => tick < o.tick,
            };
            if q.0 == 0 || beyond {
                return Err(Fault::BadEvent);
            }
            let n = fee::notional(q, tick, ts).ok_or(Fault::Overflow)?;
            match o.side {
                Side::Buy => {
                    let rel = sub128(r_buy(o, rem_u, ts)?, r_buy(o, after, ts)?)?;
                    b.quote_resv = sub128(b.quote_resv, rel)?;
                    b.quote_free = add128(b.quote_free, sub128(rel, n)?)?;
                    b.base_free = add64(b.base_free, u64::from(q.0))?;
                }
                Side::Sell => {
                    b.base_resv = sub64(b.base_resv, u64::from(q.0))?;
                    b.quote_free = add128(b.quote_free, n)?;
                }
            }
            match kind {
                FillKind::Taker => acc.taker_notional = add128(acc.taker_notional, n)?,
                FillKind::Maker => charge(b, acc, n, fees.maker_ppm)?,
                FillKind::Auction => charge(b, acc, n, fees.auction_ppm)?,
            }
            o.settled = o.settled.checked_add(q).ok_or(Fault::Overflow)?;
            if o.settled == o.qty && !o.closed {
                close(b, o)?;
            }
            Ok(())
        })
    }

    /// `TakerEnd` (10 §4.4): charges `taker_ppm` once on the step's taker notional, rounded once,
    /// and resets it. Unless the remainder `rests`, the open remainder leaves the book: IOC, FOK,
    /// STP and auction-only remainders release with `filled_final = settled`.
    pub fn taker_end(&mut self, o: &mut OrderRisk, rests: bool) -> Result<(), Fault> {
        self.atomic(o, |b, acc, o, fees, ts| {
            let n = acc.taker_notional;
            charge(b, acc, n, fees.taker_ppm)?;
            acc.taker_notional = 0;
            if !rests && !o.closed {
                let settled = o.settled;
                release_open(b, o, settled, ts)?;
            }
            Ok(())
        })
    }

    /// The release at a `CancelAck`, an `Out` or a kill (10 §3.9): `filled_final` is final (05).
    pub fn release(&mut self, o: &mut OrderRisk, filled_final: Qty) -> Result<(), Fault> {
        self.atomic(o, |b, _, o, _, ts| release_open(b, o, filled_final, ts))
    }

    /// `StpOut` (10 §3.6, §4.4): the BBO core removed `removed` open lots of a resting order.
    pub fn stp_out(&mut self, o: &mut OrderRisk, removed: Qty) -> Result<(), Fault> {
        let filled_final = o.qty.checked_sub(removed).ok_or(Fault::BadEvent)?;
        self.release(o, filled_final)
    }

    /// A `Reduce` by `k` lots that leaves the order live (04 §6.4): releases
    /// `R_buy(rem_u) − R_buy(rem_u − k)` (buy) or `k` lots (sell), and `qty −= k`. A reduce that
    /// ends the order is a cancel: use [`Settle::release`]. Faults unless the order is open and
    /// `1 ≤ k < qty − settled`.
    pub fn reduce(&mut self, o: &mut OrderRisk, k: Qty) -> Result<(), Fault> {
        self.atomic(o, |b, _, o, _, ts| {
            let rem_u = o.qty.checked_sub(o.settled).ok_or(Fault::BadEvent)?;
            if o.closed || k.0 == 0 || k >= rem_u {
                return Err(Fault::BadEvent);
            }
            let after = rem_u.checked_sub(k).ok_or(Fault::BadEvent)?;
            match o.side {
                Side::Buy => {
                    let rel = sub128(r_buy(o, rem_u, ts)?, r_buy(o, after, ts)?)?;
                    b.quote_resv = sub128(b.quote_resv, rel)?;
                    b.quote_free = add128(b.quote_free, rel)?;
                }
                Side::Sell => {
                    b.base_resv = sub64(b.base_resv, u64::from(k.0))?;
                    b.base_free = add64(b.base_free, u64::from(k.0))?;
                }
            }
            o.qty = o.qty.checked_sub(k).ok_or(Fault::BadEvent)?;
            Ok(())
        })
    }

    /// The money half of a `Shed` event (10 §3.11): as if the op never arrived. Releases the whole
    /// reservation and returns the message fee from `fee_acc` to `quote_free`. Faults if any lot
    /// settled. The tokens come back with [`crate::Risk::refund_shed_tokens`].
    pub fn shed(&mut self, o: &mut OrderRisk) -> Result<(), Fault> {
        self.atomic(o, |b, acc, o, _, ts| {
            if o.settled.0 != 0 {
                return Err(Fault::BadEvent);
            }
            release_open(b, o, Qty(0), ts)?;
            let fee = o.msg_fee;
            b.quote_free = add128(b.quote_free, u128::from(fee))?;
            acc.fee_acc = acc
                .fee_acc
                .checked_sub(i128::from(fee))
                .ok_or(Fault::Overflow)?;
            Ok(())
        })
    }
}
