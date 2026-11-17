//! Control ops of 10 §2.4 that change risk state: allocation credit and debit (§2.5), limits
//! (§3.4), kill (§3.7) and fees (§5.2). They arrive on control session 0 as finalized ops, never on
//! the 1 µs path. A rejected op leaves the state unchanged and is answered `CtlDone` with the
//! reject.

use vyrn_types::{Qty, RejectReason};

use crate::account::{AcctRisk, AcctState, BookBal, BookSpec, FeeRates, band_mul};
use crate::consts::{
    PROTO_D_UNKNOWN_TYPE, REQ_LANE_CROSS_RATE, RSK_COD_MIN_NS, RSK_D_OVERFLOW, RSK_LIMIT_BAND_BPS,
    RSK_LIMIT_COD, RSK_LIMIT_CROSS_RATE, RSK_LIMIT_MAX_NOTIONAL, RSK_LIMIT_MAX_OPEN,
    RSK_LIMIT_MAX_QTY, RSK_LIMIT_NEW_RATE, RSK_LIMIT_STP_MODE, RSK_MAX_OPEN_HARD,
};
use crate::gcra::Gcra;
use crate::reject::{Reject, rej};

/// The asset of an allocation op: byte 1 of `CtlAllocCredit` (0 quote, 1 base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset {
    Quote,
    Base,
}

/// `CtlAllocCredit` (10 §2.5): adds `amount` to the free balance. Reject on overflow: `BAD_QTY`,
/// `RSK_D_OVERFLOW`, and nothing changes.
pub fn credit(bal: &mut BookBal, asset: Asset, amount: u64) -> Result<(), Reject> {
    let over = rej(RejectReason::BadQty, RSK_D_OVERFLOW);
    match asset {
        Asset::Quote => {
            bal.quote_free = bal.quote_free.checked_add(u128::from(amount)).ok_or(over)?;
        }
        Asset::Base => bal.base_free = bal.base_free.checked_add(amount).ok_or(over)?,
    }
    Ok(())
}

/// `finish_debit` (10 §2.5): debits `min(amount, free)` and returns it for `AllocDebited`.
/// Reserved balance is never touched (§2.3 rule 2). `CANCEL_SIDE` calls this after its cancels.
pub fn debit_free(bal: &mut BookBal, asset: Asset, amount: u64) -> u64 {
    match asset {
        Asset::Quote => {
            let d = bal.quote_free.min(u128::from(amount));
            bal.quote_free = bal.quote_free.saturating_sub(d);
            u64::try_from(d).unwrap_or(amount)
        }
        Asset::Base => {
            let d = bal.base_free.min(amount);
            bal.base_free = bal.base_free.saturating_sub(d);
            d
        }
    }
}

/// `CtlSetLimit` (10 §3.4). Applies to orders that arrive after it; resting orders are untouched.
///
/// | id | limit | accepted values |
/// |---|---|---|
/// | 1 | `max_open_orders` | `0 ..= RSK_MAX_OPEN_HARD` |
/// | 2 | `max_order_qty` | `0 ..= Qty::MAX` |
/// | 3 | `max_notional` | any u64 (`RSK_NOTIONAL_HARD_MAX = u64::MAX`) |
/// | 4 | `band_bps` (book) | `0 ..= 10_000` |
/// | 5 | `new_rate` /s | `≥ 1` |
/// | 6 | `cross_rate` /s | `1 ..= REQ_LANE_CROSS_RATE` |
/// | 7 | `cod_timeout_ns` | `0`, or `≥ RSK_COD_MIN_NS` |
/// | 8 | `stp_mode` | `1 ..= 3` |
///
/// Rejects: an unknown id is `BAD_TYPE` / `PROTO_D_UNKNOWN_TYPE`; a value outside its range is
/// `BAD_QTY` with the limit id as detail (10 does not define these codes; a spec gap). A rate
/// change keeps the bucket's burst and its `tat`.
pub fn set_limit(
    acct: &mut AcctRisk,
    spec: &mut BookSpec,
    id: u8,
    value: u64,
) -> Result<(), Reject> {
    let bad = rej(RejectReason::BadQty, u32::from(id));
    let rate =
        |old: &Gcra, r: u64| Gcra::from_rate(r, old.burst).map(|g| Gcra { tat: old.tat, ..g });
    match id {
        RSK_LIMIT_MAX_OPEN => {
            let v = u32::try_from(value)
                .ok()
                .filter(|v| *v <= RSK_MAX_OPEN_HARD);
            acct.max_open_orders = v.ok_or(bad)?;
        }
        RSK_LIMIT_MAX_QTY => acct.max_order_qty = Qty(u32::try_from(value).map_err(|_| bad)?),
        RSK_LIMIT_MAX_NOTIONAL => acct.max_notional = value,
        RSK_LIMIT_BAND_BPS => {
            let bps = u32::try_from(value).map_err(|_| bad)?;
            spec.band_mul = band_mul(bps).ok_or(bad)?;
        }
        RSK_LIMIT_NEW_RATE => acct.buckets.new = rate(&acct.buckets.new, value).ok_or(bad)?,
        RSK_LIMIT_CROSS_RATE => {
            if value > REQ_LANE_CROSS_RATE {
                return Err(bad);
            }
            acct.buckets.cross = rate(&acct.buckets.cross, value).ok_or(bad)?;
        }
        RSK_LIMIT_COD => {
            if value != 0 && value < RSK_COD_MIN_NS {
                return Err(bad);
            }
            acct.cod_timeout_ns = value;
        }
        RSK_LIMIT_STP_MODE => {
            let m = u8::try_from(value).ok().filter(|m| (1..=3).contains(m));
            acct.stp_mode = m.ok_or(bad)?;
        }
        _ => return Err(rej(RejectReason::BadType, PROTO_D_UNKNOWN_TYPE)),
    }
    Ok(())
}

/// `CtlKillAccount` (10 §3.7): byte 1 = 1 kills, 0 unkills. The lane cancels the account's
/// orders; an unkill restores none of them.
pub fn kill(acct: &mut AcctRisk, killed: bool) {
    acct.state = if killed {
        AcctState::Killed
    } else {
        AcctState::Active
    };
}

/// `CtlSetFees` (10 §5.2 rule 2). New rates apply to orders that arrive after it; each resting
/// order keeps the `fee_mul` it reserved with.
///
/// Reject: a raise of `fee_mul` while the book holds a buy reservation (`quote_resv ≠ 0`) could
/// break the release lemma, so it is `RISK_ORDER_COUNT` with detail `open_orders` ("cancel orders
/// first", 04 §8). Lowering is always accepted. Sells never block it: their fee comes from their
/// proceeds.
pub fn set_fees(acct: &mut AcctRisk, bal: &BookBal, rates: FeeRates) -> Result<(), Reject> {
    if rates.fee_mul > acct.fees.fee_mul && bal.quote_resv != 0 {
        return Err(rej(RejectReason::RiskOrderCount, bal.open_orders));
    }
    acct.fees = rates;
    Ok(())
}
