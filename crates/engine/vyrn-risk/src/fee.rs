//! Reservation and fee arithmetic (10 §3.2, §3.3, §5.4). Every function is total: `None` is an
//! overflow, which a pre-trade caller turns into `BAD_QTY` / `RSK_D_OVERFLOW` and settlement into
//! an engine fault (10 §4.5).

use vyrn_types::{Qty, Tick};

use crate::consts::RSK_FEE_DENOM;

/// 2^64.
const TWO64: u128 = 0x1_0000_0000_0000_0000;

/// `max(taker_ppm, maker_ppm, auction_ppm, 0)` (10 §3.2).
#[inline]
pub fn max_fee_ppm(taker_ppm: i32, maker_ppm: i32, auction_ppm: i32) -> u32 {
    let m = taker_ppm.max(maker_ppm).max(auction_ppm).max(0);
    u32::try_from(m).unwrap_or(0)
}

/// `fee_mul = ceil(max_fee_ppm × 2^64 / RSK_FEE_DENOM)` (10 §3.2). `None` above 10^6 ppm.
#[inline]
pub fn fee_mul(max_fee_ppm: u32) -> Option<u64> {
    let x = u128::from(max_fee_ppm).checked_mul(TWO64)?;
    u64::try_from(x.div_ceil(RSK_FEE_DENOM)).ok()
}

/// `N(q, t) = q × t × tick_size`, exact (10 §2.1). Cannot overflow for u32 × u32 × u64; still
/// checked.
#[inline]
pub fn notional(qty: Qty, tick: Tick, tick_size: u64) -> Option<u128> {
    u128::from(qty.0)
        .checked_mul(u128::from(tick.0))?
        .checked_mul(u128::from(tick_size))
}

/// The fee cap `F = ((N × fee_mul) >> 64) + 1 + n`, and 0 for `n = 0` lots (10 §3.2).
#[inline]
pub fn fee_cap(n: u128, qty: Qty, fee_mul: u64) -> Option<u128> {
    if qty.0 == 0 {
        return Some(0);
    }
    let hi = n.checked_mul(u128::from(fee_mul))?.checked_shr(64)?;
    hi.checked_add(1)?.checked_add(u128::from(qty.0))
}

/// `R_buy(n, t) = N(n, t) + F(n, t)`: the quote a buy of `n` lots at limit `t` reserves.
#[inline]
pub fn r_buy(qty: Qty, tick: Tick, tick_size: u64, fee_mul: u64) -> Option<u128> {
    let n = notional(qty, tick, tick_size)?;
    n.checked_add(fee_cap(n, qty, fee_mul)?)
}

/// The fee of one execution of notional `n` at rate `ppm` (10 §3.3), signed as it moves into
/// `fee_acc`: a charge `ceil(n × ppm / D)` for `ppm ≥ 0`, a rebate `−floor(n × |ppm| / D)` below.
#[inline]
pub fn fill_fee(n: u128, ppm: i32) -> Option<i128> {
    let x = n.checked_mul(u128::from(ppm.unsigned_abs()))?;
    if ppm >= 0 {
        i128::try_from(x.div_ceil(RSK_FEE_DENOM)).ok()
    } else {
        i128::try_from(x.checked_div(RSK_FEE_DENOM)?)
            .ok()?
            .checked_neg()
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn worked_example_of_10_5_4() {
        // Tier 1, buy 7 lots at 100_000, tick_size 10.
        let fm = fee_mul(300).unwrap();
        assert_eq!(notional(Qty(7), Tick(100_000), 10), Some(7_000_000));
        assert_eq!(fee_cap(7_000_000, Qty(7), fm), Some(2_108));
        assert_eq!(r_buy(Qty(7), Tick(100_000), 10, fm), Some(7_002_108));
        // Taker fee on the step: ceil(6_999_900 × 300 / 10^6) = ceil(2_099.97).
        assert_eq!(fill_fee(2_999_940 + 3_999_960, 300), Some(2_100));
    }

    #[test]
    fn fee_mul_rounds_up_and_bounds_the_rate() {
        // 1 ppm: 2^64 / 10^6 = 18_446_744_073_709.55… → …710.
        assert_eq!(fee_mul(1), Some(18_446_744_073_710));
        assert_eq!(fee_mul(0), Some(0));
        assert_eq!(fee_mul(1_000_000), None);
        assert_eq!(max_fee_ppm(-5, -1, -9), 0);
        assert_eq!(max_fee_ppm(300, 50, 100), 300);
    }

    #[test]
    fn fee_cap_is_zero_for_zero_lots_and_at_least_one_plus_n() {
        assert_eq!(fee_cap(0, Qty(0), u64::MAX), Some(0));
        assert_eq!(fee_cap(0, Qty(3), 0), Some(4));
        assert_eq!(fee_cap(u128::MAX, Qty(1), 2), None);
    }

    #[test]
    fn charges_round_up_and_rebates_round_down() {
        // Maker 50 on 2_999_940: 149.997 → 150. Rebate 20 on it: 59.9988 → 59.
        assert_eq!(fill_fee(2_999_940, 50), Some(150));
        assert_eq!(fill_fee(2_999_940, -20), Some(-59));
        // Exact multiples do not round.
        assert_eq!(fill_fee(1_000_000, 7), Some(7));
        assert_eq!(fill_fee(1_000_000, -7), Some(-7));
        assert_eq!(fill_fee(0, 400), Some(0));
    }
}
