//! Lane-local account state (10 §1.2), per-book balances (10 §2), the book's risk configuration,
//! and the buckets of 04 §9.1 and 10 §3.8. Every record here is written only by the owning lane
//! (`INV-WRITER`).

use vyrn_types::{AccountId, Dense, DenseId, Qty, RejectReason, Tick};

use crate::consts::{
    NS_PER_S, PROTO_BBO_BURST, PROTO_BBO_RATE, PROTO_MSG_BURST, PROTO_MSG_RATE, PROTO_PKT_BURST,
    PROTO_PKT_RATE, REQ_LANE_CROSS_RATE, REQ_LANE_IMPROVE_RATE, RSK_BAND_BPS_MAX, RSK_CROSS_BURST,
    RSK_CROSS_RATE, RSK_DEFAULT_AUCTION_PPM, RSK_DEFAULT_BAND_BPS, RSK_DEFAULT_MAKER_PPM,
    RSK_DEFAULT_MAX_NOTIONAL, RSK_DEFAULT_MAX_OPEN, RSK_DEFAULT_MSG_FEE_CROSS,
    RSK_DEFAULT_MSG_FEE_IMPROVE, RSK_DEFAULT_STP_MODE, RSK_DEFAULT_TAKER_PPM, RSK_FEE_PPM_MAX,
    RSK_LANE_CROSS_BURST, RSK_LANE_IMPROVE_BURST, RSK_NEW_BURST, RSK_NEW_RATE, RSK_POOL_CORES,
};
use crate::fee;
use crate::gcra::Gcra;
use crate::order::Route;
use crate::reject::{Reject, rej};

/// A dense lane-local account slot (10 §1.2). The session table maps a session to it, so the hot
/// path never looks an account up by `AccountId`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AcctSlot(pub u32);

impl DenseId for AcctSlot {
    #[inline(always)]
    fn raw(self) -> u64 {
        u64::from(self.0)
    }
}

/// 10 §1.2 `AcctState`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AcctState {
    #[default]
    Active,
    Killed,
    Closed,
}

/// An account's fee rates (10 §5.1–§5.3) and the reservation multiplier derived from them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRates {
    pub taker_ppm: i32,
    pub maker_ppm: i32,
    pub auction_ppm: i32,
    pub msg_fee_improve: u32,
    pub msg_fee_cross: u32,
    /// `ceil(max_fee_ppm × 2^64 / RSK_FEE_DENOM)` (10 §3.2).
    pub fee_mul: u64,
}

impl FeeRates {
    /// All zero: no fee, no rebate, `fee_mul` 0.
    pub const ZERO: Self = Self {
        taker_ppm: 0,
        maker_ppm: 0,
        auction_ppm: 0,
        msg_fee_improve: 0,
        msg_fee_cross: 0,
        fee_mul: 0,
    };

    /// Contract (10 §5.1, §5.2 rule 1). Returns `None` unless every rate has magnitude at most
    /// `RSK_FEE_PPM_MAX`, `taker_ppm ≥ 0`, `auction_ppm ≥ 0` (the auction fee is charged on both
    /// sides, never paid), and `−maker_ppm ≤ taker_ppm`, so a rebate never exceeds the taker fee
    /// of the same match. Computes `fee_mul` from `max(taker, maker, auction, 0)`.
    pub fn new(
        taker_ppm: i32,
        maker_ppm: i32,
        auction_ppm: i32,
        msg_fee_improve: u32,
        msg_fee_cross: u32,
    ) -> Option<Self> {
        let in_cap = |p: i32| p.unsigned_abs() <= RSK_FEE_PPM_MAX;
        if !(in_cap(taker_ppm) && in_cap(maker_ppm) && in_cap(auction_ppm)) {
            return None;
        }
        if taker_ppm < 0 || auction_ppm < 0 || maker_ppm.checked_neg()? > taker_ppm {
            return None;
        }
        let fee_mul = fee::fee_mul(fee::max_fee_ppm(taker_ppm, maker_ppm, auction_ppm))?;
        Some(Self {
            taker_ppm,
            maker_ppm,
            auction_ppm,
            msg_fee_improve,
            msg_fee_cross,
            fee_mul,
        })
    }

    /// The message fee of an accepted order charged as `route` (10 §5.3): joins are free.
    #[inline]
    pub const fn msg_fee(&self, route: Route) -> u32 {
        match route {
            Route::Join => 0,
            Route::Improve => self.msg_fee_improve,
            Route::Cross => self.msg_fee_cross,
        }
    }
}

impl Default for FeeRates {
    /// Tier 0 of 10 §5.2 and the message fees of 10 §5.3.
    fn default() -> Self {
        Self::new(
            RSK_DEFAULT_TAKER_PPM,
            RSK_DEFAULT_MAKER_PPM,
            RSK_DEFAULT_AUCTION_PPM,
            RSK_DEFAULT_MSG_FEE_IMPROVE,
            RSK_DEFAULT_MSG_FEE_CROSS,
        )
        .unwrap_or(Self::ZERO)
    }
}

/// A bucket of `rate` per second; a zero rate gets a one-per-second bucket.
fn bucket(rate: u64, burst: u64) -> Gcra {
    Gcra::from_rate(rate, burst).unwrap_or(Gcra::new(NS_PER_S, burst))
}

/// A session's buckets of 04 §9.1 (ids 1–3). Tier T1 defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBuckets {
    pub pkt: Gcra,
    pub msg: Gcra,
    pub bbo: Gcra,
}

impl Default for SessionBuckets {
    fn default() -> Self {
        Self {
            pkt: bucket(PROTO_PKT_RATE, PROTO_PKT_BURST),
            msg: bucket(PROTO_MSG_RATE, PROTO_MSG_BURST),
            bbo: bucket(PROTO_BBO_RATE, PROTO_BBO_BURST),
        }
    }
}

/// An account's buckets: 04 §9.1 at account scope (ids 4–6), and 10 §3.8 `new_bucket` and
/// `cross_bucket`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcctBuckets {
    pub pkt: Gcra,
    pub msg: Gcra,
    pub bbo: Gcra,
    pub new: Gcra,
    pub cross: Gcra,
}

impl Default for AcctBuckets {
    fn default() -> Self {
        Self {
            pkt: bucket(PROTO_PKT_RATE, PROTO_PKT_BURST),
            msg: bucket(PROTO_MSG_RATE, PROTO_MSG_BURST),
            bbo: bucket(PROTO_BBO_RATE, PROTO_BBO_BURST),
            new: bucket(RSK_NEW_RATE, RSK_NEW_BURST),
            cross: bucket(RSK_CROSS_RATE, RSK_CROSS_BURST),
        }
    }
}

/// The `lane_cross` and `lane_improve` buckets of one dedicated lane, or of the whole pool
/// (10 §3.8). In a book group they meter the group's sum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneBuckets {
    pub cross: Gcra,
    pub improve: Gcra,
}

impl LaneBuckets {
    /// One dedicated lane: 220k crosses/s burst 2_200, 440k improves/s burst 4_400.
    pub fn dedicated() -> Self {
        Self::scaled(1)
    }

    /// The pool: `RSK_POOL_CORES` times a dedicated lane, per pool, not per pool core.
    pub fn pool() -> Self {
        Self::scaled(RSK_POOL_CORES)
    }

    fn scaled(k: u64) -> Self {
        let s = |x: u64| x.saturating_mul(k);
        Self {
            cross: bucket(s(REQ_LANE_CROSS_RATE), s(RSK_LANE_CROSS_BURST)),
            improve: bucket(s(REQ_LANE_IMPROVE_RATE), s(RSK_LANE_IMPROVE_BURST)),
        }
    }
}

/// One account in its lane (10 §1.2 `AcctRisk`, without the cache-line layout: see the crate
/// docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcctRisk {
    pub account: AccountId,
    pub master: AccountId,
    pub state: AcctState,
    /// Limit 8: the account's default STP mode, 1–3 (01 §6.2 bits 4–5).
    pub stp_mode: u8,
    /// 0 = no STP; else the master's tag for this epoch (10 §3.6).
    pub stp_tag: u16,
    /// Limit 1, per book.
    pub max_open_orders: u32,
    /// Limit 2.
    pub max_order_qty: Qty,
    /// Limit 3, quote units per order.
    pub max_notional: u64,
    /// Limit 7, 0 = off.
    pub cod_timeout_ns: u64,
    pub fees: FeeRates,
    pub buckets: AcctBuckets,
}

impl AcctRisk {
    /// An active account with every config default of 10 §3.4, §3.8 and §5.
    pub fn new(account: AccountId, master: AccountId) -> Self {
        Self {
            account,
            master,
            state: AcctState::Active,
            stp_mode: RSK_DEFAULT_STP_MODE,
            stp_tag: 0,
            max_open_orders: RSK_DEFAULT_MAX_OPEN,
            max_order_qty: Qty(u32::MAX),
            max_notional: RSK_DEFAULT_MAX_NOTIONAL,
            cod_timeout_ns: 0,
            fees: FeeRates::default(),
            buckets: AcctBuckets::default(),
        }
    }
}

/// An account's allocation (escrow) in one book (10 §1.2, §2.2). Free plus reserved is the
/// allocation; reserved backs live orders.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BookBal {
    pub quote_free: u128,
    pub quote_resv: u128,
    pub base_free: u64,
    pub base_resv: u64,
    /// Live orders of this account in this book.
    pub open_orders: u32,
}

const _: () = assert!(core::mem::size_of::<BookBal>() == 64);

/// The lane's per-book accumulators: `fee_acc` (10 §5.5), the venue's net fees, and the taker
/// notional of the step being settled (10 §4.4, one taker fee per order and step).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BookAcc {
    pub fee_acc: i128,
    pub taker_notional: u128,
}

/// What risk reads of a book's `BookSpec` (10 §2.1, §3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookSpec {
    /// Quote units per lot per tick, ≥ 1.
    pub tick_size: u64,
    pub min_tick: Tick,
    pub max_tick: Tick,
    /// `floor(band_bps × 2^32 / 10_000)`, computed at config time.
    pub band_mul: u64,
}

impl BookSpec {
    /// `None` unless `tick_size ≥ 1`, `1 ≤ min_tick ≤ max_tick` and `band_bps ≤ 10_000`.
    pub fn new(tick_size: u64, min_tick: Tick, max_tick: Tick, band_bps: u32) -> Option<Self> {
        if tick_size == 0 || min_tick.0 == 0 || min_tick > max_tick {
            return None;
        }
        Some(Self {
            tick_size,
            min_tick,
            max_tick,
            band_mul: band_mul(band_bps)?,
        })
    }

    /// A book with the default 500 bps band.
    pub fn with_default_band(tick_size: u64, min_tick: Tick, max_tick: Tick) -> Option<Self> {
        Self::new(tick_size, min_tick, max_tick, RSK_DEFAULT_BAND_BPS)
    }
}

/// `floor(band_bps × 2^32 / 10_000)`, `None` above `RSK_BAND_BPS_MAX`.
pub fn band_mul(band_bps: u32) -> Option<u64> {
    if band_bps > RSK_BAND_BPS_MAX {
        return None;
    }
    u64::from(band_bps)
        .checked_mul(1 << 32)?
        .checked_div(u64::from(RSK_BAND_BPS_MAX))
}

/// The accounts of one lane and their balances in one book, by dense slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accounts<const N: usize> {
    acct: Dense<AcctRisk, N>,
    bal: Dense<BookBal, N>,
}

impl<const N: usize> Accounts<N> {
    /// `N` copies of `fill`, with empty balances. `N` must be a power of two (`Dense`).
    pub fn new(fill: AcctRisk) -> Self {
        Self {
            acct: Dense::new([fill; N]),
            bal: Dense::new([BookBal::default(); N]),
        }
    }

    /// The account and balance in `slot`, or `UNKNOWN_HANDLE` (detail 0) if the slot is not in
    /// this lane (10 §2.5).
    pub fn get_mut(&mut self, slot: AcctSlot) -> Result<(&mut AcctRisk, &mut BookBal), Reject> {
        let unknown = rej(RejectReason::UnknownHandle, 0);
        let a = self.acct.get_mut(slot).ok_or(unknown)?;
        let b = self.bal.get_mut(slot).ok_or(unknown)?;
        Ok((a, b))
    }
}
