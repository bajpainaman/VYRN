//! Constants of spec/10-accounts-risk-md.md (Local definitions) and spec/04-protocol.md §9.1 and
//! §14 that the risk checks use. A **config** value here is the default; the epoch configuration
//! may override it. Every value is a budget unless marked otherwise.

// ---- Fees and hard bounds (10 §5.1, §3.4; const) ----

/// Fee rates are parts per `RSK_FEE_DENOM` (ppm).
pub const RSK_FEE_DENOM: u128 = 1_000_000;
/// Hard cap on the magnitude of any fee rate (1%).
pub const RSK_FEE_PPM_MAX: u32 = 10_000;
/// Tiers per book in a fee schedule.
pub const RSK_FEE_TIERS: usize = 8;
/// Hard bound of limit 1, `max_open_orders`.
pub const RSK_MAX_OPEN_HARD: u32 = 1_048_576;
/// Hard bound of limit 3, `max_notional`.
pub const RSK_NOTIONAL_HARD_MAX: u64 = u64::MAX;
/// Hard bound of limit 6, `cross_rate`: `REQ_LANE_CROSS_RATE` (02 REQ-THR-6).
pub const REQ_LANE_CROSS_RATE: u64 = 220_000;
/// Improve rate of one dedicated lane (10 §3.8, 02).
pub const REQ_LANE_IMPROVE_RATE: u64 = 440_000;

// ---- Limit ids of `CtlSetLimit` (10 §3.4) ----

pub const RSK_LIMIT_MAX_OPEN: u8 = 1;
pub const RSK_LIMIT_MAX_QTY: u8 = 2;
pub const RSK_LIMIT_MAX_NOTIONAL: u8 = 3;
pub const RSK_LIMIT_BAND_BPS: u8 = 4;
pub const RSK_LIMIT_NEW_RATE: u8 = 5;
pub const RSK_LIMIT_CROSS_RATE: u8 = 6;
pub const RSK_LIMIT_COD: u8 = 7;
pub const RSK_LIMIT_STP_MODE: u8 = 8;

// ---- Config defaults (10 §3.4, §3.5, §3.7, §3.8, §5.2, §5.3) ----

/// Default limit 1.
pub const RSK_DEFAULT_MAX_OPEN: u32 = 10_000;
/// Default limit 3, quote units per order.
pub const RSK_DEFAULT_MAX_NOTIONAL: u64 = 1_000_000_000_000;
/// Default limit 4, the band in basis points.
pub const RSK_DEFAULT_BAND_BPS: u32 = 500;
/// Hard bound of limit 4.
pub const RSK_BAND_BPS_MAX: u32 = 10_000;
/// Smallest band half-width in ticks.
pub const RSK_BAND_MIN_TICKS: u32 = 16;
/// Smallest nonzero cancel-on-disconnect timeout.
pub const RSK_COD_MIN_NS: u64 = 1_000_000;
/// Default STP mode, 1 = cancel newest (10 §3.4 limit 8).
pub const RSK_DEFAULT_STP_MODE: u8 = 1;
/// Tier-0 taker and maker rates, and the auction rate.
pub const RSK_DEFAULT_TAKER_PPM: i32 = 400;
pub const RSK_DEFAULT_MAKER_PPM: i32 = 100;
pub const RSK_DEFAULT_AUCTION_PPM: i32 = 100;
/// Message fees: `RSK_MSGFEE_PER_BBO_NS` (1) × `BBO_IMPROVE_NS` (8) and × `BBO_CROSS_NS` (15).
pub const RSK_DEFAULT_MSG_FEE_IMPROVE: u32 = 8;
pub const RSK_DEFAULT_MSG_FEE_CROSS: u32 = 15;
/// Account buckets: rate per second and burst.
pub const RSK_NEW_RATE: u64 = 1_000_000;
pub const RSK_NEW_BURST: u64 = 10_000;
pub const RSK_CROSS_RATE: u64 = 100_000;
pub const RSK_CROSS_BURST: u64 = 1_000;
/// Lane buckets of one dedicated lane; the pool's are `RSK_POOL_CORES` times these.
pub const RSK_LANE_CROSS_BURST: u64 = 2_200;
pub const RSK_LANE_IMPROVE_BURST: u64 = 4_400;
pub const RSK_POOL_CORES: u64 = 7;

// ---- Reject details (10 Local definitions, §3.1, §1.4; const) ----

/// `RATE_LIMIT` details for the buckets of 10 §3.8: 8–11, after 04 §9.1's bucket ids 1–7.
pub const RSK_BUCKET_NEW: u32 = 8;
pub const RSK_BUCKET_CROSS: u32 = 9;
pub const RSK_BUCKET_LANE_CROSS: u32 = 10;
pub const RSK_BUCKET_LANE_IMPROVE: u32 = 11;
/// `BAD_QTY` details (10 §3.1).
pub const RSK_D_QTY_ZERO: u32 = 1;
pub const RSK_D_QTY_MAX: u32 = 2;
pub const RSK_D_NOTIONAL: u32 = 3;
pub const RSK_D_OVERFLOW: u32 = 4;
/// `RISK_ORDER_COUNT` detail when the lane's slot pool is full (10 §3.4).
pub const RSK_D_LANE_FULL: u32 = 5;
/// `SESSION_CLOSED` detail flag for a session closed because its account moved lane (10 §1.4).
pub const RSK_D_MOVED: u32 = 0x100;
/// `RISK_CREDIT` details (10 §3.1): which asset is short.
pub const RSK_CREDIT_QUOTE: u32 = 1;
pub const RSK_CREDIT_BASE: u32 = 2;

// ---- 04 §9.1 buckets; the id is the `RATE_LIMIT` detail ----

pub const PROTO_BUCKET_PKT: u32 = 1;
pub const PROTO_BUCKET_MSG: u32 = 2;
pub const PROTO_BUCKET_BBO: u32 = 3;
pub const PROTO_BUCKET_PKT_ACCOUNT: u32 = 4;
pub const PROTO_BUCKET_MSG_ACCOUNT: u32 = 5;
pub const PROTO_BUCKET_BBO_ACCOUNT: u32 = 6;
/// `MSG` tokens per `CancelAll`.
pub const PROTO_CANCELALL_TOKENS: u64 = 16;
/// `BBO` units of a cross (`IOC` and `FOK` included) and of an improve.
pub const PROTO_BBO_UNITS_CROSS: u64 = 5;
pub const PROTO_BBO_UNITS_IMPROVE: u64 = 1;
/// Tier T1 defaults: rate per second and burst. `BBO` is 100k cross-equivalents/s in units.
pub const PROTO_PKT_RATE: u64 = 1_000_000;
pub const PROTO_PKT_BURST: u64 = 256;
pub const PROTO_MSG_RATE: u64 = 5_000_000;
pub const PROTO_MSG_BURST: u64 = 2_560;
pub const PROTO_BBO_RATE: u64 = 500_000;
pub const PROTO_BBO_BURST: u64 = 640;

// ---- 04 §14 detail and phase codes ----

/// `BAD_TYPE` detail for an unknown code (here: an unknown limit id).
pub const PROTO_D_UNKNOWN_TYPE: u32 = 1;
/// `AUCTION_PHASE` details.
pub const PROTO_PHASE_CONTINUOUS: u32 = 1;
pub const PROTO_PHASE_AUCTION: u32 = 2;

/// Nanoseconds per second, for bucket rates.
pub const NS_PER_S: u64 = 1_000_000_000;
