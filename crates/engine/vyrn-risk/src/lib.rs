//! Lane-local accounts, reservations (01 §12.1), rate limits, fees, positions.
//!
//! The pre-trade checks of spec/10-accounts-risk-md.md §3 in the check order of
//! spec/04-protocol.md §3.3, the rate buckets of 04 §9.1 and 10 §3.8, settlement on fill events
//! (10 §4), fees (10 §5) and the risk control ops (10 §2.4). Every check returns a 01 §6.5 reject
//! ([`Reject`]); settlement never rejects and returns a [`Fault`] only for an engine bug.
//!
//! - [`Risk`]: `check_packet` (04 V10), `check_new` (M1–M8), `check_cancel`, `refund_shed_tokens`.
//! - [`Settle`]: `fill`, `taker_end`, `release`, `stp_out`, `reduce`, `shed`.
//! - [`ctl`]: `credit`, `debit_free`, `set_limit`, `kill`, `set_fees`.
//! - [`fee`]: `notional`, `fee_cap`, `r_buy`, `fill_fee`, `fee_mul`.
//!
//! The records keep 10 §1.2's fields but not its cache-line layout (`AcctRisk` is 128 B there);
//! the layout belongs with the B-RSK1 benchmark. The v2 perps preview (10 §6) is out of scope.
#![forbid(unsafe_code)]
#![no_std]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

mod account;
mod band;
mod check;
pub mod consts;
pub mod ctl;
pub mod fee;
mod gcra;
mod order;
mod reject;
mod settle;

pub use account::{
    Accounts, AcctBuckets, AcctRisk, AcctSlot, AcctState, BookAcc, BookBal, BookSpec, FeeRates,
    LaneBuckets, SessionBuckets, band_mul,
};
pub use band::band_width;
pub use check::{CancelKind, Risk, charged_route};
pub use gcra::Gcra;
pub use order::{NewOrder, OrderRisk, Phase, Route, Side, Snapshot, Tif};
pub use reject::Reject;
pub use settle::{Fault, FillKind, Settle};
