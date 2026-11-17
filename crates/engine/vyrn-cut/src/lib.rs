//! Every cross-core primitive of the engine (spec/11-build.md §1.3): the lane counters, the cut
//! publication (two half-cut lines, 01 §14.3), the snapshot seqlock, `LaneCut`, the rings
//! (lane → BBO, BBO → lane fill events, lane → stream core, BBO → stream and TX cores; 01 §14.5),
//! and the pool primitives of 01 §14.15. Everything except the pool RMWs goes through a
//! `Visibility` backend: `Hw` (atomics) or `Sim` (seeded delays for `vyrn-sim`, §6.4).
//!
//! Each primitive's doc names its writer, its readers, its memory orderings and its spec section.
//! Every line one core writes and another reads is aligned to `SHARED_ALIGN` (§3.6).
#![deny(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

mod line;
mod lines;
pub mod pool;
// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod ring;
mod sync;
mod vis;

pub use line::{PUB_RING, PubRing, Published, Words};
pub use lines::{
    BboFloor, Counter, CounterLine, CutEntry, CutNotMonotone, CutWriter, Floor, HALF_CUT_WORDS,
    HalfCut, HalfCutVal, LANES_PER_HALF, LaneCut, LaneCutEntry, OccEvent, Snapshot, SnapshotLine,
};
pub use pool::{NotHolder, PoolTok, SegMask, StealGuard, StealLock, TakeError};
pub use ring::{Consumer, Producer, Ring};
pub use vis::{Hw, HwLine, SIM_PENDING, Sim, SimLine, Visibility};

/// `BLD_SHARED_ALIGN` (11 §3.6): every single-writer line that crosses cores, on every target.
pub const SHARED_ALIGN: usize = 128;
// Holds for CACHE_LINE = 64 (x86-64, Linux aarch64) and 128 (Apple M-series).
const _: () = assert!(
    SHARED_ALIGN >= vyrn_types::CACHE_LINE && SHARED_ALIGN.is_multiple_of(vyrn_types::CACHE_LINE)
);

/// One 64-byte ring entry line (05 §4.12, §4.15).
pub type Line64 = [u64; 8];
/// One 32-byte `FillEvent` (05 §4.12).
pub type Line32 = [u64; 4];

/// Ring capacities (05 §16).
pub const ENG_FWD_RING: usize = 1024;
pub const ENG_FILL_RING: usize = 65_536;
pub const ENG_OS_RING: usize = 4096;
pub const ENG_STEP_LOG: usize = 4096;
pub const ENG_TX_RING: usize = 4096;
/// StepLog readers: stream cores A and B, fill TX cores A, B and C (01 §14.15.3, §14.17.3).
pub const STEP_LOG_READERS: usize = 5;

/// Lane → BBO: forwarded ops and their dependency lines, pushed with `push_all`.
pub type FwdRing<V> = Ring<Line64, ENG_FWD_RING, 1, V>;
/// BBO → lane: fill events.
pub type FillRing<V> = Ring<Line32, ENG_FILL_RING, 1, V>;
/// Lane → its half's stream core: pre-encoded `PacketRecord`s and `AcctTake`s (01 §14.5).
pub type OsRing<V> = Ring<Line64, ENG_OS_RING, 1, V>;
/// BBO → stream and fill TX cores: step headers and delta lines, pushed with `push_all`.
pub type StepLog<V> = Ring<Line64, ENG_STEP_LOG, STEP_LOG_READERS, V>;
/// BBO → one fill TX core (A, B or C): a header and its response records.
pub type TxRing<V> = Ring<Line64, ENG_TX_RING, 1, V>;
