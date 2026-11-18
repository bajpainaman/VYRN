//! Market data and drop copy from replay events (spec/10-accounts-risk-md.md §7, §8).
//!
//! # Contract
//!
//! This section is the crate's contract. The code below implements it; the conformance tests in
//! `tests/` check it against vectors that another implementation can run.
//!
//! ## Roles
//!
//! - **Writer of the input:** the observer replica's replay engine (`vyrn-replica --observer`,
//!   10 §7.1). It hands `vyrn-md` the replayed events of one book through [`ReplayStream`]. The
//!   replica crate is not a dependency yet; the trait is the seam it will implement.
//! - **This crate:** [`MboEncoder`] turns the event stream into `MBO` packets (10 §7.3, §7.4).
//!   Its output is a pure function of the stream, so the A and B observers emit identical bytes.
//! - **Readers of the output:** subscribers, the snapshotter (itself a subscriber, 10 §7.6) and
//!   relays. [`MboSubscriber`] is the reference reader: it applies the merge rule of 10 §7.4 and
//!   rebuilds the replica's book after every step.
//!
//! ## Input ordering (the [`ReplayStream`] contract)
//!
//! 1. Events of one book and one epoch, in replay order. `rx_ts` never decreases.
//! 2. A [`EventKind::Step`] opens step `T` (`T` strictly increases; the first step is 1). The
//!    `n_exec` [`EventKind::Exec`] events of `T` and its [`EventKind::StepOp`]s follow it before
//!    the next step. The *interval* of `T` runs from step `T` to step `T + 1`.
//! 3. A [`EventKind::LaneOp`] is a lane op (join, cancel, reduce) ordered after the open step and
//!    before the next one. Ops before step 1 are in interval 0.
//! 4. [`EventKind::TimerTick`] marks the `CtlTimerTick` boundary that drives heartbeats.
//!
//! The encoder rejects a stream that breaks 1 or 2 with a [`StreamError`].
//!
//! ## Output (10 §7.3–§7.5)
//!
//! - UDP payload: a 32-byte [`Header`] and `count` 16-byte [`Record`]s, `count ≤ 88`.
//! - Channels: lane channel `k = lane mod 4` carries lane ops; channel 4 (the step channel)
//!   carries `MD_STEP`, its `MD_EXEC`s, step ops, `MD_STATUS` and `MD_ATTEST`.
//! - `seq` starts at 1 per channel per epoch and grows by 1 per packet, heartbeats included.
//! - A lane channel emits `MD_SYNC(T)` before its first record of interval `T`.
//! - A packet closes when (a) it holds 88 records, (b) it is non-empty at the end of an interval
//!   that added no record to it, (c) at the end of the first interval after which its first record
//!   is `MD_FLUSH_NS` older than the newest `rx_ts`, or (d) a record's `ts_delta` would not fit
//!   in `u16` against the packet's `ts_base`.
//! - Lane-channel `step_base` is the watermark `W`: every record ordered before step `W + 1` is in
//!   this packet or earlier. [`NO_WATERMARK`] means "none yet" (interval 0, see spec gaps).
//! - Step-channel `step_base` is the step open when the packet's first record was written.
//! - `ts_base` is the `rx_ts` of the packet's first record.
//!
//! ## Reader rule (10 §7.4)
//!
//! Apply step `T` only when `W_k ≥ T − 1` for every lane channel `k`. Before step `T`, apply every
//! pending lane op whose `MD_SYNC` position is `< T`. [`MboSubscriber`] implements this.
//!
//! ## Reject reasons
//!
//! - [`RecordError`]: unknown type, non-zero reserved bytes or flag bits, out-of-range codes.
//! - [`PacketError`]: short packet, unknown feed, too many records, length ≠ `32 + 16 × count`.
//! - [`SubError`]: wrong feed or book, sequence gap, a record on the wrong channel, a record that
//!   does not apply to the book (duplicate oid, unknown oid, over-fill).
//!
//! ## Spec gaps (choices made here, each labeled in the code)
//!
//! 1. 10 §7.4's rule is vacuous for step 1 (`W ≥ 0` always holds), so a reader could apply step 1
//!    before every interval-0 lane op arrived. Here a lane packet closed inside interval 0 carries
//!    [`NO_WATERMARK`], and a reader starts with no watermark. \[Guessing\]
//! 2. A quiet lane channel advances its watermark only by heartbeat (`MD_HEARTBEAT_MS = 1`), which
//!    can hold steps for up to 1 ms, against `MD_LAG_P99_NS = 5_000`. \[Likely\] Not solved here.
//! 3. `MD_SYNC` is emitted only at a new interval, as 10 §7.4 says, so a reader that joins
//!    mid-stream cannot place lane ops until `MD_SNAP_RESUME` carries the position. \[Likely\]
//! 4. At epoch end every channel sends one final packet (a heartbeat if empty) with `W` = the last
//!    step, so readers can apply the last steps. 10 §7.3 does not say this. \[Guessing\]
//! 5. `ts_base` choice and the step-channel `step_base` at a packet that starts with `MD_STEP(T)`
//!    (here `T`) are not fixed by 10 §7.3. \[Guessing\]
#![forbid(unsafe_code)]

/// A `u8`-coded enum with `code` and `from_code`.
macro_rules! code_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $v:ident = $c:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name { $($(#[$vdoc])* $v = $c),* }

        impl $name {
            pub const fn code(self) -> u8 {
                self as u8
            }

            pub const fn from_code(c: u8) -> Option<Self> {
                match c {
                    $($c => Some(Self::$v),)*
                    _ => None,
                }
            }
        }
    };
}

pub mod dropcopy;
mod mbo;
mod packet;
mod record;
mod stream;
mod subscriber;

pub use mbo::{MboEncoder, PacketSink, StreamError};
pub use packet::{Channel, Feed, HEADER_BYTES, Header, NO_WATERMARK, Packet, PacketError};
pub use record::{AttestKind, BookStatus, DeleteCause, REC_BYTES, Record, RecordError, Side};
pub use stream::{BookOp, Event, EventKind, ReplayStream, oid};
pub use subscriber::{Book, BookError, MboSubscriber, Order, SubError};

/// Records per packet (10 §7.3).
pub const MD_MAX_RECS_PER_PKT: usize = 88;
/// MBO lane channels; the step channel has index 4 (10 §7.4).
pub const MD_MBO_LANE_CHANNELS: usize = 4;
/// Index of the MBO step channel (10 §7.4).
pub const MD_MBO_STEP_CHANNEL: u8 = 4;
/// Flush rule (c), in ns of order-stream time (10 §7.3).
pub const MD_FLUSH_NS: u64 = 1_000;
/// Heartbeat period of a channel with nothing to send (10 §7.3).
pub const MD_HEARTBEAT_MS: u64 = 1;
