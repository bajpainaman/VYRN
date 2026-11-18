//! The VYRN log (spec/07-replication.md §2, §3, §6.1, §8): order-stream encoding with LEB128
//! deltas, block assembly, the hash chain, block storage, and the readers replay uses.
//!
//! The byte formats are a contract that every client, the Vx client included, reproduces bit
//! for bit. Each module documents its format before its code:
//!
//! - [`leb`]: LEB128 and ZigZag, canonical forms only.
//! - [`layout`]: which lanes each substream carries.
//! - [`stream`]: sections, lane records, step half-records, `BlockMark`, `TenureStart`, and
//!   the shared encoder/decoder state of one substream.
//! - [`frame`]: the 24-byte frame header and the per-substream [`StreamEncoder`] and
//!   [`StreamDecoder`].
//! - [`merge`]: whole `StepRecord`s from the two substreams.
//! - [`block`]: the 190-byte `BlockHeader`, `header_hash`, `seq_sig`, the roots, assembly and
//!   the chain rules.
//! - [`writer`]: the sequencer's stream core on one substream, engine records in, frames out.
//! - [`store`]: `REP_BlockRecord`, the [`BlockStore`] trait, [`MemStore`], [`FileStore`] and
//!   [`LogReader`].
//!
//! Golden vectors that an independent implementation can check are in
//! `tests/golden/vyrn_log_vectors.{py,out}` at the repository root.
//!
//! Decoding is strict: a decoder accepts exactly the bytes the encoder produces from the same
//! state, so two clients never disagree on whether a frame is valid. Every rejection is a
//! sequencer fault ([`RepErr`]); nothing here panics on input bytes.
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod block;
pub mod frame;
pub mod layout;
pub mod leb;
pub mod merge;
pub mod store;
pub mod stream;
pub mod writer;

pub use block::{BlockAssembler, ChainError, check_anchor, check_link, header_hash};
pub use frame::{
    Body, Frame, FrameHeader, FrameKind, Heartbeat, Ident, StreamDecoder, StreamEncoder,
};
pub use layout::Layout;
pub use merge::{MergedStep, StepMerger};
pub use store::{Block, BlockKind, BlockStore, FileStore, LogReader, MemStore, StoreError};
pub use stream::{
    BlockMark, BodyKind, HalfBlock, Home, LaneBase, LaneRec, Section, SessionBind, StepHalf,
    SubstreamState, TenureStart,
};
pub use writer::SeqWriter;

/// Decoder and stream errors. Each is a sequencer fault: the replica stops voting for the block
/// and records the error with `(epoch, tenure, stream, frame_seq)` (07 §3.12). The first seven
/// are 07's `REP_E_*` codes (07 §15); the rest name rejections 07 leaves unnamed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RepErr {
    /// `REP_E_TAG`: a reserved tag, a tag not allowed in this frame kind, or bad padding.
    #[error("REP_E_TAG")]
    Tag,
    /// `REP_E_COUNT`: a count above 10, an empty run, or a malformed Advance or AcctTake.
    #[error("REP_E_COUNT")]
    Count,
    /// `REP_E_TS`: `rx_ts` leaves the u64 range.
    #[error("REP_E_TS")]
    Ts,
    /// `REP_E_KIND`: a step kind 9–15, or a source or payload the kind does not allow.
    #[error("REP_E_KIND")]
    Kind,
    /// `REP_E_CUT`: a cut mode or form other than the canonical one, or a home on the wrong half.
    #[error("REP_E_CUT")]
    Cut,
    /// `REP_E_TENURE`: `TenureStart` missing from frame 1, present elsewhere, or inconsistent.
    #[error("REP_E_TENURE")]
    Tenure,
    /// `REP_E_HASHLAG` is time-based and raised by the replica, not by this decoder.
    #[error("REP_E_HASHLAG")]
    HashLag,
    /// The body ended inside a field.
    #[error("truncated")]
    Truncated,
    /// A LEB128 varint that is overlong or above `u64::MAX`.
    #[error("non-canonical LEB128")]
    Leb,
    /// A flag set with nothing to signal: a zero delta, or the predicted `pkt_seq`.
    #[error("non-canonical record")]
    Canon,
    /// A value outside its field or an overflow: slot, u32 field, LaneSeq, StepId, unbound slot.
    #[error("value out of range")]
    Range,
    /// A lane that is not on this substream's half.
    #[error("lane not on this substream")]
    Half,
    /// A `BlockMark` that disagrees with the decoded state, or a step at or below the last mark.
    #[error("bad block mark")]
    Mark,
    /// A `HashRun` longer than the lane's records awaiting a hash.
    #[error("hash run without records")]
    Hash,
    /// The two substreams' step records do not merge.
    #[error("step records do not merge")]
    Step,
    /// A bad frame header.
    #[error("bad frame header")]
    Header,
    /// A `frame_seq` other than the next one.
    #[error("frame_seq is not the next one")]
    Seq,
    /// The substream already failed.
    #[error("substream already failed")]
    Poisoned,
    /// An invalid [`Layout`] or a stream it does not have.
    #[error("bad layout")]
    Layout,
}
