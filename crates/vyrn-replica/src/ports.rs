//! The two boundaries this crate owns for crates that are not merged yet.
//!
//! - [`ReplayEngine`] is 11 §5.3's trait. `RustReplay` (over `vyrn-engine` in replay mode) and
//!   `VxReplay` (over [`crate::vx`]) will implement it. The payload half exists:
//!   [`crate::DataJoin`] is `vyrn_engine::Payloads`. `RustReplay` does not, because
//!   `vyrn_engine::Engine::replay` takes the engine's own journal (`OwnedRec::Step` with
//!   `StepEntry`) and compares every field but `pub_a`/`pub_b`, while 07's wire `StepRecord`
//!   carries no `n_tx`, `n_fills`, `fill_lanes`, `flags` or band, and 07 fixes no interleaving of
//!   one block's packet records and steps. [`BlockInputs`] therefore cannot be turned into the
//!   engine's input [Certain: from both crates' code]; see the spec gap in the PR.
//! - [`EpochView`] is what the replica reads from the epoch schedule (08, `vyrn-epoch`): the
//!   epoch and book it serves, the sequencer keys of `REP_Membership` (07 §13.1) and the
//!   `INV-FENCE` boundary (07 §6.4 item 5).
//!
//! Both traits are deliberately small. Each method names the spec section it serves, so the
//! crates that implement them can be checked against the same text.

use vyrn_log::{LaneRec, MergedStep};
use vyrn_types::{BlockHeader, BookId, Epoch, Hash, Height, PubKey};

/// The epoch facts the order core needs (08, 07 §13.1).
pub trait EpochView {
    /// The epoch this replica serves.
    fn epoch(&self) -> Epoch;
    /// The book this replica serves.
    fn book(&self) -> BookId;
    /// The `seq_key` that `REP_Membership` registers for sequencer index `sender`, if any.
    fn seq_key(&self, sender: u8) -> Option<PubKey>;
    /// Whether an `INV-FENCE` boundary forbids a block of this epoch at `height` (07 §6.4 item
    /// 5, 08).
    fn fenced(&self, height: Height) -> bool;
}

/// The inputs of one block for replay (07 §7.1), in the order 07 guarantees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInputs<const N: usize> {
    /// The checked header.
    pub header: BlockHeader,
    /// Lane records, substream A's then B's, each in O-order. Every PacketRecord has its
    /// `pkt_hash`. Payloads are joined later, by `(session, pkt_seq)` (07 §5.4).
    pub lanes: Vec<LaneRec>,
    /// `lanes[..split]` are substream A's, the rest B's (`data_root` hashes each half apart).
    pub split: usize,
    /// Steps `header.first_step ..= header.last_step`, gapless.
    pub steps: Vec<MergedStep<N>>,
}

/// Replay outputs of one block that reach the vote and the root (11 §5.3, 07 §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOutputs {
    /// The hash of the block's response records and fill events.
    pub output_hash: Hash,
}

/// A snapshot to load (07 §7.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot(pub Vec<u8>);

/// The canonical state bytes an engine writes at a checkpoint (11 §5.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalStateWriter(pub Vec<u8>);

/// An engine failure. Replay is deterministic, so any error halts this replica's attestations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("replay error: {0}")]
pub struct ReplayError(pub String);

/// The replay boundary of 11 §5.3, implemented by the Rust and the Vx engine.
pub trait ReplayEngine<const N: usize> {
    fn load_snapshot(&mut self, snap: &StateSnapshot) -> Result<(), ReplayError>;
    /// Hands the engine the inputs of one block. It returns when the block's outputs are done.
    fn replay_block(&mut self, blk: &BlockInputs<N>) -> Result<BlockOutputs, ReplayError>;
    fn write_state(&self, w: &mut CanonicalStateWriter) -> Result<(), ReplayError>;
}
