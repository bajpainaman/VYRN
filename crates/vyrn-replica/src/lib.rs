//! The replica: two-path order frames, data fetch, replay engine (Rust or Vx), state roots, votes
//! (spec/07-replication.md, spec/11-build.md §1.3, layer 6 of §1.4).
//!
//! This crate is the replica's order core (07 §7.2 core 3). It sits on `vyrn-log`'s decoder and
//! adds the checks a vote needs that a stateless decoder cannot make, the data join and the epoch
//! handoff state. Repair, the Simplex runtime, replay threads and snapshots are follow-ups.
//!
//! # Contract
//!
//! **Writer.** The sequencer's stream cores, through `vyrn-log`'s `StreamEncoder` (07 §3).
//! Nothing here writes frames.
//!
//! **Input.** [`OrderCore::on_frame`] takes the frames of one tenure, one substream at a time, in
//! `frame_seq` order with no gap, after core 1 has deduplicated the two paths and repaired holes
//! (07 §4.9, §4.10). A frame out of order is [`FrameErr::OutOfOrder`]: the caller's error, not a
//! fault, and nothing changes. [`OrderCore::tick`] runs the `REP_E_HASHLAG` timer. `now` is the
//! replica's monotonic receive clock in nanoseconds. Only the timer reads it, so replay never
//! depends on it (`INV-DET`).
//!
//! **Readers.**
//! - Replay: [`OrderCore::take_ready`] yields one [`BlockInputs`] per block in height order. Each
//!   one has passed every check below, and a [`ReplayEngine`] (11 §5.3) consumes it.
//! - The vote: [`OrderCore::verdict`] answers 07 §6.4 items 2 and 5 for a height range as a
//!   `vyrn_consensus::Verdict`, and [`DataJoin::check`] answers item 3 for a ready block. Item 4
//!   (CHAIN tags) is not here yet, so these are preconditions for a vote, not the whole rule.
//!
//! **Ordering.** Sections are applied in frame order, so a step half-record is checked against
//! the lane records before it on the same substream. A half-cut covers only its own half's lanes,
//! and those lanes travel on the same substream (07 §3.4, §3.8), so the check never waits on the
//! other substream. Steps are merged by StepId (`vyrn_log::StepMerger`). A block becomes ready once
//! four things hold: both halves are closed by their `BlockMark`, its header is held and checked,
//! every PacketRecord in it has its `pkt_hash`, and every step through its `last_step` is merged.
//! Once both halves are closed, a step through `last_step` that the merger lacks is a fault:
//! `vyrn-log` refuses any step at or below a passed mark, so it can never arrive.
//!
//! **Lane-state rules** ([`lane`], 07 §3.5–§3.7). Each lane of each half keeps:
//! - L1: the *decoded prefix*, `next_lane_seq − 1`, which only lane records advance;
//! - L2: the LaneSeq ranges of packets that carry `SHED`;
//! - L3: the FIFO of PacketRecords that wait for their `pkt_hash` (Advance records and
//!   `AcctTake`s never wait). A `HashRun` entry must name the FIFO's head.
//!
//! **Step rules** ([`check_step`], 07 §3.12). Each step half-record must satisfy:
//! - S1, `INV-CUT-MONO`: no lane of the half-cut moves back;
//! - S2: no `cut[l]` above lane `l`'s decoded prefix, `TenureStart.prev_cut` included;
//! - S3: `src_lane` and payload follow the kind table of 07 §3.8;
//! - S4: `src_lane_seq` is a decoded op of `src_lane`, so `1 ≤ src_lane_seq ≤ prefix`;
//! - S5: no step names an op whose packet carries `SHED`, because a shed packet's ops were never
//!   forwarded.
//!
//! **Timer** ([`hashlag`], 07 §3.7 INV-REP-8). A record that waits for its hash for more than
//! [`REP_HASHLAG_MAX_NS`] (1 ms) raises `REP_E_HASHLAG`.
//!
//! **Header rules** (07 §3.10, §6.4 item 1). The header of height `h` must be signed by the
//! frame's sender under [`EpochView::seq_key`], be in the view's epoch and book, chain from the
//! previous header (or from the `TenureStart` anchor), cover exactly the steps its two
//! `BlockMark`s close, and have `order_root` equal to the root of the two halves' ORDER bytes.
//!
//! **Reject reasons.** Every rejection is a sequencer fault: [`Fault`] records `(epoch, tenure,
//! stream, frame_seq)`, the first height that loses its vote, and a [`FaultKind`] with its
//! `REP_E_*` code ([`FaultKind::code`]). After a fault the core takes no more frames, and
//! [`OrderCore::verdict`] is `Invalid` for every range that reaches the faulted height (07 §3.12,
//! §10.1).
//!
//! **Boundaries owned here** ([`ports`]). The replay engine and the epoch schedule reach this
//! crate through two traits it owns: [`ReplayEngine`] (11 §5.3) and [`EpochView`] (08).
//! [`ActiveEpoch`] implements [`EpochView`] over `vyrn_epoch::Activation` and builds the epoch's
//! `vyrn_consensus` voter config. [`ReplicaLocal`] is this replica's `vyrn_epoch::LocalView`,
//! and [`EpochJournal`] makes `SignOnce` admissions and `armed(e+1)` durable before they are
//! acted on ([`epoch`]). [`DataJoin`] joins payloads, checks `data_root` (07 §6.4 item 3) and
//! is the engine's `Payloads` ([`data`]). [`DataFeed`] fills it from `vyrn-data` frames and
//! reports `data_seq` gaps and silent data boxes ([`feed`]). [`RustReplay`] implements `ReplayEngine` over
//! `vyrn_engine::Engine::replay_wire` ([`rust`], which also fixes the block output hash).
//!
//! **Conformance.** `tests/golden/vyrn_replica_vectors.txt` at the repository root lists frame
//! sequences and the verdict a conforming replica reaches on each one. `tests/conformance.rs`
//! runs them. `tests/replay.rs` runs a live engine through `vyrn_log::SeqWriter`, this order core
//! and [`RustReplay`], and checks that replay reproduces the live run byte for byte.
#![deny(unsafe_code)]
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod check;
pub mod data;
pub mod epoch;
pub mod feed;
pub mod hashlag;
pub mod lane;
pub mod order;
pub mod ports;
pub mod rust;

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod vx;

pub use check::{StepErr, check_step};
pub use data::{DataErr, DataJoin, full_hash};
pub use epoch::{ActiveEpoch, EpochJournal, JournalErr, ReplicaLocal};
pub use feed::{DataFeed, Fed, FeedErr, Gap, REP_DATA_SILENCE_NS};
pub use hashlag::{REP_HASHLAG_MAX_NS, check_hashlag};
pub use lane::{LaneErr, LaneState};
pub use order::{Fault, FaultKind, FrameErr, HeaderErr, OrderCore};
pub use ports::{
    BlockInputs, BlockOutputs, CanonicalStateWriter, EpochView, ReplayEngine, ReplayError,
    StateSnapshot,
};
pub use rust::{OUTPUT_DOMAIN, RustReplay, output_hash};
