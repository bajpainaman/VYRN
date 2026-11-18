//! `vyrn-engine`: lane, cut and BBO joined into one engine, in two modes, live and replay
//! (11 §1.3, 05 §1.1, §10, 01 §11.6). It owns [`alloc::seal`], the sealing allocator
//! (`INV-NOALLOC`, 11 §3.5) and the core-role table ([`role`]).
//!
//! # Contract
//!
//! The engine adds no matching rule. Every decision is made by `vyrn-lane` (admission, risk,
//! routing, settlement) or `vyrn-bbo` (steps). The engine plays the cores that neither crate
//! implements, and it is the only writer of the lines those cores own:
//!
//! | object | writer | readers | ordering | spec |
//! |---|---|---|---|---|
//! | half-cuts A and B | engine, cut-core role ([`Engine::step`]) | BBO core | each lane's `CounterLine` is read (Acquire), then both halves are published through `CutWriter` (`INV-CUT-MONO`; a backwards entry is [`Fault::CutNotMonotone`]) before every BBO poll | 05 §4.13, §7.1 |
//! | `LaneCut[l]` | engine, stream-core role | lane `l` | written after the step's `StepEntry` and every `CutDelta` line were read from the `StepLog` (frame first, `INV-FRAME-FIRST`) | 05 §4.15 |
//! | each lane's `SnapshotLine` | engine, snapshot fan-out | lane `l` | copied from the BBO's line before every BBO poll and before every lane poll | 05 §4.14 |
//! | order stream ([`Rec`]) | engine, in call order | [`Sink`], [`Engine::replay`] | lane records in each lane's production order; a step's [`Rec::Step`] after its last lane record that the step's cut covers | 01 §6.6, 05 §6.2 |
//! | responses | lanes ([`Sink::lane_resp`]) and the fill TX role ([`Sink::tx`]) | gateway | lane packets carry their `Gate`; TX packets go out after their `StepEntry` | 05 §8.10 |
//!
//! **Modes** (`C-ONEBIN`: one code path, chosen by the call, not by a build flag).
//!
//! - **Live.** The caller feeds received packets to [`Engine::ingest`] and calls
//!   [`Engine::step`] and [`Engine::poll_lanes`] (or [`Engine::run`]) to drive the BBO core and
//!   the lane boundaries. Clocks are passed in: the lane's and the BBO's deadline tests are the
//!   only clock reads (11 §3.1).
//! - **Replay.** [`Engine::replay`] takes the order stream and a [`Payloads`] store and re-runs
//!   every lane call and every step. No clock is read: a `SHED` record is replayed with a late
//!   clock, every other packet with an on-time clock, and each step's source deadline test is
//!   given the instant that reproduces its logged kind (`Shed` or not). Because the replayed
//!   steps write the same `LaneCut` values in the same record order, a non-`MID` Advance record
//!   is replayed as the lane's idle poll, and the `MID` Advance records of a packet are
//!   reproduced by the lane's own polls inside it; both are then checked against the log (05
//!   §10 table rows 1–3 and 6).
//!
//! **Replay rejects** ([`Diverged`]): a record the replayed engine does not reproduce byte for
//! byte ([`Why::Mismatch`]), a packet record without payload ([`Why::NoPayload`]), a step whose
//! source op is older than the packet history ([`Why::SourceTooOld`]), a record with no lane
//! work behind it ([`Why::BadRecord`]), a step the BBO core does not take ([`Why::NoStep`]),
//! and any lane or BBO fault ([`Why::Fault`]).
//!
//! **Scope of this version** (each is a PR follow-up):
//!
//! - Live mode is the single-threaded schedule of 11 §6.4 (`vyrn-sim` order). The engine
//!   crates may not spawn threads (11 §3.3), so pinned cores are the binary's: it runs the same
//!   roles from [`role`] on its own threads.
//! - Replay re-derives each step's cut and source by running the BBO core on the same inputs and
//!   checks them against the logged `StepEntry`, and the lane routes by its snapshot. Spec 05
//!   §10 rows 4, 5 and 7 (take `StepRecord.cut`, `src` and kind from the log, route iff a
//!   `StepRecord` names the op) need a `vyrn-bbo` step-replay entry point and a forced-route
//!   input in `vyrn-lane`. Until then, replay reproduces only logs that this engine's own
//!   schedule produced.
//! - Pooled lanes (`AcctTake`), auction control steps, and the `Sim` visibility backend in tests.
//!
//! Determinism (`INV-DET`): the engine's own choices are the call order and nothing else. It
//! reads no clock, no ring fill level for a decision, no hash-map order and no float.
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

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod alloc;
mod engine;
mod replay;
pub mod role;

pub use engine::{Engine, Fault, Rec, Shared, Sink};
pub use replay::{Diverged, OwnedRec, Payloads, Why};
