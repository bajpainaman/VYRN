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
//! | pool account tokens (`vyrn_cut::PoolTok`) and their [`AcctTake`](vyrn_types::AcctTake) records | engine, pool-core role ([`Engine::pool_session`]) | pool cores, [`Sink::take`] | per record of a pooled session: take (CAS), [`Sink::take`], release, then the record; `ver` is gapless across the pool | 01 §14.17.4, 05 §6.9 |
//! | control commands | caller, control role ([`Engine::command`]) | BBO core | one per step, before ring heads; replay queues the same commands before the stream | 05 §4.1, §8.8 |
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
//!   clock and every other packet with an on-time clock. Each step runs through
//!   `vyrn_bbo::Bbo::replay_step` with its cut (`C_{s−1}` plus the record's deltas), source,
//!   kind (incl. `Shed`, `CONT`) and `Rescan` band taken from the record (05 §10 rows 4–5); the
//!   cut cores still publish before it, since it reads the half-cuts. Each packet goes through
//!   `vyrn_lane::Lane::replay_packet`: its `MID` Advance records become `Mid` boundaries at
//!   `(f, C_f[l])`, with `C_f` from the replayed step `f`'s cut (kept for the last
//!   `ENG_STEP_LOG` steps), and op `(l, q)` is forwarded iff a later `StepRecord` has
//!   `src = (l, q)`, never by the lane's snapshot (05 §10 rows 1–3, 7). A non-`MID` Advance
//!   record is replayed as the lane's idle poll, which reads the `LaneCut` that the replayed
//!   step wrote. Every call's output records are checked against the log.
//!
//! **Replay rejects** ([`Diverged`]): a record the replayed engine does not reproduce byte for
//! byte ([`Why::Mismatch`]), a packet record without payload ([`Why::NoPayload`]), a step
//! record that does not decode ([`Why::BadStep`]), a step the BBO core refuses as its next one
//! ([`Why::Step`] with `vyrn_bbo::Diverge`), a `MID` record older than the cut history
//! ([`Why::StepTooOld`]), a record with no lane work behind it
//! ([`Why::BadRecord`]), a step the BBO core does not publish ([`Why::NoStep`]), and any lane
//! or BBO fault ([`Why::Fault`]).
//!
//! **Scope of this version** (each is a PR follow-up):
//!
//! - Live mode is the single-threaded schedule of 11 §6.4 (`vyrn-sim` order). The engine
//!   crates may not spawn threads (11 §3.3), so pinned cores are the binary's: it runs the same
//!   roles from [`role`] on its own threads.
//! - Pooled lanes. Each record of a pooled session takes the account's token, logs
//!   `AcctTake` and releases it. The lane's work for that record is already done: one thread
//!   plays every pool core, so nothing else can write the account in between. Boundary work
//!   (B1 fills, B2 settlement) on a pooled account takes no token and logs no `AcctTake`,
//!   because the lane does not report which accounts a boundary touched. The account's ledger
//!   and sessions stay lane-local (`vyrn-lane` has no shared `PoolAcct`). Replay does not yet
//!   check `AcctTake` records, and [`OwnedRec`] cannot hold one.
//! - Control steps carry their kind, not their command, in the order stream. A replayer
//!   queues the commands through [`Engine::command`] before [`Engine::replay`].
//! - On a delayed backend (`Sim`), a step's lines may become visible after `Bbo::poll`
//!   publishes it. The stream role reads step `s` once the BBO snapshot shows `done_step ≥ s`
//!   (published after the step's other lines) and polls the BBO core again only after that, so
//!   a step is never read in part. [`Engine::run`] is quiet when no visible line has work.
//!   Replay runs a non-`MID` Advance record as the lane's idle poll on the newest `LaneCut`; a
//!   live poll that read an older `LaneCut` replays as a mismatch (follow-up).
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
