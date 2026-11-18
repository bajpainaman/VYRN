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
//! | order stream ([`Rec`]) | engine, in call order | [`Sink`], [`Engine::replay`] | lane records ([`Rec::Packet`], and [`Rec::Route`] for each op the lane classified, forwarded or rejected) in each lane's production order; a step's [`Rec::Step`] after its last lane record that the step's cut covers | 01 §6.6, 05 §6.2, 07 §3.6 |
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
//!   every lane call and every step. No clock is read: a `SHED` record is replayed from the record
//!   alone, with no payload (`vyrn_lane::Lane::replay_shed`, 05 §18 Q17), and every other packet
//!   with an on-time clock. Each step runs through
//!   `vyrn_bbo::Bbo::replay_step` with its cut (`C_{s−1}` plus the record's deltas), source,
//!   kind (incl. `Shed`, `CONT`) and `Rescan` band taken from the record (05 §10 rows 4–5); the
//!   cut cores still publish before it, since it reads the half-cuts. Each packet goes through
//!   `vyrn_lane::Lane::replay_packet`: its `MID` Advance records become `Mid` boundaries at
//!   `(f, C_f[l])`, with `C_f` from the replayed step `f`'s cut (kept for the last
//!   `ENG_STEP_LOG` steps), and each op's route from its packet's [`Rec::Route`] records, never
//!   from the lane's snapshot or a step's kind (05 §10 rows 1–3, 7; 07 §3.6): the replayed pass 1
//!   then forwards or rejects the op as live, and every other op is a `Join`. A non-`MID` Advance
//!   record is replayed as the lane boundary it logs, at `(fills_applied, C_f[l])` like a `MID`
//!   record, not as an idle poll on the newest `LaneCut`: live, the poll may have read an older
//!   one. Every call's output records are checked against the log.
//!
//! - **Replay from 07** ([`Engine::replay_wire`]): the replica's entry point. Input is 07's wire
//!   records only: every lane's `PacketRecord`s in O-order, the block's `RouteRecord`s
//!   (`vyrn_log::LaneRec::Route`, any order; each is matched to its packet by `(lane,
//!   lane_seq)`), and the merged steps as [`WireStep`] (kind, source, `CROSS` bit, full cut,
//!   kind payload; build one with [`WireStep::of`] from a `vyrn-log` `MergedStep`). They are merged by 07 §7.1 `REP_MERGE`: before step `s`, each lane
//!   in lane id order replays its records due at `f < s`, where `f` is a packet's
//!   `fills_applied` raised to that of its `MID` records. `n_tx`, `n_fills`, `fill_lanes`,
//!   `flags`, `pub_a/b` and `CONT` are derived, not compared; the `Rescan` band is the payload
//!   (8 B, or empty for all ticks). Call it once per block on the same engine: records a block
//!   does not settle carry to the next call ([`Engine::carried`], `REP_MERGE` item 3). Errors are [`WireDiverged`] at a lane record index, a step,
//!   or the end.
//! - **Response log** ([`Responses`]): both entry points check every lane response (per lane, in
//!   order) and fill TX packet (in order) against a log when one is given ([`Why::Response`]).
//!   [`Engine::replay`] also checks that the log is used up at the end; after
//!   [`Engine::replay_wire`] the caller checks [`Responses::finished`] after its last block. [`NoResponses`] checks nothing.
//!
//! **Snapshots (05 §6.5, 07 §7.1).** A live lane classifies each packet against the snapshot it
//! reads at accept and logs it as `PacketRecord.snap_lag`, versions past the one its
//! `fills_applied` step published (carried in `LaneCut`). Replay restores that version from a ring
//! of [`REPLAY_SNAP_HIST`] versions before the packet, and a record is due only once its version is
//! published.
//!
//! **Replay rejects** ([`Diverged`]): a record the replayed engine does not reproduce byte for
//! byte ([`Why::Mismatch`]), a packet record without payload ([`Why::NoPayload`]), a step
//! record that does not decode ([`Why::BadStep`]), a step the BBO core refuses as its next one
//! ([`Why::Step`] with `vyrn_bbo::Diverge`), a `MID` record older than the cut history
//! ([`Why::StepTooOld`]), a record with no lane work behind it
//! ([`Why::BadRecord`]), a response that differs from the log ([`Why::Response`]), inputs
//! `REP_MERGE` cannot order ([`Why::Order`], `REP_E_ORDER`), a packet record whose
//! `snap_lag` names a snapshot version replay does not hold ([`Why::NoSnapshot`], 07 §7.1), a step the BBO core does not publish ([`Why::NoStep`]), and any lane
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
//!   and sessions stay lane-local (`vyrn-lane` has no shared `PoolAcct`). [`Engine::replay`]
//!   checks `AcctTake` records ([`OwnedRec::Take`]): each is part of the lane call of the record
//!   it covers, and must be reproduced right before that packet's group (its own route
//!   records and the packet, in emitted order) with the same `ver`. Otherwise replay fails
//!   with [`Why::Mismatch`] at the take, including when a route record of another packet, on
//!   any lane, sits between them. [`Engine::replay_wire`] does not take them yet.
//! - Control steps carry their kind, not their command, in the order stream. A replayer
//!   queues the commands through [`Engine::command`] before [`Engine::replay`].
//! - On a delayed backend (`Sim`), a step's lines may become visible after `Bbo::poll`
//!   publishes it. The stream role reads step `s` once the BBO snapshot shows `done_step ≥ s`
//!   (published after the step's other lines) and polls the BBO core again only after that, so
//!   a step is never read in part. [`Engine::run`] is quiet when no visible line has work.
//!   Replay is exact under the same delays (`tests/sim.rs`).
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
pub mod retain;
pub mod role;

pub use engine::{Engine, Fault, REPLAY_SNAP_HIST, Rec, Shared, Sink};
pub use replay::{
    CONTROL_PAYLOAD_LEN, Diverged, NoResponses, OwnedRec, Payloads, Responses, Why, WireAt,
    WireDiverged, WireStep, control_of_payload, control_payload,
};
