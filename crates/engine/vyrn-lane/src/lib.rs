//! One lane: admission, sessions, MAC, risk, classify/dispatch, FIFO arena (11 §1.3, 05).
//!
//! # Contract
//!
//! A lane is a single-writer state machine over one inbound packet stream (05 §3). It owns the
//! lane arena (05 §4.5) and talks to the BBO core only through rings (05 §4.12).
//!
//! | object | writer | readers | ordering | spec |
//! |---|---|---|---|---|
//! | arena slots, segments, heads, journal, occupancy | this lane (`ArenaWriter`) | BBO core via [`LaneBook`] (`vyrn_bbo::BookSource`) | `tomb_ts` then `tomb_seq` (Release); segment `mask` word last (Release); `kill_ts` then `kill_seq` (Release); readers Acquire the last word | 05 §4.5, §4.6 |
//! | forward ring (`FwdEntry`, `FwdDep`) | this lane, pass 2 | BBO core | `vyrn_cut::Producer::push_all`, one entry per call | 05 §4.12 |
//! | fill ring (`FillEvent`) | BBO core | this lane at B1 | `vyrn_cut` ring, `step` last | 05 §4.12, §7.4 |
//! | lane counter (`applied`, `fills_applied`, `fwd_pend`) | this lane, end of packet and of each boundary | BBO cut | `vyrn_cut` counter (Release) | 05 §3.3, §6.2 |
//! | response packets, `PacketRecord` log | this lane | gateway, journal | packet order; `Gate` holds a packet until its step or packet is cut | 05 §6.2, §8.10, 01 §6.4 |
//!
//! Packet pipeline (05 §6.3): V1 length, V2 header, V4 session state, V5 sequence window, admit at
//! dequeue, V6 MAC (verified by the caller; `PktHash` supplied), V7 per-message decode, V8 risk,
//! admit at commit, then pass 1 (local ops in `LaneSeq` order), classify, forward (pass 2), V9
//! counter publication and V10 responses. Reject reasons are `vyrn_types::RejectReason`: the lane
//! issues every reason except the BBO's `IOC_REST`, `STP`, `AUCTION` outs and its own `Reject`
//! events (`BUSY`, `BOOK_HALTED`, `AUCTION_PHASE`, `TOO_LATE`, `STP`), which the lane relays.
//!
//! Rules the spec leaves open, fixed here and pinned by `tests/`:
//!
//! - **F (`fwd_pend`).** A forwarded entry is *executed* once B1 applies any event of its first
//!   step: a `Dep` event naming one of its dependencies, or a `Fill`/`Rested`/`Out`/`Reject` with
//!   `liq = LIQ_TAKER` on its source vslot. `fwd_pend` is the minimum dependency floor
//!   (`seq − max back`) over unexecuted entries, and 0 when there are none. It is never derived
//!   from `FwdCons`: a consumed line is not an executed entry.
//! - **G (boundary gate).** A boundary for step `f` runs only when the lane cut's step is greater
//!   than `fills_applied` and `SnapshotLine.done_step ≥ f`: the BBO publishes its step log before
//!   the step's fill events, so this is when every event of `f` is visible.
//! - **B (batch takers).** A `Rescan` batch taker's records are emitted by the lane (05 §8.10
//!   rule 4). Its status is its latest `Rested` cause: `RESTED_IN_FLIGHT` while capped steps
//!   continue, `RESTED_DONE` at the end. B2 holds that version's own `Ack`/`ReplaceAck` while it
//!   is in flight; settles after it keep `LaneSeq` order behind it. Later ops of the lane are
//!   kept out by the BBO's cut, which stops before the first op keyed after the taker (vyrn-bbo
//!   `febe805`); the lane adds no hold of its own for them.
//! - **R (cancel of a replace).** Each `NewPrio` version records its own predecessor and whether
//!   that replace is still at the BBO core. A cancel that pass 2 applies tombstones the current
//!   version and every pending predecessor in the chain, with one journal entry. When a replace
//!   takes effect (its first taker event, `Rested`, or a Join dependency resting) the
//!   predecessor ends there and the new leg's reservation drops by the predecessor's fills. A
//!   per-session `CancelAll` walks the same chain.
//! - **D (reduce).** A `ReduceAck` for version `v` reduces `min(r, open)`, where `open` is the
//!   version's quantity less its fills before `v`'s reduce (fills on a successor leg do not
//!   count). The order ends there only if its end detail is not `FILLED`.
//! - **P (pool index).** `FwdEntry.acct_ix`, `OrderSlot.acct_ix` and `AcctKill` carry the index
//!   set by [`Lane::set_pool_index`], the pool-wide index on a pooled lane (05 §6.9), else the
//!   lane-local account.
//! - **Y (replay routing).** [`Lane::replay_packet`] forwards exactly the ops it is given, with
//!   the route the live lane classified them with, and keeps every other op local (05 §10
//!   row 7). It never reads the snapshot to route. The route is not the step's kind (a fill-less
//!   `Cross` steps as `Improve`), and the 05 §10 log does not carry it yet: a spec follow-up.
//!   [`Lane::process_packet`] is unchanged.
//!
//! The arena's ordering protocol is checked by Miri on `arena_tests` and by the lane–BBO
//! conformance tests, not by a loom model: `loom` is a dev-dependency of `vyrn-cut` only (11 §2.2,
//! `tools/lint-engine/rules.toml`). Adding it here is a PR follow-up.
//!
//! Determinism (`INV-DET`): every output is a function of the packet stream, the fill-event
//! stream and the boundary positions logged as Advance records. Nothing reads a clock except
//! [`admit`].
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

pub mod admit;
// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod arena;
#[cfg(test)]
mod arena_tests;
pub mod book;
mod fifo;
pub mod lane;
pub mod layout;
pub mod out;
pub mod session;
mod settle;

pub use admit::{Class, DEADLINE_GUARD_NS, PathTable, Point};
pub use arena::{Arena, ArenaConfig, ArenaView, ArenaWriter};
pub use book::LaneBook;
pub use lane::{Config, Lane, Mid, Ports, Rx, RxIn, SNAP_LAG_MAX};
pub use out::{Gate, LogRec, RespPkt};
pub use session::{SessState, SessionSpec};
