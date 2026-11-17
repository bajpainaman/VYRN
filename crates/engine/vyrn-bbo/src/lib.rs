//! The BBO core (spec/11-build.md §1.3): the steps of 01 §14.10 and 05 §8.1, the deadline test on
//! forwarded ops, the merge of lane FIFO heads by `(prio_ts, rank_e(lane))`, the filled-quantity
//! array, snapshot publication, and the opening-auction uncross.
//!
//! # Contract
//!
//! **Writer.** One BBO core per book (core 2). It is the only writer of every output below
//! (`INV-WRITER`). It never writes a lane-owned line, an order slot or a balance (01 §12.2).
//!
//! | Structure | Direction | Type | Spec |
//! |---|---|---|---|
//! | half-cuts A and B | cut cores → BBO | `vyrn_cut::HalfCut` | 05 §4.13 |
//! | forwarded ops | lane → BBO | `vyrn_cut::FwdRing`, [`FwdEntry`] + [`FwdDep`] lines | 05 §4.12 |
//! | control commands | control role → BBO | [`ControlRing`], [`ControlCmd`] | 05 §4.1, §8.8 |
//! | lane arenas, masks, journal | lanes → BBO | [`BookSource`] | 05 §4.3–§4.9 |
//! | fill events | BBO → lane | `vyrn_cut::FillRing`, [`FillEvent`] | 05 §4.12 |
//! | step log | BBO → stream and fill TX cores | `vyrn_cut::StepLog`, [`StepEntry`] + [`CutDelta`] lines | 05 §4.15 |
//! | responses | BBO → fill TX core | `vyrn_cut::TxRing`, [`TxEntry`] + [`Record`] lines | 05 §4.15, §8.10 |
//! | snapshot | BBO → lanes, TX | `vyrn_cut::SnapshotLine` | 05 §4.14 |
//! | floor | BBO → cut cores | `vyrn_cut::BboFloor` | 05 §4.13 |
//!
//! **Ordering.** Each pass reads both half-cuts (Acquire), *then* the ring heads (05 §8.3); a
//! step's outputs are published in the order of 05 §8.2 `finish_step`: step log, fill events
//! (per lane, one contiguous run in ordinal order), `TxEntry`s, snapshot (with `done_step`),
//! floor. A full ring stalls the publication ([`Poll::Stalled`]) and never changes a decision
//! (`INV-ENG-6`).
//!
//! **Decisions.** Every decision is a function of the half-cut values, the ring entries, the
//! lanes' write-once arena fields and this core's own state, except the deadline test of
//! [`admit`], which reads the clock and whose result is logged as a `Shed` step (01 §14.1).
//! The cut, source and kind of every step are in its [`StepEntry`], so replay never repeats a
//! choice (05 §10).
//!
//! **Rejects and outcomes this core decides** (05 §2.3–§2.5, §8.5): `BOOK_HALTED` (P1),
//! `AUCTION_PHASE` (Frozen), `TOO_LATE` (a `Replace` or dependency `Cancel` whose order had no
//! open quantity), `POST_ONLY_WOULD_CROSS`, `FOK_UNFILLABLE`, `BUSY` (`Shed`), and `Out` with
//! causes `IOC_REST`, `STP` and `AUCTION`. Every other reject is the lane's.
//!
//! **Not on the pinned path.** [`mem`] is an in-memory [`BookSource`] for tests, `vyrn-sim`
//! and oracle bindings.
#![forbid(unsafe_code)]
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
mod bbo;
mod book;
mod codec;
mod cut;
mod io;
mod key;
pub mod mem;
mod out;
mod view;

pub use bbo::{Bbo, Config};
pub use codec::{
    ControlCmd, CutDelta, DEP_CANCEL, DEP_JOIN, FillEvent, FillKind, FwdDep, FwdEntry, INDEX_MAKER,
    LIQ_AUCTION, LIQ_MAKER, LIQ_TAKER, MAX_RECORDS, MSG_NEW, MSG_REPLACE, OUT_AUCTION,
    OUT_IOC_REST, OUT_STP, Phase, ROLE_DEPS, ROLE_MAKER, ROLE_TAKER, Record, STEP_CONT, StepEntry,
    TxEntry, decode_records, encode_fwd, encode_records, line_bytes, line32_bytes,
};
pub use cut::{Cut, HalfPair, SrcRule, step_cut};
pub use io::{ControlCons, ControlRing, FillProd, FwdCons, Poll, Ports, StepLogProd, TxProd};
pub use key::{OrderFlags, PrioKey, Side, Stp, Tif, rank_e};
pub use out::{StepOut, TxOut};
pub use view::{AcctKill, BookSource, JEnt, JKind, OrderSlot, Segment16, SlotKind};

/// Lanes a cut can hold (05 §5.4: `N_LANES ≤ 64`).
pub const MAX_LANES: usize = 64;
/// Maker fills per step; one level per step (05 §8.5, D14). STP removals count too (see
/// spec follow-up F3 in the PR).
pub const ENG_STEP_FILLS: u32 = 8;
/// Fills per `Uncross` step (05 §8.8).
pub const ENG_UNCROSS_CHUNK: u32 = 6;
/// `Pend` entries (05 §8.5).
pub const ENG_PEND_CAP: usize = 256;
/// Snapshot versions kept for envelopes (05 §8.6).
pub const ENG_SNAP_HIST: usize = 4096;
/// Control ring entries (05 §4.1).
pub const ENG_CONTROL_RING: usize = 256;
/// Dependencies per forwarded op: at most 9 earlier messages of a 10-message packet.
pub const MAX_DEPS: usize = 9;
/// "No ask" (05 §4.14).
pub const NO_ASK: vyrn_types::Tick = vyrn_types::Tick(u32::MAX);
/// "No bid" (05 §4.14).
pub const NO_BID: vyrn_types::Tick = vyrn_types::Tick(0);
