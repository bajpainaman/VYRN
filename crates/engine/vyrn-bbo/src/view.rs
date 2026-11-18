//! The read contract between a lane's order arenas and the BBO core (05 §4.3–§4.9, §4.13).
//!
//! The arenas are **lane-written, BBO-read** (`INV-WRITER`). `vyrn-lane::arena` owns their memory
//! and their `unsafe` (UNSAFE.toml); this crate sits below `vyrn-lane` in the layer graph (11
//! §1.4), so it states what it reads as the `BookSource` trait and the lane implements it.
//! `vyrn-sim`, the Vx oracle binding and this crate's tests implement it over plain memory.
//!
//! Ordering contract (05 §4.6, §5.1, Lemma 9.4). An implementation over shared memory must give:
//!
//! - `segment` loads `mask` with `Acquire` before the other fields it returns; the lane writes
//!   `slot[i]`, `qty[i]`, `dts[i]` and the slot line before it stores the mask bit (`Release`).
//! - `slot` returns the write-once fields of 05 §4.3 (`INV-ENG-2`): `tomb_seq` loaded with
//!   `Acquire`, then `tomb_ts`; `next_ver` is written before the `tomb_seq` of the same op.
//! - `acct_kill` loads `kill_seq` with `Acquire`.
//! - `head` loads the head word of the directory named by the lane's `dir_sel`, read after the
//!   cut (05 §5.5).
//! - `occ` and `occ_next` are conservative for the cut of the step that reads them
//!   (`INV-ENG-3`, Lemma 7.1): a lane with a live order at `(side, tick)` that is not wild, not a
//!   lag lane and not in `Pend` has its bit set. Extra bits are allowed.
//! - `journal` yields the entries of 05 §4.9 with `from < seq ≤ to` in `seq` order; the lane
//!   keeps every entry with `seq > LaneCut[l].cut`, so a `Rescan` never asks for a trimmed one.
//!
//! None of these reads may block or allocate; a wrong value is an engine fault, not a reject.

use vyrn_types::{LaneId, LaneSeq, Nanos, SessionId, Tick};

use crate::key::{OrderFlags, Side};

/// `OrderSlot.kind` (05 §4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SlotKind {
    #[default]
    Original,
    /// A `Reduce` version: keeps the position and the key of the version it follows.
    KeepPrio,
    /// A `Replace` version with a new position and key.
    NewPrio,
}

/// `OrderSlot` (05 §4.3, 64 B). Writer: the lane, write-once per field (`INV-ENG-2`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrderSlot {
    pub prio_ts: Nanos,
    /// Op that created this version.
    pub ins_seq: LaneSeq,
    /// `KeepPrio`: ts of the `Reduce` op. `NewPrio`: low 32 bits = `pred_total` (total of the
    /// version it replaces), high 32 bits = `pred_pos` (its position slot). `Original`: 0.
    pub ins_ts: u64,
    /// Op that ended this version; 0 = live.
    pub tomb_seq: LaneSeq,
    pub tomb_ts: Nanos,
    /// The `KeepPrio` version that follows; 0 = none.
    pub next_ver: u32,
    pub tick: Tick,
    /// Total of the order as of this version (filled + open).
    pub total: u32,
    pub acct_ix: u32,
    /// Root slot of the order.
    pub root: u32,
    pub flags: OrderFlags,
    /// Generation of the root slot.
    pub gen_: u8,
    pub kind: SlotKind,
    /// Lane whose `LaneSeq` `tomb_seq` is (≠ own lane only in a pool, 05 §6.9).
    pub tomb_lane: LaneId,
}

impl OrderSlot {
    /// The ts of the op that created this version (05 §5.2): `ins_ts` for `KeepPrio`, else
    /// `prio_ts`.
    pub fn ins_time(&self) -> Nanos {
        match self.kind {
            SlotKind::KeepPrio => Nanos(self.ins_ts),
            _ => self.prio_ts,
        }
    }
    /// `pred_total` of a `NewPrio` version (05 §4.3 bytes 16–19).
    pub fn pred_total(&self) -> u32 {
        u32::try_from(self.ins_ts & 0xFFFF_FFFF).unwrap_or(0)
    }
    /// `pred_pos` of a `NewPrio` version (05 §4.3 bytes 20–23): the position slot of the
    /// version it replaces; 0 = none.
    pub fn pred_pos(&self) -> u32 {
        u32::try_from(self.ins_ts >> 32).unwrap_or(0)
    }
}

/// `Segment16` (05 §4.6, 192 B): 16 queue positions of one lane FIFO at one `(side, tick)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Segment16 {
    /// Position slot (first version) of each position; 0 = unused.
    pub slot: [u32; 16],
    /// Total of the position slot.
    pub qty: [u32; 16],
    /// Bits 0–15 active, bits 16–31 pend.
    pub mask: u32,
    /// +1 on every reuse (ABA check, 05 §7.8).
    pub gen_: u32,
    /// Next segment of this FIFO; 0 = end.
    pub succ: u32,
    pub tick: Tick,
    pub side: u8,
    /// Positions that need the slot line (`NewPrio` position slot, or a reduced order).
    pub vmask: u16,
    pub base_ts: Nanos,
    /// `prio_ts − base_ts` of each position.
    pub dts: [u16; 16],
}

/// `AcctKill` (05 §4.7). Writer: the lane, per `CancelAll`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcctKill {
    /// `LaneSeq` of the newest `CancelAll` of this account; 0 = none.
    pub kill_seq: LaneSeq,
    pub kill_ts: Nanos,
}

/// `JEnt.kind` (05 §4.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JKind {
    New,
    KeepPrio,
    NewPrio,
    /// `slot` = the ended version.
    Tomb,
    /// `slot` = `acct_ix`.
    AcctKill,
}

/// One journal entry (05 §4.9): an independent op that changed the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JEnt {
    pub seq: LaneSeq,
    pub tick: Tick,
    pub slot: u32,
    pub kind: JKind,
}

/// What the BBO core reads from the lanes. See the module doc for the ordering contract.
pub trait BookSource {
    /// Head segment of lane `lane`'s FIFO at `(side, tick)`; 0 = empty level.
    fn head(&self, lane: LaneId, side: Side, tick: Tick) -> u32;
    /// Segment `seg` of lane `lane`'s arena; `None` for an index outside the arena (a fault).
    fn segment(&self, lane: LaneId, seg: u32) -> Option<Segment16>;
    /// Slot `slot` of lane `lane`'s arena; `None` for an index outside the arena (a fault).
    fn slot(&self, lane: LaneId, slot: u32) -> Option<OrderSlot>;
    /// `AcctKill[acct_ix]` of lane `lane`.
    fn acct_kill(&self, lane: LaneId, acct_ix: u32) -> AcctKill;
    /// Session that owns root `root`. 05 §4.5 keeps it lane-private (`SlotAux.session`), but
    /// maker `TxEntry`s need it (05 §4.15); see the crate doc's spec follow-ups.
    fn session(&self, lane: LaneId, root: u32) -> SessionId;
    /// `client_tag` of root `root` (05 §4.5 `SlotAux.client_tag`, lane-private like `session`).
    /// Dependency records and a `Replace` source's records need it; `FwdDep` and a `Replace`
    /// message do not carry it.
    fn client_tag(&self, lane: LaneId, root: u32) -> u32;
    /// Journal entries of lane `lane` with `from < seq ≤ to`, in `seq` order.
    fn journal<F: FnMut(JEnt)>(&self, lane: LaneId, from: LaneSeq, to: LaneSeq, f: F);
    /// Lanes that may have a non-empty FIFO at `(side, tick)` (bit `l`; 05 §4.13 `occ`).
    fn occ(&self, side: Side, tick: Tick) -> u64;
    /// The first tick at or beyond `from`, moving away from the spread (down for bids, up for
    /// asks), with `occ(side, tick) ≠ 0`; `None` if there is none in the ladder.
    fn occ_next(&self, side: Side, from: Tick) -> Option<Tick>;
    /// The same walk over lane `lane`'s own occupancy bitmap (05 §4.8), for wild and lag lanes.
    fn lane_next(&self, lane: LaneId, side: Side, from: Tick) -> Option<Tick>;
}
