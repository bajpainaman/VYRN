//! Per-lane decoded state: the lane-state rules L1–L3 of the crate contract (07 §3.5–§3.7).
//!
//! `vyrn-log` keeps its own `LaneDec` to decode deltas. This is the replica's view of the same
//! lane, which it needs to check steps and to time hashes. Both views see the same records in the
//! same order, so they agree on `next_lane_seq`. A disagreement is a [`LaneErr::Order`].

use std::collections::VecDeque;

use vyrn_log::LaneBase;
use vyrn_types::{AcctTake, Height, LaneSeq, PacketFlags, PacketRecord, PktHash};

/// A record waiting for its `pkt_hash` (rule L3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Awaiting {
    /// The record's `first_lane_seq`, which names it in a `HashRun` entry.
    pub lane_seq: LaneSeq,
    /// Receive time of its ORDER frame, ns.
    pub arrived: u64,
    /// The `frame_seq` of that frame.
    pub frame_seq: u64,
    /// The block that holds the record, and its index in that block's lane records.
    pub height: Height,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LaneErr {
    /// A record whose `first_lane_seq` is below the decoded prefix (L1).
    #[error("lane record below the decoded prefix")]
    Order,
    /// A `HashRun` entry that does not name the head of the awaiting FIFO (L3).
    #[error("hash entry does not name the oldest record awaiting a hash")]
    Hash,
}

/// One lane's state (rules L1–L3).
#[derive(Clone, Debug, Default)]
pub struct LaneState {
    next_lane_seq: u64,
    /// `[first, end)` LaneSeq ranges of `SHED` packets, oldest first (L2).
    shed: VecDeque<(u64, u64)>,
    awaiting: VecDeque<Awaiting>,
}

impl LaneState {
    /// The state after a `TenureStart` that set this lane's base.
    pub fn from_base(base: &LaneBase) -> Self {
        Self {
            next_lane_seq: base.next_lane_seq.0,
            ..Self::default()
        }
    }

    /// The decoded prefix: the highest LaneSeq any decoded record covers (L1).
    pub const fn prefix(&self) -> LaneSeq {
        LaneSeq(self.next_lane_seq.saturating_sub(1))
    }

    /// Whether `seq` lies in a packet that carries `SHED` and is still tracked (L2).
    pub fn is_shed(&self, seq: LaneSeq) -> bool {
        self.shed.iter().any(|&(a, b)| a <= seq.0 && seq.0 < b)
    }

    /// The oldest record that waits for a hash.
    pub fn oldest_awaiting(&self) -> Option<&Awaiting> {
        self.awaiting.front()
    }

    /// Applies a decoded PacketRecord or Advance record, which sits at `(height, index)` of its
    /// block. `arrived` and `frame_seq` go to the awaiting FIFO when the record needs a hash.
    pub fn on_packet(
        &mut self,
        rec: &PacketRecord,
        arrived: u64,
        frame_seq: u64,
        (height, index): (Height, usize),
    ) -> Result<(), LaneErr> {
        let first = rec.first_lane_seq.0;
        // A `MID` Advance record names an op of the packet before it (07 §3.6; the decoder
        // checked `back`) and takes no LaneSeq.
        if rec.flags & PacketFlags::MID != 0 {
            return Ok(());
        }
        if first < self.next_lane_seq {
            return Err(LaneErr::Order);
        }
        let end = first
            .checked_add(u64::from(rec.count))
            .ok_or(LaneErr::Order)?;
        self.next_lane_seq = end;
        if rec.flags & PacketFlags::SHED != 0 && end > first {
            self.shed.push_back((first, end));
        }
        if rec.flags & PacketFlags::ADVANCE == 0 {
            self.awaiting.push_back(Awaiting {
                lane_seq: rec.first_lane_seq,
                arrived,
                frame_seq,
                height,
                index,
            });
        }
        Ok(())
    }

    /// Applies an `AcctTake`: it takes no LaneSeq, and `vyrn-log` sets its `lane_seq` to the
    /// lane's `next_lane_seq`.
    pub const fn on_take(&self, t: &AcctTake) -> Result<(), LaneErr> {
        if t.lane_seq.0 != self.next_lane_seq {
            return Err(LaneErr::Order);
        }
        Ok(())
    }

    /// Applies one `HashRun` entry and returns the record it completes.
    pub fn on_hash(&mut self, lane_seq: LaneSeq, _hash: PktHash) -> Result<Awaiting, LaneErr> {
        match self.awaiting.front() {
            Some(a) if a.lane_seq == lane_seq => self.awaiting.pop_front().ok_or(LaneErr::Hash),
            _ => Err(LaneErr::Hash),
        }
    }

    /// Forgets `SHED` ranges that end at or below `bound`. The order core calls it at each
    /// `BlockMark` with the bound of the mark before, so a step can name a shed op of the current
    /// or the previous block. That window is this crate's choice; see the spec gaps in the PR.
    pub fn prune_shed(&mut self, bound: LaneSeq) {
        while self
            .shed
            .front()
            .is_some_and(|&(_, b)| b <= bound.0.saturating_add(1))
        {
            self.shed.pop_front();
        }
    }
}
