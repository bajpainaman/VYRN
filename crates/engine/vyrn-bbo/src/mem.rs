//! An in-memory [`BookSource`]: the lane arenas of 05 §4.3–§4.9 over plain vectors. It writes
//! what a lane writes, in the lane's layout, so tests, `vyrn-sim` and oracle bindings drive the
//! BBO core with real slot, segment and journal contents. Not for the pinned path: it allocates.
//!
//! Occupancy is conservative (05 Lemma 7.1): a level's bit is set when a position is placed and
//! never cleared.

use std::collections::{BTreeMap, BTreeSet};

use vyrn_types::{LaneId, LaneSeq, Nanos, SessionId, Tick};

use crate::key::{OrderFlags, Side};
use crate::view::{AcctKill, BookSource, JEnt, JKind, OrderSlot, Segment16, SlotKind};

/// One order as a test or a simulator writes it.
#[derive(Clone, Copy, Debug)]
pub struct MemOrder {
    pub flags: OrderFlags,
    pub tick: Tick,
    pub qty: u32,
    /// `LaneSeq` of the op that created it.
    pub seq: LaneSeq,
    /// Its `prio_ts`.
    pub ts: Nanos,
    pub acct_ix: u32,
    pub session: SessionId,
    pub client_tag: u32,
}

/// Generation every root slot of a `MemBook` gets.
pub const MEM_GEN: u8 = 1;

/// The lane arenas of `n_lanes` lanes.
#[derive(Clone, Debug, Default)]
pub struct MemBook {
    slots: Vec<Vec<OrderSlot>>,
    segs: Vec<Vec<Segment16>>,
    heads: BTreeMap<(u8, u8, u32), u32>,
    tails: BTreeMap<(u8, u8, u32), u32>,
    pos_of: BTreeMap<(u8, u32), (u32, usize)>,
    kills: BTreeMap<(u8, u32), AcctKill>,
    owners: BTreeMap<(u8, u32), (SessionId, u32)>,
    journal: Vec<Vec<JEnt>>,
    occ: BTreeMap<(u8, u32), u64>,
    lane_occ: BTreeSet<(u8, u8, u32)>,
}

fn bit(i: usize) -> u32 {
    u32::try_from(i)
        .ok()
        .and_then(|i| 1u32.checked_shl(i))
        .unwrap_or(0)
}

impl MemBook {
    pub fn new(n_lanes: usize) -> Self {
        Self {
            // Slot 0 and segment 0 are null (05 §4.2).
            slots: vec![vec![OrderSlot::default()]; n_lanes],
            segs: vec![vec![Segment16::default()]; n_lanes],
            journal: vec![Vec::new(); n_lanes],
            ..Self::default()
        }
    }

    fn lane_ix(lane: LaneId) -> usize {
        usize::from(lane.0)
    }

    /// Writes a slot line and returns its index. `root = 0` means "itself".
    pub fn write_slot(&mut self, lane: LaneId, mut v: OrderSlot) -> u32 {
        let Some(arena) = self.slots.get_mut(Self::lane_ix(lane)) else {
            return 0;
        };
        let ix = u32::try_from(arena.len()).unwrap_or(0);
        if v.root == 0 {
            v.root = ix;
        }
        if v.tomb_lane == LaneId(0) {
            v.tomb_lane = lane;
        }
        arena.push(v);
        ix
    }

    /// A slot line, for edits a test makes before the BBO core reads it.
    pub fn slot_mut(&mut self, lane: LaneId, slot: u32) -> Option<&mut OrderSlot> {
        self.slots
            .get_mut(Self::lane_ix(lane))?
            .get_mut(usize::try_from(slot).ok()?)
    }

    /// Writes the root slot of a new order without a queue position (a forwarded op or a Join
    /// dependency in pass 1, 05 §6.6) and records its owner.
    pub fn new_slot(&mut self, lane: LaneId, o: &MemOrder) -> u32 {
        let ix = self.write_slot(
            lane,
            OrderSlot {
                prio_ts: o.ts,
                ins_seq: o.seq,
                tick: o.tick,
                total: o.qty,
                acct_ix: o.acct_ix,
                flags: o.flags,
                gen_: MEM_GEN,
                kind: SlotKind::Original,
                ..OrderSlot::default()
            },
        );
        self.owners.insert((lane.0, ix), (o.session, o.client_tag));
        ix
    }

    /// The `NewPrio` version of a `Replace` at op `seq` (ts `ts`) of the order whose current
    /// version is `old`, without a queue position.
    pub fn replace_slot(
        &mut self,
        lane: LaneId,
        old: u32,
        seq: LaneSeq,
        ts: Nanos,
        tick: Tick,
        qty: u32,
    ) -> u32 {
        let Some(v) = self.slot(lane, old) else {
            return 0;
        };
        self.write_slot(
            lane,
            OrderSlot {
                prio_ts: ts,
                ins_seq: seq,
                ins_ts: u64::from(v.total),
                tick,
                total: qty,
                acct_ix: v.acct_ix,
                root: v.root,
                flags: v.flags,
                gen_: v.gen_,
                kind: SlotKind::NewPrio,
                ..OrderSlot::default()
            },
        )
    }

    /// Gives `slot` the next queue position at the tail of its level (05 §4.6) and sets its
    /// `active | pend` bits, as pass 2 (or B1 for an explicit op) does.
    pub fn place(&mut self, lane: LaneId, slot: u32) {
        let Some(v) = self.slot(lane, slot) else {
            return;
        };
        let side = v.flags.side().code();
        let k = (lane.0, side, v.tick.0);
        let l = Self::lane_ix(lane);
        let Some(arena) = self.segs.get_mut(l) else {
            return;
        };
        let tail = self.tails.get(&k).copied().unwrap_or(0);
        let fits = usize::try_from(tail)
            .ok()
            .and_then(|t| arena.get(t))
            .filter(|_| tail != 0)
            .and_then(|g| {
                let used = g.slot.iter().position(|s| *s == 0)?;
                let dts = v.prio_ts.0.checked_sub(g.base_ts.0)?;
                u16::try_from(dts).ok().map(|d| (used, d))
            });
        let (seg, i, dts) = match fits {
            Some((i, d)) => (tail, i, d),
            None => {
                let ix = u32::try_from(arena.len()).unwrap_or(0);
                arena.push(Segment16 {
                    gen_: 1,
                    tick: v.tick,
                    side,
                    base_ts: v.prio_ts,
                    ..Segment16::default()
                });
                if let Some(prev) = usize::try_from(tail).ok().and_then(|t| arena.get_mut(t))
                    && tail != 0
                {
                    prev.succ = ix;
                } else {
                    self.heads.insert(k, ix);
                }
                self.tails.insert(k, ix);
                (ix, 0, 0)
            }
        };
        if let Some(g) = usize::try_from(seg).ok().and_then(|s| arena.get_mut(s)) {
            if let (Some(s), Some(q), Some(d)) =
                (g.slot.get_mut(i), g.qty.get_mut(i), g.dts.get_mut(i))
            {
                *s = slot;
                *q = v.total;
                *d = dts;
            }
            g.mask |= bit(i) | bit(i.saturating_add(16));
            if v.kind == SlotKind::NewPrio {
                g.vmask |= u16::try_from(bit(i)).unwrap_or(0);
            }
        }
        self.pos_of.insert((lane.0, slot), (seg, i));
        let o = self.occ.entry((side, v.tick.0)).or_insert(0);
        *o |= 1u64.checked_shl(u32::from(lane.0)).unwrap_or(0);
        self.lane_occ.insert((lane.0, side, v.tick.0));
    }

    /// An independent resting order written by pass 2: slot, position and journal entry.
    pub fn rest(&mut self, lane: LaneId, o: &MemOrder) -> u32 {
        let ix = self.new_slot(lane, o);
        self.place(lane, ix);
        self.push_journal(
            lane,
            JEnt {
                seq: o.seq,
                tick: o.tick,
                slot: ix,
                kind: JKind::New,
            },
        );
        ix
    }

    /// Ends version `slot` at op `seq` (ts `ts`): tombstone, `active` cleared, `pend` set.
    pub fn tombstone(&mut self, lane: LaneId, slot: u32, seq: LaneSeq, ts: Nanos) {
        let tick = self.slot(lane, slot).map(|v| v.tick).unwrap_or_default();
        if let Some(v) = self.slot_mut(lane, slot) {
            v.tomb_ts = ts;
            v.tomb_seq = seq;
        }
        let root_pos = self
            .slot(lane, slot)
            .and_then(|v| self.pos_of.get(&(lane.0, v.root)).copied());
        if let Some((seg, i)) = self.pos_of.get(&(lane.0, slot)).copied().or(root_pos)
            && let Some(g) = self.seg_mut(lane, seg)
            && slot_is_position(g, i, slot)
        {
            g.mask = (g.mask & !bit(i)) | bit(i.saturating_add(16));
        }
        self.push_journal(
            lane,
            JEnt {
                seq,
                tick,
                slot,
                kind: JKind::Tomb,
            },
        );
    }

    /// `Reduce` of version `old` by `r` at op `seq`: a `KeepPrio` version at the same position
    /// (05 §4.4). Returns the new version's slot.
    pub fn reduce(&mut self, lane: LaneId, old: u32, r: u32, seq: LaneSeq, ts: Nanos) -> u32 {
        let Some(v) = self.slot(lane, old) else {
            return 0;
        };
        let w = self.write_slot(
            lane,
            OrderSlot {
                kind: SlotKind::KeepPrio,
                ins_seq: seq,
                ins_ts: ts.0,
                total: v.total.saturating_sub(r),
                tomb_seq: LaneSeq(0),
                tomb_ts: Nanos(0),
                next_ver: 0,
                ..v
            },
        );
        if let Some(x) = self.slot_mut(lane, old) {
            x.next_ver = w;
            x.tomb_ts = ts;
            x.tomb_seq = seq;
        }
        if let Some((seg, i)) = self.pos_of.get(&(lane.0, v.root)).copied()
            && let Some(g) = self.seg_mut(lane, seg)
        {
            g.vmask |= u16::try_from(bit(i)).unwrap_or(0);
            g.mask |= bit(i.saturating_add(16));
        }
        self.push_journal(
            lane,
            JEnt {
                seq,
                tick: v.tick,
                slot: w,
                kind: JKind::KeepPrio,
            },
        );
        w
    }

    /// `CancelAll` of account `acct_ix` at op `seq` (05 §4.7).
    pub fn cancel_all(&mut self, lane: LaneId, acct_ix: u32, seq: LaneSeq, ts: Nanos) {
        self.kills.insert(
            (lane.0, acct_ix),
            AcctKill {
                kill_seq: seq,
                kill_ts: ts,
            },
        );
        self.push_journal(
            lane,
            JEnt {
                seq,
                tick: Tick(0),
                slot: acct_ix,
                kind: JKind::AcctKill,
            },
        );
    }

    pub fn push_journal(&mut self, lane: LaneId, j: JEnt) {
        if let Some(jr) = self.journal.get_mut(Self::lane_ix(lane)) {
            jr.push(j);
        }
    }

    fn seg_mut(&mut self, lane: LaneId, seg: u32) -> Option<&mut Segment16> {
        self.segs
            .get_mut(Self::lane_ix(lane))?
            .get_mut(usize::try_from(seg).ok()?)
    }
}

fn slot_is_position(g: &Segment16, i: usize, _slot: u32) -> bool {
    g.slot.get(i).is_some_and(|s| *s != 0)
}

impl BookSource for MemBook {
    fn head(&self, lane: LaneId, side: Side, tick: Tick) -> u32 {
        self.heads
            .get(&(lane.0, side.code(), tick.0))
            .copied()
            .unwrap_or(0)
    }
    fn segment(&self, lane: LaneId, seg: u32) -> Option<Segment16> {
        self.segs
            .get(Self::lane_ix(lane))?
            .get(usize::try_from(seg).ok()?)
            .copied()
    }
    fn slot(&self, lane: LaneId, slot: u32) -> Option<OrderSlot> {
        if slot == 0 {
            return None;
        }
        self.slots
            .get(Self::lane_ix(lane))?
            .get(usize::try_from(slot).ok()?)
            .copied()
    }
    fn acct_kill(&self, lane: LaneId, acct_ix: u32) -> AcctKill {
        self.kills
            .get(&(lane.0, acct_ix))
            .copied()
            .unwrap_or_default()
    }
    fn session(&self, lane: LaneId, root: u32) -> SessionId {
        self.owners
            .get(&(lane.0, root))
            .map_or(SessionId(0), |o| o.0)
    }
    fn client_tag(&self, lane: LaneId, root: u32) -> u32 {
        self.owners.get(&(lane.0, root)).map_or(0, |o| o.1)
    }
    fn journal<F: FnMut(JEnt)>(&self, lane: LaneId, from: LaneSeq, to: LaneSeq, mut f: F) {
        if let Some(jr) = self.journal.get(Self::lane_ix(lane)) {
            for j in jr.iter().filter(|j| j.seq > from && j.seq <= to) {
                f(*j);
            }
        }
    }
    fn occ(&self, side: Side, tick: Tick) -> u64 {
        self.occ.get(&(side.code(), tick.0)).copied().unwrap_or(0)
    }
    fn occ_next(&self, side: Side, from: Tick) -> Option<Tick> {
        let s = side.code();
        let hit = match side {
            Side::Buy => self.occ.range((s, 0)..=(s, from.0)).next_back(),
            Side::Sell => self.occ.range((s, from.0)..=(s, u32::MAX)).next(),
        };
        hit.map(|((_, t), _)| Tick(*t))
    }
    fn lane_next(&self, lane: LaneId, side: Side, from: Tick) -> Option<Tick> {
        let s = side.code();
        let hit = match side {
            Side::Buy => self
                .lane_occ
                .range((lane.0, s, 0)..=(lane.0, s, from.0))
                .next_back(),
            Side::Sell => self
                .lane_occ
                .range((lane.0, s, from.0)..=(lane.0, s, u32::MAX))
                .next(),
        };
        hit.map(|(_, _, t)| Tick(*t))
    }
}
