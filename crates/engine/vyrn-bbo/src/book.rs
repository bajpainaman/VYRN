//! The book as the BBO core sees it at one step: visibility of a version at a cut or at a key
//! (05 §5.1, §5.2), a lane's live positions at a level (§5.3), the merged level FIFO (§5.4), and
//! the search for the next level with a live order (`advance_bound`, §8.5).
//!
//! This is the reference form: every position reads its slot line, and the merge compares one
//! head per lane. The mask fast path, the head cache, the loser tree and the AVX-512 segment
//! pass of 05 §5.4 and §8.5 are optimizations of the same order and must give the same makers
//! (spec follow-up F7 in the PR).

use core::cell::Cell;

use vyrn_types::{Handle, LaneId, LaneSeq, Nanos, StepId, Tick};

use crate::cut::Cut;
use crate::key::{PrioKey, Side, Tif};
use crate::view::{BookSource, OrderSlot, Segment16, SlotKind};
use crate::{ENG_PEND_CAP, MAX_LANES};

/// `BboSlotState[lane][root]` (05 §4.11) plus the generation it belongs to, so a reused root
/// slot starts at zero, and `np_seq`: the `LaneSeq` of the newest explicit new-priority
/// `Replace` of the root, which ends every older version of it at every later step.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RootSt {
    pub gen_: u8,
    pub killed: bool,
    pub filled: u32,
    pub np_seq: u64,
}

/// One `Pend` entry (05 §8.5): an explicit op that rested and that its lane has not yet written.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendEnt {
    pub lane: usize,
    pub slot: u32,
    pub seq: LaneSeq,
    pub step: StepId,
    pub side: Side,
    pub tick: Tick,
    /// Index in its source's dependency list, or `NO_DEP` for a source that rested.
    pub dep: u8,
}

/// `PendEnt.dep` of a source.
pub(crate) const NO_DEP: u8 = u8::MAX;

/// BBO-private per-order state, allocated once (`INV-NOALLOC`).
pub(crate) struct State {
    pub n_lanes: usize,
    slot_cap: usize,
    pub seg_cap: u32,
    roots: Vec<RootSt>,
    /// `BboVer` bit 1 as the `LaneSeq` of the explicit op that wrote the slot (0 = none), so a
    /// reused slot is never explicit by accident.
    expl: Vec<u64>,
    /// `BboVer` bit 0 (05 §4.11): `ins_seq << 1 | ok` of a checked `NewPrio` version; 0 =
    /// unchecked. Checked once, when the version is first considered, which is at or after its
    /// position in L and before any fill of it (05 §8.5 `replace_ok`).
    rok: Vec<Cell<u64>>,
    pub pend: Vec<PendEnt>,
    pub rank: [u8; MAX_LANES],
    /// An engine fault (05 §14.3): an arena index out of range or a full buffer.
    pub fault: bool,
}

impl State {
    pub fn new(n_lanes: usize, slot_cap: usize, seg_cap: u32, rank: [u8; MAX_LANES]) -> Self {
        let n = n_lanes.saturating_mul(slot_cap);
        Self {
            n_lanes,
            slot_cap,
            seg_cap,
            roots: vec![RootSt::default(); n],
            expl: vec![0; n],
            rok: (0..n).map(|_| Cell::new(0)).collect(),
            pend: Vec::with_capacity(ENG_PEND_CAP),
            rank,
            fault: false,
        }
    }

    fn ix(&self, lane: usize, slot: u32) -> Option<usize> {
        let s = usize::try_from(slot).ok()?;
        if lane >= self.n_lanes || s >= self.slot_cap {
            return None;
        }
        lane.checked_mul(self.slot_cap)?.checked_add(s)
    }

    pub fn root(&self, lane: usize, root: u32, gen_: u8) -> RootSt {
        match self.ix(lane, root).and_then(|i| self.roots.get(i)) {
            Some(r) if r.gen_ == gen_ => *r,
            _ => RootSt {
                gen_,
                ..RootSt::default()
            },
        }
    }

    pub fn root_mut(&mut self, lane: usize, root: u32, gen_: u8) -> Option<&mut RootSt> {
        let i = self.ix(lane, root);
        match i.and_then(|i| self.roots.get_mut(i)) {
            Some(r) => {
                if r.gen_ != gen_ {
                    *r = RootSt {
                        gen_,
                        ..RootSt::default()
                    };
                }
                Some(r)
            }
            None => {
                self.fault = true;
                None
            }
        }
    }

    pub fn explicit(&self, lane: usize, slot: u32, seq: LaneSeq) -> bool {
        seq.0 != 0
            && self
                .ix(lane, slot)
                .and_then(|i| self.expl.get(i))
                .is_some_and(|s| *s == seq.0)
    }

    pub fn set_explicit(&mut self, lane: usize, slot: u32, seq: LaneSeq) {
        match self.ix(lane, slot).and_then(|i| self.expl.get_mut(i)) {
            Some(s) => *s = seq.0,
            None => self.fault = true,
        }
    }

    /// 05 §8.5 `replace_ok`: the version a `NewPrio` slot replaces still had open quantity.
    pub fn replace_ok(&self, lane: usize, slot: u32, v: &OrderSlot) -> bool {
        let Some(c) = self.ix(lane, slot).and_then(|i| self.rok.get(i)) else {
            return false;
        };
        let x = c.get();
        if x != 0 && x.wrapping_shr(1) == v.ins_seq.0 {
            return x & 1 == 1;
        }
        let r = self.root(lane, v.root, v.gen_);
        let ok = !r.killed && r.filled < v.pred_total();
        c.set(v.ins_seq.0.wrapping_shl(1) | u64::from(ok));
        ok
    }

    pub fn pend_insert(&mut self, p: PendEnt) {
        if self.pend.len() < ENG_PEND_CAP {
            self.pend.push(p);
        } else {
            self.fault = true;
        }
    }

    fn in_pend(&self, lane: usize, slot: u32, seq: LaneSeq) -> bool {
        self.pend
            .iter()
            .any(|p| p.lane == lane && p.slot == slot && p.seq == seq)
    }
}

#[inline(always)]
pub(crate) fn bit(i: usize) -> u64 {
    u32::try_from(i)
        .ok()
        .and_then(|i| 1u64.checked_shl(i))
        .unwrap_or(0)
}

/// Lanes `0..n` as a mask.
#[inline(always)]
pub(crate) fn lanes_mask(n: usize) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        bit(n).wrapping_sub(1)
    }
}

/// One maker candidate: the version of a position (or a `Pend` leaf) live at the step.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Maker {
    pub lane: usize,
    /// The version that trades.
    pub vslot: u32,
    pub v: OrderSlot,
    pub key: PrioKey,
    pub open: u32,
    /// Index into `State::pend` for a `Pend` leaf.
    pub pend: Option<usize>,
}

impl Maker {
    pub fn handle(&self) -> Handle {
        Handle::new(self.v.root, self.v.gen_).unwrap_or(Handle(0))
    }
}

/// What a step sees: the cut, `C_{s−1}`, and for a `Rescan` entry the key it runs at.
pub(crate) struct Ctx<'a, S> {
    pub src: &'a S,
    pub st: &'a State,
    pub c: &'a Cut,
    pub prev: &'a Cut,
    /// `Some(k)`: visibility at key `k` inside the batch (05 §5.2). `None`: at the cut (§5.1).
    pub key: Option<PrioKey>,
    /// An `Uncross` step: auction-only orders are visible (05 §2.5 P2).
    pub auction: bool,
    /// Wild and lag lanes: probed at every level whatever the masks say (Lemma 7.1).
    pub probe: u64,
}

impl<S: BookSource> Ctx<'_, S> {
    fn cut(&self, l: usize) -> u64 {
        self.c.get(l).map_or(0, |s| s.0)
    }
    fn prev_cut(&self, l: usize) -> u64 {
        self.prev.get(l).map_or(0, |s| s.0)
    }
    pub fn rank(&self, l: usize) -> u8 {
        self.st.rank.get(l).copied().unwrap_or(0)
    }
    pub fn key_of(&self, ts: Nanos, l: usize, seq: LaneSeq) -> PrioKey {
        PrioKey {
            ts,
            rank: self.rank(l),
            seq,
        }
    }

    /// Op `seq` of lane `l` (with ts `ts`) has taken effect at this point: inside the cut, and at
    /// key `k` either inside `C_{s−1}` or before `k` in the batch.
    fn done(&self, seq: LaneSeq, ts: Nanos, l: usize) -> bool {
        if seq.0 == 0 || seq.0 > self.cut(l) {
            return false;
        }
        match self.key {
            None => true,
            Some(k) => seq.0 <= self.prev_cut(l) || self.key_of(ts, l, seq) < k,
        }
    }

    /// 05 §5.1 `visible` (at a cut) or §5.2 `visible_at` (at a key), plus the BBO's own end of
    /// versions replaced by an explicit new-priority `Replace`.
    pub fn visible(&self, l: usize, slot: u32, v: &OrderSlot) -> bool {
        let inserted =
            self.st.explicit(l, slot, v.ins_seq) || self.done(v.ins_seq, v.ins_time(), l);
        if !inserted {
            return false;
        }
        if self.done(v.tomb_seq, v.tomb_ts, usize::from(v.tomb_lane.0)) {
            return false;
        }
        let k = self.src.acct_kill(LaneId(lane_u8(l)), v.acct_ix);
        if k.kill_seq.0 != 0 && v.ins_seq < k.kill_seq && self.done(k.kill_seq, k.kill_ts, l) {
            return false;
        }
        let r = self.st.root(l, v.root, v.gen_);
        !(r.np_seq != 0 && v.ins_seq.0 < r.np_seq)
    }

    /// Open quantity of the order whose version is `v`; `None` when killed or filled.
    pub fn open(&self, l: usize, v: &OrderSlot) -> Option<u32> {
        let r = self.st.root(l, v.root, v.gen_);
        if r.killed {
            return None;
        }
        v.total.checked_sub(r.filled).filter(|o| *o > 0)
    }

    /// 05 §5.1 `live`: visible, not killed, open > 0, and auction-only only in an uncross.
    pub fn live(&self, l: usize, slot: u32, v: &OrderSlot) -> Option<u32> {
        if v.flags.tif() == Tif::AuctionOnly && !self.auction {
            return None;
        }
        if !self.visible(l, slot, v) {
            return None;
        }
        if v.kind == SlotKind::NewPrio && !self.st.replace_ok(l, slot, v) {
            return None;
        }
        self.open(l, v)
    }

    /// The version of the order at `slot` in effect here: `slot`, or the `KeepPrio` successor
    /// whose predecessor's tombstone has taken effect. Also whether it has ended (tombstone,
    /// `AcctKill`, or an explicit new-priority `Replace`).
    pub fn current_version(&self, l: usize, slot: u32) -> Option<(u32, OrderSlot, bool)> {
        let lane = LaneId(lane_u8(l));
        let (mut s, mut v) = (slot, self.src.slot(lane, slot)?);
        for _ in 0..16 {
            if v.next_ver == 0 || !self.done(v.tomb_seq, v.tomb_ts, usize::from(v.tomb_lane.0)) {
                break;
            }
            s = v.next_ver;
            v = self.src.slot(lane, s)?;
        }
        let k = self.src.acct_kill(lane, v.acct_ix);
        let r = self.st.root(l, v.root, v.gen_);
        let ended = self.done(v.tomb_seq, v.tomb_ts, usize::from(v.tomb_lane.0))
            || (k.kill_seq.0 != 0 && v.ins_seq < k.kill_seq && self.done(k.kill_seq, k.kill_ts, l))
            || (r.np_seq != 0 && v.ins_seq.0 < r.np_seq);
        Some((s, v, ended))
    }

    /// 05 §5.1 `version_at`: the position slot, or the `KeepPrio` successor in effect here.
    /// Returns `(version slot, version, position slot line)`.
    fn version_at(&self, l: usize, g: &Segment16, i: usize) -> Option<(u32, OrderSlot, OrderSlot)> {
        let ps = *g.slot.get(i)?;
        if ps == 0 {
            return None;
        }
        let lane = LaneId(lane_u8(l));
        let pos = self.src.slot(lane, ps)?;
        let (mut s, mut v) = (ps, pos);
        if u64::from(g.vmask) & bit(i) != 0 {
            // ≤ one hop per Reduce of the order; 16 bounds a corrupt chain.
            for _ in 0..16 {
                if v.next_ver == 0 || !self.done(v.tomb_seq, v.tomb_ts, usize::from(v.tomb_lane.0))
                {
                    break;
                }
                s = v.next_ver;
                v = self.src.slot(lane, s)?;
            }
        }
        Some((s, v, pos))
    }

    /// 05 §5.3 `lane_head`, as a cursor: the next live position of lane `l` at `(side, tick)`.
    fn lane_next(&self, l: usize, side: Side, tick: Tick, cur: &mut Cursor) -> Option<Maker> {
        if cur.done {
            return None;
        }
        let lane = LaneId(lane_u8(l));
        if !cur.started {
            cur.started = true;
            cur.seg = self.src.head(lane, side, tick);
            cur.pos = 0;
        }
        let mut hops = 0u32;
        'segs: while cur.seg != 0 && hops <= self.st.seg_cap {
            let Some(g) = self.src.segment(lane, cur.seg) else {
                break;
            };
            if g.tick != tick || g.side != side.code() {
                break;
            }
            let m = u64::from(g.mask);
            let cand = (m | m.wrapping_shr(16)) & 0xFFFF;
            while cur.pos < 16 {
                let i = cur.pos;
                cur.pos = cur.pos.saturating_add(1);
                if cand & bit(i) == 0 {
                    continue;
                }
                let Some((vs, v, pos)) = self.version_at(l, &g, i) else {
                    continue;
                };
                if self
                    .st
                    .in_pend(l, *g.slot.get(i).unwrap_or(&0), pos.ins_seq)
                {
                    continue; // its Pend leaf stands in for it (05 §5.4)
                }
                if v.ins_seq.0 > self.cut(l) && !self.st.explicit(l, vs, v.ins_seq) {
                    break 'segs; // the tail beyond the cut: every later position is later too
                }
                if let Some(open) = self.live(l, vs, &v) {
                    return Some(Maker {
                        lane: l,
                        vslot: vs,
                        v,
                        key: self.key_of(pos.prio_ts, l, pos.ins_seq),
                        open,
                        pend: None,
                    });
                }
            }
            cur.seg = g.succ;
            cur.pos = 0;
            hops = hops.saturating_add(1);
        }
        cur.done = true;
        None
    }

    fn pend_maker(&self, ix: usize, side: Side, tick: Tick) -> Option<Maker> {
        let p = self.st.pend.get(ix)?;
        if p.side != side || p.tick != tick {
            return None;
        }
        let v = self.src.slot(LaneId(lane_u8(p.lane)), p.slot)?;
        if v.ins_seq != p.seq {
            return None;
        }
        let open = self.live(p.lane, p.slot, &v)?;
        Some(Maker {
            lane: p.lane,
            vslot: p.slot,
            v,
            key: self.key_of(v.prio_ts, p.lane, v.ins_seq),
            open,
            pend: Some(ix),
        })
    }
}

pub(crate) fn lane_u8(l: usize) -> u8 {
    u8::try_from(l).unwrap_or(u8::MAX)
}

#[derive(Clone, Copy, Debug, Default)]
struct Cursor {
    seg: u32,
    pos: usize,
    started: bool,
    done: bool,
}

/// The merged level FIFO at `(side, tick)` (05 §5.4): makers in key order across lanes and
/// `Pend` leaves. Never stored; rebuilt per level per step.
pub(crate) struct Level {
    side: Side,
    tick: Tick,
    cur: [Cursor; MAX_LANES],
    head: [Option<Maker>; MAX_LANES],
    pend_done: [u64; 4],
}

impl Level {
    pub fn new<S: BookSource>(ctx: &Ctx<'_, S>, side: Side, tick: Tick) -> Self {
        let mut lv = Self {
            side,
            tick,
            cur: [Cursor::default(); MAX_LANES],
            head: [None; MAX_LANES],
            pend_done: [0; 4],
        };
        let mask = (ctx.src.occ(side, tick) | ctx.probe) & lanes_mask(ctx.st.n_lanes);
        for l in 0..ctx.st.n_lanes {
            if mask & bit(l) != 0
                && let (Some(c), Some(h)) = (lv.cur.get_mut(l), lv.head.get_mut(l))
            {
                *h = ctx.lane_next(l, side, tick, c);
            }
        }
        lv
    }

    fn pend_is_done(&self, ix: usize) -> bool {
        self.pend_done
            .get(ix.wrapping_shr(6))
            .is_some_and(|w| w & bit(ix & 63) != 0)
    }

    /// The next maker in key order, or `None` when the level has no more live orders.
    pub fn next<S: BookSource>(&mut self, ctx: &Ctx<'_, S>) -> Option<Maker> {
        let mut best: Option<Maker> = None;
        for m in self.head.iter().flatten() {
            if best.is_none_or(|b| m.key < b.key) {
                best = Some(*m);
            }
        }
        for ix in 0..ctx.st.pend.len() {
            if self.pend_is_done(ix) {
                continue;
            }
            if let Some(m) = ctx.pend_maker(ix, self.side, self.tick)
                && best.is_none_or(|b| m.key < b.key)
            {
                best = Some(m);
            }
        }
        let m = best?;
        match m.pend {
            Some(ix) => {
                if let Some(w) = self.pend_done.get_mut(ix.wrapping_shr(6)) {
                    *w |= bit(ix & 63);
                }
            }
            None => {
                if let (Some(c), Some(h)) = (self.cur.get_mut(m.lane), self.head.get_mut(m.lane)) {
                    *h = ctx.lane_next(m.lane, self.side, self.tick, c);
                }
            }
        }
        Some(m)
    }
}

/// Moves `t` one tick away from the spread on `side` (down for bids, up for asks).
pub(crate) fn away(side: Side, t: Tick) -> Option<Tick> {
    match side {
        Side::Buy => t.checked_sub(1).filter(|t| t.0 > 0),
        Side::Sell => t.checked_add(1).filter(|t| t.0 < u32::MAX),
    }
}

/// `limit` admits level `t` on maker side `side`: bids `t ≥ limit`, asks `t ≤ limit`.
pub(crate) fn within(side: Side, t: Tick, limit: Tick) -> bool {
    match side {
        Side::Buy => t >= limit,
        Side::Sell => t <= limit,
    }
}

/// The first level at or beyond `from` on `side`, within `limit`, with a live order at the
/// step (05 §8.5 `advance_bound`, read-only). Candidates come from the occupancy masks, the
/// bitmaps of probed lanes and the `Pend` entries.
pub(crate) fn next_level<S: BookSource>(
    ctx: &Ctx<'_, S>,
    side: Side,
    from: Tick,
    limit: Tick,
) -> Option<Tick> {
    let better = |a: Tick, b: Tick| match side {
        Side::Buy => a > b,
        Side::Sell => a < b,
    };
    let beyond = |t: Tick, f: Tick| match side {
        Side::Buy => t <= f,
        Side::Sell => t >= f,
    };
    let mut from = from;
    // Every pass moves past one empty level; 2^24 is the whole ladder (05 §13.1).
    for _ in 0..(1u32 << 24) {
        let mut best = ctx.src.occ_next(side, from);
        let probe = ctx.probe & lanes_mask(ctx.st.n_lanes);
        for l in 0..ctx.st.n_lanes {
            if probe & bit(l) != 0
                && let Some(t) = ctx.src.lane_next(LaneId(lane_u8(l)), side, from)
                && best.is_none_or(|b| better(t, b))
            {
                best = Some(t);
            }
        }
        for p in &ctx.st.pend {
            if p.side == side && beyond(p.tick, from) && best.is_none_or(|b| better(p.tick, b)) {
                best = Some(p.tick);
            }
        }
        let t = best?;
        if !within(side, t, limit) {
            return None;
        }
        if Level::new(ctx, side, t).next(ctx).is_some() {
            return Some(t);
        }
        from = away(side, t)?;
    }
    None
}
