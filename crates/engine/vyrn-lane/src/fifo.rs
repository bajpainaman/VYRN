//! The lane FIFO (05 §4.6, 01 §14.13): queue positions in `Segment16` chains, assigned in pass 1
//! in `LaneSeq` order and written later (pass 2 for an independent op, B1 for an explicit one).
//! Lane-private state: each level's tail, each segment's used count, base ts and mask mirror.
//!
//! Positions never move. A position whose op never rests stays empty forever. Segments and
//! slots are taken in index order and not reused in this PR (05 §7.8 reclaim is a follow-up), so
//! every index is a function of the order stream.

use vyrn_bbo::Side;
use vyrn_types::{Nanos, Tick};

use crate::arena::ArenaWriter;
use crate::layout::join;
use crate::layout::{dts_at, seg_word18, u32_at};

/// A queue position: segment and index 0–15.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Pos {
    pub seg: u32,
    pub i: u8,
}

/// A position assigned now, and whether its level had no segment before (an occupancy SET).
pub(crate) struct Assigned {
    pub pos: Pos,
    pub new_level: bool,
}

#[derive(Clone, Copy, Default)]
struct SegP {
    used: u8,
    base: u64,
    mask: u32,
    vmask: u16,
    side: u8,
}

pub(crate) struct Fifo {
    tick_min: u32,
    n_ticks: usize,
    tails: Vec<u32>,
    segs: Vec<SegP>,
    next_seg: u32,
}

fn bit(i: u8) -> u32 {
    1u32.checked_shl(u32::from(i)).unwrap_or(0)
}

fn pend(i: u8) -> u32 {
    bit(i).checked_shl(16).unwrap_or(0)
}

impl Fifo {
    pub fn new(tick_min: Tick, tick_max: Tick, seg_cap: u32) -> Self {
        let n =
            usize::try_from(tick_max.0.saturating_sub(tick_min.0).saturating_add(1)).unwrap_or(0);
        Self {
            tick_min: tick_min.0,
            n_ticks: n,
            tails: vec![0; n.saturating_mul(2)],
            segs: vec![SegP::default(); usize::try_from(seg_cap).unwrap_or(0)],
            next_seg: 1,
        }
    }

    fn dir(&self, side: Side, t: Tick) -> Option<usize> {
        let off = usize::try_from(t.0.checked_sub(self.tick_min)?).ok()?;
        (off < self.n_ticks).then(|| match side {
            Side::Buy => off,
            Side::Sell => self.n_ticks.saturating_add(off),
        })
    }

    fn seg(&self, s: u32) -> Option<&SegP> {
        self.segs.get(usize::try_from(s).ok()?)
    }

    /// Whether [`Self::assign`] would succeed: the tick is in the ladder and a segment is free
    /// if one is needed. A pure test, so a risk check can run before anything is taken.
    pub fn can_assign(&self, side: Side, t: Tick, ts: Nanos) -> bool {
        let Some(d) = self.dir(side, t) else {
            return false;
        };
        let tail = self.tails.get(d).copied().unwrap_or(0);
        self.fits(tail, ts) || usize::try_from(self.next_seg).is_ok_and(|n| n < self.segs.len())
    }

    fn fits(&self, tail: u32, ts: Nanos) -> bool {
        tail != 0
            && self.seg(tail).is_some_and(|g| {
                g.used < 16
                    && ts
                        .0
                        .checked_sub(g.base)
                        .is_some_and(|d| d <= u64::from(u16::MAX))
            })
    }

    /// The next position at the tail of `(side, tick)` for an op with key ts `ts` (pass 1).
    pub fn assign(
        &mut self,
        a: &ArenaWriter<'_>,
        side: Side,
        t: Tick,
        ts: Nanos,
    ) -> Option<Assigned> {
        let d = self.dir(side, t)?;
        let tail = self.tails.get(d).copied().unwrap_or(0);
        if self.fits(tail, ts) {
            let g = self.segs.get_mut(usize::try_from(tail).ok()?)?;
            let i = g.used;
            g.used = g.used.saturating_add(1);
            return Some(Assigned {
                pos: Pos { seg: tail, i },
                new_level: false,
            });
        }
        let s = self.next_seg;
        let g = self.segs.get_mut(usize::try_from(s).ok()?)?;
        self.next_seg = s.saturating_add(1);
        *g = SegP {
            used: 1,
            base: ts.0,
            mask: 0,
            vmask: 0,
            side: side.code(),
        };
        // A fresh segment: every word, then the link that publishes it (`Release`).
        for k in 0..16 {
            a.seg_word(s, k, 0);
        }
        a.seg_word(s, 18, seg_word18(side.code(), 0));
        a.seg_word(s, 19, ts.0);
        for k in 20..24 {
            a.seg_word(s, k, 0);
        }
        a.seg_mask(s, join(0, 1));
        // `succ = 0` with this segment's tick, before the link.
        a.seg_succ(s, join(0, t.0));
        if tail == 0 {
            a.head(side.code(), t, s);
            a.occ_set(side.code(), t);
        } else {
            a.seg_succ(tail, join(s, t.0));
        }
        if let Some(x) = self.tails.get_mut(d) {
            *x = s;
        }
        Some(Assigned {
            pos: Pos { seg: s, i: 0 },
            new_level: tail == 0,
        })
    }

    fn put32(a: &ArenaWriter<'_>, seg: u32, base: usize, i: u8, v: u32) {
        let (k, sh) = u32_at(base, usize::from(i));
        let old = a.seg_word_own(seg, k);
        let keep = !(0xFFFF_FFFFu64 << sh);
        a.seg_word(seg, k, (old & keep) | (u64::from(v) << sh));
    }

    /// Writes position `p` for version `slot` (05 §4.6): `slot[i]`, `qty[i]`, `dts[i]`, then
    /// `active | pend` in one `Release` store of the mask (`active` only if `live`: an
    /// explicit op whose version was already tombstoned gets `pend` alone).
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        a: &ArenaWriter<'_>,
        p: Pos,
        slot: u32,
        qty: u32,
        ts: Nanos,
        live: bool,
        vbit: bool,
    ) {
        let Some(g) = usize::try_from(p.seg)
            .ok()
            .and_then(|s| self.segs.get_mut(s))
        else {
            return;
        };
        Self::put32(a, p.seg, 0, p.i, slot);
        Self::put32(a, p.seg, 8, p.i, qty);
        let (k, sh) = dts_at(usize::from(p.i));
        let d = ts.0.saturating_sub(g.base).min(u64::from(u16::MAX));
        let old = a.seg_word_own(p.seg, k);
        a.seg_word(p.seg, k, (old & !(0xFFFFu64 << sh)) | (d << sh));
        if vbit {
            g.vmask |= u16::try_from(bit(p.i)).unwrap_or(0);
            a.seg_word(p.seg, 18, seg_word18(g.side, g.vmask));
        }
        g.mask |= pend(p.i) | if live { bit(p.i) } else { 0 };
        a.seg_mask(p.seg, join(g.mask, 1));
    }

    /// A cancel or an end at a position: `active` cleared, `pend` set, one `Release` store.
    pub fn end(&mut self, a: &ArenaWriter<'_>, p: Pos) {
        let Some(g) = usize::try_from(p.seg)
            .ok()
            .and_then(|s| self.segs.get_mut(s))
        else {
            return;
        };
        g.mask = (g.mask & !bit(p.i)) | pend(p.i);
        a.seg_mask(p.seg, join(g.mask, 1));
    }

    /// A `Reduce`: the position now has a version chain (`vmask`) and needs the slot (`pend`).
    pub fn chain(&mut self, a: &ArenaWriter<'_>, p: Pos) {
        let Some(g) = usize::try_from(p.seg)
            .ok()
            .and_then(|s| self.segs.get_mut(s))
        else {
            return;
        };
        g.vmask |= u16::try_from(bit(p.i)).unwrap_or(0);
        a.seg_word(p.seg, 18, seg_word18(g.side, g.vmask));
        g.mask |= pend(p.i);
        a.seg_mask(p.seg, join(g.mask, 1));
    }
}
