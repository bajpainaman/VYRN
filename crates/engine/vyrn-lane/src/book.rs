//! [`LaneBook`]: `vyrn_bbo::BookSource` over the lanes' arenas (05 §4.3–§4.9). This is the read
//! contract the BBO core runs on; vyrn-bbo's `view.rs` states its ordering rules and
//! [`crate::arena`] implements them.
//!
//! `occ` here is the OR of the lanes' own occupancy bitmaps (05 §4.8), read directly. That set is
//! a superset of what the cut cores' masks may hold (Lemma 7.1 needs no more), so a BBO core run
//! on it sees every lane as trusted. The engine's cut-core masks (05 §7.2) replace it in
//! `vyrn-engine`.

use vyrn_bbo::{AcctKill, BookSource, JEnt, OrderSlot, Segment16, Side};
use vyrn_types::{LaneId, LaneSeq, Nanos, SessionId, Tick};

use crate::arena::ArenaView;
use crate::layout::halves;
use crate::layout::{jent_from_words, seg_from_words, slot_from_words};

/// The arenas of lanes `0..views.len()`, lane `l` at index `l`.
#[derive(Clone, Copy)]
pub struct LaneBook<'v, 'a> {
    views: &'v [ArenaView<'a>],
}

impl<'v, 'a> LaneBook<'v, 'a> {
    pub fn new(views: &'v [ArenaView<'a>]) -> Self {
        Self { views }
    }
    fn lane(&self, l: LaneId) -> Option<&ArenaView<'a>> {
        self.views.get(usize::from(l.0))
    }
    /// The ladder `[min, max]` shared by every lane (lane 0's configuration).
    fn ladder(&self) -> Option<(u32, u32)> {
        let c = self.views.first()?.config();
        Some((c.tick_min.0, c.tick_max.0))
    }
    /// The first tick at or beyond `from` (away from the spread) where `hit` holds.
    fn scan(&self, side: Side, from: Tick, hit: impl Fn(Tick) -> bool) -> Option<Tick> {
        let (lo, hi) = self.ladder()?;
        match side {
            Side::Buy => {
                let mut t = from.0.min(hi);
                while t >= lo {
                    if hit(Tick(t)) {
                        return Some(Tick(t));
                    }
                    t = t.checked_sub(1)?;
                }
                None
            }
            Side::Sell => {
                let mut t = from.0.max(lo);
                while t <= hi {
                    if hit(Tick(t)) {
                        return Some(Tick(t));
                    }
                    t = t.checked_add(1)?;
                }
                None
            }
        }
    }
}

impl BookSource for LaneBook<'_, '_> {
    fn head(&self, lane: LaneId, side: Side, tick: Tick) -> u32 {
        self.lane(lane).map_or(0, |v| v.head(side.code(), tick))
    }
    fn segment(&self, lane: LaneId, seg: u32) -> Option<Segment16> {
        Some(seg_from_words(&self.lane(lane)?.seg_words(seg)?))
    }
    fn slot(&self, lane: LaneId, slot: u32) -> Option<OrderSlot> {
        Some(slot_from_words(&self.lane(lane)?.slot_words(slot)?))
    }
    fn acct_kill(&self, lane: LaneId, acct_ix: u32) -> AcctKill {
        self.lane(lane).map_or(AcctKill::default(), |v| {
            let (seq, ts) = v.acct_kill(acct_ix);
            AcctKill {
                kill_seq: LaneSeq(seq),
                kill_ts: Nanos(ts),
            }
        })
    }
    fn session(&self, lane: LaneId, root: u32) -> SessionId {
        SessionId(self.lane(lane).map_or(0, |v| halves(v.owner(root)).0))
    }
    fn client_tag(&self, lane: LaneId, root: u32) -> u32 {
        self.lane(lane).map_or(0, |v| halves(v.owner(root)).1)
    }
    fn journal<F: FnMut(JEnt)>(&self, lane: LaneId, from: LaneSeq, to: LaneSeq, mut f: F) {
        let Some(v) = self.lane(lane) else { return };
        // The ring holds the newest `journal_len` entries, one per position, in seq order: scan
        // it once and keep the entries in range, oldest first.
        let n = v.journal_len();
        let mut best: Option<(u64, u64)> = None; // (oldest seq in range, its position)
        for p in 0..n {
            if let Some(j) = jent_from_words(&v.journal(p))
                && j.seq > from
                && j.seq <= to
                && best.is_none_or(|(s, _)| j.seq.0 < s)
            {
                best = Some((j.seq.0, p));
            }
        }
        let Some((_, start)) = best else { return };
        let mut last = from;
        for k in 0..n {
            let p = start.wrapping_add(k);
            match jent_from_words(&v.journal(p)) {
                Some(j) if j.seq > last && j.seq <= to => {
                    last = j.seq;
                    f(j);
                }
                _ => break,
            }
        }
    }
    fn occ(&self, side: Side, tick: Tick) -> u64 {
        let mut m = 0u64;
        for (l, v) in self.views.iter().enumerate() {
            if v.occ(side.code(), tick) {
                m |= u32::try_from(l)
                    .ok()
                    .and_then(|l| 1u64.checked_shl(l))
                    .unwrap_or(0);
            }
        }
        m
    }
    fn occ_next(&self, side: Side, from: Tick) -> Option<Tick> {
        self.scan(side, from, |t| self.occ(side, t) != 0)
    }
    fn lane_next(&self, lane: LaneId, side: Side, from: Tick) -> Option<Tick> {
        let v = self.lane(lane)?;
        self.scan(side, from, |t| v.occ(side.code(), t))
    }
}
