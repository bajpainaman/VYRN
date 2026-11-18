//! `vyrn-lane::arena` (UNSAFE.toml, 11 §3.2): the lane's lane-written, BBO-read memory (05 §4.1):
//! `OrderSlot` lines (§4.3), `Segment16` blocks (§4.6), level heads, `AcctKill` (§4.7), the
//! journal (§4.9), the occupancy bitmap (§4.8) and the owner words behind
//! `BookSource::session`/`client_tag`.
//!
//! **No `unsafe`.** Every shared word is an `AtomicU64`, so a reader racing the writer sees an old
//! or a new word, never undefined behaviour. The layouts are the spec tables: word `k` of a line
//! holds bytes `8k .. 8k + 8`, little-endian.
//!
//! **Writer.** Exactly one [`ArenaWriter`] exists per arena ([`Arena::split`] runs once). It is
//! held by the lane, the only writer (`INV-WRITER`). Writes are single-writer read-modify-store,
//! never RMW instructions.
//!
//! **Readers.** [`ArenaView`] is `Copy`: the BBO core (through [`crate::LaneBook`]) and the cut
//! core. Reads never block and never allocate.
//!
//! **Ordering** (05 §4.3, §4.6, §4.7; vyrn-bbo `view.rs`). Each `Release` store below is paired
//! with the `Acquire` load named next to it:
//!
//! | Store (writer) | `Release` word | Read first with `Acquire` |
//! |---|---|---|
//! | slot body, then a tombstone (`tomb_ts`, then `tomb_seq`) | `tomb_seq` (word 3) | `tomb_seq`, then `tomb_ts` |
//! | `slot[i]`, `qty[i]`, `dts[i]`, `vmask`, then the mask | `mask \| gen` (word 16) | `mask`, then the rest |
//! | a new segment's fields, then the link to it | head word, `succ` (word 17) | head, `succ` |
//! | `kill_ts`, then `kill_seq` | `kill_seq` | `kill_seq`, then `kill_ts` |
//!
//! A slot line written for a forwarded op is published by the `FwdRing` push (`Release`), and a
//! journal entry by the counter publish (`Release`); both use `Relaxed` stores here.

use core::sync::atomic::{AtomicU64, Ordering};

use vyrn_types::{LaneSeq, Nanos, Tick};

pub use crate::layout::ArenaConfig;
use crate::layout::halves;

/// `n` lines of `W` atomic words.
struct Lines<const W: usize>(Box<[[AtomicU64; W]]>);

impl<const W: usize> Lines<W> {
    fn new(n: usize) -> Self {
        Self(
            (0..n)
                .map(|_| core::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
        )
    }
    fn word(&self, line: usize, k: usize) -> Option<&AtomicU64> {
        self.0.get(line)?.get(k)
    }
    #[inline(always)]
    fn load(&self, line: usize, k: usize, o: Ordering) -> u64 {
        self.word(line, k).map_or(0, |w| w.load(o))
    }
    #[inline(always)]
    fn store(&self, line: usize, k: usize, v: u64, o: Ordering) {
        if let Some(w) = self.word(line, k) {
            w.store(v, o);
        }
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// One lane's shared arenas. Allocated once; split once into its writer and its readers.
pub struct Arena {
    slots: Lines<8>,
    segs: Lines<24>,
    heads: Lines<1>,
    kills: Lines<2>,
    owners: Lines<1>,
    journal: Lines<2>,
    occ: Lines<1>,
    cfg: ArenaConfig,
    split: bool,
}

/// The one writer (the lane). Not `Clone`.
pub struct ArenaWriter<'a>(&'a Arena);

/// A reader (the BBO core, the cut core).
#[derive(Clone, Copy)]
pub struct ArenaView<'a>(&'a Arena);

fn ix(x: u32) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

impl Arena {
    pub fn new(cfg: ArenaConfig) -> Self {
        let ticks = ix(cfg
            .tick_max
            .0
            .saturating_sub(cfg.tick_min.0)
            .saturating_add(1));
        Self {
            slots: Lines::new(ix(cfg.slot_cap)),
            segs: Lines::new(ix(cfg.seg_cap)),
            heads: Lines::new(ticks.saturating_mul(2)),
            kills: Lines::new(ix(cfg.accounts)),
            owners: Lines::new(ix(cfg.slot_cap)),
            journal: Lines::new(ix(cfg.journal.next_power_of_two())),
            occ: Lines::new(ticks.div_ceil(64).saturating_mul(2)),
            cfg,
            split: false,
        }
    }

    /// The writer and a reader; `None` after the first call.
    pub fn split(&mut self) -> Option<(ArenaWriter<'_>, ArenaView<'_>)> {
        if self.split {
            return None;
        }
        self.split = true;
        let a: &Self = self;
        Some((ArenaWriter(a), ArenaView(a)))
    }

    pub fn config(&self) -> ArenaConfig {
        self.cfg
    }

    /// Directory index of `(side, tick)`; `None` outside the ladder.
    fn dir(&self, side: u8, t: Tick) -> Option<usize> {
        let n = ix(self
            .cfg
            .tick_max
            .0
            .checked_sub(self.cfg.tick_min.0)?
            .checked_add(1)?);
        let off = ix(t.0.checked_sub(self.cfg.tick_min.0)?);
        (off < n).then(|| {
            if side & 1 == 0 {
                off
            } else {
                n.saturating_add(off)
            }
        })
    }

    /// Occupancy word index and bit of `(side, tick)`.
    fn occ_at(&self, side: u8, t: Tick) -> Option<(usize, u64)> {
        let n = ix(self
            .cfg
            .tick_max
            .0
            .checked_sub(self.cfg.tick_min.0)?
            .checked_add(1)?);
        let off = ix(t.0.checked_sub(self.cfg.tick_min.0)?);
        if off >= n {
            return None;
        }
        let words = n.div_ceil(64);
        let w = (off >> 6).saturating_add(if side & 1 == 0 { 0 } else { words });
        Some((w, 1u64.checked_shl(u32::try_from(off & 63).ok()?)?))
    }
}

impl ArenaWriter<'_> {
    /// A slot line's 8 words (05 §4.3) before its publication (`FwdRing` push or mask store).
    pub(crate) fn slot_words(&self, slot: u32, w: [u64; 8]) {
        for (k, v) in w.into_iter().enumerate() {
            // ORDERING: published later by a `Release` (mask, `tomb_seq` or ring tail).
            self.0.slots.store(ix(slot), k, v, Ordering::Relaxed);
        }
    }
    /// `next_ver | tick << 32` (word 5): written before the same op's `tomb_seq`.
    pub(crate) fn slot_next_ver(&self, slot: u32, word5: u64) {
        self.0.slots.store(ix(slot), 5, word5, Ordering::Relaxed);
    }
    /// The tombstone: `tomb_ts`, then `tomb_seq` with `Release` (write-once, `INV-ENG-2`).
    pub(crate) fn tombstone(&self, slot: u32, seq: LaneSeq, ts: Nanos) {
        self.0.slots.store(ix(slot), 4, ts.0, Ordering::Relaxed);
        self.0.slots.store(ix(slot), 3, seq.0, Ordering::Release);
    }
    /// Segment word `k` (05 §4.6). Word 16 (`mask | gen`) and 17 (`succ | tick`) go through
    /// [`Self::seg_mask`] and [`Self::seg_succ`].
    pub(crate) fn seg_word(&self, seg: u32, k: usize, v: u64) {
        self.0.segs.store(ix(seg), k, v, Ordering::Relaxed);
    }
    pub(crate) fn seg_word_own(&self, seg: u32, k: usize) -> u64 {
        self.0.segs.load(ix(seg), k, Ordering::Relaxed)
    }
    /// `mask | gen << 32` with `Release`: publishes the positions written before it.
    pub(crate) fn seg_mask(&self, seg: u32, word16: u64) {
        self.0.segs.store(ix(seg), 16, word16, Ordering::Release);
    }
    /// `succ | tick << 32` with `Release`: publishes the successor's fields.
    pub(crate) fn seg_succ(&self, seg: u32, word17: u64) {
        self.0.segs.store(ix(seg), 17, word17, Ordering::Release);
    }
    /// The head word of `(side, tick)` with `Release`. `false` outside the ladder.
    pub(crate) fn head(&self, side: u8, t: Tick, seg: u32) -> bool {
        let Some(d) = self.0.dir(side, t) else {
            return false;
        };
        self.0.heads.store(d, 0, u64::from(seg), Ordering::Release);
        true
    }
    /// Sets the lane bitmap bit of `(side, tick)` (05 §4.8).
    pub(crate) fn occ_set(&self, side: u8, t: Tick) {
        if let Some((w, b)) = self.0.occ_at(side, t) {
            let old = self.0.occ.load(w, 0, Ordering::Relaxed);
            // ORDERING: conservative bits; the head word (`Release`) is what readers follow.
            self.0.occ.store(w, 0, old | b, Ordering::Relaxed);
        }
    }
    /// `AcctKill[acct]` (05 §4.7): `kill_ts`, then `kill_seq` with `Release`.
    pub(crate) fn acct_kill(&self, acct: u32, seq: LaneSeq, ts: Nanos) {
        self.0.kills.store(ix(acct), 1, ts.0, Ordering::Relaxed);
        self.0.kills.store(ix(acct), 0, seq.0, Ordering::Release);
    }
    /// `session | client_tag << 32` of a root, before its publication.
    pub(crate) fn owner(&self, root: u32, word: u64) {
        self.0.owners.store(ix(root), 0, word, Ordering::Relaxed);
    }
    /// Journal entry at ring position `pos` (05 §4.9), published by the counter publish.
    pub(crate) fn journal(&self, pos: u64, w: [u64; 2]) {
        let mask = u64::try_from(self.0.journal.len()).map_or(0, |n| n.saturating_sub(1));
        let line = usize::try_from(pos & mask).unwrap_or(usize::MAX);
        for (k, v) in w.into_iter().enumerate() {
            self.0.journal.store(line, k, v, Ordering::Relaxed);
        }
    }
    pub fn view(&self) -> ArenaView<'_> {
        ArenaView(self.0)
    }
}

impl<'a> ArenaView<'a> {
    pub fn config(&self) -> ArenaConfig {
        self.0.cfg
    }
    /// Slot words, `tomb_seq` first with `Acquire`, then `tomb_ts`, then the rest. `None` for
    /// slot 0 or an index outside the arena.
    pub(crate) fn slot_words(&self, slot: u32) -> Option<[u64; 8]> {
        let s = ix(slot);
        if slot == 0 || s >= self.0.slots.len() {
            return None;
        }
        let w3 = self.0.slots.load(s, 3, Ordering::Acquire);
        let w4 = self.0.slots.load(s, 4, Ordering::Relaxed);
        Some(core::array::from_fn(|k| match k {
            3 => w3,
            4 => w4,
            // ORDERING: after the `Acquire` above, and after the publication the caller read.
            _ => self.0.slots.load(s, k, Ordering::Relaxed),
        }))
    }
    /// Segment words: `mask` and `succ` with `Acquire` first, then the rest.
    pub(crate) fn seg_words(&self, seg: u32) -> Option<[u64; 24]> {
        let g = ix(seg);
        if seg == 0 || g >= self.0.segs.len() {
            return None;
        }
        let w16 = self.0.segs.load(g, 16, Ordering::Acquire);
        let w17 = self.0.segs.load(g, 17, Ordering::Acquire);
        Some(core::array::from_fn(|k| match k {
            16 => w16,
            17 => w17,
            // ORDERING: covered by the `Acquire` loads of words 16 and 17.
            _ => self.0.segs.load(g, k, Ordering::Relaxed),
        }))
    }
    pub(crate) fn head(&self, side: u8, t: Tick) -> u32 {
        self.0
            .dir(side, t)
            .map_or(0, |d| halves(self.0.heads.load(d, 0, Ordering::Acquire)).0)
    }
    /// `(kill_seq, kill_ts)`.
    pub(crate) fn acct_kill(&self, acct: u32) -> (u64, u64) {
        let seq = self.0.kills.load(ix(acct), 0, Ordering::Acquire);
        (seq, self.0.kills.load(ix(acct), 1, Ordering::Relaxed))
    }
    pub(crate) fn owner(&self, root: u32) -> u64 {
        self.0.owners.load(ix(root), 0, Ordering::Relaxed)
    }
    pub(crate) fn journal(&self, pos: u64) -> [u64; 2] {
        let mask = u64::try_from(self.0.journal.len()).map_or(0, |n| n.saturating_sub(1));
        let line = usize::try_from(pos & mask).unwrap_or(usize::MAX);
        core::array::from_fn(|k| self.0.journal.load(line, k, Ordering::Relaxed))
    }
    pub(crate) fn journal_len(&self) -> u64 {
        u64::try_from(self.0.journal.len()).unwrap_or(0)
    }
    /// Lane bitmap bit of `(side, tick)`.
    pub(crate) fn occ(&self, side: u8, t: Tick) -> bool {
        self.0
            .occ_at(side, t)
            .is_some_and(|(w, b)| self.0.occ.load(w, 0, Ordering::Relaxed) & b != 0)
    }
}
