//! The typed shared lines of 05 §4.10, §4.13, §4.14 and §4.15. Each type's encoding is its
//! spec table: word `i` holds bytes `8 + 8 i ..` of the line (offset 0 is the seqlock).

use vyrn_types::{LaneSeq, StepId, Tick};

use super::line::{PubRing, Published, Words, join, split, u32_at};

/// One occupancy event (05 §4.10): `tick | back u16 | bits u16`; bit 0 side, bit 1 CLEAR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OccEvent {
    pub tick: Tick,
    pub back: u16,
    pub bits: u16,
}

impl OccEvent {
    #[inline]
    fn word(self) -> u64 {
        let [b0, b1] = self.back.to_le_bytes();
        let [c0, c1] = self.bits.to_le_bytes();
        join(self.tick.0.to_le_bytes(), [b0, b1, c0, c1])
    }
    #[inline]
    fn from_word(w: u64) -> Self {
        let (t, [b0, b1, c0, c1]) = split(w);
        Self {
            tick: Tick(u32_at(t)),
            back: u16::from_le_bytes([b0, b1]),
            bits: u16::from_le_bytes([c0, c1]),
        }
    }
}

/// `CounterLine` (05 §4.10). Writer: lane `l`, after every op and as its idle heartbeat.
/// Readers: the cut core of `l`'s half, the control role.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counter {
    /// Every op ≤ `seq` is applied, or explicit.
    pub seq: LaneSeq,
    pub snap_ver: u32,
    pub f_lo: u32,
    pub fwd_pend: LaneSeq,
    pub n_ev: u32,
    pub dir_sel: u8,
    /// 0 Running, 1 Parking, 2 Parked.
    pub state: u8,
    /// The three newest events, newest last.
    pub ev: [OccEvent; 3],
}

impl Words<7> for Counter {
    #[inline]
    fn to_words(&self) -> [u64; 7] {
        let [n0, n1, n2, n3] = self.n_ev.to_le_bytes();
        let [e0, e1, e2] = self.ev;
        [
            self.seq.0,
            join(self.snap_ver.to_le_bytes(), self.f_lo.to_le_bytes()),
            self.fwd_pend.0,
            join([n0, n1, n2, n3], [self.dir_sel, self.state, 0, 0]),
            e0.word(),
            e1.word(),
            e2.word(),
        ]
    }
    #[inline]
    fn from_words([seq, sf, fwd, w3, e0, e1, e2]: [u64; 7]) -> Self {
        let (snap_ver, f_lo) = split(sf);
        let (n_ev, [dir_sel, state, _, _]) = split(w3);
        Self {
            seq: LaneSeq(seq),
            snap_ver: u32_at(snap_ver),
            f_lo: u32_at(f_lo),
            fwd_pend: LaneSeq(fwd),
            n_ev: u32_at(n_ev),
            dir_sel,
            state,
            ev: [e0, e1, e2].map(OccEvent::from_word),
        }
    }
}

/// `SnapshotLine` (05 §4.14). Writer: the BBO core, once per step that changes it. Readers:
/// lanes, TX cores. Bytes 40–63 are reserved and not stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub version: u64,
    /// 0 = no bid.
    pub bid: Tick,
    /// `u32::MAX` = no ask.
    pub ask: Tick,
    pub done_step: StepId,
    pub win_center: Tick,
    /// 0 Continuous, 1 Auction, 2 Halted, 3 Frozen.
    pub phase: u8,
    pub flags: u8,
}

impl Words<4> for Snapshot {
    #[inline]
    fn to_words(&self) -> [u64; 4] {
        [
            self.version,
            join(self.bid.0.to_le_bytes(), self.ask.0.to_le_bytes()),
            self.done_step.0,
            join(
                self.win_center.0.to_le_bytes(),
                [self.phase, self.flags, 0, 0],
            ),
        ]
    }
    #[inline]
    fn from_words([version, ba, done, w3]: [u64; 4]) -> Self {
        let (bid, ask) = split(ba);
        let (c, [phase, flags, _, _]) = split(w3);
        Self {
            version,
            bid: Tick(u32_at(bid)),
            ask: Tick(u32_at(ask)),
            done_step: StepId(done),
            win_center: Tick(u32_at(c)),
            phase,
            flags,
        }
    }
}

/// Lanes in one half-cut (01 §14.3: core 1 reads lanes 0–24, core 6 lanes 25–48).
pub const LANES_PER_HALF: usize = 25;

/// One lane's entry in a half-cut (05 §4.13), copied from its `Counter`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CutEntry {
    pub seq: LaneSeq,
    pub snap_ver: u32,
    pub f_lo: u32,
}

/// One half-cut publication (05 §4.13). Words 0–6 are line 0 (`pub_id`, `wild`, `occ_center`,
/// then the reserved bytes 24–63, stored as zero); entry `i` is words `7 + 2 i` and `8 + 2 i`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HalfCutVal {
    /// Set by `PubRing::publish`.
    pub pub_id: u64,
    /// Bit `i`: lane `i` of the half is not trusted (§7.3).
    pub wild: u32,
    pub occ_center: Tick,
    pub entries: [CutEntry; LANES_PER_HALF],
}

/// Words of a `HalfCutVal`.
pub const HALF_CUT_WORDS: usize = 7 + 2 * LANES_PER_HALF;

impl Words<HALF_CUT_WORDS> for HalfCutVal {
    #[inline]
    fn to_words(&self) -> [u64; HALF_CUT_WORDS] {
        let head = [
            self.pub_id,
            join(self.wild.to_le_bytes(), self.occ_center.0.to_le_bytes()),
            0,
            0,
            0,
            0,
            0,
        ];
        let body = self.entries.iter().flat_map(|e| {
            [
                e.seq.0,
                join(e.snap_ver.to_le_bytes(), e.f_lo.to_le_bytes()),
            ]
        });
        let mut out = [0u64; HALF_CUT_WORDS];
        for (dst, src) in out.iter_mut().zip(head.into_iter().chain(body)) {
            *dst = src;
        }
        out
    }
    #[inline]
    fn from_words(words: [u64; HALF_CUT_WORDS]) -> Self {
        let mut it = words.into_iter();
        let pub_id = it.next().unwrap_or(0);
        let (wild, center) = split(it.next().unwrap_or(0));
        let mut it = it.skip(5);
        let entries = core::array::from_fn(|_| {
            let seq = it.next().unwrap_or(0);
            let (snap_ver, f_lo) = split(it.next().unwrap_or(0));
            CutEntry {
                seq: LaneSeq(seq),
                snap_ver: u32_at(snap_ver),
                f_lo: u32_at(f_lo),
            }
        });
        Self {
            pub_id,
            wild: u32_at(wild),
            occ_center: Tick(u32_at(center)),
            entries,
        }
    }
}

/// A half-cut was not pointwise ≥ the half's previous publication (`INV-CUT-MONO`, 01 §14.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutNotMonotone {
    /// Index of the first lane in the half that went back.
    pub lane_ix: usize,
}

/// The cut core's private publication state for one half (05 §7.1).
#[derive(Clone, Debug)]
pub struct CutWriter {
    next: u64,
    last: [LaneSeq; LANES_PER_HALF],
}

impl Default for CutWriter {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl CutWriter {
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: 1,
            last: [LaneSeq(0); LANES_PER_HALF],
        }
    }

    /// Publishes `val` as the half's next publication and returns its id, or rejects it
    /// without publishing if any entry went back (`INV-CUT-MONO`; the caller fail-stops, §14.3).
    #[inline]
    pub fn publish<V: super::Visibility>(
        &mut self,
        half: &HalfCut<V>,
        vis: &V,
        val: &HalfCutVal,
    ) -> Result<u64, CutNotMonotone> {
        let back = self
            .last
            .iter()
            .zip(&val.entries)
            .position(|(prev, e)| e.seq < *prev);
        if let Some(lane_ix) = back {
            return Err(CutNotMonotone { lane_ix });
        }
        let id = self.next;
        half.publish(vis, id, val);
        for (prev, e) in self.last.iter_mut().zip(&val.entries) {
            *prev = e.seq;
        }
        self.next = id.wrapping_add(1);
        Ok(id)
    }
}

/// `BboFloor` (05 §4.13). Writer: the BBO core. Readers: both cut cores. Every step the BBO
/// core starts from now on uses half-cuts with ids ≥ `(done_a, done_b)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Floor {
    pub done_a: u64,
    pub done_b: u64,
}

impl Words<2> for Floor {
    #[inline]
    fn to_words(&self) -> [u64; 2] {
        [self.done_a, self.done_b]
    }
    #[inline]
    fn from_words([done_a, done_b]: [u64; 2]) -> Self {
        Self { done_a, done_b }
    }
}

/// `LaneCut[l]` (05 §4.15). Writer: the stream core of `l`'s half, after step `step` is framed.
/// Reader: lane `l`. `snap` is the BBO snapshot of step `step` (`done_step = step`). At its
/// boundary at `step` the lane takes `snap.version` as the base of its packets' `snap_lag`, and
/// `snap` itself if newer than its own (05 §6.5), so replay rebuilds both from `(f, C_f[l])`
/// alone (07 §7.1). The 16-B single-copy-atomic
/// form of 05 needs SIMD stores that safe Rust cannot express, so this is the spec's fallback: a
/// per-entry seqlock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaneCutEntry {
    pub step: StepId,
    pub cut: LaneSeq,
    pub snap: Snapshot,
}

impl Words<6> for LaneCutEntry {
    #[inline]
    fn to_words(&self) -> [u64; 6] {
        let [s0, s1, s2, s3] = self.snap.to_words();
        [self.step.0, self.cut.0, s0, s1, s2, s3]
    }
    #[inline]
    fn from_words([step, cut, s0, s1, s2, s3]: [u64; 6]) -> Self {
        Self {
            step: StepId(step),
            cut: LaneSeq(cut),
            snap: Snapshot::from_words([s0, s1, s2, s3]),
        }
    }
}

pub type CounterLine<V> = Published<Counter, 7, V>;
pub type SnapshotLine<V> = Published<Snapshot, 4, V>;
/// `CutPub[h]`: one per half; written by cut core A (core 1) or B (core 6), read by the BBO.
pub type HalfCut<V> = PubRing<HalfCutVal, HALF_CUT_WORDS, V>;
pub type BboFloor<V> = Published<Floor, 2, V>;
pub type LaneCut<V> = Published<LaneCutEntry, 6, V>;

#[cfg(not(loom))]
const _: () = {
    use super::{Hw, SHARED_ALIGN};
    assert!(size_of::<CounterLine<Hw>>() == SHARED_ALIGN);
    assert!(size_of::<SnapshotLine<Hw>>() == SHARED_ALIGN);
    assert!(size_of::<LaneCut<Hw>>() == SHARED_ALIGN);
    // Line 0 plus lines 1–7 of 05 §4.13 (8 × 64 B), in four 128-B pairs.
    assert!(size_of::<Published<HalfCutVal, HALF_CUT_WORDS, Hw>>() == 4 * SHARED_ALIGN);
};
