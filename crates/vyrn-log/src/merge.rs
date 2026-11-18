//! Merging the two substreams' step half-records into whole `StepRecord`s (07 §3.8).
//!
//! Step `s` is complete when its home record and, if that record has OTHER set, the other
//! substream's cut-only record of `s` are decoded. A half with no record at `s` keeps its
//! previous half-cut. Steps are emitted gapless in StepId order, so the full cut of every
//! earlier step is known when `s` is emitted. These are faults (`RepErr::Step` unless noted):
//! a step that no substream can still deliver; a cut-only record whose home record did not set
//! OTHER, or that the home record's substream skipped; a cut-only record whose kind differs
//! from its home record's (`RepErr::Kind`).

use std::collections::VecDeque;

use vyrn_types::{LaneId, LaneSeq, StepId, StepRecord};

use crate::stream::StepHalf;
use crate::{Layout, RepErr};

/// One whole step for replay: the record of 01 §6.6 and its kind payload (07 §3.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedStep<const N: usize> {
    pub rec: StepRecord<N>,
    pub payload: Vec<u8>,
}

/// Joins substream A's and B's [`StepHalf`]s. `N` is the box's lane count.
#[derive(Clone, Debug)]
pub struct StepMerger<const N: usize> {
    layout: Layout,
    next_step: u64,
    cut: [LaneSeq; N],
    queues: [VecDeque<StepHalf>; 2],
}

impl<const N: usize> StepMerger<N> {
    /// Starts at `first_step` with the full cut both `TenureStart`s set.
    pub fn new(layout: Layout, first_step: StepId, cut: [LaneSeq; N]) -> Result<Self, RepErr> {
        if usize::from(layout.n_lanes()) != N {
            return Err(RepErr::Layout);
        }
        Ok(Self {
            layout,
            next_step: first_step.0,
            cut,
            queues: [VecDeque::new(), VecDeque::new()],
        })
    }

    /// The next step [`pop`](Self::pop) will emit.
    pub const fn next_step(&self) -> StepId {
        StepId(self.next_step)
    }

    /// Queues a half-record decoded from substream `stream`.
    pub fn push(&mut self, stream: u8, half: StepHalf) -> Result<(), RepErr> {
        if stream >= self.layout.streams() || half.cut.len() != self.layout.half(stream).len() {
            return Err(RepErr::Layout);
        }
        let q = self
            .queues
            .get_mut(usize::from(stream))
            .ok_or(RepErr::Layout)?;
        if half.step.0 < self.next_step || q.back().is_some_and(|b| b.step >= half.step) {
            return Err(RepErr::Step);
        }
        q.push_back(half);
        Ok(())
    }

    /// The next complete step, `Ok(None)` while a record it needs has not arrived.
    pub fn pop(&mut self) -> Result<Option<MergedStep<N>>, RepErr> {
        let s = self.next_step;
        let head = |q: &VecDeque<StepHalf>| q.front().map(|h| (h.step.0, h.home.is_some()));
        let [qa, qb] = &self.queues;
        let heads = [head(qa), head(qb)];
        let home_on = (0..2).find(|&i| heads.get(i).copied().flatten() == Some((s, true)));
        let Some(h) = home_on else {
            // No home record of s at any head. Each queue only grows with later steps, so once
            // every substream has a record queued, none of them can still deliver s.
            let live = heads.iter().flatten().count();
            if live == usize::from(self.layout.streams()) {
                return Err(RepErr::Step);
            }
            return Ok(None);
        };
        let o = 1usize.saturating_sub(h);
        let other = self
            .queues
            .get(h)
            .and_then(|q| q.front())
            .is_some_and(|x| x.other);
        let o_head = heads.get(o).copied().flatten();
        if other {
            match o_head {
                None => return Ok(None),
                Some((st, false)) if st == s => {}
                Some(_) => return Err(RepErr::Step),
            }
        } else if o_head.is_some_and(|(st, _)| st == s) {
            return Err(RepErr::Step);
        }
        let home_rec = self.queues.get_mut(h).and_then(VecDeque::pop_front);
        let other_rec = if other {
            self.queues.get_mut(o).and_then(VecDeque::pop_front)
        } else {
            None
        };
        let Some(home_rec) = home_rec else {
            return Err(RepErr::Step);
        };
        if other_rec.as_ref().is_some_and(|c| c.kind != home_rec.kind) {
            return Err(RepErr::Kind);
        }
        let mut lowver = 0u64;
        for (stream, rec) in [(h, Some(&home_rec)), (o, other_rec.as_ref())] {
            let Some(rec) = rec else { continue };
            let half = self.layout.half(u8::try_from(stream).unwrap_or(0));
            let start = half.start;
            lowver |= rec.lowver.checked_shl(u32::from(start)).unwrap_or(0);
            for (lane, c) in half.zip(&rec.cut) {
                if let Some(slot) = self.cut.get_mut(usize::from(lane)) {
                    *slot = *c;
                }
            }
        }
        let home = home_rec.home.unwrap_or_else(|| crate::stream::Home {
            src_lane: LaneId(0xFF),
            src_lane_seq: LaneSeq(0),
            flags: 0,
            payload: Vec::new(),
        });
        self.next_step = s.checked_add(1).ok_or(RepErr::Range)?;
        Ok(Some(MergedStep {
            rec: StepRecord {
                step: StepId(s),
                kind: home_rec.kind,
                src_lane: home.src_lane,
                src_lane_seq: home.src_lane_seq,
                flags: home.flags,
                cut: self.cut,
                lowver,
            },
            payload: home.payload,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::stream::Home;
    use vyrn_types::StepKind;

    fn half(step: u64, home: bool, other: bool, cut: [u64; 2]) -> StepHalf {
        StepHalf {
            lowver: 0,
            step: StepId(step),
            kind: StepKind::Idle,
            other,
            home: home.then(|| Home {
                src_lane: LaneId(0xFF),
                src_lane_seq: LaneSeq(0),
                flags: 0,
                payload: Vec::new(),
            }),
            cut: cut.map(LaneSeq).to_vec(),
        }
    }

    fn merger() -> StepMerger<4> {
        StepMerger::new(Layout::new(4, 2, 0).unwrap(), StepId(1), [LaneSeq(0); 4]).unwrap()
    }

    #[test]
    fn waits_for_the_cut_only_record_then_merges() {
        let mut m = merger();
        m.push(0, half(1, true, true, [1, 0])).unwrap();
        assert_eq!(m.pop(), Ok(None));
        m.push(1, half(1, false, true, [0, 3])).unwrap();
        let s = m.pop().unwrap().unwrap();
        assert_eq!(s.rec.cut, [1, 0, 0, 3].map(LaneSeq));
        // Step 2 only on A: B keeps its half-cut.
        m.push(0, half(2, true, false, [2, 0])).unwrap();
        assert_eq!(m.pop().unwrap().unwrap().rec.cut, [2, 0, 0, 3].map(LaneSeq));
    }

    #[test]
    fn faults() {
        // A skipped step: both substreams are past step 1.
        let mut m = merger();
        m.push(0, half(2, true, false, [1, 0])).unwrap();
        m.push(1, half(3, false, true, [0, 1])).unwrap();
        assert_eq!(m.pop(), Err(RepErr::Step));
        // OTHER set but B's next record is a later step.
        let mut m = merger();
        m.push(0, half(1, true, true, [1, 0])).unwrap();
        m.push(1, half(2, false, true, [0, 1])).unwrap();
        assert_eq!(m.pop(), Err(RepErr::Step));
        // A cut-only record of a step whose home record did not set OTHER.
        let mut m = merger();
        m.push(0, half(1, true, false, [1, 0])).unwrap();
        m.push(1, half(1, false, true, [0, 1])).unwrap();
        assert_eq!(m.pop(), Err(RepErr::Step));
        // Kinds differ.
        let mut m = merger();
        m.push(0, half(1, true, true, [1, 0])).unwrap();
        let mut c = half(1, false, true, [0, 1]);
        c.kind = StepKind::Depletion;
        m.push(1, c).unwrap();
        assert_eq!(m.pop(), Err(RepErr::Kind));
        // Non-increasing pushes.
        let mut m = merger();
        m.push(0, half(2, true, false, [1, 0])).unwrap();
        assert_eq!(m.push(0, half(2, true, false, [1, 0])), Err(RepErr::Step));
    }
}
