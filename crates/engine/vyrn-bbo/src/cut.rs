//! The step cut (05 §3.3, §8.3).
//!
//! ```text
//! C_s[l]   = max(C_{s−1}[l], min(K[l], h[l] − 1))                      l ≠ src
//! C_s[src] = max(C_{s−1}[src], min(max(K[src], a), h'[src] − 1, q))
//! ```
//!
//! `K` is the newest cut (lanes 0–24 from half A, 25–48 from half B), `h[l]` the dependency floor
//! of lane `l`'s oldest unexecuted FwdRing entry (∞ when none), `a = q − applied_back`, and `h'`
//! the floor of the source lane's next entry. F1 (monotone) holds by the outer `max`; F2 (explicit
//! ops stay out of earlier cuts) by the `h − 1` clamp; F3 (only published ops) by `min(K, …)`.

use vyrn_cut::{CutEntry, HalfCutVal, LANES_PER_HALF};
use vyrn_types::LaneSeq;

use crate::MAX_LANES;

/// One cut: `C[l]` for every lane; lanes ≥ `N_LANES` stay 0.
pub type Cut = [LaneSeq; MAX_LANES];

/// The two newest half-cut publications a step uses, with their ids.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HalfPair {
    pub a: (u64, HalfCutVal),
    pub b: (u64, HalfCutVal),
}

impl HalfPair {
    /// Lane `l`'s entry: half A for `l < 25`, half B for the rest.
    pub fn entry(&self, l: usize) -> CutEntry {
        let (half, i) = if l < LANES_PER_HALF {
            (&self.a.1, l)
        } else {
            (&self.b.1, l.saturating_sub(LANES_PER_HALF))
        };
        half.entries.get(i).copied().unwrap_or_default()
    }
    /// `K`: every lane's published seq.
    pub fn k(&self) -> Cut {
        core::array::from_fn(|l| self.entry(l).seq)
    }
    /// Lanes their cut core does not trust (05 §7.3), as a lane bitmask.
    pub fn wild(&self) -> u64 {
        u64::from(self.a.1.wild) & ((1u64 << LANES_PER_HALF) - 1)
            | (u64::from(self.b.1.wild) & ((1u64 << LANES_PER_HALF) - 1)) << LANES_PER_HALF
    }
}

/// The source rule's inputs (05 §3.3): lane, `q`, `a`, and `h'` (`None` = ∞).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrcRule {
    pub lane: usize,
    pub q: LaneSeq,
    pub a: LaneSeq,
    pub next_floor: Option<LaneSeq>,
}

#[inline(always)]
fn below(floor: Option<LaneSeq>) -> u64 {
    floor.map_or(u64::MAX, |h| h.0.saturating_sub(1))
}

/// The step cut of 05 §3.3. `floor[l]` is `h[l]` (`None` = ∞). Pure: the same inputs give the
/// same cut on every implementation.
pub fn step_cut(
    prev: &Cut,
    k: &Cut,
    floor: &[Option<LaneSeq>; MAX_LANES],
    src: Option<SrcRule>,
) -> Cut {
    let mut c: Cut = core::array::from_fn(|l| {
        let p = prev.get(l).copied().unwrap_or_default();
        let kl = k.get(l).copied().unwrap_or_default();
        let h = below(floor.get(l).copied().flatten());
        LaneSeq(p.0.max(kl.0.min(h)))
    });
    if let Some(s) = src
        && let (Some(cl), Some(p), Some(kl)) = (c.get_mut(s.lane), prev.get(s.lane), k.get(s.lane))
    {
        let top = kl.0.max(s.a.0).min(below(s.next_floor)).min(s.q.0);
        *cl = LaneSeq(p.0.max(top));
    }
    c
}
