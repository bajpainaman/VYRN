//! The rate bucket of spec/04-protocol.md §9.1: a GCRA (a token bucket written as one timestamp,
//! ITU-T I.371), on `rx_ts` time, integer only. 10 §3.8 defers its bucket arithmetic to 04, so
//! every bucket of this crate, session, account, lane or pool, is this one type.

use vyrn_types::Nanos;

use crate::consts::NS_PER_S;

/// One GCRA bucket. `tat` is the theoretical arrival time; `t_ns` is the time one token takes to
/// refill (`10^9 / rate`); `burst` is the number of tokens a full bucket holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gcra {
    pub tat: Nanos,
    pub t_ns: u64,
    pub burst: u64,
}

impl Gcra {
    pub const fn new(t_ns: u64, burst: u64) -> Self {
        Self {
            tat: Nanos(0),
            t_ns,
            burst,
        }
    }

    /// A bucket of `rate` tokens per second. `t_ns = ceil(10^9 / rate)`, so the integer bucket
    /// never admits more than `rate` per second (04 §9.1 leaves the rounding open). `None` for a
    /// zero rate.
    pub const fn from_rate(rate: u64, burst: u64) -> Option<Self> {
        if rate == 0 {
            return None;
        }
        Some(Self::new(NS_PER_S.div_ceil(rate), burst))
    }

    /// The `tat` after taking `cost` tokens at `now` while leaving at least `keep`, or `None` when
    /// the bucket cannot pay (04 §9.1 `take`). Pure: the caller commits it, so several buckets can
    /// be tested before any is charged ("both or neither", 10 §3.1 decision 3).
    ///
    /// Overflow of `tat` is a defined refusal (01 §11 rule 4). The allowance
    /// `now + (burst − keep) × t_ns` saturates, which only widens it at the end of time.
    #[inline]
    pub fn next_tat(&self, now: Nanos, cost: u64, keep: u64) -> Option<Nanos> {
        let base = if self.tat.0 > now.0 {
            self.tat.0
        } else {
            now.0
        };
        let next = base.checked_add(cost.checked_mul(self.t_ns)?)?;
        let allowance = self.burst.saturating_sub(keep).saturating_mul(self.t_ns);
        if next > now.0.saturating_add(allowance) {
            return None;
        }
        Some(Nanos(next))
    }

    /// Takes `cost` tokens unless fewer than `keep` would be left. Returns whether it took them.
    #[inline]
    pub fn take(&mut self, now: Nanos, cost: u64, keep: u64) -> bool {
        match self.next_tat(now, cost, keep) {
            Some(t) => {
                self.tat = t;
                true
            }
            None => false,
        }
    }

    /// Returns `cost` tokens at `now`, capped at the burst: `tat` never falls below `now`
    /// (10 §3.11, a `Shed` refund).
    #[inline]
    pub fn refund(&mut self, now: Nanos, cost: u64) {
        let back = self.tat.0.saturating_sub(cost.saturating_mul(self.t_ns));
        self.tat = Nanos(if back > now.0 { back } else { now.0 });
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn from_rate_rounds_the_period_up() {
        // 10^9 / 220_000 = 4545.45…: ceil keeps the lane at or below REQ_LANE_CROSS_RATE.
        assert_eq!(Gcra::from_rate(220_000, 1).map(|g| g.t_ns), Some(4_546));
        assert_eq!(Gcra::from_rate(1_000_000, 1).map(|g| g.t_ns), Some(1_000));
        assert_eq!(Gcra::from_rate(0, 1), None);
    }

    #[test]
    fn a_fresh_bucket_pays_exactly_its_burst_then_refills_one_per_period() {
        let mut g = Gcra::new(100, 4);
        let now = Nanos(1_000);
        for _ in 0..4 {
            assert!(g.take(now, 1, 0));
        }
        assert!(!g.take(now, 1, 0));
        assert!(!g.take(Nanos(1_099), 1, 0));
        assert!(g.take(Nanos(1_100), 1, 0));
    }

    #[test]
    fn keep_reserves_tokens_and_a_refusal_changes_nothing() {
        let mut g = Gcra::new(10, 8);
        // keep = 2: six tokens are available, the seventh is refused.
        for _ in 0..6 {
            assert!(g.take(Nanos(0), 1, 2));
        }
        let before = g;
        assert!(!g.take(Nanos(0), 1, 2));
        assert_eq!(g, before);
        // keep = 0 still reaches the reserve.
        assert!(g.take(Nanos(0), 2, 0));
        assert!(!g.take(Nanos(0), 1, 0));
    }

    #[test]
    fn refund_is_capped_at_the_burst() {
        let mut g = Gcra::new(10, 2);
        assert!(g.take(Nanos(50), 2, 0));
        g.refund(Nanos(50), 5);
        assert_eq!(g.tat, Nanos(50));
        assert!(g.take(Nanos(50), 2, 0));
        assert!(!g.take(Nanos(50), 1, 0));
    }

    #[test]
    fn overflow_is_a_refusal() {
        let mut g = Gcra::new(u64::MAX, u64::MAX);
        assert!(!g.take(Nanos(1), 2, 0));
        assert_eq!(g.tat, Nanos(0));
    }
}
