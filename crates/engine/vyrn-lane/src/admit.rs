//! `vyrn-lane::admit`: deadline admission at the lane (05 §6.8, 01 §14.1, 04 §3.5). The only
//! module of this crate that reads a clock (11 §3.1; `tools/lint-engine` enforces it).
//!
//! A packet is late at point `at` when `now − rx_ts + rest > LAT_MAX_NS − DEADLINE_GUARD_NS`,
//! with `rest = path_ns[n][class]`, minus `prepass_ns` at the commit point. A late packet is
//! answered `Reject BUSY` per message, takes no `LaneSeq`, does not advance `pkt_seq`, and is
//! logged as a `PacketRecord` with `SHED` (05 §3.1). Replay reads `SHED` and never calls
//! [`Clock::now`].

pub use vyrn_bbo::admit::{Clock, FixedClock, NeverLate};

use vyrn_types::{LAT_MAX_NS, Nanos};

/// `DEADLINE_GUARD_NS` (01 §14.17.1: 20 ns; 05 §6.8 still says 30, see the PR's follow-ups).
pub const DEADLINE_GUARD_NS: u64 = 20;

/// The class of a packet at dequeue (05 §6.8): `Local` has no `New` or `Replace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Local,
    Order,
}

/// Where the test runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    Dequeue,
    Commit,
}

/// `predicted_path_ns` (05 §6.8, 10 `BookSpec`): worst path for `n` = 1..=10 messages, without
/// NIC RX, per class; and the pre-pass share removed at the commit point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathTable {
    pub local: [u64; 10],
    pub order: [u64; 10],
    pub prepass_ns: u64,
}

impl PathTable {
    /// The 05 §6.8 table: `Local = 505 + 14n`, `Order = max(510 + 5n, 505 + 14n)`, pre-pass 45.
    pub fn spec() -> Self {
        let f = |n: u64, a: u64, b: u64| a.saturating_add(b.saturating_mul(n));
        let n = |i: usize| u64::try_from(i).unwrap_or(0).saturating_add(1);
        Self {
            local: core::array::from_fn(|i| f(n(i), 505, 14)),
            order: core::array::from_fn(|i| f(n(i), 510, 5).max(f(n(i), 505, 14))),
            prepass_ns: 45,
        }
    }

    fn rest(&self, n: u8, cls: Class, at: Point) -> u64 {
        let i = usize::from(n.clamp(1, 10)).saturating_sub(1);
        let t = match cls {
            Class::Local => self.local.get(i),
            Class::Order => self.order.get(i),
        };
        let pre = if at == Point::Commit {
            self.prepass_ns
        } else {
            0
        };
        t.copied().unwrap_or(u64::MAX).saturating_sub(pre)
    }
}

/// The age test, pure: `age + rest > LAT_MAX_NS − DEADLINE_GUARD_NS`. A clock behind `rx_ts`
/// counts as age 0.
pub fn late_at(now: u64, rx_ts: Nanos, n: u8, cls: Class, at: Point, t: &PathTable) -> bool {
    let age = now.saturating_sub(rx_ts.0);
    age.saturating_add(t.rest(n, cls, at)) > LAT_MAX_NS.saturating_sub(DEADLINE_GUARD_NS)
}

/// The test the lane runs at dequeue and at the commit point.
#[inline(always)]
pub fn late<C: Clock>(
    clock: &C,
    rx_ts: Nanos,
    n: u8,
    cls: Class,
    at: Point,
    t: &PathTable,
) -> bool {
    late_at(clock.now(), rx_ts, n, cls, at, t)
}
