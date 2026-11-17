//! `vyrn-bbo::admit`: the BBO core's deadline test (05 §6.8, 01 §14.1). The only module of this
//! crate that reads a clock (11 §3.1; `tools/lint-engine` enforces it).
//!
//! `FwdEntry.deadline` is the latest PTP time, low 32 bits, at which the op's step may start. If
//! the clock is past it when the op would start, the op and its dependencies become a `Shed`
//! step: `Reject BUSY` for each, nothing applied. The decision is logged as the step's kind, so
//! replay reads it and never calls [`Clock::now`] (05 §10, Lemma 9.15). A continuation is never
//! shed: it already traded (05 §8.5).

/// PTP time in ns, as the platform maps TSC to PHC (06). Live engines pass the platform clock;
/// replay and tests pass [`NeverLate`] or a fixed value.
pub trait Clock {
    fn now(&self) -> u64;
}

/// A clock for replay: every op is on time.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverLate;

impl Clock for NeverLate {
    fn now(&self) -> u64 {
        0
    }
}

/// A fixed instant (tests, `vyrn-sim`).
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// `now_lo32 − deadline` read as a signed 32-bit value is `> 0` (05 §8.2): later than the
/// deadline by 1 to 2^31 − 1 ns. Equal is on time. Wrapping makes the test valid across the
/// 4.29 s wrap of the low 32 bits.
#[inline(always)]
pub fn is_late(now_lo32: u32, deadline: u32) -> bool {
    let d = now_lo32.wrapping_sub(deadline);
    d != 0 && d < 0x8000_0000
}

/// The test the main loop runs on a source at step start.
#[inline(always)]
pub fn late<C: Clock>(clock: &C, deadline: u32) -> bool {
    let now = clock.now().to_le_bytes();
    is_late(
        u32::from_le_bytes([now[0], now[1], now[2], now[3]]),
        deadline,
    )
}
