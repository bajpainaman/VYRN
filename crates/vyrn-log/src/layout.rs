//! Which lanes each substream carries (07 §2.2, §3.4, §3.5).
//!
//! With two substreams, stream 0 (A) carries lanes `0 .. N_HALF` and stream 1 (B) carries lanes
//! `N_HALF .. N_LANES`, where `N_HALF = (N_LANES + 1) / 2`. With one substream (CONSUMER, AWS),
//! stream 0 carries every lane. The pooled lanes (01 §14.15) share one session-slot table, so
//! they must all sit in one half.

use core::ops::Range;

use crate::RepErr;

/// The lane split of one box. Both ends of a stream must use the same layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    n_lanes: u8,
    streams: u8,
    pool: u64,
}

impl Layout {
    /// `n_lanes` in 1..=64 (the 6-bit lane tag), `streams` 1 or 2, `pool` a bitmask of lanes.
    pub fn new(n_lanes: u8, streams: u8, pool: u64) -> Result<Self, RepErr> {
        let ok_lanes = (1..=64).contains(&n_lanes) && (streams == 1 || n_lanes >= 2);
        let all = u64::MAX
            .checked_shr(64u32.saturating_sub(u32::from(n_lanes)))
            .unwrap_or(0);
        if !ok_lanes || !(1..=2).contains(&streams) || pool & !all != 0 {
            return Err(RepErr::Layout);
        }
        let l = Self {
            n_lanes,
            streams,
            pool,
        };
        if streams == 2 {
            let in_a = (0..l.n_half()).any(|x| l.is_pool(x));
            let in_b = (l.n_half()..n_lanes).any(|x| l.is_pool(x));
            if in_a && in_b {
                return Err(RepErr::Layout);
            }
        }
        Ok(l)
    }

    /// REF: 49 lanes on two substreams; lanes 42–48 are the pool (01 §14.15).
    pub fn reference() -> Self {
        Self {
            n_lanes: 49,
            streams: 2,
            pool: 0x7f << 42,
        }
    }

    pub const fn n_lanes(&self) -> u8 {
        self.n_lanes
    }

    pub const fn streams(&self) -> u8 {
        self.streams
    }

    /// `N_HALF = (N_LANES + 1) / 2`.
    pub const fn n_half(&self) -> u8 {
        self.n_lanes.div_ceil(2)
    }

    /// The lanes substream `stream` carries.
    pub fn half(&self, stream: u8) -> Range<u8> {
        match (self.streams, stream) {
            (1, _) => 0..self.n_lanes,
            (_, 0) => 0..self.n_half(),
            _ => self.n_half()..self.n_lanes,
        }
    }

    /// The substream that carries `lane`.
    pub fn stream_of(&self, lane: u8) -> u8 {
        u8::from(self.streams == 2 && lane >= self.n_half())
    }

    pub fn is_pool(&self, lane: u8) -> bool {
        lane < 64 && self.pool & (1u64 << lane) != 0
    }
}
