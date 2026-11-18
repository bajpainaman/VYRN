//! Order flags (01 §6.2) and the priority key (05 §3.2).
//!
//! The merge order of every level FIFO, of the source choice (§8.4) and of a `Rescan` batch
//! (§3.4) is `PrioKey` order: `(ts, rank_e(lane), seq)`, compared lexicographically. `rank` is a
//! per-epoch rotation of the lane id, so no lane wins every timestamp tie for a whole epoch
//! (§12). Within one lane key order is `LaneSeq` order (§3.2, Lemma 9.1).

use vyrn_types::{Epoch, LaneId, LaneSeq, Nanos};

/// Order side: bit 0 of the wire flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    #[inline(always)]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
    /// 0 bid, 1 ask: the encoding of `OccEvent` and `Segment16.side`.
    #[inline(always)]
    pub const fn code(self) -> u8 {
        match self {
            Self::Buy => 0,
            Self::Sell => 1,
        }
    }
    #[inline(always)]
    pub const fn from_code(c: u8) -> Self {
        if c & 1 == 0 { Self::Buy } else { Self::Sell }
    }
}

/// Time in force: bits 1–2 of the wire flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tif {
    Day,
    Ioc,
    Fok,
    AuctionOnly,
}

/// Self-trade prevention: bits 4–5 of the wire flags. The taker's mode governs (05 §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stp {
    None,
    CancelNewest,
    CancelOldest,
    CancelBoth,
}

/// The wire flags byte of an order (01 §6.2), as carried in `OrderSlot.flags`, `FwdDep.flags`
/// and byte 1 of a `New` or `Replace` message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OrderFlags(pub u8);

impl OrderFlags {
    #[inline(always)]
    pub const fn new(side: Side, tif: Tif, post_only: bool, stp: Stp) -> Self {
        let t = match tif {
            Tif::Day => 0,
            Tif::Ioc => 1,
            Tif::Fok => 2,
            Tif::AuctionOnly => 3,
        };
        let s = match stp {
            Stp::None => 0,
            Stp::CancelNewest => 1,
            Stp::CancelOldest => 2,
            Stp::CancelBoth => 3,
        };
        let p = if post_only { 1 } else { 0 };
        Self(side.code() | (t << 1) | (p << 3) | (s << 4))
    }
    #[inline(always)]
    pub const fn side(self) -> Side {
        Side::from_code(self.0)
    }
    #[inline(always)]
    pub const fn tif(self) -> Tif {
        match (self.0 >> 1) & 3 {
            0 => Tif::Day,
            1 => Tif::Ioc,
            2 => Tif::Fok,
            _ => Tif::AuctionOnly,
        }
    }
    #[inline(always)]
    pub const fn post_only(self) -> bool {
        self.0 & 8 != 0
    }
    #[inline(always)]
    pub const fn stp(self) -> Stp {
        match (self.0 >> 4) & 3 {
            0 => Stp::None,
            1 => Stp::CancelNewest,
            2 => Stp::CancelOldest,
            _ => Stp::CancelBoth,
        }
    }
}

/// `PrioKey` (05 §3.2). Field order is comparison order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrioKey {
    pub ts: Nanos,
    pub rank: u8,
    pub seq: LaneSeq,
}

impl PrioKey {
    pub const MIN: Self = Self {
        ts: Nanos(0),
        rank: 0,
        seq: LaneSeq(0),
    };
    pub const MAX: Self = Self {
        ts: Nanos(u64::MAX),
        rank: u8::MAX,
        seq: LaneSeq(u64::MAX),
    };
}

/// `rank_e(l) = (l + e) mod n_lanes` (05 §3.2), computed in u64 so no epoch overflows it.
/// `n_lanes` is the box's lane count (`N_LANES`); 0 is treated as 1.
#[inline(always)]
pub fn rank_e(epoch: Epoch, lane: LaneId, n_lanes: u8) -> u8 {
    let n = u64::from(n_lanes.max(1));
    let r = u64::from(lane.0)
        .wrapping_add(u64::from(epoch.0))
        .checked_rem(n)
        .unwrap_or(0);
    u8::try_from(r).unwrap_or(0)
}
