//! Newtypes of 01 §3, constants of 01 §5, codes of 01 §6.5 and §14.10, and the record structs of
//! 01 §6.6. No dependencies. No logic beyond checked arithmetic on `Qty`, `Tick` and notional
//! (01 §11.4).
#![forbid(unsafe_code)]
#![no_std]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

mod codes;
mod dense;
mod records;

pub use codes::{HomeCode, Mode, RejectReason, StepKind};
pub use dense::{Dense, DenseId};
pub use records::{
    AcctTake, BlockHeader, Ed25519Sig, HandoffRecord, PacketFlags, PacketRecord, PubKey, StepRecord,
};

// Every target is 64-bit (01 §10: x86-64 and aarch64), so u64 → usize never truncates.
const _: () = assert!(usize::BITS == 64);

macro_rules! newtype {
    ($(#[$doc:meta])* $name:ident($repr:ty)) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
        #[repr(transparent)]
        pub struct $name(pub $repr);
    };
}

newtype!(
    /// Absolute price index in the book's tick ladder. Tick 0 is "no bid" (05 §13.1).
    Tick(u32)
);
newtype!(
    /// Quantity in lots.
    Qty(u32)
);
newtype!(
    /// One account. It belongs to exactly one lane per epoch.
    AccountId(u32)
);
newtype!(
    /// One client session. It belongs to one account.
    SessionId(u32)
);
newtype!(
    /// 0 … `N_LANES − 1`.
    LaneId(u8)
);
newtype!(
    /// Per-lane sequence of applied ops. Starts at 1 each epoch.
    LaneSeq(u64)
);
newtype!(
    /// Per-book sequence of BBO-core steps. Starts at 1 each epoch.
    StepId(u64)
);
newtype!(
    /// A lane-local order handle: bits 0–23 the slot, bits 24–31 the generation.
    Handle(u32)
);
newtype!(
    /// Epoch number. The wire carries its low 16 bits.
    Epoch(u32)
);
newtype!(
    /// Block height. Never resets.
    Height(u64)
);
newtype!(
    /// Nanoseconds of PTP time (TAI).
    Nanos(u64)
);
newtype!(
    /// Instrument.
    BookId(u16)
);
newtype!(
    /// The first 8 bytes of BLAKE3-256 of a packet's bytes 0..end-of-messages, little-endian.
    PktHash(u64)
);
newtype!(
    /// SipHash-2-4 MAC output.
    Tag(u64)
);

/// BLAKE3-256.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
#[repr(transparent)]
pub struct Hash(pub [u8; 32]);

impl Epoch {
    /// The low 16 bits that the wire carries (`epoch16`, 01 §6.1).
    #[inline(always)]
    pub const fn low16(self) -> u16 {
        let [b0, b1, _, _] = self.0.to_le_bytes();
        u16::from_le_bytes([b0, b1])
    }
}

impl Handle {
    /// Slots per lane: 2^`SLOT_BITS`.
    pub const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;

    /// A handle from a slot and a generation, or `None` if the slot does not fit in 24 bits.
    #[inline(always)]
    pub const fn new(slot: u32, generation: u8) -> Option<Self> {
        if slot > Self::SLOT_MASK {
            return None;
        }
        let [b0, b1, b2, _] = slot.to_le_bytes();
        Some(Self(u32::from_le_bytes([b0, b1, b2, generation])))
    }

    #[inline(always)]
    pub const fn slot(self) -> u32 {
        self.0 & Self::SLOT_MASK
    }

    #[inline(always)]
    pub const fn generation(self) -> u8 {
        let [_, _, _, g] = self.0.to_le_bytes();
        g
    }
}

impl Qty {
    #[inline(always)]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(q) => Some(Self(q)),
            None => None,
        }
    }

    #[inline(always)]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(q) => Some(Self(q)),
            None => None,
        }
    }

    /// Notional in quote atomic units: `qty × tick × quote_per_tick_lot` (05 §13.1). Computed in
    /// u128 and `None` unless it fits in u64, which 05 rejects as `BAD_QTY`.
    #[inline(always)]
    pub fn notional(self, tick: Tick, quote_per_tick_lot: u64) -> Option<u64> {
        let n = u128::from(self.0)
            .checked_mul(u128::from(tick.0))?
            .checked_mul(u128::from(quote_per_tick_lot))?;
        u64::try_from(n).ok()
    }
}

impl Tick {
    /// `self + ticks`, `None` on overflow.
    #[inline(always)]
    pub const fn checked_add(self, ticks: u32) -> Option<Self> {
        match self.0.checked_add(ticks) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }

    /// `self − ticks`, `None` below zero.
    #[inline(always)]
    pub const fn checked_sub(self, ticks: u32) -> Option<Self> {
        match self.0.checked_sub(ticks) {
            Some(t) => Some(Self(t)),
            None => None,
        }
    }
}

// Constants of 01 §5. Every value is a budget unless 01 says otherwise.

/// Lanes on the reference box: 42 dedicated + 7 pooled (01 §14.15).
pub const N_LANES_REF: usize = 49;
/// Lanes on the consumer box.
pub const N_LANES_CONSUMER: usize = 11;
/// Every client message and every response record.
pub const MSG_BYTES: usize = 16;
/// Request and response packet header.
pub const PKT_HDR_BYTES: usize = 16;
/// Messages in one request packet, at most.
pub const MAX_MSGS_PER_PKT: u8 = 10;
/// One MAC tag; every request packet carries two.
pub const TAG_BYTES: usize = 8;
/// 16 + 10 × 16 + 2 × 8.
pub const MAX_REQ_PAYLOAD: usize = 192;
/// Hard maximum, first bit in to first bit of the response out (REQ-LAT-1).
pub const LAT_MAX_NS: u64 = 1_000;
/// Maximum NIC echo (RX + TX) for a NIC to qualify.
pub const NIC_FLOOR_NS: u64 = 560;
/// Average lane work per message, all costs amortized.
pub const LANE_NS_PER_MSG: u64 = 30;
/// BBO-core work per step, maximum.
pub const BBO_CROSS_NS: u64 = 15;
/// BBO-core work per improve or depletion.
pub const BBO_IMPROVE_NS: u64 = 8;
/// Crosses per second per book at `BBO_MAX_LOAD` (0.60).
pub const CROSS_CAP: u64 = 10_000_000;
/// Maximum age of the newest published cut.
pub const CUT_REFRESH_NS: u64 = 100;
/// Block length.
pub const BLOCK_NS: u64 = 1_000_000;
/// REQ-FIN-1 hard maximum.
pub const FINALITY_MAX_MS: u64 = 10;
/// Epoch length.
pub const EPOCH_HOURS: u64 = 8;
/// Replica-set size and quorum in base mode.
pub const N_BASE: usize = 4;
pub const Q_BASE: usize = 3;
/// Validator-set size and quorum in chain mode.
pub const N_CHAIN: usize = 5;
pub const Q_CHAIN: usize = 4;
/// Byzantine faults tolerated.
pub const F: usize = 1;
/// Sequencer silence that starts a failover.
pub const FAILOVER_SILENCE_MS: u64 = 2;
/// Published sequencer-failover outage.
pub const FAILOVER_TARGET_MS: u64 = 20;
/// `Handle` layout: 16M slots per lane, 256 generations.
pub const SLOT_BITS: u32 = 24;
pub const GEN_BITS: u32 = 8;
/// Response packets per session kept by the recovery service.
pub const RESP_RETAIN_PKTS: usize = 65_536;
/// Sessions one lane serves.
pub const MAX_SESSIONS_PER_LANE: usize = 4_096;
/// Levels per side in a lane's dense level array.
pub const TICK_HOT_WINDOW: usize = 4_096;
/// Independent switch paths for order frames.
pub const REPL_PATHS: usize = 2;
/// Alignment of hot shared structures on this target (01 §5): 128 on Apple M-series, else 64.
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
pub const CACHE_LINE: usize = 128;
#[cfg(not(all(target_vendor = "apple", target_arch = "aarch64")))]
pub const CACHE_LINE: usize = 64;

const _: () = assert!(MAX_REQ_PAYLOAD == PKT_HDR_BYTES + 160 + 2 * TAG_BYTES);
const _: () = assert!(SLOT_BITS + GEN_BITS == 32);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn handle_splits_slot_and_generation() {
        let h = Handle::new(0x00AB_CDEF, 0x7F).unwrap();
        assert_eq!(h.0, 0x7FAB_CDEF);
        assert_eq!(h.slot(), 0x00AB_CDEF);
        assert_eq!(h.generation(), 0x7F);
        assert_eq!(Handle::new(Handle::SLOT_MASK, 0).unwrap().slot(), 0xFF_FFFF);
        assert!(Handle::new(1 << 24, 0).is_none());
    }

    #[test]
    fn epoch_low16_is_the_wire_field() {
        // 04 §11 scenario: epoch 1000 → epoch16 0x03e8; and a value above 16 bits.
        assert_eq!(Epoch(1000).low16(), 0x03e8);
        assert_eq!(Epoch(0x0001_03e8).low16(), 0x03e8);
    }

    #[test]
    fn qty_and_tick_arithmetic_is_checked() {
        assert_eq!(Qty(u32::MAX).checked_add(Qty(1)), None);
        assert_eq!(Qty(3).checked_sub(Qty(4)), None);
        assert_eq!(Qty(7).checked_sub(Qty(4)), Some(Qty(3)));
        assert_eq!(Tick(0).checked_sub(1), None);
        assert_eq!(Tick(u32::MAX).checked_add(1), None);
    }

    #[test]
    fn notional_rejects_what_does_not_fit_in_u64() {
        assert_eq!(Qty(8).notional(Tick(100_001), 3), Some(2_400_024));
        // u32::MAX² fits in u64; one more factor of 2 does not.
        let max = u64::from(u32::MAX);
        assert_eq!(Qty(u32::MAX).notional(Tick(u32::MAX), 1), Some(max * max));
        assert_eq!(Qty(u32::MAX).notional(Tick(u32::MAX), 2), None);
        // The intermediate product overflows u64 but the result is still checked in u128.
        assert_eq!(Qty(u32::MAX).notional(Tick(u32::MAX), u64::MAX), None);
    }
}
