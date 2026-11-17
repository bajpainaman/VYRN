//! The per-queue contract every NIC backend implements (06 §6.1). The engine sees only these
//! traits, so it never depends on a NIC (11 §1.4).
//!
//! Contract rules, checked by the `sim` backend's tests:
//! 1. `poll` returns one queue's frames in arrival order, with `rx_ts` non-decreasing.
//! 2. Hot-path errors are counters, never `Err`. `evq_overflow` and `fatal_hw` are fatal: the
//!    lane checks `counters().fatal()` once per poll and fail-stops.
//! 3. `send` sends the whole frame or returns `TxFull`, never part of one.
//! 4. Queues are opened before `seal()`, each by its owner thread.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use vyrn_types::Nanos;

/// `PLT_RX_BURST`: the most frames one `poll` returns.
pub const RX_BURST: usize = 16;

/// `VYNS_RX_*` flags of one received frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct RxFlags(pub u16);

impl RxFlags {
    /// `rx_ts` is a NIC hardware timestamp.
    pub const TS: Self = Self(0x0001);
    /// The NIC clock reported "in sync".
    pub const TS_SYNC: Self = Self(0x0002);
    pub const BAD_CSUM: Self = Self(0x0004);
    pub const TRUNC: Self = Self(0x0008);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One received frame. Same layout as `vyns_rx` in shim.h, so the shim fills it directly. The
/// bytes are reached through `RxRing::bytes`, which owns the buffer.
///
/// The fields are read-only, so safe code cannot lengthen or redirect a descriptor it was given.
/// Safe code can still build one with `new`; that is why `RxRing::bytes` validates descriptors
/// against the ring's own storage instead of trusting `data` and `len`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RxPkt {
    data: NonNull<u8>,
    len: u16,
    flags: RxFlags,
    buf_id: u32,
    rx_ts: Nanos,
}
const _: () = assert!(size_of::<RxPkt>() == 24 && core::mem::offset_of!(RxPkt, rx_ts) == 16);

impl RxPkt {
    /// For backends: `data` is the first byte of the Ethernet frame in a buffer the ring owns.
    pub const fn new(
        data: NonNull<u8>,
        len: u16,
        flags: RxFlags,
        buf_id: u32,
        rx_ts: Nanos,
    ) -> Self {
        Self {
            data,
            len,
            flags,
            buf_id,
            rx_ts,
        }
    }

    /// An entry for `poll`'s output array before it is written. Never dereferenced.
    pub const fn empty() -> Self {
        Self {
            data: NonNull::dangling(),
            len: 0,
            flags: RxFlags(0),
            buf_id: 0,
            rx_ts: Nanos(0),
        }
    }

    /// The pointer the backend stored. Only the backend that produced this descriptor may
    /// dereference it, after checking `buf_id` and `len` against its own buffers.
    pub const fn data(&self) -> NonNull<u8> {
        self.data
    }

    /// Frame length without FCS.
    pub const fn len(&self) -> u16 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn flags(&self) -> RxFlags {
        self.flags
    }

    pub const fn buf_id(&self) -> u32 {
        self.buf_id
    }

    /// TAI ns; the source is `RxRing::ts_source()`.
    pub const fn rx_ts(&self) -> Nanos {
        self.rx_ts
    }
}

/// Where `rx_ts` comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TsSource {
    NicPhc,
    TscAtPoll,
    Kernel,
    Virtual,
}

/// `send` found no free descriptor; the caller reaps and retries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxFull;

/// One queue's counters. Same layout as `vyns_counters` in shim.h. A single thread writes them
/// (the one that polls or sends on the queue) with a relaxed load and store, never a locked
/// read-modify-write; any thread may read them.
#[derive(Debug, Default)]
#[repr(C)]
pub struct NicCounters {
    pub rx_pkts: AtomicU64,
    pub rx_discard: AtomicU64,
    pub rx_no_ts: AtomicU64,
    pub rx_trunc: AtomicU64,
    pub tx_pkts: AtomicU64,
    pub tx_ctpio: AtomicU64,
    pub tx_fallback: AtomicU64,
    pub tx_full: AtomicU64,
    /// Nonzero: events were lost, so frames may have been lost silently. Fatal.
    pub evq_overflow: AtomicU64,
    /// Nonzero: the device reported an error. Fatal.
    pub fatal_hw: AtomicU64,
}
const _: () = assert!(size_of::<NicCounters>() == 80);

impl NicCounters {
    pub const fn new() -> Self {
        Self {
            rx_pkts: AtomicU64::new(0),
            rx_discard: AtomicU64::new(0),
            rx_no_ts: AtomicU64::new(0),
            rx_trunc: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0),
            tx_ctpio: AtomicU64::new(0),
            tx_fallback: AtomicU64::new(0),
            tx_full: AtomicU64::new(0),
            evq_overflow: AtomicU64::new(0),
            fatal_hw: AtomicU64::new(0),
        }
    }

    /// Adds `n` to a counter. Only the queue's owner thread calls it.
    #[inline(always)]
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.store(
            counter.load(Ordering::Relaxed).wrapping_add(n),
            Ordering::Relaxed,
        );
    }

    /// True once either fatal counter is nonzero (rule 2).
    #[inline(always)]
    pub fn fatal(&self) -> bool {
        self.evq_overflow.load(Ordering::Relaxed) | self.fatal_hw.load(Ordering::Relaxed) != 0
    }
}

/// One receive queue, as a lane or the cut core sees it.
pub trait RxRing: Send {
    /// Never blocks. Writes up to `RX_BURST` frames and returns how many. No allocation, no lock,
    /// no syscall (the `kernel` backend excepted).
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize;
    /// Gives back the oldest `n` frames not yet released, in poll order.
    fn release(&mut self, n: usize);
    /// A frame's bytes. The borrow ends before the next `release`.
    ///
    /// `p` is untrusted: safe code can build any `RxPkt`. The backend resolves it against storage
    /// it owns (by `buf_id`) and bounds-checks `len` against that buffer, and returns an empty
    /// slice for a descriptor it did not produce or has already released. It never dereferences
    /// `p.data()` without that check, so this method is sound for every input.
    fn bytes<'a>(&'a self, p: &'a RxPkt) -> &'a [u8];
    fn ts_source(&self) -> TsSource;
    fn counters(&self) -> &NicCounters;
}

/// One transmit queue, as a TX core sees it.
pub trait TxRing: Send {
    /// Sends one complete frame, whose headers `vyrn-wire` built. The bytes are copied or written
    /// to the NIC before it returns.
    fn send(&mut self, frame: &[u8]) -> Result<(), TxFull>;
    /// Processes TX completions and returns how many. Called every `PLT_TX_REAP_EVERY` sends.
    fn reap(&mut self) -> usize;
    fn counters(&self) -> &NicCounters;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_is_either_fatal_counter() {
        let c = NicCounters::new();
        NicCounters::add(&c.rx_discard, 5);
        NicCounters::add(&c.tx_full, 1);
        assert!(!c.fatal(), "ordinary drops are not fatal");
        NicCounters::add(&c.evq_overflow, 1);
        assert!(c.fatal());
        let c = NicCounters::new();
        NicCounters::add(&c.fatal_hw, 1);
        assert!(c.fatal());
    }

    #[test]
    fn rx_flags() {
        let f = RxFlags::TS.union(RxFlags::TRUNC);
        assert!(
            f.contains(RxFlags::TS) && f.contains(RxFlags::TRUNC) && !f.contains(RxFlags::TS_SYNC)
        );
    }
}
