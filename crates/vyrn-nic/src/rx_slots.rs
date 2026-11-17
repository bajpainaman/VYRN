//! The receive buffers of one queue, shared by `sim` and `kernel_udp`, and the one place that
//! implements `RxRing::bytes`'s validation.
//!
//! Slots are filled and released in the same order, so the unreleased frames are always the
//! `held` sequence numbers before `produced`. A frame's `buf_id` is its sequence number (mod
//! 2^32) and its slot is `buf_id & mask`. So `bytes` checks liveness with two subtractions and
//! needs no per-slot state, and a stale copy whose slot has been reused fails the window check
//! instead of reading the new frame.

use core::ptr::NonNull;

use vyrn_types::Nanos;
use vyrn_wire::{NicCounters, RxFlags, RxPkt};

use crate::ExtCounters;

/// Bytes per receive buffer: a `MAX_FRAME_BYTES` frame, rounded up.
pub(crate) const SLOT_BYTES: usize = 2048;
const _: () = assert!(SLOT_BYTES >= crate::frame::MAX_FRAME_BYTES);

pub(crate) struct RxSlots {
    buf: Box<[u8]>,
    lens: Box<[u16]>,
    mask: u32,
    /// Sequence number of the next frame (wrapping).
    produced: u32,
    /// Frames polled and not yet released.
    held: u32,
    last_ts: Nanos,
}

impl RxSlots {
    /// `n` is a power of two up to 65536, checked by `NicConfig::check`.
    pub(crate) fn new(n: usize) -> Self {
        debug_assert!(n.is_power_of_two() && n <= 65536);
        Self {
            buf: vec![0; n * SLOT_BYTES].into_boxed_slice(),
            lens: vec![0; n].into_boxed_slice(),
            mask: (n - 1) as u32,
            produced: 0,
            held: 0,
            last_ts: Nanos(0),
        }
    }

    pub(crate) fn free(&self) -> usize {
        (self.mask + 1 - self.held) as usize
    }

    fn slot(&self, seq: u32) -> usize {
        (seq & self.mask) as usize
    }

    /// The buffer the next frame goes into. Only call it when `free() > 0`.
    pub(crate) fn next_buf(&mut self) -> &mut [u8; SLOT_BYTES] {
        let at = self.slot(self.produced) * SLOT_BYTES;
        let s = &mut self.buf[at..at + SLOT_BYTES];
        s.try_into().unwrap_or_else(|_| unreachable!())
    }

    /// The buffers of the next `k` frames, in order, wrapping at the end of the ring. Only call
    /// it with `k <= free()`. `kernel_udp` receives a burst into them with one syscall.
    #[cfg(target_os = "linux")]
    pub(crate) fn next_bufs(&mut self, k: usize) -> impl Iterator<Item = &mut [u8; SLOT_BYTES]> {
        debug_assert!(k <= self.free());
        let (wrapped, ahead) = self.buf.split_at_mut(self.slot(self.produced) * SLOT_BYTES);
        // Both halves are whole slots: the buffer is `n * SLOT_BYTES`, split at a slot edge.
        let (ahead, rest_a) = ahead.as_chunks_mut::<SLOT_BYTES>();
        let (wrapped, rest_w) = wrapped.as_chunks_mut::<SLOT_BYTES>();
        debug_assert!(rest_a.is_empty() && rest_w.is_empty());
        ahead.iter_mut().chain(wrapped).take(k)
    }

    /// Copies the first `len` bytes of the buffer `ahead` frames past the next one into the
    /// next one's, so the frames after a dropped datagram of a burst fill the ring in order.
    #[cfg(target_os = "linux")]
    pub(crate) fn pull(&mut self, ahead: usize, len: usize) {
        debug_assert!(ahead < self.free() && len <= SLOT_BYTES);
        let to = self.slot(self.produced) * SLOT_BYTES;
        let from = self.slot(self.produced.wrapping_add(ahead as u32)) * SLOT_BYTES;
        self.buf.copy_within(from..from + len, to);
    }

    /// Publishes the frame just written to `next_buf` and returns its descriptor. Clamps a
    /// regressing stamp to the previous one and counts it (06 §6.1 rule 1), and counts `rx_pkts`.
    pub(crate) fn commit(
        &mut self,
        len: u16,
        flags: RxFlags,
        ts: Nanos,
        c: &NicCounters,
        ext: &ExtCounters,
    ) -> RxPkt {
        debug_assert!(self.free() > 0 && usize::from(len) <= SLOT_BYTES);
        let ts = if ts < self.last_ts {
            NicCounters::add(&ext.rx_ts_regress, 1);
            self.last_ts
        } else {
            ts
        };
        self.last_ts = ts;
        let seq = self.produced;
        let slot = self.slot(seq);
        self.lens[slot] = len;
        self.produced = seq.wrapping_add(1);
        self.held += 1;
        NicCounters::add(&c.rx_pkts, 1);
        RxPkt::new(self.slot_ptr(slot), len, flags, seq, ts)
    }

    fn slot_ptr(&self, slot: usize) -> NonNull<u8> {
        NonNull::from(&self.buf[slot * SLOT_BYTES])
    }

    pub(crate) fn release(&mut self, n: usize) {
        self.held -= u32::try_from(n).unwrap_or(u32::MAX).min(self.held);
    }

    /// `RxRing::bytes`. The frame is returned only if this queue produced `p` and has not
    /// released it: `buf_id` is in the unreleased window, `data` is that slot's address (compared,
    /// never dereferenced) and `len` is the length the backend wrote. Anything else gets `&[]`.
    pub(crate) fn bytes(&self, p: &RxPkt) -> &[u8] {
        let back = self.produced.wrapping_sub(p.buf_id());
        if back == 0 || back > self.held {
            return &[];
        }
        let slot = self.slot(p.buf_id());
        let len = self.lens[slot];
        if p.len() != len || p.data() != self.slot_ptr(slot) {
            return &[];
        }
        let at = slot * SLOT_BYTES;
        &self.buf[at..at + usize::from(len)]
    }
}
