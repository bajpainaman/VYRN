//! Pool primitives (01 §14.15; 05 §6.9; 10 §1.2). These are read-modify-writes on one word, so
//! they are not delayed by `Visibility`: an RMW always acts on the newest value.

use vyrn_types::LaneId;

use super::line::{join, split, u32_at};
use super::sync::{AtomicU32, AtomicU64, Ordering};

/// `PoolTok`: the token of one pooled account.
///
/// Writers: any pool core, by CAS. Readers: pool cores. Word = `holder: u8 | 3 B zero | ver: u32`
/// (05 §6.9 `AcctTok`). `holder = 0xFF` is free. A take moves `holder: free → c` and `ver → ver
/// + 1` in one CAS (`Acquire` on success: the taker sees every write of the previous holder);
/// `release` stores `free` with the same `ver` (`Release`). While core `c` holds the token it is
/// the only writer of the account's records (`INV-WRITER`). The `ver` a take returns is the
/// `AcctTake.ver` to log (01 §14.17.4): gapless from 1 after `new`.
#[derive(Debug)]
#[repr(C, align(16))]
pub struct PoolTok {
    word: AtomicU64,
}

/// `holder` of a free token.
pub const FREE: u8 = 0xFF;

/// Why `try_take` did not take the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeError {
    /// Another core holds it.
    Held(LaneId),
    /// Another core took it, and may have released it, between the load and the CAS.
    Raced,
    /// `ver` would wrap (2^32 takes in one epoch).
    VerExhausted,
    /// `0xFF` is not a lane.
    BadLane,
}

/// `release` by a core that does not hold the token: a bug (`INV-WRITER`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotHolder;

fn tok(holder: u8, ver: u32) -> u64 {
    join([holder, 0, 0, 0], ver.to_le_bytes())
}

fn untok(w: u64) -> (u8, u32) {
    let ([holder, _, _, _], ver) = split(w);
    (holder, u32_at(ver))
}

impl Default for PoolTok {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl PoolTok {
    /// Free, `ver` 0 (the start of an epoch).
    #[inline]
    pub fn new() -> Self {
        Self {
            word: AtomicU64::new(tok(FREE, 0)),
        }
    }

    /// One attempt, never a spin (the poll rule, 11 §3.1). On success returns the new `ver`.
    #[inline]
    pub fn try_take(&self, lane: LaneId) -> Result<u32, TakeError> {
        if lane.0 == FREE {
            return Err(TakeError::BadLane);
        }
        // ORDERING: only the CAS's expected value; the CAS below is the synchronizing access.
        let cur = self.word.load(Ordering::Relaxed);
        let (holder, ver) = untok(cur);
        if holder != FREE {
            return Err(TakeError::Held(LaneId(holder)));
        }
        let next = ver.checked_add(1).ok_or(TakeError::VerExhausted)?;
        self.word
            .compare_exchange(cur, tok(lane.0, next), Ordering::Acquire, Ordering::Relaxed)
            .map(|_| next)
            .map_err(|now| match untok(now).0 {
                FREE => TakeError::Raced,
                h => TakeError::Held(LaneId(h)),
            })
    }

    /// Holder only. Returns the `ver` of the take it ends.
    #[inline]
    pub fn release(&self, lane: LaneId) -> Result<u32, NotHolder> {
        // ORDERING: while `lane` holds the token no other core changes the word, so this reads
        // `lane`'s own CAS.
        let (holder, ver) = untok(self.word.load(Ordering::Relaxed));
        if holder != lane.0 || holder == FREE {
            return Err(NotHolder);
        }
        self.word.store(tok(FREE, ver), Ordering::Release);
        Ok(ver)
    }

    /// The holder (`None` = free) and `ver`, for audits and tests.
    #[inline]
    pub fn peek(&self) -> (Option<LaneId>, u32) {
        let (h, ver) = untok(self.word.load(Ordering::Acquire));
        ((h != FREE).then_some(LaneId(h)), ver)
    }
}

/// The consumer lock of one pool core's RX queue (05 §6.9 `RxQueue[c]`).
///
/// Writers: every core that dequeues from the queue, its owner included; each holds the lock for
/// the dequeue. `0` is free, `c + 1` is held by core `c`. `try_lock` is one CAS (`Acquire`), the
/// guard's drop a `Release` store of 0. Its own `SHARED_ALIGN` line.
#[derive(Debug, Default)]
#[repr(C, align(128))]
pub struct StealLock {
    word: AtomicU32,
}

/// Holds a `StealLock` until dropped.
#[derive(Debug)]
pub struct StealGuard<'a> {
    lock: &'a StealLock,
}

impl StealLock {
    #[inline]
    pub fn new() -> Self {
        Self {
            word: AtomicU32::new(0),
        }
    }

    /// One attempt, never a spin.
    #[inline]
    pub fn try_lock(&self, core: LaneId) -> Option<StealGuard<'_>> {
        let me = u32::from(core.0).saturating_add(1);
        self.word
            .compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| StealGuard { lock: self })
    }

    /// The core holding it, if any.
    #[inline]
    pub fn holder(&self) -> Option<LaneId> {
        let w = self.word.load(Ordering::Relaxed);
        let c = w.checked_sub(1)?;
        u8::try_from(c).ok().map(LaneId)
    }
}

impl Drop for StealGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.lock.word.store(0, Ordering::Release);
    }
}

/// A `Segment16.mask` word (05 §4.6): bits 0–15 active, 16–31 pend.
///
/// Writers: the segment's lane, and in a pool any pool core holding the order's account token
/// (05 §6.9). Pool segments change only by `fetch_or`/`fetch_and` (`Release`), so concurrent
/// changes of different bits never overwrite each other; a dedicated lane, the sole writer, may
/// `store`. Readers: the BBO core's sweep and the lane, with `load` (`Acquire`): a reader that
/// sees a bit set sees the slot and position writes made before it was set.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct SegMask(AtomicU32);

impl SegMask {
    #[inline]
    pub fn new(v: u32) -> Self {
        Self(AtomicU32::new(v))
    }

    /// The bit of position `pos` (0–15) in the active half; `None` past 15.
    #[inline]
    pub fn active_bit(pos: u8) -> Option<u32> {
        (pos < 16)
            .then(|| 1u32.checked_shl(u32::from(pos)))
            .flatten()
    }

    /// The bit of position `pos` in the pend half.
    #[inline]
    pub fn pend_bit(pos: u8) -> Option<u32> {
        Self::active_bit(pos).and_then(|b| b.checked_shl(16))
    }

    #[inline]
    pub fn load(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    /// Sole writer (dedicated lane) only.
    #[inline]
    pub fn store(&self, v: u32) {
        self.0.store(v, Ordering::Release);
    }

    /// Sets `bits`; returns the previous mask.
    #[inline]
    pub fn fetch_or(&self, bits: u32) -> u32 {
        self.0.fetch_or(bits, Ordering::Release)
    }

    /// Clears `bits` (a sibling-segment cancel clears one active bit); returns the previous mask.
    #[inline]
    pub fn fetch_and_not(&self, bits: u32) -> u32 {
        self.0.fetch_and(!bits, Ordering::Release)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn token_take_release_and_gapless_ver() {
        let t = PoolTok::new();
        assert_eq!(t.try_take(LaneId(42)), Ok(1));
        assert_eq!(t.try_take(LaneId(43)), Err(TakeError::Held(LaneId(42))));
        assert_eq!(t.release(LaneId(43)), Err(NotHolder));
        assert_eq!(t.release(LaneId(42)), Ok(1));
        assert_eq!(t.release(LaneId(42)), Err(NotHolder), "released twice");
        assert_eq!(t.try_take(LaneId(43)), Ok(2));
        assert_eq!(t.peek(), (Some(LaneId(43)), 2));
        assert_eq!(t.try_take(LaneId(FREE)), Err(TakeError::BadLane));
    }

    #[test]
    fn token_word_layout_is_05_acct_tok() {
        // holder at byte 0, ver at bytes 4–7.
        assert_eq!(
            tok(0x2A, 0x0102_0304).to_le_bytes(),
            [0x2A, 0, 0, 0, 4, 3, 2, 1]
        );
    }

    #[test]
    fn ver_exhaustion_is_an_error_not_a_wrap() {
        let t = PoolTok {
            word: AtomicU64::new(tok(FREE, u32::MAX)),
        };
        assert_eq!(t.try_take(LaneId(1)), Err(TakeError::VerExhausted));
    }

    #[test]
    fn steal_lock_guard_releases_on_drop() {
        let l = StealLock::new();
        let g = l.try_lock(LaneId(44));
        assert!(g.is_some());
        assert_eq!(l.holder(), Some(LaneId(44)));
        assert!(l.try_lock(LaneId(45)).is_none());
        drop(g);
        assert_eq!(l.holder(), None);
        assert!(l.try_lock(LaneId(45)).is_some());
    }

    #[test]
    fn seg_mask_bits() {
        assert_eq!(SegMask::active_bit(15), Some(1 << 15));
        assert_eq!(SegMask::pend_bit(0), Some(1 << 16));
        assert_eq!(SegMask::active_bit(16), None);
        let m = SegMask::new(0b11);
        assert_eq!(m.fetch_and_not(0b01), 0b11);
        assert_eq!(m.fetch_or(1 << 16), 0b10);
        assert_eq!(m.load(), 0b10 | 1 << 16);
    }
}
