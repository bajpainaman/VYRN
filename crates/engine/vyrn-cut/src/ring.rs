//! `vyrn-cut::ring` (UNSAFE.toml): bounded rings with one producer and `C` consumers over
//! `MaybeUninit` slots (spec/11-build.md §3.2; 05 §4.12, §4.15, §14.2).
//!
//! `C = 1` is the SPSC ring (FwdRing, FillRing, OsRing, TxRing). `C > 1` is a broadcast ring:
//! every consumer reads every entry (StepLog: stream and fill TX cores).
//!
//! **Lines.** `tail` (writer: producer) counts entries pushed; `heads[i]` (writer: consumer `i`,
//! the spec's `FwdCons`/`FillCons`) counts entries consumer `i` has read. Both are one-word
//! `Visibility` lines: `Release` publish, `Acquire` read on `Hw`. Each sits on its own
//! `SHARED_ALIGN` line. Indices are u64 and never wrap.
//!
//! **Ownership.** Slot `k mod N` holds entry `k`. The producer owns it from the moment every
//! consumer's published head is > `k − N` (so all have finished reading entry `k − N`) until it
//! publishes `tail > k`. From then until consumer `i` publishes `head_i > k`, consumer `i` may
//! read it, and nobody writes it. The producer reads `heads` only when its cached bound says
//! full; a consumer reads `tail` only when its cached bound says empty.
//!
//! **Full** is back-pressure, never a drop (05 §14.2): `push` returns the value.
//! **Handles.** `split` hands out the one `Producer` and the `C` `Consumer`s once per ring.

use core::mem::MaybeUninit;

use super::Visibility;
use super::sync::UnsafeCell;

#[repr(C, align(128))]
struct IndexLine<V: Visibility>(V::Line<1>);

struct Slot<T>(UnsafeCell<MaybeUninit<T>>);

/// A ring of `N` entries (`N` a power of two) with `C ≥ 1` consumers.
pub struct Ring<T: Copy, const N: usize, const C: usize, V: Visibility> {
    tail: IndexLine<V>,
    heads: [IndexLine<V>; C],
    slots: Box<[Slot<T>]>,
    split: bool,
}

// SAFETY: slots are reached only through the handles of `split`, which follow §ownership: a
// slot is written by the single `Producer` only while no consumer may read it, and read only
// after the producer's `tail` publication that follows the write. The sealed `Visibility` makes
// those publications `Release`/`Acquire` on `Hw`. `V::Line<1>: Sync` excludes `Sim`, whose lines
// are single-threaded. `T: Send` because entries move between threads.
unsafe impl<T: Copy + Send, const N: usize, const C: usize, V: Visibility> Sync for Ring<T, N, C, V> where
    V::Line<1>: Sync
{
}

impl<T: Copy, const N: usize, const C: usize, V: Visibility> Ring<T, N, C, V> {
    #[allow(clippy::as_conversions)] // usize is 64-bit (vyrn-types asserts it): lossless.
    const CAP: u64 = {
        assert!(N.is_power_of_two(), "ring capacity must be a power of two");
        assert!(C >= 1, "a ring needs a consumer");
        N as u64
    };

    /// Allocates the slots: call before `seal()` (`INV-NOALLOC`).
    pub fn new(vis: &V) -> Self {
        let slots = (0..Self::CAP)
            .map(|_| Slot(UnsafeCell::new(MaybeUninit::uninit())))
            .collect();
        Self {
            tail: IndexLine(vis.line([0])),
            heads: core::array::from_fn(|_| IndexLine(vis.line([0]))),
            slots,
            split: false,
        }
    }

    /// The producer and the consumers; `None` after the first call.
    #[allow(clippy::type_complexity)]
    pub fn split(&mut self) -> Option<(Producer<'_, T, N, C, V>, [Consumer<'_, T, N, C, V>; C])> {
        if self.split {
            return None;
        }
        self.split = true;
        let ring: &Self = self;
        let producer = Producer {
            ring,
            tail: 0,
            free_to: Self::CAP,
        };
        let consumers = core::array::from_fn(|id| Consumer {
            ring,
            id,
            head: 0,
            avail_to: 0,
        });
        Some((producer, consumers))
    }

    #[inline(always)]
    fn slot(&self, index: u64) -> Option<&Slot<T>> {
        let i = usize::try_from(index & Self::CAP.wrapping_sub(1)).ok()?;
        self.slots.get(i)
    }
}

/// The ring's only writer of slots and of `tail`.
pub struct Producer<'a, T: Copy, const N: usize, const C: usize, V: Visibility> {
    ring: &'a Ring<T, N, C, V>,
    tail: u64,
    /// Entries `< free_to` are free to write: min published head + `N`, as last read.
    free_to: u64,
}

impl<T: Copy, const N: usize, const C: usize, V: Visibility> Producer<'_, T, N, C, V> {
    /// Pushes one entry, or returns it if the ring is full.
    #[inline]
    pub fn push(&mut self, vis: &V, value: T) -> Result<(), T> {
        if self.push_all(vis, core::slice::from_ref(&value)) {
            Ok(())
        } else {
            Err(value)
        }
    }

    /// Pushes all of `values` with one `tail` publication, so a consumer sees all or none (an
    /// entry and its dependency or delta lines, 05 §4.12, §4.15). `false` and nothing pushed if
    /// they do not fit now.
    pub fn push_all(&mut self, vis: &V, values: &[T]) -> bool {
        let Some(end) = u64::try_from(values.len())
            .ok()
            .and_then(|n| self.tail.checked_add(n))
        else {
            return false;
        };
        if end > self.free_to {
            let heads = self.ring.heads.iter().filter_map(|h| vis.try_read(&h.0));
            let min = heads.map(|[h]| h).min().unwrap_or(0);
            self.free_to = min.saturating_add(Ring::<T, N, C, V>::CAP);
            if end > self.free_to {
                return false;
            }
        }
        for (k, value) in (self.tail..end).zip(values) {
            let Some(slot) = self.ring.slot(k) else {
                return false;
            };
            slot.0.with_mut(|p| {
                // SAFETY: k < free_to = (min published head) + N, so every consumer has
                // finished entry k − N, and k ≥ tail is unpublished, so no consumer reads slot
                // k mod N (§ownership). This handle is the only producer (`split` runs once).
                unsafe { p.write(MaybeUninit::new(*value)) }
            });
        }
        self.tail = end;
        vis.publish(&self.ring.tail.0, [end]);
        true
    }

    /// Entries pushed so far.
    pub fn pushed(&self) -> u64 {
        self.tail
    }
}

/// Consumer `id`: the only writer of `heads[id]`.
pub struct Consumer<'a, T: Copy, const N: usize, const C: usize, V: Visibility> {
    ring: &'a Ring<T, N, C, V>,
    id: usize,
    head: u64,
    /// Entries `< avail_to` are published: the producer's `tail`, as last read.
    avail_to: u64,
}

impl<T: Copy, const N: usize, const C: usize, V: Visibility> Consumer<'_, T, N, C, V> {
    /// The next entry, or `None` if none is visible.
    #[inline]
    pub fn pop(&mut self, vis: &V) -> Option<T> {
        if self.head >= self.avail_to {
            let [tail] = vis.try_read(&self.ring.tail.0)?;
            self.avail_to = tail;
            if self.head >= tail {
                return None;
            }
        }
        let slot = self.ring.slot(self.head)?;
        let value = slot.0.with(|p| {
            // SAFETY: head < avail_to, a `tail` this consumer read (`Acquire`) after the
            // producer wrote the slot, and the producer does not rewrite slot head mod N until
            // this consumer publishes a head > head (§ownership). `T: Copy`: nothing moves.
            unsafe { p.read().assume_init() }
        });
        self.head = self.head.wrapping_add(1);
        if let Some(line) = self.ring.heads.get(self.id) {
            vis.publish(&line.0, [self.head]);
        }
        Some(value)
    }

    /// Entries read so far.
    pub fn popped(&self) -> u64 {
        self.head
    }
}
