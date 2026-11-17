//! The `Visibility` backends (spec/11-build.md §1.3, §6.4).
//!
//! A *line* is a value of `W` u64 words with **one writer** and any number of readers. The writer
//! calls `publish`; a reader calls `try_read` and gets a whole publication or `None`, never a mix
//! of two publications.
//!
//! - **`Hw`** is the production backend. A line is a seqlock (05 §4.10): `lock` odd while the
//!   writer stores, data words as `Relaxed` atomics between a `Release` fence and a `Release`
//!   store of the even `lock`; the reader pairs them with an `Acquire` load and an `Acquire`
//!   fence (Boehm, "Can seqlocks get along with programming language memory models?", 2012).
//!   A one-word line skips the lock: one `Release` store, one `Acquire` load.
//! - **`Sim`** is `vyrn-sim`'s backend (§6.4, SF-13). Each publication becomes visible a seeded
//!   number of virtual nanoseconds (≤ `max_delay_ns`, `BLD_SIM_VIS_MAX_NS`) after it is made,
//!   and publications become visible **in the order they were made, across all lines of one
//!   `Sim`**. So readers see stale cuts, snapshots and ring tails, but never a later store
//!   without an earlier one: the staleness is what hardware can show, and no causality break is
//!   invented. Deadlines are non-decreasing in publication order, so the visible publications
//!   are always those with a deadline ≤ `max(now, floor)`: a prefix of the global order. When a
//!   line has `SIM_PENDING` publications in flight, `floor` rises to that line's oldest deadline,
//!   which shortens the delay of every publication up to it on every line, and so keeps the
//!   prefix (no value is dropped or reordered). `Sim` lines are `!Sync`: the simulator runs every
//!   core on one thread.
//!
//! The trait is sealed. The ring's `unsafe` relies on `publish`/`try_read` ordering the slot
//! writes before the reads (ring.rs), so no other implementation may exist.

use core::cell::Cell;

use super::sync::{AtomicU64, Ordering, fence};

mod sealed {
    pub trait Sealed {}
}

/// A store-visibility backend: how a single-writer line's publications reach its readers.
pub trait Visibility: sealed::Sealed {
    /// One line of `W` words.
    type Line<const W: usize>;
    /// A line whose first visible value is `init`.
    fn line<const W: usize>(&self, init: [u64; W]) -> Self::Line<W>;
    /// Writer only. Makes `words` the line's next publication.
    fn publish<const W: usize>(&self, line: &Self::Line<W>, words: [u64; W]);
    /// Readers. One whole publication (the newest visible one), or `None` if the writer was
    /// storing (`Hw` only; the caller retries on a later poll).
    fn try_read<const W: usize>(&self, line: &Self::Line<W>) -> Option<[u64; W]>;
}

/// Hardware atomics.
#[derive(Clone, Copy, Debug, Default)]
pub struct Hw;

/// A seqlocked line: `lock` at offset 0, the words from offset 8 (05 §4.10, §4.14).
#[derive(Debug)]
#[repr(C)]
pub struct HwLine<const W: usize> {
    lock: AtomicU64,
    words: [AtomicU64; W],
}

impl sealed::Sealed for Hw {}

impl Visibility for Hw {
    type Line<const W: usize> = HwLine<W>;

    fn line<const W: usize>(&self, init: [u64; W]) -> HwLine<W> {
        HwLine {
            lock: AtomicU64::new(0),
            words: init.map(AtomicU64::new),
        }
    }

    #[inline(always)]
    fn publish<const W: usize>(&self, line: &HwLine<W>, words: [u64; W]) {
        if W == 1 {
            for (a, v) in line.words.iter().zip(words) {
                a.store(v, Ordering::Release);
            }
            return;
        }
        // ORDERING: the writer is the only core that stores `lock`, so it reads its own value.
        let s = line.lock.load(Ordering::Relaxed);
        line.lock.store(s.wrapping_add(1), Ordering::Relaxed);
        // The odd `lock` is ordered before every data store (pairs with the reader's fence).
        fence(Ordering::Release);
        for (a, v) in line.words.iter().zip(words) {
            // ORDERING: covered by the fence above and the `Release` store below.
            a.store(v, Ordering::Relaxed);
        }
        line.lock.store(s.wrapping_add(2), Ordering::Release);
    }

    #[inline(always)]
    fn try_read<const W: usize>(&self, line: &HwLine<W>) -> Option<[u64; W]> {
        if W == 1 {
            return Some(line.words.each_ref().map(|a| a.load(Ordering::Acquire)));
        }
        let s1 = line.lock.load(Ordering::Acquire);
        if s1 & 1 == 1 {
            return None;
        }
        // ORDERING: a torn read is caught by the `lock` recheck after the `Acquire` fence.
        let out = line.words.each_ref().map(|a| a.load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        (line.lock.load(Ordering::Relaxed) == s1).then_some(out)
    }
}

/// Publications in flight per `Sim` line.
pub const SIM_PENDING: usize = 8;

/// The simulator's backend: one per simulated box, driven by `vyrn-sim`'s virtual clock.
#[derive(Debug)]
pub struct Sim {
    now: Cell<u64>,
    /// Publications with a deadline ≤ `floor` are visible even before `now` reaches it.
    floor: Cell<u64>,
    last_vis: Cell<u64>,
    rng: Cell<u64>,
    max_delay_ns: u64,
}

#[derive(Clone, Copy, Debug)]
struct SimState<const W: usize> {
    visible: [u64; W],
    /// `(visible_at, words)`, oldest first; `visible_at` is non-decreasing.
    pending: [(u64, [u64; W]); SIM_PENDING],
    len: usize,
}

/// A `Sim` line.
#[derive(Debug)]
pub struct SimLine<const W: usize> {
    st: Cell<SimState<W>>,
}

impl Sim {
    /// `seed` comes from the simulator's per-component stream (§6.4); each publication is
    /// delayed by a draw in `0..=max_delay_ns`.
    pub fn new(seed: u64, max_delay_ns: u64) -> Self {
        Self {
            now: Cell::new(0),
            floor: Cell::new(0),
            last_vis: Cell::new(0),
            rng: Cell::new(seed),
            max_delay_ns,
        }
    }

    /// Virtual time in ns.
    pub fn virtual_ns(&self) -> u64 {
        self.now.get()
    }

    /// Moves virtual time forward to `t` (never back).
    pub fn advance_to(&self, t: u64) {
        self.now.set(self.now.get().max(t));
    }

    /// SplitMix64: a fixed, published generator, so a seed replays on every host.
    fn draw(&self) -> u64 {
        let s = self.rng.get().wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.rng.set(s);
        let z = (s ^ (s >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn drain<const W: usize>(&self, st: &mut SimState<W>) {
        let now = self.now.get().max(self.floor.get());
        let due = st
            .pending
            .iter()
            .take(st.len)
            .take_while(|(at, _)| *at <= now);
        let mut k = 0usize;
        for (_, words) in due {
            st.visible = *words;
            k = k.saturating_add(1);
        }
        st.pending.copy_within(k.., 0);
        st.len = st.len.saturating_sub(k);
    }
}

impl sealed::Sealed for Sim {}

impl Visibility for Sim {
    type Line<const W: usize> = SimLine<W>;

    fn line<const W: usize>(&self, init: [u64; W]) -> SimLine<W> {
        SimLine {
            st: Cell::new(SimState {
                visible: init,
                pending: [(0, init); SIM_PENDING],
                len: 0,
            }),
        }
    }

    fn publish<const W: usize>(&self, line: &SimLine<W>, words: [u64; W]) {
        let delay = self
            .draw()
            .checked_rem(self.max_delay_ns.saturating_add(1))
            .unwrap_or(0);
        let at = self
            .now
            .get()
            .saturating_add(delay)
            .max(self.last_vis.get());
        self.last_vis.set(at);
        let mut st = line.st.get();
        self.drain(&mut st);
        if st.len >= SIM_PENDING {
            // Full: make this line's oldest publication, and everything published before it on
            // any line, visible now. Its deadline is ≤ every later one, so the drain frees a slot.
            if let Some((oldest, _)) = st.pending.first() {
                self.floor.set(self.floor.get().max(*oldest));
            }
            self.drain(&mut st);
        }
        if let Some(e) = st.pending.get_mut(st.len) {
            *e = (at, words);
            st.len = st.len.saturating_add(1);
        }
        line.st.set(st);
    }

    fn try_read<const W: usize>(&self, line: &SimLine<W>) -> Option<[u64; W]> {
        let mut st = line.st.get();
        self.drain(&mut st);
        line.st.set(st);
        Some(st.visible)
    }
}

// loom's atomics are larger than core's, so layout asserts hold for the production build only.
#[cfg(not(loom))]
const _: () = assert!(size_of::<HwLine<7>>() == 64);
#[cfg(not(loom))]
const _: () = assert!(core::mem::offset_of!(HwLine<7>, words) == 8);
