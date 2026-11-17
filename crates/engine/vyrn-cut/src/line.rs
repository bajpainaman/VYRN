//! `Published<T, W, V>`: one single-writer shared line holding a `T` encoded as `W` words, padded
//! to `SHARED_ALIGN` (spec/11-build.md §3.6). The counter, snapshot, floor and `LaneCut` lines
//! are this type with their own `T`; `PubRing` is the cut publication of 05 §4.13.

use core::marker::PhantomData;

use super::Visibility;

/// A value with a fixed encoding as `W` little-endian words. The byte image of word `i` is the
/// spec layout's bytes `8 + 8 i ..` (the seqlock word sits at offset 0). `from_words` is total.
pub trait Words<const W: usize>: Copy {
    fn to_words(&self) -> [u64; W];
    fn from_words(words: [u64; W]) -> Self;
}

impl Words<1> for u64 {
    #[inline]
    fn to_words(&self) -> [u64; 1] {
        [*self]
    }
    #[inline]
    fn from_words([w]: [u64; 1]) -> Self {
        w
    }
}

/// Writer: the one core named by the line's type. Readers: any core, with `try_read`.
#[repr(C, align(128))]
pub struct Published<T, const W: usize, V: Visibility> {
    line: V::Line<W>,
    _t: PhantomData<fn() -> T>,
}

impl<T: Words<W>, const W: usize, V: Visibility> Published<T, W, V> {
    #[inline]
    pub fn new(vis: &V, init: &T) -> Self {
        Self {
            line: vis.line(init.to_words()),
            _t: PhantomData,
        }
    }

    /// Writer only (`INV-WRITER`).
    #[inline(always)]
    pub fn publish(&self, vis: &V, value: &T) {
        vis.publish(&self.line, value.to_words());
    }

    /// The newest visible publication, or `None` while the writer stores (retry next poll).
    #[inline(always)]
    pub fn try_read(&self, vis: &V) -> Option<T> {
        self.try_read_words(vis).map(T::from_words)
    }

    #[inline(always)]
    pub(crate) fn try_read_words(&self, vis: &V) -> Option<[u64; W]> {
        vis.try_read(&self.line)
    }

    #[inline(always)]
    pub(crate) fn publish_words(&self, vis: &V, words: [u64; W]) {
        vis.publish(&self.line, words);
    }
}

/// Publications in a `PubRing` (05 §4.13: "ring of 4 per half").
pub const PUB_RING: usize = 4;

/// A ring of `PUB_RING` seqlocked publications plus a `newest` line (05 §4.13, §7.1).
///
/// Writer: one core. It writes publication `id` into slot `id mod 4`, then stores `newest = id`
/// (`Release`). Word 0 of every publication is its id; `publish` sets it. Readers load `newest`
/// (`Acquire`), then its slot, and reject a slot whose word 0 is not that id: the writer has
/// lapped them. So a reader gets publication `newest` or `None`, and reads of one reader never
/// go back to an older id (`INV-CUT-MONO` per half). Id 0 is the initial value.
pub struct PubRing<T, const W: usize, V: Visibility> {
    slots: [Published<T, W, V>; PUB_RING],
    newest: Published<u64, 1, V>,
}

impl<T: Words<W>, const W: usize, V: Visibility> PubRing<T, W, V> {
    /// Every slot starts as `init` with id 0.
    #[inline]
    pub fn new(vis: &V, init: &T) -> Self {
        let mut words = init.to_words();
        if let Some(w0) = words.first_mut() {
            *w0 = 0;
        }
        let init = T::from_words(words);
        Self {
            slots: core::array::from_fn(|_| Published::new(vis, &init)),
            newest: Published::new(vis, &0),
        }
    }

    #[inline]
    fn slot(&self, id: u64) -> Option<&Published<T, W, V>> {
        self.slots.get(usize::try_from(id & 3).ok()?)
    }

    /// Writer only. `id` must grow by one per call, from 1.
    #[inline]
    pub fn publish(&self, vis: &V, id: u64, value: &T) {
        let mut words = value.to_words();
        if let Some(w0) = words.first_mut() {
            *w0 = id;
        }
        if let Some(s) = self.slot(id) {
            s.publish_words(vis, words);
        }
        self.newest.publish(vis, &id);
    }

    /// The newest publication and its id, or `None` (writer storing or lapping; retry).
    #[inline]
    pub fn try_read_newest(&self, vis: &V) -> Option<(u64, T)> {
        let id = self.newest.try_read(vis)?;
        let words = self.slot(id)?.try_read_words(vis)?;
        (words.first() == Some(&id)).then(|| (id, T::from_words(words)))
    }
}

/// Little-endian `lo ‖ hi` in one word.
#[inline(always)]
pub(crate) fn join(lo: [u8; 4], hi: [u8; 4]) -> u64 {
    let [a, b, c, d] = lo;
    let [e, f, g, h] = hi;
    u64::from_le_bytes([a, b, c, d, e, f, g, h])
}

/// The inverse of `join`.
#[inline(always)]
pub(crate) fn split(w: u64) -> ([u8; 4], [u8; 4]) {
    let [a, b, c, d, e, f, g, h] = w.to_le_bytes();
    ([a, b, c, d], [e, f, g, h])
}

#[inline(always)]
pub(crate) fn u32_at(b: [u8; 4]) -> u32 {
    u32::from_le_bytes(b)
}
