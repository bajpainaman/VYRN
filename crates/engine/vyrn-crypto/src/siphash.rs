//! SipHash-2-4 with a 128-bit key and a 64-bit tag, in-house (spec/11-build.md §2.4).
//!
//! `siphash24` is the one-shot form the lane inlines into its packet loop. `SipHasher24` is the
//! streaming form behind `FixedState`, for non-engine hash maps. Both run the same rounds.

use core::hash::{BuildHasher, Hasher};
use vyrn_types::Tag;

#[derive(Clone, Copy)]
struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    #[inline(always)]
    fn new(key: &[u8; 16]) -> Self {
        let k0 = u64::from_le_bytes(key.first_chunk::<8>().copied().unwrap_or_default());
        let k1 = u64::from_le_bytes(key.last_chunk::<8>().copied().unwrap_or_default());
        Self {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
        }
    }

    #[inline(always)]
    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13) ^ self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16) ^ self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21) ^ self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17) ^ self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    #[inline(always)]
    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.round();
        self.v0 ^= m;
    }

    #[inline(always)]
    fn finish(mut self, last: u64) -> u64 {
        self.compress(last);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// The final block: the trailing bytes, then the message length mod 256 in the top byte.
#[inline(always)]
fn last_block(tail: &[u8], len: usize) -> u64 {
    let mut b = [0u8; 8];
    for (dst, src) in b.iter_mut().zip(tail) {
        *dst = *src;
    }
    let [len_low, ..] = len.to_le_bytes();
    b[7] = len_low;
    u64::from_le_bytes(b)
}

/// SipHash-2-4 of `bytes` under `key`.
#[inline(always)]
pub fn siphash24(key: &[u8; 16], bytes: &[u8]) -> Tag {
    let mut s = State::new(key);
    let (blocks, tail) = bytes.as_chunks::<8>();
    for block in blocks {
        s.compress(u64::from_le_bytes(*block));
    }
    Tag(s.finish(last_block(tail, bytes.len())))
}

/// Compares two tags without a data-dependent branch, so the time to reject a forged tag does not
/// depend on which byte differs (spec/11-build.md §2.4).
#[inline(always)]
pub fn tag_eq(a: Tag, b: Tag) -> bool {
    (a.0 ^ b.0) == 0
}

/// True when `tag` is the SipHash-2-4 of `bytes` under `key`.
#[inline(always)]
pub fn verify(key: &[u8; 16], bytes: &[u8], tag: Tag) -> bool {
    tag_eq(siphash24(key, bytes), tag)
}

/// Streaming SipHash-2-4, for `core::hash::Hasher` users. Byte-at-a-time buffering keeps it
/// simple; the hot path uses `siphash24`.
#[derive(Clone, Copy)]
pub struct SipHasher24 {
    state: State,
    buf: [u8; 8],
    nbuf: usize,
    len: usize,
}

impl SipHasher24 {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            state: State::new(key),
            buf: [0; 8],
            nbuf: 0,
            len: 0,
        }
    }
}

impl Hasher for SipHasher24 {
    fn write(&mut self, bytes: &[u8]) {
        self.len = self.len.wrapping_add(bytes.len());
        for &byte in bytes {
            if let Some(slot) = self.buf.get_mut(self.nbuf) {
                *slot = byte;
            }
            self.nbuf = self.nbuf.wrapping_add(1);
            if self.nbuf == 8 {
                self.state.compress(u64::from_le_bytes(self.buf));
                self.nbuf = 0;
            }
        }
    }

    fn finish(&self) -> u64 {
        let tail = self.buf.get(..self.nbuf).unwrap_or_default();
        self.state.finish(last_block(tail, self.len))
    }
}

/// The published key of `FixedState`: ASCII "vyrn fixed state".
pub const FIXED_STATE_KEY: [u8; 16] = *b"vyrn fixed state";

/// A `BuildHasher` with a fixed, published key, so iteration order of a `HashMap` is a function
/// of its keys only (01 §11.2, spec/11-build.md §3.3). Not for engine crates, which use `Dense`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FixedState;

impl BuildHasher for FixedState {
    type Hasher = SipHasher24;

    fn build_hasher(&self) -> SipHasher24 {
        SipHasher24::new(&FIXED_STATE_KEY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_eq_compares_every_bit() {
        assert!(tag_eq(
            Tag(0xa129_ca61_49be_45e5),
            Tag(0xa129_ca61_49be_45e5)
        ));
        for bit in 0..64 {
            let flipped = Tag(0xa129_ca61_49be_45e5 ^ (1u64 << bit));
            assert!(!tag_eq(Tag(0xa129_ca61_49be_45e5), flipped));
        }
    }

    #[test]
    fn fixed_state_is_reproducible() {
        let h = |x: u64| FixedState.hash_one(x);
        assert_eq!(h(42), h(42));
        assert_ne!(h(42), h(43));
        // Streaming over the native-endian bytes equals the one-shot function.
        assert_eq!(h(42), siphash24(&FIXED_STATE_KEY, &42u64.to_ne_bytes()).0);
    }
}
