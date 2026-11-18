//! The order LtHash (09 §9.4): a lattice hash of the resting-order set, 1024 × u16.
//!
//! ```text
//! elem(o)  = le16(book) ‖ [lane] ‖ le32(handle) ‖ le32(account) ‖ [side] ‖ le32(tick)
//!            ‖ le32(open_qty) ‖ le64(rx_ts)                                         28 B
//! v(o)     = BLAKE3_XOF(derive_key("vyrn v1 lthash", elem(o)))[0..2048] as [u16; 1024] LE
//! L(S)     = Σ v(o) componentwise mod 2^16
//! digest   = BLAKE3(derive_key("vyrn v1 lthash digest", L as 2048 LE bytes))
//! ```
//!
//! Addition commutes, so each lane sums its own diff and the commit box adds the lane sums
//! ([`LtHash::add_hash`]). An order whose `open_qty` changes is a different element: remove the
//! old one and add the new one.

use vyrn_crypto::hash::hash;
use vyrn_crypto::{derive_key, hash_xof};
use vyrn_types::{BookId, Hash};

/// `CHN_LTHASH_DIM` (09 §17.1).
pub const DIM: usize = 1024;
/// The byte length of the vector.
pub const BYTES: usize = DIM * 2;
/// The `derive_key` context of an element (09 §17.3).
pub const ELEM_CONTEXT: &str = "vyrn v1 lthash";
/// The `derive_key` context of the digest (09 §17.3).
pub const DIGEST_CONTEXT: &str = "vyrn v1 lthash digest";

/// One resting order as the LtHash sees it (09 §9.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrderElem {
    /// Book.
    pub book: BookId,
    /// Lane within the book.
    pub lane: u8,
    /// Order handle.
    pub handle: u32,
    /// Owner account.
    pub account: u32,
    /// Side (01 §3).
    pub side: u8,
    /// Price tick.
    pub tick: u32,
    /// Open quantity at the commit.
    pub open_qty: u32,
    /// Receive timestamp.
    pub rx_ts: u64,
}

impl OrderElem {
    /// The 28-byte encoding, fields in order, little-endian.
    pub fn encode(&self) -> [u8; 28] {
        let mut b = [0u8; 28];
        let parts: [&[u8]; 8] = [
            &self.book.0.to_le_bytes(),
            &[self.lane],
            &self.handle.to_le_bytes(),
            &self.account.to_le_bytes(),
            &[self.side],
            &self.tick.to_le_bytes(),
            &self.open_qty.to_le_bytes(),
            &self.rx_ts.to_le_bytes(),
        ];
        let mut at = 0usize;
        for p in parts {
            let end = at.saturating_add(p.len());
            if let Some(dst) = b.get_mut(at..end) {
                dst.copy_from_slice(p);
            }
            at = end;
        }
        b
    }

    /// `v(o)`.
    pub fn vector(&self) -> LtHash {
        let mut bytes = [0u8; BYTES];
        hash_xof(&derive_key(ELEM_CONTEXT, &self.encode()), &mut bytes);
        LtHash::from_bytes(&bytes)
    }
}

/// An LtHash vector: the sum of a set's elements, or one element.
#[derive(Clone, PartialEq, Eq)]
pub struct LtHash(Box<[u16; DIM]>);

impl Default for LtHash {
    fn default() -> Self {
        Self(Box::new([0; DIM]))
    }
}

impl core::fmt::Debug for LtHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LtHash({:?})", self.digest())
    }
}

impl LtHash {
    /// `L(∅)`.
    pub fn new() -> Self {
        Self::default()
    }

    /// From the 2048 published bytes (09 §9.4: `L_k` is in the commitment stream).
    pub fn from_bytes(b: &[u8; BYTES]) -> Self {
        let mut v = Self::default();
        for (x, c) in v.0.iter_mut().zip(b.as_chunks::<2>().0) {
            *x = u16::from_le_bytes(*c);
        }
        v
    }

    /// The 2048 bytes, little-endian.
    pub fn to_bytes(&self) -> [u8; BYTES] {
        let mut b = [0u8; BYTES];
        for (c, x) in b.as_chunks_mut::<2>().0.iter_mut().zip(self.0.iter()) {
            *c = x.to_le_bytes();
        }
        b
    }

    /// `self += other`, componentwise mod 2^16.
    pub fn add_hash(&mut self, other: &LtHash) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    /// `self −= other`, componentwise mod 2^16.
    pub fn sub_hash(&mut self, other: &LtHash) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = a.wrapping_sub(*b);
        }
    }

    /// Adds `v(o)`.
    pub fn insert(&mut self, o: &OrderElem) {
        self.add_hash(&o.vector());
    }

    /// Subtracts `v(o)`.
    pub fn remove(&mut self, o: &OrderElem) {
        self.sub_hash(&o.vector());
    }

    /// `digest_k`, the value in `StateCommit.orders_lthash`.
    pub fn digest(&self) -> Hash {
        hash(&derive_key(DIGEST_CONTEXT, &self.to_bytes()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn o(handle: u32, qty: u32) -> OrderElem {
        OrderElem {
            book: BookId(0x0102),
            lane: 3,
            handle,
            account: 0x0a0b_0c0d,
            side: 1,
            tick: 1_000,
            open_qty: qty,
            rx_ts: 0x1122_3344_5566_7788,
        }
    }

    #[test]
    fn element_layout_is_28_bytes_in_field_order() {
        let b = o(0x0403_0201, 5).encode();
        assert_eq!(&b[..3], &[2, 1, 3]);
        assert_eq!(&b[3..7], &[1, 2, 3, 4]);
        assert_eq!(b[11], 1, "side");
        assert_eq!(&b[20..28], &0x1122_3344_5566_7788u64.to_le_bytes());
    }

    /// Computed with `b3sum` 1.8.7: `b3sum --derive-key "vyrn v1 lthash"` over `elem`, then
    /// `b3sum --raw -l 2048` over the 32-byte key; and `b3sum --derive-key "vyrn v1 lthash
    /// digest"` over the vector, then `b3sum` over that.
    #[test]
    fn vector_and_digest_match_b3sum() {
        let v = o(7, 5).vector().to_bytes();
        assert_eq!(hex(&v[..8]), VEC_HEAD);
        assert_eq!(hex(&v[BYTES - 8..]), VEC_TAIL);
        assert_eq!(hex(&o(7, 5).vector().digest().0), DIGEST);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const VEC_HEAD: &str = "738cd139b4fc5486";
    const VEC_TAIL: &str = "380906fdaef7b0ac";
    const DIGEST: &str = "15ccb1eb4317a7beb7be9bb267aa52ef94867ea5c6e1604b24a5f4c65ffa7c49";

    #[test]
    fn set_hash_is_order_independent_and_diffs_commute() {
        let (a, b, c) = (o(1, 5), o(2, 5), o(3, 9));
        let mut x = LtHash::new();
        for e in [&a, &b, &c] {
            x.insert(e);
        }
        let mut y = LtHash::new();
        for e in [&c, &a, &b] {
            y.insert(e);
        }
        assert_eq!(x, y);
        // A fill changes open_qty: remove old, add new; different from the original set.
        let mut z = x.clone();
        z.remove(&b);
        z.insert(&o(2, 4));
        assert_ne!(z.digest(), x.digest());
        z.remove(&o(2, 4));
        z.insert(&b);
        assert_eq!(z, x);
        // Two lane sums add to the whole set.
        let mut lane1 = LtHash::new();
        lane1.insert(&a);
        let mut lane2 = LtHash::new();
        lane2.insert(&b);
        lane2.insert(&c);
        lane1.add_hash(&lane2);
        assert_eq!(lane1, x);
        assert_eq!(LtHash::from_bytes(&x.to_bytes()), x);
        // Remove everything: back to zero.
        for e in [&a, &b, &c] {
            x.remove(e);
        }
        assert_eq!(x, LtHash::new());
    }
}
