//! The balance SMT (09 §9.3): a binary sparse Merkle tree of depth 256 over BLAKE3.
//!
//! ```text
//! leaf_hash = BLAKE3(derive_key("vyrn v1 smt leaf", key ‖ value))
//! node_hash = BLAKE3(derive_key("vyrn v1 smt node", left ‖ right))
//! E[0] = [0; 32];  E[h + 1] = node_hash(E[h], E[h])     // the empty subtree of height h
//! ```
//!
//! Bit d of a key (d = 0 is the most significant bit of byte 0) takes the right child at depth d.
//! A proof is `{ bitmap, siblings }`: bit d of `bitmap`, counted the same way, is set iff the
//! sibling at depth d is not empty, and `siblings` holds the non-empty ones in increasing depth.
//! An absent key has leaf hash E[0].
//!
//! The leaf value layouts are the ones `contracts/` proposed for the 09 §9.3 gap (all integers
//! little-endian, 01 §3); the L1 `escapeClaim` decodes the same bytes:
//!
//! ```text
//! AccountLeaf key   = BLAKE3(0x01 ‖ le32(account))
//! AccountLeaf value = owner_kind ‖ owner (32 B) ‖ le64(nonce) ‖ exit_address (20 B)        61 B
//! BalanceLeaf key   = BLAKE3(0x02 ‖ le32(account) ‖ le16(asset))
//! BalanceLeaf value = le128 × 5: free, alloc_sum, transit, pending_unposted, pending_posted  80 B
//! ```
//!
//! `AllocLeaf`, `SessionLeaf` and `OperatorLeaf` have no fixed layout yet (a follow-up).
//!
//! [`Smt`] is the reference tree: an in-memory map, rebuilt per query. The commit box's incremental
//! tree (09 §9.3 "net diff", B-CHN-2) must produce the same roots and proofs.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use vyrn_crypto::derive_key;
use vyrn_crypto::hash::hash;
use vyrn_types::Hash;

use crate::eip712::Address;

/// The `derive_key` context of a leaf (09 §17.3).
pub const LEAF_CONTEXT: &str = "vyrn v1 smt leaf";
/// The `derive_key` context of an inner node (09 §17.3).
pub const NODE_CONTEXT: &str = "vyrn v1 smt node";
/// Tree depth.
pub const DEPTH: usize = 256;

/// The hash of a leaf with `key` and encoded `value`.
pub fn leaf_hash(key: &Hash, value: &[u8]) -> Hash {
    let mut m = Vec::with_capacity(32usize.saturating_add(value.len()));
    m.extend_from_slice(&key.0);
    m.extend_from_slice(value);
    hash(&derive_key(LEAF_CONTEXT, &m))
}

/// The hash of an inner node.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut m = [0u8; 64];
    let (l, r) = m.split_at_mut(32);
    l.copy_from_slice(&left.0);
    r.copy_from_slice(&right.0);
    hash(&derive_key(NODE_CONTEXT, &m))
}

/// E[h], the root of an empty subtree of height h ≤ 256.
pub fn empty(height: usize) -> Hash {
    static TABLE: OnceLock<Vec<Hash>> = OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = Vec::with_capacity(DEPTH.saturating_add(1));
        let mut h = Hash([0; 32]);
        t.push(h);
        for _ in 0..DEPTH {
            h = node_hash(&h, &h);
            t.push(h);
        }
        t
    });
    t.get(height).copied().unwrap_or_default()
}

/// Bit `d` of `key`, MSB first.
pub fn bit(key: &Hash, d: usize) -> bool {
    key.0
        .get(d / 8)
        .is_some_and(|b| (b >> (7 - (d % 8))) & 1 == 1)
}

fn set_bit(bitmap: &mut [u8; 32], d: usize) {
    if let Some(b) = bitmap.get_mut(d / 8) {
        *b |= 0x80 >> (d % 8);
    }
}

/// An SMT proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proof {
    /// Bit d set iff the sibling at depth d is not empty.
    pub bitmap: [u8; 32],
    /// The non-empty siblings, in increasing depth.
    pub siblings: Vec<Hash>,
}

impl Proof {
    /// The root that `leaf` at `key` implies; `None` if the sibling count does not match the bitmap.
    pub fn root(&self, key: &Hash, leaf: &Hash) -> Option<Hash> {
        let want: u32 = self.bitmap.iter().map(|b| b.count_ones()).sum();
        if want as usize != self.siblings.len() {
            return None;
        }
        let mut sibs = self.siblings.iter().rev();
        let mut h = *leaf;
        for d in (0..DEPTH).rev() {
            let s = if bit(&Hash(self.bitmap), d) {
                *sibs.next()?
            } else {
                empty(DEPTH - 1 - d)
            };
            h = if bit(key, d) {
                node_hash(&s, &h)
            } else {
                node_hash(&h, &s)
            };
        }
        Some(h)
    }

    /// Whether `leaf` sits at `key` under `root`.
    pub fn verify(&self, root: &Hash, key: &Hash, leaf: &Hash) -> bool {
        self.root(key, leaf) == Some(*root)
    }
}

/// The reference sparse Merkle tree: key → leaf hash.
#[derive(Clone, Debug, Default)]
pub struct Smt {
    leaves: BTreeMap<Hash, Hash>,
}

impl Smt {
    /// An empty tree; its root is E[256].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the leaf at `key`. Setting E[0] removes it.
    pub fn insert(&mut self, key: Hash, leaf: Hash) {
        if leaf == empty(0) {
            self.leaves.remove(&key);
        } else {
            self.leaves.insert(key, leaf);
        }
    }

    /// The leaf hash at `key`, E[0] if absent.
    pub fn get(&self, key: &Hash) -> Hash {
        self.leaves.get(key).copied().unwrap_or_default()
    }

    /// The root.
    pub fn root(&self) -> Hash {
        let all: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        subtree(&all, 0)
    }

    /// The proof for `key`, present or absent.
    pub fn proof(&self, key: &Hash) -> Proof {
        let all: Vec<(Hash, Hash)> = self.leaves.iter().map(|(k, v)| (*k, *v)).collect();
        let mut cur: &[(Hash, Hash)] = &all;
        let mut p = Proof::default();
        for d in 0..DEPTH {
            let split = cur.partition_point(|(k, _)| !bit(k, d));
            let (l, r) = cur.split_at(split);
            let (same, other) = if bit(key, d) { (r, l) } else { (l, r) };
            let s = subtree(other, d.saturating_add(1));
            if s != empty(DEPTH - 1 - d) {
                set_bit(&mut p.bitmap, d);
                p.siblings.push(s);
            }
            cur = same;
        }
        p
    }
}

/// The hash of the subtree at `depth` holding `leaves`, which are sorted and share their first
/// `depth` bits.
fn subtree(leaves: &[(Hash, Hash)], depth: usize) -> Hash {
    match leaves {
        [] => empty(DEPTH.saturating_sub(depth)),
        [(_, leaf)] if depth >= DEPTH => *leaf,
        _ if depth >= DEPTH => Hash::default(), // two equal keys: impossible from a BTreeMap
        _ => {
            let split = leaves.partition_point(|(k, _)| !bit(k, depth));
            let (l, r) = leaves.split_at(split);
            let next = depth.saturating_add(1);
            node_hash(&subtree(l, next), &subtree(r, next))
        }
    }
}

/// `AccountLeaf` (09 §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountLeaf {
    /// `AccountId` (01 §3).
    pub account: u32,
    /// 0 Ed25519 key, 1 EVM address (right-aligned in `owner`).
    pub owner_kind: u8,
    /// The owner key or address.
    pub owner: [u8; 32],
    /// Transaction nonce.
    pub nonce: u64,
    /// Where escape pays (09 §6.6).
    pub exit_address: Address,
}

impl AccountLeaf {
    /// Its key.
    pub fn key(&self) -> Hash {
        let mut m = [0u8; 5];
        m[0] = 0x01;
        m[1..].copy_from_slice(&self.account.to_le_bytes());
        hash(&m)
    }

    /// Its 61-byte value.
    pub fn value(&self) -> [u8; 61] {
        let mut v = [0u8; 61];
        v[0] = self.owner_kind;
        v[1..33].copy_from_slice(&self.owner);
        v[33..41].copy_from_slice(&self.nonce.to_le_bytes());
        v[41..61].copy_from_slice(&self.exit_address);
        v
    }

    /// Its leaf hash.
    pub fn leaf_hash(&self) -> Hash {
        leaf_hash(&self.key(), &self.value())
    }
}

/// `BalanceLeaf` (09 §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceLeaf {
    /// `AccountId`.
    pub account: u32,
    /// `AssetId`, u16 (01 §3).
    pub asset: u16,
    /// Free balance.
    pub free: u128,
    /// Sum over the account's allocations.
    pub alloc_sum: u128,
    /// Moving between books (09 §4.7).
    pub transit: u128,
    /// Withdrawals not yet in a signed post.
    pub pending_unposted: u128,
    /// Withdrawals in a signed post.
    pub pending_posted: u128,
}

impl BalanceLeaf {
    /// Its key.
    pub fn key(&self) -> Hash {
        let mut m = [0u8; 7];
        m[0] = 0x02;
        m[1..5].copy_from_slice(&self.account.to_le_bytes());
        m[5..7].copy_from_slice(&self.asset.to_le_bytes());
        hash(&m)
    }

    /// Its 80-byte value.
    pub fn value(&self) -> [u8; 80] {
        let mut v = [0u8; 80];
        let fields = [
            self.free,
            self.alloc_sum,
            self.transit,
            self.pending_unposted,
            self.pending_posted,
        ];
        for (chunk, f) in v.as_chunks_mut::<16>().0.iter_mut().zip(fields) {
            chunk.copy_from_slice(&f.to_le_bytes());
        }
        v
    }

    /// Its leaf hash.
    pub fn leaf_hash(&self) -> Hash {
        leaf_hash(&self.key(), &self.value())
    }

    /// What `escapeClaim` pays (09 §6.6): `free + alloc_sum + transit + pending_unposted`.
    /// `pending_posted` is excluded because the post's own claims pay it. `None` on overflow.
    pub fn escape_amount(&self) -> Option<u128> {
        self.free
            .checked_add(self.alloc_sum)?
            .checked_add(self.transit)?
            .checked_add(self.pending_unposted)
    }
}
