//! The commit box's incremental balance SMT (09 §9.3 "net diff", B-CHN-2): the same roots and
//! proofs as the reference [`crate::smt::Smt`], updated in place from a batch of dirty leaves.
//!
//! Only non-empty nodes are stored, keyed by (depth, key prefix). [`IncSmt::apply`] writes the
//! leaves, then rehashes each dirty parent once per level, so leaves that share an upper path
//! share its hashes. A batch of n leaves costs at most 256·n node hashes and less when paths
//! overlap; proofs read stored siblings without hashing.
//!
//! **Spec gap (cost).** 09 §9.3 budgets ~20 node hashes per changed leaf. With the §9.3 hashing
//! (`E[d]` siblings, no path compression) a leaf below a sparse region still rehashes every level
//! from the leaf up, ~256 per isolated leaf. This module keeps the spec's bytes exactly; meeting
//! the budget needs a compressed internal layout with the same roots (follow-up, measured below).

use std::collections::{BTreeMap, BTreeSet};

use vyrn_types::Hash;

use crate::smt::{DEPTH, Proof, empty, node_hash};

/// Node identity: depth (0 = root, 256 = leaf) and the key with bits ≥ depth cleared.
type NodeId = (u16, [u8; 32]);

fn prefix(key: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut p = *key;
    for (i, b) in p.iter_mut().enumerate() {
        let lo = i.saturating_mul(8);
        if lo >= depth {
            *b = 0;
        } else if depth < lo.saturating_add(8) {
            *b &= 0xffu8 << (8 - (depth - lo));
        }
    }
    p
}

fn with_bit(p: &[u8; 32], d: usize) -> [u8; 32] {
    let mut q = *p;
    if let Some(b) = q.get_mut(d / 8) {
        *b |= 0x80 >> (d % 8);
    }
    q
}

fn depth_id(d: usize) -> u16 {
    u16::try_from(d).unwrap_or(u16::MAX)
}

/// An incremental sparse Merkle tree with the 09 §9.3 hashing.
#[derive(Clone, Debug, Default)]
pub struct IncSmt {
    nodes: BTreeMap<NodeId, Hash>,
    hashes: u64,
}

impl IncSmt {
    /// An empty tree; its root is E[256].
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, d: usize, p: &[u8; 32]) -> Hash {
        self.nodes
            .get(&(depth_id(d), *p))
            .copied()
            .unwrap_or_else(|| empty(DEPTH - d))
    }

    fn put(&mut self, d: usize, p: [u8; 32], h: Hash) {
        if h == empty(DEPTH - d) {
            self.nodes.remove(&(depth_id(d), p));
        } else {
            self.nodes.insert((depth_id(d), p), h);
        }
    }

    /// The root.
    pub fn root(&self) -> Hash {
        self.get(0, &[0; 32])
    }

    /// The leaf hash at `key`, E[0] if absent.
    pub fn leaf(&self, key: &Hash) -> Hash {
        self.get(DEPTH, &key.0)
    }

    /// Applies a commit's dirty leaves; a leaf of E[0] removes the key. With repeated keys the
    /// last value wins.
    pub fn apply(&mut self, dirty: impl IntoIterator<Item = (Hash, Hash)>) {
        let mut level: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (k, leaf) in dirty {
            self.put(DEPTH, k.0, leaf);
            level.insert(k.0);
        }
        for d in (0..DEPTH).rev() {
            let parents: BTreeSet<[u8; 32]> = level.iter().map(|k| prefix(k, d)).collect();
            for p in &parents {
                let l = self.get(d + 1, p);
                let r = self.get(d + 1, &with_bit(p, d));
                let h = node_hash(&l, &r);
                self.hashes = self.hashes.saturating_add(1);
                self.put(d, *p, h);
            }
            level = parents;
        }
    }

    /// The proof for `key`, present or absent; the same as [`crate::smt::Smt::proof`].
    pub fn proof(&self, key: &Hash) -> Proof {
        let mut p = Proof::default();
        for d in 0..DEPTH {
            let own = prefix(&key.0, d + 1);
            // The sibling flips bit d of our own prefix at depth d + 1.
            let mut sib = own;
            if let Some(b) = sib.get_mut(d / 8) {
                *b ^= 0x80 >> (d % 8);
            }
            if let Some(h) = self.nodes.get(&(depth_id(d + 1), sib)) {
                if let Some(b) = p.bitmap.get_mut(d / 8) {
                    *b |= 0x80 >> (d % 8);
                }
                p.siblings.push(*h);
            }
        }
        p
    }

    /// Node hashes computed so far (B-CHN-2 accounting).
    pub fn hashes(&self) -> u64 {
        self.hashes
    }

    /// Stored non-empty nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::smt::Smt;
    use vyrn_crypto::hash::hash;

    fn h(i: u32) -> Hash {
        hash(&i.to_le_bytes())
    }

    #[test]
    fn matches_the_reference_tree_through_inserts_updates_and_removals() {
        let mut r = Smt::new();
        let mut t = IncSmt::new();
        assert_eq!(t.root(), r.root());
        // Batches with shared prefixes, repeats, updates and removals.
        let mut keys: Vec<Hash> = (0..40).map(h).collect();
        // Two keys that differ only in the last bit: the deepest split.
        let mut near = keys[0];
        near.0[31] ^= 1;
        keys.push(near);
        for round in 0..4u32 {
            let batch: Vec<(Hash, Hash)> = keys
                .iter()
                .enumerate()
                .filter(|(i, _)| !(*i as u32 + round).is_multiple_of(3))
                .map(|(i, k)| {
                    let leaf = if round == 3 && i % 2 == 0 {
                        Hash([0; 32])
                    } else {
                        h(1000 * round + i as u32)
                    };
                    (*k, leaf)
                })
                .collect();
            for (k, l) in &batch {
                r.insert(*k, *l);
            }
            t.apply(batch);
            assert_eq!(t.root(), r.root(), "round {round}");
            for k in keys.iter().chain([&h(9999)]) {
                assert_eq!(t.proof(k), r.proof(k), "proof, round {round}");
                assert_eq!(t.leaf(k), r.get(k));
                assert!(t.proof(k).verify(&t.root(), k, &t.leaf(k)));
            }
        }
        // Remove everything: back to E[256] with nothing stored.
        t.apply(keys.iter().map(|k| (*k, Hash([0; 32]))));
        assert_eq!(t.root(), empty(DEPTH));
        assert!(t.is_empty());
    }

    #[test]
    fn last_value_wins_within_a_batch_and_shared_paths_hash_once() {
        let mut t = IncSmt::new();
        t.apply([(h(1), h(2)), (h(1), h(3))]);
        assert_eq!(t.leaf(&h(1)), h(3));
        assert_eq!(t.hashes(), 256);
        let mut u = IncSmt::new();
        u.apply((0..64).map(|i| (h(i), h(i))));
        // 64 leaves share the top ~6 levels: fewer than 64 × 256 hashes.
        assert!(u.hashes() < 64 * 256 - 64 * 5, "{}", u.hashes());
    }
}
