//! The withdrawal tree of a post (09 §6.2; `contracts/README.md` §Withdrawal tree).
//!
//! It is OpenZeppelin `StandardMerkleTree` with leaf types `["uint64","address","uint256","address"]`:
//!
//! ```text
//! leaf = keccak256(keccak256(abi.encode(uint64 wdId, address token, uint256 amount, address recipient)))
//! node = keccak256(min(a, b) ‖ max(a, b))            // sorted pair
//! ```
//!
//! Leaves are sorted by hash, laid out in a complete binary tree of 2n − 1 nodes with the leaves at
//! the end in reverse order, exactly as `@openzeppelin/merkle-tree` 1.0.8 does, so its tooling
//! produces the same roots and proofs. An empty tree has root zero (the `post2` vector: `wdCount`
//! 0, `wdRoot` 0); OpenZeppelin has no empty tree.

use crate::eip712::{Address, U256};
use crate::keccak::{keccak256, keccak256_parts};

/// One withdrawal (09 §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// Unique across all posts; each pays at most once.
    pub wd_id: u64,
    /// The L1 token.
    pub token: Address,
    /// Base units.
    pub amount: u128,
    /// Paid by `claim`.
    pub recipient: Address,
}

impl Withdrawal {
    /// The leaf hash.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut enc = [0u8; 128];
        let words = [
            (24usize, self.wd_id.to_be_bytes().to_vec()),
            (32 + 12, self.token.to_vec()),
            (64 + 16, self.amount.to_be_bytes().to_vec()),
            (96 + 12, self.recipient.to_vec()),
        ];
        for (at, bytes) in words {
            if let Some(dst) = enc.get_mut(at..at.saturating_add(bytes.len())) {
                dst.copy_from_slice(&bytes);
            }
        }
        keccak256(&keccak256(&enc))
    }
}

/// The sorted-pair node hash.
pub fn node(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        keccak256_parts(&[a, b])
    } else {
        keccak256_parts(&[b, a])
    }
}

/// The flat tree: index 0 is the root, the last n entries are the sorted leaves in reverse.
fn build(withdrawals: &[Withdrawal]) -> Vec<[u8; 32]> {
    let mut leaves: Vec<[u8; 32]> = withdrawals.iter().map(Withdrawal::leaf_hash).collect();
    leaves.sort_unstable();
    let n = leaves.len();
    if n == 0 {
        return Vec::new();
    }
    let len = n.saturating_mul(2).saturating_sub(1);
    let mut tree = vec![[0u8; 32]; len];
    for (i, leaf) in leaves.iter().enumerate() {
        if let Some(slot) = tree.get_mut(len.saturating_sub(1).saturating_sub(i)) {
            *slot = *leaf;
        }
    }
    for i in (0..len.saturating_sub(n)).rev() {
        let l = tree.get(i.saturating_mul(2).saturating_add(1)).copied();
        let r = tree.get(i.saturating_mul(2).saturating_add(2)).copied();
        if let (Some(l), Some(r), Some(slot)) = (l, r, tree.get_mut(i)) {
            *slot = node(&l, &r);
        }
    }
    tree
}

/// The `wdRoot` of a post; zero when there are no withdrawals.
pub fn root(withdrawals: &[Withdrawal]) -> [u8; 32] {
    build(withdrawals).first().copied().unwrap_or([0; 32])
}

/// The proof for `withdrawals[index]`, as `claim` takes it; `None` if `index` is out of range.
pub fn proof(withdrawals: &[Withdrawal], index: usize) -> Option<Vec<[u8; 32]>> {
    let leaf = withdrawals.get(index)?.leaf_hash();
    let tree = build(withdrawals);
    let mut i = tree.iter().rposition(|h| *h == leaf)?;
    let mut out = Vec::new();
    while i > 0 {
        let sib = if i % 2 == 1 {
            i.checked_add(1)?
        } else {
            i.checked_sub(1)?
        };
        out.push(*tree.get(sib)?);
        i = (i.checked_sub(1)?) / 2;
    }
    Some(out)
}

/// OpenZeppelin `MerkleProof.processProof` compared with `root`: the contract's `claim` check.
pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    proof.iter().fold(*leaf, |h, p| node(&h, p)) == *root
}

/// `wdTotals`: the sum per token in `assets` order, as uint256. `None` if a token is not listed
/// or a sum overflows 2^256 (it cannot with fewer than 2^128 withdrawals).
pub fn totals(withdrawals: &[Withdrawal], assets: &[Address]) -> Option<Vec<U256>> {
    let mut out = vec![[0u8; 32]; assets.len()];
    for w in withdrawals {
        let i = assets.iter().position(|a| *a == w.token)?;
        add(out.get_mut(i)?, w.amount)?;
    }
    Some(out)
}

/// `acc += x` on a big-endian uint256; `None` on overflow.
fn add(acc: &mut U256, x: u128) -> Option<()> {
    let mut carry = x;
    for b in acc.iter_mut().rev() {
        if carry == 0 {
            return Some(());
        }
        let sum = u128::from(*b).checked_add(carry & 0xff)?;
        *b = (sum & 0xff) as u8;
        carry = (carry >> 8).checked_add(sum >> 8)?;
    }
    (carry == 0).then_some(())
}
