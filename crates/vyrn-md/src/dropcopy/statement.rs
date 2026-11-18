//! The drop copy's part of the end-of-epoch statement, and the statement tree (10 §8.3, §10).
//!
//! **Leaf.** One per account, in `AccountId` order. Its bytes are
//!
//! ```text
//! off   size  field
//!   0      1  0x00          leaf domain
//!   1      4  account       AccountId, LE
//!   5      2  n             books, LE
//!   7  n×194  per book, ascending BookId: book u16 LE, then the account's own stream's four
//!             DC_EOD records (ordinal 0–3, 48 B each, 10 §8.1) as sent
//! ```
//!
//! so a client checks its leaf with the `DC_EOD` records it already holds, the last of which
//! carries its canonical stream's hash (§8.3). The leaf hash is BLAKE3 of those bytes.
//!
//! **Tree.** A node is BLAKE3(`0x01` ‖ left ‖ right); a level with an odd count carries its
//! last node up unchanged; the root of no leaves is BLAKE3 of the empty input. That root is
//! `ACC_STMT_ROOT`. A [`Proof`] lists, from the leaf up, each sibling with its side.
//!
//! Readings (10 §10, recorded there): the leaf carries only what the drop copy derives; the
//! other §10 fields (allocations, rebates, `MUST_SPLIT`, next tier, class, lane move, router
//! totals) are not built yet and take a later leaf domain. A master's aggregate stream is not a
//! leaf: its accounts are.

use std::collections::BTreeMap;

use vyrn_types::{AccountId, BookId, Hash};

use super::record::{DC_REC_BYTES, DcRecord, DcType};

const LEAF: u8 = 0x00;
const NODE: u8 = 0x01;

/// One account's drop-copy section for one book: its own stream's `DC_EOD` records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub book: BookId,
    pub eod: [DcRecord; 4],
}

impl Section {
    /// The four `DC_EOD` records of `account`'s stream, in ordinal order, as a section.
    pub fn from_eod(book: BookId, eod: [DcRecord; 4]) -> Option<Self> {
        let account = eod[0].account();
        let ok = eod.iter().enumerate().all(|(i, r)| {
            r.kind() == DcType::Eod && usize::from(r.ordinal()) == i && r.account() == account
        });
        ok.then_some(Self { book, eod })
    }

    pub fn account(&self) -> AccountId {
        self.eod[0].account()
    }

    /// The canonical stream's hash (the last `DC_EOD`).
    pub fn stream_hash(&self) -> [u8; 32] {
        self.eod[3].hash()
    }
}

/// An account's statement leaf: its sections, one per book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub account: AccountId,
    pub sections: Vec<Section>,
}

impl Statement {
    pub fn leaf_bytes(&self) -> Vec<u8> {
        let mut s = self.sections.clone();
        s.sort_unstable_by_key(|x| x.book.0);
        let mut b = Vec::with_capacity(7 + s.len() * (2 + 4 * DC_REC_BYTES));
        b.push(LEAF);
        b.extend_from_slice(&self.account.0.to_le_bytes());
        b.extend_from_slice(&u16::try_from(s.len()).unwrap_or(u16::MAX).to_le_bytes());
        for x in &s {
            b.extend_from_slice(&x.book.0.to_le_bytes());
            for r in &x.eod {
                b.extend_from_slice(&r.0);
            }
        }
        b
    }

    pub fn leaf_hash(&self) -> Hash {
        Hash(*blake3::hash(&self.leaf_bytes()).as_bytes())
    }
}

/// A Merkle path: each sibling from the leaf up, `true` when the sibling is on the right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub siblings: Vec<(bool, Hash)>,
}

impl Proof {
    /// Whether `leaf` is under `root` along this path.
    pub fn verify(&self, leaf: Hash, root: Hash) -> bool {
        let up = self.siblings.iter().fold(
            leaf,
            |h, &(right, s)| if right { node(h, s) } else { node(s, h) },
        );
        up == root
    }
}

fn node(l: Hash, r: Hash) -> Hash {
    let mut b = [0u8; 65];
    b[0] = NODE;
    b[1..33].copy_from_slice(&l.0);
    b[33..].copy_from_slice(&r.0);
    Hash(*blake3::hash(&b).as_bytes())
}

/// The statement tree over every account's leaf, in `AccountId` order.
#[derive(Clone, Debug)]
pub struct StmtTree {
    accounts: Vec<AccountId>,
    levels: Vec<Vec<Hash>>,
}

impl StmtTree {
    /// Merges sections by account (one section per account and book; a later duplicate of an
    /// `(account, book)` is refused with `None`).
    pub fn build(sections: impl IntoIterator<Item = Section>) -> Option<Self> {
        let mut by: BTreeMap<AccountId, Statement> = BTreeMap::new();
        for s in sections {
            let st = by.entry(s.account()).or_insert_with(|| Statement {
                account: s.account(),
                sections: Vec::new(),
            });
            if st.sections.iter().any(|x| x.book == s.book) {
                return None;
            }
            st.sections.push(s);
        }
        let accounts: Vec<AccountId> = by.keys().copied().collect();
        let mut levels = vec![by.values().map(Statement::leaf_hash).collect::<Vec<_>>()];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let l = levels.last()?;
            let next = l
                .chunks(2)
                .map(|p| match p {
                    [a, b] => node(*a, *b),
                    [a] => *a,
                    _ => Hash([0; 32]),
                })
                .collect();
            levels.push(next);
        }
        Some(Self { accounts, levels })
    }

    /// `ACC_STMT_ROOT`.
    pub fn root(&self) -> Hash {
        match self.levels.last().and_then(|l| l.first()) {
            Some(h) => *h,
            None => Hash(*blake3::hash(&[]).as_bytes()),
        }
    }

    /// `account`'s path to the root.
    pub fn proof(&self, account: AccountId) -> Option<Proof> {
        let mut i = self.accounts.binary_search(&account).ok()?;
        let mut siblings = Vec::new();
        for l in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let j = i ^ 1;
            if let Some(s) = l.get(j) {
                siblings.push((j > i, *s));
            }
            i /= 2;
        }
        Some(Proof { siblings })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn section(a: u32, book: u16, tag: u8) -> Section {
        let acct = AccountId(a);
        let eod = [
            DcRecord::eod(acct, 0, [u64::from(tag), 1, 2, 3, 4]),
            DcRecord::eod(acct, 1, [5, 6, 0, 0, 0]),
            DcRecord::eod(acct, 2, [7, 8, 9, 10, 0]),
            DcRecord::eod_hash(acct, 11, &[tag; 32]),
        ];
        Section::from_eod(BookId(book), eod).unwrap()
    }

    #[test]
    fn every_account_proves_and_a_changed_leaf_does_not() {
        for n in 1..=7u32 {
            let t = StmtTree::build((0..n).map(|a| section(100 + a, 7, a as u8))).unwrap();
            for a in 0..n {
                let s = Statement {
                    account: AccountId(100 + a),
                    sections: vec![section(100 + a, 7, a as u8)],
                };
                let p = t.proof(s.account).unwrap();
                assert!(p.verify(s.leaf_hash(), t.root()), "n={n} a={a}");
                let other = Statement {
                    account: s.account,
                    sections: vec![section(100 + a, 7, a as u8 ^ 0x80)],
                };
                assert!(!p.verify(other.leaf_hash(), t.root()));
            }
        }
    }

    #[test]
    fn sections_of_one_account_share_a_leaf_in_book_order() {
        let t1 = StmtTree::build([section(5, 9, 1), section(5, 2, 2)]).unwrap();
        let t2 = StmtTree::build([section(5, 2, 2), section(5, 9, 1)]).unwrap();
        assert_eq!(t1.root(), t2.root());
        assert!(StmtTree::build([section(5, 2, 2), section(5, 2, 3)]).is_none());
    }
}
