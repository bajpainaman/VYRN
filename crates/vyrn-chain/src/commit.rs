//! `StateCommit`, `CommitVote` and `CommitCert` (09 §9.5): once per second, the log hash, the
//! balance SMT root and the order LtHash under 4 vote-key signatures.
//!
//! **Spec gaps (readings chosen).**
//! - *Encoding.* `encode(StateCommit)` is the fields after `ctx` in order, little-endian (01 §3),
//!   with `books` as `le16(count)` then `count × (le16(book) ‖ le64(height))`, books strictly
//!   ascending. `ctx` is not encoded: it is the `derive_key` context of the signature, as with
//!   `VoteMsg` (09 §2.5). 226 + 10 · count bytes.
//! - *Commit hash.* `CommitVote.commit` and `StateCommit.prev` are `BLAKE3(encode(StateCommit))`.
//! - *Signature list.* `CommitCert.sigs` is strictly ascending by `OpIdx`, so each operator counts
//!   once and the encoding is canonical; ≥ 4 entries (`QUORUM`).

use vyrn_crypto::derive_key;
use vyrn_crypto::ed25519;
use vyrn_crypto::hash::hash;
use vyrn_types::{BookId, Epoch, Hash, Height};

use crate::codec::{Reader, Writer};
use crate::signer::{Ed25519Signer, SignerError, sign_checked};
use crate::tesla::OpIdx;

/// The `derive_key` context of commit votes (09 §17.3).
pub const COMMIT_CONTEXT: &str = "vyrn v1 commit";
/// `CHN_COMMIT_BLOCKS` (09 §17.1).
pub const COMMIT_BLOCKS: u64 = 1_000;
/// Matching votes a `CommitCert` needs (4 of 5, 09 §9.5).
pub const QUORUM: usize = 4;
/// The encoded length without `books`.
pub const FIXED_LEN: usize = 226;

/// `StateCommit` (09 §9.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateCommit {
    /// Chain identifier.
    pub chain_id: u32,
    /// The epoch of chain height `height`.
    pub epoch: Epoch,
    /// Chain height `second × CHN_COMMIT_BLOCKS`.
    pub height: Height,
    /// The commit's second k.
    pub second: u64,
    /// `log_hash(height)` (09 §9.2).
    pub log_hash: Hash,
    /// Balance SMT root (09 §9.3).
    pub smt_root: Hash,
    /// LtHash digest of the resting orders (09 §9.4).
    pub orders_lthash: Hash,
    /// Resting orders in the set.
    pub orders_count: u64,
    /// The last book height of each covered book, ascending by book.
    pub books: Vec<(BookId, Height)>,
    /// Hash of the `ParamSet` in force.
    pub params_hash: Hash,
    /// `keys_hash(epoch)` (09 §10.2).
    pub keys_hash: Hash,
    /// The hash of the commit of `second − 1`.
    pub prev: Hash,
}

/// Why a commit, vote or certificate is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// Not the encoding above (short, long, or books not strictly ascending).
    #[error("malformed commit")]
    Malformed,
    /// `height ≠ second × CHN_COMMIT_BLOCKS`.
    #[error("height is not second × CHN_COMMIT_BLOCKS")]
    Height,
    /// It does not follow the previous commit (`second`, `prev`, `chain_id`).
    #[error("does not follow the previous commit")]
    Chain,
    /// Fewer than `QUORUM` signatures, or operators not strictly ascending.
    #[error("signature list is short or not strictly ascending")]
    Signers,
    /// An operator has no vote key for the epoch.
    #[error("unknown operator {0}")]
    UnknownOperator(OpIdx),
    /// A signature does not verify under the operator's vote key.
    #[error("bad signature by operator {0}")]
    BadSignature(OpIdx),
}

impl StateCommit {
    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w =
            Writer::with_capacity(FIXED_LEN.saturating_add(self.books.len().saturating_mul(10)));
        w.u32(self.chain_id);
        w.u32(self.epoch.0);
        w.u64(self.height.0);
        w.u64(self.second);
        w.bytes(&self.log_hash.0);
        w.bytes(&self.smt_root.0);
        w.bytes(&self.orders_lthash.0);
        w.u64(self.orders_count);
        w.u16(u16::try_from(self.books.len()).unwrap_or(u16::MAX));
        for (b, h) in &self.books {
            w.u16(b.0);
            w.u64(h.0);
        }
        w.bytes(&self.params_hash.0);
        w.bytes(&self.keys_hash.0);
        w.bytes(&self.prev.0);
        w.finish()
    }

    /// Reads one commit from the front of `r`.
    fn read(r: &mut Reader<'_>) -> Option<Self> {
        let chain_id = r.u32()?;
        let epoch = Epoch(r.u32()?);
        let height = Height(r.u64()?);
        let second = r.u64()?;
        let log_hash = Hash(r.array()?);
        let smt_root = Hash(r.array()?);
        let orders_lthash = Hash(r.array()?);
        let orders_count = r.u64()?;
        let n = r.u16()?;
        let mut books = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let b = BookId(r.u16()?);
            if books
                .last()
                .is_some_and(|(last, _): &(BookId, Height)| *last >= b)
            {
                return None;
            }
            books.push((b, Height(r.u64()?)));
        }
        Some(Self {
            chain_id,
            epoch,
            height,
            second,
            log_hash,
            smt_root,
            orders_lthash,
            orders_count,
            books,
            params_hash: Hash(r.array()?),
            keys_hash: Hash(r.array()?),
            prev: Hash(r.array()?),
        })
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8]) -> Result<Self, CommitError> {
        let mut r = Reader::new(b);
        let c = Self::read(&mut r).ok_or(CommitError::Malformed)?;
        r.finish().ok_or(CommitError::Malformed)?;
        Ok(c)
    }

    /// `BLAKE3(encode(self))`: what votes and the next commit's `prev` name.
    pub fn hash(&self) -> Hash {
        hash(&self.encode())
    }

    /// The 32-byte message a vote key signs: `derive_key("vyrn v1 commit", encode(self))`.
    pub fn signing_message(&self) -> [u8; 32] {
        derive_key(COMMIT_CONTEXT, &self.encode())
    }

    /// Checks `height = second × CHN_COMMIT_BLOCKS` and, given the previous commit, that this one
    /// is the next second of the same chain and names it in `prev`.
    pub fn check(&self, prev: Option<&StateCommit>) -> Result<(), CommitError> {
        if Some(self.height.0) != self.second.checked_mul(COMMIT_BLOCKS) {
            return Err(CommitError::Height);
        }
        if let Some(p) = prev
            && (p.chain_id != self.chain_id
                || p.second.checked_add(1) != Some(self.second)
                || p.hash() != self.prev)
        {
            return Err(CommitError::Chain);
        }
        Ok(())
    }
}

/// `CommitVote` (09 §9.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitVote {
    /// `StateCommit::hash`.
    pub commit: Hash,
    /// The voting operator.
    pub op: OpIdx,
    /// Ed25519 by `VK(op, home(epoch))` over [`StateCommit::signing_message`].
    pub sig: [u8; 64],
}

impl CommitVote {
    /// Signs `c` as operator `op`, checking the device's output.
    pub fn sign(c: &StateCommit, op: OpIdx, vk: &impl Ed25519Signer) -> Result<Self, SignerError> {
        Ok(Self {
            commit: c.hash(),
            op,
            sig: sign_checked(vk, &c.signing_message())?,
        })
    }

    /// Whether this vote is `vk`'s valid vote for `c`.
    pub fn verify(&self, c: &StateCommit, vk: &[u8; 32]) -> bool {
        self.commit == c.hash() && ed25519::verify(vk, &c.signing_message(), &self.sig)
    }
}

/// `CommitCert` (09 §9.5), item 0x24.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCert {
    /// The commit.
    pub commit: StateCommit,
    /// `(op, sig)`, strictly ascending by op, at least `QUORUM`.
    pub sigs: Vec<(OpIdx, [u8; 64])>,
}

impl CommitCert {
    /// Builds a certificate from votes for `commit`: keeps one vote per operator, sorted. The
    /// result still needs [`Self::verify`].
    pub fn from_votes(commit: StateCommit, votes: &[CommitVote]) -> Self {
        let h = commit.hash();
        let mut sigs: Vec<(OpIdx, [u8; 64])> = votes
            .iter()
            .filter(|v| v.commit == h)
            .map(|v| (v.op, v.sig))
            .collect();
        sigs.sort_by_key(|(op, _)| *op);
        sigs.dedup_by_key(|(op, _)| *op);
        Self { commit, sigs }
    }

    /// `encode(commit) ‖ [n] ‖ n × ([op] ‖ sig)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(&self.commit.encode());
        w.u8(u8::try_from(self.sigs.len()).unwrap_or(u8::MAX));
        for (op, sig) in &self.sigs {
            w.u8(*op);
            w.bytes(sig);
        }
        w.finish()
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8]) -> Result<Self, CommitError> {
        let mut r = Reader::new(b);
        let m = CommitError::Malformed;
        let commit = StateCommit::read(&mut r).ok_or(m)?;
        let n = r.u8().ok_or(m)?;
        let mut sigs = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            sigs.push((r.u8().ok_or(m)?, r.array().ok_or(m)?));
        }
        r.finish().ok_or(m)?;
        Ok(Self { commit, sigs })
    }

    /// Verifies ≥ `QUORUM` strictly ascending operators, each signature under `vote_key(op)` =
    /// `VK(op, home(commit.epoch))` from the epoch's key table (09 §10.2).
    pub fn verify(&self, vote_key: impl Fn(OpIdx) -> Option<[u8; 32]>) -> Result<(), CommitError> {
        if self.sigs.len() < QUORUM
            || self
                .sigs
                .windows(2)
                .any(|w| matches!(w, [a, b] if a.0 >= b.0))
        {
            return Err(CommitError::Signers);
        }
        let msg = self.commit.signing_message();
        for (op, sig) in &self.sigs {
            let vk = vote_key(*op).ok_or(CommitError::UnknownOperator(*op))?;
            if !ed25519::verify(&vk, &msg, sig) {
                return Err(CommitError::BadSignature(*op));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::signer::SoftEd25519;

    fn sc(second: u64, prev: Hash) -> StateCommit {
        StateCommit {
            chain_id: 7,
            epoch: Epoch(3),
            height: Height(second * COMMIT_BLOCKS),
            second,
            log_hash: Hash([1; 32]),
            smt_root: Hash([2; 32]),
            orders_lthash: Hash([3; 32]),
            orders_count: 42,
            books: vec![(BookId(1), Height(10)), (BookId(4), Height(12))],
            params_hash: Hash([4; 32]),
            keys_hash: Hash([5; 32]),
            prev,
        }
    }

    fn keys() -> Vec<SoftEd25519> {
        (0..5u8).map(|i| SoftEd25519::new([i + 1; 32])).collect()
    }

    #[test]
    fn encoding_is_canonical() {
        let c = sc(9, Hash([6; 32]));
        let b = c.encode();
        assert_eq!(b.len(), FIXED_LEN + 20);
        assert_eq!(&b[..4], &7u32.to_le_bytes());
        assert_eq!(&b[16..24], &9u64.to_le_bytes(), "second after height");
        assert_eq!(&b[128..130], &[2, 0], "book count");
        assert_eq!(StateCommit::decode(&b), Ok(c.clone()));
        assert_eq!(
            StateCommit::decode(&b[..b.len() - 1]),
            Err(CommitError::Malformed)
        );
        // Books out of order or repeated do not decode.
        let mut dup = c.clone();
        dup.books[1].0 = BookId(1);
        assert_eq!(
            StateCommit::decode(&dup.encode()),
            Err(CommitError::Malformed)
        );
    }

    #[test]
    fn check_links_seconds() {
        let a = sc(9, Hash([6; 32]));
        let b = sc(10, a.hash());
        assert_eq!(b.check(Some(&a)), Ok(()));
        assert_eq!(sc(11, a.hash()).check(Some(&a)), Err(CommitError::Chain));
        assert_eq!(
            sc(10, Hash([0; 32])).check(Some(&a)),
            Err(CommitError::Chain)
        );
        assert_eq!(
            StateCommit {
                chain_id: 8,
                ..b.clone()
            }
            .check(Some(&a)),
            Err(CommitError::Chain)
        );
        assert_eq!(
            StateCommit {
                height: Height(10_001),
                ..b
            }
            .check(None),
            Err(CommitError::Height)
        );
    }

    #[test]
    fn cert_needs_four_distinct_valid_signers() {
        let c = sc(9, Hash([6; 32]));
        let ks = keys();
        let table = |op: OpIdx| ks.get(usize::from(op)).map(|k| k.public_key());
        let votes: Vec<CommitVote> = (0..5u8)
            .rev()
            .map(|op| CommitVote::sign(&c, op, &ks[usize::from(op)]).unwrap())
            .collect();
        for v in &votes {
            assert!(v.verify(&c, &ks[usize::from(v.op)].public_key()));
            assert!(!v.verify(&sc(10, Hash([6; 32])), &ks[usize::from(v.op)].public_key()));
        }
        let cert = CommitCert::from_votes(c.clone(), &votes[..4]);
        assert_eq!(
            cert.sigs.iter().map(|s| s.0).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(cert.verify(table), Ok(()));
        assert_eq!(CommitCert::decode(&cert.encode()), Ok(cert.clone()));

        // Three signers, or one signer counted twice, is not a quorum.
        let three = CommitCert::from_votes(c.clone(), &votes[..3]);
        assert_eq!(three.verify(table), Err(CommitError::Signers));
        let mut twice = cert.clone();
        twice.sigs[1] = twice.sigs[0];
        assert_eq!(twice.verify(table), Err(CommitError::Signers));
        // A signature from the wrong key, or an operator with no key.
        let mut bad = cert.clone();
        bad.sigs[2].1 = bad.sigs[1].1;
        assert_eq!(bad.verify(table), Err(CommitError::BadSignature(3)));
        assert_eq!(
            cert.verify(|op| (op != 2).then(|| table(op)).flatten()),
            Err(CommitError::UnknownOperator(2))
        );
        // Votes for another commit are dropped by from_votes.
        let other = CommitVote::sign(&sc(10, Hash([6; 32])), 0, &ks[0]).unwrap();
        let mixed = CommitCert::from_votes(c, &[other, votes[0], votes[1], votes[2]]);
        assert_eq!(mixed.sigs.len(), 3);
    }
}
