//! Slashing evidence (09 §8): the four self-contained kinds, verified against chain state, with
//! the §8.4 amounts, the `CHN_EVIDENCE_EPOCHS` age limit and duplicate suppression.
//!
//! | Kind | Checked by | Slash (bps) | Jail |
//! |---|---|---|---|
//! | `SeqEquivocation` | two `seq_sig`s (vyrn-log), one `SK`, same book and height | 10,000 seq + 5,000 op | yes |
//! | `DoubleVote` | two `VoteMsg` signatures by `VK`s of one operator, one (epoch, view) | 5,000 op | yes |
//! | `DoubleCommit` | two `CommitVote`s, one operator, one (chain_id, second) | 2,500 op | yes |
//! | `BadPost` | `ecrecover` of a `BK` signature on a post the chain did not make | 10,000 op | yes |
//!
//! **Spec gaps (readings chosen).**
//! - ⚠ *`VoteMsg` bytes:* 09 §2.5 gives fields only. Here: `le32 chain_id ‖ le32 epoch ‖ [kind] ‖
//!   le64 view ‖ le64 height ‖ block` (57 B); `ctx` is the `derive_key` context of the signature.
//! - *Duplicate key:* "the same fault by the same operator" is (kind, operator, slot), with slot
//!   (book, height) for `SeqEquivocation`, (epoch, view) for `DoubleVote`, second for
//!   `DoubleCommit` and post number for `BadPost`.
//! - *Age:* evidence is older than 42 epochs when its fault epoch + 42 < the current epoch.
//! - `FenceViolation`, `HandoffWithheld`, `CrossHomeVote`, `Censorship` and `WrongExclusion` need
//!   records 09 does not encode yet (`HandoffRecord` cert, `NodeCert` homes, item proofs); they are
//!   follow-ups.

use std::collections::BTreeSet;

use vyrn_crypto::{derive_key, ed25519};
use vyrn_types::{BlockHeader, BookId, Epoch, Hash, Height, PubKey};

use crate::codec::Writer;
use crate::commit::StateCommit;
use crate::eip712::{self, Address, Domain, Post};
use crate::tesla::OpIdx;

/// The `derive_key` context of consensus votes (09 §17.3).
pub const VOTE_CONTEXT: &str = "vyrn v1 vote";
/// `CHN_EVIDENCE_EPOCHS` (09 §17.1).
pub const EVIDENCE_EPOCHS: u32 = 42;
/// `CHN_REPORTER_SHARE` in basis points (09 §17.1).
pub const REPORTER_SHARE_BPS: u32 = 500;

/// Simplex vote kinds (09 §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VoteKind {
    /// 1.
    Notarize = 1,
    /// 2.
    Nullify = 2,
    /// 3.
    Finalize = 3,
}

/// `VoteMsg` (09 §2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteMsg {
    /// Chain identifier.
    pub chain_id: u32,
    /// Epoch.
    pub epoch: Epoch,
    /// Vote kind.
    pub kind: VoteKind,
    /// Simplex view, from 1.
    pub view: u64,
    /// Chain height of the proposal; 0 for Nullify.
    pub height: Height,
    /// BLAKE3 of the `ChainHeader`; zero for Nullify.
    pub block: Hash,
}

impl VoteMsg {
    /// The 57 bytes (see the module's gap).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(57);
        w.u32(self.chain_id);
        w.u32(self.epoch.0);
        w.u8(match self.kind {
            VoteKind::Notarize => 1,
            VoteKind::Nullify => 2,
            VoteKind::Finalize => 3,
        });
        w.u64(self.view);
        w.u64(self.height.0);
        w.bytes(&self.block.0);
        w.finish()
    }

    /// The message a vote key signs.
    pub fn signing_message(&self) -> [u8; 32] {
        derive_key(VOTE_CONTEXT, &self.encode())
    }
}

/// A signed vote with the key that signed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedVote {
    /// The vote.
    pub msg: VoteMsg,
    /// One of the operator's `VK`s.
    pub key: PubKey,
    /// Ed25519 over [`VoteMsg::signing_message`].
    pub sig: [u8; 64],
}

/// A commit vote with the commit it signs (the hash alone is not enough to check the signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCommit {
    /// The commit.
    pub commit: StateCommit,
    /// The operator's `VK`.
    pub key: PubKey,
    /// Ed25519 over [`StateCommit::signing_message`].
    pub sig: [u8; 64],
}

/// `Evidence` (09 §8.2), the kinds this crate verifies.
// Evidence is rare and off the hot path; boxing the headers would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Two headers for one book and height, both signed by one `SK`.
    SeqEquivocation {
        /// First header.
        a: BlockHeader,
        /// Second header.
        b: BlockHeader,
        /// The `SK` both verify under.
        seq_key: PubKey,
    },
    /// Two conflicting votes by one operator in one (epoch, view).
    DoubleVote {
        /// The operator.
        op: OpIdx,
        /// First vote.
        a: SignedVote,
        /// Second vote.
        b: SignedVote,
    },
    /// Two different commits for one second by one operator.
    DoubleCommit {
        /// The operator.
        op: OpIdx,
        /// First vote.
        a: SignedCommit,
        /// Second vote.
        b: SignedCommit,
    },
    /// A bridge-key signature on a post that differs from the chain's post with that number.
    BadPost {
        /// The signed post.
        post: Post,
        /// `r ‖ s ‖ v`.
        sig: [u8; 65],
    },
}

/// What evidence checks read from chain state.
pub trait EvidenceState {
    /// The current epoch.
    fn current_epoch(&self) -> Epoch;
    /// The operator whose `NodeCert` lists `key` as a seq key valid in `epoch`.
    fn seq_key_owner(&self, epoch: Epoch, key: &PubKey) -> Option<OpIdx>;
    /// Whether `key` is one of `op`'s vote keys valid in `epoch` (any home).
    fn is_vote_key(&self, op: OpIdx, epoch: Epoch, key: &PubKey) -> bool;
    /// The operator whose bridge key is `addr`, under the signer set in force.
    fn bridge_key_owner(&self, addr: &Address) -> Option<OpIdx>;
    /// The struct hash of the chain's own post `post_no`, if it made one.
    fn post_hash(&self, post_no: u64) -> Option<[u8; 32]>;
    /// The bridge's EIP-712 domain.
    fn domain(&self) -> Domain;
}

/// A proven fault and what it costs (09 §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// The faulty operator.
    pub op: OpIdx,
    /// Share of the sequencer bond slashed, in basis points.
    pub seq_bond_bps: u32,
    /// Share of the operator bond slashed, in basis points.
    pub op_bond_bps: u32,
    /// Whether the operator is jailed at the next boundary.
    pub jail: bool,
}

/// Why evidence is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// The two halves do not conflict under the rules of their kind.
    #[error("the evidence does not show a conflict")]
    NoConflict,
    /// A signature does not verify, or the key is not the operator's.
    #[error("bad signature or key")]
    BadSignature,
    /// Older than `CHN_EVIDENCE_EPOCHS`.
    #[error("evidence too old")]
    TooOld,
    /// The same fault by the same operator was already processed (a no-op).
    #[error("duplicate evidence")]
    Duplicate,
}

/// The dedup key of a fault: (kind, operator, slot).
type FaultKey = (u8, OpIdx, u64, u64);

fn too_old(st: &impl EvidenceState, e: Epoch) -> bool {
    u64::from(e.0) + u64::from(EVIDENCE_EPOCHS) < u64::from(st.current_epoch().0)
}

impl Evidence {
    /// Verifies the evidence (09 §8.1 step 1, 2) and returns the fault and its dedup key.
    fn verify(&self, st: &impl EvidenceState) -> Result<(Fault, FaultKey), EvidenceError> {
        use EvidenceError::{BadSignature, NoConflict, TooOld};
        match self {
            Evidence::SeqEquivocation { a, b, seq_key } => {
                if a.book != b.book
                    || a.height != b.height
                    || a.epoch != b.epoch
                    || vyrn_log::block::header_hash(a) == vyrn_log::block::header_hash(b)
                {
                    return Err(NoConflict);
                }
                if too_old(st, a.epoch) {
                    return Err(TooOld);
                }
                let op = st.seq_key_owner(a.epoch, seq_key).ok_or(BadSignature)?;
                if !vyrn_log::block::verify_seq_sig(a, seq_key)
                    || !vyrn_log::block::verify_seq_sig(b, seq_key)
                {
                    return Err(BadSignature);
                }
                let fault = Fault {
                    op,
                    seq_bond_bps: 10_000,
                    op_bond_bps: 5_000,
                    jail: true,
                };
                Ok((fault, (1, op, u64::from(book_u16(a.book)), a.height.0)))
            }
            Evidence::DoubleVote { op, a, b } => {
                let (x, y) = (&a.msg, &b.msg);
                if x.chain_id != y.chain_id || x.epoch != y.epoch || x.view != y.view {
                    return Err(NoConflict);
                }
                let conflict = match (x.kind, y.kind) {
                    (VoteKind::Notarize, VoteKind::Notarize)
                    | (VoteKind::Finalize, VoteKind::Finalize) => x.block != y.block,
                    (VoteKind::Finalize, VoteKind::Nullify)
                    | (VoteKind::Nullify, VoteKind::Finalize) => true,
                    _ => false,
                };
                if !conflict {
                    return Err(NoConflict);
                }
                if too_old(st, x.epoch) {
                    return Err(TooOld);
                }
                for v in [a, b] {
                    if !st.is_vote_key(*op, v.msg.epoch, &v.key)
                        || !ed25519::verify(&v.key, &v.msg.signing_message(), &v.sig)
                    {
                        return Err(BadSignature);
                    }
                }
                let fault = Fault {
                    op: *op,
                    seq_bond_bps: 0,
                    op_bond_bps: 5_000,
                    jail: true,
                };
                Ok((fault, (2, *op, u64::from(x.epoch.0), x.view)))
            }
            Evidence::DoubleCommit { op, a, b } => {
                let (x, y) = (&a.commit, &b.commit);
                if x.chain_id != y.chain_id || x.second != y.second || x.hash() == y.hash() {
                    return Err(NoConflict);
                }
                if too_old(st, x.epoch) {
                    return Err(TooOld);
                }
                for v in [a, b] {
                    if !st.is_vote_key(*op, v.commit.epoch, &v.key)
                        || !ed25519::verify(&v.key, &v.commit.signing_message(), &v.sig)
                    {
                        return Err(BadSignature);
                    }
                }
                let fault = Fault {
                    op: *op,
                    seq_bond_bps: 0,
                    op_bond_bps: 2_500,
                    jail: true,
                };
                Ok((fault, (3, *op, x.second, 0)))
            }
            Evidence::BadPost { post, sig } => {
                let h = post.struct_hash();
                if st.post_hash(post.post_no) == Some(h) {
                    return Err(NoConflict);
                }
                let signer =
                    eip712::recover(&st.domain().digest(&h), sig).map_err(|_| BadSignature)?;
                let op = st.bridge_key_owner(&signer).ok_or(BadSignature)?;
                let fault = Fault {
                    op,
                    seq_bond_bps: 0,
                    op_bond_bps: 10_000,
                    jail: true,
                };
                Ok((fault, (4, op, post.post_no, 0)))
            }
        }
    }
}

fn book_u16(b: BookId) -> u16 {
    b.0
}

/// Processed faults, for duplicate suppression (09 §8.1 step 2).
#[derive(Clone, Debug, Default)]
pub struct EvidenceLedger {
    seen: BTreeSet<FaultKey>,
}

impl EvidenceLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `ev` and records its fault; a second proof of the same fault is `Duplicate`.
    pub fn process(
        &mut self,
        ev: &Evidence,
        st: &impl EvidenceState,
    ) -> Result<Fault, EvidenceError> {
        let (fault, key) = ev.verify(st)?;
        if !self.seen.insert(key) {
            return Err(EvidenceError::Duplicate);
        }
        Ok(fault)
    }
}

/// The reporter's share of `slashed` (`CHN_REPORTER_SHARE`, 5%), rounded down.
pub fn reporter_share(slashed: u128) -> u128 {
    slashed / 10_000 * u128::from(REPORTER_SHARE_BPS)
        + slashed % 10_000 * u128::from(REPORTER_SHARE_BPS) / 10_000
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::signer::{Ed25519Signer, SoftEd25519};
    use vyrn_types::StepId;

    struct St {
        seq: PubKey,
        vks: Vec<PubKey>,
        bk: Address,
        post: Option<[u8; 32]>,
        epoch: u32,
    }
    impl EvidenceState for St {
        fn current_epoch(&self) -> Epoch {
            Epoch(self.epoch)
        }
        fn seq_key_owner(&self, _: Epoch, k: &PubKey) -> Option<OpIdx> {
            (*k == self.seq).then_some(2)
        }
        fn is_vote_key(&self, op: OpIdx, _: Epoch, k: &PubKey) -> bool {
            op == 1 && self.vks.contains(k)
        }
        fn bridge_key_owner(&self, a: &Address) -> Option<OpIdx> {
            (*a == self.bk).then_some(3)
        }
        fn post_hash(&self, _: u64) -> Option<[u8; 32]> {
            self.post
        }
        fn domain(&self) -> Domain {
            Domain {
                chain_id: 1,
                verifying_contract: [7; 20],
            }
        }
    }

    fn st() -> St {
        St {
            seq: SoftEd25519::new([1; 32]).public_key(),
            vks: vec![
                SoftEd25519::new([2; 32]).public_key(),
                SoftEd25519::new([3; 32]).public_key(),
            ],
            bk: eip712::address_of_secret(&[4; 32]).unwrap(),
            post: None,
            epoch: 10,
        }
    }

    fn header(root: u8) -> BlockHeader {
        let mut h = BlockHeader {
            height: Height(5),
            epoch: Epoch(10),
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(2),
            prev: Hash([0; 32]),
            order_root: Hash([root; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        };
        h.seq_sig = vyrn_crypto::ed25519::sign(&[1; 32], &vyrn_log::block::signing_message(&h));
        h
    }

    fn vote(kind: VoteKind, block: u8, seed: u8) -> SignedVote {
        let msg = VoteMsg {
            chain_id: 7,
            epoch: Epoch(10),
            kind,
            view: 3,
            height: Height(9),
            block: Hash([block; 32]),
        };
        let k = SoftEd25519::new([seed; 32]);
        SignedVote {
            msg,
            key: k.public_key(),
            sig: k.sign(&msg.signing_message()).unwrap(),
        }
    }

    #[test]
    fn seq_equivocation_and_duplicates() {
        let s = st();
        let mut l = EvidenceLedger::new();
        let ev = Evidence::SeqEquivocation {
            a: header(1),
            b: header(2),
            seq_key: s.seq,
        };
        let f = l.process(&ev, &s).unwrap();
        assert_eq!(
            (f.op, f.seq_bond_bps, f.op_bond_bps, f.jail),
            (2, 10_000, 5_000, true)
        );
        assert_eq!(l.process(&ev, &s), Err(EvidenceError::Duplicate));
        let same = Evidence::SeqEquivocation {
            a: header(1),
            b: header(1),
            seq_key: s.seq,
        };
        assert_eq!(
            EvidenceLedger::new().process(&same, &s),
            Err(EvidenceError::NoConflict)
        );
        let mut forged = header(3);
        forged.seq_sig[0] ^= 1;
        let bad = Evidence::SeqEquivocation {
            a: header(1),
            b: forged,
            seq_key: s.seq,
        };
        assert_eq!(
            EvidenceLedger::new().process(&bad, &s),
            Err(EvidenceError::BadSignature)
        );
        // Epoch 10 + 42 = 52: still in time at 52, too old at 53.
        assert!(
            EvidenceLedger::new()
                .process(&ev, &St { epoch: 52, ..st() })
                .is_ok()
        );
        assert_eq!(
            EvidenceLedger::new().process(&ev, &St { epoch: 53, ..st() }),
            Err(EvidenceError::TooOld)
        );
    }

    #[test]
    fn double_vote_follows_the_simplex_conflicts() {
        let s = st();
        let dv = |a, b| EvidenceLedger::new().process(&Evidence::DoubleVote { op: 1, a, b }, &s);
        use VoteKind::*;
        // Two keys of one operator count as one operator.
        assert!(dv(vote(Notarize, 1, 2), vote(Notarize, 2, 3)).is_ok());
        assert!(dv(vote(Finalize, 1, 2), vote(Finalize, 2, 2)).is_ok());
        assert!(dv(vote(Nullify, 0, 2), vote(Finalize, 1, 3)).is_ok());
        // Not conflicts: same block, Notarize + Nullify, Notarize + Finalize, another view.
        assert_eq!(
            dv(vote(Notarize, 1, 2), vote(Notarize, 1, 3)),
            Err(EvidenceError::NoConflict)
        );
        assert_eq!(
            dv(vote(Notarize, 1, 2), vote(Nullify, 0, 2)),
            Err(EvidenceError::NoConflict)
        );
        assert_eq!(
            dv(vote(Notarize, 1, 2), vote(Finalize, 2, 2)),
            Err(EvidenceError::NoConflict)
        );
        let mut later = vote(Notarize, 2, 2);
        later.msg.view = 4;
        later.sig = SoftEd25519::new([2; 32])
            .sign(&later.msg.signing_message())
            .unwrap();
        assert_eq!(
            dv(vote(Notarize, 1, 2), later),
            Err(EvidenceError::NoConflict)
        );
        // A key that is not the operator's.
        assert_eq!(
            dv(vote(Notarize, 1, 2), vote(Notarize, 2, 9)),
            Err(EvidenceError::BadSignature)
        );
    }

    #[test]
    fn double_commit_and_bad_post() {
        let s = st();
        let k = SoftEd25519::new([2; 32]);
        let sc = |log: u8| StateCommit {
            chain_id: 7,
            epoch: Epoch(10),
            second: 4,
            height: Height(4_000),
            log_hash: Hash([log; 32]),
            ..Default::default()
        };
        let signed = |c: StateCommit| SignedCommit {
            sig: k.sign(&c.signing_message()).unwrap(),
            key: k.public_key(),
            commit: c,
        };
        let ev = Evidence::DoubleCommit {
            op: 1,
            a: signed(sc(1)),
            b: signed(sc(2)),
        };
        assert_eq!(
            EvidenceLedger::new().process(&ev, &s).unwrap().op_bond_bps,
            2_500
        );
        let same = Evidence::DoubleCommit {
            op: 1,
            a: signed(sc(1)),
            b: signed(sc(1)),
        };
        assert_eq!(
            EvidenceLedger::new().process(&same, &s),
            Err(EvidenceError::NoConflict)
        );

        let post = Post {
            post_no: 3,
            chain_id: 7,
            prev_post: [0; 32],
            commit: [1; 32],
            smt_root: [2; 32],
            deposit_nonce: 0,
            wd_root: [0; 32],
            wd_count: 0,
            wd_totals: vec![],
        };
        let sig = eip712::sign(&s.domain().digest(&post.struct_hash()), &[4; 32]).unwrap();
        let ev = Evidence::BadPost {
            post: post.clone(),
            sig,
        };
        let f = EvidenceLedger::new().process(&ev, &s).unwrap();
        assert_eq!((f.op, f.op_bond_bps), (3, 10_000));
        // The chain's own post is not a fault.
        let honest = St {
            post: Some(post.struct_hash()),
            ..st()
        };
        assert_eq!(
            EvidenceLedger::new().process(&ev, &honest),
            Err(EvidenceError::NoConflict)
        );
        assert_eq!(reporter_share(1_000_001), 50_000);
    }
}
