//! Post assembly by the validators and post review by the guardians (09 §6.4, §6.5).
//!
//! Both read the chain through [`Replica`] and the bridge signer table through [`Epochs`]; neither
//! talks to L1. A relayer carries the [`Post`] and its signatures to `proposePost`, and a guardian
//! process that gets [`Verdict::Veto`] sends `veto(postNo)`.

use vyrn_types::Hash;

use crate::eip712::{Address, Domain, Post, SigError, count_sigs};
use crate::wdtree::{self, Withdrawal};
use crate::{Epochs, Replica};

/// The state one post checkpoints (09 §6.4): a finalized `StateCommit` and the withdrawals that
/// state moved to `pending_posted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Hash of the `StateCommit` (09 §9.5).
    pub commit: Hash,
    /// Its `smt_root`; the SMT already reflects the debits of `withdrawals`.
    pub smt_root: Hash,
    /// Highest deposit nonce credited in that state.
    pub deposit_nonce: u64,
    /// The withdrawals of this post.
    pub withdrawals: Vec<Withdrawal>,
}

/// Why a post cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// A withdrawal names a token the bridge does not list.
    #[error("withdrawal token is not a listed asset")]
    UnlistedToken,
    /// A per-asset total overflows uint256.
    #[error("withdrawal total overflows")]
    Overflow,
    /// More than u32::MAX withdrawals.
    #[error("too many withdrawals")]
    TooMany,
}

/// Builds post `post_no` from `cp`. `prev_post` is the struct hash of post `post_no − 1` (zero for
/// post 1); `assets` is the bridge's `assets()` list.
pub fn build_post(
    chain_id: u32,
    post_no: u64,
    prev_post: [u8; 32],
    cp: &Checkpoint,
    assets: &[Address],
) -> Result<Post, BuildError> {
    let wd_totals = wdtree::totals(&cp.withdrawals, assets).ok_or_else(|| {
        if cp.withdrawals.iter().all(|w| assets.contains(&w.token)) {
            BuildError::Overflow
        } else {
            BuildError::UnlistedToken
        }
    })?;
    Ok(Post {
        post_no,
        chain_id,
        prev_post,
        commit: cp.commit.0,
        smt_root: cp.smt_root.0,
        deposit_nonce: cp.deposit_nonce,
        wd_root: wdtree::root(&cp.withdrawals),
        wd_count: u32::try_from(cp.withdrawals.len()).map_err(|_| BuildError::TooMany)?,
        wd_totals,
    })
}

/// Why a guardian vetoes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VetoReason {
    /// This replica has no finalized `StateCommit` with the post's `commit`.
    UnknownCommit,
    /// This replica has no post `post_no − 1` to chain `prev_post` from.
    UnknownPrev,
    /// The chain has not made post `post_no`, so nothing can match it.
    UnknownPost,
    /// The struct hash differs from the chain's own post with the same number (`BadPost`, §6.5).
    NotCanonical,
    /// The post differs from the one this replica computes for the same commit.
    Differs,
}

/// A guardian's decision on a proposed post.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The post is the chain's own; let the challenge period run.
    Accept,
    /// Veto it. `signers` is the bitmask of bridge keys that signed it: with ≥ 4 valid signatures
    /// on a wrong post, that is `BadPost` evidence against them (09 §6.5, §8.2).
    Veto {
        /// Why.
        reason: VetoReason,
        /// Bit i = BK_i signed.
        signers: u8,
    },
    /// L1 rejects these signatures itself, so there is nothing to veto.
    Ignore(SigError),
    /// The signer set of `rotation_no` is unknown here: escalate, do not guess.
    UnknownSignerSet,
}

/// A guardian process of one operator (09 §6.5).
pub struct Guardian<'a, R: Replica, E: Epochs> {
    /// Its own validator's view of the chain.
    pub replica: &'a R,
    /// The bridge signer table.
    pub epochs: &'a E,
    /// The EIP-712 domain of the bridge it watches.
    pub domain: Domain,
    /// VYRN chain id.
    pub chain_id: u32,
    /// The bridge's `assets()`.
    pub assets: &'a [Address],
}

impl<R: Replica, E: Epochs> Guardian<'_, R, E> {
    /// Reviews `post` as L1 accepted it under signer rotation `rotation_no`.
    pub fn review<S: AsRef<[u8]>>(&self, rotation_no: u64, post: &Post, sigs: &[S]) -> Verdict {
        let Some(set) = self.epochs.bridge_signers(rotation_no) else {
            return Verdict::UnknownSignerSet;
        };
        let digest = self.domain.digest(&post.struct_hash());
        let signers = match count_sigs(&digest, sigs, &set.bridge_keys) {
            Ok(mask) => mask,
            Err(e) => return Verdict::Ignore(e),
        };
        let veto = |reason| Verdict::Veto { reason, signers };
        // 09 §6.5: the post must be the chain's post with this number. Recomputing from the
        // commit alone would accept an older finalized checkpoint reposted under a new number.
        match self.replica.post_hash(post.post_no) {
            None => return veto(VetoReason::UnknownPost),
            Some(h) if h != post.struct_hash() => return veto(VetoReason::NotCanonical),
            Some(_) => {}
        }
        let Some(cp) = self.replica.checkpoint(&Hash(post.commit)) else {
            return veto(VetoReason::UnknownCommit);
        };
        let prev = match post.post_no.checked_sub(1) {
            None | Some(0) => [0u8; 32],
            Some(p) => match self.replica.post_hash(p) {
                Some(h) => h,
                None => return veto(VetoReason::UnknownPrev),
            },
        };
        match build_post(self.chain_id, post.post_no, prev, &cp, self.assets) {
            Ok(expected) if expected == *post => Verdict::Accept,
            _ => veto(VetoReason::Differs),
        }
    }
}
