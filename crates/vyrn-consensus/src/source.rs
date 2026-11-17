//! The block-source boundary: what consensus needs from the log (spec/11-build.md §1.3–1.4,
//! spec/07-replication.md §6.3–6.4).
//!
//! Consensus orders blocks; it never builds them and never calls matching (11 §1.4). It reads
//! headers ([`BlockHeader`], 01 §6.6) and asks one yes/no/not-yet question about the rest of a
//! block. Everything below the header (ORDER bytes, payloads, CHAIN tags) is opaque to this crate
//! and stays with the source, which is `vyrn-log` in production.
//!
//! Split of the vote rule INV-REP-4 (07 §6.4):
//! - item 1 (headers, `seq_sig`, `prev` chain, step contiguity, `last_hash`) is checked here, from
//!   [`BlockSource::header`], so every source gets the same header rule;
//! - items 2–5 (order bytes, payloads, tags, fences) are [`BlockSource::check_body`].

use crate::header::{header_hash, verify_seq_sig};
use crate::proposal::{Proposal, ProposalKind};
use vyrn_types::{BlockHeader, Epoch, Hash, Height, PubKey, StepId};

/// Answer of the source about a block range (07 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every item holds.
    Valid,
    /// A contradiction: a root mismatch after repair, a fence. Final for this range.
    Invalid,
    /// Something is still missing (a frame, a payload, a tag verdict). Ask again.
    Pending,
}

/// What a voter holds of the log. Implementations must be cheap to call repeatedly: consensus
/// polls while a range is pending.
pub trait BlockSource: Clone + Send + Sync + 'static {
    /// The header at `height` with its `seq_sig`, if held. Validity is checked by the caller.
    fn header(&self, height: Height) -> Option<BlockHeader>;

    /// Vote-rule items 2–5 for `first ..= last` (07 §6.4). BASE sources ignore item 4.
    fn check_body(&self, epoch: Epoch, first: Height, last: Height) -> Verdict;

    /// `excl_root` for `first ..= last`: 32 zero bytes in BASE, 09's root in CHAIN.
    fn excl_root(&self, epoch: Epoch, first: Height, last: Height) -> Hash;
}

/// Where one epoch's Simplex instance starts: the HandoffRecord's last block (07 §6.3, 08).
/// The genesis Simplex payload is `hash`, the `header_hash` of that block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Genesis {
    pub height: Height,
    pub hash: Hash,
    pub last_step: StepId,
}

/// The last block of a parent proposal: what the next range must chain from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tip {
    pub height: Height,
    pub hash: Hash,
    pub last_step: StepId,
}

impl From<Genesis> for Tip {
    fn from(g: Genesis) -> Self {
        Self {
            height: g.height,
            hash: g.hash,
            last_step: g.last_step,
        }
    }
}

/// The longest run (≤ `limit`) of held headers after `tip` that pass item 1 under `seq_key`, in
/// ascending order. With `limit` = 16 these are the candidate last headers of a proposal.
pub(crate) fn chain_after<S: BlockSource>(
    source: &S,
    epoch: Epoch,
    seq_key: &PubKey,
    tip: Tip,
    limit: usize,
) -> Vec<BlockHeader> {
    let mut out = Vec::new();
    let (mut prev_hash, mut prev_step, mut height) = (tip.hash, tip.last_step, tip.height);
    while out.len() < limit {
        let Some(next) = height.0.checked_add(1).map(Height) else {
            break;
        };
        let Some(h) = source.header(next) else {
            break;
        };
        let contiguous = prev_step.0.checked_add(1) == Some(h.first_step.0)
            && h.last_step
                .0
                .checked_add(1)
                .is_some_and(|l| l >= h.first_step.0);
        if h.height != next
            || h.epoch != epoch
            || h.prev != prev_hash
            || !contiguous
            || !verify_seq_sig(&h, seq_key)
        {
            break;
        }
        prev_hash = header_hash(&h);
        prev_step = h.last_step;
        height = next;
        out.push(h);
    }
    out
}

/// The kind-0 proposal covering `tip.height + 1 ..= last.height`.
pub(crate) fn proposal_for<S: BlockSource>(
    source: &S,
    epoch: Epoch,
    tip: Tip,
    last: &BlockHeader,
) -> Proposal {
    proposal_range(source, epoch, Height(tip.height.0.saturating_add(1)), last)
}

/// The kind-0 proposal covering `first ..= last.height`.
pub(crate) fn proposal_range<S: BlockSource>(
    source: &S,
    epoch: Epoch,
    first: Height,
    last: &BlockHeader,
) -> Proposal {
    Proposal {
        kind: ProposalKind::Headers,
        epoch,
        first_height: first,
        last_height: last.height,
        last_hash: header_hash(last),
        excl_root: source.excl_root(epoch, first, last.height),
    }
}

#[cfg(test)]
pub(crate) mod mem {
    //! An in-memory source for tests: every body is valid, `excl_root` is zero (BASE).
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub struct MemSource(pub Arc<Mutex<BTreeMap<Height, BlockHeader>>>);

    impl MemSource {
        pub fn insert(&self, h: BlockHeader) {
            if let Ok(mut m) = self.0.lock() {
                m.insert(h.height, h);
            }
        }
    }

    impl BlockSource for MemSource {
        fn header(&self, height: Height) -> Option<BlockHeader> {
            self.0.lock().ok()?.get(&height).copied()
        }
        fn check_body(&self, _: Epoch, _: Height, _: Height) -> Verdict {
            Verdict::Valid
        }
        fn excl_root(&self, _: Epoch, _: Height, _: Height) -> Hash {
            Hash([0; 32])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mem::MemSource;
    use super::*;
    use crate::header::seq_sign;
    use vyrn_types::BookId;

    const SEED: [u8; 32] = [0x51; 32];

    fn next(prev: &BlockHeader) -> BlockHeader {
        let mut h = BlockHeader {
            height: Height(prev.height.0 + 1),
            epoch: prev.epoch,
            book: prev.book,
            first_step: StepId(prev.last_step.0 + 1),
            last_step: StepId(prev.last_step.0 + 3),
            prev: header_hash(prev),
            order_root: Hash([4; 32]),
            data_root: Hash([5; 32]),
            seq_sig: [0; 64],
        };
        h.seq_sig = seq_sign(&SEED, &h);
        h
    }

    #[test]
    fn chain_stops_at_the_first_broken_link_and_at_16() {
        let key = vyrn_crypto::ed25519::public_key(&SEED);
        let base = BlockHeader {
            height: Height(10),
            epoch: Epoch(1),
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(20),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        };
        let tip = Tip {
            height: base.height,
            hash: header_hash(&base),
            last_step: base.last_step,
        };
        let src = MemSource::default();
        let mut prev = base;
        for _ in 0..20 {
            prev = next(&prev);
            src.insert(prev);
        }
        assert_eq!(chain_after(&src, Epoch(1), &key, tip, 16).len(), 16);
        // A header whose seq_sig is not the sequencer's ends the run before it.
        let mut bad = src.header(Height(14)).unwrap_or(base);
        bad.seq_sig = seq_sign(&[0x52; 32], &bad);
        src.insert(bad);
        let run = chain_after(&src, Epoch(1), &key, tip, 16);
        assert_eq!(run.last().map(|h| h.height), Some(Height(13)));
        let p = proposal_for(&src, Epoch(1), tip, &run[2]);
        assert_eq!((p.first_height, p.last_height), (Height(11), Height(13)));
        assert_eq!(p.last_hash, header_hash(&run[2]));
    }
}
