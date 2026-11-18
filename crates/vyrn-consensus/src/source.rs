//! The block-source boundary: what consensus needs from the log (spec/11-build.md §1.3–1.4,
//! spec/07-replication.md §6.3–6.4).
//!
//! Consensus orders blocks; it never builds them and never calls matching (11 §1.4). It reads
//! headers ([`BlockHeader`], 01 §6.6) and asks one yes/no/not-yet question about the rest of a
//! block. Everything below the header (ORDER bytes, payloads, CHAIN tags) is opaque to this crate
//! and stays with the source. Header bytes, `header_hash` and `seq_sig` are `vyrn-log`'s
//! ([`vyrn_log::block`]); [`LogSource`] is the source backed by a `vyrn-log` [`BlockStore`].
//!
//! Split of the vote rule INV-REP-4 (07 §6.4):
//! - item 1 (headers, `seq_sig`, `prev` chain, step contiguity, `last_hash`) is checked here, from
//!   [`BlockSource::header`], so every source gets the same header rule;
//! - items 2–5 (order bytes, payloads, tags, fences) are [`BlockSource::check_body`].

use crate::proposal::{Proposal, ProposalKind};
use crate::tail::SealExt;
use std::sync::{Arc, PoisonError, RwLock};
use vyrn_log::block::{check_anchor, header_hash, verify_seq_sig};
use vyrn_log::store::BlockStore;
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

    /// `excl_root` for `first ..= last`: 32 zero bytes in BASE, 09's root in CHAIN. For a seal
    /// range it also covers the seal's unavailable packets (07 §9.4).
    fn excl_root(&self, epoch: Epoch, first: Height, last: Height) -> Hash;

    /// The seal of this epoch's deposed tenure, once this voter has seen it deposed and holds
    /// the seal it would propose or accept (07 §9.2–9.4); `None` while the tenure is live. From
    /// the first `Some`, this voter proposes only the seal (INV-REP-5).
    ///
    /// Spec gap: 07 §9.4 does not say how a voter learns the leader's seal header and
    /// `REP_SealExt` behind a 32-byte payload, since `Relay` is a no-op. Reading: the source
    /// holds the candidate (computed from the reports it holds, or received from the leader by
    /// the source itself), and a seal payload that is not this candidate is never accepted.
    fn seal(&self, _epoch: Epoch) -> Option<Seal> {
        None
    }

    /// 07 §9.4's checks on the tail of `seal`: §6.4 items 3 and 4 for the seal header and §9.3
    /// items 3 and 4 (consistency, data). The signed headers below it get [`check_body`]
    /// (BlockSource::check_body) as any range does.
    fn check_seal(&self, _epoch: Epoch, _seal: &Seal) -> Verdict {
        Verdict::Invalid
    }
}

/// A seal candidate (07 §9.4): the seal header on top of `H*` and its `REP_SealExt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    pub header: BlockHeader,
    pub ext: SealExt,
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
        // check_anchor: height, prev and last_step ≥ first_step − 1. Within one epoch the steps
        // also continue from the previous header's.
        if check_anchor(prev_hash, height, &h).is_err()
            || h.epoch != epoch
            || prev_step.0.checked_add(1) != Some(h.first_step.0)
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

/// A [`BlockSource`] over a `vyrn-log` [`BlockStore`], for a voter that restarts or catches up
/// and resolves notarized ranges from its own journal.
///
/// A block is written once, when its `verify` passes (07 §8.2), so a stored range has passed
/// items 2–4 (order bytes, payloads, tags): those never change once true. Item 5 (fences, a
/// seal, `REP_A_DIVERGE`, the state-root gate) can close after the write, so `gate` answers it
/// at every call. [`check_body`](BlockSource::check_body) is `Pending` while a height is not
/// stored, and `gate`'s verdict once all are. Only headers are read ([`BlockStore::header`]);
/// order bytes and payloads stay in the store. A read error counts as not held. `excl_root` is
/// BASE's 32 zero bytes: the CHAIN exclusion root (09) is not part of `REP_BlockRecord`.
pub struct LogSource<St, G> {
    store: Arc<RwLock<St>>,
    gate: G,
}

impl<St, G> LogSource<St, G>
where
    G: Fn(Epoch, Height, Height) -> Verdict,
{
    /// The source over `store`; the caller keeps its handle to write blocks. `gate(epoch, first,
    /// last)` is vote-rule item 5 for the range as of now (07 §6.4).
    pub const fn new(store: Arc<RwLock<St>>, gate: G) -> Self {
        Self { store, gate }
    }
}

impl<St, G: Clone> Clone for LogSource<St, G> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            gate: self.gate.clone(),
        }
    }
}

impl<St, G> BlockSource for LogSource<St, G>
where
    St: BlockStore + Send + Sync + 'static,
    G: Fn(Epoch, Height, Height) -> Verdict + Clone + Send + Sync + 'static,
{
    fn header(&self, height: Height) -> Option<BlockHeader> {
        let store = self.store.read().unwrap_or_else(PoisonError::into_inner);
        store.header(height).ok().flatten()
    }

    fn check_body(&self, epoch: Epoch, first: Height, last: Height) -> Verdict {
        if first > last {
            return Verdict::Invalid;
        }
        // Heights are stored without gaps (BlockStore::put), so the range bounds decide.
        let stored = {
            let store = self.store.read().unwrap_or_else(PoisonError::into_inner);
            store
                .range()
                .is_some_and(|(lo, hi)| lo <= first && last <= hi)
        };
        if stored {
            (self.gate)(epoch, first, last)
        } else {
            Verdict::Pending
        }
    }

    fn excl_root(&self, _: Epoch, _: Height, _: Height) -> Hash {
        Hash([0; 32])
    }
}

#[cfg(test)]
pub(crate) mod mem {
    //! An in-memory source for tests: every body is valid, `excl_root` is zero (BASE).
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Headers by height, and the seal candidate once a test deposes the tenure.
    #[derive(Clone, Default)]
    pub struct MemSource(
        pub Arc<Mutex<BTreeMap<Height, BlockHeader>>>,
        pub Arc<Mutex<Option<Seal>>>,
    );

    impl MemSource {
        pub fn insert(&self, h: BlockHeader) {
            if let Ok(mut m) = self.0.lock() {
                m.insert(h.height, h);
            }
        }

        /// Deposes the tenure: from now on `seal` answers `s` and `check_seal` accepts only it.
        pub fn depose(&self, s: Seal) {
            if let Ok(mut m) = self.1.lock() {
                *m = Some(s);
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
        fn seal(&self, _: Epoch) -> Option<Seal> {
            self.1.lock().ok()?.clone()
        }
        fn check_seal(&self, _: Epoch, s: &Seal) -> Verdict {
            if self.seal(Epoch(0)).as_ref() == Some(s) {
                Verdict::Valid
            } else {
                Verdict::Invalid
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mem::MemSource;
    use super::*;
    use vyrn_log::block::sign_header;
    use vyrn_log::store::{Block, BlockKind, MemStore};
    use vyrn_types::BookId;

    const SEED: [u8; 32] = [0x51; 32];

    fn next(prev: &BlockHeader) -> BlockHeader {
        let h = BlockHeader {
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
        sign_header(&h, &SEED)
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
        let bad = sign_header(&src.header(Height(14)).unwrap_or(base), &[0x52; 32]);
        src.insert(bad);
        let run = chain_after(&src, Epoch(1), &key, tip, 16);
        assert_eq!(run.last().map(|h| h.height), Some(Height(13)));
        let p = proposal_for(&src, Epoch(1), tip, &run[2]);
        assert_eq!((p.first_height, p.last_height), (Height(11), Height(13)));
        assert_eq!(p.last_hash, header_hash(&run[2]));
    }

    #[test]
    fn log_source_reads_headers_from_the_store_and_waits_for_missing_blocks() {
        let key = vyrn_crypto::ed25519::public_key(&SEED);
        let genesis = BlockHeader {
            height: Height(0),
            epoch: Epoch(1),
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(0),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        };
        let block = |header| Block {
            header,
            tenure: 0,
            kind: BlockKind::Normal,
            order_a: Vec::new(),
            order_b: Vec::new(),
            pkt_hashes: Vec::new(),
            data: vec![0xEE; 300],
            unavailable: Vec::new(),
        };
        let store = Arc::new(RwLock::new(MemStore::default()));
        // Item 5 as the replica would report it: a fence over heights ≥ 3 once `fenced` is set.
        let fenced = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = {
            let fenced = Arc::clone(&fenced);
            move |_: Epoch, _: Height, last: Height| {
                if fenced.load(std::sync::atomic::Ordering::SeqCst) && last >= Height(3) {
                    Verdict::Invalid
                } else {
                    Verdict::Valid
                }
            }
        };
        let src = LogSource::new(Arc::clone(&store), gate);
        let mut prev = genesis;
        for _ in 0..5 {
            prev = next(&prev);
            store.write().unwrap().put(&block(prev)).unwrap();
        }
        let tip = Tip {
            height: genesis.height,
            hash: header_hash(&genesis),
            last_step: genesis.last_step,
        };
        let run = chain_after(&src, Epoch(1), &key, tip, 16);
        assert_eq!(run.len(), 5);
        assert_eq!(run.last(), Some(&prev));
        assert_eq!(
            src.check_body(Epoch(1), Height(1), Height(5)),
            Verdict::Valid
        );
        assert_eq!(
            src.check_body(Epoch(1), Height(4), Height(6)),
            Verdict::Pending
        );
        assert_eq!(
            src.check_body(Epoch(1), Height(0), Height(2)),
            Verdict::Pending
        );
        assert_eq!(
            src.check_body(Epoch(1), Height(3), Height(2)),
            Verdict::Invalid
        );
        // Height 6 arrives through the writer's handle; the same source now sees it.
        store.write().unwrap().put(&block(next(&prev))).unwrap();
        assert_eq!(
            src.check_body(Epoch(1), Height(4), Height(6)),
            Verdict::Valid
        );
        assert_eq!(chain_after(&src, Epoch(1), &key, tip, 16).len(), 6);
        // A fence that closes after the blocks were stored rejects them on the next check.
        fenced.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            src.check_body(Epoch(1), Height(1), Height(5)),
            Verdict::Invalid
        );
        assert_eq!(
            src.check_body(Epoch(1), Height(1), Height(2)),
            Verdict::Valid
        );
        // A missing height stays pending whatever the gate says.
        assert_eq!(
            src.check_body(Epoch(1), Height(6), Height(7)),
            Verdict::Pending
        );
    }
}
