//! One voter's Simplex instance: the `commonware-consensus` 2026.10.0 mapping of
//! spec/07-replication.md §6.3.
//!
//! | Simplex hook | Here |
//! |---|---|
//! | `Automaton::propose` | [`App`]: longest valid header run after the parent (≤ 16), once its body is valid (07 §6.3) |
//! | `Automaton::verify` | [`App`]: INV-REP-4 (07 §6.4); pending until `REP_VERIFY_WAIT_MS`, then false |
//! | certify | true exactly when this voter's `verify` (or its own proposal) accepted the payload |
//! | `Relay` | no-op: headers reach voters through frames (07 §6.3) |
//! | `Reporter` | [`Finalized`]: every finalization as a [`FinalityCert`], this voter's own finalize votes as [`FinalizeVote`]s for the sequencer's listener (07 §6.8), and conflicting votes as [`VoterFault`] evidence (07 §10.2) |
//! | Elector | [`VoterOrder`]: round-robin in `REP_Membership.voters` order ([`Committee::leader`]) |
//!
//! A voter does not need the proposal bytes to vote: given the parent it rebuilds every candidate
//! range from its own headers and matches the payload digest, so the payload never travels.
//!
//! **Seal** (07 §9.4). Once [`BlockSource::seal`] answers, the tenure is deposed at this voter: as
//! leader it proposes only the kind-1 seal on top of its parent, with payload [`seal_digest`], and
//! as voter it accepts a seal payload only when it is its source's candidate on top of the
//! context's parent and [`BlockSource::check_body`] (the signed headers) and
//! [`BlockSource::check_seal`] (the tail) both pass. Certificates and finalize votes of a seal
//! carry its `REP_SealExt` (07 §6.5).

use crate::cert::{FinalityCert, NAMESPACE};
use crate::evidence::{FaultKind, VoterFault};
use crate::membership::{Committee, VoterOrder};
use crate::observer::FinalizeVote;
use crate::proposal::{MAX_HDRS_PER_PROPOSAL, MAX_SEAL_RANGE, Proposal};
use crate::source::{
    BlockSource, Genesis, Seal, SigCache, Tip, Verdict, chain_after, proposal_for, proposal_range,
};
use crate::tail::{SealExt, seal_digest, seal_proposal};
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    simplex::{
        Plan,
        config::{Config, Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        scheme::ed25519::Scheme,
        types::{Activity, Attributable, Context, Finalization, Finalize},
    },
    types::{Epoch as CwEpoch, Round, ViewDelta},
};
use commonware_cryptography::{blake3::Digest, ed25519};
use commonware_p2p::Blocker;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Spawner, buffer::paged::CacheRef};
use commonware_utils::{
    Participant,
    channel::{fallible::OneshotExt, oneshot},
};
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use vyrn_log::block::header_hash;
use vyrn_types::{BlockHeader, Ed25519Sig, Epoch, Height, PubKey, StepId};

/// `REP_VERIFY_WAIT_MS` (07 §6.4).
pub const VERIFY_WAIT: Duration = Duration::from_millis(4);
/// How often a pending propose or verify asks the source again.
pub const POLL: Duration = Duration::from_micros(100);

/// Simplex timeouts. [`Timeouts::SPEC`] is 07 §6.3 (`REP_DELTA_MS` = 1).
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// `t_l = 2Δ`.
    pub leader: Duration,
    /// `t_a = 3Δ`.
    pub advance: Duration,
    /// Commonware's nullify rebroadcast and inactive-leader skip.
    pub retry: Duration,
    pub skip: Duration,
}

impl Timeouts {
    pub const SPEC: Self = Self {
        leader: Duration::from_millis(2),
        advance: Duration::from_millis(3),
        retry: Duration::from_millis(3),
        skip: Duration::from_millis(4),
    };
}

/// What one voter's instance needs.
pub struct VoterConfig<S> {
    pub committee: Committee,
    /// The 32-byte seed of this voter's `vote_key`.
    pub vote_seed: [u8; 32],
    /// The current tenure's `seq_key` (07 §3.10).
    pub seq_key: PubKey,
    pub epoch: Epoch,
    pub genesis: Genesis,
    pub source: S,
    pub timeouts: Timeouts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VoterErr {
    #[error("vote_seed is not the key of a committee voter; the sequencer never votes (01 §14.4)")]
    NotAVoter,
}

/// How far above its lowest known tip a voter rebuilds a parent it never saw (07 §6.7: a backlog
/// of B blocks clears in about B/16 views). A voter further behind catches up from a snapshot.
pub const RECOVER_HEIGHTS: usize = 4096;

/// What one payload stands for: its proposal (none for genesis), a seal's `REP_SealExt`, and the
/// tip it ends at.
#[derive(Clone, Debug)]
struct Entry {
    proposal: Option<Proposal>,
    seal: Option<SealExt>,
    tip: Tip,
}

impl Entry {
    const fn headers(proposal: Proposal, tip: Tip) -> Self {
        Self {
            proposal: Some(proposal),
            seal: None,
            tip,
        }
    }
}

/// A seal on top of one parent: the payload it would be and what checks it.
struct SealCand {
    seal: Seal,
    proposal: Proposal,
    digest: Digest,
    /// `H*`, the last signed header under the seal header.
    signed_last: Height,
}

impl SealCand {
    fn entry(&self) -> Entry {
        Entry {
            proposal: Some(self.proposal),
            seal: Some(self.seal.ext.clone()),
            tip: Tip {
                height: self.seal.header.height,
                hash: self.proposal.last_hash,
                last_step: self.seal.header.last_step,
            },
        }
    }
}

/// Payloads this voter has seen, by digest.
#[derive(Default)]
struct Known {
    tips: BTreeMap<Digest, Entry>,
    /// `(view, payload)` this voter verified or proposed in that view: what `certify` answers.
    accepted: BTreeSet<(u64, Digest)>,
}

impl Known {
    /// Drops what a finalization at `view` ending at `height` makes unnecessary: tips below the
    /// final one and verdicts of earlier views.
    fn prune(&mut self, view: u64, height: Height) {
        self.tips.retain(|_, e| e.tip.height >= height);
        self.accepted.retain(|(v, _)| *v >= view);
    }
}

/// The Automaton, certifier and relay of one voter.
pub struct App<E, S> {
    /// Shared, because runtime contexts are not `Clone`; tasks spawn from children of it.
    context: Arc<E>,
    source: S,
    epoch: Epoch,
    seq_key: PubKey,
    known: Arc<Mutex<Known>>,
    /// `seq_sig` verdicts under `seq_key`, each header checked once (07 §6.4).
    sigs: Arc<SigCache>,
}

impl<E, S: Clone> Clone for App<E, S> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            source: self.source.clone(),
            epoch: self.epoch,
            seq_key: self.seq_key,
            known: self.known.clone(),
            sigs: self.sigs.clone(),
        }
    }
}

fn lock(known: &Mutex<Known>) -> std::sync::MutexGuard<'_, Known> {
    known.lock().unwrap_or_else(PoisonError::into_inner)
}

fn tip_at(p: &Proposal, last: &BlockHeader) -> Tip {
    Tip {
        height: last.height,
        hash: p.last_hash,
        last_step: last.last_step,
    }
}

impl<E: Clock + Spawner, S: BlockSource> App<E, S> {
    fn accept(&self, view: u64, digest: Digest, entry: Entry) {
        let mut k = lock(&self.known);
        k.tips.insert(digest, entry);
        k.accepted.insert((view, digest));
    }

    /// The seal on top of `parent`, when the source holds one whose header sits on `parent` or on
    /// a held signed header above it, within `REP_MAX_SEAL_RANGE` (07 §9.4).
    fn seal_after(&self, parent: Tip) -> Option<SealCand> {
        let seal = self.source.seal(self.epoch)?;
        let h = &seal.header;
        let (star, star_step) = if h.prev == parent.hash {
            (parent.height, parent.last_step)
        } else {
            let max = usize::try_from(MAX_SEAL_RANGE - 1).unwrap_or(63);
            let run = chain_after(
                &self.source,
                self.epoch,
                &self.seq_key,
                parent,
                max,
                &self.sigs,
            );
            let last = run.iter().find(|r| header_hash(r) == h.prev)?;
            (last.height, last.last_step)
        };
        self.seal_cand(
            Height(parent.height.0.checked_add(1)?),
            seal,
            star,
            star_step,
        )
    }

    /// The seal range `first ..= seal.header.height` on top of `H*` = `star`, if the seal header
    /// sits on it (height and steps) and the range fits `REP_MAX_SEAL_RANGE`.
    fn seal_cand(
        &self,
        first: Height,
        seal: Seal,
        star: Height,
        star_step: StepId,
    ) -> Option<SealCand> {
        let h = &seal.header;
        if h.epoch != self.epoch
            || star.0.checked_add(1) != Some(h.height.0)
            || star_step.0.checked_add(1) != Some(h.first_step.0)
        {
            return None;
        }
        let excl = self.source.excl_root(self.epoch, first, h.height);
        let proposal = seal_proposal(self.epoch, first, h, excl).ok()?;
        let digest = Digest(seal_digest(&proposal, &seal.ext).0);
        Some(SealCand {
            seal,
            proposal,
            digest,
            signed_last: star,
        })
    }

    /// 07 §9.4: §6.4 on the signed headers of the seal range, then the source's tail checks.
    fn check_seal(&self, c: &SealCand) -> Verdict {
        let first = c.proposal.first_height;
        let signed = if c.signed_last >= first {
            self.source.check_body(self.epoch, first, c.signed_last)
        } else {
            Verdict::Valid
        };
        match signed {
            Verdict::Valid => self.source.check_seal(self.epoch, &c.seal),
            v => v,
        }
    }

    /// The proposal and tip of `digest`: known, or rebuilt from held headers. A parent in a
    /// context is notarized (Q voters verified it), so a voter that missed it, or several
    /// proposals before it, finds it as any range of ≤ 16 valid headers above its lowest known tip.
    fn resolve(&self, digest: &Digest) -> Option<Entry> {
        let tips: Vec<Tip> = {
            let k = lock(&self.known);
            if let Some(hit) = k.tips.get(digest) {
                return Some(hit.clone());
            }
            k.tips.values().map(|e| e.tip).collect()
        };
        // A seal on top of a known tip.
        if let Some(c) = tips
            .iter()
            .find_map(|t| self.seal_after(*t).filter(|c| c.digest == *digest))
        {
            let e = c.entry();
            lock(&self.known).tips.insert(*digest, e.clone());
            return Some(e);
        }
        // Cheap: a range right after a known tip.
        let mut hit = tips.iter().find_map(|t| self.find(*t, digest));
        // Deep: any range above the lowest known tip.
        if hit.is_none()
            && let Some(low) = tips.iter().min_by_key(|t| t.height)
        {
            let walk = chain_after(
                &self.source,
                self.epoch,
                &self.seq_key,
                *low,
                RECOVER_HEIGHTS,
                &self.sigs,
            );
            let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
            hit = (0..walk.len()).find_map(|i| {
                walk[i..walk.len().min(i + max)].iter().find_map(|last| {
                    let p = proposal_range(&self.source, self.epoch, walk[i].height, last);
                    (Digest(p.digest().0) == *digest).then(|| (p, tip_at(&p, last)))
                })
            });
            // A seal starting at any held height up to `H*`, within REP_MAX_SEAL_RANGE.
            if hit.is_none()
                && let Some(seal) = self.source.seal(self.epoch)
                && let Some(at) = walk.iter().position(|h| header_hash(h) == seal.header.prev)
            {
                let star = &walk[at];
                let span = usize::try_from(MAX_SEAL_RANGE - 1).unwrap_or(63);
                let firsts = walk[at.saturating_sub(span - 1)..=at]
                    .iter()
                    .map(|f| f.height)
                    .chain(star.height.0.checked_add(1).map(Height));
                let found = firsts.into_iter().find_map(|first| {
                    self.seal_cand(first, seal.clone(), star.height, star.last_step)
                        .filter(|c| c.digest == *digest)
                });
                if let Some(c) = found {
                    let e = c.entry();
                    lock(&self.known).tips.insert(*digest, e.clone());
                    return Some(e);
                }
            }
        }
        let (p, tip) = hit?;
        let e = Entry::headers(p, tip);
        lock(&self.known).tips.insert(*digest, e.clone());
        Some(e)
    }

    /// The candidate after `parent` whose digest is `payload`.
    fn find(&self, parent: Tip, payload: &Digest) -> Option<(Proposal, Tip)> {
        let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
        let run = chain_after(
            &self.source,
            self.epoch,
            &self.seq_key,
            parent,
            max,
            &self.sigs,
        );
        run.iter().find_map(|last| {
            let p = proposal_for(&self.source, self.epoch, parent, last);
            (Digest(p.digest().0) == *payload).then(|| (p, tip_at(&p, last)))
        })
    }
}

impl<E, S> Automaton for App<E, S>
where
    E: Clock + Spawner,
    S: BlockSource,
{
    type Context = Context<Digest, ed25519::PublicKey>;
    type Digest = Digest;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Digest> {
        let (tx, rx) = oneshot::channel();
        let app = self.clone();
        let view = context.round.view().get();
        self.context
            .child("propose")
            .spawn(move |clock| async move {
                let Some(parent) = app.resolve(&context.parent.1).map(|e| e.tip) else {
                    return; // An unknown parent: decline (consensus drops the view).
                };
                let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
                // Wait for at least one header whose body verifies (07 §6.3).
                while !tx.is_closed() {
                    // A deposed tenure: the seal or nothing (07 §9.2, INV-REP-5).
                    if let Some(c) = app.seal_after(parent) {
                        match app.check_seal(&c) {
                            Verdict::Valid => {
                                app.accept(view, c.digest, c.entry());
                                tx.send_lossy(c.digest);
                                return;
                            }
                            Verdict::Invalid => return,
                            Verdict::Pending => {}
                        }
                        clock.sleep(POLL).await;
                        continue;
                    }
                    if app.source.seal(app.epoch).is_some() {
                        return; // Deposed, and the seal does not extend this parent.
                    }
                    let run =
                        chain_after(&app.source, app.epoch, &app.seq_key, parent, max, &app.sigs);
                    if let Some(last) = run.last() {
                        let p = proposal_for(&app.source, app.epoch, parent, last);
                        match app
                            .source
                            .check_body(app.epoch, p.first_height, p.last_height)
                        {
                            Verdict::Valid => {
                                let digest = Digest(p.digest().0);
                                app.accept(view, digest, Entry::headers(p, tip_at(&p, last)));
                                tx.send_lossy(digest);
                                return;
                            }
                            Verdict::Invalid => return,
                            Verdict::Pending => {}
                        }
                    }
                    clock.sleep(POLL).await;
                }
            });
        rx
    }

    /// INV-REP-4 against this context's parent, every time: an earlier acceptance of the same
    /// payload under another parent proves nothing, and fences (item 5) may have closed since.
    async fn verify(&mut self, context: Self::Context, payload: Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let app = self.clone();
        let view = context.round.view().get();
        self.context.child("verify").spawn(move |clock| async move {
            let deadline = clock.current() + VERIFY_WAIT;
            let verdict = loop {
                if tx.is_closed() {
                    return;
                }
                let parent = app.resolve(&context.parent.1).map(|e| e.tip);
                let seal = parent.and_then(|t| app.seal_after(t).filter(|c| c.digest == payload));
                if let Some(c) = seal {
                    match app.check_seal(&c) {
                        Verdict::Valid => {
                            app.accept(view, payload, c.entry());
                            break true;
                        }
                        Verdict::Invalid => break false,
                        Verdict::Pending => {}
                    }
                } else if let Some(parent) = parent
                    // No match, even from a full run, is no contradiction: the payload may be a
                    // seal this voter's source does not hold yet (07 §9.4).
                    && let Some((p, tip)) = app.find(parent, &payload)
                {
                    match app
                        .source
                        .check_body(app.epoch, p.first_height, p.last_height)
                    {
                        Verdict::Valid => {
                            app.accept(view, payload, Entry::headers(p, tip));
                            break true;
                        }
                        Verdict::Invalid => break false,
                        Verdict::Pending => {}
                    }
                }
                if clock.current() >= deadline {
                    break false;
                }
                clock.sleep(POLL).await;
            };
            tx.send_lossy(verdict);
        });
        rx
    }
}

impl<E, S> CertifiableAutomaton for App<E, S>
where
    E: Clock + Spawner,
    S: BlockSource,
{
    /// 07 §6.3: certify returns the result of `verify` for the same payload, and adds nothing.
    /// Keyed by `(round, payload)`, as Commonware requires.
    async fn certify(&mut self, round: Round, payload: Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let ok = lock(&self.known)
            .accepted
            .contains(&(round.view().get(), payload));
        tx.send_lossy(ok);
        rx
    }
}

impl<E: Send + Sync + 'static, S: Clone + Send + 'static> Relay for App<E, S> {
    type Digest = Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = Plan<ed25519::PublicKey>;

    /// No-op (07 §6.3).
    fn broadcast(&mut self, _payload: Digest, _plan: Self::Plan) -> Feedback {
        Feedback::Ok
    }
}

/// The reporter: every finalization this voter learns, as a `REP_FinalityCert` (07 §6.5).
pub struct Finalized<E, S> {
    app: App<E, S>,
    committee: Committee,
    epoch: Epoch,
    out: mpsc::UnboundedSender<FinalityCert>,
    /// This voter's Commonware signer index, and where its own finalize votes go.
    me: Participant,
    votes: mpsc::UnboundedSender<FinalizeVote>,
    faults: mpsc::UnboundedSender<VoterFault>,
}

impl<E, S: Clone> Clone for Finalized<E, S> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            committee: self.committee.clone(),
            epoch: self.epoch,
            out: self.out.clone(),
            me: self.me,
            votes: self.votes.clone(),
            faults: self.faults.clone(),
        }
    }
}

impl<E: Clock + Spawner, S: BlockSource> Finalized<E, S> {
    fn cert(&self, f: &Finalization<Scheme, Digest>) -> Option<FinalityCert> {
        // A finalization of a payload this voter never saw is rebuilt from its headers.
        let entry = self.app.resolve(&f.proposal.payload)?;
        let proposal = entry.proposal?;
        let mut sigs: Vec<(u8, Ed25519Sig)> = f
            .certificate
            .signers
            .iter()
            .zip(&f.certificate.signatures)
            .filter_map(|(p, sig)| {
                let bytes: &[u8] = sig.get()?.as_ref();
                Some((self.committee.voter_of(p)?, bytes.try_into().ok()?))
            })
            .collect();
        sigs.sort_by_key(|(i, _)| *i);
        let view = f.proposal.round.view().get();
        lock(&self.app.known).prune(view, proposal.last_height);
        self.app.sigs.prune(proposal.last_height);
        Some(FinalityCert {
            epoch: self.epoch,
            view,
            parent_view: f.proposal.parent.get(),
            proposal,
            sigs,
            seal: entry.seal,
        })
    }
}

impl<E: Clock + Spawner, S: BlockSource> Finalized<E, S> {
    /// Hands out Simplex conflict evidence as a [`VoterFault`]. Optional output, like votes.
    fn fault(&self, kind: FaultKind, signer: Participant, votes: Vec<u8>) {
        if let Some(voter) = self.committee.voter_of(signer) {
            let _ = self.faults.send(VoterFault { kind, voter, votes });
        }
    }

    /// This voter's own finalize vote, for the sequencer and the standby (07 §6.8).
    fn own_vote(&self, f: &Finalize<Scheme, Digest>) -> Option<FinalizeVote> {
        if f.attestation.signer != self.me {
            return None;
        }
        let entry = self.app.resolve(&f.proposal.payload)?;
        let proposal = entry.proposal?;
        let sig: &[u8] = f.attestation.signature.get()?.as_ref();
        Some(FinalizeVote {
            epoch: self.epoch,
            view: f.proposal.round.view().get(),
            parent_view: f.proposal.parent.get(),
            proposal,
            index: self.committee.voter_of(self.me)?,
            sig: sig.try_into().ok()?,
            seal: entry.seal,
        })
    }
}

impl<E: Clock + Spawner, S: BlockSource> Reporter for Finalized<E, S> {
    type Activity = Activity<Scheme, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let closed = match activity {
            Activity::Finalization(f) => self.cert(&f).is_some_and(|c| self.out.send(c).is_err()),
            Activity::Finalize(f) => {
                // Optional output: a dropped receiver discards votes, never stops the reporter.
                if let Some(v) = self.own_vote(&f) {
                    let _ = self.votes.send(v);
                }
                false
            }
            Activity::ConflictingNotarize(c) => {
                self.fault(
                    FaultKind::ConflictingNotarize,
                    c.signer(),
                    c.encode().to_vec(),
                );
                false
            }
            Activity::ConflictingFinalize(c) => {
                self.fault(
                    FaultKind::ConflictingFinalize,
                    c.signer(),
                    c.encode().to_vec(),
                );
                false
            }
            Activity::NullifyFinalize(c) => {
                self.fault(FaultKind::NullifyFinalize, c.signer(), c.encode().to_vec());
                false
            }
            _ => false,
        };
        if closed {
            return Feedback::Closed;
        }
        Feedback::Ok
    }
}

/// What one voter's instance hands out besides Simplex itself. Dropping `certs` stops the
/// reporter; dropping any other receiver only discards what it would carry.
pub struct Outputs {
    /// Every finalization this voter learns, as a `REP_FinalityCert` (07 §6.5).
    pub certs: mpsc::UnboundedReceiver<FinalityCert>,
    /// This voter's own finalize votes, to send to the sequencer's and the standby's
    /// `REP_UDP_CTRL` (07 §6.8).
    pub votes: mpsc::UnboundedReceiver<FinalizeVote>,
    /// Conflicting votes this voter's Simplex saw, as evidence against their voter (07 §10.2).
    pub faults: mpsc::UnboundedReceiver<VoterFault>,
}

/// The Simplex configuration of one voter, with its [`Outputs`].
#[allow(clippy::type_complexity)]
pub fn config<E, S, B>(
    context: E,
    blocker: B,
    cfg: VoterConfig<S>,
) -> Result<
    (
        Config<Scheme, VoterOrder, B, Digest, App<E, S>, App<E, S>, Finalized<E, S>, Sequential>,
        Outputs,
    ),
    VoterErr,
>
where
    E: Clock + Spawner,
    S: BlockSource,
    B: Blocker<PublicKey = ed25519::PublicKey>,
{
    let index = cfg
        .committee
        .index_of(&vyrn_crypto::ed25519::public_key(&cfg.vote_seed))
        .ok_or(VoterErr::NotAVoter)?;
    let key =
        ed25519::PrivateKey::decode(cfg.vote_seed.to_vec()).map_err(|_| VoterErr::NotAVoter)?;
    let scheme = Scheme::signer(NAMESPACE, cfg.committee.participants().clone(), key)
        .ok_or(VoterErr::NotAVoter)?;
    let elector = cfg.committee.elector();
    let genesis = Digest(cfg.genesis.hash.0);
    let known = Arc::new(Mutex::new(Known::default()));
    lock(&known).tips.insert(
        genesis,
        Entry {
            proposal: None,
            seal: None,
            tip: Tip::from(cfg.genesis),
        },
    );
    let (out, certs) = mpsc::unbounded_channel();
    let (votes, votes_rx) = mpsc::unbounded_channel();
    let (faults, faults_rx) = mpsc::unbounded_channel();
    let own_key = vyrn_crypto::ed25519::public_key(&cfg.vote_seed);
    let me = cfg
        .committee
        .participants()
        .iter()
        .position(|k| {
            let bytes: &[u8] = k.as_ref();
            bytes == own_key.as_slice()
        })
        .map(Participant::from_usize)
        .ok_or(VoterErr::NotAVoter)?;
    let app = App {
        context: Arc::new(context),
        source: cfg.source,
        epoch: cfg.epoch,
        seq_key: cfg.seq_key,
        known: known.clone(),
        sigs: Arc::default(),
    };
    let reporter = Finalized {
        app: app.clone(),
        committee: cfg.committee,
        epoch: cfg.epoch,
        out,
        me,
        votes,
        faults,
    };
    let epoch = CwEpoch::new(u64::from(cfg.epoch.0));
    let t = cfg.timeouts;
    let one = NonZeroUsize::MIN;
    let config = Config {
        scheme,
        elector,
        blocker,
        automaton: app.clone(),
        relay: app,
        reporter,
        track_historical_votes: false,
        strategy: Sequential,
        // One journal per (epoch, voter): Commonware requires a unique partition per epoch.
        partition: format!("vyrn-consensus-{}-{index}", cfg.epoch.0),
        mailbox_size: one.saturating_mul(NonZeroUsize::new(1024).unwrap_or(one)),
        epoch,
        floor: Floor::Genesis(genesis),
        replay_buffer: NonZeroUsize::new(1 << 20).unwrap_or(one),
        write_buffer: NonZeroUsize::new(1 << 20).unwrap_or(one),
        page_cache: CacheRef::new(
            NonZeroU16::new(1024).unwrap_or(NonZeroU16::MIN),
            NonZeroUsize::new(16).unwrap_or(one),
        ),
        leader_timeout: t.leader,
        certification_timeout: t.advance,
        timeout_retry: t.retry,
        view_retention: ViewDelta::new(64),
        skip: SkipPolicy::Enabled {
            timeout: t.skip,
            budget: SkipBudget::Participants,
        },
        fetch_timeout: commonware_utils::NonZeroDuration::new(t.advance).unwrap_or(
            commonware_utils::NonZeroDuration::new(Duration::from_millis(1))
                .unwrap_or_else(|| unreachable!()),
        ),
        fetch_retry_delay: POLL,
        forward: ForwardPolicy::Disabled,
    };
    Ok((
        config,
        Outputs {
            certs,
            votes: votes_rx,
            faults: faults_rx,
        },
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::source::mem::MemSource;
    use commonware_consensus::types::View;
    use commonware_runtime::{Runner, Supervisor, deterministic};
    use vyrn_log::block::{header_hash, sign_header};
    use vyrn_types::{BookId, Hash, StepId};

    const SEQ: [u8; 32] = [0x99; 32];
    const EPOCH: Epoch = Epoch(3);

    /// Headers `1..=n` chained on a genesis header at height 0, and the genesis tip.
    fn chain(n: u64) -> (MemSource, Tip) {
        let mut prev = BlockHeader {
            height: Height(0),
            epoch: EPOCH,
            book: BookId(1),
            first_step: StepId(1),
            last_step: StepId(0),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        };
        let genesis = Tip {
            height: Height(0),
            hash: header_hash(&prev),
            last_step: StepId(0),
        };
        let src = MemSource::default();
        for _ in 0..n {
            let h = BlockHeader {
                height: Height(prev.height.0 + 1),
                first_step: StepId(prev.last_step.0 + 1),
                last_step: StepId(prev.last_step.0 + 1),
                prev: header_hash(&prev),
                ..prev
            };
            let h = sign_header(&h, &SEQ);
            src.insert(h);
            prev = h;
        }
        (src, genesis)
    }

    fn digest(src: &MemSource, first: u64, last: u64) -> Digest {
        let h = src.header(Height(last)).unwrap();
        Digest(proposal_range(src, EPOCH, Height(first), &h).digest().0)
    }

    /// Runs `f` with an App that knows only the genesis tip.
    fn with_app<F, Fut>(n: u64, f: F)
    where
        F: FnOnce(App<deterministic::Context, MemSource>, MemSource, Digest) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let cfg = deterministic::Config::new()
            .with_cycle(Duration::from_micros(1))
            .with_timeout(Some(Duration::from_secs(5)));
        deterministic::Runner::new(cfg).start(|ctx| async move {
            let (src, genesis) = chain(n);
            let known = Arc::new(Mutex::new(Known::default()));
            let g = Digest(genesis.hash.0);
            lock(&known).tips.insert(
                g,
                Entry {
                    proposal: None,
                    seal: None,
                    tip: genesis,
                },
            );
            let app = App {
                context: Arc::new(ctx.child("app")),
                source: src.clone(),
                epoch: EPOCH,
                seq_key: vyrn_crypto::ed25519::public_key(&SEQ),
                known,
                sigs: Arc::default(),
            };
            f(app, src, g).await;
        });
    }

    fn ctx(view: u64, parent_view: u64, parent: Digest) -> Context<Digest, ed25519::PublicKey> {
        let leader =
            ed25519::PublicKey::decode(vyrn_crypto::ed25519::public_key(&[1; 32]).to_vec())
                .unwrap();
        Context {
            round: Round::new(CwEpoch::new(u64::from(EPOCH.0)), View::new(view)),
            leader,
            parent: (View::new(parent_view), parent),
        }
    }

    #[test]
    fn a_cached_payload_under_another_parent_is_rejected() {
        with_app(3, |mut app, src, g| async move {
            let p12 = digest(&src, 1, 2);
            let p3 = digest(&src, 3, 3);
            assert!(app.verify(ctx(1, 0, g), p12).await.await.unwrap());
            assert!(app.verify(ctx(2, 1, p12), p3).await.await.unwrap());
            // Heights 1–2 again, now as a child of a proposal ending at 3: the parent rule fails.
            assert!(!app.verify(ctx(3, 2, p3), p12).await.await.unwrap());
            // certify answers per round: view 3 never verified it.
            assert!(app.certify(ctx(1, 0, g).round, p12).await.await.unwrap());
            assert!(!app.certify(ctx(3, 2, p3).round, p12).await.await.unwrap());
        });
    }

    #[test]
    fn a_distant_parent_is_rebuilt_from_headers() {
        with_app(40, |mut app, src, _| async move {
            // The voter knows only genesis; the parent covers 17–32, two ranges ahead.
            let parent = digest(&src, 17, 32);
            let child = digest(&src, 33, 34);
            assert!(app.verify(ctx(5, 4, parent), child).await.await.unwrap());
            // A digest that is no range of held headers stays unresolved.
            assert!(app.resolve(&digest(&src, 17, 33)).is_none());
        });
    }

    fn seal_of(src: &MemSource, star: u64) -> Seal {
        let last = src.header(Height(star)).unwrap();
        Seal {
            header: crate::tail::seal_header(
                &last,
                StepId(last.last_step.0 + 2),
                Hash([0x5A; 32]),
                Hash([0x5B; 32]),
            ),
            ext: SealExt {
                end_frame_seq: [9, 8],
                next_seq: 1,
                next_tenure: 1,
                unavail: vec![(vyrn_types::SessionId(3), 7)],
            },
        }
    }

    fn seal_payload(seal: &Seal, first: u64) -> Digest {
        let p = seal_proposal(EPOCH, Height(first), &seal.header, Hash([0; 32])).unwrap();
        Digest(seal_digest(&p, &seal.ext).0)
    }

    #[test]
    fn a_deposed_leader_proposes_the_seal_and_voters_verify_it() {
        with_app(5, |mut app, src, g| async move {
            let seal = seal_of(&src, 5);
            let want = seal_payload(&seal, 1);
            src.depose(seal.clone());
            // The leader proposes the seal over 1..=6 (five signed headers and the seal header),
            // not the kind-0 range it would have proposed before.
            let got = app.propose(ctx(1, 0, g)).await.await.unwrap();
            assert_eq!(got, want);
            assert!(app.verify(ctx(1, 0, g), want).await.await.unwrap());
            // The same seal with another REP_SealExt is not this voter's candidate.
            let mut other = seal.clone();
            other.ext.next_seq = 2;
            assert!(
                !app.verify(ctx(2, 0, g), seal_payload(&other, 1))
                    .await
                    .await
                    .unwrap()
            );
            // Its entry keeps the REP_SealExt for the certificate.
            let e = app.resolve(&want).unwrap();
            assert_eq!(e.seal, Some(seal.ext.clone()));
            assert_eq!(e.tip.height, Height(6));
            // On top of a notarized 1..=2, the seal starts at 3.
            let p12 = digest(&src, 1, 2);
            assert!(app.verify(ctx(3, 0, g), p12).await.await.unwrap());
            let on12 = seal_payload(&seal, 3);
            assert!(app.verify(ctx(4, 3, p12), on12).await.await.unwrap());
            // Nothing extends the seal: a leader whose parent is the seal declines.
            assert!(app.propose(ctx(5, 1, want)).await.await.is_err());
        });
    }

    #[test]
    fn a_seal_over_an_unseen_parent_is_rebuilt_from_headers() {
        with_app(20, |app, src, _| async move {
            // Only genesis is known; the finalized seal covers 17..=21 on top of an unseen 1..=16.
            let seal = seal_of(&src, 20);
            src.depose(seal.clone());
            let e = app.resolve(&seal_payload(&seal, 17)).unwrap();
            assert_eq!(e.proposal.map(|p| p.first_height), Some(Height(17)));
            assert_eq!((e.tip.height, e.seal), (Height(21), Some(seal.ext)));
        });
    }

    #[test]
    fn a_long_seal_waits_for_its_headers_and_candidate() {
        with_app(20, |mut app, src, g| async move {
            let seal = seal_of(&src, 20);
            // This voter holds 1..=16 and no candidate yet: a full kind-0 run, no match.
            let late: Vec<_> = (17..=20).map(|h| src.header(Height(h)).unwrap()).collect();
            src.0.lock().unwrap().retain(|h, _| h.0 <= 16);
            let rx = app.verify(ctx(1, 0, g), seal_payload(&seal, 1)).await;
            for h in late {
                src.insert(h);
            }
            src.depose(seal);
            assert!(rx.await.unwrap());
        });
    }

    #[test]
    fn finalization_prunes_tips_and_verdicts() {
        let mut k = Known::default();
        let tip = |h: u64| Tip {
            height: Height(h),
            hash: Hash([0; 32]),
            last_step: StepId(h),
        };
        for v in 1..=10u64 {
            let d = Digest([u8::try_from(v).unwrap(); 32]);
            k.tips.insert(
                d,
                Entry {
                    proposal: None,
                    seal: None,
                    tip: tip(v),
                },
            );
            k.accepted.insert((v, d));
        }
        k.prune(8, Height(8));
        assert_eq!(k.tips.len(), 3);
        assert_eq!(
            k.accepted.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            vec![8, 9, 10]
        );
    }
}
