//! One voter's Simplex instance: the `commonware-consensus` 2026.10.0 mapping of
//! spec/07-replication.md §6.3.
//!
//! | Simplex hook | Here |
//! |---|---|
//! | `Automaton::propose` | [`App`]: longest valid header run after the parent (≤ 16), once its body is valid (07 §6.3) |
//! | `Automaton::verify` | [`App`]: INV-REP-4 (07 §6.4); pending until `REP_VERIFY_WAIT_MS`, then false |
//! | certify | true exactly when this voter's `verify` (or its own proposal) accepted the payload |
//! | `Relay` | no-op: headers reach voters through frames (07 §6.3) |
//! | `Reporter` | [`Finalized`]: every finalization as a [`FinalityCert`], and this voter's own finalize votes as [`FinalizeVote`]s for the sequencer's listener (07 §6.8) |
//! | Elector | [`VoterOrder`]: round-robin in `REP_Membership.voters` order ([`Committee::leader`]) |
//!
//! A voter does not need the proposal bytes to vote: given the parent it rebuilds every candidate
//! range from its own headers and matches the payload digest, so the payload never travels.

use crate::cert::{FinalityCert, NAMESPACE};
use crate::membership::{Committee, VoterOrder};
use crate::observer::FinalizeVote;
use crate::proposal::{MAX_HDRS_PER_PROPOSAL, Proposal};
use crate::source::{
    BlockSource, Genesis, Tip, Verdict, chain_after, proposal_for, proposal_range,
};
use commonware_actor::Feedback;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    simplex::{
        Plan,
        config::{Config, Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        scheme::ed25519::Scheme,
        types::{Activity, Context, Finalization, Finalize},
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
use vyrn_types::{BlockHeader, Ed25519Sig, Epoch, Height, PubKey};

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

/// Payloads this voter has seen, by digest: the proposal and the tip it ends at.
#[derive(Default)]
struct Known {
    tips: BTreeMap<Digest, (Option<Proposal>, Tip)>,
    /// `(view, payload)` this voter verified or proposed in that view: what `certify` answers.
    accepted: BTreeSet<(u64, Digest)>,
}

impl Known {
    /// Drops what a finalization at `view` ending at `height` makes unnecessary: tips below the
    /// final one and verdicts of earlier views.
    fn prune(&mut self, view: u64, height: Height) {
        self.tips.retain(|_, (_, t)| t.height >= height);
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
}

impl<E, S: Clone> Clone for App<E, S> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            source: self.source.clone(),
            epoch: self.epoch,
            seq_key: self.seq_key,
            known: self.known.clone(),
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
    fn accept(&self, view: u64, digest: Digest, proposal: Proposal, tip: Tip) {
        let mut k = lock(&self.known);
        k.tips.insert(digest, (Some(proposal), tip));
        k.accepted.insert((view, digest));
    }

    /// The proposal and tip of `digest`: known, or rebuilt from held headers. A parent in a
    /// context is notarized (Q voters verified it), so a voter that missed it, or several
    /// proposals before it, finds it as any range of ≤ 16 valid headers above its lowest known tip.
    fn resolve(&self, digest: &Digest) -> Option<(Option<Proposal>, Tip)> {
        let tips: Vec<Tip> = {
            let k = lock(&self.known);
            if let Some(hit) = k.tips.get(digest) {
                return Some(*hit);
            }
            k.tips.values().map(|(_, t)| *t).collect()
        };
        // Cheap: a range right after a known tip.
        let mut hit = tips.iter().find_map(|t| self.find(*t, digest).0);
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
            );
            let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
            hit = (0..walk.len()).find_map(|i| {
                walk[i..walk.len().min(i + max)].iter().find_map(|last| {
                    let p = proposal_range(&self.source, self.epoch, walk[i].height, last);
                    (Digest(p.digest().0) == *digest).then(|| (p, tip_at(&p, last)))
                })
            });
        }
        let (p, tip) = hit?;
        lock(&self.known).tips.insert(*digest, (Some(p), tip));
        Some((Some(p), tip))
    }

    /// The candidate after `parent` whose digest is `payload`, with whether the run is complete.
    fn find(&self, parent: Tip, payload: &Digest) -> (Option<(Proposal, Tip)>, bool) {
        let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
        let run = chain_after(&self.source, self.epoch, &self.seq_key, parent, max);
        let full = run.len() >= max;
        let hit = run.iter().find_map(|last| {
            let p = proposal_for(&self.source, self.epoch, parent, last);
            (Digest(p.digest().0) == *payload).then(|| (p, tip_at(&p, last)))
        });
        (hit, full)
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
                let Some((_, parent)) = app.resolve(&context.parent.1) else {
                    return; // An unknown parent: decline (consensus drops the view).
                };
                let max = usize::try_from(MAX_HDRS_PER_PROPOSAL).unwrap_or(16);
                // Wait for at least one header whose body verifies (07 §6.3).
                while !tx.is_closed() {
                    let run = chain_after(&app.source, app.epoch, &app.seq_key, parent, max);
                    if let Some(last) = run.last() {
                        let p = proposal_for(&app.source, app.epoch, parent, last);
                        match app
                            .source
                            .check_body(app.epoch, p.first_height, p.last_height)
                        {
                            Verdict::Valid => {
                                let digest = Digest(p.digest().0);
                                app.accept(view, digest, p, tip_at(&p, last));
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
                if let Some((_, parent)) = app.resolve(&context.parent.1) {
                    match app.find(parent, &payload) {
                        (Some((p, tip)), _) => {
                            match app
                                .source
                                .check_body(app.epoch, p.first_height, p.last_height)
                            {
                                Verdict::Valid => {
                                    app.accept(view, payload, p, tip);
                                    break true;
                                }
                                Verdict::Invalid => break false,
                                Verdict::Pending => {}
                            }
                        }
                        // Every possible range is held and none matches: a contradiction.
                        (None, true) => break false,
                        (None, false) => {}
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
        }
    }
}

impl<E: Clock + Spawner, S: BlockSource> Finalized<E, S> {
    fn cert(&self, f: &Finalization<Scheme, Digest>) -> Option<FinalityCert> {
        // A finalization of a payload this voter never saw is rebuilt from its headers.
        let proposal = self.app.resolve(&f.proposal.payload)?.0?;
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
        Some(FinalityCert {
            epoch: self.epoch,
            view,
            parent_view: f.proposal.parent.get(),
            proposal,
            sigs,
        })
    }
}

impl<E: Clock + Spawner, S: BlockSource> Finalized<E, S> {
    /// This voter's own finalize vote, for the sequencer and the standby (07 §6.8).
    fn own_vote(&self, f: &Finalize<Scheme, Digest>) -> Option<FinalizeVote> {
        if f.attestation.signer != self.me {
            return None;
        }
        let proposal = self.app.resolve(&f.proposal.payload)?.0?;
        let sig: &[u8] = f.attestation.signature.get()?.as_ref();
        Some(FinalizeVote {
            epoch: self.epoch,
            view: f.proposal.round.view().get(),
            parent_view: f.proposal.parent.get(),
            proposal,
            index: self.committee.voter_of(self.me)?,
            sig: sig.try_into().ok()?,
        })
    }
}

impl<E: Clock + Spawner, S: BlockSource> Reporter for Finalized<E, S> {
    type Activity = Activity<Scheme, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let closed = match activity {
            Activity::Finalization(f) => self.cert(&f).is_some_and(|c| self.out.send(c).is_err()),
            Activity::Finalize(f) => self
                .own_vote(&f)
                .is_some_and(|v| self.votes.send(v).is_err()),
            _ => false,
        };
        if closed {
            return Feedback::Closed;
        }
        Feedback::Ok
    }
}

/// What one voter's instance hands out besides Simplex itself.
pub struct Outputs {
    /// Every finalization this voter learns, as a `REP_FinalityCert` (07 §6.5).
    pub certs: mpsc::UnboundedReceiver<FinalityCert>,
    /// This voter's own finalize votes, to send to the sequencer's and the standby's
    /// `REP_UDP_CTRL` (07 §6.8).
    pub votes: mpsc::UnboundedReceiver<FinalizeVote>,
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
    lock(&known)
        .tips
        .insert(genesis, (None, Tip::from(cfg.genesis)));
    let (out, certs) = mpsc::unbounded_channel();
    let (votes, votes_rx) = mpsc::unbounded_channel();
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
    };
    let reporter = Finalized {
        app: app.clone(),
        committee: cfg.committee,
        epoch: cfg.epoch,
        out,
        me,
        votes,
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
            lock(&known).tips.insert(g, (None, genesis));
            let app = App {
                context: Arc::new(ctx.child("app")),
                source: src.clone(),
                epoch: EPOCH,
                seq_key: vyrn_crypto::ed25519::public_key(&SEQ),
                known,
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
            k.tips.insert(d, (None, tip(v)));
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
