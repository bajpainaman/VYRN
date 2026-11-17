//! One voter's Simplex instance: the `commonware-consensus` 2026.10.0 mapping of
//! spec/07-replication.md §6.3.
//!
//! | Simplex hook | Here |
//! |---|---|
//! | `Automaton::propose` | [`App`]: longest valid header run after the parent (≤ 16), once its body is valid (07 §6.3) |
//! | `Automaton::verify` | [`App`]: INV-REP-4 (07 §6.4); pending until `REP_VERIFY_WAIT_MS`, then false |
//! | certify | true exactly when this voter's `verify` (or its own proposal) accepted the payload |
//! | `Relay` | no-op: headers reach voters through frames (07 §6.3) |
//! | `Reporter` | [`Finalized`]: every finalization as a [`FinalityCert`] |
//! | Elector | `RoundRobin` (see the follow-up on its order in the PR) |
//!
//! A voter does not need the proposal bytes to vote: given the parent it rebuilds every candidate
//! range from its own headers and matches the payload digest, so the payload never travels.

use crate::cert::{FinalityCert, NAMESPACE};
use crate::membership::Committee;
use crate::proposal::Proposal;
use crate::source::{BlockSource, Genesis, Tip, Verdict, chain_after, proposal_for};
use commonware_actor::Feedback;
use commonware_codec::DecodeExt;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Relay, Reporter,
    simplex::{
        Plan,
        config::{Config, Floor, ForwardPolicy, SkipBudget, SkipPolicy},
        elector::RoundRobin,
        scheme::ed25519::Scheme,
        types::{Activity, Context, Finalization},
    },
    types::{Epoch as CwEpoch, Round, ViewDelta},
};
use commonware_cryptography::{blake3::Digest, ed25519};
use commonware_p2p::Blocker;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Spawner, buffer::paged::CacheRef};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use vyrn_types::{Ed25519Sig, Epoch, PubKey};

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

/// Payloads this voter has seen, by digest: the proposal and the tip it ends at.
#[derive(Default)]
struct Known {
    tips: BTreeMap<Digest, (Option<Proposal>, Tip)>,
    accepted: BTreeSet<Digest>,
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

impl<E: Clock + Spawner, S: BlockSource> App<E, S> {
    fn tip_of(&self, digest: &Digest) -> Option<Tip> {
        lock(&self.known).tips.get(digest).map(|(_, t)| *t)
    }

    fn accept(&self, digest: Digest, proposal: Proposal, tip: Tip) {
        let mut k = lock(&self.known);
        k.tips.insert(digest, (Some(proposal), tip));
        k.accepted.insert(digest);
    }

    /// The tip of `digest`: known, or rebuilt from the headers after any known tip. A voter that
    /// missed a notarized parent's `verify` still finds it this way, since its range starts right
    /// after a tip the voter knows (07 §6.3 parent rule).
    fn resolve(&self, digest: &Digest) -> Option<Tip> {
        if let Some(tip) = self.tip_of(digest) {
            return Some(tip);
        }
        let tips: Vec<Tip> = lock(&self.known).tips.values().map(|(_, t)| *t).collect();
        let (p, tip) = tips.into_iter().find_map(|t| self.find(t, digest).0)?;
        lock(&self.known).tips.insert(*digest, (Some(p), tip));
        Some(tip)
    }

    /// The candidate after `parent` whose digest is `payload`, with whether the run is complete.
    fn find(&self, parent: Tip, payload: &Digest) -> (Option<(Proposal, Tip)>, bool) {
        let run = chain_after(&self.source, self.epoch, &self.seq_key, parent);
        let full = run.len() as u64 >= crate::proposal::MAX_HDRS_PER_PROPOSAL;
        let hit = run.iter().find_map(|last| {
            let p = proposal_for(&self.source, self.epoch, parent, last);
            (Digest(p.digest().0) == *payload).then(|| {
                let tip = Tip {
                    height: last.height,
                    hash: p.last_hash,
                    last_step: last.last_step,
                };
                (p, tip)
            })
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
        self.context
            .child("propose")
            .spawn(move |clock| async move {
                let Some(parent) = app.resolve(&context.parent.1) else {
                    return; // An unknown parent: decline (consensus drops the view).
                };
                // Wait for at least one header whose body verifies (07 §6.3).
                while !tx.is_closed() {
                    let run = chain_after(&app.source, app.epoch, &app.seq_key, parent);
                    if let Some(last) = run.last() {
                        let p = proposal_for(&app.source, app.epoch, parent, last);
                        match app
                            .source
                            .check_body(app.epoch, p.first_height, p.last_height)
                        {
                            Verdict::Valid => {
                                let digest = Digest(p.digest().0);
                                let tip = Tip {
                                    height: last.height,
                                    hash: p.last_hash,
                                    last_step: last.last_step,
                                };
                                app.accept(digest, p, tip);
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

    async fn verify(&mut self, context: Self::Context, payload: Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let app = self.clone();
        self.context.child("verify").spawn(move |clock| async move {
            let deadline = clock.current() + VERIFY_WAIT;
            let verdict = loop {
                if tx.is_closed() {
                    return;
                }
                if lock(&app.known).accepted.contains(&payload) {
                    break true;
                }
                if let Some(parent) = app.resolve(&context.parent.1) {
                    match app.find(parent, &payload) {
                        (Some((p, tip)), _) => {
                            match app
                                .source
                                .check_body(app.epoch, p.first_height, p.last_height)
                            {
                                Verdict::Valid => {
                                    app.accept(payload, p, tip);
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
    async fn certify(&mut self, _round: Round, payload: Digest) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(lock(&self.known).accepted.contains(&payload));
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
#[derive(Clone)]
pub struct Finalized {
    committee: Committee,
    epoch: Epoch,
    known: Arc<Mutex<Known>>,
    out: mpsc::UnboundedSender<FinalityCert>,
}

impl Finalized {
    fn cert(&self, f: &Finalization<Scheme, Digest>) -> Option<FinalityCert> {
        let mut known = lock(&self.known);
        let proposal = known.tips.get(&f.proposal.payload)?.0?;
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
        // Older payloads are now final ancestors; drop every tip below this one.
        let floor = proposal.last_height;
        known.tips.retain(|_, (_, t)| t.height >= floor);
        Some(FinalityCert {
            epoch: self.epoch,
            view: f.proposal.round.view().get(),
            parent_view: f.proposal.parent.get(),
            proposal,
            sigs,
        })
    }
}

impl Reporter for Finalized {
    type Activity = Activity<Scheme, Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Activity::Finalization(f) = activity
            && let Some(cert) = self.cert(&f)
            && self.out.send(cert).is_err()
        {
            return Feedback::Closed;
        }
        Feedback::Ok
    }
}

/// The Simplex configuration of one voter, with the receiver of its finality certificates.
#[allow(clippy::type_complexity)]
pub fn config<E, S, B>(
    context: E,
    blocker: B,
    cfg: VoterConfig<S>,
) -> Result<
    (
        Config<Scheme, RoundRobin, B, Digest, App<E, S>, App<E, S>, Finalized, Sequential>,
        mpsc::UnboundedReceiver<FinalityCert>,
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
    let genesis = Digest(cfg.genesis.hash.0);
    let known = Arc::new(Mutex::new(Known::default()));
    lock(&known)
        .tips
        .insert(genesis, (None, Tip::from(cfg.genesis)));
    let (out, rx) = mpsc::unbounded_channel();
    let app = App {
        context: Arc::new(context),
        source: cfg.source,
        epoch: cfg.epoch,
        seq_key: cfg.seq_key,
        known: known.clone(),
    };
    let reporter = Finalized {
        committee: cfg.committee,
        epoch: cfg.epoch,
        known,
        out,
    };
    let epoch = CwEpoch::new(u64::from(cfg.epoch.0));
    let t = cfg.timeouts;
    let one = NonZeroUsize::MIN;
    let config = Config {
        scheme,
        elector: RoundRobin::default(),
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
    Ok((config, rx))
}
