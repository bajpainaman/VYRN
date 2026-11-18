//! Whole-committee tests on `commonware-runtime::deterministic` (spec/11-build.md §6.4): a
//! sequencer task writes one signed header per `BLOCK_NS` into a shared [`MemSource`] (standing in
//! for frames reaching every voter), and n Simplex voters over the simulated p2p network order
//! them. Every certificate a voter reports is re-checked with [`verify_finality_cert`].
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::source::Seal;
use crate::source::mem::MemSource;
use crate::tail::{SealExt, seal_header};
use crate::voter::{Timeouts, VoterConfig, config};
use crate::{Committee, FinalityCert, FinalizeVote, Genesis, Listener, verify_finality_cert};
use commonware_consensus::simplex::{Engine, max_payload_size, scheme::ed25519::Scheme};
use commonware_cryptography::{blake3::Digest, ed25519};
use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
use commonware_runtime::{Clock, Handle, Quota, Runner, Spawner, Supervisor, deterministic};
use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::Duration;
use vyrn_log::block::{header_hash, sign_header};
use vyrn_types::{BLOCK_NS, BlockHeader, BookId, Epoch, Hash, Height, Mode, SessionId, StepId};

const SEQ_SEED: [u8; 32] = [0x99; 32];
const EPOCH: Epoch = Epoch(3);

fn seed(i: usize) -> [u8; 32] {
    [u8::try_from(i + 1).unwrap(); 32]
}

fn genesis_header() -> BlockHeader {
    BlockHeader {
        height: Height(0),
        epoch: EPOCH,
        book: BookId(1),
        first_step: StepId(1),
        last_step: StepId(0),
        prev: Hash([0; 32]),
        order_root: Hash([0; 32]),
        data_root: Hash([0; 32]),
        seq_sig: [0; 64],
    }
}

/// The seal a deposed tenure ends with after `last` (07 §9.4), as every voter's source computes it.
fn seal_on(last: &BlockHeader) -> Seal {
    Seal {
        header: seal_header(
            last,
            StepId(last.last_step.0 + 3),
            Hash([0x5A; 32]),
            Hash([0x5B; 32]),
        ),
        ext: SealExt {
            end_frame_seq: [40, 41],
            next_seq: 1,
            next_tenure: 1,
            unavail: vec![(SessionId(3), 7)],
        },
    }
}

/// The sequencer: one header per block, signed with `seq_key`. It never votes. With `stop`, it
/// dies after that height and the voters' sources depose its tenure with [`seal_on`].
fn sequencer(ctx: deterministic::Context, source: MemSource, stop: Option<u64>) -> Handle<()> {
    ctx.child("sequencer").spawn(move |ctx| async move {
        let mut prev = genesis_header();
        loop {
            if stop == Some(prev.height.0) {
                source.depose(seal_on(&prev));
                return;
            }
            ctx.sleep(Duration::from_nanos(BLOCK_NS)).await;
            let h = BlockHeader {
                height: Height(prev.height.0 + 1),
                first_step: StepId(prev.last_step.0 + 1),
                last_step: StepId(prev.last_step.0 + 2),
                prev: header_hash(&prev),
                order_root: Hash([7; 32]),
                data_root: Hash([8; 32]),
                ..prev
            };
            let h = sign_header(&h, &SEQ_SEED);
            source.insert(h);
            prev = h;
        }
    })
}

struct Run {
    committee: Committee,
    /// Per voter, every certificate it reported.
    certs: Vec<Vec<FinalityCert>>,
    /// Certificates the sequencer's listener assembled from the voters' own finalize votes,
    /// received through their wire form (07 §6.8).
    listened: Vec<FinalityCert>,
}

/// Runs an n-voter committee until every live voter holds a certificate at or above `target`.
/// Voter `crash` (if any) is stopped once every voter has finalized `crash_at`.
fn run(mode: Mode, target: u64, crash: Option<(usize, u64)>) -> Run {
    run_with(mode, target, crash, None)
}

/// [`run`], with the sequencer dying after height `stop`, if any.
fn run_with(mode: Mode, target: u64, crash: Option<(usize, u64)>, stop: Option<u64>) -> Run {
    deterministic::Runner::new(
        // A 1 µs cycle: the default 1 ms per event-loop turn would swamp 2 ms Simplex timeouts.
        deterministic::Config::new()
            .with_cycle(Duration::from_micros(1))
            .with_timeout(Some(Duration::from_secs(60))),
    )
    .start(|ctx| async move {
        let n = mode.n();
        let seq_key = vyrn_crypto::ed25519::public_key(&SEQ_SEED);
        let voters: Vec<_> = (0..n)
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .collect();
        let committee = Committee::new(mode, voters.clone(), &[seq_key]).unwrap();
        let keys: Vec<ed25519::PublicKey> = committee.participants().iter().cloned().collect();

        let (network, oracle) = Network::new_with_peers(
            ctx.child("network"),
            NetConfig {
                max_size: commonware_p2p::max_message_size(&[max_payload_size::<Scheme, Digest>(
                    u32::try_from(n).unwrap(),
                )]),
                max_peers_per_set: NonZeroUsize::new(n).unwrap(),
                disconnect_on_block: true,
                tracked_peer_sets: NonZeroUsize::MIN,
            },
            keys.clone(),
        )
        .await;
        network.start();
        // Metro one-way ~0.5 ms (07 §6.6).
        let link = Link {
            latency: Duration::from_micros(500),
            jitter: Duration::from_micros(50),
            success_rate: commonware_utils::probability!(1.0),
        };
        for a in &keys {
            for b in &keys {
                if a != b {
                    oracle
                        .add_link(a.clone(), b.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }
        }

        let g = genesis_header();
        let genesis = Genesis {
            height: g.height,
            hash: header_hash(&g),
            last_step: g.last_step,
        };
        let source = MemSource::default();
        let _seq = sequencer(ctx.child("seq"), source.clone(), stop);

        let quota = Quota::per_second(NonZeroU32::new(1_000_000).unwrap());
        let mut engines = Vec::new();
        let mut receivers = Vec::new();
        let mut vote_rxs = Vec::new();
        let mut listener = Listener::new(committee.clone(), EPOCH, genesis.height);
        let mut listened = Vec::new();
        for (i, voter) in voters.iter().enumerate() {
            let pk = keys
                .iter()
                .find(|k| k.as_ref() == voter.as_slice())
                .unwrap()
                .clone();
            let control = oracle.control(pk);
            let vote = control.register(0, quota).await.unwrap();
            let cert = control.register(1, quota).await.unwrap();
            let resolver = control.register(2, quota).await.unwrap();
            let vctx = ctx.child("voter").with_attribute("index", i);
            let (cfg, out) = config(
                vctx.child("app"),
                control,
                VoterConfig {
                    committee: committee.clone(),
                    vote_seed: seed(i),
                    seq_key,
                    epoch: EPOCH,
                    genesis,
                    source: source.clone(),
                    timeouts: Timeouts::SPEC,
                },
            )
            .unwrap();
            engines.push(Engine::new(vctx.child("engine"), cfg).start(vote, cert, resolver));
            receivers.push(out.certs);
            vote_rxs.push(out.votes);
        }

        let mut certs: Vec<Vec<FinalityCert>> = vec![Vec::new(); n];
        let mut crashed = None;
        loop {
            for (i, rx) in receivers.iter_mut().enumerate() {
                while let Ok(c) = rx.try_recv() {
                    certs[i].push(c);
                }
            }
            for rx in &mut vote_rxs {
                while let Ok(v) = rx.try_recv() {
                    let v = FinalizeVote::decode(&v.encode()).unwrap();
                    // Late votes for a final view, or Ahead after a long gap, are fine here.
                    if let Ok(Some(c)) = listener.on_vote(&v) {
                        listened.push(c);
                    }
                }
            }
            let top = |i: usize| {
                certs[i]
                    .iter()
                    .map(|c| c.proposal.last_height.0)
                    .max()
                    .unwrap_or(0)
            };
            if let Some((who, at)) = crash
                && crashed.is_none()
                && (0..n).all(|i| top(i) >= at)
            {
                engines[who].abort();
                crashed = Some(who);
            }
            let live = (0..n).filter(|i| Some(*i) != crashed);
            if crash.is_none_or(|_| crashed.is_some()) && live.clone().all(|i| top(i) >= target) {
                break;
            }
            ctx.sleep(Duration::from_millis(1)).await;
            if ctx
                .current()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 200
                == 0
            {}
        }
        Run {
            committee,
            certs,
            listened,
        }
    })
}

/// Every certificate verifies offline, and no two voters finalize different proposals in one view.
fn check(run: &Run) {
    let mut by_view: BTreeMap<u64, Hash> = BTreeMap::new();
    // The listener learned finality from votes alone, and agrees with the voters.
    assert!(!run.listened.is_empty(), "the listener never reached Q");
    for c in run.certs.iter().flatten().chain(&run.listened) {
        assert_eq!(verify_finality_cert(c, &run.committee), Ok(()));
        assert!(c.sigs.len() >= run.committee.quorum());
        let d = c.proposal.digest();
        assert_eq!(
            *by_view.entry(c.view).or_insert(d),
            d,
            "fork at view {}",
            c.view
        );
    }
}

#[test]
fn base_committee_of_4_finalizes() {
    let r = run(Mode::Base, 30, None);
    check(&r);
    assert_eq!(r.committee.quorum(), 3);
}

#[test]
fn chain_committee_of_5_finalizes() {
    let r = run(Mode::Chain, 30, None);
    check(&r);
    assert_eq!(r.committee.quorum(), 4);
}

#[test]
fn one_crashed_voter_does_not_stop_finality() {
    for mode in [Mode::Base, Mode::Chain] {
        let r = run(mode, 40, Some((1, 10)));
        check(&r);
        // After the crash, finality still advanced at the others, without voter 1.
        let later = r.certs[0].iter().filter(|c| c.proposal.last_height.0 > 20);
        assert!(later.clone().count() > 0);
        assert!(later.clone().any(|c| c.sigs.iter().all(|(i, _)| *i != 1)));
    }
}

#[test]
fn certificates_from_the_engine_survive_the_wire_format() {
    let r = run(Mode::Base, 5, None);
    let c = &r.certs[0][0];
    let back = FinalityCert::decode(&c.encode()).unwrap();
    assert_eq!(verify_finality_cert(&back, &r.committee), Ok(()));
    // Dropping signatures below Q makes the same certificate prove nothing.
    let mut short = back;
    short.sigs.truncate(2);
    assert_eq!(
        verify_finality_cert(&short, &r.committee),
        Err(crate::CertErr::TooFew { got: 2, need: 3 })
    );
}

#[test]
fn a_deposed_tenure_finalizes_its_seal() {
    // The sequencer dies after height 12; the seal header is height 13 (07 §9.4).
    let r = run_with(Mode::Base, 13, None, Some(12));
    check(&r);
    let seals: Vec<_> = r
        .certs
        .iter()
        .flatten()
        .chain(&r.listened)
        .filter(|c| c.proposal.kind == crate::ProposalKind::Seal)
        .collect();
    assert!(!seals.is_empty(), "no voter finalized the seal");
    for c in seals {
        assert_eq!(c.proposal.last_height, Height(13));
        assert_eq!(c.seal.as_ref().map(|e| e.next_seq), Some(1));
        // The REP_SealExt travels in the certificate's bytes, and the decoded one still verifies.
        let back = FinalityCert::decode(&c.encode()).unwrap();
        assert_eq!(verify_finality_cert(&back, &r.committee), Ok(()));
    }
    // Nothing above the seal is ever final (INV-REP-5).
    assert!(
        r.certs
            .iter()
            .flatten()
            .all(|c| c.proposal.last_height <= Height(13))
    );
}
