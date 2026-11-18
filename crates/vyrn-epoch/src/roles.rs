//! The role state machines of a handoff (08 §4.2–4.5), force seal (§4.3), and halt and
//! reassignment (§10.3).
//!
//! Each machine is a value with one transition function, `on(event)`, which returns the next state
//! or a [`RoleErr`] naming the state and the event that cannot follow it. The machines read no
//! clock: the timing rules are separate pure predicates ([`lane_seals`], [`force_seal_due`],
//! [`failover_kind`], [`halt_due`], [`reassign_open`]) over PTP times the caller logs, so a
//! replica that replays the log reaches the same states (`INV-DET`).
//!
//! | Machine | Spec | States |
//! |---|---|---|
//! | [`OldSeq`] | §4.2 | Active → Deciding → Armed → Sealing → Sealed(S) → Follower; a hold returns to Active |
//! | [`OldReplica`] | §4.3 | Voting → WaitFinal → Replayed → Signed → Fenced(S) → Follower; or Voting → ForceSeal → Fenced(S) |
//! | [`NewReplica`] | §4.4 | Follower → Preparing → Collecting → Voting → Activated; Collecting → Faulty → Follower |
//! | [`NewSeq`] | §4.5 | Follower → Preparing → Collect → Apply(S′) → Uncross → Live (on Q `EpoArmed`); S′ ≠ S re-specs; a force-sealed epoch goes Collect → Uncross on the root at S |
//!
//! Signed messages: [`EpoForceSeal`] (each voter of `R_e`, vote key) and [`EpoReassign`]
//! (operator keys). Their bodies and contexts are spec gaps, listed on each type.

use crate::membership::Membership;
use crate::{Domain, NS_PER_S};
use std::collections::BTreeMap;
use thiserror::Error;
use vyrn_types::{BookId, Ed25519Sig, Epoch, Hash, Height, HomeCode, Nanos, PubKey, StepId};

const NS_PER_US: u64 = 1_000;
const NS_PER_MS: u64 = 1_000_000;
/// An idle lane seals this long after T (08 §4.2 step 1).
pub const EPO_SEAL_SLACK_US: u64 = 5;
/// `R_e` force-seals this long after T without a `Seal` frame (08 §4.3).
pub const EPO_SEAL_GRACE_MS: u64 = 5;
/// A failover that starts later than this before T runs in seal mode (= `FAILOVER_TARGET_MS`).
pub const EPO_SEAL_GUARD_MS: u64 = 20;
/// The new control core logs `EpoHalt` this long after T without a certificate (08 §10.3).
pub const EPO_HALT_COLLECT_MS: u64 = 250;
/// The old home pages operators this long after the seal without `EpoActivated` (08 §10.3).
pub const EPO_ACTIVATE_ALARM_MS: u64 = 1_500;
/// The earliest manual reassignment after T (08 §10.3).
pub const EPO_REASSIGN_MIN_S: u64 = 60;
/// The signing context of [`EpoForceSeal`] (spec gap: 08 names none) [Guessing].
pub const FORCE_SEAL_CONTEXT: &str = "vyrn      v1 force seal";
/// The signing context of [`EpoReassign`] (spec gap: 08 names none) [Guessing].
pub const REASSIGN_CONTEXT: &str = "vyrn      v1 reassign";

fn add(t: Nanos, ns: u64) -> Nanos {
    Nanos(t.0.saturating_add(ns))
}

// ---------------------------------------------------------------------------------------------
// Timing rules
// ---------------------------------------------------------------------------------------------

/// §4.2 step 1: a lane applies a packet only if `rx_ts < T`; its first packet with `rx_ts ≥ T`
/// seals it.
pub fn lane_seals(rx_ts: Nanos, t: Nanos) -> bool {
    rx_ts >= t
}

/// §4.2 step 1: a lane that receives nothing seals when the control core's PTP time passes
/// `T + EPO_SEAL_SLACK_US`.
pub fn idle_lane_seals(ptp: Nanos, t: Nanos) -> bool {
    ptp > add(t, EPO_SEAL_SLACK_US * NS_PER_US)
}

/// §4.3: a voter of `R_e` force-seals when its PTP clock passes `T + EPO_SEAL_GRACE_MS` with no
/// `Seal` frame.
pub fn force_seal_due(ptp: Nanos, t: Nanos, seal_frame_seen: bool) -> bool {
    !seal_frame_seen && ptp > add(t, EPO_SEAL_GRACE_MS * NS_PER_MS)
}

/// What a failover of the old sequencer does (§4.3 "Failover guard", §10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailoverKind {
    /// Before `T − EPO_SEAL_GUARD_MS`: promote the old home's standby, which trades until T.
    Promote,
    /// Later: finalize the longest prefix and promote no one; S is its last step.
    SealMode,
}

/// §4.3: the kind of a failover that starts at `start`.
pub fn failover_kind(start: Nanos, t: Nanos) -> FailoverKind {
    if start.0 < t.0.saturating_sub(EPO_SEAL_GUARD_MS * NS_PER_MS) {
        FailoverKind::Promote
    } else {
        FailoverKind::SealMode
    }
}

/// §10.3: the new control core logs `EpoHalt` once its PTP time reaches
/// `T + EPO_HALT_COLLECT_MS` without a verified certificate.
pub fn halt_due(ptp: Nanos, t: Nanos, cert_held: bool) -> bool {
    !cert_held && ptp >= add(t, EPO_HALT_COLLECT_MS * NS_PER_MS)
}

/// §10.3: the old home pages operators at `seal + EPO_ACTIVATE_ALARM_MS` without `EpoActivated`.
pub fn activate_alarm_due(ptp: Nanos, seal: Nanos, activated: bool) -> bool {
    !activated && ptp >= add(seal, EPO_ACTIVATE_ALARM_MS * NS_PER_MS)
}

/// §10.3: operators may reassign from `T + EPO_REASSIGN_MIN_S`.
///
/// Spec gap: 08 says "after `EPO_REASSIGN_MIN_S`" without an origin. This crate counts from T
/// [Likely]: the halt is a function of T, and T is in the log.
pub fn reassign_open(now: Nanos, t: Nanos) -> bool {
    now >= add(t, EPO_REASSIGN_MIN_S * NS_PER_S)
}

// ---------------------------------------------------------------------------------------------
// Machines
// ---------------------------------------------------------------------------------------------

/// A transition that the machine does not allow from its state.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{event} cannot follow {state}")]
pub struct RoleErr {
    /// The state, as `Debug` prints it.
    pub state: String,
    /// The event, as `Debug` prints it.
    pub event: String,
}

fn illegal<S: core::fmt::Debug, E: core::fmt::Debug>(s: &S, e: &E) -> RoleErr {
    RoleErr {
        state: format!("{s:?}"),
        event: format!("{e:?}"),
    }
}

/// The old sequencer (§4.2). The old standby runs the same machine as a follower.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldSeq {
    Active,
    /// From `T − EPO_GO_LEAD_S` until the go/no-go is final.
    Deciding,
    /// `EpoGo` is final; T is fixed.
    Armed,
    /// At least one lane has sealed.
    Sealing,
    /// The `Seal` step S ran and the last block of e is signed.
    Sealed(StepId),
    /// cert(e, S) seen: answers strays with `EPOCH_MISMATCH` (§10.7) and follows e+1.
    Follower,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldSeqEv {
    GoLead,
    GoFinal,
    /// `EpoHold` is final: T moves to `t_new`, back to Active.
    HoldFinal,
    /// A lane saw `rx_ts ≥ T`, or the idle-lane slack passed.
    LaneSealed,
    /// Every lane sealed, the final cut was drained, and the `Seal` step S ran.
    SealStep(StepId),
    CertSeen,
}

impl OldSeq {
    pub fn on(self, ev: OldSeqEv) -> Result<Self, RoleErr> {
        use OldSeqEv as E;
        Ok(match (self, ev) {
            (Self::Active, E::GoLead) => Self::Deciding,
            (Self::Deciding, E::GoFinal) => Self::Armed,
            (Self::Deciding, E::HoldFinal) => Self::Active,
            (Self::Armed, E::LaneSealed) | (Self::Sealing, E::LaneSealed) => Self::Sealing,
            (Self::Sealing, E::SealStep(s)) => Self::Sealed(s),
            (Self::Sealed(_), E::CertSeen) => Self::Follower,
            (s, e) => return Err(illegal(&s, &e)),
        })
    }
}

/// A voter of the old replica set `R_e` (§4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldReplica {
    Voting,
    /// The `Seal` frame arrived; waiting for the block that contains S to be final.
    WaitFinal(StepId),
    /// That block is final; replaying to S.
    Replay(StepId),
    /// `state_root` and `log_hash` at S are ready and its `HandoffSig` is persisted and sent.
    Signed(StepId),
    /// No `Seal` frame by `T + EPO_SEAL_GRACE_MS`: `EpoForceSeal` sent, seal-mode failover.
    ForceSeal,
    /// Q signatures on one record are held: `INV-FENCE` applies from here (§8).
    Fenced(StepId),
    Follower,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldReplicaEv {
    SealFrame(StepId),
    BlockFinal,
    RootReady,
    /// [`force_seal_due`] became true.
    GraceExpired,
    /// Seal mode finalized its prefix; S is that prefix's last step.
    PrefixFinal(StepId),
    /// Q valid `HandoffSig` on one record with this S.
    QuorumSigs(StepId),
    Activated,
}

impl OldReplica {
    pub fn on(self, ev: OldReplicaEv) -> Result<Self, RoleErr> {
        use OldReplicaEv as E;
        Ok(match (self, ev) {
            (Self::Voting, E::SealFrame(s)) => Self::WaitFinal(s),
            (Self::Voting, E::GraceExpired) => Self::ForceSeal,
            (Self::WaitFinal(s), E::BlockFinal) => Self::Replay(s),
            (Self::Replay(s), E::RootReady) => Self::Signed(s),
            // Seal mode ends like the ordinary path: the replica replays to S and signs.
            (Self::ForceSeal, E::PrefixFinal(s)) => Self::Replay(s),
            // The fence applies from the first moment Q signatures are held, whatever this
            // node's own progress (§4.3 "Fence"); a node that has not signed then signs nothing.
            (
                Self::Voting
                | Self::WaitFinal(_)
                | Self::Replay(_)
                | Self::Signed(_)
                | Self::ForceSeal,
                E::QuorumSigs(s),
            ) => Self::Fenced(s),
            (Self::Fenced(_), E::Activated) => Self::Follower,
            (s, e) => return Err(illegal(&s, &e)),
        })
    }

    /// Whether this replica may still sign a `HandoffRecord` (§5.3 adds the per-record rules).
    pub fn may_sign(self) -> bool {
        matches!(self, Self::Replay(_))
    }
}

/// A voter of the new replica set `R_{e+1}` (§4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewReplica {
    Follower,
    /// From `T − EPO_PREP_LEAD_S`: `EpoConfig(e+1)` loaded, `EpoReady` sent every second.
    Preparing,
    /// From T: votes on window blocks only.
    Collecting,
    /// cert(e, S) verified, root equal, `armed(e+1)` persisted, `EpoArmed` sent: votes on all of e+1.
    Voting,
    /// The opening block is final and `EpoActivated` was sent.
    Activated,
    /// Its root at S differs: stop voting, alarm, re-sync from a snapshot.
    Faulty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewReplicaEv {
    PrepLead,
    T,
    /// §5.4 passed: checks 1–4, and check 5 with this result.
    CertVerified {
        root_equal: bool,
    },
    OpeningFinal,
    Resynced,
}

impl NewReplica {
    pub fn on(self, ev: NewReplicaEv) -> Result<Self, RoleErr> {
        use NewReplicaEv as E;
        Ok(match (self, ev) {
            (Self::Follower, E::PrepLead) => Self::Preparing,
            (Self::Preparing, E::T) => Self::Collecting,
            (Self::Collecting, E::CertVerified { root_equal: true }) => Self::Voting,
            (Self::Collecting, E::CertVerified { root_equal: false }) => Self::Faulty,
            (Self::Voting, E::OpeningFinal) => Self::Activated,
            (Self::Faulty, E::Resynced) => Self::Follower,
            (s, e) => return Err(illegal(&s, &e)),
        })
    }

    /// F4 (§4.4, §8.2): a block with a step may be voted on only once `armed(e+1)`.
    pub fn may_vote_on_step(self) -> bool {
        matches!(self, Self::Voting | Self::Activated)
    }
}

/// The phase of the new sequencer (§4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewSeqPhase {
    Follower,
    Preparing,
    /// From T by its own PTP clock: queue-ack, stream `PacketRecord`s, propose window blocks.
    /// `cert` is S once cert(e, S) is verified, before the replay reached it.
    Collect {
        cert: Option<StepId>,
    },
    /// The speculative replay executed the `Seal` step S′; lanes apply window ops against it.
    /// `cert` is S once cert(e, S) is verified and S == S′.
    Apply {
        s_prime: StepId,
        cert: Option<StepId>,
    },
    /// S′ ≠ S, or the first root comparison at S failed (§10.1, §10.5): undo to the last final
    /// block, replay the certified log to S, re-apply.
    Respec(StepId),
    /// The roots at S are equal: the window closes and U runs, but the first auction fill waits
    /// for `EpoArmed` from Q members of `R_{e+1}`.
    Uncross,
    /// The first auction fill may leave: lanes catch up, then go live.
    Live,
    /// The root at S still differs after a re-spec: stop; the standby activates (§10.4).
    Faulty,
}

/// The new sequencer (§4.5); the standby runs the same machine without client traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewSeq {
    pub phase: NewSeqPhase,
    /// `EpoArmed` from Q members of `R_{e+1}` is held. It may arrive before this box has
    /// verified the certificate itself.
    pub armed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NewSeqEv {
    PrepLead,
    T,
    /// The speculative replay executed the `Seal` step S′.
    ReplaySeal(StepId),
    /// cert(e, S) verified (§5.4 checks 1–4).
    Cert(StepId),
    /// This box has executed S (by the speculative replay, the re-spec, or, after a force seal
    /// with no `Seal` step, by replaying the certified log to S) and compared its `state_root`
    /// and `log_hash` with the record's.
    RootAt {
        s: StepId,
        equal: bool,
    },
    /// `EpoArmed` from Q members of `R_{e+1}`.
    ArmedQuorum,
}

impl NewSeq {
    pub const FOLLOWER: Self = Self {
        phase: NewSeqPhase::Follower,
        armed: false,
    };

    pub fn on(self, ev: NewSeqEv) -> Result<Self, RoleErr> {
        use NewSeqEv as E;
        use NewSeqPhase as P;
        let to = |phase| {
            Ok(Self {
                phase,
                armed: self.armed,
            })
        };
        // §4.5: a first root mismatch re-specs from the certified log; only a mismatch after
        // the re-spec makes the box faulty.
        let root = |equal: bool, s: StepId, respec: bool| match (equal, respec, self.armed) {
            (false, false, _) => P::Respec(s),
            (false, true, _) => P::Faulty,
            (true, _, false) => P::Uncross,
            (true, _, true) => P::Live,
        };
        match (self.phase, ev) {
            (P::Follower, E::PrepLead) => to(P::Preparing),
            (P::Preparing, E::T) => to(P::Collect { cert: None }),
            (P::Collect { cert: None }, E::Cert(s)) => to(P::Collect { cert: Some(s) }),
            (P::Collect { cert: None }, E::ReplaySeal(sp)) => to(P::Apply {
                s_prime: sp,
                cert: None,
            }),
            (P::Collect { cert: Some(s) }, E::ReplaySeal(sp))
            | (
                P::Apply {
                    s_prime: sp,
                    cert: None,
                },
                E::Cert(s),
            ) => to(if s == sp {
                P::Apply {
                    s_prime: sp,
                    cert: Some(s),
                }
            } else {
                P::Respec(s)
            }),
            // A force-sealed epoch has no `Seal` step: the box replays the certified log to S.
            (P::Collect { cert: Some(s) }, E::RootAt { s: at, equal })
            | (P::Apply { cert: Some(s), .. }, E::RootAt { s: at, equal })
                if at == s =>
            {
                to(root(equal, s, false))
            }
            (P::Respec(s), E::RootAt { s: at, equal }) if at == s => to(root(equal, s, true)),
            (P::Collect { .. } | P::Apply { .. } | P::Respec(_) | P::Uncross, E::ArmedQuorum) => {
                Ok(Self {
                    phase: if self.phase == P::Uncross {
                        P::Live
                    } else {
                        self.phase
                    },
                    armed: true,
                })
            }
            (_, e) => Err(illegal(&self, &e)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Force seal
// ---------------------------------------------------------------------------------------------

/// Why a signed role message is not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SealErr {
    #[error("names another book or epoch")]
    Other,
    #[error("index {0} is not a signer")]
    Unknown(u8),
    #[error("signature of {0} is invalid")]
    BadSig(u8),
    #[error("{0} already signed")]
    Duplicate(u8),
    #[error("the operator cannot read its node's high-water mark")]
    Unreadable,
    #[error("the operator's node is armed(e+1): the new home may already trade")]
    Armed,
    #[error("before T + EPO_REASSIGN_MIN_S")]
    TooEarly,
    #[error("{got} signatures, need {need}")]
    Count { got: usize, need: usize },
}

/// `EpoForceSeal{e, last_height_held}` (§4.3): a voter of `R_e` attests that no `Seal` frame
/// arrived by `T + EPO_SEAL_GRACE_MS`. Q of them are the attestation 09 slashes as a withheld
/// handoff.
///
/// Spec gaps [Guessing]: 08 gives no encoding. The signed body is 14 bytes, little-endian,
/// `book u16 ‖ epoch u32 ‖ last_height_held u64` (the book is added so a book group's records
/// stay apart), under [`FORCE_SEAL_CONTEXT`] with the voter's vote key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpoForceSeal {
    pub book: BookId,
    pub epoch: Epoch,
    pub last_height_held: Height,
    pub index: u8,
    pub sig: Ed25519Sig,
}

impl EpoForceSeal {
    pub fn body(&self) -> [u8; 14] {
        let mut b = [0u8; 14];
        b[0..2].copy_from_slice(&self.book.0.to_le_bytes());
        b[2..6].copy_from_slice(&self.epoch.0.to_le_bytes());
        b[6..14].copy_from_slice(&self.last_height_held.0.to_le_bytes());
        b
    }

    pub fn signed(mut self, seed: &[u8; 32], domain: &Domain) -> Self {
        self.sig =
            vyrn_crypto::ed25519::sign(seed, &domain.message(FORCE_SEAL_CONTEXT, &self.body()));
        self
    }

    fn verify(&self, domain: &Domain, old: &Membership) -> Result<(), SealErr> {
        let key = old
            .committee()
            .voter(self.index)
            .ok_or(SealErr::Unknown(self.index))?;
        let msg = domain.message(FORCE_SEAL_CONTEXT, &self.body());
        if vyrn_crypto::ed25519::verify(key, &msg, &self.sig) {
            Ok(())
        } else {
            Err(SealErr::BadSig(self.index))
        }
    }
}

/// Collects `EpoForceSeal` for one (book, e) from the voters of `R_e`.
#[derive(Clone, Debug)]
pub struct ForceSealPool {
    book: BookId,
    epoch: Epoch,
    got: BTreeMap<u8, EpoForceSeal>,
}

impl ForceSealPool {
    pub fn new(book: BookId, epoch: Epoch) -> Self {
        Self {
            book,
            epoch,
            got: BTreeMap::new(),
        }
    }

    /// Adds one attestation after checking it against `old` (`R_e`).
    pub fn add(
        &mut self,
        m: EpoForceSeal,
        domain: &Domain,
        old: &Membership,
    ) -> Result<(), SealErr> {
        if m.book != self.book || m.epoch != self.epoch || old.epoch() != self.epoch {
            return Err(SealErr::Other);
        }
        m.verify(domain, old)?;
        if self.got.contains_key(&m.index) {
            return Err(SealErr::Duplicate(m.index));
        }
        self.got.insert(m.index, m);
        Ok(())
    }

    /// Q attestations, ascending by index, once held: the slashing evidence.
    pub fn attestation(&self, old: &Membership) -> Option<Vec<EpoForceSeal>> {
        let q = old.committee().quorum();
        (self.got.len() >= q).then(|| self.got.values().take(q).copied().collect())
    }
}

// ---------------------------------------------------------------------------------------------
// Halt and reassignment
// ---------------------------------------------------------------------------------------------

/// The head of the window chain a fenced node holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WinHead {
    pub wheight: u32,
    pub hash: Hash,
}

/// What an operator reads from its fenced node in the new home (§10.3 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighWater {
    pub armed: bool,
    /// The node's highest final window block, if any.
    pub win_head: Option<WinHead>,
}

/// §10.3 step 1: an operator signs only when it could read its fenced node's mark and the mark
/// does not show `armed(e+1)`. `mark` is `None` when it could not read it.
pub fn may_sign_reassign(mark: Option<HighWater>, now: Nanos, t: Nanos) -> Result<(), SealErr> {
    if !reassign_open(now, t) {
        return Err(SealErr::TooEarly);
    }
    match mark {
        None => Err(SealErr::Unreadable),
        Some(m) if m.armed => Err(SealErr::Armed),
        Some(_) => Ok(()),
    }
}

/// §10.3 step 2: `win_head` is the highest final window block that any of the Q fenced nodes
/// holds.
pub fn win_head(marks: &[HighWater]) -> Option<WinHead> {
    marks.iter().filter_map(|m| m.win_head).max()
}

/// `EpoReassign{e+1, home, win_head}` (§10.3), signed by Q operator keys (CHAIN: `OIK`; BASE: the
/// admin keys).
///
/// Spec gaps [Guessing]: no encoding in 08. The signed body is 43 bytes, little-endian,
/// `book u16 ‖ epoch u32 ‖ home u8 ‖ wheight u32 ‖ win_hash [32]` (wheight 0 and a zero hash when
/// no window block is final), under [`REASSIGN_CONTEXT`]. The operator key list and Q come from
/// the caller, because 09 has no operator roster encoding yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpoReassign {
    pub book: BookId,
    /// e+1.
    pub epoch: Epoch,
    pub home: HomeCode,
    pub win_head: Option<WinHead>,
}

impl EpoReassign {
    pub fn body(&self) -> [u8; 43] {
        let mut b = [0u8; 43];
        b[0..2].copy_from_slice(&self.book.0.to_le_bytes());
        b[2..6].copy_from_slice(&self.epoch.0.to_le_bytes());
        b[6] = self.home.code();
        if let Some(w) = self.win_head {
            b[7..11].copy_from_slice(&w.wheight.to_le_bytes());
            b[11..43].copy_from_slice(&w.hash.0);
        }
        b
    }

    pub fn sign(&self, seed: &[u8; 32], domain: &Domain) -> Ed25519Sig {
        vyrn_crypto::ed25519::sign(seed, &domain.message(REASSIGN_CONTEXT, &self.body()))
    }

    /// Valid with `quorum` distinct, ascending operator indices whose signatures verify.
    pub fn verify(
        &self,
        sigs: &[(u8, Ed25519Sig)],
        operators: &[PubKey],
        quorum: usize,
        domain: &Domain,
    ) -> Result<(), SealErr> {
        if sigs.len() < quorum {
            return Err(SealErr::Count {
                got: sigs.len(),
                need: quorum,
            });
        }
        if let Some(w) = sigs.windows(2).find(|w| w[0].0 >= w[1].0) {
            return Err(SealErr::Duplicate(w[1].0));
        }
        let msg = domain.message(REASSIGN_CONTEXT, &self.body());
        for (i, sig) in sigs {
            let key = operators.get(usize::from(*i)).ok_or(SealErr::Unknown(*i))?;
            if !vyrn_crypto::ed25519::verify(key, &msg, sig) {
                return Err(SealErr::BadSig(*i));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;
    use vyrn_types::Mode;

    const T: Nanos = Nanos(1_000 * NS_PER_S);

    #[test]
    fn timing_rules_sit_on_their_boundaries() {
        assert!(!lane_seals(Nanos(T.0 - 1), T) && lane_seals(T, T));
        assert!(!idle_lane_seals(Nanos(T.0 + 5_000), T) && idle_lane_seals(Nanos(T.0 + 5_001), T));
        let grace = T.0 + 5 * NS_PER_MS;
        assert!(!force_seal_due(Nanos(grace), T, false));
        assert!(force_seal_due(Nanos(grace + 1), T, false));
        assert!(!force_seal_due(Nanos(grace + 1), T, true));
        let guard = T.0 - 20 * NS_PER_MS;
        assert_eq!(failover_kind(Nanos(guard - 1), T), FailoverKind::Promote);
        assert_eq!(failover_kind(Nanos(guard), T), FailoverKind::SealMode);
        let halt = T.0 + 250 * NS_PER_MS;
        assert!(!halt_due(Nanos(halt - 1), T, false) && halt_due(Nanos(halt), T, false));
        assert!(!halt_due(Nanos(halt), T, true));
        assert!(activate_alarm_due(Nanos(T.0 + 1_500 * NS_PER_MS), T, false));
        assert!(!reassign_open(Nanos(T.0 + 60 * NS_PER_S - 1), T));
        assert!(reassign_open(Nanos(T.0 + 60 * NS_PER_S), T));
    }

    #[test]
    fn old_sequencer_holds_seals_and_follows() {
        use OldSeqEv as E;
        let s = OldSeq::Active
            .on(E::GoLead)
            .and_then(|s| s.on(E::HoldFinal));
        assert_eq!(s, Ok(OldSeq::Active));
        let mut s = OldSeq::Active;
        for e in [
            E::GoLead,
            E::GoFinal,
            E::LaneSealed,
            E::LaneSealed,
            E::SealStep(StepId(9)),
            E::CertSeen,
        ] {
            s = s.on(e).unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(s, OldSeq::Follower);
        // Never seal before the go is final, never resume after the seal (E7).
        assert_eq!(
            OldSeq::Deciding.on(E::LaneSealed).err().map(|e| e.state),
            Some("Deciding".into())
        );
        assert!(OldSeq::Sealed(StepId(9)).on(E::GoLead).is_err());
        assert!(OldSeq::Sealed(StepId(9)).on(E::HoldFinal).is_err());
    }

    #[test]
    fn old_replica_signs_once_on_either_path_and_fences() {
        use OldReplicaEv as E;
        let s = OldReplica::Voting
            .on(E::SealFrame(StepId(9)))
            .and_then(|s| s.on(E::BlockFinal));
        assert_eq!(s, Ok(OldReplica::Replay(StepId(9))));
        assert!(s.is_ok_and(|s| s.may_sign()));
        // Force seal: S is the prefix's last step, not the absent Seal step.
        let s = OldReplica::Voting
            .on(E::GraceExpired)
            .and_then(|s| s.on(E::PrefixFinal(StepId(7))));
        assert_eq!(s, Ok(OldReplica::Replay(StepId(7))));
        // A Seal frame after the force seal started is not accepted.
        assert!(OldReplica::ForceSeal.on(E::SealFrame(StepId(9))).is_err());
        // Q signatures fence a node that has not signed; it then cannot sign.
        let f = OldReplica::WaitFinal(StepId(9)).on(E::QuorumSigs(StepId(9)));
        assert_eq!(f, Ok(OldReplica::Fenced(StepId(9))));
        assert!(f.is_ok_and(|f| !f.may_sign()));
        assert_eq!(
            OldReplica::Fenced(StepId(9)).on(E::Activated),
            Ok(OldReplica::Follower)
        );
        assert!(
            OldReplica::Fenced(StepId(9))
                .on(E::QuorumSigs(StepId(9)))
                .is_err()
        );
    }

    #[test]
    fn new_replica_votes_steps_only_when_armed() {
        use NewReplicaEv as E;
        let c = NewReplica::Follower
            .on(E::PrepLead)
            .and_then(|s| s.on(E::T));
        assert_eq!(c, Ok(NewReplica::Collecting));
        assert!(c.is_ok_and(|c| !c.may_vote_on_step()));
        let v = NewReplica::Collecting.on(E::CertVerified { root_equal: true });
        assert!(v.is_ok_and(|v| v.may_vote_on_step()));
        assert_eq!(
            NewReplica::Voting.on(E::OpeningFinal),
            Ok(NewReplica::Activated)
        );
        let f = NewReplica::Collecting.on(E::CertVerified { root_equal: false });
        assert_eq!(f, Ok(NewReplica::Faulty));
        assert_eq!(NewReplica::Faulty.on(E::Resynced), Ok(NewReplica::Follower));
        assert!(
            NewReplica::Preparing
                .on(E::CertVerified { root_equal: true })
                .is_err()
        );
    }

    #[test]
    fn new_sequencer_activates_respecs_or_fails() {
        use NewSeqEv as E;
        use NewSeqPhase as P;
        let run = |evs: &[NewSeqEv]| {
            evs.iter()
                .try_fold(NewSeq::FOLLOWER, |s, e| s.on(*e))
                .map(|s| s.phase)
        };
        let start = [E::PrepLead, E::T];
        let s9 = StepId(9);
        let ok = E::RootAt { s: s9, equal: true };
        // Replay first or cert first: both reach Uncross, and only Q EpoArmed opens Live.
        assert_eq!(
            run(&[&start[..], &[E::ReplaySeal(s9), E::Cert(s9), ok]].concat()),
            Ok(P::Uncross)
        );
        assert_eq!(
            run(&[
                &start[..],
                &[E::Cert(s9), E::ReplaySeal(s9), ok, E::ArmedQuorum]
            ]
            .concat()),
            Ok(P::Live)
        );
        // EpoArmed may arrive before this box verified the cert.
        assert_eq!(
            run(&[
                &start[..],
                &[E::ArmedQuorum, E::ReplaySeal(s9), E::Cert(s9), ok]
            ]
            .concat()),
            Ok(P::Live)
        );
        // Force seal: no Seal step; the box replays the certified log to S.
        assert_eq!(
            run(&[&start[..], &[E::Cert(s9), ok, E::ArmedQuorum]].concat()),
            Ok(P::Live)
        );
        // S′ beyond S (§10.1): re-spec to S, then the root decides.
        let respec = [&start[..], &[E::ReplaySeal(StepId(11)), E::Cert(s9)]].concat();
        assert_eq!(run(&respec), Ok(P::Respec(s9)));
        assert_eq!(run(&[&respec[..], &[ok]].concat()), Ok(P::Uncross));
        let bad = E::RootAt {
            s: s9,
            equal: false,
        };
        assert_eq!(run(&[&respec[..], &[bad]].concat()), Ok(P::Faulty));
        // Same S, different root: re-spec first; faulty only if the root still differs.
        let same = [&start[..], &[E::ReplaySeal(s9), E::Cert(s9), bad]].concat();
        assert_eq!(run(&same), Ok(P::Respec(s9)));
        assert_eq!(run(&[&same[..], &[bad]].concat()), Ok(P::Faulty));
        assert_eq!(
            run(&[&same[..], &[ok, E::ArmedQuorum]].concat()),
            Ok(P::Live)
        );
        // A root at another step, or before the cert, is refused.
        assert!(run(&[&start[..], &[E::ReplaySeal(s9), ok]].concat()).is_err());
        assert!(
            run(&[
                &start[..],
                &[
                    E::Cert(s9),
                    E::RootAt {
                        s: StepId(8),
                        equal: true
                    }
                ]
            ]
            .concat())
            .is_err()
        );
        assert!(run(&[E::PrepLead, E::ReplaySeal(s9)]).is_err());
    }

    #[test]
    fn force_seal_needs_q_distinct_valid_voters() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let book = BookId(1);
        let m = |i: u8| {
            EpoForceSeal {
                book,
                epoch: Epoch(7),
                last_height_held: Height(40),
                index: i,
                sig: [0; 64],
            }
            .signed(&testkit::seed(i), &domain)
        };
        let mut pool = ForceSealPool::new(book, Epoch(7));
        assert_eq!(pool.add(m(0), &domain, &old), Ok(()));
        assert_eq!(pool.add(m(0), &domain, &old), Err(SealErr::Duplicate(0)));
        let mut forged = m(1);
        forged.index = 2;
        assert_eq!(pool.add(forged, &domain, &old), Err(SealErr::BadSig(2)));
        let mut other = m(1);
        other.epoch = Epoch(8);
        assert_eq!(pool.add(other, &domain, &old), Err(SealErr::Other));
        // Another mode's domain does not verify.
        assert_eq!(
            pool.add(m(1), &testkit::domain(Mode::Chain), &old),
            Err(SealErr::BadSig(1))
        );
        assert_eq!(pool.add(m(1), &domain, &old), Ok(()));
        assert!(pool.attestation(&old).is_none());
        assert_eq!(pool.add(m(3), &domain, &old), Ok(()));
        let a = pool.attestation(&old).unwrap_or_default();
        assert_eq!(a.iter().map(|m| m.index).collect::<Vec<_>>(), [0, 1, 3]);
    }

    #[test]
    fn reassignment_needs_unarmed_readable_marks_and_q_operators() {
        let late = Nanos(T.0 + 60 * NS_PER_S);
        let head = |h: u32| {
            Some(WinHead {
                wheight: h,
                hash: Hash([h as u8; 32]),
            })
        };
        assert_eq!(
            may_sign_reassign(
                Some(HighWater {
                    armed: false,
                    win_head: None
                }),
                Nanos(late.0 - 1),
                T
            ),
            Err(SealErr::TooEarly)
        );
        assert_eq!(may_sign_reassign(None, late, T), Err(SealErr::Unreadable));
        assert_eq!(
            may_sign_reassign(
                Some(HighWater {
                    armed: true,
                    win_head: head(3)
                }),
                late,
                T
            ),
            Err(SealErr::Armed)
        );
        assert_eq!(
            may_sign_reassign(
                Some(HighWater {
                    armed: false,
                    win_head: head(3)
                }),
                late,
                T
            ),
            Ok(())
        );
        let marks = [
            HighWater {
                armed: false,
                win_head: head(3),
            },
            HighWater {
                armed: false,
                win_head: None,
            },
            HighWater {
                armed: false,
                win_head: head(5),
            },
        ];
        assert_eq!(win_head(&marks), head(5));

        let domain = testkit::domain(Mode::Base);
        let seeds: Vec<[u8; 32]> = (0..4u8).map(|i| [0xA0 + i; 32]).collect();
        let ops: Vec<PubKey> = seeds.iter().map(vyrn_crypto::ed25519::public_key).collect();
        let r = EpoReassign {
            book: BookId(1),
            epoch: Epoch(8),
            home: HomeCode::Nyc,
            win_head: win_head(&marks),
        };
        let sigs: Vec<(u8, Ed25519Sig)> = [0u8, 2, 3]
            .iter()
            .map(|&i| (i, r.sign(&seeds[usize::from(i)], &domain)))
            .collect();
        assert_eq!(r.verify(&sigs, &ops, 3, &domain), Ok(()));
        assert_eq!(
            r.verify(&sigs[..2], &ops, 3, &domain),
            Err(SealErr::Count { got: 2, need: 3 })
        );
        let moved = EpoReassign {
            home: HomeCode::Tyo,
            ..r
        };
        assert_eq!(
            moved.verify(&sigs, &ops, 3, &domain),
            Err(SealErr::BadSig(0))
        );
        let dup = [sigs[0], sigs[0], sigs[1]];
        assert_eq!(r.verify(&dup, &ops, 3, &domain), Err(SealErr::Duplicate(0)));
    }
}
