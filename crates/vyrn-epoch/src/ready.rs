//! Readiness and the go/no-go (08 §2.6).
//!
//! From `T − EPO_PREP_LEAD_S`, every voter of `R_{e+1}` and both new `vyrn-seq` boxes send an
//! [`EpoReady`] to every voter of `R_e`. At `T − EPO_GO_LEAD_S` the proposer logs one
//! [`EpoGo`] or [`EpoHold`]; every voter of `R_e` checks it before it votes:
//!
//! - `EpoGo` is valid when its `Q` voter and 2 sequencer `EpoReady` verify, come from distinct
//!   voters and from both boxes in `seq_order`, are each fresher than `EPO_READY_FRESH_MS` at the
//!   proposal's `rx_ts`, and `seq_index`/`next_seq_key` name the F1 box ([`EpoGo::validate`]).
//! - `EpoHold` is valid only when the voter's own [`ReadyPool`] holds no such set
//!   ([`EpoHold::validate`]), so a byzantine proposer cannot hold a healthy handoff.
//!
//! Spec gaps, each [Guessing]:
//! - `EpoReady` has no timestamp in 08, yet freshness is measured against it. This crate adds
//!   `sent: Nanos` (the sender's PTP time) to the signed body.
//! - `member` is "a voting member of R_{e+1}, or a sequencer box" in one u8. This crate sets bit 7
//!   ([`SEQ_MEMBER`]) for a sequencer box, whose roster index is then bits 0–6.
//! - The signing key is `NK(member, home(e+1))`, a node key with no roster field yet. This crate
//!   verifies with the voter's vote key and the box's seq key from [`Membership`].
//! - The signed body is 35 bytes, little-endian: `epoch u32, member u8, follow_height u64,
//!   lag_ns u64, keys_ready u8, version u32, b4_pass u8, sent u64`, under
//!   `derive_key("vyrn      v1 ready", genesis_hash ‖ mode ‖ body)`.

use crate::membership::Membership;
use crate::{Domain, EPO_READY_FRESH_MS, EPO_READY_LAG_MS};
use std::collections::BTreeMap;
use thiserror::Error;
use vyrn_types::{Ed25519Sig, Epoch, Height, Nanos, PubKey};

/// The signing context, six spaces after "vyrn" as 08 §2.6 writes it.
pub const READY_CONTEXT: &str = "vyrn      v1 ready";
/// `EpoReady.member` bit for a sequencer box.
pub const SEQ_MEMBER: u8 = 0x80;
const BODY_BYTES: usize = 35;
const NS_PER_MS: u64 = 1_000_000;

/// One node's readiness for epoch e+1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpoReady {
    pub epoch: Epoch,
    /// Voter index in `R_{e+1}`, or `SEQ_MEMBER | roster index` of a sequencer box.
    pub member: u8,
    pub follow_height: Height,
    pub lag_ns: u64,
    /// Sequencer boxes only: `K_seq`/`K_out` derived for every session.
    pub keys_ready: bool,
    pub version: u32,
    pub b4_pass: bool,
    /// Sender's PTP time (spec gap, see the module docs).
    pub sent: Nanos,
    pub sig: Ed25519Sig,
}

impl EpoReady {
    /// The signed body.
    pub fn body(&self) -> [u8; BODY_BYTES] {
        let mut b = [0u8; BODY_BYTES];
        b[0..4].copy_from_slice(&self.epoch.0.to_le_bytes());
        b[4] = self.member;
        b[5..13].copy_from_slice(&self.follow_height.0.to_le_bytes());
        b[13..21].copy_from_slice(&self.lag_ns.to_le_bytes());
        b[21] = u8::from(self.keys_ready);
        b[22..26].copy_from_slice(&self.version.to_le_bytes());
        b[26] = u8::from(self.b4_pass);
        b[27..35].copy_from_slice(&self.sent.0.to_le_bytes());
        b
    }

    /// Signs `self` (its `sig` is ignored) with the node's key seed.
    pub fn signed(mut self, seed: &[u8; 32], domain: &Domain) -> Self {
        self.sig = vyrn_crypto::ed25519::sign(seed, &domain.message(READY_CONTEXT, &self.body()));
        self
    }

    pub fn is_seq(&self) -> bool {
        self.member & SEQ_MEMBER != 0
    }

    fn fresh_at(&self, at: Nanos) -> bool {
        self.sent <= at && at.0 - self.sent.0 <= EPO_READY_FRESH_MS * NS_PER_MS
    }
}

/// Why a readiness message or a go/no-go record is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GoErr {
    #[error("names another epoch")]
    Epoch,
    #[error("member {0:#x} is not in R_(e+1) or seq_order")]
    Unknown(u8),
    #[error("signature of member {0:#x} is invalid")]
    BadSig(u8),
    #[error("EpoReady of member {0:#x} is older than EPO_READY_FRESH_MS")]
    Stale(u8),
    #[error("member {0:#x} does not meet the send rule (lag, version, B4, keys)")]
    NotReady(u8),
    #[error("{got} voter EpoReady, need exactly Q = {need}")]
    Count { got: usize, need: usize },
    #[error("voter EpoReady are not ascending and distinct, or name a sequencer box")]
    Order,
    #[error("seq_ready is not the two boxes of seq_order, in order")]
    SeqBoxes,
    #[error("seq_index or next_seq_key is not the F1 box")]
    SeqKey,
    #[error("a hold while this voter holds Q + 2 fresh EpoReady")]
    HealthyHold,
}

/// `EpoGo` (08 §2.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpoGo {
    pub next_epoch: Epoch,
    pub seq_index: u8,
    pub next_seq_key: PubKey,
    /// Exactly `Q`, ascending by voter index.
    pub ready: Vec<EpoReady>,
    /// `[primary, standby]` in `seq_order`.
    pub seq_ready: [EpoReady; 2],
}

/// `EpoHold` (08 §2.5–2.6). The timetable checks `t_new = T + EPO_HOLD_S`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpoHold {
    pub epoch: Epoch,
    pub t_new: Nanos,
}

fn key_of(next: &Membership, member: u8) -> Option<PubKey> {
    if member & SEQ_MEMBER != 0 {
        let index = member & !SEQ_MEMBER;
        next.seq()
            .iter()
            .find(|b| b.index == index)
            .map(|b| b.seq_key)
    } else {
        next.committee().voter(member).copied()
    }
}

/// Signature, epoch and the sender's own rule; freshness is the caller's.
fn check_one(r: &EpoReady, domain: &Domain, next: &Membership, version: u32) -> Result<(), GoErr> {
    if r.epoch != next.epoch() {
        return Err(GoErr::Epoch);
    }
    let key = key_of(next, r.member).ok_or(GoErr::Unknown(r.member))?;
    let msg = domain.message(READY_CONTEXT, &r.body());
    if !vyrn_crypto::ed25519::verify(&key, &msg, &r.sig) {
        return Err(GoErr::BadSig(r.member));
    }
    let ok = r.lag_ns <= EPO_READY_LAG_MS * NS_PER_MS
        && r.version == version
        && r.b4_pass
        && (!r.is_seq() || r.keys_ready);
    if !ok {
        return Err(GoErr::NotReady(r.member));
    }
    Ok(())
}

impl EpoGo {
    /// Check 3 of 08 §2.6 for `EpoGo`, at the proposal's `rx_ts` `at`. `next` is `R_{e+1}` and
    /// `version` is `EpoConfig(e+1).version`.
    pub fn validate(
        &self,
        at: Nanos,
        domain: &Domain,
        next: &Membership,
        version: u32,
    ) -> Result<(), GoErr> {
        if self.next_epoch != next.epoch() {
            return Err(GoErr::Epoch);
        }
        let [f1, f2] = next.seq();
        if self.seq_index != f1.index || self.next_seq_key != f1.seq_key {
            return Err(GoErr::SeqKey);
        }
        let need = next.committee().quorum();
        if self.ready.len() != need {
            return Err(GoErr::Count {
                got: self.ready.len(),
                need,
            });
        }
        if self.ready.iter().any(EpoReady::is_seq)
            || self.ready.windows(2).any(|w| w[0].member >= w[1].member)
        {
            return Err(GoErr::Order);
        }
        if self.seq_ready[0].member != SEQ_MEMBER | f1.index
            || self.seq_ready[1].member != SEQ_MEMBER | f2.index
        {
            return Err(GoErr::SeqBoxes);
        }
        for r in self.ready.iter().chain(&self.seq_ready) {
            check_one(r, domain, next, version)?;
            if !r.fresh_at(at) {
                return Err(GoErr::Stale(r.member));
            }
        }
        Ok(())
    }
}

impl EpoHold {
    /// Check 3 of 08 §2.6 for `EpoHold`: valid only if `pool` holds no ready set at `at`.
    pub fn validate(&self, at: Nanos, pool: &ReadyPool, next: &Membership) -> Result<(), GoErr> {
        if pool.go(at, next).is_some() {
            return Err(GoErr::HealthyHold);
        }
        Ok(())
    }
}

/// The `EpoReady` one voter of `R_e` holds: the newest valid one per member.
#[derive(Clone, Debug)]
pub struct ReadyPool {
    version: u32,
    latest: BTreeMap<u8, EpoReady>,
}

impl ReadyPool {
    /// `version` is `EpoConfig(e+1).version`.
    pub fn new(version: u32) -> Self {
        Self {
            version,
            latest: BTreeMap::new(),
        }
    }

    /// Verifies and keeps `r` if it is newer than what the pool holds for its member.
    pub fn add(&mut self, r: EpoReady, domain: &Domain, next: &Membership) -> Result<(), GoErr> {
        check_one(&r, domain, next, self.version)?;
        let keep = self
            .latest
            .get(&r.member)
            .is_none_or(|old| r.sent > old.sent);
        if keep {
            self.latest.insert(r.member, r);
        }
        Ok(())
    }

    /// The `EpoGo` this pool supports at `at`: the `Q` lowest fresh voters and both boxes, all
    /// for `next.epoch()`. Messages for an earlier target never count.
    pub fn go(&self, at: Nanos, next: &Membership) -> Option<EpoGo> {
        let need = next.committee().quorum();
        let ready: Vec<EpoReady> = self
            .latest
            .values()
            .filter(|r| r.epoch == next.epoch() && !r.is_seq() && r.fresh_at(at))
            .take(need)
            .copied()
            .collect();
        if ready.len() < need {
            return None;
        }
        let [f1, f2] = next.seq();
        let fresh_box = |index: u8| {
            self.latest
                .get(&(SEQ_MEMBER | index))
                .filter(|r| r.epoch == next.epoch() && r.fresh_at(at))
                .copied()
        };
        Some(EpoGo {
            next_epoch: next.epoch(),
            seq_index: f1.index,
            next_seq_key: f1.seq_key,
            ready,
            seq_ready: [fresh_box(f1.index)?, fresh_box(f2.index)?],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit;
    use vyrn_types::Mode;

    const AT: Nanos = Nanos(50_000 * NS_PER_MS);

    fn pool_with(members: &[u8], sent: Nanos) -> (ReadyPool, Membership, Domain) {
        let domain = testkit::domain(Mode::Base);
        let next = testkit::next(Mode::Base);
        let mut pool = ReadyPool::new(testkit::VERSION);
        for &m in members {
            let r = testkit::ready(m, sent, &domain);
            assert_eq!(pool.add(r, &domain, &next), Ok(()));
        }
        (pool, next, domain)
    }

    #[test]
    fn a_full_pool_proposes_a_valid_go_and_refuses_a_hold() {
        let s = SEQ_MEMBER;
        let (pool, next, domain) = pool_with(&[3, 0, 2, s | 5, s | 6], AT);
        let go = pool
            .go(AT, &next)
            .unwrap_or_else(|| panic!("ready set expected"));
        assert_eq!(
            go.ready.iter().map(|r| r.member).collect::<Vec<_>>(),
            [0, 2, 3]
        );
        assert_eq!(go.validate(AT, &domain, &next, testkit::VERSION), Ok(()));
        let hold = EpoHold {
            epoch: Epoch(7),
            t_new: AT,
        };
        assert_eq!(hold.validate(AT, &pool, &next), Err(GoErr::HealthyHold));
        // 3 s later every EpoReady is stale: the go fails and a hold is valid.
        let late = Nanos(AT.0 + EPO_READY_FRESH_MS * NS_PER_MS + 1);
        assert_eq!(
            go.validate(late, &domain, &next, testkit::VERSION),
            Err(GoErr::Stale(0))
        );
        assert_eq!(hold.validate(late, &pool, &next), Ok(()));
    }

    #[test]
    fn a_pool_reused_for_a_new_target_ignores_old_readiness() {
        let s = SEQ_MEMBER;
        let (pool, _, _) = pool_with(&[0, 1, 2, s | 5, s | 6], AT);
        let retarget = Membership::new(
            Epoch(9),
            vyrn_types::HomeCode::Nyc,
            Mode::Base,
            testkit::next_voters(Mode::Base),
            *testkit::next(Mode::Base).seq(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(pool.go(AT, &retarget), None);
        let hold = EpoHold {
            epoch: Epoch(7),
            t_new: AT,
        };
        assert_eq!(hold.validate(AT, &pool, &retarget), Ok(()));
    }

    #[test]
    fn without_a_standby_the_home_is_held() {
        let (pool, next, _) = pool_with(&[0, 1, 2, 3, SEQ_MEMBER | 5], AT);
        assert_eq!(pool.go(AT, &next), None);
    }

    #[test]
    fn a_byzantine_go_is_rejected() {
        let s = SEQ_MEMBER;
        let (pool, next, domain) = pool_with(&[0, 1, 2, s | 5, s | 6], AT);
        let go = pool.go(AT, &next).unwrap_or_else(|| panic!("ready set"));
        let v = testkit::VERSION;
        let standby = EpoGo {
            seq_index: 6,
            ..go.clone()
        };
        assert_eq!(standby.validate(AT, &domain, &next, v), Err(GoErr::SeqKey));
        let mut dup = go.clone();
        dup.ready[2] = dup.ready[1];
        assert_eq!(dup.validate(AT, &domain, &next, v), Err(GoErr::Order));
        let mut short = go.clone();
        short.ready.pop();
        assert!(matches!(
            short.validate(AT, &domain, &next, v),
            Err(GoErr::Count { got: 2, need: 3 })
        ));
        let mut forged = go.clone();
        forged.ready[0].follow_height = Height(1);
        assert_eq!(
            forged.validate(AT, &domain, &next, v),
            Err(GoErr::BadSig(0))
        );
        assert_eq!(
            go.validate(AT, &domain, &next, v + 1),
            Err(GoErr::NotReady(0))
        );
    }

    #[test]
    fn a_lagging_node_is_not_ready() {
        let domain = testkit::domain(Mode::Base);
        let next = testkit::next(Mode::Base);
        let mut r = testkit::ready(1, AT, &domain);
        r.lag_ns = EPO_READY_LAG_MS * NS_PER_MS + 1;
        let r = r.signed(&testkit::next_seed(1), &domain);
        let mut pool = ReadyPool::new(testkit::VERSION);
        assert_eq!(pool.add(r, &domain, &next), Err(GoErr::NotReady(1)));
        let mut seq = testkit::ready(SEQ_MEMBER | 5, AT, &domain);
        seq.keys_ready = false;
        let seq = seq.signed(&testkit::seq_seed(0), &domain);
        assert_eq!(pool.add(seq, &domain, &next), Err(GoErr::NotReady(0x85)));
    }
}
