//! The key bundle of one epoch and its hand-off to `vyrn-consensus` (08 §9, 07 §13.1).
//!
//! A [`Membership`] is everything a verifier needs about `R_e`: the voters as a
//! [`vyrn_consensus::Committee`] (vote keys `VK(i, home(e))`), and the home's two `vyrn-seq`
//! boxes in `seq_order` with their block keys `SK` and exchange keys `XK`. Keys change only at a
//! boundary (E9): the bundle of e+1 comes from `EpoConfig(e+1)`, which cert(e − 1) covered.
//!
//! [`Membership::hand_off`] is the one door from e to e+1: given cert(e, S) it runs 08 §5.4 against
//! `R_e` and the node's replay, checks that `next_seq_key` is the F1 box of `R_{e+1}` (§9.1), and
//! returns the [`Activation`] that `vyrn-replica` hands to `vyrn-consensus`: the next committee,
//! the block key it accepts, and the [`Fence`] for epoch e.
//!
//! [`Membership::from_roster`] (in `roster.rs`) builds the bundle from the roster bytes that
//! `EpoConfig.roster_hash` names (08 §9.6); [`Membership::new`] builds one from keys the caller
//! already trusts, for tests and tools.

use crate::Domain;
use crate::fence::Fence;
use crate::handoff::{HandoffCert, HandoffErr, LocalView, accept_cert};
use thiserror::Error;
use vyrn_consensus::{Committee, CommitteeErr, Genesis};
use vyrn_types::{Epoch, HomeCode, Mode, PubKey, StepId};

/// One `vyrn-seq` box of a home.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqBox {
    /// Roster index, as `EpoConfig.seq_order` and `EpoGo.seq_index` name it.
    pub index: u8,
    /// Node key `NK(index, home)`: `EpoReady` (08 §2.6).
    pub node_key: PubKey,
    /// Block-signing key `SK(index, home)`.
    pub seq_key: PubKey,
    /// Exchange key `XK(index, home)` for session keys (§9.1).
    pub xchg_key: PubKey,
}

/// Why a key bundle is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MembershipErr {
    #[error("voters: {0}")]
    Committee(CommitteeErr),
    #[error("one node key per voter is needed")]
    NodeKeys,
    #[error("the primary and the standby are the same box")]
    SeqBoxes,
}

/// The voters and sequencer boxes of one home for one epoch.
#[derive(Clone, Debug)]
pub struct Membership {
    epoch: Epoch,
    home: HomeCode,
    committee: Committee,
    /// `NK(i, home)` of voter i.
    node_keys: Vec<PubKey>,
    seq: [SeqBox; 2],
    spares: Vec<SeqBox>,
}

/// What `vyrn-consensus` and `vyrn-replica` need to start epoch e+1.
#[derive(Clone, Debug)]
pub struct Activation {
    /// e+1.
    pub epoch: Epoch,
    pub home: HomeCode,
    /// The voters of e+1, for `vyrn_consensus::voter::config`.
    pub committee: Committee,
    /// The only key `seq_sig` verifies under until a failover in e+1 (§9.1, F4).
    pub seq_key: PubKey,
    /// The standby's key, which a failover in e+1 promotes (§10.4).
    pub standby_key: PubKey,
    /// `INV-FENCE` for epoch e.
    pub fence: Fence,
    /// What the first block of e+1 extends, for `vyrn_consensus::voter::VoterConfig::genesis`:
    /// the certified last block of e (`last_height`, `log_hash`). Steps restart at 1 each epoch, so
    /// `last_step` is 0. Assumes `log_hash` is `vyrn-log`'s `header_hash` (08 Requests to 01 item 3)
    /// [Likely].
    pub genesis: Genesis,
}

impl Membership {
    /// `voters` (vote keys) and `node_keys` in voter-index order, and `seq` as `[primary F1,
    /// standby F2]`. The committee refuses a sequencer key among the voters (01 §14.4).
    pub fn new(
        epoch: Epoch,
        home: HomeCode,
        mode: Mode,
        voters: Vec<PubKey>,
        node_keys: Vec<PubKey>,
        seq: [SeqBox; 2],
    ) -> Result<Self, MembershipErr> {
        if node_keys.len() != voters.len() {
            return Err(MembershipErr::NodeKeys);
        }
        if seq[0].index == seq[1].index || seq[0].seq_key == seq[1].seq_key {
            return Err(MembershipErr::SeqBoxes);
        }
        let committee = Committee::new(mode, voters, &[seq[0].seq_key, seq[1].seq_key])
            .map_err(MembershipErr::Committee)?;
        Ok(Self {
            epoch,
            home,
            committee,
            node_keys,
            seq,
            spares: Vec::new(),
        })
    }

    /// The other `vyrn-seq` boxes of the home, after the standby in `REP_Membership.seq_order`.
    pub(crate) fn with_spares(mut self, spares: Vec<SeqBox>) -> Self {
        self.spares = spares;
        self
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn home(&self) -> HomeCode {
        self.home
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// `NK(voter, home)`, which signs the voter's `EpoReady` (08 §2.6).
    pub fn node_key(&self, voter: u8) -> Option<&PubKey> {
        self.node_keys.get(usize::from(voter))
    }

    /// `[primary F1, standby F2]`.
    pub fn seq(&self) -> &[SeqBox; 2] {
        &self.seq
    }

    /// The spares, in roster order: `REP_Membership.seq_order` after `[primary, standby]`.
    pub fn spares(&self) -> &[SeqBox] {
        &self.spares
    }

    /// The hand-off from this epoch (`R_e`) to `next` (`R_{e+1}`) on cert(e, S).
    pub fn hand_off(
        &self,
        next: &Self,
        cert: &HandoffCert,
        domain: &Domain,
        local: &impl LocalView,
    ) -> Result<Activation, HandoffErr> {
        if next.epoch <= self.epoch || next.home != cert.record.next_home {
            return Err(HandoffErr::NotForMe);
        }
        accept_cert(cert, domain, self, local)?;
        // The bundle must be the epoch the final EpoGo names, not merely one with the same home
        // and primary key (a skip or a long hold changes the target, §2.5).
        if local.go().map(|(e, _)| e) != Some(next.epoch)
            || cert.record.next_seq_key != next.seq[0].seq_key
        {
            return Err(HandoffErr::SeqKey);
        }
        Ok(Activation {
            epoch: next.epoch,
            home: next.home,
            committee: next.committee.clone(),
            seq_key: next.seq[0].seq_key,
            standby_key: next.seq[1].seq_key,
            fence: Fence::from_record(&cert.record),
            genesis: Genesis {
                height: cert.record.last_height,
                hash: cert.record.log_hash,
                last_step: StepId(0),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, Local};

    #[test]
    fn hand_off_yields_the_next_committee_and_fence() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let next = testkit::next(Mode::Base);
        let cert = testkit::cert(&domain, &[0, 1, 2]);
        let local = Local::matching(&cert.record);
        let a = old
            .hand_off(&next, &cert, &domain, &local)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((a.epoch, a.home), (Epoch(8), HomeCode::Ldn));
        assert_eq!(a.committee.voter(0), next.committee().voter(0));
        assert_eq!(a.seq_key, next.seq()[0].seq_key);
        assert_eq!(a.fence.epoch(), Epoch(7));
        assert_eq!(
            (a.genesis.height, a.genesis.hash),
            (cert.record.last_height, cert.record.log_hash)
        );
        // The certificate must be checked against R_e, not R_{e+1}.
        assert_eq!(
            next.hand_off(&next, &cert, &domain, &local).err(),
            Some(HandoffErr::NotForMe)
        );
    }

    #[test]
    fn the_next_seq_key_must_be_the_f1_box() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let mut seq = *testkit::next(Mode::Base).seq();
        seq.swap(0, 1);
        let swapped = Membership::new(
            Epoch(8),
            HomeCode::Ldn,
            Mode::Base,
            testkit::next_voters(Mode::Base),
            testkit::next_node_keys(Mode::Base),
            seq,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let cert = testkit::cert(&domain, &[0, 1, 2]);
        let local = Local::matching(&cert.record);
        assert_eq!(
            old.hand_off(&swapped, &cert, &domain, &local).err(),
            Some(HandoffErr::SeqKey)
        );
    }

    #[test]
    fn the_next_epoch_must_be_the_one_epogo_names() {
        let domain = testkit::domain(Mode::Base);
        let old = testkit::old(Mode::Base);
        let next = testkit::next(Mode::Base);
        let later = Membership::new(
            Epoch(11),
            HomeCode::Ldn,
            Mode::Base,
            testkit::next_voters(Mode::Base),
            testkit::next_node_keys(Mode::Base),
            *next.seq(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let cert = testkit::cert(&domain, &[0, 1, 2]);
        let local = Local::matching(&cert.record);
        assert_eq!(
            old.hand_off(&later, &cert, &domain, &local).err(),
            Some(HandoffErr::SeqKey)
        );
    }

    #[test]
    fn a_sequencer_key_never_votes() {
        let seq = *testkit::next(Mode::Base).seq();
        let mut voters = testkit::next_voters(Mode::Base);
        voters[1] = seq[1].seq_key;
        assert!(matches!(
            Membership::new(
                Epoch(8),
                HomeCode::Ldn,
                Mode::Base,
                voters,
                testkit::next_node_keys(Mode::Base),
                seq
            ),
            Err(MembershipErr::Committee(CommitteeErr::Sequencer(1)))
        ));
    }
}
