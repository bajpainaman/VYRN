//! The sequencer's finality listener and the finality gate (spec/07-replication.md §6.8,
//! INV-REP-10).
//!
//! **Voters → sequencer.** Every voter sends its own finalize vote ([`FinalizeVote`]) to the
//! sequencer's and the standby's `REP_UDP_CTRL`, and later the `REP_FinalityCert`. The voter side
//! is [`crate::voter::Outputs::votes`].
//!
//! **Listener.** [`Listener`] runs on the sequencer's control core (51). It checks each vote's
//! signature on arrival and stores `final_height` once it holds `Q` valid votes from distinct
//! voters for one `(view, parent_view, proposal)`, so the sequencer learns finality at hop 4,
//! like the voters. No single voter can forge it: the listener returns the assembled
//! [`FinalityCert`], which [`crate::verify_finality_cert`] accepts.
//!
//! **Gate.** [`Gate`] is the check core 4 makes at every flush: halt once more than
//! `FIN_GATE_BLOCKS` closed blocks are not final, resume at `REP_GATE_RESUME_BLOCKS`.
//!
//! Spec gap (07 §6.8 names the vote sent to `REP_UDP_CTRL` but not its bytes). Reading taken: a
//! [`FinalizeVote`] is a `REP_FinalityCert` with `count = 1` (170 bytes), so one decoder and one
//! signed message serve both. **Wire layout: new record on `REP_UDP_CTRL`.**

use crate::cert::{CertErr, FinalityCert, finalize_message, verify_finality_cert};
use crate::membership::Committee;
use crate::proposal::Proposal;
use crate::tail::SealExt;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use vyrn_types::{Ed25519Sig, Epoch, Height};

/// `FIN_GATE_BLOCKS` (01 §14.9): the most closed blocks that may be unfinal while responses flow.
pub const FIN_GATE_BLOCKS: u64 = 8;
/// `REP_GATE_RESUME_BLOCKS` (07 §6.8).
pub const GATE_RESUME_BLOCKS: u64 = 4;
/// How many views above the last final one the listener keeps votes for. A voter's
/// `view_retention` is 64 views too ([`crate::voter`]); a vote further ahead is refused, and the
/// certificate that voters send later still finalizes it.
pub const VIEW_WINDOW: u64 = 64;

/// One voter's finalize vote, as sent to `REP_UDP_CTRL` (spec gap above).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeVote {
    pub epoch: Epoch,
    pub view: u64,
    pub parent_view: u64,
    pub proposal: Proposal,
    /// The voter index of the signer.
    pub index: u8,
    pub sig: Ed25519Sig,
    /// A seal's `REP_SealExt` (07 §9.4), as in [`FinalityCert::seal`].
    pub seal: Option<SealExt>,
}

impl FinalizeVote {
    fn as_cert(&self) -> FinalityCert {
        FinalityCert {
            epoch: self.epoch,
            view: self.view,
            parent_view: self.parent_view,
            proposal: self.proposal,
            sigs: vec![(self.index, self.sig)],
            seal: self.seal.clone(),
        }
    }

    /// The `REP_FinalityCert` layout with one entry (07 §6.5).
    pub fn encode(&self) -> Vec<u8> {
        self.as_cert().encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CertErr> {
        let c = FinalityCert::decode(bytes)?;
        let [(index, sig)] = c.sigs[..] else {
            return Err(CertErr::Length);
        };
        Ok(Self {
            epoch: c.epoch,
            view: c.view,
            parent_view: c.parent_view,
            proposal: c.proposal,
            index,
            sig,
            seal: c.seal,
        })
    }
}

/// Why the listener refused a vote. A refused vote changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VoteErr {
    #[error("vote of epoch {0:?}, listener is at another epoch")]
    Epoch(Epoch),
    #[error("view {0} is more than VIEW_WINDOW above the last final view")]
    Ahead(u64),
    #[error("voter {0} already voted another proposal in this view")]
    Twice(u8),
    #[error(transparent)]
    Cert(#[from] CertErr),
}

/// `(view, parent_view, proposal, seal)`: what Q votes must agree on.
type VoteKey = (u64, u64, Proposal, Option<SealExt>);

/// The finality listener of one (home, epoch) (07 §6.8).
#[derive(Clone, Debug)]
pub struct Listener {
    committee: Committee,
    epoch: Epoch,
    final_height: Height,
    final_view: u64,
    /// Valid votes by `(view, parent_view, proposal, seal)`.
    pending: BTreeMap<VoteKey, Vec<(u8, Ed25519Sig)>>,
    /// `(view, voter)` already counted: one vote per voter per view, so a Byzantine voter holds
    /// at most `VIEW_WINDOW` entries.
    voted: BTreeSet<(u64, u8)>,
}

impl Listener {
    /// A listener whose genesis is `final_height` (the HandoffRecord's `last_height`, 08).
    pub fn new(committee: Committee, epoch: Epoch, final_height: Height) -> Self {
        Self {
            committee,
            epoch,
            final_height,
            final_view: 0,
            pending: BTreeMap::new(),
            voted: BTreeSet::new(),
        }
    }

    /// The highest height final at the sequencer.
    pub fn final_height(&self) -> Height {
        self.final_height
    }

    /// Counts one vote. Returns the certificate when this vote completes `Q`, and `Ok(None)`
    /// when it is valid but not the `Q`-th, or is for a view already final.
    pub fn on_vote(&mut self, vote: &FinalizeVote) -> Result<Option<FinalityCert>, VoteErr> {
        if vote.epoch != self.epoch {
            return Err(VoteErr::Epoch(vote.epoch));
        }
        if vote.view <= self.final_view {
            return Ok(None);
        }
        if vote.view > self.final_view.saturating_add(VIEW_WINDOW) {
            return Err(VoteErr::Ahead(vote.view));
        }
        let key = (
            vote.view,
            vote.parent_view,
            vote.proposal,
            vote.seal.clone(),
        );
        if let Some(sigs) = self.pending.get(&key)
            && sigs.iter().any(|(i, _)| *i == vote.index)
        {
            return Ok(None); // A repeat of a counted vote.
        }
        if self.voted.contains(&(vote.view, vote.index)) {
            return Err(VoteErr::Twice(vote.index));
        }
        let p = &vote.proposal;
        p.check_range().map_err(CertErr::Proposal)?;
        if p.epoch != self.epoch {
            return Err(CertErr::Epoch.into());
        }
        if (p.kind == crate::proposal::ProposalKind::Seal) != vote.seal.is_some() {
            return Err(CertErr::Seal.into());
        }
        let key_of = self
            .committee
            .voter(vote.index)
            .ok_or(CertErr::Unknown(vote.index))?;
        let msg = finalize_message(
            vote.epoch,
            vote.view,
            vote.parent_view,
            p,
            vote.seal.as_ref(),
        );
        if !vyrn_crypto::ed25519::verify(key_of, &msg, &vote.sig) {
            return Err(CertErr::BadSig(vote.index).into());
        }
        self.voted.insert((vote.view, vote.index));
        let seal = key.3.clone();
        let sigs = self.pending.entry(key).or_default();
        sigs.push((vote.index, vote.sig));
        if sigs.len() < self.committee.quorum() {
            return Ok(None);
        }
        let mut sigs = std::mem::take(sigs);
        sigs.sort_by_key(|(i, _)| *i);
        let cert = FinalityCert {
            epoch: vote.epoch,
            view: vote.view,
            parent_view: vote.parent_view,
            proposal: *p,
            sigs,
            seal,
        };
        self.finalize(&cert);
        Ok(Some(cert))
    }

    /// Counts a whole certificate (voters send it after their vote).
    pub fn on_cert(&mut self, cert: &FinalityCert) -> Result<(), VoteErr> {
        if cert.epoch != self.epoch {
            return Err(VoteErr::Epoch(cert.epoch));
        }
        verify_finality_cert(cert, &self.committee)?;
        self.finalize(cert);
        Ok(())
    }

    /// A final proposal makes its ancestors final (07 §6.7), so `final_height` only grows.
    fn finalize(&mut self, cert: &FinalityCert) {
        self.final_height = self.final_height.max(cert.proposal.last_height);
        self.final_view = self.final_view.max(cert.view);
        let v = self.final_view;
        self.pending.retain(|(view, ..), _| *view > v);
        self.voted.retain(|(view, _)| *view > v);
    }
}

/// What core 4 does after a [`Gate::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateAction {
    /// No change.
    Hold,
    /// Put `HaltReq` on the BBO control ring: `Control(Halt)` follows (07 §6.8).
    Halt,
    /// `Control(Resume)`.
    Resume,
}

/// INV-REP-10 (07 §6.8): block `h + 9` opens only when block `h` is final.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gate {
    halted: bool,
}

impl Gate {
    pub fn halted(&self) -> bool {
        self.halted
    }

    /// The check at every flush: `lag = closed_height − final_height`.
    pub fn check(&mut self, closed_height: Height, final_height: Height) -> GateAction {
        let lag = closed_height.0.saturating_sub(final_height.0);
        if !self.halted && lag > FIN_GATE_BLOCKS {
            self.halted = true;
            GateAction::Halt
        } else if self.halted && lag <= GATE_RESUME_BLOCKS {
            self.halted = false;
            GateAction::Resume
        } else {
            GateAction::Hold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposal::ProposalKind;
    use vyrn_types::{Hash, Mode};

    fn seed(i: u8) -> [u8; 32] {
        [i + 1; 32]
    }

    fn listener(mode: Mode) -> Listener {
        let n = u8::try_from(mode.n()).unwrap_or(0);
        let voters = (0..n)
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .collect();
        let c = Committee::new(mode, voters, &[]).unwrap_or_else(|e| panic!("{e}"));
        Listener::new(c, Epoch(7), Height(100))
    }

    fn vote(i: u8, view: u64, last: u64) -> FinalizeVote {
        let proposal = Proposal {
            kind: ProposalKind::Headers,
            epoch: Epoch(7),
            first_height: Height(101),
            last_height: Height(last),
            last_hash: Hash([u8::try_from(last % 256).unwrap_or(0); 32]),
            excl_root: Hash([0; 32]),
        };
        let msg = finalize_message(Epoch(7), view, view - 1, &proposal, None);
        FinalizeVote {
            epoch: Epoch(7),
            view,
            parent_view: view - 1,
            proposal,
            index: i,
            sig: vyrn_crypto::ed25519::sign(&seed(i), &msg),
            seal: None,
        }
    }

    #[test]
    fn quorum_of_votes_is_final_and_yields_a_valid_cert() {
        let mut l = listener(Mode::Chain);
        for i in [4, 0, 2] {
            assert_eq!(l.on_vote(&vote(i, 5, 103)), Ok(None));
            // A repeat counts once.
            assert_eq!(l.on_vote(&vote(i, 5, 103)), Ok(None));
        }
        assert_eq!(l.final_height(), Height(100));
        let cert = l
            .on_vote(&vote(1, 5, 103))
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("no cert at Q"));
        assert_eq!(l.final_height(), Height(103));
        assert_eq!(
            cert.sigs.iter().map(|s| s.0).collect::<Vec<_>>(),
            vec![0, 1, 2, 4]
        );
        assert_eq!(verify_finality_cert(&cert, &l.committee), Ok(()));
        // A late vote for a final view changes nothing.
        assert_eq!(l.on_vote(&vote(3, 5, 103)), Ok(None));
        // The wire form is a one-entry REP_FinalityCert.
        let v = vote(3, 6, 104);
        assert_eq!(v.encode().len(), 106 + 65);
        assert_eq!(FinalizeVote::decode(&v.encode()), Ok(v));
        assert_eq!(FinalizeVote::decode(&cert.encode()), Err(CertErr::Length));
    }

    #[test]
    fn forged_split_and_far_votes_do_not_finalize() {
        let mut l = listener(Mode::Base);
        // Q - 1 valid votes plus one forged: not final.
        assert_eq!(l.on_vote(&vote(0, 3, 102)), Ok(None));
        assert_eq!(l.on_vote(&vote(1, 3, 102)), Ok(None));
        let mut forged = vote(2, 3, 102);
        forged.sig = vote(2, 4, 102).sig;
        assert_eq!(l.on_vote(&forged), Err(VoteErr::Cert(CertErr::BadSig(2))));
        // Voter 2 votes a different proposal in view 3; then may not vote again in that view.
        assert_eq!(l.on_vote(&vote(2, 3, 101)), Ok(None));
        assert_eq!(l.on_vote(&vote(2, 3, 102)), Err(VoteErr::Twice(2)));
        assert_eq!(l.final_height(), Height(100));
        assert_eq!(
            l.on_vote(&vote(0, VIEW_WINDOW + 1, 102)),
            Err(VoteErr::Ahead(VIEW_WINDOW + 1))
        );
        let mut other = vote(0, 3, 102);
        other.epoch = Epoch(8);
        assert_eq!(l.on_vote(&other), Err(VoteErr::Epoch(Epoch(8))));
        assert_eq!(
            l.on_vote(&vote(4, 3, 102)),
            Err(VoteErr::Cert(CertErr::Unknown(4)))
        );
        // A certificate finalizes without votes, and never moves final_height back.
        let mut cert = vote(0, 9, 110).as_cert();
        cert.sigs
            .extend([vote(1, 9, 110), vote(3, 9, 110)].map(|v| (v.index, v.sig)));
        assert_eq!(l.on_cert(&cert), Ok(()));
        assert_eq!(l.final_height(), Height(110));
        let mut low = vote(0, 3, 102).as_cert();
        low.sigs
            .extend([vote(1, 3, 102), vote(3, 3, 102)].map(|v| (v.index, v.sig)));
        assert_eq!(l.on_cert(&low), Ok(()));
        assert_eq!(l.final_height(), Height(110));
        cert.sigs.pop();
        assert_eq!(
            l.on_cert(&cert),
            Err(VoteErr::Cert(CertErr::TooFew { got: 2, need: 3 }))
        );
    }

    #[test]
    fn gate_halts_above_8_and_resumes_at_4() {
        let mut g = Gate::default();
        let f = Height(100);
        assert_eq!(g.check(Height(108), f), GateAction::Hold);
        assert_eq!(g.check(Height(109), f), GateAction::Halt);
        assert!(g.halted());
        assert_eq!(g.check(Height(112), f), GateAction::Hold);
        // Between 4 and 8 stays halted (hysteresis).
        assert_eq!(g.check(Height(112), Height(105)), GateAction::Hold);
        assert_eq!(g.check(Height(112), Height(108)), GateAction::Resume);
        assert_eq!(g.check(Height(112), Height(108)), GateAction::Hold);
        assert!(!g.halted());
    }
}
