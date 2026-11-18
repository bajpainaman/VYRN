//! Who votes: the voters of `REP_Membership` (spec/07-replication.md §13.1) as one committee.
//!
//! A voter is named by its **voter index**, its position in `REP_Membership.voters` (07 §2.2).
//! Certificates carry that index (07 §6.5). Commonware orders participants by sorted public key,
//! so its signer index is a different number; [`Committee`] maps one to the other, and only this
//! crate ever sees the Commonware index.
//!
//! The sequencer never votes (01 §14.4): a committee refuses any `seq_key` among its voters.
//!
//! **Who leads.** [`Committee::leader`] is the elector of 07 §6.3: plain round-robin in
//! `REP_Membership.voters` order. [`VoterOrder`] hands the same schedule to Simplex, so the leader
//! Simplex elects and the leader §9.2 names to build a seal are one function.
//!
//! Spec gap (07 §6.3 says "plain `RoundRobin` over the voters" without the arithmetic). Reading
//! taken: Commonware `RoundRobin`'s `(epoch + view) mod n` with no shuffle seed, indexing
//! `REP_Membership.voters` instead of the sorted keys. Only the order differs from Commonware's.

use commonware_codec::DecodeExt;
use commonware_consensus::{
    simplex::elector::{Config as ElectorConfig, Elector, Scheduled, Terms},
    types::Round,
};
use commonware_cryptography::{certificate::Scheme, ed25519};
use commonware_utils::{Participant, ordered::Set};
use thiserror::Error;
use vyrn_types::{Epoch, Mode, PubKey};

/// Why a voter list is not a valid committee (07 §13.1 validation rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CommitteeErr {
    #[error("{mode:?} needs {need} voters, got {got}")]
    Size { mode: Mode, need: usize, got: usize },
    #[error("voter {0} repeats an earlier vote_key")]
    Duplicate(u8),
    #[error("voter {0} is a sequencer key; the sequencer never votes (01 §14.4)")]
    Sequencer(u8),
    #[error("voter {0} is not a valid Ed25519 public key")]
    BadKey(u8),
}

/// The `n` voters of one home and epoch, in `REP_Membership.voters` order.
#[derive(Clone, Debug)]
pub struct Committee {
    mode: Mode,
    voters: Vec<PubKey>,
    /// The same keys as Commonware participants, sorted.
    participants: Set<ed25519::PublicKey>,
}

impl Committee {
    /// Builds the committee of `mode` from `voters` (in voter-index order) and the
    /// `REP_Membership.seq_order` keys, which must all be absent from `voters`.
    pub fn new(mode: Mode, voters: Vec<PubKey>, seq_keys: &[PubKey]) -> Result<Self, CommitteeErr> {
        if voters.len() != mode.n() {
            return Err(CommitteeErr::Size {
                mode,
                need: mode.n(),
                got: voters.len(),
            });
        }
        let mut keys = Vec::with_capacity(voters.len());
        for (i, key) in voters.iter().enumerate() {
            // n ≤ 5, so the index always fits.
            let index = u8::try_from(i).unwrap_or(u8::MAX);
            if voters[..i].contains(key) {
                return Err(CommitteeErr::Duplicate(index));
            }
            if seq_keys.contains(key) {
                return Err(CommitteeErr::Sequencer(index));
            }
            keys.push(
                ed25519::PublicKey::decode(key.to_vec())
                    .map_err(|_| CommitteeErr::BadKey(index))?,
            );
        }
        let participants = Set::try_from(keys).map_err(|_| CommitteeErr::Duplicate(0))?;
        Ok(Self {
            mode,
            voters,
            participants,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// `N_BASE` or `N_CHAIN`.
    pub fn n(&self) -> usize {
        self.voters.len()
    }

    /// `Q_BASE` or `Q_CHAIN` (`INV-QUORUM`).
    pub fn quorum(&self) -> usize {
        self.mode.quorum()
    }

    /// The `vote_key` of voter `index`.
    pub fn voter(&self, index: u8) -> Option<&PubKey> {
        self.voters.get(usize::from(index))
    }

    /// The voter index of `key`, or `None` when `key` does not vote.
    pub fn index_of(&self, key: &PubKey) -> Option<u8> {
        let i = self.voters.iter().position(|k| k == key)?;
        u8::try_from(i).ok()
    }

    /// The voter index that leads `view` of `epoch` (07 §6.3): `(epoch + view) mod n`. No index
    /// is skipped and a failover does not change it (07 §6.3, §9.2).
    pub fn leader(&self, epoch: Epoch, view: u64) -> u8 {
        let n = self.voters.len().max(1) as u64;
        // n ≤ 5, so the index always fits.
        u8::try_from(u64::from(epoch.0).wrapping_add(view) % n).unwrap_or(u8::MAX)
    }

    /// The Simplex elector of this committee (07 §6.3).
    pub fn elector(&self) -> VoterOrder {
        // For each voter index, its Commonware participant index.
        let order = self
            .voters
            .iter()
            .filter_map(|v| {
                let at = self.participants.iter().position(|k| {
                    let bytes: &[u8] = k.as_ref();
                    bytes == v.as_slice()
                })?;
                Some(Participant::from_usize(at))
            })
            .collect();
        VoterOrder { order }
    }

    /// The Commonware participant set (sorted keys).
    pub(crate) fn participants(&self) -> &Set<ed25519::PublicKey> {
        &self.participants
    }

    /// The voter index behind a Commonware signer index.
    pub(crate) fn voter_of(&self, participant: Participant) -> Option<u8> {
        let key = self
            .participants
            .get(usize::try_from(participant.get()).ok()?)?;
        let bytes: &[u8] = key.as_ref();
        self.voters
            .iter()
            .position(|k| k.as_slice() == bytes)
            .and_then(|i| u8::try_from(i).ok())
    }
}

/// The elector of 07 §6.3 for `commonware-consensus` Simplex: round-robin over
/// `REP_Membership.voters` order. It is both the elector config and the built elector; build it
/// with [`Committee::elector`].
#[derive(Clone, Debug)]
pub struct VoterOrder {
    /// `order[i]` is the Commonware participant index of voter `i`.
    order: Vec<Participant>,
}

impl<S: Scheme> ElectorConfig<S> for VoterOrder {
    type Elector = Self;

    /// Panics if `participants` is not the committee this elector came from: Simplex would
    /// otherwise elect leaders other voters do not.
    fn build(self, participants: &Set<S::PublicKey>) -> Self {
        assert_eq!(
            participants.len(),
            self.order.len(),
            "elector built for another committee"
        );
        self
    }
}

impl<S: Scheme> Elector<S> for VoterOrder {
    type Mode = Scheduled;

    fn terms(&self) -> Terms {
        Terms::rotating()
    }

    fn elect(&self, round: Round, _: ()) -> Participant {
        let n = self.order.len().max(1) as u64;
        let at = round.epoch().get().wrapping_add(round.view().get()) % n;
        self.order
            .get(usize::try_from(at).unwrap_or(0))
            .copied()
            .unwrap_or(Participant::new(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::scheme::ed25519::Scheme as Ed,
        types::{Epoch as CwEpoch, View},
    };

    fn key(seed: u8) -> PubKey {
        vyrn_crypto::ed25519::public_key(&[seed; 32])
    }

    #[test]
    fn sizes_follow_the_mode() {
        let four: Vec<_> = (1..=4).map(key).collect();
        let c = Committee::new(Mode::Base, four.clone(), &[]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((c.n(), c.quorum()), (4, 3));
        assert!(matches!(
            Committee::new(Mode::Chain, four, &[]),
            Err(CommitteeErr::Size {
                need: 5,
                got: 4,
                ..
            })
        ));
        let five: Vec<_> = (1..=5).map(key).collect();
        let c = Committee::new(Mode::Chain, five, &[]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((c.n(), c.quorum()), (5, 4));
    }

    #[test]
    fn the_sequencer_and_duplicates_are_refused() {
        let voters: Vec<_> = (1..=4).map(key).collect();
        assert_eq!(
            Committee::new(Mode::Base, voters.clone(), &[key(3)]).err(),
            Some(CommitteeErr::Sequencer(2))
        );
        let dup = vec![key(1), key(2), key(1), key(4)];
        assert_eq!(
            Committee::new(Mode::Base, dup, &[]).err(),
            Some(CommitteeErr::Duplicate(2))
        );
    }

    #[test]
    fn simplex_elects_in_membership_order() {
        // Voters listed in an order their sorted keys do not follow.
        let voters: Vec<_> = [9, 3, 7, 1, 5].into_iter().map(key).collect();
        let mut sorted = voters.clone();
        sorted.sort();
        assert_ne!(sorted, voters);
        let c = Committee::new(Mode::Chain, voters.clone(), &[]).unwrap_or_else(|e| panic!("{e}"));
        let elector: VoterOrder =
            <VoterOrder as ElectorConfig<Ed>>::build(c.elector(), c.participants());
        for epoch in [0u32, 3, u32::MAX] {
            for view in [1u64, 2, 3, 4, 5, 6, 11, 1 << 40] {
                let round = Round::new(CwEpoch::new(u64::from(epoch)), View::new(view));
                let p = Elector::<Ed>::elect(&elector, round, ());
                let elected: &[u8] = c
                    .participants()
                    .get(usize::try_from(p.get()).unwrap_or(usize::MAX))
                    .map_or(&[], |k| k.as_ref());
                // Independent of the code under test: (epoch + view) mod 5 into `voters`.
                let want = (u128::from(epoch) + u128::from(view)) % 5;
                let want = u8::try_from(want).unwrap_or(u8::MAX);
                assert_eq!(
                    c.leader(Epoch(epoch), view),
                    want,
                    "epoch {epoch} view {view}"
                );
                assert_eq!(elected, voters[usize::from(want)].as_slice());
            }
        }
        // Consecutive views never repeat a leader (07 §6.6: one view in n).
        let leaders: Vec<u8> = (1..=10).map(|v| c.leader(Epoch(0), v)).collect();
        assert_eq!(leaders, vec![1, 2, 3, 4, 0, 1, 2, 3, 4, 0]);
    }

    #[test]
    fn commonware_indices_map_back_to_voter_indices() {
        let voters: Vec<_> = (1..=4).map(key).collect();
        let c = Committee::new(Mode::Base, voters.clone(), &[]).unwrap_or_else(|e| panic!("{e}"));
        for p in 0..4u32 {
            let v = c.voter_of(Participant::new(p)).unwrap_or(u8::MAX);
            let cw: &[u8] = c.participants().get(p as usize).map_or(&[], |k| k.as_ref());
            assert_eq!(c.voter(v).map(|k| k.as_slice()), Some(cw));
        }
        assert_eq!(c.voter_of(Participant::new(4)), None);
    }
}
