//! Who votes: the voters of `REP_Membership` (spec/07-replication.md §13.1) as one committee.
//!
//! A voter is named by its **voter index**, its position in `REP_Membership.voters` (07 §2.2).
//! Certificates carry that index (07 §6.5). Commonware orders participants by sorted public key,
//! so its signer index is a different number; [`Committee`] maps one to the other, and only this
//! crate ever sees the Commonware index.
//!
//! The sequencer never votes (01 §14.4): a committee refuses any `seq_key` among its voters.

use commonware_codec::DecodeExt;
use commonware_cryptography::ed25519;
use commonware_utils::{Participant, ordered::Set};
use thiserror::Error;
use vyrn_types::{Mode, PubKey};

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

#[cfg(test)]
mod tests {
    use super::*;

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
