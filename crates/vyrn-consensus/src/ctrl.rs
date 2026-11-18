//! What consensus puts on `REP_UDP_CTRL` (spec/07-replication.md §6.8): each voter's
//! `REP_FinalizeVote`s and `REP_FinalityCert`s, sent to the sequencer's and the standby's CTRL
//! port. Simplex traffic between voters is not here: it runs on `commonware-p2p` (07 §3.1,
//! [`crate::net`]).
//!
//! **Datagram** (07 §6.8): the 07 §6.5 bytes and nothing else. A `REP_FinalizeVote` is a
//! `REP_FinalityCert` with `count = 1` (171 B under scheme 0), so one decoder serves both and the
//! count tells them apart: no certificate has fewer than `Q` ≥ 3 entries. Validity is the
//! consumer's check ([`crate::Listener`], [`crate::verify_finality_cert`]).

use crate::cert::{CertErr, FinalityCert};
use crate::observer::FinalizeVote;

/// One decoded `REP_UDP_CTRL` datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ctrl {
    Vote(FinalizeVote),
    Cert(FinalityCert),
}

/// A `REP_FinalizeVote` datagram.
pub fn encode_vote(v: &FinalizeVote) -> Vec<u8> {
    v.encode()
}

/// A `REP_FinalityCert` datagram.
pub fn encode_cert(c: &FinalityCert) -> Vec<u8> {
    c.encode()
}

/// Parses one datagram. Structure only: votes and certificates are verified by their consumer.
pub fn decode(bytes: &[u8]) -> Result<Ctrl, CertErr> {
    let c = FinalityCert::decode(bytes)?;
    Ok(match c.sigs[..] {
        [(index, sig)] => Ctrl::Vote(FinalizeVote {
            epoch: c.epoch,
            view: c.view,
            parent_view: c.parent_view,
            proposal: c.proposal,
            index,
            sig,
            seal: c.seal,
        }),
        _ => Ctrl::Cert(c),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::proposal::{Proposal, ProposalKind};
    use vyrn_types::{Epoch, Hash, Height};

    fn vote() -> FinalizeVote {
        FinalizeVote {
            epoch: Epoch(1),
            view: 5,
            parent_view: 4,
            proposal: Proposal {
                kind: ProposalKind::Headers,
                epoch: Epoch(1),
                first_height: Height(3),
                last_height: Height(4),
                last_hash: Hash([7; 32]),
                excl_root: Hash([0; 32]),
            },
            index: 2,
            sig: [9; 64],
            seal: None,
        }
    }

    #[test]
    fn the_count_tells_a_vote_from_a_certificate() {
        let v = vote();
        let d = encode_vote(&v);
        // 07 §6.8: 106 + 65 = 171 B under scheme 0, no framing byte.
        assert_eq!(d.len(), 171);
        assert_eq!(decode(&d), Ok(Ctrl::Vote(v.clone())));
        let c = FinalityCert {
            epoch: v.epoch,
            view: v.view,
            parent_view: v.parent_view,
            proposal: v.proposal,
            sigs: vec![(0, [1; 64]), (1, [2; 64]), (2, [3; 64])],
            seal: None,
        };
        assert_eq!(decode(&encode_cert(&c)), Ok(Ctrl::Cert(c)));
        assert_eq!(decode(&d[..170]), Err(CertErr::Length));
        assert_eq!(decode(&[]), Err(CertErr::Length));
    }
}
