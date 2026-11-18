//! Conflict evidence (spec/07-replication.md §10): proofs of a faulty sequencer or voter that
//! anyone with `REP_Membership` checks offline.
//!
//! | Fault | Type | Check | Spec |
//! |---|---|---|---|
//! | Two signed headers for one `(epoch, height)` | [`SeqEquivocation`] | [`SeqEquivocation::verify`] under the tenure's `seq_key` | 07 §10.1 |
//! | Conflicting votes of one voter in one view | [`VoterFault`] ([`FaultKind`]) | [`VoterFault::verify`] against the committee | 07 §10.2 |
//!
//! A voter's Simplex reporter hands out every [`VoterFault`] it sees through
//! [`crate::voter::Outputs::faults`]; 09 slashes on it in CHAIN, and both modes remove the voter at
//! the next epoch. The holder of a [`SeqEquivocation`] broadcasts it and suspects at once with
//! [`crate::silence::Reason::Equivocation`] (07 §10.1).
//!
//! **What is signed.** A [`VoterFault`] carries the two Simplex votes in their
//! `commonware-consensus` 2026.10.0 encoding. [`VoterFault::verify`] rebuilds each vote's signed
//! bytes (namespace `b"vyrn-v1"` plus Commonware's `_NOTARIZE`, `_NULLIFY` or `_FINALIZE`
//! suffix, as [`crate::cert`] does for finalize votes) and checks them with
//! `vyrn_crypto::ed25519::verify` (ZIP-215), so no Commonware state is needed.
//!
//! Spec gaps (labelled `Spec gap` below):
//! 1. 07 §10.1 gives `SeqEquivocation{epoch, height, header_a [190], header_b [190]}` as 384 B,
//!    but those fields add up to 4 + 8 + 190 + 190 = 392. Reading: the fields as listed, 392 B.
//!    **Wire layout differs from the stated size.**
//! 2. 07 §10.2 names the Simplex evidence but no VYRN wire form. Reading: `kind u8 ‖ voter u8 ‖`
//!    the Commonware encoding of the two votes. **New wire record**, tied to the pinned
//!    Commonware version, as `REP_FinalityCert`'s signed bytes already are (07 §6.5).

use crate::cert::NAMESPACE;
use crate::membership::Committee;
use commonware_codec::{Copying, Encode, Read};
use commonware_consensus::simplex::{
    scheme::ed25519::Scheme,
    types::{Finalize, Notarize, Nullify, Proposal as CwProposal},
};
use commonware_consensus::types::Round;
use commonware_cryptography::{blake3::Digest, certificate::Attestation};
use thiserror::Error;
use vyrn_log::block::{HEADER_BYTES, decode_header, encode_header, verify_seq_sig};
use vyrn_types::{BlockHeader, Epoch, Height, PubKey};

/// Encoded size of a [`SeqEquivocation`] (spec gap 1).
pub const SEQ_EQUIVOCATION_BYTES: usize = 4 + 8 + 2 * HEADER_BYTES;

/// Why evidence proves nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EvidenceErr {
    #[error("evidence bytes are malformed")]
    Malformed,
    #[error("unknown fault kind {0}")]
    Kind(u8),
    #[error("the two items are not for the same epoch, height or round")]
    Mismatch,
    #[error("the two items do not conflict")]
    NoConflict,
    #[error("the items are not both signed by the named signer")]
    Signer,
    #[error("a signature is invalid")]
    BadSig,
}

/// `SeqEquivocation` (07 §10.1): two headers for one `(epoch, height)` with different bytes,
/// both with a valid `seq_sig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqEquivocation {
    pub epoch: Epoch,
    pub height: Height,
    pub header_a: BlockHeader,
    pub header_b: BlockHeader,
}

impl SeqEquivocation {
    /// The evidence of `a` and `b` when they prove equivocation under `seq_key`.
    pub fn from_headers(a: &BlockHeader, b: &BlockHeader, seq_key: &PubKey) -> Option<Self> {
        let e = Self {
            epoch: a.epoch,
            height: a.height,
            header_a: *a,
            header_b: *b,
        };
        e.verify(seq_key).ok().map(|()| e)
    }

    /// `Ok` exactly when both headers carry `epoch` and `height`, differ in their bytes, and
    /// both `seq_sig`s verify under `seq_key`.
    pub fn verify(&self, seq_key: &PubKey) -> Result<(), EvidenceErr> {
        let (a, b) = (&self.header_a, &self.header_b);
        if (a.epoch, a.height) != (self.epoch, self.height)
            || (b.epoch, b.height) != (self.epoch, self.height)
        {
            return Err(EvidenceErr::Mismatch);
        }
        if encode_header(a) == encode_header(b) {
            return Err(EvidenceErr::NoConflict);
        }
        if !verify_seq_sig(a, seq_key) || !verify_seq_sig(b, seq_key) {
            return Err(EvidenceErr::BadSig);
        }
        Ok(())
    }

    /// `epoch u32 ‖ height u64 ‖ header_a [190] ‖ header_b [190]`, little-endian.
    pub fn encode(&self) -> [u8; SEQ_EQUIVOCATION_BYTES] {
        let mut out = [0u8; SEQ_EQUIVOCATION_BYTES];
        out[..4].copy_from_slice(&self.epoch.0.to_le_bytes());
        out[4..12].copy_from_slice(&self.height.0.to_le_bytes());
        out[12..12 + HEADER_BYTES].copy_from_slice(&encode_header(&self.header_a));
        out[12 + HEADER_BYTES..].copy_from_slice(&encode_header(&self.header_b));
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceErr> {
        let b: &[u8; SEQ_EQUIVOCATION_BYTES] =
            bytes.try_into().map_err(|_| EvidenceErr::Malformed)?;
        let header = |at: usize| {
            b[at..at + HEADER_BYTES]
                .try_into()
                .map(decode_header)
                .map_err(|_| EvidenceErr::Malformed)
        };
        Ok(Self {
            epoch: Epoch(u32::from_le_bytes(
                b[..4].try_into().map_err(|_| EvidenceErr::Malformed)?,
            )),
            height: Height(u64::from_le_bytes(
                b[4..12].try_into().map_err(|_| EvidenceErr::Malformed)?,
            )),
            header_a: header(12)?,
            header_b: header(12 + HEADER_BYTES)?,
        })
    }
}

/// The Simplex conflict evidence of 07 §10.2, as Commonware's reporter names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FaultKind {
    /// Two notarize votes for different proposals in one view.
    ConflictingNotarize = 0,
    /// Two finalize votes for different proposals in one view.
    ConflictingFinalize = 1,
    /// A nullify and a finalize in one view.
    NullifyFinalize = 2,
}

/// A voter's conflicting votes in one view (07 §10.2), self-verifying given the committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoterFault {
    pub kind: FaultKind,
    /// The voter index of the faulty voter.
    pub voter: u8,
    /// The two votes in their Commonware encoding (spec gap 2).
    pub votes: Vec<u8>,
}

/// One decoded vote: its round, signer and the bytes it signs.
struct Signed {
    round: Round,
    signer: u32,
    /// What distinguishes two votes of one round: the proposal, or nothing for a nullify.
    subject: Option<CwProposal<Digest>>,
    message: Vec<u8>,
    sig: [u8; 64],
}

fn signed(
    attestation: &Attestation<Scheme>,
    round: Round,
    suffix: &[u8],
    subject: Option<CwProposal<Digest>>,
    body: &[u8],
) -> Result<Signed, EvidenceErr> {
    let sig: &[u8] = attestation
        .signature
        .get()
        .ok_or(EvidenceErr::Malformed)?
        .as_ref();
    let namespace = commonware_utils::union(NAMESPACE, suffix);
    Ok(Signed {
        round,
        signer: attestation.signer.get(),
        subject,
        message: commonware_utils::union_unique(&namespace, body),
        sig: sig.try_into().map_err(|_| EvidenceErr::Malformed)?,
    })
}

fn notarize(n: &Notarize<Scheme, Digest>) -> Result<Signed, EvidenceErr> {
    let p = n.proposal.clone();
    signed(
        &n.attestation,
        p.round,
        b"_NOTARIZE",
        Some(p.clone()),
        &p.encode(),
    )
}

fn finalize(f: &Finalize<Scheme, Digest>) -> Result<Signed, EvidenceErr> {
    let p = f.proposal.clone();
    signed(
        &f.attestation,
        p.round,
        b"_FINALIZE",
        Some(p.clone()),
        &p.encode(),
    )
}

fn nullify(n: &Nullify<Scheme>) -> Result<Signed, EvidenceErr> {
    signed(
        &n.attestation,
        n.round,
        b"_NULLIFY",
        None,
        &n.round.encode(),
    )
}

fn read<T: Read<Cfg = ()>>(buf: &mut Copying<'_>) -> Result<T, EvidenceErr> {
    T::read_cfg(buf, &()).map_err(|_| EvidenceErr::Malformed)
}

impl VoterFault {
    /// `kind u8 ‖ voter u8 ‖ votes` (spec gap 2).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.votes.len());
        out.push(self.kind as u8);
        out.push(self.voter);
        out.extend_from_slice(&self.votes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceErr> {
        let [kind, voter, votes @ ..] = bytes else {
            return Err(EvidenceErr::Malformed);
        };
        let kind = match kind {
            0 => FaultKind::ConflictingNotarize,
            1 => FaultKind::ConflictingFinalize,
            2 => FaultKind::NullifyFinalize,
            k => return Err(EvidenceErr::Kind(*k)),
        };
        Ok(Self {
            kind,
            voter: *voter,
            votes: votes.to_vec(),
        })
    }

    /// `Ok` exactly when `votes` holds two valid votes by voter `voter` of `committee` in one
    /// round that Simplex forbids together. Returns the round's `(epoch, view)`.
    pub fn verify(&self, committee: &Committee) -> Result<(u64, u64), EvidenceErr> {
        let mut buf = Copying(&self.votes);
        let (a, b) = match self.kind {
            FaultKind::ConflictingNotarize => {
                (notarize(&read(&mut buf)?)?, notarize(&read(&mut buf)?)?)
            }
            FaultKind::ConflictingFinalize => {
                (finalize(&read(&mut buf)?)?, finalize(&read(&mut buf)?)?)
            }
            FaultKind::NullifyFinalize => (nullify(&read(&mut buf)?)?, finalize(&read(&mut buf)?)?),
        };
        if !buf.0.is_empty() {
            return Err(EvidenceErr::Malformed);
        }
        if a.round != b.round {
            return Err(EvidenceErr::Mismatch);
        }
        // A nullify and any finalize conflict; two votes of one kind conflict on different
        // proposals.
        if self.kind != FaultKind::NullifyFinalize && a.subject == b.subject {
            return Err(EvidenceErr::NoConflict);
        }
        let signer = commonware_utils::Participant::new(a.signer);
        if a.signer != b.signer || committee.voter_of(signer) != Some(self.voter) {
            return Err(EvidenceErr::Signer);
        }
        let key = committee.voter(self.voter).ok_or(EvidenceErr::Signer)?;
        for v in [&a, &b] {
            if !vyrn_crypto::ed25519::verify(key, &v.message, &v.sig) {
                return Err(EvidenceErr::BadSig);
            }
        }
        Ok((a.round.epoch().get(), a.round.view().get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_consensus::simplex::types::{
        ConflictingFinalize, ConflictingNotarize, NullifyFinalize,
    };
    use commonware_consensus::types::{Epoch as CwEpoch, View};
    use commonware_cryptography::ed25519;
    use vyrn_log::block::sign_header;
    use vyrn_types::{BookId, Hash, Mode, StepId};

    fn seed(i: u8) -> [u8; 32] {
        [i + 1; 32]
    }

    fn committee() -> Committee {
        // Listed in an order their sorted keys do not follow, so voter and signer indices differ.
        let voters = [3u8, 0, 2, 1]
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .to_vec();
        Committee::new(Mode::Base, voters, &[]).unwrap_or_else(|e| panic!("{e}"))
    }

    fn scheme(c: &Committee, s: [u8; 32]) -> Scheme {
        let key = ed25519::PrivateKey::decode(s.to_vec()).unwrap_or_else(|_| panic!("key"));
        Scheme::signer(NAMESPACE, c.participants().clone(), key).unwrap_or_else(|| panic!("signer"))
    }

    fn proposal(view: u64, payload: u8) -> CwProposal<Digest> {
        CwProposal::new(
            Round::new(CwEpoch::new(7), View::new(view)),
            View::new(view - 1),
            Digest([payload; 32]),
        )
    }

    #[test]
    fn conflicting_votes_prove_a_fault_of_the_named_voter() {
        let c = committee();
        let s = scheme(&c, seed(2));
        let voter = c
            .index_of(&vyrn_crypto::ed25519::public_key(&seed(2)))
            .unwrap_or(u8::MAX);
        let n1 = Notarize::sign(&s, proposal(5, 1)).unwrap_or_else(|| panic!("sign"));
        let n2 = Notarize::sign(&s, proposal(5, 2)).unwrap_or_else(|| panic!("sign"));
        let f1 = Finalize::sign(&s, proposal(5, 1)).unwrap_or_else(|| panic!("sign"));
        let f2 = Finalize::sign(&s, proposal(5, 2)).unwrap_or_else(|| panic!("sign"));
        let x = Nullify::sign::<Digest>(&s, proposal(5, 1).round).unwrap_or_else(|| panic!("sign"));
        let cases = [
            (
                FaultKind::ConflictingNotarize,
                ConflictingNotarize::new(n1.clone(), n2).encode(),
            ),
            (
                FaultKind::ConflictingFinalize,
                ConflictingFinalize::new(f1.clone(), f2).encode(),
            ),
            (
                FaultKind::NullifyFinalize,
                NullifyFinalize::new(x, f1.clone()).encode(),
            ),
        ];
        for (kind, votes) in cases {
            let fault = VoterFault {
                kind,
                voter,
                votes: votes.to_vec(),
            };
            assert_eq!(fault.verify(&c), Ok((7, 5)), "{kind:?}");
            assert_eq!(VoterFault::decode(&fault.encode()), Ok(fault.clone()));
            // Blaming another voter, or one flipped signature byte, proves nothing.
            let mut other = fault.clone();
            other.voter = (voter + 1) % 4;
            assert_eq!(other.verify(&c), Err(EvidenceErr::Signer));
            let mut forged = fault.clone();
            let at = forged.votes.len() - 1;
            forged.votes[at] ^= 1;
            assert!(forged.verify(&c).is_err(), "{kind:?}");
            let mut long = fault.clone();
            long.votes.push(0);
            assert_eq!(long.verify(&c), Err(EvidenceErr::Malformed));
        }
        // The same vote twice is no conflict; votes of two views are no conflict either.
        let mut same = n1.encode().to_vec();
        same.extend_from_slice(&n1.encode());
        let fault = VoterFault {
            kind: FaultKind::ConflictingNotarize,
            voter,
            votes: same,
        };
        assert_eq!(fault.verify(&c), Err(EvidenceErr::NoConflict));
        let mut split = n1.encode().to_vec();
        split.extend_from_slice(
            &Notarize::sign(&s, proposal(6, 2))
                .unwrap_or_else(|| panic!("sign"))
                .encode(),
        );
        let fault = VoterFault {
            kind: FaultKind::ConflictingNotarize,
            voter,
            votes: split,
        };
        assert_eq!(fault.verify(&c), Err(EvidenceErr::Mismatch));
        assert_eq!(VoterFault::decode(&[3, 0]), Err(EvidenceErr::Kind(3)));
    }

    #[test]
    fn two_signed_headers_at_one_height_prove_equivocation() {
        let seq = [0x99; 32];
        let seq_key = vyrn_crypto::ed25519::public_key(&seq);
        let base = BlockHeader {
            height: Height(12),
            epoch: Epoch(7),
            book: BookId(1),
            first_step: StepId(100),
            last_step: StepId(110),
            prev: Hash([1; 32]),
            order_root: Hash([2; 32]),
            data_root: Hash([3; 32]),
            seq_sig: [0; 64],
        };
        let a = sign_header(&base, &seq);
        let b = sign_header(
            &BlockHeader {
                order_root: Hash([9; 32]),
                ..base
            },
            &seq,
        );
        let e = SeqEquivocation::from_headers(&a, &b, &seq_key)
            .unwrap_or_else(|| panic!("no evidence"));
        let bytes = e.encode();
        assert_eq!(bytes.len(), 392);
        assert_eq!(SeqEquivocation::decode(&bytes), Ok(e));
        assert_eq!(
            SeqEquivocation::decode(&bytes[..391]),
            Err(EvidenceErr::Malformed)
        );
        // The same header twice, another key, another height, or an unsigned header: no proof.
        assert_eq!(SeqEquivocation::from_headers(&a, &a, &seq_key), None);
        let other = vyrn_crypto::ed25519::public_key(&[0x98; 32]);
        assert_eq!(e.verify(&other), Err(EvidenceErr::BadSig));
        let c = sign_header(
            &BlockHeader {
                height: Height(13),
                ..base
            },
            &seq,
        );
        assert_eq!(SeqEquivocation::from_headers(&a, &c, &seq_key), None);
        let mut unsigned = e;
        unsigned.header_b.seq_sig = [0; 64];
        assert_eq!(unsigned.verify(&seq_key), Err(EvidenceErr::BadSig));
    }
}
