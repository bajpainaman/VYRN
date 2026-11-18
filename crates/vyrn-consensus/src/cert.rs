//! `REP_FinalityCert`: what a finality certificate proves, and the one function that checks it
//! offline (spec/07-replication.md §6.5, `INV-QUORUM` in 01 §7).
//!
//! **What it proves.** At least `Q` distinct voters of the committee signed a Simplex finalize
//! vote for `proposal` in round `(epoch, view)` with parent `parent_view`. Finalizing `proposal`
//! makes every header in `first_height ..= last_height` final, and every ancestor with it,
//! because `last_hash` commits to the chain through `prev` (07 §6.3).
//!
//! **Who signs what.** Each voter signs, with its `vote_key`, exactly the bytes
//! `commonware-consensus` 2026.10.0 `simplex::scheme::ed25519` signs for a finalize vote:
//! [`finalize_message`]. The sequencer signs nothing here (01 §14.4).
//!
//! **What a verifier needs.** The certificate and the committee (`REP_Membership.voters`), nothing
//! else: no network, no log, no Commonware state. [`verify_finality_cert`] is the only check; no
//! other crate reimplements it (07 §6.5). Signatures are checked with
//! `vyrn_crypto::ed25519::verify` (ZIP-215, 11 §2.5).
//!
//! **What it does not reveal.** Only the 85-byte proposal: heights and hashes, never ORDER bytes,
//! payloads or sessions. CHAIN's `excl_root` is a hash, not the excluded list.
//!
//! **Seals.** A kind-1 certificate carries its `REP_SealExt` after the signature entries, and its
//! signers signed the seal digest (07 §9.4), so it too is checked from its own bytes.
//!
//! Conformance vectors: `vectors/finality_cert.txt`, checked by the `conformance` test.

use crate::membership::Committee;
use crate::proposal::{PROPOSAL_BYTES, Proposal, ProposalErr, ProposalKind};
use crate::tail::{SealExt, seal_digest};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::Proposal as CwProposal,
    types::{Epoch as CwEpoch, Round, View},
};
use commonware_cryptography::blake3;
use thiserror::Error;
use vyrn_types::{Ed25519Sig, Epoch};

/// The Simplex namespace (07 §6.3).
pub const NAMESPACE: &[u8] = b"vyrn-v1";
/// `simplex::scheme` appends this to [`NAMESPACE`] for finalize votes (commonware-consensus
/// 2026.10.0, `scheme/mod.rs` `FINALIZE_SUFFIX`).
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";
/// Bytes before the first signature entry.
pub const CERT_HEADER_BYTES: usize = 4 + 8 + 8 + PROPOSAL_BYTES + 1;
/// One `{ index u8, sig [u8; 64] }` entry.
pub const CERT_ENTRY_BYTES: usize = 1 + 64;

/// `REP_FinalityCert` (07 §6.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityCert {
    pub epoch: Epoch,
    pub view: u64,
    pub parent_view: u64,
    pub proposal: Proposal,
    /// `(voter index, finalize signature)`, ascending and distinct by index.
    pub sigs: Vec<(u8, Ed25519Sig)>,
    /// The seal's `REP_SealExt`: `Some` exactly when `proposal.kind` is [`ProposalKind::Seal`]
    /// (07 §9.4). Encoded after the signature entries.
    pub seal: Option<SealExt>,
}

/// Why a certificate does not prove finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CertErr {
    #[error("certificate bytes have the wrong length")]
    Length,
    #[error("bad proposal: {0}")]
    Proposal(ProposalErr),
    #[error("proposal epoch differs from the certificate's")]
    Epoch,
    #[error("{got} signatures, quorum is {need} (INV-QUORUM)")]
    TooFew { got: usize, need: usize },
    #[error("signer indices are not ascending and distinct")]
    Order,
    #[error("voter index {0} is not in the committee")]
    Unknown(u8),
    #[error("signature of voter {0} is invalid")]
    BadSig(u8),
    #[error("a seal certificate needs its REP_SealExt, and only a seal certificate has one")]
    Seal,
}

/// The exact bytes a voter's finalize signature covers: Commonware's
/// `union_unique(NAMESPACE ‖ "_FINALIZE", Proposal{ round: (epoch, view), parent, payload })`
/// with `payload = proposal.digest()`, or [`seal_digest`] for a seal with its `seal` (07 §9.4).
pub fn finalize_message(
    epoch: Epoch,
    view: u64,
    parent_view: u64,
    proposal: &Proposal,
    seal: Option<&SealExt>,
) -> Vec<u8> {
    let payload = seal.map_or_else(|| proposal.digest(), |ext| seal_digest(proposal, ext));
    let cw = CwProposal::new(
        Round::new(CwEpoch::new(u64::from(epoch.0)), View::new(view)),
        View::new(parent_view),
        blake3::Digest(payload.0),
    );
    let namespace = commonware_utils::union(NAMESPACE, FINALIZE_SUFFIX);
    commonware_utils::union_unique(&namespace, &cw.encode())
}

impl FinalityCert {
    /// The bytes this certificate's signers signed.
    pub fn message(&self) -> Vec<u8> {
        finalize_message(
            self.epoch,
            self.view,
            self.parent_view,
            &self.proposal,
            self.seal.as_ref(),
        )
    }

    /// The layout of 07 §6.5, little-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CERT_HEADER_BYTES + CERT_ENTRY_BYTES * self.sigs.len());
        out.extend_from_slice(&self.epoch.0.to_le_bytes());
        out.extend_from_slice(&self.view.to_le_bytes());
        out.extend_from_slice(&self.parent_view.to_le_bytes());
        out.extend_from_slice(&self.proposal.encode());
        out.push(u8::try_from(self.sigs.len()).unwrap_or(u8::MAX));
        for (index, sig) in &self.sigs {
            out.push(*index);
            out.extend_from_slice(sig);
        }
        if let Some(ext) = &self.seal {
            out.extend_from_slice(&ext.encode());
        }
        out
    }

    /// Parses 07 §6.5 bytes, with the trailing `REP_SealExt` of a seal (07 §9.4). Structure only;
    /// [`verify_finality_cert`] decides validity.
    pub fn decode(bytes: &[u8]) -> Result<Self, CertErr> {
        let head = bytes.get(..CERT_HEADER_BYTES).ok_or(CertErr::Length)?;
        let count = usize::from(head[CERT_HEADER_BYTES - 1]);
        let (entries, rest) = bytes[CERT_HEADER_BYTES..]
            .split_at_checked(count * CERT_ENTRY_BYTES)
            .ok_or(CertErr::Length)?;
        let u64_at = |at: usize| u64::from_le_bytes(head[at..at + 8].try_into().unwrap_or([0; 8]));
        let proposal =
            Proposal::decode(&head[20..20 + PROPOSAL_BYTES]).map_err(CertErr::Proposal)?;
        let seal = match proposal.kind {
            ProposalKind::Seal => Some(SealExt::decode(rest).map_err(|_| CertErr::Length)?),
            ProposalKind::Headers if rest.is_empty() => None,
            ProposalKind::Headers => return Err(CertErr::Length),
        };
        let sigs = entries
            .as_chunks::<CERT_ENTRY_BYTES>()
            .0
            .iter()
            .map(|e| (e[0], e[1..].try_into().unwrap_or([0; 64])))
            .collect();
        Ok(Self {
            epoch: Epoch(u32::from_le_bytes(head[0..4].try_into().unwrap_or([0; 4]))),
            view: u64_at(4),
            parent_view: u64_at(12),
            proposal,
            sigs,
            seal,
        })
    }
}

/// `verify_finality_cert(&cert, &membership)` of 07 §6.5: `Ok` exactly when the certificate
/// holds at least `Q` valid finalize signatures from distinct voters of `committee`.
pub fn verify_finality_cert(cert: &FinalityCert, committee: &Committee) -> Result<(), CertErr> {
    cert.proposal.check_range().map_err(CertErr::Proposal)?;
    if cert.proposal.epoch != cert.epoch {
        return Err(CertErr::Epoch);
    }
    if (cert.proposal.kind == ProposalKind::Seal) != cert.seal.is_some() {
        return Err(CertErr::Seal);
    }
    let need = committee.quorum();
    if cert.sigs.len() < need {
        return Err(CertErr::TooFew {
            got: cert.sigs.len(),
            need,
        });
    }
    if cert.sigs.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(CertErr::Order);
    }
    let message = cert.message();
    for (index, sig) in &cert.sigs {
        let key = committee.voter(*index).ok_or(CertErr::Unknown(*index))?;
        if !vyrn_crypto::ed25519::verify(key, &message, sig) {
            return Err(CertErr::BadSig(*index));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposal::ProposalKind;
    use vyrn_types::{Hash, Height, Mode};

    /// Voter `i` (0-based) has seed `[i + 1; 32]`.
    fn seed(i: u8) -> [u8; 32] {
        [i + 1; 32]
    }

    fn committee(mode: Mode) -> Committee {
        let n = u8::try_from(mode.n()).unwrap_or(0);
        let voters = (0..n)
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .collect();
        Committee::new(mode, voters, &[]).unwrap_or_else(|e| panic!("{e}"))
    }

    fn signed(signers: &[u8]) -> FinalityCert {
        let proposal = Proposal {
            kind: ProposalKind::Headers,
            epoch: Epoch(7),
            first_height: Height(101),
            last_height: Height(101),
            last_hash: Hash([0x5A; 32]),
            excl_root: Hash([0; 32]),
        };
        let mut cert = FinalityCert {
            epoch: Epoch(7),
            view: 42,
            parent_view: 41,
            proposal,
            sigs: Vec::new(),
            seal: None,
        };
        let msg = cert.message();
        cert.sigs = signers
            .iter()
            .map(|&i| (i, vyrn_crypto::ed25519::sign(&seed(i), &msg)))
            .collect();
        cert
    }

    #[test]
    fn quorum_of_valid_signatures_is_final() {
        let base = committee(Mode::Base);
        assert_eq!(verify_finality_cert(&signed(&[0, 1, 3]), &base), Ok(()));
        let chain = committee(Mode::Chain);
        assert_eq!(verify_finality_cert(&signed(&[0, 1, 2, 4]), &chain), Ok(()));
    }

    #[test]
    fn fewer_than_quorum_is_rejected() {
        let base = committee(Mode::Base);
        assert_eq!(
            verify_finality_cert(&signed(&[0, 2]), &base),
            Err(CertErr::TooFew { got: 2, need: 3 })
        );
        // Three valid BASE signatures are still too few for CHAIN.
        let chain = committee(Mode::Chain);
        assert_eq!(
            verify_finality_cert(&signed(&[0, 1, 2]), &chain),
            Err(CertErr::TooFew { got: 3, need: 4 })
        );
    }

    #[test]
    fn repeated_unknown_and_forged_signers_are_rejected() {
        let base = committee(Mode::Base);
        let mut dup = signed(&[0, 1, 2]);
        dup.sigs[2] = dup.sigs[1];
        assert_eq!(verify_finality_cert(&dup, &base), Err(CertErr::Order));
        assert_eq!(
            verify_finality_cert(&signed(&[0, 1, 4]), &base),
            Err(CertErr::Unknown(4))
        );
        let mut forged = signed(&[0, 1, 2]);
        forged.view = 43;
        forged.sigs[2] = signed(&[2]).sigs[0];
        assert_eq!(
            verify_finality_cert(&forged, &base),
            Err(CertErr::BadSig(0))
        );
    }

    #[test]
    fn encoding_round_trips_with_07_sizes() {
        let cert = signed(&[0, 1, 2, 3]);
        let bytes = cert.encode();
        // 07 §6.5: "about 0.37 KB (Q = 4)".
        assert_eq!(bytes.len(), 106 + 4 * 65);
        assert_eq!(FinalityCert::decode(&bytes), Ok(cert));
        assert_eq!(
            FinalityCert::decode(&bytes[..bytes.len() - 1]),
            Err(CertErr::Length)
        );
    }

    #[test]
    fn a_seal_cert_carries_its_ext_and_verifies_alone() {
        let base = committee(Mode::Base);
        let proposal = Proposal {
            kind: ProposalKind::Seal,
            epoch: Epoch(7),
            first_height: Height(90),
            last_height: Height(101),
            last_hash: Hash([0x5A; 32]),
            excl_root: Hash([0; 32]),
        };
        let ext = SealExt {
            end_frame_seq: [500, 480],
            next_seq: 1,
            next_tenure: 3,
            unavail: vec![(vyrn_types::SessionId(4), 9)],
        };
        let mut cert = FinalityCert {
            epoch: Epoch(7),
            view: 42,
            parent_view: 41,
            proposal,
            sigs: Vec::new(),
            seal: Some(ext.clone()),
        };
        let msg = cert.message();
        cert.sigs = [0u8, 1, 3]
            .iter()
            .map(|&i| (i, vyrn_crypto::ed25519::sign(&seed(i), &msg)))
            .collect();
        assert_eq!(verify_finality_cert(&cert, &base), Ok(()));
        // 07 §6.5 layout, then REP_SealExt: 106 + 3·65 + 22 + 8·n_unavail.
        let bytes = cert.encode();
        assert_eq!(bytes.len(), 106 + 3 * 65 + 22 + 8);
        assert_eq!(&bytes[106 + 3 * 65..], &ext.encode()[..]);
        let back = FinalityCert::decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back, cert);
        assert_eq!(verify_finality_cert(&back, &base), Ok(()));
        // Without its ext, or with a truncated one, a seal cert does not decode.
        assert_eq!(
            FinalityCert::decode(&bytes[..106 + 3 * 65]),
            Err(CertErr::Length)
        );
        assert_eq!(
            FinalityCert::decode(&bytes[..bytes.len() - 1]),
            Err(CertErr::Length)
        );
        // The signatures cover the ext: another next_seq breaks them.
        let mut other = cert.clone();
        other.seal = Some(SealExt { next_seq: 2, ..ext });
        assert_eq!(verify_finality_cert(&other, &base), Err(CertErr::BadSig(0)));
        // A seal without its ext, or headers with one, is refused before any signature check.
        let mut bare = cert.clone();
        bare.seal = None;
        assert_eq!(verify_finality_cert(&bare, &base), Err(CertErr::Seal));
        let mut headers = signed(&[0, 1, 3]);
        headers.seal = cert.seal.clone();
        assert_eq!(verify_finality_cert(&headers, &base), Err(CertErr::Seal));
        // Trailing bytes after a kind-0 cert are refused.
        let mut long = signed(&[0, 1, 3]).encode();
        long.push(0);
        assert_eq!(FinalityCert::decode(&long), Err(CertErr::Length));
    }
}
