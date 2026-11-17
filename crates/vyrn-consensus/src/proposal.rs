//! `REP_Proposal`: what one Simplex payload commits to (spec/07-replication.md §6.3).
//!
//! A Simplex payload is the digest of a proposal, never the block bytes: the headers and ORDER
//! bytes are already at every voter through frames (07 §6.3, `Relay` is a no-op). A proposal names
//! a contiguous range of heights and commits to all of it through `last_hash`, because each
//! header's `prev` is `header_hash` of the one before (07 §2.2).
//!
//! Versioning: the layout has no version field. The domain string [`PROPOSAL_CONTEXT`] carries
//! `v1`, and `kind` is the extension point (0 = headers, 1 = seal, 07 §9.4); a decoder rejects any
//! other kind rather than guess.

use thiserror::Error;
use vyrn_types::{Epoch, Hash, Height};

/// Encoded size: `1 + 4 + 8 + 8 + 32 + 32` (07 §6.3).
pub const PROPOSAL_BYTES: usize = 85;
/// `REP_MAX_HDRS_PER_PROPOSAL` (07 §6.3, §15): a kind-0 range holds at most 16 heights.
pub const MAX_HDRS_PER_PROPOSAL: u64 = 16;
/// `REP_MAX_SEAL_RANGE` (07 §9.4): a kind-1 range holds at most 64 heights.
pub const MAX_SEAL_RANGE: u64 = 64;
/// Domain string of the proposal digest, byte for byte as 07 §6.3 writes it (six spaces).
pub const PROPOSAL_CONTEXT: &[u8] = b"vyrn      v1 proposal";

/// `REP_Proposal.kind` (07 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ProposalKind {
    /// A range of signed headers (07 §6.3).
    Headers = 0,
    /// The seal of a deposed tenure (07 §9.4). Encoded and decoded here; this crate does not yet
    /// propose or vote for one.
    Seal = 1,
}

/// `REP_Proposal` (07 §6.3), encoded little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal {
    pub kind: ProposalKind,
    pub epoch: Epoch,
    pub first_height: Height,
    pub last_height: Height,
    /// `header_hash(last_height)`; the `prev` links commit to the whole range.
    pub last_hash: Hash,
    /// BASE: 32 zero bytes. CHAIN: BLAKE3 over the sorted `(session, pkt_seq)` excluded in the
    /// range (09).
    pub excl_root: Hash,
}

/// Why bytes are not a valid `REP_Proposal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ProposalErr {
    #[error("a proposal is {PROPOSAL_BYTES} bytes, got {0}")]
    Length(usize),
    #[error("unknown proposal kind {0}")]
    Kind(u8),
    #[error("last_height is below first_height")]
    Inverted,
    #[error("range of {0} heights exceeds the cap for its kind")]
    TooLong(u64),
}

impl Proposal {
    /// Number of heights in the range, or `None` when `last_height < first_height`.
    pub fn heights(&self) -> Option<u64> {
        self.last_height
            .0
            .checked_sub(self.first_height.0)?
            .checked_add(1)
    }

    /// The 85 bytes of 07 §6.3.
    pub fn encode(&self) -> [u8; PROPOSAL_BYTES] {
        let mut out = [0u8; PROPOSAL_BYTES];
        let parts: [&[u8]; 6] = [
            &[self.kind as u8],
            &self.epoch.0.to_le_bytes(),
            &self.first_height.0.to_le_bytes(),
            &self.last_height.0.to_le_bytes(),
            &self.last_hash.0,
            &self.excl_root.0,
        ];
        let mut at = 0;
        for part in parts {
            let end = at + part.len();
            out[at..end].copy_from_slice(part);
            at = end;
        }
        out
    }

    /// Parses and validates 07 §6.3 bytes: exact length, known kind, and a range within its cap.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProposalErr> {
        let b: &[u8; PROPOSAL_BYTES] = bytes
            .try_into()
            .map_err(|_| ProposalErr::Length(bytes.len()))?;
        let kind = match b[0] {
            0 => ProposalKind::Headers,
            1 => ProposalKind::Seal,
            k => return Err(ProposalErr::Kind(k)),
        };
        let u32_at = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]));
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
        let hash_at = |at: usize| Hash(b[at..at + 32].try_into().unwrap_or([0; 32]));
        let p = Self {
            kind,
            epoch: Epoch(u32_at(1)),
            first_height: Height(u64_at(5)),
            last_height: Height(u64_at(13)),
            last_hash: hash_at(21),
            excl_root: hash_at(53),
        };
        p.check_range()?;
        Ok(p)
    }

    /// The range rule of 07 §6.3 and §9.4.
    pub fn check_range(&self) -> Result<(), ProposalErr> {
        let len = self.heights().ok_or(ProposalErr::Inverted)?;
        let cap = match self.kind {
            ProposalKind::Headers => MAX_HDRS_PER_PROPOSAL,
            ProposalKind::Seal => MAX_SEAL_RANGE,
        };
        if len > cap {
            return Err(ProposalErr::TooLong(len));
        }
        Ok(())
    }

    /// `digest = BLAKE3("vyrn      v1 proposal" ‖ REP_Proposal bytes)` (07 §6.3). This is the
    /// Simplex payload every vote and certificate signs.
    pub fn digest(&self) -> Hash {
        let mut msg = [0u8; PROPOSAL_CONTEXT.len() + PROPOSAL_BYTES];
        let (ctx, body) = msg.split_at_mut(PROPOSAL_CONTEXT.len());
        ctx.copy_from_slice(PROPOSAL_CONTEXT);
        body.copy_from_slice(&self.encode());
        vyrn_crypto::hash::hash(&msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Proposal {
        Proposal {
            kind: ProposalKind::Headers,
            epoch: Epoch(0x0102_0304),
            first_height: Height(0x1112_1314_1516_1718),
            last_height: Height(0x1112_1314_1516_1727),
            last_hash: Hash([0xAA; 32]),
            excl_root: Hash([0xBB; 32]),
        }
    }

    #[test]
    fn layout_is_little_endian_in_field_order() {
        let b = sample().encode();
        assert_eq!(b[0], 0);
        assert_eq!(&b[1..5], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&b[5..13], &[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        assert_eq!(b[13], 0x27);
        assert_eq!(&b[21..53], &[0xAA; 32]);
        assert_eq!(&b[53..85], &[0xBB; 32]);
        assert_eq!(Proposal::decode(&b), Ok(sample()));
    }

    #[test]
    fn decode_enforces_the_range_caps() {
        // 16 heights is the kind-0 cap; 17 is one too many, but fits a seal.
        let mut p = sample();
        assert_eq!(p.heights(), Some(16));
        p.last_height.0 += 1;
        assert_eq!(Proposal::decode(&p.encode()), Err(ProposalErr::TooLong(17)));
        p.kind = ProposalKind::Seal;
        assert_eq!(Proposal::decode(&p.encode()), Ok(p));
        p.last_height.0 = p.first_height.0 - 1;
        assert_eq!(Proposal::decode(&p.encode()), Err(ProposalErr::Inverted));
        let mut b = sample().encode();
        b[0] = 2;
        assert_eq!(Proposal::decode(&b), Err(ProposalErr::Kind(2)));
        assert_eq!(Proposal::decode(&b[..84]), Err(ProposalErr::Length(84)));
    }

    #[test]
    fn digest_is_domain_separated_and_covers_every_field() {
        let p = sample();
        let mut plain = Vec::from(PROPOSAL_CONTEXT);
        plain.extend_from_slice(&p.encode());
        assert_eq!(p.digest(), vyrn_crypto::hash::hash(&plain));
        assert_ne!(p.digest(), vyrn_crypto::hash::hash(&p.encode()));
        let mut q = p;
        q.excl_root.0[31] ^= 1;
        assert_ne!(p.digest(), q.digest());
    }
}
