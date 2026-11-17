//! The signed part of a `BlockHeader` (01 §6.6) as 07 §3.10 lays it out, `header_hash` (07 §2.2)
//! and the `seq_sig` check of the vote rule's item 1 (07 §6.4).
//!
//! The HEADER frame itself is `vyrn-log`'s (11 §1.3). Consensus needs only these three functions
//! of a header, so they live here until `vyrn-log` lands; then one crate re-exports the other's,
//! and the unit tests below pin the bytes both must produce.

use vyrn_types::{BlockHeader, Ed25519Sig, Hash, PubKey};

/// Bytes `0..126` of the HEADER frame: every field but `seq_sig` (07 §3.10).
pub const SIGNED_BYTES: usize = 126;
/// The whole HEADER body, `seq_sig` included.
pub const HEADER_BYTES: usize = 190;
/// Domain string of `seq_sig`, byte for byte as 07 §3.10 writes it (six spaces).
pub const BLOCK_CONTEXT: &[u8] = b"vyrn      v1 block";
/// Domain string of `header_hash` (07 §2.2).
pub const HEADER_CONTEXT: &[u8] = b"vyrn v1 header";

/// Bytes `0..126` of 07 §3.10, little-endian, in 01 §6.6 field order.
pub fn signed_bytes(h: &BlockHeader) -> [u8; SIGNED_BYTES] {
    let mut out = [0u8; SIGNED_BYTES];
    let parts: [&[u8]; 8] = [
        &h.height.0.to_le_bytes(),
        &h.epoch.0.to_le_bytes(),
        &h.book.0.to_le_bytes(),
        &h.first_step.0.to_le_bytes(),
        &h.last_step.0.to_le_bytes(),
        &h.prev.0,
        &h.order_root.0,
        &h.data_root.0,
    ];
    let mut at = 0;
    for part in parts {
        let end = at + part.len();
        out[at..end].copy_from_slice(part);
        at = end;
    }
    out
}

/// The 190-byte HEADER body of 07 §3.10.
pub fn header_bytes(h: &BlockHeader) -> [u8; HEADER_BYTES] {
    let mut out = [0u8; HEADER_BYTES];
    out[..SIGNED_BYTES].copy_from_slice(&signed_bytes(h));
    out[SIGNED_BYTES..].copy_from_slice(&h.seq_sig);
    out
}

fn with_context(context: &[u8], h: &BlockHeader) -> Vec<u8> {
    let mut msg = Vec::with_capacity(context.len() + SIGNED_BYTES);
    msg.extend_from_slice(context);
    msg.extend_from_slice(&signed_bytes(h));
    msg
}

/// `header_hash(h) = BLAKE3("vyrn v1 header" ‖ header_bytes(h)[0..126])` (07 §2.2). It is the
/// `prev` of the next header and the `last_hash` of a proposal ending at `h`.
pub fn header_hash(h: &BlockHeader) -> Hash {
    vyrn_crypto::hash::hash(&with_context(HEADER_CONTEXT, h))
}

/// The bytes `seq_sig` signs: `"vyrn      v1 block" ‖ bytes 0..126` (07 §3.10).
pub fn seq_sig_message(h: &BlockHeader) -> Vec<u8> {
    with_context(BLOCK_CONTEXT, h)
}

/// True when `h.seq_sig` is a ZIP-215-valid signature by `seq_key` (11 §2.5). A seal header's
/// all-zero `seq_sig` (07 §9.4) never passes; its certificate stands in for it.
pub fn verify_seq_sig(h: &BlockHeader, seq_key: &PubKey) -> bool {
    vyrn_crypto::ed25519::verify(seq_key, &seq_sig_message(h), &h.seq_sig)
}

/// Signs `h` with the 32-byte `seed` of a sequencer key (what core 4 does, 07 §6.2) and returns
/// the signature. `vyrn-seq` and simulations use it; voters never call it.
pub fn seq_sign(seed: &[u8; 32], h: &BlockHeader) -> Ed25519Sig {
    vyrn_crypto::ed25519::sign(seed, &seq_sig_message(h))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyrn_types::{BookId, Epoch, Height, StepId};

    fn header() -> BlockHeader {
        BlockHeader {
            height: Height(0x0807_0605_0403_0201),
            epoch: Epoch(0x0C0B_0A09),
            book: BookId(0x0E0D),
            first_step: StepId(7),
            last_step: StepId(6),
            prev: Hash([1; 32]),
            order_root: Hash([2; 32]),
            data_root: Hash([3; 32]),
            seq_sig: [0; 64],
        }
    }

    #[test]
    fn offsets_match_07_3_10() {
        let b = header_bytes(&header());
        assert_eq!(&b[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&b[8..12], &[9, 10, 11, 12]);
        assert_eq!(&b[12..14], &[13, 14]);
        assert_eq!(b[14], 7);
        assert_eq!(b[22], 6);
        assert_eq!(&b[30..62], &[1; 32]);
        assert_eq!(&b[62..94], &[2; 32]);
        assert_eq!(&b[94..126], &[3; 32]);
    }

    #[test]
    fn seq_sig_covers_the_header_and_not_the_signature() {
        let seed = [9u8; 32];
        let key = vyrn_crypto::ed25519::public_key(&seed);
        let mut h = header();
        h.seq_sig = seq_sign(&seed, &h);
        assert!(verify_seq_sig(&h, &key));
        // header_hash ignores seq_sig, so a resigned header keeps its hash.
        let unsigned = header();
        assert_eq!(header_hash(&h), header_hash(&unsigned));
        let mut tampered = h;
        tampered.last_step = StepId(7);
        assert!(!verify_seq_sig(&tampered, &key));
        assert!(!verify_seq_sig(&unsigned, &key));
        assert!(!verify_seq_sig(
            &h,
            &vyrn_crypto::ed25519::public_key(&[8; 32])
        ));
    }
}
