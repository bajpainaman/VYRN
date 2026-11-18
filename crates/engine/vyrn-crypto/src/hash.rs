//! BLAKE3-256 everywhere (01 §4): content hashes, `PktHash`, and the KDF through `derive_key`.

use vyrn_types::{Hash, PktHash};

/// The `derive_key` context for session keys (01 §4).
pub const SESSION_CONTEXT: &str = "vyrn v1 session";

/// BLAKE3-256 of `bytes`.
#[inline(always)]
pub fn hash(bytes: &[u8]) -> Hash {
    Hash(*blake3::hash(bytes).as_bytes())
}

/// BLAKE3-256 keyed with `key`.
#[inline(always)]
pub fn keyed_hash(key: &[u8; 32], bytes: &[u8]) -> Hash {
    Hash(*blake3::keyed_hash(key, bytes).as_bytes())
}

/// BLAKE3 in extendable-output mode: fills `out` with the first `out.len()` bytes of the XOF of
/// `bytes`. The first 32 bytes equal [`hash`]. 09 §9.4 uses it for the 2 KB LtHash element.
#[inline]
pub fn hash_xof(bytes: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new();
    h.update(bytes);
    h.finalize_xof().fill(out);
}

/// BLAKE3 `derive_key(context, material)`. `context` is a hard-coded, globally unique string;
/// never derive it from input.
#[inline(always)]
pub fn derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

/// `PktHash` (01 §3): the first 8 bytes, little-endian, of BLAKE3-256 of a request packet's bytes
/// 0..16+16n. The caller passes exactly those bytes, with the two tags excluded.
#[inline(always)]
pub fn pkt_hash(header_and_messages: &[u8]) -> PktHash {
    let full = blake3::hash(header_and_messages);
    PktHash(u64::from_le_bytes(
        full.as_bytes()
            .first_chunk::<8>()
            .copied()
            .unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkt_hash_is_the_little_endian_prefix_of_the_full_hash() {
        let bytes = [7u8; 48];
        let full = hash(&bytes).0;
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(full.get(..8).unwrap_or_default());
        assert_eq!(pkt_hash(&bytes).0, u64::from_le_bytes(prefix));
        // Byte 0 of the hash is the low byte of PktHash, not the high one.
        assert_eq!(
            pkt_hash(&bytes).0 & 0xff,
            u64::from(full.first().copied().unwrap_or(0))
        );
    }
}
