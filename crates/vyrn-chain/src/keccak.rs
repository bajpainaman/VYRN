//! Keccak-256 as Ethereum uses it: Keccak-f[1600], rate 136 bytes, pad `0x01 … 0x80` (not the
//! SHA3 `0x06` pad).
//!
//! 01 §14.11 allows keccak256 only for the parts that face Ethereum L1: the EIP-712 digests and the
//! withdrawal tree ([`crate::eip712`], [`crate::wdtree`]). No crate on the §2.2 allowlist provides
//! it, so it is written here, like SipHash in `vyrn-crypto`, and checked against digests that
//! eth-account and OpenZeppelin computed (`contracts/vectors`).

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];
const RATE: usize = 136;

#[allow(clippy::indexing_slicing)] // every index is a constant below 25
fn keccak_f(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[5 * y + x] ^= d;
            }
        }
        let mut t = a[1];
        for (&j, &r) in PI.iter().zip(ROT.iter()) {
            let next = a[j];
            a[j] = t.rotate_left(r);
            t = next;
        }
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        a[0] ^= rc;
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8; RATE]) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
    keccak_f(state);
}

/// Keccak-256 of the concatenation of `parts`.
pub fn keccak256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut block = [0u8; RATE];
    let mut fill = 0usize;
    for part in parts {
        for &b in *part {
            if let Some(slot) = block.get_mut(fill) {
                *slot = b;
            }
            fill = fill.wrapping_add(1);
            if fill == RATE {
                absorb_block(&mut state, &block);
                block = [0; RATE];
                fill = 0;
            }
        }
    }
    if let Some(slot) = block.get_mut(fill) {
        *slot ^= 0x01;
    }
    if let Some(last) = block.last_mut() {
        *last ^= 0x80;
    }
    absorb_block(&mut state, &block);
    let mut out = [0u8; 32];
    for (chunk, lane) in out.as_chunks_mut::<8>().0.iter_mut().zip(state.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Keccak-256 of `bytes`.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    keccak256_parts(&[bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        // Ethereum's keccak256 of "" and of "abc" (published values).
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn parts_and_block_boundaries_agree() {
        // 135, 136 and 137 bytes straddle the rate; split points must not change the digest.
        for n in [0usize, 1, 135, 136, 137, 272, 300] {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let whole = keccak256(&data);
            for cut in [0, n / 3, n / 2, n] {
                let (a, b) = data.split_at(cut);
                assert_eq!(keccak256_parts(&[a, b]), whole, "n={n} cut={cut}");
            }
        }
    }
}
