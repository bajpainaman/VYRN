//! Ed25519 under the ZIP-215 rules (spec/11-build.md §2.5).
//!
//! Every validator must reach the same verdict on every signature, or a client's signed session
//! open could split the state. ZIP-215 fixes that verdict: `S` must be canonical (< ℓ); `A` and
//! `R` may be non-canonical encodings of curve points; and the check is the cofactored equation
//! `[8]([S]B − [k]A − R) = 0` with `k = SHA-512(R ‖ A ‖ M) mod ℓ` over the encodings as received.
//!
//! `ed25519-dalek`'s own `verify` is cofactorless and compares encodings of `R`, so it rejects
//! signatures that ZIP-215 accepts. This is the only verify function in VYRN; the Rust and the
//! Vx clients both call it.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Digest, Sha512, Signer, SigningKey};

/// True when `signature` is a valid ZIP-215 signature of `message` under `public_key`.
// Group operations on curve points; nothing here is integer arithmetic that can overflow.
#[allow(clippy::arithmetic_side_effects)]
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let (Some(r_bytes), Some(s_bytes)) =
        (signature.first_chunk::<32>(), signature.last_chunk::<32>())
    else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(*s_bytes)) else {
        return false;
    };
    let Some(a) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    let Some(r) = CompressedEdwardsY(*r_bytes).decompress() else {
        return false;
    };

    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(public_key);
    h.update(message);
    let wide: [u8; 64] = h.finalize().into();
    let k = Scalar::from_bytes_mod_order_wide(&wide);

    // [S]B − [k]A, then subtract R and clear the cofactor.
    let sb_minus_ka = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &(-a), &s);
    (sb_minus_ka - r).mul_by_cofactor().is_identity()
}

/// RFC 8032 deterministic signature of `message` with the 32-byte secret `seed`.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// The public key of the 32-byte secret `seed`.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}
