//! Signing keys behind a trait (09 §2.2): the vote key `VK` and the bridge key `BK` sign through
//! these traits, so a production node plugs in its HSM and tests plug in the software signers.
//!
//! Each trait signs exactly one message kind. The caller passes the 32-byte message the spec
//! defines (a `derive_key` output for Ed25519, an EIP-712 digest for secp256k1), never raw bytes
//! chosen by a peer, so a key never signs a message of another purpose.
//!
//! This is classical crypto only; the hybrid post-quantum scheme in review (PR #51) is not assumed.

use crate::eip712::{self, Address};

/// A signer that failed: the HSM is unreachable, refused, or returned a malformed signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignerError {
    /// The device did not answer or refused.
    #[error("signer unavailable")]
    Unavailable,
    /// The device returned bytes that do not verify under its own public key.
    #[error("signer returned an invalid signature")]
    BadOutput,
}

/// An Ed25519 key that signs 32-byte `derive_key` messages: `VK` for votes and commit votes.
pub trait Ed25519Signer {
    /// The public key, as the `NodeCert` lists it.
    fn public_key(&self) -> [u8; 32];
    /// The signature of `message`.
    fn sign(&self, message: &[u8; 32]) -> Result<[u8; 64], SignerError>;
}

/// A secp256k1 key that signs EIP-712 digests: `BK` for posts and signer rotations (09 §6).
pub trait BridgeSigner {
    /// The key's Ethereum address.
    fn address(&self) -> Address;
    /// `r ‖ s ‖ v`, low `s`, `v` ∈ {27, 28}, as `VyrnBridge._countSigs` accepts.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], SignerError>;
}

/// Signs with `signer` and checks the result under its own key, so a faulty device never puts an
/// invalid signature on the wire.
pub fn sign_checked(
    signer: &impl Ed25519Signer,
    message: &[u8; 32],
) -> Result<[u8; 64], SignerError> {
    let sig = signer.sign(message)?;
    if vyrn_crypto::ed25519::verify(&signer.public_key(), message, &sig) {
        Ok(sig)
    } else {
        Err(SignerError::BadOutput)
    }
}

/// Signs `digest` with `signer` and checks that it recovers to the signer's address.
pub fn sign_digest_checked(
    signer: &impl BridgeSigner,
    digest: &[u8; 32],
) -> Result<[u8; 65], SignerError> {
    let sig = signer.sign_digest(digest)?;
    match eip712::recover(digest, &sig) {
        Ok(a) if a == signer.address() => Ok(sig),
        _ => Err(SignerError::BadOutput),
    }
}

/// An in-memory Ed25519 key, for tests, `vyrn-sim` and DEV. Production keys live in the node's
/// encrypted key file (VK) or an HSM; never use this for `OIK`.
#[derive(Clone)]
pub struct SoftEd25519 {
    seed: [u8; 32],
    public: [u8; 32],
}

impl SoftEd25519 {
    /// From a 32-byte seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            public: vyrn_crypto::ed25519::public_key(&seed),
        }
    }
}

impl core::fmt::Debug for SoftEd25519 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftEd25519")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Ed25519Signer for SoftEd25519 {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }
    fn sign(&self, message: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Ok(vyrn_crypto::ed25519::sign(&self.seed, message))
    }
}

/// An in-memory secp256k1 key, for tests and `vyrn-sim`. Production bridge keys sign in an HSM.
#[derive(Clone)]
pub struct SoftBridgeKey {
    secret: [u8; 32],
    address: Address,
}

impl SoftBridgeKey {
    /// From a secret scalar; `None` if it is not a valid one.
    pub fn new(secret: [u8; 32]) -> Option<Self> {
        Some(Self {
            secret,
            address: eip712::address_of_secret(&secret)?,
        })
    }
}

impl core::fmt::Debug for SoftBridgeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftBridgeKey")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl BridgeSigner for SoftBridgeKey {
    fn address(&self) -> Address {
        self.address
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], SignerError> {
        eip712::sign(digest, &self.secret).ok_or(SignerError::Unavailable)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Broken(SoftEd25519);
    impl Ed25519Signer for Broken {
        fn public_key(&self) -> [u8; 32] {
            self.0.public_key()
        }
        fn sign(&self, m: &[u8; 32]) -> Result<[u8; 64], SignerError> {
            let mut s = self.0.sign(m)?;
            s[0] ^= 1;
            Ok(s)
        }
    }

    struct WrongKey(SoftBridgeKey, Address);
    impl BridgeSigner for WrongKey {
        fn address(&self) -> Address {
            self.1
        }
        fn sign_digest(&self, d: &[u8; 32]) -> Result<[u8; 65], SignerError> {
            self.0.sign_digest(d)
        }
    }

    #[test]
    fn checked_signing_refuses_bad_device_output() {
        let k = SoftEd25519::new([3; 32]);
        let m = [9u8; 32];
        let sig = sign_checked(&k, &m).unwrap();
        assert!(vyrn_crypto::ed25519::verify(&k.public_key(), &m, &sig));
        assert_eq!(sign_checked(&Broken(k), &m), Err(SignerError::BadOutput));

        let b = SoftBridgeKey::new([5; 32]).unwrap();
        let sig = sign_digest_checked(&b, &m).unwrap();
        assert_eq!(eip712::recover(&m, &sig), Ok(b.address()));
        assert_eq!(
            sign_digest_checked(&WrongKey(b, [1; 20]), &m),
            Err(SignerError::BadOutput)
        );
        assert!(
            SoftBridgeKey::new([0; 32]).is_none(),
            "zero is not a scalar"
        );
        assert!(!format!("{:?}", SoftEd25519::new([3; 32])).contains("seed"));
    }
}
