//! `TxEnvelope` (09 §4.4): the signed wrapper of every item on the transaction path.
//!
//! ```text
//! unsigned = [version = 1] ‖ [kind] ‖ le16(body_len) ‖ signer ‖ le64(nonce) ‖ le64(max_fee)
//!            ‖ body ‖ [scheme]
//! envelope = unsigned ‖ sig                         64 B (scheme 0) or 65 B (scheme 1)
//! Ed25519 signs derive_key("vyrn v1 tx", unsigned)
//! ```
//!
//! **Spec gaps (readings chosen).**
//! - *`SignerRef` bytes:* a tag byte, then `0 Account le32 · 1 Session le32 · 2 Node [op] [home] ·
//!   3 Operator [op] · 4 Anyone` (nothing).
//! - *"Envelope without sig"* keeps `scheme`, so a signature cannot be replayed under the other
//!   scheme.
//! - *secp256k1 (scheme 1):* 09 §4.4 names an EIP-712 digest over the same fields but gives no
//!   type string. This module decodes scheme-1 envelopes and leaves their verification to a
//!   follow-up; [`TxEnvelope::verify_ed25519`] refuses them.

use vyrn_crypto::{derive_key, ed25519};
use vyrn_types::{AccountId, HomeCode, SessionId};

use crate::codec::{Reader, Writer};
use crate::signer::{Ed25519Signer, SignerError, sign_checked};
use crate::tesla::OpIdx;

/// The `derive_key` context of item signatures (09 §17.3).
pub const TX_CONTEXT: &str = "vyrn v1 tx";
/// The envelope version.
pub const VERSION: u8 = 1;
/// `scheme` of an Ed25519 signature.
pub const SCHEME_ED25519: u8 = 0;
/// `scheme` of a secp256k1 EIP-712 signature.
pub const SCHEME_SECP256K1: u8 = 1;

/// Who signs an item (09 §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRef {
    /// A wallet.
    Account(AccountId),
    /// A session's `sign_pub`.
    Session(SessionId),
    /// A node key `NK(op, home)`.
    Node(OpIdx, HomeCode),
    /// An operator identity key.
    Operator(OpIdx),
    /// Unsigned (evidence).
    Anyone,
}

/// `TxEnvelope` (09 §4.4). `version` is always 1 and `body_len` is `body.len()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEnvelope {
    /// Item kind (09 §4.5).
    pub kind: u8,
    /// The signer.
    pub signer: SignerRef,
    /// Per signer; must be last + 1.
    pub nonce: u64,
    /// USDC micro-units.
    pub max_fee: u64,
    /// The item body.
    pub body: Vec<u8>,
    /// 0 Ed25519, 1 secp256k1.
    pub scheme: u8,
    /// 64 or 65 bytes, by scheme.
    pub sig: Vec<u8>,
}

/// Why an envelope does not decode or verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// Not the encoding above.
    #[error("malformed envelope")]
    Malformed,
    /// The signature does not verify, or the scheme is not the one asked for.
    #[error("bad signature")]
    BadSignature,
}

fn sig_len(scheme: u8) -> Option<usize> {
    match scheme {
        SCHEME_ED25519 => Some(64),
        SCHEME_SECP256K1 => Some(65),
        _ => None,
    }
}

impl TxEnvelope {
    /// The bytes every scheme signs over.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(self.body.len().saturating_add(32));
        w.u8(VERSION);
        w.u8(self.kind);
        w.u16(u16::try_from(self.body.len()).unwrap_or(u16::MAX));
        match self.signer {
            SignerRef::Account(a) => {
                w.u8(0);
                w.u32(a.0);
            }
            SignerRef::Session(s) => {
                w.u8(1);
                w.u32(s.0);
            }
            SignerRef::Node(op, home) => {
                w.u8(2);
                w.u8(op);
                w.u8(home.code());
            }
            SignerRef::Operator(op) => {
                w.u8(3);
                w.u8(op);
            }
            SignerRef::Anyone => w.u8(4),
        }
        w.u64(self.nonce);
        w.u64(self.max_fee);
        w.bytes(&self.body);
        w.u8(self.scheme);
        w.finish()
    }

    /// `unsigned ‖ sig`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.unsigned_bytes();
        b.extend_from_slice(&self.sig);
        b
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8]) -> Result<Self, TxError> {
        let m = TxError::Malformed;
        let mut r = Reader::new(b);
        if r.u8().ok_or(m)? != VERSION {
            return Err(m);
        }
        let kind = r.u8().ok_or(m)?;
        let body_len = usize::from(r.u16().ok_or(m)?);
        let signer = match r.u8().ok_or(m)? {
            0 => SignerRef::Account(AccountId(r.u32().ok_or(m)?)),
            1 => SignerRef::Session(SessionId(r.u32().ok_or(m)?)),
            2 => SignerRef::Node(
                r.u8().ok_or(m)?,
                HomeCode::from_code(r.u8().ok_or(m)?).ok_or(m)?,
            ),
            3 => SignerRef::Operator(r.u8().ok_or(m)?),
            4 => SignerRef::Anyone,
            _ => return Err(m),
        };
        let nonce = r.u64().ok_or(m)?;
        let max_fee = r.u64().ok_or(m)?;
        let body = r.take(body_len).ok_or(m)?.to_vec();
        let scheme = r.u8().ok_or(m)?;
        let sig = r.take(sig_len(scheme).ok_or(m)?).ok_or(m)?.to_vec();
        r.finish().ok_or(m)?;
        Ok(Self {
            kind,
            signer,
            nonce,
            max_fee,
            body,
            scheme,
            sig,
        })
    }

    /// `derive_key("vyrn v1 tx", unsigned)`, the message an Ed25519 signer signs.
    pub fn ed25519_message(&self) -> [u8; 32] {
        derive_key(TX_CONTEXT, &self.unsigned_bytes())
    }

    /// Sets `scheme` to Ed25519 and signs with `key`.
    pub fn sign_ed25519(&mut self, key: &impl Ed25519Signer) -> Result<(), SignerError> {
        self.scheme = SCHEME_ED25519;
        self.sig = sign_checked(key, &self.ed25519_message())?.to_vec();
        Ok(())
    }

    /// Verifies an Ed25519 envelope under `public_key` (ZIP-215, 11 §2.5).
    pub fn verify_ed25519(&self, public_key: &[u8; 32]) -> Result<(), TxError> {
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| TxError::BadSignature)?;
        if self.scheme == SCHEME_ED25519
            && ed25519::verify(public_key, &self.ed25519_message(), &sig)
        {
            Ok(())
        } else {
            Err(TxError::BadSignature)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::signer::SoftEd25519;

    fn env(signer: SignerRef) -> TxEnvelope {
        TxEnvelope {
            kind: 0x10,
            signer,
            nonce: 5,
            max_fee: 10_000,
            body: vec![1, 2, 3],
            scheme: 0,
            sig: vec![],
        }
    }

    #[test]
    fn round_trip_every_signer_and_sign_verify() {
        let k = SoftEd25519::new([8; 32]);
        for s in [
            SignerRef::Account(AccountId(1)),
            SignerRef::Session(SessionId(2)),
            SignerRef::Node(3, HomeCode::Ldn),
            SignerRef::Operator(4),
            SignerRef::Anyone,
        ] {
            let mut e = env(s);
            e.sign_ed25519(&k).unwrap();
            assert_eq!(TxEnvelope::decode(&e.encode()), Ok(e.clone()));
            assert_eq!(e.verify_ed25519(&k.public_key()), Ok(()));
        }
        let mut e = env(SignerRef::Session(SessionId(2)));
        e.sign_ed25519(&k).unwrap();
        let b = e.encode();
        assert_eq!(&b[..4], &[1, 0x10, 3, 0]);
        // Any changed signed field breaks the signature, including scheme.
        for f in [
            |e: &mut TxEnvelope| e.nonce += 1,
            |e: &mut TxEnvelope| e.max_fee += 1,
            |e: &mut TxEnvelope| e.body[0] ^= 1,
            |e: &mut TxEnvelope| e.signer = SignerRef::Session(SessionId(3)),
        ] {
            let mut x = e.clone();
            f(&mut x);
            assert_eq!(
                x.verify_ed25519(&k.public_key()),
                Err(TxError::BadSignature)
            );
        }
        let mut x = e.clone();
        x.scheme = SCHEME_SECP256K1;
        x.sig.push(27);
        assert_eq!(
            x.verify_ed25519(&k.public_key()),
            Err(TxError::BadSignature)
        );
        assert_eq!(
            TxEnvelope::decode(&x.encode()),
            Ok(x.clone()),
            "scheme 1 decodes"
        );
        // Truncated, trailing, bad version, bad signer tag, bad home, bad scheme.
        assert_eq!(
            TxEnvelope::decode(&b[..b.len() - 1]),
            Err(TxError::Malformed)
        );
        let mut long = b.clone();
        long.push(0);
        assert_eq!(TxEnvelope::decode(&long), Err(TxError::Malformed));
        for (at, v) in [(0, 2u8), (4, 9), (b.len() - 65, 2)] {
            let mut y = b.clone();
            y[at] = v;
            assert_eq!(TxEnvelope::decode(&y), Err(TxError::Malformed), "byte {at}");
        }
        let mut n = env(SignerRef::Node(1, HomeCode::Tyo));
        n.sig = vec![0; 64];
        let mut y = n.encode();
        y[6] = 0;
        assert_eq!(TxEnvelope::decode(&y), Err(TxError::Malformed), "home 0");
    }
}
