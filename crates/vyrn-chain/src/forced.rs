//! `ForcedPacket` (09 §7): item 0x10, a request packet on the transaction path, authenticated by
//! the session's Ed25519 key instead of its tags.
//!
//! [`check`] runs the cheap checks first (09 §7.5): kind and signer, session, rate, fee, size and
//! the packet header. Only then does it verify the signature, so junk costs a validator no
//! signature verification.
//!
//! **Spec gap (rate window).** `CHN_FORCED_RATE` is "100 packets per second per session". The
//! caller passes how many forced packets of the session it already accepted in the current chain
//! second; this module refuses the 101st.

use vyrn_types::{MAX_REQ_PAYLOAD, SessionId};
use vyrn_wire::Request;

use crate::tx::{SignerRef, TxEnvelope};

/// Item kind of a forced packet (09 §4.5).
pub const KIND_FORCED: u8 = 0x10;
/// `CHN_FORCED_RATE` (09 §17.1).
pub const FORCED_RATE: u32 = 100;
/// `CHN_FEE_FORCED`: 0.01 USDC in micro-units (09 §17.1).
pub const FEE_FORCED: u64 = 10_000;

/// Why a forced packet is refused, in check order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForcedReject {
    /// Not kind 0x10, or the signer is not `Session(σ)`.
    #[error("not a session-signed ForcedPacket")]
    Kind,
    /// The session is unknown or not open.
    #[error("session not open")]
    Session,
    /// More than `CHN_FORCED_RATE` this second.
    #[error("forced rate exceeded")]
    Rate,
    /// `max_fee < CHN_FEE_FORCED`.
    #[error("max_fee below CHN_FEE_FORCED")]
    Fee,
    /// Longer than `MAX_REQ_PAYLOAD`, not a request packet, another session's packet, or
    /// `envelope.nonce ≠ pkt_seq`.
    #[error("malformed forced packet")]
    Packet,
    /// The Ed25519 signature does not verify under the session's `sign_pub`.
    #[error("bad session signature")]
    Signature,
}

/// What the checks read from chain state.
pub trait ForcedState {
    /// `sign_pub` of an open session.
    fn sign_pub(&self, session: SessionId) -> Option<[u8; 32]>;
    /// Forced packets of `session` already accepted in the current chain second.
    fn forced_this_second(&self, session: SessionId) -> u32;
}

/// A checked forced packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forced<'a> {
    /// σ.
    pub session: SessionId,
    /// The packet's `pkt_seq`; also `envelope.nonce`.
    pub pkt_seq: u32,
    /// The request packet, as the lane applies it (tags may be zero).
    pub packet: &'a [u8],
}

/// Checks a `ForcedPacket` envelope (09 §7.2, §7.5).
pub fn check<'a>(env: &'a TxEnvelope, st: &impl ForcedState) -> Result<Forced<'a>, ForcedReject> {
    let SignerRef::Session(session) = env.signer else {
        return Err(ForcedReject::Kind);
    };
    if env.kind != KIND_FORCED {
        return Err(ForcedReject::Kind);
    }
    let sign_pub = st.sign_pub(session).ok_or(ForcedReject::Session)?;
    if st.forced_this_second(session) >= FORCED_RATE {
        return Err(ForcedReject::Rate);
    }
    if env.max_fee < FEE_FORCED {
        return Err(ForcedReject::Fee);
    }
    if env.body.len() > MAX_REQ_PAYLOAD {
        return Err(ForcedReject::Packet);
    }
    let req = Request::parse(&env.body).map_err(|_| ForcedReject::Packet)?;
    req.check_header().map_err(|_| ForcedReject::Packet)?;
    let pkt_seq = req.header().pkt_seq.get();
    if req.header().session() != session || env.nonce != u64::from(pkt_seq) {
        return Err(ForcedReject::Packet);
    }
    env.verify_ed25519(&sign_pub)
        .map_err(|_| ForcedReject::Signature)?;
    Ok(Forced {
        session,
        pkt_seq,
        packet: &env.body,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::signer::{Ed25519Signer, SoftEd25519};
    use vyrn_types::AccountId;

    struct St {
        key: [u8; 32],
        used: u32,
    }
    impl ForcedState for St {
        fn sign_pub(&self, s: SessionId) -> Option<[u8; 32]> {
            (s == SessionId(9)).then_some(self.key)
        }
        fn forced_this_second(&self, _: SessionId) -> u32 {
            self.used
        }
    }

    fn packet(session: u32, pkt_seq: u32) -> Vec<u8> {
        // 01 §6.1: session, pkt_seq, count = 1, flags, epoch16, book, reserved; one message.
        let mut b = session.to_le_bytes().to_vec();
        b.extend_from_slice(&pkt_seq.to_le_bytes());
        b.extend_from_slice(&[1, 0, 1, 0, 1, 0, 0, 0]);
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&[0u8; 16]); // tag_seq, tag_com: zero on the forced path
        b
    }

    fn env(k: &SoftEd25519, body: Vec<u8>, nonce: u64) -> TxEnvelope {
        let mut e = TxEnvelope {
            kind: KIND_FORCED,
            signer: SignerRef::Session(SessionId(9)),
            nonce,
            max_fee: FEE_FORCED,
            body,
            scheme: 0,
            sig: vec![],
        };
        e.sign_ed25519(k).unwrap();
        e
    }

    #[test]
    fn checks_in_cheap_first_order() {
        let k = SoftEd25519::new([1; 32]);
        let st = St {
            key: k.public_key(),
            used: 0,
        };
        let good = env(&k, packet(9, 44), 44);
        let f = check(&good, &st).unwrap();
        assert_eq!((f.session, f.pkt_seq), (SessionId(9), 44));

        let mut e = good.clone();
        e.signer = SignerRef::Account(AccountId(9));
        assert_eq!(check(&e, &st), Err(ForcedReject::Kind));
        let mut e = env(&k, packet(10, 44), 44);
        e.signer = SignerRef::Session(SessionId(10));
        assert_eq!(check(&e, &st), Err(ForcedReject::Session));
        // At the rate limit, a bad signature is never looked at.
        let mut e = good.clone();
        e.sig[0] ^= 1;
        assert_eq!(
            check(
                &e,
                &St {
                    used: FORCED_RATE,
                    ..st
                }
            ),
            Err(ForcedReject::Rate)
        );
        assert_eq!(
            check(
                &e,
                &St {
                    used: FORCED_RATE - 1,
                    ..st
                }
            ),
            Err(ForcedReject::Signature)
        );
        let mut e = env(&k, packet(9, 44), 44);
        e.max_fee = FEE_FORCED - 1;
        e.sign_ed25519(&k).unwrap();
        assert_eq!(check(&e, &st), Err(ForcedReject::Fee));
        // Another session's packet, a nonce that is not pkt_seq, a non-packet.
        assert_eq!(
            check(&env(&k, packet(8, 44), 44), &st),
            Err(ForcedReject::Packet)
        );
        assert_eq!(
            check(&env(&k, packet(9, 44), 45), &st),
            Err(ForcedReject::Packet)
        );
        assert_eq!(
            check(&env(&k, vec![0; 20], 44), &st),
            Err(ForcedReject::Packet)
        );
        // A valid signature by another key.
        let other = env(&SoftEd25519::new([2; 32]), packet(9, 44), 44);
        assert_eq!(check(&other, &st), Err(ForcedReject::Signature));
    }
}
