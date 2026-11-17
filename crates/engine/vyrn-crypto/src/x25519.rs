//! X25519 key agreement (01 §4). Session keys are `derive_key(SESSION_CONTEXT, …)` over the
//! shared secret; 09 §6 owns the exact material.

use x25519_dalek::{PublicKey, StaticSecret};

/// The public key of `secret`.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// The shared secret of `secret` and `their_public`, or `None` when `their_public` is a
/// low-order point and the result is all zeros (it would not depend on our secret).
pub fn shared_secret(secret: &[u8; 32], their_public: &[u8; 32]) -> Option<[u8; 32]> {
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*their_public));
    shared.was_contributory().then(|| shared.to_bytes())
}
