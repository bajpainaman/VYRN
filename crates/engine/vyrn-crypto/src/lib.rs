//! VYRN's one crypto stack (01 §4, spec/11-build.md §1.3): SipHash-2-4 (in-house), BLAKE3,
//! Ed25519 under ZIP-215, X25519, and the `derive_key` contexts.
#![forbid(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

pub mod ed25519;
pub mod hash;
pub mod siphash;
pub mod x25519;

pub use hash::{SESSION_CONTEXT, derive_key, hash_xof, pkt_hash};
pub use siphash::{FixedState, siphash24, tag_eq};
