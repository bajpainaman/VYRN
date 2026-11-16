//! SipHash-2-4 (in-house), BLAKE3, Ed25519 (ZIP-215), X25519, derive_key contexts (01 §4).
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
