//! Cross-core primitives: counters, cut publication, SPSC rings, seqlock, pool primitives.
#![deny(unsafe_code)]
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod ring;
