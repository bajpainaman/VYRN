//! The replica: two-path order frames, data fetch, replay engine (Rust or Vx), state roots, votes.
#![deny(unsafe_code)]

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod vx;
