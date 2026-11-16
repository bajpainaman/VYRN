//! Deterministic whole-cluster simulator, oracle binding, invariant checkers. Test-only.
#![deny(unsafe_code)]

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod oracle;
