//! NIC backends: efvi, dpdk (Linux, C shim), kernel_udp, sim; platform calls in sys.
#![deny(unsafe_code)]

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod ffi;
// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod sys;
