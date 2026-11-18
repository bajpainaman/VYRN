//! `vyrn-nic::ffi` (UNSAFE.toml). Every `unsafe` block needs a `// SAFETY:` comment.
//!
//! The bindings to c/vyrn-nic-shim (06 §7.2). They exist only where the shim is built: Linux with
//! the `shim` feature. `vyrn_wire::RxPkt` and `NicCounters` carry the layouts of `vyns_rx` and
//! `vyns_counters`; both sides assert them at compile time.

use crate::NicError;

/// Refuses a shim whose ABI version is not `vyrn_wire::ring::RING_ABI_VERSION` (06 §7.5 "ABI drift").
pub fn check_abi_version(shim: u32) -> Result<(), NicError> {
    let expected = vyrn_wire::ring::RING_ABI_VERSION;
    if shim == expected {
        Ok(())
    } else {
        Err(NicError::ShimAbi { shim, expected })
    }
}

#[cfg(all(feature = "shim", target_os = "linux"))]
unsafe extern "C" {
    fn vyns_abi_version() -> u32;
}

/// Asks the linked shim for its ABI version and refuses a mismatch. Every backend built on the
/// shim calls this first in `NicBackend::open`, before any other shim call.
#[cfg(all(feature = "shim", target_os = "linux"))]
pub fn check_shim_abi() -> Result<(), NicError> {
    // SAFETY: `vyns_abi_version` takes no arguments, touches no state and returns a constant
    // (shim.c); shim.h declares it with this exact signature.
    check_abi_version(unsafe { vyns_abi_version() })
}
