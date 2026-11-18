//! The shim ABI check of 06 §7.5: vyrn-nic refuses a C shim of another ABI version.

use vyrn_nic::NicError;
use vyrn_nic::ffi::check_abi_version;

#[test]
fn another_abi_version_is_refused() {
    assert!(check_abi_version(vyrn_wire::ring::RING_ABI_VERSION).is_ok());
    let next = vyrn_wire::ring::RING_ABI_VERSION + 1;
    assert!(matches!(
        check_abi_version(next),
        Err(NicError::ShimAbi { shim, expected }) if shim == next && expected == vyrn_wire::ring::RING_ABI_VERSION
    ));
}

/// Calls the C shim that build.rs compiled and linked: its `VYNS_ABI_VERSION` must be the one
/// whose layouts `RxPkt` and `NicCounters` mirror.
#[cfg(all(feature = "shim", target_os = "linux"))]
#[test]
fn the_linked_shim_has_this_builds_abi_version() {
    vyrn_nic::ffi::check_shim_abi().unwrap();
}
