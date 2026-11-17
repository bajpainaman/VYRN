// Declares `cfg(loom)` (spec/11-build.md §6.1: `RUSTFLAGS="--cfg loom"` runs the loom models).
// A build script talks to cargo on stdout; it never runs on a pinned core (§8.3 does not apply).
#![allow(clippy::disallowed_macros)]

fn main() {
    println!("cargo::rustc-check-cfg=cfg(loom)");
}
