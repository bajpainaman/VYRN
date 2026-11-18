#!/usr/bin/env bash
# CI's vx job, with .agents/setup's own functions so the reproducible vxc build (W-10: path
# remaps, sorted build scripts) has one source. `toolchain`: rustup and the pinned rustc.
# `vxc`: the pinned vxc (vx/TOOLCHAIN, 11 §5.4), run only on a cache miss. The job runs in
# debian:trixie with HOME=/home/user, the host kind vxc_blake3.x86_64-linux was pinned on; vx/build.sh
# then checks the hash.
set -euo pipefail
cd "$(dirname "$0")/../.."
# Everything before .agents/setup's first step is definitions; it finds the repository from its
# own path, so the copy sits next to it.
defs="$(mktemp -p .agents)"
trap 'rm -f "$defs"' EXIT
sed '/^step "apt base packages"/,$d' .agents/setup >"$defs"
# shellcheck disable=SC1090
source "$defs"
case "${1:-}" in
  toolchain)
    step "rustup" rustup_install
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    # The pin is the default, as setup's `toolchains` makes it: Vx's own setup.sh runs cargo
    # outside this repository.
    rustup toolchain install
    rustup default "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" >/dev/null
    ;;
  vxc)
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    step "apt base packages" apt_base
    step "LLVM/MLIR $VX_LLVM for vxc" llvm_for_vx
    step "vxc $VX_TAG" vxc_build
    ;;
  *)
    echo "usage: $0 toolchain|vxc" >&2
    exit 2
    ;;
esac
