#!/usr/bin/env bash
# Prints one version a release manifest records, each from its one source:
#   version                the workspace version, [workspace.package] in Cargo.toml
#   protocol_version       vyrn-wire's PROTO_VERSION (04 §12, spec/11-build.md §10.2)
#   config_schema_version  [workspace.metadata.vyrn] in Cargo.toml (§10.1)
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
case "$1" in
  version) sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" ;;
  protocol_version)
    sed -n 's/^pub const PROTO_VERSION: u16 = \([0-9]*\);/\1/p' \
      "$root/crates/engine/vyrn-wire/src/lib.rs" ;;
  *) sed -n "/^\[workspace.metadata.vyrn\]/,/^\[/s/^$1 = \([0-9]*\)/\1/p" "$root/Cargo.toml" ;;
esac | grep . || { echo "meta.sh: $1 not found" >&2; exit 1; }
