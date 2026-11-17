#!/usr/bin/env bash
# Builds the bundle of one library crate's release in DIST (deploy/release/MANIFEST.md, kind crate):
# <name>-<version>.crate, CHANGELOG.md and an unsigned manifest.toml, then verifies it.
#
#   deploy/release/crate.sh NAME DIST
#
# The crate must set its own `version` (not `version.workspace = true`), and so must every
# workspace crate it depends on: `cargo package` needs a version on each dependency. `cargo package`
# cannot verify a crate whose dependencies are not on crates.io, so the script packages without
# verification and then builds the unpacked .crate files itself, outside the workspace, with the
# dependencies patched to their unpacked .crate files and the workspace's Cargo.lock.
set -euo pipefail

name="$1"
dist="$(mkdir -p "$2" && cd "$2" && pwd)"
root="$(git rev-parse --show-toplevel)"
cd "$root"
meta="$(cargo metadata --format-version 1 --no-deps --locked)"
# Where `cargo package` writes, wherever CARGO_TARGET_DIR or build.target-dir put it.
target_dir="$(jq -r .target_directory <<<"$meta")"

pkg() { jq -e --arg n "$1" '.packages[] | select(.name == $n)' <<<"$meta"; }
pkg "$name" >/dev/null || { echo "crate.sh: no workspace package $name" >&2; exit 1; }
version="$(pkg "$name" | jq -r .version)"
tag="$name-v$version"

# The crate and its workspace dependencies (normal and build, not dev), depth first.
closure=()
visit() {
  local n="$1" dir dep
  [[ " ${closure[*]} " == *" $n "* ]] && return
  dir="$(dirname "$(pkg "$n" | jq -r .manifest_path)")"
  if grep -Eq '^version\.workspace[[:space:]]*=[[:space:]]*true' "$dir/Cargo.toml"; then
    echo "crate.sh: $n inherits the workspace version; give it its own (deploy/release/README.md)" >&2
    exit 1
  fi
  while read -r dep; do
    [[ -n "$dep" ]] && visit "$dep"
  done < <(pkg "$n" | jq -r '.dependencies[] | select(.path != null and .kind != "dev") | .name')
  closure+=("$n")
}
visit "$name"
echo "crate.sh: $tag packages ${closure[*]}"

# One crate at a time and without a lock file: with either, cargo resolves the crates' path
# dependencies against crates.io, where they are not. The verify build below uses Cargo.lock.
for n in "${closure[@]}"; do
  cargo package --locked --no-verify --exclude-lockfile --quiet -p "$n"
done

# Verify: build the unpacked crates as a workspace of their own.
work="$(mktemp -d "${TMPDIR:-/tmp}/vyrn-crate.XXXXXX")"
trap 'rm -rf "$work"' EXIT
members="" patch=""
for n in "${closure[@]}"; do
  v="$(pkg "$n" | jq -r .version)"
  tar -xzf "$target_dir/package/$n-$v.crate" -C "$work"
  members+="\"$n-$v\", "
  patch+="$n = { path = \"$n-$v\" }"$'\n'
done
printf '[workspace]\nresolver = "3"\nmembers = [%s]\n\n[patch.crates-io]\n%s' \
  "$members" "$patch" >"$work/Cargo.toml"
# The pinned toolchain too: outside the repository rustup would pick its default.
cp Cargo.lock rust-toolchain.toml "$work/"
(cd "$work" && CARGO_TARGET_DIR="$target_dir/crate-verify" cargo build --quiet -p "$name")
echo "crate.sh: the unpacked $name-$version.crate builds"

cp "$target_dir/package/$name-$version.crate" "$dist/"
crate_dir="$(dirname "$(pkg "$name" | jq -r .manifest_path)")"
if [[ -f "$crate_dir/CHANGELOG.md" ]]; then
  cp "$crate_dir/CHANGELOG.md" "$dist/CHANGELOG.md"
else
  DRY_RUN=true deploy/release/changelog.sh "$name" "$version" >"$dist/CHANGELOG.md"
fi

jq -r '.packages[] | "\(.name) \(.version)"' <<<"$meta" >"$work/crates.txt"
commit="$(git rev-parse HEAD)"
cargo run --quiet --locked -p repro-build -- manifest "$dist" kind=crate name="$name" \
  version="$version" tag="$tag" commit="$commit" \
  source_date_epoch="$(git log -1 --format=%ct "$commit")" \
  protocol_version="$(deploy/release/meta.sh protocol_version)" \
  config_schema_version="$(deploy/release/meta.sh config_schema_version)" \
  crates="$work/crates.txt"
cargo run --quiet --locked -p vyrn-admin -- release verify "$dist" --unsigned
