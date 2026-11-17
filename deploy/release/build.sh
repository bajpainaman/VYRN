#!/usr/bin/env bash
# Builds the release binaries of one target twice and compares them (spec/11-build.md §9.4), then
# fills DIST with the bundle files of that target (deploy/release/MANIFEST.md):
#   <binary>.<target>, sbom.<binary>.<target>.cdx.json,
#   provenance.<target>.build-a.b3, provenance.<target>.build-b.b3, provenance.<target>.toolchain.toml
#
#   deploy/release/build.sh TARGET DIST [REF]
#
# Both builds come from `git worktree`s of REF (default HEAD) at two different paths with two target
# directories, so a path that leaks into a binary shows up as a difference. Both run on this
# machine; the second builder on another machine (§9.4) is a follow-up. Any difference fails.
# Release binaries are every bin target of a package under crates/ or bin/; tools/ are CI gates.
set -euo pipefail

target="$1"
dist="$(mkdir -p "$2" && cd "$2" && pwd)"
ref="${3:-HEAD}"
root="$(git rev-parse --show-toplevel)"
commit="$(git -C "$root" rev-parse "$ref^{commit}")"
work="$(mktemp -d "${TMPDIR:-/tmp}/vyrn-repro.XXXXXX")"
trap 'git -C "$root" worktree remove --force "$work/a" 2>/dev/null || true
      git -C "$root" worktree remove --force "$work/build-b-longer-path" 2>/dev/null || true
      rm -rf "$work"' EXIT

# §9.4 inputs: the commit time, remapped paths, the lock file.
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct "$commit")"
export SOURCE_DATE_EPOCH
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

bins() {
  cargo metadata --format-version 1 --no-deps --locked --manifest-path "$1/Cargo.toml" |
    jq -r --arg root "$1/" '.packages[]
      | select(.manifest_path | ltrimstr($root) | test("^(crates|bin)/"))
      | .targets[] | select(.kind == ["bin"]) | .name' | sort
}

build() { # build SRC TARGET_DIR
  local src="$1" tdir="$2" flags bin_args=()
  # rustc applies the last matching prefix, so the target directory (inside SRC) comes last.
  flags="[\"--remap-path-prefix=$cargo_home=/cargo\", \"--remap-path-prefix=$rustup_home=/rustup\","
  flags+=" \"--remap-path-prefix=$src=/vyrn\", \"--remap-path-prefix=$tdir=/target\"]"
  while read -r bin; do bin_args+=(--bin "$bin"); done < <(bins "$src")
  # C and assembly from build scripts (blake3's SIMD code) go through the cc crate: clang, the
  # compiler the toolchain list hashes, with the same path maps.
  local t="${target//-/_}" cflags
  cflags="-ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$src=/vyrn"
  cflags+=" -ffile-prefix-map=$tdir=/target"
  (cd "$src" && env "CC_$t=clang" "CFLAGS_$t=$cflags" "ASMFLAGS_$t=$cflags" \
    CARGO_TARGET_DIR="$tdir" cargo build --release --locked --workspace \
    --target "$target" --config "target.$target.rustflags=$flags" "${bin_args[@]}")
  mkdir -p "$tdir/out"
  while read -r bin; do
    cp "$tdir/$target/release/$bin" "$tdir/out/$bin.$target"
  done < <(bins "$src")
}

repro=(cargo run --quiet --locked --release --manifest-path "$root/Cargo.toml" -p repro-build --)
git -C "$root" worktree add --quiet --detach "$work/a" "$commit"
git -C "$root" worktree add --quiet --detach "$work/build-b-longer-path" "$commit"
build "$work/a" "$work/a/target"
build "$work/build-b-longer-path" "$work/tb"

"${repro[@]}" hash "$work/a/target/out" >"$dist/provenance.$target.build-a.b3"
"${repro[@]}" hash "$work/tb/out" >"$dist/provenance.$target.build-b.b3"
if ! diff -u "$dist/provenance.$target.build-a.b3" "$dist/provenance.$target.build-b.b3"; then
  echo "build.sh: the two builds of $commit for $target differ; the release stops (§9.4)" >&2
  exit 1
fi
echo "build.sh: two builds of $commit for $target are identical:"
cat "$dist/provenance.$target.build-a.b3"

cp "$work/a/target/out/"* "$dist/"
"${repro[@]}" toolchain "$target" >"$dist/provenance.$target.toolchain.toml"

# CycloneDX SBOM per binary. Not part of the comparison: the tool stamps a time and a random
# serial number into each one.
(cd "$work/a" && cargo cyclonedx --quiet --format json --spec-version 1.5 --describe binaries \
  --target "$target")
while IFS= read -r -d '' sbom; do
  name="$(basename "$sbom" _bin.cdx.json)"
  if [[ -f "$dist/$name.$target" ]]; then
    mv "$sbom" "$dist/sbom.$name.$target.cdx.json"
  fi
done < <(find "$work/a/crates" "$work/a/bin" -name '*_bin.cdx.json' -print0)
