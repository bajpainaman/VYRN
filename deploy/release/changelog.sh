#!/usr/bin/env bash
# The changelog section of a release, from git history (git-cliff, cliff.toml).
#
#   deploy/release/changelog.sh NAME VERSION
#
# NAME is a crate (only commits touching its directory, since its previous `NAME-v*` tag) or
# `vyrn` (the final package: every commit since the previous `v*` tag). cargo-release runs it as
# its pre-release hook: then it prepends the section to the crate's CHANGELOG.md, which the
# release commit carries. With DRY_RUN=true it prints the section instead.
set -euo pipefail

name="$1" version="$2"
root="$(git rev-parse --show-toplevel)"
cd "$root"
args=(--config "$root/cliff.toml" --strip header)
if [[ "$name" == vyrn ]]; then
  tag="v$version"
  args+=(--tag-pattern '^v[0-9]')
  out=""
else
  tag="$name-v$version"
  dir="$(cargo metadata --format-version 1 --no-deps --locked |
    jq -r --arg n "$name" '.packages[] | select(.name == $n) | .manifest_path' | xargs dirname)"
  rel="${dir#"$root"/}"
  args+=(--tag-pattern "^$name-v[0-9]" --include-path "$rel/**")
  out="$dir/CHANGELOG.md"
fi
# On the tag itself (CI), the section is the tag's; before tagging (the hook), it is unreleased.
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  args+=(--latest)
else
  args+=(--unreleased --tag "$tag")
fi

if [[ "${DRY_RUN:-false}" == true || -z "$out" ]]; then
  git cliff "${args[@]}"
elif [[ -f "$out" ]]; then
  git cliff "${args[@]}" --prepend "$out"
else
  { printf '# Changelog of %s\n\n' "$name"; git cliff "${args[@]}"; } >"$out"
  git add "$out" # cargo-release commits with `git commit -a`, which skips new files
fi
