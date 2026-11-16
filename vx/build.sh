#!/usr/bin/env bash
# The only way Vx artifacts are built (spec/11-build.md §5.4). Flag spellings live here only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! find vyrn-vx-oracle vyrn-vx-client -name '*.vx' -print -quit | grep -q .; then
  echo "vx/build.sh: no Vx sources yet; nothing to build."
  exit 0
fi
command -v vxc >/dev/null || { echo "vx/build.sh: vxc not on PATH" >&2; exit 1; }

want="$(sed -n 's/^vxc_blake3 = "\(.*\)"/\1/p' TOOLCHAIN)"
if [[ -n "$want" ]]; then
  have="$(b3sum --no-names "$(command -v vxc)")"
  [[ "$have" == "$want" ]] || { echo "vx/build.sh: vxc hash $have != $want" >&2; exit 1; }
fi

# Steps 2-6 of §5.4 (shared libraries, -fweak-relaxed-atomics on aarch64, vxc --audit,
# --sanitize=thread into ../target/vx/tsan/, nm -D export check, ../target/vx/manifest.toml)
# land with the first Vx sources.
echo "vx/build.sh: Vx sources found but the build steps are not written yet." >&2
exit 1
