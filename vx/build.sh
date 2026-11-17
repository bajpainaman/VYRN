#!/usr/bin/env bash
# The only way Vx artifacts are built (spec/11-build.md §5.4). Flag spellings live here only.
# Outputs go to ../target/vx/: one shared library per Vx part, and manifest.toml.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! find vyrn-vx-oracle vyrn-vx-client -name '*.vx' -print -quit | grep -q .; then
  echo "vx/build.sh: no Vx sources yet; nothing to build."
  exit 0
fi
die() { echo "vx/build.sh: $*" >&2; exit 1; }

# Step 1: the vxc on PATH must be the pinned build (vx/TOOLCHAIN).
vxc_path="$(command -v vxc)" || die "vxc not on PATH"
command -v b3sum >/dev/null || die "b3sum not on PATH (cargo install --locked b3sum)"
want="$(sed -n 's/^vxc_blake3 = "\(.*\)"/\1/p' TOOLCHAIN)"
[[ -n "$want" ]] || die "vx/TOOLCHAIN has no vxc_blake3"
have="$(b3sum --no-names "$vxc_path")"
[[ "$have" == "$want" ]] || die "vxc hash $have != $want (vx/TOOLCHAIN)"

# VX-WORKAROUND W-15 (issue to file): vxc asks the llvm-config on PATH for its runtime
# libraries. That one matches rustc's LLVM, not vxc's LLVM 22 (11 §4.2), so point vxc at its own.
if [[ -z "${LLVM_CONFIG_PATH:-}" && -x /usr/lib/llvm-22/bin/llvm-config ]]; then
  export LLVM_CONFIG_PATH=/usr/lib/llvm-22/bin/llvm-config
fi

out="../target/vx"
mkdir -p "$out/obj"
triple="$(cc -dumpmachine)"
flags=(--action emit-obj -O 3)
# Step 2: without it, Relaxed loads compile as Acquire on aarch64 (DESIGN §8).
case "$(uname -m)" in aarch64 | arm64) flags+=(-fweak-relaxed-atomics) ;; esac
case "$(uname -s)" in
  Darwin) ext=dylib ;;
  *) ext=so ;;
esac

manifest="# Written by vx/build.sh (spec/11-build.md §5.4 step 6).
vxc = \"$vxc_path\"
vxc_blake3 = \"$have\"
target = \"$triple\"
"

# build <part> <export prefix>
build() {
  local part="$1" prefix="$2" src="$1/oracle.vx" lib name
  name="lib${part//-/_}.$ext"
  [[ "$part" == vyrn-vx-client ]] && src="$part/client.vx"
  [[ -f "$src" ]] || return 0
  lib="$out/$name"

  # Step 3: every fact vxc trusts without a proof must be listed in AUDIT.allow.
  local audit unlisted
  audit="$(vxc "$src" --audit 2>/dev/null)" || die "vxc --audit failed on $src"
  unlisted="$(grep -vxF -f <(grep -v '^#' AUDIT.allow | sed '/^$/d') <<<"$audit" || true)"
  [[ -z "$unlisted" ]] || die "unproven facts not in vx/AUDIT.allow:
$unlisted"

  # Step 2: an object from vxc, linked as a shared library that exports only <prefix>*.
  # VX-WORKAROUND W-09 (issue to file): vxc exports every function, so the linker hides them.
  vxc "$src" "${flags[@]}" -o "$out/obj/$part.o" 2>"$out/obj/$part.log" ||
    { cat "$out/obj/$part.log" >&2; die "vxc failed on $src"; }
  if [[ "$ext" == dylib ]]; then
    echo "_${prefix}*" >"$out/obj/$part.exports"
    cc -dynamiclib -o "$lib" "$out/obj/$part.o" -Wl,-exported_symbols_list,"$out/obj/$part.exports"
  else
    printf '{ global: %s*; local: *; };\n' "$prefix" >"$out/obj/$part.map"
    cc -shared -o "$lib" "$out/obj/$part.o" -Wl,--version-script="$out/obj/$part.map"
  fi

  # Step 5: exported symbols (§5.1).
  local syms bad
  if [[ "$ext" == dylib ]]; then
    syms="$(nm -gU "$lib" | awk '{print $3}' | sed 's/^_//')"
  else
    syms="$(nm -D --defined-only "$lib" | awk '{print $3}')"
  fi
  bad="$(grep -v "^${prefix}" <<<"$syms" || true)"
  [[ -z "$bad" ]] || die "$lib exports symbols outside ${prefix}*: $bad"

  manifest+="
[lib.\"$part\"]
path = \"target/vx/$name\"
blake3 = \"$(b3sum --no-names "$lib")\"
"
  echo "vx/build.sh: built $lib"
}

build vyrn-vx-oracle pbo_
# Step 4 (the TSan build of the client) lands with the client's sources.
build vyrn-vx-client pbv_

# Step 6.
printf '%s' "$manifest" >"$out/manifest.toml"
echo "vx/build.sh: wrote $out/manifest.toml"
