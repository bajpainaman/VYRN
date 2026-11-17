# Releases

Two kinds, both on GitHub Releases only. Nothing goes to crates.io: every crate is
`publish = false` under the [LICENSE](../../LICENSE).

| Kind | Tag | Workflow | Bundle | Signed |
|---|---|---|---|---|
| **Per-crate** | `<crate>-v<version>`, such as `vyrn-wire-v0.1.0` | `release-crate.yml` | `<crate>-<version>.crate`, `CHANGELOG.md`, `manifest.toml` | optional |
| **Final package** | `v<version>` | `release.yml` | binaries per architecture, SBOMs, provenance, toolchain hashes, `CHANGELOG.md`, `manifest.toml` | 2 of 3, required (§9.5) |

The bundle format is [MANIFEST.md](MANIFEST.md). `vyrn-admin release verify` checks it offline.

## Versions

- **The final package** has one version, `[workspace.package] version` in `Cargo.toml`. It names
  one commit and its artifacts (spec/11-build.md §10.2), and every binary and tool inherits it.
  Its manifest also records `protocol_version` (vyrn-wire's `PROTO_VERSION`) and
  `config_schema_version` (`[workspace.metadata.vyrn]` in `Cargo.toml`). Those are separate from
  the release version: they change only when the bytes on the wire or the config schema change
  (§10.1–10.2).
- **A library crate** gets its own version when it is ready to release alone: set
  `version = "0.1.0"` in its `Cargo.toml` in place of `version.workspace = true`, and add the same
  `version` to its line in `[workspace.dependencies]`. Every workspace crate it depends on needs
  the same treatment, because `cargo package` needs a version on each dependency. vyrn-types,
  vyrn-crypto and vyrn-wire have their own versions today. New crates inherit the workspace
  version until someone gives them their own; the scripts find crates through `cargo metadata`
  and need no edit for a new one.
- The final manifest lists every crate with its version (`[[crate]]`). So a crate's own version
  never replaces the release commit; it only says which crate releases that commit contains.

## Cut a per-crate release

Needs [cargo-release](https://github.com/crate-ci/cargo-release) 1.1.7 and
[git-cliff](https://git-cliff.org) 2.14.2 (`cargo binstall cargo-release@1.1.7 git-cliff@2.14.2`).
Run it on an up-to-date `main` with a clean tree:

```sh
cargo release -p vyrn-wire minor              # dry run: shows the bump, changelog and tag
cargo release -p vyrn-wire minor --execute    # bumps the version, writes the CHANGELOG.md,
                                              # commits "release: bump crate versions", and tags vyrn-wire-v0.2.0
git push origin main vyrn-wire-v0.2.0         # the tag push runs release-crate.yml
```

`[workspace.metadata.release]` in `Cargo.toml` sets the tag name and turns off publishing and
pushing, and it runs [changelog.sh](changelog.sh) as the pre-release hook. Workspace crates that
depend on the crate get their requirement raised in the same commit. If `main` is protected, push
the release commit as a PR first, then tag the merged commit and push only the tag.

To rebuild a crate's bundle without tagging, run `deploy/release/crate.sh vyrn-wire dist`
locally. To do the same in CI, run the **Release crate** workflow by hand: `crate` = `vyrn-wire`,
`dry_run` checked. A dry run uploads the bundle as a workflow artifact and publishes nothing.

## Cut the final release

```sh
sed -i '0,/^version = ".*"/s//version = "0.1.0"/' Cargo.toml   # [workspace.package] version
cargo update --workspace
git commit -am "release: vyrn v0.1.0"
git tag -a v0.1.0 -m "vyrn v0.1.0"
git push origin main v0.1.0                                     # runs release.yml
```

`release.yml` builds the release binaries on Linux x86-64 and aarch64, twice each, from two
checkouts at different paths ([build.sh](build.sh)), and stops if any file hash differs. It
writes the SBOMs, the toolchain hashes, the changelog and an **unsigned** `manifest.toml`, checks
them with `vyrn-admin release verify --unsigned`, and creates a **draft** GitHub Release. To build
without tagging, run the **Release** workflow by hand with `dry_run` checked.

### Sign it (offline, two of three maintainers)

CI holds no release key (§9.5). Each of two maintainers, on their own machine:

```sh
gh release download v0.1.0 -D v0.1.0 && cd v0.1.0
cargo run -q -p vyrn-admin -- release verify . --unsigned     # hashes match the files
# Sign the exact bytes of manifest.toml with the Ed25519 key on the hardware token
# (RFC 8032, no pre-hash), and write the 64-byte signature as 128 lowercase hex:
#   manifest.toml.<key-id>.sig
gh release upload v0.1.0 manifest.toml.<key-id>.sig
```

With a PKCS#11 token, `pkcs11-tool --sign --mechanism EDDSA -i manifest.toml -o sig.bin` should
write the raw 64-byte signature, and `xxd -p -c 64 sig.bin` turns it into hex. Check this once
per token type with `release verify --keys` before the first real release. A maintainer then
checks both signatures against the trusted keys and publishes the draft:

```sh
gh release download v0.1.0 -D check --clobber
cargo run -q -p vyrn-admin -- release verify check --keys release-keys.toml
gh release edit v0.1.0 --draft=false
```

`release-keys.toml` holds the three public keys (`[[key]] id, ed25519`, see MANIFEST.md). It is
not in this repository yet: the maintainers add it with their keys by a reviewed commit. No key
was created here.

## Reproducibility (§9.4)

In place now: `SOURCE_DATE_EPOCH` set to the commit time; `--remap-path-prefix` for the source,
target, cargo home and rustup paths; `--locked`; `codegen-units = 1` (the release profile); two
builds compared by BLAKE3 hash of every binary. The two build hash lists ship in the bundle as
`provenance.<target>.build-{a,b}.b3`.

Not yet: the second build on a separate machine with a different OS install (`tools/repro-build`
on a release builder), the pinned OCI build image of `deploy/image/`, `--offline` against a
vendored `vendor/`, and `-ffile-prefix-map` for the C shim, which no release binary links yet.
