# Release manifest, format 1

The contract between the release builder and every verifier (spec/11-build.md §9.5). A verifier
checks a bundle offline with this page, the bundle, and the trusted public keys, and nothing
else: no network, no repository, no CI. `tools/repro-build manifest` writes it;
`vyrn-admin release verify` checks it. Any other implementation that follows this page is equally
valid, and `bin/vyrn-admin/tests/release_verify.rs` is the conformance suite to run it against.

## Bundle

A bundle is one flat directory, as `gh release download <tag>` writes it:

| File | Role |
|---|---|
| `manifest.toml` | This format. The only signed file. |
| `manifest.toml.<key-id>.sig` | One detached signature per maintainer key. Not listed in the manifest. |
| every other file | Listed in the manifest under `[[file]]`, with its size and BLAKE3 hash. |

Names are flat (no `/`), because GitHub release assets are. A file in the directory that the
manifest does not list, other than the two kinds above, fails verification.

## `manifest.toml`

TOML, UTF-8. Fields not named here are an error in format 1; a later format adds them under a new
`manifest_version`.

```toml
manifest_version = 1                  # integer; a verifier rejects any version it does not know
kind = "workspace"                    # "workspace": the final package; "crate": one library crate
name = "vyrn"                         # "vyrn" for kind = "workspace", else the crate name
version = "0.1.0"                     # SemVer: the workspace version, or the crate's own version
tag = "v0.1.0"                        # "v<version>", or "<name>-v<version>" for a crate
commit = "e54c379…"                   # 40 lowercase hex: the git commit the tag points at
source_date_epoch = 1763416800        # seconds; the commit time, used as SOURCE_DATE_EPOCH
protocol_version = 2                  # §10.2; vyrn-wire's PROTO_VERSION (04 §12)
config_schema_version = 0             # §10.1; 0 while deploy/schema/ defines none

[[crate]]                             # every workspace package at this commit, sorted by name
name = "vyrn-wire"
version = "0.1.0"

[[toolchain]]                         # every tool that produced a listed file, per target
name = "rustc"                        # rustc, librustc_driver, cargo, clang, ld.lld, vxc, ...
target = "x86_64-unknown-linux-gnu"
version = "rustc 1.100.0 (…)"         # first line of `<tool> --version`; "" for a library
blake3 = "…"                          # 64 lowercase hex of the tool's file

[[file]]                              # every file of the bundle except manifest.toml and *.sig,
path = "vyrn-seq.x86_64-unknown-linux-gnu"   # sorted by path
size = 1234567                        # bytes
blake3 = "…"                          # 64 lowercase hex, BLAKE3-256 of the whole file
```

Every scalar field above is required. `[[crate]]` and `[[toolchain]]` may be empty; `[[file]]`
has at least one entry.

### File names in a workspace bundle

| Pattern | What |
|---|---|
| `<binary>.<target>` | A release binary (§9.5), `release` profile, stripped of nothing |
| `<library>.<target>.so` | A Vx library from `vx/build.sh` (§5.4), once Vx sources exist |
| `sbom.<package>.<target>.cdx.json` | CycloneDX SBOM of one binary package |
| `provenance.<target>.build-a.b3`, `.build-b.b3` | BLAKE3 list of each of the two builds (§9.4) |
| `provenance.<target>.toolchain.toml` | The `[[toolchain]]` entries of that target's builder |
| `CHANGELOG.md` | Release notes |

A crate bundle holds `<name>-<version>.crate` (from `cargo package`) and `CHANGELOG.md`.

`<target>` is `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-gnu`.

## Signatures (§9.5)

- **Message.** The exact bytes of `manifest.toml`. Nothing is hashed or canonicalised first, so
  any RFC 8032 Ed25519 signer works, including a hardware token through PKCS#11.
- **Signature file.** `manifest.toml.<key-id>.sig`: 128 lowercase hex characters (the 64-byte
  signature), optionally followed by one newline. `<key-id>` is `[a-z0-9-]{1,32}`.
- **Trusted keys.** A TOML file the verifier holds, never one from the bundle:

  ```toml
  [[key]]
  id = "maintainer-a"                 # matches <key-id>
  ed25519 = "…"                       # 64 lowercase hex, the 32-byte public key
  ```

- **Rule.** Signatures verify under ZIP-215 (§2.5, `vyrn_crypto::ed25519::verify`). A bundle is
  signed when at least `BLD_RELEASE_SIGS` = 2 distinct trusted keys have a valid signature. A
  keys file that lists one public key twice, under any ids, is rejected. A
  signature file whose key is not trusted, or that does not verify, fails the bundle: a bad
  signature is a sign of tampering, never a file to skip.
- **Rotation.** The keys file changes by a reviewed commit; a release names no keys, so old
  bundles stay verifiable against the keys file of their time.

## Verifier procedure

1. Read `manifest.toml`; reject a `manifest_version` other than 1, an unknown field, or a missing
   one.
2. Check the signatures by the rule above (skipped only with `--unsigned`, which DEV and CI use
   and which a box never accepts).
3. For each `[[file]]`: the name is flat and listed once, the file exists, and its size and BLAKE3
   hash match.
4. Reject any other file in the directory except `manifest.toml.*.sig`.

Exit status 0 means the bundle verified; anything else means it did not, with the reason on
stderr.

## Privacy

The manifest names commits, versions and hashes only. It carries no builder host names, user
names or paths: `--remap-path-prefix` removes them from the binaries too (§9.4).
