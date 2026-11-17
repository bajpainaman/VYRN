//! `vyrn-admin release verify` (spec/11-build.md §9.5): checks a release bundle offline against
//! deploy/release/MANIFEST.md, format 1. Cold path only: it runs before a bundle is staged.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

/// Signatures a release needs (`BLD_RELEASE_SIGS`, 11 Local definitions).
pub const BLD_RELEASE_SIGS: usize = 2;

const MANIFEST: &str = "manifest.toml";
const SIG_PREFIX: &str = "manifest.toml.";
const SIG_SUFFIX: &str = ".sig";

#[derive(Deserialize)]
struct VersionOnly {
    manifest_version: i64,
}

// Format 1 requires every field, so each is parsed; verify interprets only some of them.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    manifest_version: i64,
    kind: String,
    name: String,
    version: String,
    tag: String,
    commit: String,
    source_date_epoch: u64,
    protocol_version: u16,
    config_schema_version: u32,
    #[serde(rename = "crate", default)]
    crates: Vec<CrateEntry>,
    #[serde(rename = "toolchain", default)]
    toolchains: Vec<Toolchain>,
    #[serde(rename = "file")]
    files: Vec<FileEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrateEntry {
    name: String,
    version: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    name: String,
    target: String,
    version: String,
    blake3: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    path: String,
    size: u64,
    blake3: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    #[serde(rename = "key")]
    keys: Vec<Key>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    id: String,
    ed25519: String,
}

/// What a successful verification established.
pub struct Verified {
    pub tag: String,
    pub commit: String,
    pub files: usize,
    /// Key ids with a valid signature; empty when run with `--unsigned`.
    pub signers: Vec<String>,
}

/// Verifies the bundle in `dir`. With `keys`, at least [`BLD_RELEASE_SIGS`] trusted keys must
/// have signed `manifest.toml`; with `None` (`--unsigned`), signatures are not checked.
pub fn verify(dir: &Path, keys: Option<&Path>) -> Result<Verified, String> {
    let manifest_bytes = read(&dir.join(MANIFEST))?;
    let text = std::str::from_utf8(&manifest_bytes).map_err(|_| "manifest.toml is not UTF-8")?;
    let version: VersionOnly = toml::from_str(text).map_err(|e| format!("manifest.toml: {e}"))?;
    if version.manifest_version != 1 {
        return Err(format!(
            "manifest_version {} is not supported (this verifier knows 1)",
            version.manifest_version
        ));
    }
    let manifest: Manifest = toml::from_str(text).map_err(|e| format!("manifest.toml: {e}"))?;
    check_fields(&manifest)?;

    let mut sig_files = BTreeSet::new();
    let mut other_files = BTreeSet::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("file name {n:?} is not UTF-8"))?;
        if !entry
            .file_type()
            .map_err(|e| format!("{name}: {e}"))?
            .is_file()
        {
            return Err(format!("{name}: a bundle holds regular files only"));
        }
        if name == MANIFEST {
            continue;
        }
        if let Some(id) = sig_key_id(&name) {
            sig_files.insert(id.to_owned());
        } else {
            other_files.insert(name);
        }
    }

    let signers = match keys {
        Some(keys) => check_signatures(dir, &manifest_bytes, &sig_files, keys)?,
        None => Vec::new(),
    };

    let mut listed = BTreeSet::new();
    for file in &manifest.files {
        if !flat_name(&file.path) || file.path == MANIFEST || sig_key_id(&file.path).is_some() {
            return Err(format!(
                "[[file]] path {:?} is not a bundle file name",
                file.path
            ));
        }
        if !listed.insert(file.path.as_str()) {
            return Err(format!("{} is listed twice", file.path));
        }
        let path = dir.join(&file.path);
        let size = fs::metadata(&path)
            .map_err(|e| format!("{}: {e}", file.path))?
            .len();
        if size != file.size {
            return Err(format!(
                "{}: size {size}, manifest says {}",
                file.path, file.size
            ));
        }
        let have = hex(&vyrn_crypto::hash::hash(&read(&path)?).0);
        if have != file.blake3 {
            return Err(format!(
                "{}: BLAKE3 {have}, manifest says {}",
                file.path, file.blake3
            ));
        }
    }
    if let Some(extra) = other_files.iter().find(|f| !listed.contains(f.as_str())) {
        return Err(format!("{extra} is in the bundle but not in the manifest"));
    }

    Ok(Verified {
        tag: manifest.tag,
        commit: manifest.commit,
        files: manifest.files.len(),
        signers,
    })
}

fn check_fields(m: &Manifest) -> Result<(), String> {
    let tag = match m.kind.as_str() {
        "workspace" if m.name == "vyrn" => format!("v{}", m.version),
        "workspace" => {
            return Err(format!(
                "kind workspace needs name \"vyrn\", not {:?}",
                m.name
            ));
        }
        "crate" => format!("{}-v{}", m.name, m.version),
        other => return Err(format!("kind {other:?} is not workspace or crate")),
    };
    if m.tag != tag {
        return Err(format!("tag {:?} does not match {tag:?}", m.tag));
    }
    if !is_semver(&m.version) {
        return Err(format!("version {:?} is not MAJOR.MINOR.PATCH", m.version));
    }
    if !is_hex(&m.commit, 40) {
        return Err(format!("commit {:?} is not 40 lowercase hex", m.commit));
    }
    if m.files.is_empty() {
        return Err("the manifest lists no [[file]]".into());
    }
    for c in &m.crates {
        if c.name.is_empty() || !is_semver(&c.version) {
            return Err(format!(
                "[[crate]] {:?} {:?} is malformed",
                c.name, c.version
            ));
        }
    }
    for t in &m.toolchains {
        if t.name.is_empty() || t.target.is_empty() || !is_hex(&t.blake3, 64) {
            return Err(format!("[[toolchain]] {:?} is malformed", t.name));
        }
    }
    for f in &m.files {
        if !is_hex(&f.blake3, 64) {
            return Err(format!("{}: blake3 is not 64 lowercase hex", f.path));
        }
    }
    Ok(())
}

fn check_signatures(
    dir: &Path,
    manifest: &[u8],
    sig_files: &BTreeSet<String>,
    keys: &Path,
) -> Result<Vec<String>, String> {
    let text = String::from_utf8(read(keys)?).map_err(|_| "keys file is not UTF-8")?;
    let keys: Keys = toml::from_str(&text).map_err(|e| format!("{}: {e}", keys.display()))?;
    let mut trusted = std::collections::BTreeMap::new();
    for key in &keys.keys {
        let public: [u8; 32] = unhex(&key.ed25519)
            .ok_or_else(|| format!("key {:?}: ed25519 is not 64 lowercase hex", key.id))?;
        if !valid_key_id(&key.id) || trusted.insert(key.id.as_str(), public).is_some() {
            return Err(format!("key id {:?} is malformed or repeated", key.id));
        }
    }
    let mut signers = Vec::new();
    for id in sig_files {
        let name = format!("{SIG_PREFIX}{id}{SIG_SUFFIX}");
        let public = trusted
            .get(id.as_str())
            .ok_or_else(|| format!("{name}: key {id:?} is not trusted"))?;
        let body =
            String::from_utf8(read(&dir.join(&name))?).map_err(|_| format!("{name}: not UTF-8"))?;
        let body = body.strip_suffix('\n').unwrap_or(&body);
        let signature: [u8; 64] =
            unhex(body).ok_or_else(|| format!("{name}: not 128 lowercase hex"))?;
        if !vyrn_crypto::ed25519::verify(public, manifest, &signature) {
            return Err(format!("{name}: signature does not verify"));
        }
        signers.push(id.clone());
    }
    if signers.len() < BLD_RELEASE_SIGS {
        return Err(format!(
            "{} valid signature(s); a release needs {BLD_RELEASE_SIGS}",
            signers.len()
        ));
    }
    Ok(signers)
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn sig_key_id(name: &str) -> Option<&str> {
    let id = name.strip_prefix(SIG_PREFIX)?.strip_suffix(SIG_SUFFIX)?;
    valid_key_id(id).then_some(id)
}

fn valid_key_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn flat_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

fn is_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if !is_hex(s, 2 * N) {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
