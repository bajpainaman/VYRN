//! Release builder helpers (spec/11-build.md §9.4–9.5). The workflows in .github/workflows/
//! release*.yml call it; deploy/release/MANIFEST.md is the format it writes.
//!
//! - `repro-build hash DIR`: BLAKE3 list of every file in DIR, sorted by name (`<hex>  <name>`).
//!   Two builds of one commit must print the same list (§9.4).
//! - `repro-build toolchain TARGET`: the `[[toolchain]]` entries for this builder: rustc, its
//!   driver library, cargo, clang, ld.lld and vxc when present.
//! - `repro-build manifest DIR KEY=VALUE...`: writes DIR/manifest.toml, format 1.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["hash", dir] => hash_list(Path::new(dir)).map(|s| print!("{s}")),
        ["toolchain", target] => toolchain(target).map(|s| print!("{s}")),
        ["manifest", dir, pairs @ ..] => manifest(Path::new(dir), pairs),
        _ => {
            Err("usage: repro-build hash DIR | toolchain TARGET | manifest DIR KEY=VALUE...".into())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("repro-build: {e}");
            ExitCode::FAILURE
        }
    }
}

fn b3(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Regular files in `dir`, sorted by name.
fn files(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file() {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|n| format!("{n:?} is not UTF-8"))?;
            out.push((name, entry.path()));
        }
    }
    out.sort();
    Ok(out)
}

fn hash_list(dir: &Path) -> Result<String, String> {
    let mut out = String::new();
    for (name, path) in files(dir)? {
        out.push_str(&format!("{}  {name}\n", b3(&path)?));
    }
    Ok(out)
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn on_path(tool: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(tool))
        .find(|p| p.is_file())
        .and_then(|p| fs::canonicalize(p).ok())
}

fn toolchain(target: &str) -> Result<String, String> {
    let sysroot = PathBuf::from(run("rustc", &["--print", "sysroot"]).ok_or("rustc not found")?);
    let mut tools: Vec<(String, PathBuf, String)> = Vec::new();
    let version = |cmd: &str| {
        run(cmd, &["--version"])
            .and_then(|v| v.lines().next().map(str::to_owned))
            .unwrap_or_default()
    };
    tools.push(("rustc".into(), sysroot.join("bin/rustc"), version("rustc")));
    if let Some((_, driver)) = files(&sysroot.join("lib"))?
        .into_iter()
        .find(|(n, _)| n.starts_with("librustc_driver-"))
    {
        tools.push(("librustc_driver".into(), driver, String::new()));
    }
    let cargo = sysroot.join("bin/cargo");
    if cargo.is_file() {
        tools.push(("cargo".into(), cargo, version("cargo")));
    }
    for tool in ["clang", "ld.lld", "vxc"] {
        if let Some(path) = on_path(tool) {
            tools.push((tool.into(), path, version(tool)));
        }
    }
    let mut out = String::new();
    for (name, path, version) in tools {
        out.push_str(&format!(
            "[[toolchain]]\nname = {}\ntarget = {}\nversion = {}\nblake3 = \"{}\"\n\n",
            quote(&name),
            quote(target),
            quote(&version),
            b3(&path)?
        ));
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ToolchainFile {
    #[serde(default)]
    toolchain: Vec<toml::Table>,
}

/// Writes `dir/manifest.toml`. Keys: kind, name, version, tag, commit, source_date_epoch,
/// protocol_version, config_schema_version, crates (a file of `name version` lines). The
/// `[[toolchain]]` entries come from the bundle's `provenance.*.toolchain.toml` files.
fn manifest(dir: &Path, pairs: &[&str]) -> Result<(), String> {
    let mut kv = BTreeMap::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("{pair}: not KEY=VALUE"))?;
        kv.insert(k, v);
    }
    let get = |k: &str| kv.get(k).copied().ok_or_else(|| format!("missing {k}="));
    let int = |k: &str| -> Result<u64, String> {
        get(k)?
            .parse()
            .map_err(|_| format!("{k}= is not an integer"))
    };

    let mut out = format!(
        "manifest_version = 1\nkind = {}\nname = {}\nversion = {}\ntag = {}\ncommit = {}\n\
         source_date_epoch = {}\nprotocol_version = {}\nconfig_schema_version = {}\n",
        quote(get("kind")?),
        quote(get("name")?),
        quote(get("version")?),
        quote(get("tag")?),
        quote(get("commit")?),
        int("source_date_epoch")?,
        int("protocol_version")?,
        int("config_schema_version")?,
    );

    let crates = fs::read_to_string(get("crates")?).map_err(|e| format!("crates=: {e}"))?;
    let mut crates: Vec<(&str, &str)> = crates.lines().filter_map(|l| l.split_once(' ')).collect();
    crates.sort();
    for (name, version) in crates {
        out.push_str(&format!(
            "\n[[crate]]\nname = {}\nversion = {}\n",
            quote(name),
            quote(version.trim())
        ));
    }

    let listed: Vec<(String, PathBuf)> = files(dir)?
        .into_iter()
        .filter(|(n, _)| n != "manifest.toml" && !n.ends_with(".sig"))
        .collect();
    for (name, path) in &listed {
        if name.starts_with("provenance.") && name.ends_with(".toolchain.toml") {
            let text = fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
            let parsed: ToolchainFile =
                toml::from_str(&text).map_err(|e| format!("{name}: {e}"))?;
            for entry in parsed.toolchain {
                out.push_str("\n[[toolchain]]\n");
                for field in ["name", "target", "version", "blake3"] {
                    let value = entry
                        .get(field)
                        .and_then(toml::Value::as_str)
                        .ok_or_else(|| format!("{name}: [[toolchain]] lacks {field}"))?;
                    out.push_str(&format!("{field} = {}\n", quote(value)));
                }
            }
        }
    }
    if listed.is_empty() {
        return Err(format!("{}: no files to list", dir.display()));
    }
    for (name, path) in &listed {
        let size = fs::metadata(path).map_err(|e| e.to_string())?.len();
        out.push_str(&format!(
            "\n[[file]]\npath = {}\nsize = {size}\nblake3 = \"{}\"\n",
            quote(name),
            b3(path)?
        ));
    }
    fs::write(dir.join("manifest.toml"), out).map_err(|e| format!("manifest.toml: {e}"))
}

/// A TOML basic string.
fn quote(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}
