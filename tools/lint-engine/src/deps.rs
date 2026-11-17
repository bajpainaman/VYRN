//! The dependency checks: the §1.4 layers and the §2.2 engine allowlist, from `cargo metadata`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::Violation;
use crate::rules::Rules;

#[derive(Deserialize)]
struct Meta {
    workspace_root: String,
    packages: Vec<RawPackage>,
}

#[derive(Deserialize)]
struct RawPackage {
    name: String,
    manifest_path: String,
    dependencies: Vec<RawDep>,
}

#[derive(Deserialize)]
struct RawDep {
    name: String,
    /// `null` for a normal dependency, `"build"` or `"dev"`.
    kind: Option<String>,
    /// `null` for a path dependency.
    source: Option<String>,
    rename: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Under `crates/engine/`: the INV-DET crates (§1.2).
    Engine,
    /// Under `tools/`: outside the dependency graph.
    Tool,
    Other,
}

pub struct Dep {
    pub name: String,
    pub dev: bool,
    pub internal: bool,
    /// The key as written in the manifest, for locating the line.
    written: String,
}

pub struct Package {
    pub name: String,
    pub role: Role,
    /// Manifest path relative to the workspace root, `/`-separated.
    pub manifest: String,
    /// Package directory relative to the workspace root.
    pub dir: String,
    pub deps: Vec<Dep>,
}

pub struct Workspace {
    pub root: PathBuf,
    pub packages: Vec<Package>,
}

pub fn load(root: &Path) -> Result<Workspace, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let meta: Meta = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("cannot read cargo metadata output: {e}"))?;
    let ws_root = PathBuf::from(&meta.workspace_root);
    let rel = |p: &str| {
        let p = Path::new(p);
        let p = p.strip_prefix(&ws_root).unwrap_or(p);
        p.components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    };
    let packages = meta
        .packages
        .iter()
        .map(|p| {
            let manifest = rel(&p.manifest_path);
            let dir = manifest
                .strip_suffix("Cargo.toml")
                .unwrap_or("")
                .trim_end_matches('/')
                .to_owned();
            let role = if dir.starts_with("crates/engine/") {
                Role::Engine
            } else if dir.starts_with("tools/") {
                Role::Tool
            } else {
                Role::Other
            };
            let deps = p
                .dependencies
                .iter()
                .map(|d| Dep {
                    name: d.name.clone(),
                    dev: d.kind.as_deref() == Some("dev"),
                    internal: d.source.is_none(),
                    written: d.rename.clone().unwrap_or_else(|| d.name.clone()),
                })
                .collect();
            Package {
                name: p.name.clone(),
                role,
                manifest,
                dir,
                deps,
            }
        })
        .collect();
    Ok(Workspace {
        root: ws_root,
        packages,
    })
}

/// 1-based line in the manifest where `key` is declared as a dependency; 1 if not found.
fn dep_line(manifest: &str, key: &str) -> usize {
    let table = format!("dependencies.{key}]");
    manifest
        .lines()
        .position(|l| {
            let t = l.trim_start();
            (t.starts_with('[') && t.contains(&table))
                || t.strip_prefix(key)
                    .is_some_and(|r| r.trim_start().starts_with(['=', '.']))
        })
        .map_or(1, |n| n + 1)
}

pub fn check(ws: &Workspace, rules: &Rules, notes: &mut Vec<String>) -> Vec<Violation> {
    let mut out = Vec::new();
    let by_name: BTreeMap<&str, &Package> =
        ws.packages.iter().map(|p| (p.name.as_str(), p)).collect();
    let mut used_exceptions = vec![false; rules.exception.len()];

    for p in &ws.packages {
        let text = fs::read_to_string(ws.root.join(&p.manifest)).unwrap_or_default();
        let mut hit = |dep: Option<&Dep>, rule: &'static str, message: String| {
            out.push(Violation {
                file: p.manifest.clone(),
                line: dep.map_or(1, |d| dep_line(&text, &d.written)),
                rule,
                message,
            });
        };
        let layer = rules.layer_of(&p.name);
        if p.role != Role::Tool && layer.is_none() {
            hit(
                None,
                "unknown-crate",
                format!(
                    "`{}` has no layer: add it to rules.toml, where 11 §1.4 puts it",
                    p.name
                ),
            );
        }
        for d in &p.deps {
            if !d.internal {
                if p.role == Role::Engine && !engine_may_use(rules, &p.name, d) {
                    hit(
                        Some(d),
                        "engine-external-dependency",
                        format!(
                            "engine crate `{}` may not depend on `{}` (11 §2.2 lists who may use it)",
                            p.name, d.name
                        ),
                    );
                }
                continue;
            }
            let target = by_name.get(d.name.as_str()).copied();
            if target.is_some_and(|t| t.role == Role::Tool) {
                hit(
                    Some(d),
                    "tool-dependency",
                    format!("`{}` is a tool; nothing depends on tools", d.name),
                );
                continue;
            }
            if p.role == Role::Engine && target.is_none_or(|t| t.role != Role::Engine) {
                hit(
                    Some(d),
                    "engine-dependency",
                    format!(
                        "engine crate `{}` may depend only on crates in crates/engine/, not `{}` (11 §1.4)",
                        p.name, d.name
                    ),
                );
            }
            if p.role == Role::Tool {
                continue;
            }
            let Some(own) = layer else { continue };
            let Some(theirs) = rules.layer_of(&d.name) else {
                if target.is_none() {
                    hit(
                        Some(d),
                        "unknown-crate",
                        format!(
                            "`{}` is not a workspace member and has no layer in rules.toml",
                            d.name
                        ),
                    );
                }
                continue;
            };
            if theirs >= own {
                let exception = rules
                    .exception
                    .iter()
                    .position(|e| e.from == p.name && e.to == d.name);
                if let Some(n) = exception {
                    used_exceptions[n] = true;
                    notes.push(format!(
                        "known disagreement in the spec: `{}` -> `{}` (layer {own} -> {theirs}): {}",
                        p.name, d.name, rules.exception[n].reason
                    ));
                } else {
                    hit(
                        Some(d),
                        "layer-order",
                        format!(
                            "`{}` (layer {own}) may depend only on earlier layers, but `{}` is in layer {theirs} (11 §1.4)",
                            p.name, d.name
                        ),
                    );
                }
            }
        }
    }

    for (n, e) in rules.exception.iter().enumerate() {
        let both_present =
            by_name.contains_key(e.from.as_str()) && by_name.contains_key(e.to.as_str());
        if both_present
            && !used_exceptions[n]
            && let Some(p) = by_name.get(e.from.as_str())
        {
            out.push(Violation {
                file: p.manifest.clone(),
                line: 1,
                rule: "stale-exception",
                message: format!(
                    "rules.toml excuses `{}` -> `{}`, but no layer rule needs it: remove the exception",
                    e.from, e.to
                ),
            });
        }
    }
    out
}

fn engine_may_use(rules: &Rules, engine_crate: &str, dep: &Dep) -> bool {
    let listed = |m: &BTreeMap<String, Vec<String>>, key: &str| {
        m.get(key).is_some_and(|v| v.contains(&dep.name))
    };
    listed(&rules.engine.allow, engine_crate)
        || (dep.dev
            && (listed(&rules.engine.allow_dev, engine_crate)
                || listed(&rules.engine.allow_dev, "any")))
}
