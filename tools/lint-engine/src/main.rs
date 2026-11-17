//! `lint-engine`: the CI gate for the engine rules of spec/11-build.md.
//!
//! ```text
//! lint-engine [--root DIR] [--rules FILE]    (defaults: `.` and the rules.toml built in)
//! ```
//!
//! Output is one `path:line: rule: message` line per violation on stdout, sorted by path and
//! line; notes and a summary go to stderr. Exit status: 0 clean, 1 violations, 2 the tool could
//! not run. The rules are data (`rules.toml`, schema 1); the rule ids are the stable output.
//!
//! Dependency graph, from `cargo metadata` (§1.4, §2.2):
//!
//! | rule | meaning |
//! |---|---|
//! | `layer-order` | a crate depends on a crate in its own or a later layer |
//! | `engine-dependency` | an engine crate depends on a crate outside `crates/engine/` |
//! | `engine-external-dependency` | an engine crate depends on an external crate that §2.2 does not allow it |
//! | `tool-dependency` | a crate depends on a package under `tools/` |
//! | `unknown-crate` | a crate has no layer in `rules.toml` |
//! | `stale-exception` | a named exception no longer matches an edge |
//!
//! Source of every engine crate, from tokens (§2.2, §2.3, §3.1, §3.3, §8.3):
//!
//! | rule | meaning |
//! |---|---|
//! | `float-type`, `float-literal` | `f32`, `f64` or a float literal |
//! | `async` | `async` or `await` |
//! | `banned-crate` | `tokio`, `rand`, `rand_chacha`, `tracing` or `log` used as a crate |
//! | `banned-path` | `std::thread` or `std::env` |
//! | `deadline-clock` | `.now()` or `::now()` outside `vyrn-lane::admit` and `vyrn-bbo::admit` |
//! | `lex-error` | a file that `proc-macro2` cannot lex |
#![forbid(unsafe_code)]

mod deps;
mod rules;
mod source;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rules::Rules;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("lint-engine: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut rules_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(args.next().ok_or("--root needs a directory")?),
            "--rules" => rules_file = Some(args.next().ok_or("--rules needs a file")?),
            "-h" | "--help" => {
                println!("usage: lint-engine [--root DIR] [--rules FILE]");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let rules = match rules_file {
        Some(f) => {
            Rules::parse(&fs::read_to_string(&f).map_err(|e| format!("cannot read {f}: {e}"))?)
        }
        None => Rules::parse(rules::DEFAULT),
    }
    .map_err(|e| format!("rules: {e}"))?;

    let ws = deps::load(&root)?;
    let mut notes = Vec::new();
    let mut violations = deps::check(&ws, &rules, &mut notes);

    let mut engine_files = 0;
    for p in ws.packages.iter().filter(|p| p.role == deps::Role::Engine) {
        let mut files = Vec::new();
        rust_files(&ws.root, &ws.root.join(&p.dir), &mut files)
            .map_err(|e| format!("cannot scan {}: {e}", p.dir))?;
        files.sort();
        for rel in files {
            let src = fs::read_to_string(ws.root.join(&rel))
                .map_err(|e| format!("cannot read {rel}: {e}"))?;
            violations.extend(source::check_file(&rel, &src, &rules));
            engine_files += 1;
        }
    }

    violations.sort();
    for n in &notes {
        eprintln!("lint-engine: note: {n}");
    }
    for v in &violations {
        println!("{}:{}: {}: {}", v.file, v.line, v.rule, v.message);
    }
    eprintln!(
        "lint-engine: {} package(s), {engine_files} engine source file(s), {} violation(s)",
        ws.packages.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}

fn rust_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if entry.file_name() != "target" {
                rust_files(root, &path, out)?;
            }
        } else if ty.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            out.push(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(())
}
