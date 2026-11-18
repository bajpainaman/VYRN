//! `vx-friction` command line; the contract is in `lib.rs`.
#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use vx_friction::{FRICTION, SKIP_DIRS};

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("vx-friction: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut today = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(args.next().ok_or("--root needs a directory")?),
            "--today" => {
                let d = args.next().ok_or("--today needs YYYY-MM-DD")?;
                today =
                    Some(vx_friction::day_number(&d).ok_or(format!("--today: bad date `{d}`"))?);
            }
            "-h" | "--help" => {
                println!("usage: vx-friction [--root DIR] [--today YYYY-MM-DD]");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let today = match today {
        Some(t) => t,
        None => {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("system clock: {e}"))?
                .as_secs();
            i64::try_from(secs / 86_400).map_err(|e| format!("system clock: {e}"))?
        }
    };
    let friction = fs::read_to_string(root.join(FRICTION))
        .map_err(|e| format!("cannot read {FRICTION}: {e}"))?;
    let mut files = Vec::new();
    walk(&root, &root, &mut files).map_err(|e| format!("cannot scan: {e}"))?;
    files.sort();
    let mut found = Vec::new();
    for rel in &files {
        if let Ok(text) = fs::read_to_string(root.join(rel)) {
            found.extend(vx_friction::markers(rel, &text));
        }
    }
    let violations = vx_friction::check(&found, &friction, today);
    for v in &violations {
        println!("{}:{}: {}: {}", v.file, v.line, v.rule, v.message);
    }
    eprintln!(
        "vx-friction: {} marker(s) in {} file(s), {} violation(s)",
        found.len(),
        files.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}

fn rel(root: &Path, path: &Path) -> String {
    let r = path.strip_prefix(root).unwrap_or(path);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = rel(root, &path);
        let ty = entry.file_type()?;
        if ty.is_dir() {
            let base = entry.file_name();
            let nested = [".git", "target", "node_modules"]
                .iter()
                .any(|b| base == *b);
            if !nested && !SKIP_DIRS.contains(&name.as_str()) {
                walk(root, &path, out)?;
            }
        } else if ty.is_file() && name != FRICTION {
            out.push(name);
        }
    }
    Ok(())
}
