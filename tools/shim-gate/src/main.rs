//! `shim-gate` command line; the contract is in `lib.rs`.
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("shim-gate: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut max = shim_gate::MAX_LINES;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(args.next().ok_or("--root needs a directory")?),
            "--max" => {
                max = args
                    .next()
                    .ok_or("--max needs a number")?
                    .parse()
                    .map_err(|e| format!("--max: {e}"))?
            }
            "-h" | "--help" => {
                println!("usage: shim-gate [--root DIR] [--max N]");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let mut texts = Vec::new();
    for f in shim_gate::FILES {
        let p = root.join(f);
        texts.push(fs::read_to_string(&p).map_err(|e| format!("cannot read {f}: {e}"))?);
    }
    let files: Vec<(&str, &str)> = shim_gate::FILES
        .iter()
        .copied()
        .zip(texts.iter().map(String::as_str))
        .collect();
    let (total, violations) = shim_gate::check(&files, max);
    for v in &violations {
        println!("{}:{}: {}: {}", v.file, v.line, v.rule, v.message);
    }
    eprintln!(
        "shim-gate: {total} code line(s), limit {max}, {} violation(s)",
        violations.len()
    );
    Ok(violations.is_empty())
}
