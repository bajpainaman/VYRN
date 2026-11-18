//! `trace-dump` command line; the contract is in `lib.rs`.
#![forbid(unsafe_code)]

use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("trace-dump: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut clock = Vec::new();
    let mut rings = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--clock" => {
                let f = args.next().ok_or("--clock needs a file")?;
                let text = fs::read_to_string(&f).map_err(|e| format!("cannot read {f}: {e}"))?;
                clock = trace_dump::parse_clock(&text).map_err(|e| format!("{f}: {e}"))?;
            }
            "-h" | "--help" => {
                println!("usage: trace-dump [--clock FILE] RING...");
                return Ok(());
            }
            f => {
                let bytes = fs::read(f).map_err(|e| format!("cannot read {f}: {e}"))?;
                rings.push(trace_dump::decode(&bytes).map_err(|e| format!("{f}: {e}"))?);
            }
        }
    }
    if rings.is_empty() {
        return Err("no ring files given (usage: trace-dump [--clock FILE] RING...)".into());
    }
    for line in trace_dump::dump(&rings, &clock) {
        println!("{line}");
    }
    Ok(())
}
