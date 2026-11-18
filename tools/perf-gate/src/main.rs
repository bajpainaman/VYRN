//! `perf-gate` command line; the contract is in `lib.rs`.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use perf_gate::{Results, Runner};

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("perf-gate: {message}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str =
    "usage: perf-gate [--root DIR] --results FILE --baseline DIR [--accept-regression ID:STAT]...";

fn read(p: &Path) -> Result<String, String> {
    fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut results = None;
    let mut baseline = None;
    let mut accepted = BTreeSet::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut val = |what: &str| args.next().ok_or(format!("{arg} needs {what}"));
        match arg.as_str() {
            "--root" => root = PathBuf::from(val("a directory")?),
            "--results" => results = Some(val("a file")?),
            "--baseline" => baseline = Some(PathBuf::from(val("a directory")?)),
            "--accept-regression" => {
                accepted.insert(val("ID:STAT")?);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let shown = results.ok_or(format!("--results is required\n{USAGE}"))?;
    let baseline = root.join(baseline.ok_or(format!("--baseline is required\n{USAGE}"))?);
    let text = read(&root.join(&shown))?;
    let res = Results::parse(&text).map_err(|e| format!("{shown}: {e}"))?;
    let runner_path = baseline.join("runner.toml");
    let runner = Runner::parse(&read(&runner_path)?)
        .map_err(|e| format!("{}: {e}", runner_path.display()))?;
    let main_dir = baseline.join("main");
    let mut files: Vec<PathBuf> = match fs::read_dir(&main_dir) {
        Ok(rd) => rd
            .map(|e| e.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("cannot list {}: {e}", main_dir.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("cannot list {}: {e}", main_dir.display())),
    };
    files.retain(|p| p.extension().is_some_and(|x| x == "toml"));
    files.sort();
    let mut history = Vec::new();
    for f in &files {
        history.push(Results::parse(&read(f)?).map_err(|e| format!("{}: {e}", f.display()))?);
    }
    let (violations, notes) = perf_gate::check(&text, &res, &runner, &history, &accepted);
    for n in &notes {
        eprintln!("perf-gate: note: {n}");
    }
    for v in &violations {
        println!("{shown}:{}: {}: {}", v.line, v.rule, v.message);
    }
    eprintln!(
        "perf-gate: {} metric(s), {} baseline run(s), {} violation(s)",
        res.metric.len(),
        history.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}
