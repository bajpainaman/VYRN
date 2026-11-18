//! `asm-gate` command line; the contract is in `lib.rs`.
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use asm_gate::Config;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("asm-gate: {message}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str =
    "usage: asm-gate [--root DIR] [--config FILE] (--disasm FILE | --binary FILE) [--bodies DIR]";

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut config = None;
    let mut disasm = None;
    let mut binary = None;
    let mut bodies_dir = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut val = |what: &str| args.next().ok_or(format!("{arg} needs {what}"));
        match arg.as_str() {
            "--root" => root = PathBuf::from(val("a directory")?),
            "--config" => config = Some(PathBuf::from(val("a file")?)),
            "--disasm" => disasm = Some(PathBuf::from(val("a file")?)),
            "--binary" => binary = Some(PathBuf::from(val("a file")?)),
            "--bodies" => bodies_dir = Some(PathBuf::from(val("a directory")?)),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let config = config.unwrap_or_else(|| root.join("ASM-GATE.toml"));
    let config_text = fs::read_to_string(&config)
        .map_err(|e| format!("cannot read {}: {e}", config.display()))?;
    let cfg = Config::parse(&config_text).map_err(|e| format!("{}: {e}", config.display()))?;
    let text = match (disasm, binary) {
        (Some(d), None) => {
            fs::read_to_string(&d).map_err(|e| format!("cannot read {}: {e}", d.display()))?
        }
        (None, Some(b)) => {
            let tool = std::env::var("LLVM_OBJDUMP").unwrap_or_else(|_| "llvm-objdump".into());
            let out = Command::new(&tool)
                .args(["-d", "--no-show-raw-insn", "--symbolize-operands"])
                .arg(&b)
                .output()
                .map_err(|e| format!("cannot run {tool}: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "{tool} failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ));
            }
            String::from_utf8(out.stdout).map_err(|e| format!("{tool} output: {e}"))?
        }
        _ => {
            return Err(format!(
                "give exactly one of --disasm and --binary\n{USAGE}"
            ));
        }
    };
    let bodies = asm_gate::parse_disasm(&text);
    if let Some(dir) = bodies_dir {
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        for s in &cfg.symbol {
            if let Some(b) = bodies.iter().find(|b| b.name == s.name) {
                let p = dir.join(format!("{}.s", s.name));
                fs::write(&p, &b.text).map_err(|e| format!("cannot write {}: {e}", p.display()))?;
            }
        }
    }
    let violations = asm_gate::check(&cfg, &config_text, &bodies);
    let shown = config
        .strip_prefix(&root)
        .unwrap_or(&config)
        .to_string_lossy()
        .into_owned();
    for v in &violations {
        println!("{shown}:{}: {}: {}", v.line, v.rule, v.message);
    }
    eprintln!(
        "asm-gate: {} symbol(s) listed, {} function(s) disassembled, {} violation(s)",
        cfg.symbol.len(),
        bodies.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}
