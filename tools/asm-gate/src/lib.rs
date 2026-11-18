//! `asm-gate`: the inlining gate on the hot wrappers of a Linux release build
//! (spec/11-build.md §4.4, S2 in §9.2).
//!
//! # Contract
//!
//! - **Writers:** humans write `ASM-GATE.toml` at the repository root (schema below). The
//!   compiler writes the binary; `llvm-objdump -d --no-show-raw-insn --symbolize-operands` turns
//!   it into the text this gate reads (§4.4 step 2), with or without `--symbolize-operands`.
//! - **Reader:** this gate. It reads only the config and the disassembly text, so a stranger can
//!   rerun it on a saved disassembly without the toolchain that built the binary.
//! - **Config, schema 1:** an optional `schema = 1`, then `[[symbol]]` tables with
//!   `name` (the exact `#[no_mangle]` name), `forbid_calls` (patterns where `*` matches any run of
//!   characters, compared with the whole target name), `forbid_indirect_calls` (default `false`)
//!   and `max_bytes` (optional). Unknown keys are an error: the file is a safety list.
//! - **Body:** the instructions between a `<name>:` header and the next header or the end of its
//!   section. Its size is the next header's address minus its own. For the last symbol of a
//!   section it is the last instruction's address minus its own, plus one (a lower bound).
//! - **Calls:** every instruction whose mnemonic is a branch — x86-64 `call*`, `j*`; aarch64 `b`,
//!   `b.<cond>`, `bl`, `cbz`, `cbnz`, `tbz`, `tbnz` — and whose operand names a symbol `<target>`.
//!   `+0x..` offsets and `@plt` are dropped. A target that is the symbol itself or a local label
//!   (`L<digits>`) is not a call. Tail jumps count as calls, because a jump to `panic_bounds_check`
//!   is a bounds check that was not removed.
//! - **Indirect calls:** x86-64 `call*` whose operand starts with `*`; aarch64 `blr`, `blraa`,
//!   `blraaz`, `blrab`, `blrabz`. Indirect jumps (`jmp *`, `br`) are jump tables, not calls, and
//!   are not checked (§4.4 step 3 names only `call *` and `blr`).
//! - **Ordering:** violations are sorted by config line, then rule, then message. Each names the
//!   config line of the symbol's `name`, so the reviewer lands on the rule that failed.
//!
//! ```text
//! asm-gate [--root DIR] [--config FILE] (--disasm FILE | --binary FILE) [--bodies DIR]
//! ```
//!
//! `--binary` runs `$LLVM_OBJDUMP` (default `llvm-objdump`) itself. `--bodies DIR` writes each
//! listed symbol's body to `DIR/<name>.s` for the `unsafe` reviewer (§4.4 step 5). Output is one
//! `path:line: rule: message` line per violation on stdout and a summary on stderr. Exit status:
//! 0 clean, 1 violations, 2 the tool could not run. The rule ids are the stable output:
//!
//! | rule | meaning |
//! |---|---|
//! | `symbol-missing` | a listed symbol is not in the disassembly (renamed, inlined away or not built) |
//! | `forbidden-call` | the body calls or tail-jumps to a target that matches `forbid_calls` |
//! | `indirect-call` | the body has an indirect call and `forbid_indirect_calls` is set |
//! | `over-size` | the body is larger than `max_bytes` (something unexpected was inlined) |
//!
//! Conformance vectors: `tools/asm-gate/fixtures/*/` (a `tree/` with `ASM-GATE.toml`, a saved
//! `disasm.txt`, `args.txt`, and `expected.txt`), for x86-64 and aarch64.
#![forbid(unsafe_code)]

use serde::Deserialize;

/// `ASM-GATE.toml` (§4.4).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: Option<u32>,
    #[serde(default)]
    pub symbol: Vec<Symbol>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Symbol {
    pub name: String,
    #[serde(default)]
    pub forbid_calls: Vec<String>,
    #[serde(default)]
    pub forbid_indirect_calls: bool,
    pub max_bytes: Option<u64>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let cfg: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        if cfg.schema.is_some_and(|s| s != 1) {
            return Err("unsupported schema (only 1)".into());
        }
        Ok(cfg)
    }
}

/// One instruction: address, mnemonic, operands (trimmed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insn {
    pub addr: u64,
    pub mnemonic: String,
    pub operands: String,
}

/// One function body from the disassembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub insns: Vec<Insn>,
    /// The body's lines as printed, for `--bodies`.
    pub text: String,
}

fn header(line: &str) -> Option<(u64, &str)> {
    let (addr, rest) = line.split_once(' ')?;
    let name = rest.strip_prefix('<')?.strip_suffix(">:")?;
    Some((u64::from_str_radix(addr, 16).ok()?, name))
}

fn insn(line: &str) -> Option<Insn> {
    let (addr, rest) = line.trim_start().split_once(':')?;
    let addr = u64::from_str_radix(addr, 16).ok()?;
    let rest = rest.trim();
    let (mnemonic, operands) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    Some(Insn {
        addr,
        mnemonic: mnemonic.to_owned(),
        operands: operands.trim().to_owned(),
    })
}

/// Splits `llvm-objdump -d` text into function bodies, in file order.
pub fn parse_disasm(text: &str) -> Vec<Body> {
    let mut out: Vec<Body> = Vec::new();
    let mut open = false;
    for line in text.lines() {
        if line.starts_with("Disassembly of section") {
            open = false;
            continue;
        }
        if let Some((start, name)) = header(line) {
            if open && let Some(prev) = out.last_mut() {
                prev.size = start.saturating_sub(prev.start);
            }
            out.push(Body {
                name: name.to_owned(),
                start,
                size: 0,
                insns: Vec::new(),
                text: format!("{line}\n"),
            });
            open = true;
            continue;
        }
        let Some(cur) = out.last_mut().filter(|_| open) else {
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        cur.text.push_str(line);
        cur.text.push('\n');
        if let Some(i) = insn(line) {
            cur.size = i.addr.saturating_sub(cur.start).saturating_add(1);
            cur.insns.push(i);
        }
    }
    out
}

/// `*` matches any run of characters; everything else matches itself.
pub fn glob(pattern: &str, s: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, rest) = parts.split_first().unwrap_or((&"", &[]));
    let Some(mut tail) = s.strip_prefix(first) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return tail.is_empty();
    };
    for p in middle {
        match tail.find(p) {
            Some(at) => tail = &tail[at + p.len()..],
            None => return false,
        }
    }
    tail.ends_with(last)
}

fn is_branch(m: &str) -> bool {
    m.starts_with("call")
        || m.starts_with('j')
        || m == "b"
        || m == "bl"
        || m.starts_with("b.")
        || matches!(m, "cbz" | "cbnz" | "tbz" | "tbnz")
}

fn is_indirect_call(i: &Insn) -> bool {
    (i.mnemonic.starts_with("call") && i.operands.starts_with('*'))
        || matches!(
            i.mnemonic.as_str(),
            "blr" | "blraa" | "blraaz" | "blrab" | "blrabz"
        )
}

/// The symbol a direct branch goes to, or `None` for local and self targets.
pub fn call_target<'a>(body: &str, i: &'a Insn) -> Option<&'a str> {
    if !is_branch(&i.mnemonic) || i.operands.starts_with('*') {
        return None;
    }
    let open = i.operands.rfind('<')?;
    let inner = i.operands[open + 1..].strip_suffix('>')?;
    let name = inner.split_once('+').map_or(inner, |(n, _)| n);
    let name = name.strip_suffix("@plt").unwrap_or(name);
    let local = name
        .strip_prefix('L')
        .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()));
    (!local && name != body).then_some(name)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// The 1-based config line of `name = "<sym>"`, or 1.
fn config_line(config_text: &str, sym: &str) -> usize {
    let quoted = format!("\"{sym}\"");
    config_text
        .lines()
        .position(|l| {
            let t = l.trim_start();
            t.starts_with("name") && t.contains(&quoted)
        })
        .map_or(1, |i| i + 1)
}

/// Checks every listed symbol against the bodies.
pub fn check(cfg: &Config, config_text: &str, bodies: &[Body]) -> Vec<Violation> {
    let mut out = Vec::new();
    for s in &cfg.symbol {
        let line = config_line(config_text, &s.name);
        let Some(b) = bodies.iter().find(|b| b.name == s.name) else {
            out.push(Violation {
                line,
                rule: "symbol-missing",
                message: format!("`{}` is not in the disassembly", s.name),
            });
            continue;
        };
        for i in &b.insns {
            if s.forbid_indirect_calls && is_indirect_call(i) {
                out.push(Violation {
                    line,
                    rule: "indirect-call",
                    message: format!("{} at {:#x}: {} {}", s.name, i.addr, i.mnemonic, i.operands),
                });
            }
            if let Some(t) = call_target(&s.name, i)
                && let Some(p) = s.forbid_calls.iter().find(|p| glob(p, t))
            {
                out.push(Violation {
                    line,
                    rule: "forbidden-call",
                    message: format!(
                        "{} at {:#x}: {} {t} matches `{p}`",
                        s.name, i.addr, i.mnemonic
                    ),
                });
            }
        }
        if let Some(max) = s.max_bytes
            && b.size > max
        {
            out.push(Violation {
                line,
                rule: "over-size",
                message: format!("{} is {} bytes, max_bytes {max}", s.name, b.size),
            });
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn glob_anchors_both_ends() {
        assert!(glob("ef_*", "ef_vi_transmit"));
        assert!(!glob("ef_*", "xef_vi"));
        assert!(glob(
            "*panic_bounds_check*",
            "_ZN4core9panicking18panic_bounds_check17h01E"
        ));
        assert!(glob("__rust_dealloc", "__rust_dealloc"));
        assert!(!glob("__rust_dealloc", "__rust_dealloc2"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("a*b*c", "aXcYb"));
        assert!(!glob("ab*ba", "aba"));
    }
}
