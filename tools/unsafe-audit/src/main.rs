//! `unsafe-audit`: the CI gate for REQ-SEC-10 (spec/11-build.md §3.2).
//!
//! `unsafe` may appear only in the modules listed in `UNSAFE.toml`. The tool lexes every `.rs`
//! file under the root with `proc-macro2` (the lexer `syn` uses), so `unsafe` in comments,
//! strings and `unsafe_code` identifiers never counts, and `unsafe` inside macro bodies and
//! `cfg`-disabled code always does.
//!
//! ```text
//! unsafe-audit [--root DIR] [--config FILE]     (defaults: `.` and `<root>/UNSAFE.toml`)
//! ```
//!
//! Output is one `path:line: rule: message` line per violation on stdout, sorted by path and line,
//! and a summary on stderr. Exit status: 0 clean, 1 violations, 2 the tool could not run. The
//! rule ids are the stable part of the output:
//!
//! | rule | meaning |
//! |---|---|
//! | `unsafe-outside-allowlist` | an `unsafe` token in a file that `UNSAFE.toml` does not list |
//! | `over-budget` | a listed file has more physical lines than its `max_lines` |
//! | `missing-safety-comment` | an `unsafe` block or `unsafe impl` without `// SAFETY:` directly above |
//! | `pub-unsafe-fn` | a listed file exports an `unsafe fn`, an `unsafe trait`, or a foreign item not marked `safe` |
//! | `listed-file-missing` | an `UNSAFE.toml` entry names a file that does not exist |
//! | `config-mismatch` | an `UNSAFE.toml` entry whose `path` and `file` disagree |
//! | `lex-error` | a file that `proc-macro2` cannot lex |
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use serde::Deserialize;

/// Directories that are never scanned: build output, vendored sources (§2.6) and VCS data.
const SKIP_DIRS: &[&str] = &[".git", "target", "vendor", ".amp", "fuzz/target"];

/// `UNSAFE.toml` (§3.2). Unknown keys are an error: this file is a security allowlist.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Optional format version; only 1 exists.
    schema: Option<u32>,
    #[serde(default)]
    module: Vec<Module>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Module {
    /// `crate::module`, as the spec names it.
    path: String,
    /// The module's file, relative to the repository root.
    file: String,
    /// Line budget (§3.2 table).
    max_lines: usize,
    /// Reviewer or team (the §1.2 tree comment says "with owners").
    #[allow(dead_code)]
    owner: Option<String>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    file: String,
    line: usize,
    rule: &'static str,
    message: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `unsafe { .. }`
    Block,
    /// `unsafe impl`
    Impl,
    /// `unsafe fn` or `unsafe trait`; `exported` when it has a visibility other than `pub(self)`.
    Item { exported: bool },
    /// `unsafe extern "C" { .. }`
    ExternBlock,
    /// An item inside an `unsafe extern` block that is `pub` and not marked `safe`.
    ExportedForeign,
    /// Any other use of the keyword, such as `#[unsafe(no_mangle)]`.
    Other,
}

struct Site {
    line: usize,
    kind: Kind,
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(message) => {
            eprintln!("unsafe-audit: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let mut root = PathBuf::from(".");
    let mut config = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = PathBuf::from(args.next().ok_or("--root needs a directory")?),
            "--config" => config = Some(PathBuf::from(args.next().ok_or("--config needs a file")?)),
            "-h" | "--help" => {
                println!("usage: unsafe-audit [--root DIR] [--config FILE]");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let config = config.unwrap_or_else(|| root.join("UNSAFE.toml"));
    let text = fs::read_to_string(&config)
        .map_err(|e| format!("cannot read {}: {e}", config.display()))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", config.display()))?;
    if cfg.schema.is_some_and(|s| s != 1) {
        return Err(format!("{}: unsupported schema (only 1)", config.display()));
    }
    let config_name = display_rel(&root, &config);
    let violations = audit(&root, &cfg, &config_name)?;
    for v in &violations {
        println!("{}:{}: {}: {}", v.file, v.line, v.rule, v.message);
    }
    eprintln!(
        "unsafe-audit: {} module(s) listed, {} violation(s)",
        cfg.module.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}

fn audit(root: &Path, cfg: &Config, config_name: &str) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let mut listed: Vec<&Module> = Vec::new();
    let mut seen = BTreeSet::new();
    for m in &cfg.module {
        let mut bad = |message: String| {
            out.push(Violation {
                file: config_name.to_owned(),
                line: 1,
                rule: "config-mismatch",
                message,
            });
        };
        let normal = !m.file.starts_with('/')
            && !m.file.contains('\\')
            && m.file
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..");
        if !normal {
            bad(format!(
                "`{}`: file must be a normalised path relative to the root",
                m.file
            ));
        } else if !seen.insert(m.file.as_str()) {
            bad(format!("`{}` is listed twice", m.file));
        } else if !path_matches_file(&m.path, &m.file) {
            bad(format!(
                "path `{}` does not match file `{}`",
                m.path, m.file
            ));
        } else {
            listed.push(m);
        }
    }

    let mut files = Vec::new();
    walk(root, root, &mut files).map_err(|e| format!("cannot scan {}: {e}", root.display()))?;
    files.sort();

    for m in &listed {
        if !files.contains(&m.file) {
            out.push(Violation {
                file: config_name.to_owned(),
                line: 1,
                rule: "listed-file-missing",
                message: format!("`{}` lists `{}`, which does not exist", m.path, m.file),
            });
        }
    }

    for rel in &files {
        let src =
            fs::read_to_string(root.join(rel)).map_err(|e| format!("cannot read {rel}: {e}"))?;
        let tokens = match src.parse::<TokenStream>() {
            Ok(t) => t,
            Err(e) => {
                out.push(Violation {
                    file: rel.clone(),
                    line: 1,
                    rule: "lex-error",
                    message: format!("cannot lex this file: {e}"),
                });
                continue;
            }
        };
        let mut sites = Vec::new();
        scan(&tokens.into_iter().collect::<Vec<_>>(), false, &mut sites);
        let Some(module) = listed.iter().find(|m| &m.file == rel) else {
            for s in sites.iter().filter(|s| s.kind != Kind::ExportedForeign) {
                out.push(Violation {
                    file: rel.clone(),
                    line: s.line,
                    rule: "unsafe-outside-allowlist",
                    message: "`unsafe` outside the modules in UNSAFE.toml (11 §3.2, REQ-SEC-10)"
                        .to_owned(),
                });
            }
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        if lines.len() > module.max_lines {
            out.push(Violation {
                file: rel.clone(),
                line: module.max_lines + 1,
                rule: "over-budget",
                message: format!(
                    "`{}` has {} lines; its budget is {}",
                    module.path,
                    lines.len(),
                    module.max_lines
                ),
            });
        }
        for s in &sites {
            let (rule, message) = match s.kind {
                Kind::Block | Kind::Impl if !has_safety_comment(&lines, s.line) => (
                    "missing-safety-comment",
                    "`unsafe` needs a `// SAFETY:` comment directly above it".to_owned(),
                ),
                Kind::Item { exported: true } | Kind::ExportedForeign => (
                    "pub-unsafe-fn",
                    "an unsafe item must not leave its module: keep it private and export a safe wrapper"
                        .to_owned(),
                ),
                _ => continue,
            };
            out.push(Violation {
                file: rel.clone(),
                line: s.line,
                rule,
                message,
            });
        }
    }
    out.sort();
    Ok(out)
}

/// `vyrn-cut::ring` must name `…/vyrn-cut/src/ring.rs` or `…/vyrn-cut/src/ring/mod.rs`.
fn path_matches_file(path: &str, file: &str) -> bool {
    let mut parts = path.split("::");
    let (Some(krate), rest) = (parts.next(), parts.collect::<Vec<_>>()) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let module = rest.join("/");
    let tail = [
        format!("/{krate}/src/{module}.rs"),
        format!("/{krate}/src/{module}/mod.rs"),
    ];
    let file = format!("/{file}");
    tail.iter().any(|t| file.ends_with(t.as_str()))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = display_rel(root, &path);
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if !SKIP_DIRS.contains(&rel.as_str()) && entry.file_name() != "node_modules" {
                walk(root, &path, out)?;
            }
        } else if ty.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(rel);
        }
    }
    Ok(())
}

fn display_rel(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Finds every `unsafe` keyword in a token tree, including inside macro invocations and attributes.
/// `in_pub_trait` is true for the direct items of a `pub` trait body, where `unsafe fn` is exported
/// without a `pub` of its own.
fn scan(toks: &[TokenTree], in_pub_trait: bool, out: &mut Vec<Site>) {
    let mut pub_trait_body = None;
    for (i, tt) in toks.iter().enumerate() {
        match tt {
            TokenTree::Group(g) => {
                let inner = g.stream().into_iter().collect::<Vec<_>>();
                scan(&inner, pub_trait_body == Some(i), out);
            }
            TokenTree::Ident(id) if id == "unsafe" => classify(toks, i, in_pub_trait, out),
            TokenTree::Ident(id) if id == "trait" && is_exported(toks, i) => {
                pub_trait_body = toks
                    .iter()
                    .enumerate()
                    .skip(i + 1)
                    .find(|(_, t)| matches!(t, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace))
                    .map(|(k, _)| k);
            }
            _ => {}
        }
    }
}

fn classify(toks: &[TokenTree], i: usize, in_pub_trait: bool, out: &mut Vec<Site>) {
    let line = toks[i].span().start().line;
    let mut j = i + 1;
    let has_extern = matches!(toks.get(j), Some(TokenTree::Ident(id)) if id == "extern");
    if has_extern {
        j += 1;
        if matches!(toks.get(j), Some(TokenTree::Literal(_))) {
            j += 1;
        }
    }
    let kind = match toks.get(j) {
        Some(TokenTree::Ident(id)) if id == "fn" || id == "trait" => Kind::Item {
            exported: in_pub_trait || is_exported(toks, i),
        },
        Some(TokenTree::Ident(id)) if id == "impl" && !has_extern => Kind::Impl,
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
            if has_extern {
                foreign_items(&g.stream().into_iter().collect::<Vec<_>>(), out);
                Kind::ExternBlock
            } else {
                Kind::Block
            }
        }
        _ => Kind::Other,
    };
    out.push(Site { line, kind });
}

/// True when the item whose `unsafe` keyword is at `i` has a `pub` or `pub(..)` visibility other
/// than `pub(self)`. Looks back over `const`, `async` and `unsafe`, the qualifiers that can precede
/// `fn` or `trait`.
fn is_exported(toks: &[TokenTree], i: usize) -> bool {
    let mut k = i;
    while k > 0 {
        k -= 1;
        match &toks[k] {
            TokenTree::Ident(id) if id == "const" || id == "async" || id == "unsafe" => {}
            TokenTree::Ident(id) if id == "pub" => return true,
            TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis => {
                let after_pub =
                    k > 0 && matches!(&toks[k - 1], TokenTree::Ident(id) if id == "pub");
                return after_pub && g.stream().to_string() != "self";
            }
            _ => return false,
        }
    }
    false
}

/// Items in an `unsafe extern` block are unsafe to call unless marked `safe`, so a `pub` one is a
/// `pub unsafe fn` by another name. Items are separated by `;`; attributes come first.
fn foreign_items(toks: &[TokenTree], out: &mut Vec<Site>) {
    for item in toks.split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ';')) {
        let mut k = 0;
        while matches!(item.get(k), Some(TokenTree::Punct(p)) if p.as_char() == '#') {
            k += 2; // `#` and its `[..]` group
        }
        let Some(TokenTree::Ident(first)) = item.get(k) else {
            continue;
        };
        if first != "pub" {
            continue;
        }
        let is_safe = item
            .iter()
            .any(|t| matches!(t, TokenTree::Ident(id) if id == "safe"));
        if !is_safe {
            out.push(Site {
                line: first.span().start().line,
                kind: Kind::ExportedForeign,
            });
        }
    }
}

/// True when the comment block directly above `line` (1-based), skipping attribute lines, has a
/// line starting `SAFETY:`. Blank lines end the block, as `clippy::undocumented_unsafe_blocks`
/// does.
fn has_safety_comment(lines: &[&str], line: usize) -> bool {
    let mut i = line.saturating_sub(1);
    while i > 0
        && lines
            .get(i - 1)
            .is_some_and(|l| l.trim_start().starts_with("#["))
    {
        i -= 1;
    }
    let mut found = false;
    while i > 0 {
        let t = lines.get(i - 1).map_or("", |l| l.trim());
        if !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.ends_with("*/"))
        {
            break;
        }
        found |= t
            .trim_start_matches(['/', '*', '!'])
            .trim_start()
            .starts_with("SAFETY:");
        i -= 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites(src: &str) -> Vec<(usize, &'static str)> {
        let mut out = Vec::new();
        let toks: Vec<_> = src.parse::<TokenStream>().unwrap().into_iter().collect();
        scan(&toks, false, &mut out);
        out.iter()
            .map(|s| {
                let k = match s.kind {
                    Kind::Block => "block",
                    Kind::Impl => "impl",
                    Kind::Item { exported: true } => "pub-item",
                    Kind::Item { exported: false } => "item",
                    Kind::ExternBlock => "extern",
                    Kind::ExportedForeign => "pub-foreign",
                    Kind::Other => "other",
                };
                (s.line, k)
            })
            .collect()
    }

    #[test]
    fn classifies_the_keyword_by_what_follows_and_precedes_it() {
        let src = "pub unsafe fn a() {}\nfn b() { unsafe { x() } }\nunsafe impl Send for T {}\n\
                   pub(crate) const unsafe fn c() {}\npub(self) unsafe fn d() {}\n\
                   #[unsafe(no_mangle)]\nfn e() {}\n\
                   unsafe extern \"C\" {\n    pub fn f();\n    pub safe fn g();\n    fn h();\n}\n";
        assert_eq!(
            sites(src),
            [
                (1, "pub-item"),
                (2, "block"),
                (3, "impl"),
                (4, "pub-item"),
                (5, "item"),
                (6, "other"),
                (9, "pub-foreign"),
                (8, "extern"),
            ]
        );
    }

    #[test]
    fn unsafe_methods_of_a_pub_trait_are_exported() {
        let src = "pub trait A { unsafe fn a(); fn d() { unsafe fn inner() {} } }\n\
                   trait B { unsafe fn b(); }\npub unsafe trait C { unsafe fn c(); }\n";
        assert_eq!(
            sites(src),
            [
                (1, "pub-item"),
                (1, "item"),
                (2, "item"),
                (3, "pub-item"),
                (3, "pub-item")
            ]
        );
    }

    #[test]
    fn comments_strings_and_lint_names_are_not_unsafe() {
        let src = "// unsafe\n/* unsafe { } */\nconst S: &str = \"unsafe { }\";\n\
                   const R: &str = r#\"unsafe\"#;\n#![forbid(unsafe_code)]\nfn r#unsafe() {}\n";
        assert!(sites(src).is_empty());
    }

    #[test]
    fn unsafe_in_macro_bodies_counts() {
        assert_eq!(
            sites("macro_rules! m { () => { unsafe { f() } }; }"),
            [(1, "block")]
        );
    }

    #[test]
    fn safety_comment_must_sit_directly_above() {
        let ok = [
            "// SAFETY: x",
            "// more",
            "#[inline]",
            "unsafe impl Send for T {}",
        ];
        assert!(has_safety_comment(&ok, 4));
        let blank = ["// SAFETY: x", "", "unsafe impl Send for T {}"];
        assert!(!has_safety_comment(&blank, 3));
        let other = ["// note", "unsafe impl Send for T {}"];
        assert!(!has_safety_comment(&other, 2));
    }

    #[test]
    fn path_must_name_its_file() {
        assert!(path_matches_file(
            "vyrn-cut::ring",
            "crates/engine/vyrn-cut/src/ring.rs"
        ));
        assert!(path_matches_file(
            "vyrn-cut::ring",
            "crates/engine/vyrn-cut/src/ring/mod.rs"
        ));
        assert!(!path_matches_file(
            "vyrn-cut::ring",
            "crates/engine/vyrn-lane/src/ring.rs"
        ));
        assert!(!path_matches_file(
            "vyrn-cut",
            "crates/engine/vyrn-cut/src/lib.rs"
        ));
    }
}
