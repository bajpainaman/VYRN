//! The source checks on engine crates: floats (§3.3), async and threads (§2.3), logging and
//! environment (§8.3, §3.3), random numbers (§2.2) and clock reads (§3.1). They run on tokens from
//! `proc-macro2`, so comments and string literals never match, and macro bodies always do.

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};

use crate::Violation;
use crate::rules::Rules;

struct Cx<'a> {
    file: &'a str,
    rules: &'a Rules,
    clock_allowed: bool,
    out: Vec<Violation>,
}

impl Cx<'_> {
    fn hit(&mut self, line: usize, rule: &'static str, message: String) {
        self.out.push(Violation {
            file: self.file.to_owned(),
            line,
            rule,
            message,
        });
    }
}

/// Checks one source file of an engine crate; `file` is relative to the workspace root.
pub fn check_file(file: &str, src: &str, rules: &Rules) -> Vec<Violation> {
    let tokens = match src.parse::<TokenStream>() {
        Ok(t) => t.into_iter().collect::<Vec<_>>(),
        Err(e) => {
            return vec![Violation {
                file: file.to_owned(),
                line: 1,
                rule: "lex-error",
                message: format!("cannot lex this file: {e}"),
            }];
        }
    };
    let clock_allowed = rules
        .deadline_clock
        .allowed_in
        .iter()
        .any(|p| file == p || (p.ends_with('/') && file.starts_with(p.as_str())));
    let mut cx = Cx {
        file,
        rules,
        clock_allowed,
        out: Vec::new(),
    };
    walk(&tokens, &mut cx);
    cx.out
}

fn walk(toks: &[TokenTree], cx: &mut Cx) {
    for (i, tt) in toks.iter().enumerate() {
        let line = tt.span().start().line;
        match tt {
            TokenTree::Group(g) => walk(&g.stream().into_iter().collect::<Vec<_>>(), cx),
            TokenTree::Literal(lit) => {
                // `t.0.1` lexes `0.1` as one literal; a literal after a single `.` is a tuple index, but
                // after the `..` of a range (`..1.5`, `0..2.5`) it is a bound.
                if is_float_literal(&lit.to_string()) && !is_tuple_index(toks, i) {
                    cx.hit(
                        line,
                        "float-literal",
                        format!("float literal `{lit}` (11 §3.3)"),
                    );
                }
            }
            TokenTree::Ident(id) => ident(toks, i, &id.to_string(), line, cx),
            TokenTree::Punct(_) => {}
        }
    }
}

fn ident(toks: &[TokenTree], i: usize, written: &str, line: usize, cx: &mut Cx) {
    // `r#std` and `std` name the same item, so rules match the name without `r#`. A raw `r#async`
    // is a plain identifier and not the keyword, so it is not an async finding.
    let raw = written.starts_with("r#");
    let name = written.strip_prefix("r#").unwrap_or(written);
    match name {
        "f32" | "f64" => cx.hit(
            line,
            "float-type",
            format!("`{name}` in an engine crate (11 §3.3)"),
        ),
        "async" | "await" if !raw => {
            cx.hit(
                line,
                "async",
                format!("`{name}`: no async on pinned cores (11 §2.3)"),
            );
        }
        "now" if !cx.clock_allowed && is_clock_call(toks, i) => cx.hit(
            line,
            "deadline-clock",
            "clock read outside `vyrn-lane::admit` and `vyrn-bbo::admit` (11 §3.1)".to_owned(),
        ),
        _ => {}
    }
    if !starts_path(toks, i) {
        return;
    }
    let is_banned_crate = cx.rules.source.banned_crates.iter().any(|c| c == name);
    let introduced = is_sep(toks, i + 1)
        || matches!(i.checked_sub(1).and_then(|k| toks.get(k)),
            Some(TokenTree::Ident(p)) if p == "use" || p == "crate");
    if is_banned_crate && introduced {
        cx.hit(
            line,
            "banned-crate",
            format!("`{name}` is banned in engine crates (11 §2.2, §2.3, §8.3)"),
        );
    }
    if cx
        .rules
        .source
        .banned_paths
        .iter()
        .any(|b| b.first().is_some_and(|f| f == name))
    {
        let banned = cx.rules.source.banned_paths.clone();
        if let Some(path) = banned_path(
            &[name.to_owned()],
            toks.get(i + 1..).unwrap_or(&[]),
            &banned,
        ) {
            cx.hit(
                line,
                "banned-path",
                format!("`{path}` is banned in engine crates (11 §2.3, §3.3)"),
            );
        }
    }
}

/// Follows `a::b::{c, d::e}` after `prefix`, which is already consumed, and returns the first path
/// that starts with a banned path.
fn banned_path(prefix: &[String], rest: &[TokenTree], banned: &[Vec<String>]) -> Option<String> {
    if banned.iter().any(|b| prefix.starts_with(b)) {
        return Some(prefix.join("::"));
    }
    if !is_sep(rest, 0) {
        return None;
    }
    match rest.get(2) {
        Some(TokenTree::Ident(id)) => {
            let mut next = prefix.to_vec();
            next.push(id.to_string().trim_start_matches("r#").to_owned());
            banned_path(&next, rest.get(3..).unwrap_or(&[]), banned)
        }
        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            inner.split(|t| is_punct(Some(t), ',')).find_map(|chunk| {
                let Some(TokenTree::Ident(id)) = chunk.first() else {
                    return None;
                };
                let mut next = prefix.to_vec();
                next.push(id.to_string().trim_start_matches("r#").to_owned());
                banned_path(&next, chunk.get(1..).unwrap_or(&[]), banned)
            })
        }
        _ => None,
    }
}

/// `now` called as a method or an associated function: `.now()` or `::now()`.
fn is_clock_call(toks: &[TokenTree], i: usize) -> bool {
    let called = matches!(toks.get(i + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis);
    let qualified = is_punct(i.checked_sub(1).and_then(|k| toks.get(k)), '.')
        || i.checked_sub(2).is_some_and(|k| is_sep(toks, k));
    called && qualified
}

/// A literal at `toks[i]` that follows a single `.`, not the second dot of `..`.
fn is_tuple_index(toks: &[TokenTree], i: usize) -> bool {
    is_punct(i.checked_sub(1).and_then(|k| toks.get(k)), '.')
        && !is_punct(i.checked_sub(2).and_then(|k| toks.get(k)), '.')
}

/// Keywords that can precede a path (`use ::std::env`) without being one of its segments.
const KEYWORDS: [&str; 22] = [
    "use", "as", "in", "return", "break", "else", "match", "if", "while", "let", "mut", "ref",
    "move", "pub", "for", "where", "dyn", "impl", "fn", "const", "static", "type",
];

/// True when the identifier at `i` begins a path: it is not a field or method (`x.std`) and not a
/// later segment (`a::std`). A leading `::std` does begin one.
fn starts_path(toks: &[TokenTree], i: usize) -> bool {
    if is_punct(i.checked_sub(1).and_then(|k| toks.get(k)), '.') {
        return false;
    }
    match i.checked_sub(2) {
        Some(k) if is_sep(toks, k) => {
            !matches!(
                k.checked_sub(1).and_then(|j| toks.get(j)),
                Some(TokenTree::Ident(p)) if !KEYWORDS.contains(&p.to_string().as_str())
            ) && !is_punct(k.checked_sub(1).and_then(|j| toks.get(j)), '>')
        }
        _ => true,
    }
}

/// `::` at `toks[k]`, `toks[k + 1]`.
fn is_sep(toks: &[TokenTree], k: usize) -> bool {
    matches!((toks.get(k), toks.get(k + 1)),
        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
            if a.as_char() == ':' && a.spacing() == Spacing::Joint && b.as_char() == ':')
}

fn is_punct(t: Option<&TokenTree>, c: char) -> bool {
    matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == c)
}

/// `1.0`, `1e3`, `2f32`, `1.`; not `0x1e3`, `1usize` or `1_000`.
fn is_float_literal(s: &str) -> bool {
    if !s.starts_with(|c: char| c.is_ascii_digit())
        || ["0x", "0b", "0o"].iter().any(|p| s.starts_with(p))
    {
        return false;
    }
    const INT_SUFFIXES: [&str; 12] = [
        "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
    ];
    let body = INT_SUFFIXES
        .iter()
        .find_map(|x| s.strip_suffix(x))
        .unwrap_or(s);
    body.contains(['.', 'e', 'E']) || body.ends_with("f32") || body.ends_with("f64")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules::parse(crate::rules::DEFAULT).unwrap()
    }

    fn hits(src: &str) -> Vec<(usize, &'static str)> {
        check_file("crates/engine/vyrn-x/src/lib.rs", src, &rules())
            .iter()
            .map(|v| (v.line, v.rule))
            .collect()
    }

    #[test]
    fn float_literals_are_told_from_integers_and_tuple_indexes() {
        for yes in ["1.0", "1e3", "2f32", "1.", "0.5_f64", "1E-3"] {
            assert!(is_float_literal(yes), "{yes}");
        }
        for no in [
            "0x1e3", "1usize", "1_000", "0b1", "7", "1u8", "\"1.0\"", "'e'",
        ] {
            assert!(!is_float_literal(no), "{no}");
        }
        assert_eq!(hits("fn f(t: ((u8, u8), u8)) -> u8 { t.0.1 }"), []);
        assert_eq!(
            hits("fn f() { let _ = ..1.5; let _ = 0..2.5; let _ = 0..2; }"),
            [(1, "float-literal"), (1, "float-literal")]
        );
        assert_eq!(
            hits("const X: u32 = 1;\nconst Y: f32 = 1.5;"),
            [(2, "float-type"), (2, "float-literal")]
        );
    }

    #[test]
    fn banned_paths_are_found_in_use_groups_and_calls() {
        assert_eq!(hits("use std::thread;"), [(1, "banned-path")]);
        assert_eq!(
            hits("use std::{io, thread::{self, spawn}};"),
            [(1, "banned-path")]
        );
        assert_eq!(
            hits("fn f() { std::env::var(\"X\"); }"),
            [(1, "banned-path")]
        );
        assert_eq!(hits("use ::std::env;"), [(1, "banned-path")]);
        assert_eq!(
            hits("use r#std::r#env; fn f(_: r#f64) {}"),
            [(1, "banned-path"), (1, "float-type")]
        );
        assert_eq!(hits("fn r#async() { r#async(); }"), []);
        assert_eq!(
            hits("fn f() { ::std::thread::spawn(g); }"),
            [(1, "banned-path")]
        );
        assert_eq!(
            hits("use std::io;\nfn f() { crate::thread::x(); a::std::env::b(); }"),
            []
        );
    }

    #[test]
    fn banned_crates_need_a_path_position() {
        assert_eq!(hits("use rand::Rng;"), [(1, "banned-crate")]);
        assert_eq!(
            hits("fn f() { tracing::info!(\"x\"); }"),
            [(1, "banned-crate")]
        );
        assert_eq!(hits("extern crate tokio;"), [(1, "banned-crate")]);
        assert_eq!(hits("fn f(log: u8, rand: u8) -> u8 { log + rand }"), []);
        assert_eq!(hits("fn f() { crate::log::x(); self::rand::y(); }"), []);
    }

    #[test]
    fn clock_reads_are_flagged_unless_in_admit() {
        let src = "fn f(c: &C) { c.now(); C::now(c); let now = 1; }";
        assert_eq!(hits(src), [(1, "deadline-clock"), (1, "deadline-clock")]);
        let allowed = check_file("crates/engine/vyrn-lane/src/admit.rs", src, &rules());
        assert!(allowed.is_empty());
        let dir = check_file("crates/engine/vyrn-bbo/src/admit/clock.rs", src, &rules());
        assert!(dir.is_empty());
    }
}
