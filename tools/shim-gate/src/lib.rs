//! `shim-gate`: the size gate on the C shim (spec/11-build.md §4.5, 01 §9).
//!
//! # Contract
//!
//! - **Writer:** humans edit `c/vyrn-nic-shim/shim.c` and `shim.h`. Nothing generates them.
//! - **Reader:** this gate, on every PR (S1, §9.2). It reads the two files and nothing else.
//! - **Rule:** the non-blank, non-comment lines of `shim.c` plus `shim.h` must not exceed
//!   [`MAX_LINES`] (300). A line counts when any character on it lies outside a comment and is not
//!   whitespace. `//` and `/* .. */` comments are recognised; comment markers inside string and
//!   character literals are not comments. A line ending in `\` splices onto the next (C11
//!   translation phase 2), so a string literal or `//` comment continues there. Preprocessor
//!   lines count like any other code line.
//! - **Ordering:** `shim.h` is counted first, then `shim.c` (the header is what `vyrn-nic` binds).
//!   The violation names the file and line of the first code line past the limit, so a reviewer
//!   lands on the line that broke it.
//!
//! ```text
//! shim-gate [--root DIR] [--max N]    (defaults: `.` and 300)
//! ```
//!
//! Output is one `path:line: rule: message` line per violation on stdout and a summary on
//! stderr. Exit status: 0 clean, 1 violations, 2 the tool could not run (a file is missing or
//! is not UTF-8). The rule ids are the stable part of the output:
//!
//! | rule | meaning |
//! |---|---|
//! | `shim-too-large` | `shim.h` + `shim.c` have more than `--max` code lines |
//! | `unterminated-comment` | a `/*` comment that never closes (the count would be wrong) |
//!
//! The lower bound in the shim's header comment ("100–300 lines") is a design target, not a
//! gate: §4.5 only fails above 300.
//!
//! Conformance vectors: `tools/shim-gate/fixtures/*/` (`tree/` and `expected.txt`).
#![forbid(unsafe_code)]

/// 01 §9: the shim is at most 300 lines.
pub const MAX_LINES: usize = 300;

/// The files counted, in order, relative to the repository root.
pub const FILES: [&str; 2] = ["c/vyrn-nic-shim/shim.h", "c/vyrn-nic-shim/shim.c"];

#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// The 1-based line numbers of the code lines of one C file, or the line of an unterminated
/// `/*` as the error.
pub fn code_lines(src: &str) -> Result<Vec<usize>, usize> {
    #[derive(Clone, Copy, PartialEq)]
    enum St {
        Code,
        Block(usize),
        Str(char),
        Line,
    }
    let mut st = St::Code;
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let n = i + 1;
        let mut code = false;
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match st {
                St::Line => {}
                St::Block(_) => {
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        st = St::Code;
                    }
                }
                St::Str(q) => {
                    code = true;
                    if c == '\\' {
                        chars.next();
                    } else if c == q {
                        st = St::Code;
                    }
                }
                St::Code => match c {
                    '/' if chars.peek() == Some(&'/') => {
                        chars.next();
                        st = St::Line;
                    }
                    '/' if chars.peek() == Some(&'*') => {
                        chars.next();
                        st = St::Block(n);
                    }
                    '"' | '\'' => {
                        code = true;
                        st = St::Str(c);
                    }
                    c if c.is_whitespace() => {}
                    _ => code = true,
                },
            }
        }
        // Translation phase 2: a line that ends in `\\` splices onto the next, so a string literal
        // or a `//` comment continues there. Otherwise both end with the line.
        if matches!(st, St::Str(_) | St::Line) && !line.ends_with('\\') {
            st = St::Code;
        }
        if code {
            out.push(n);
        }
    }
    match st {
        St::Block(start) => Err(start),
        _ => Ok(out),
    }
}

/// Checks the files given as `(path, contents)` in order against `max`.
pub fn check(files: &[(&str, &str)], max: usize) -> (usize, Vec<Violation>) {
    let mut total = 0;
    let mut out = Vec::new();
    let mut first_over = None;
    for (path, src) in files {
        match code_lines(src) {
            Ok(lines) => {
                for l in lines {
                    total += 1;
                    if total == max + 1 {
                        first_over = Some((path.to_string(), l));
                    }
                }
            }
            Err(line) => out.push(Violation {
                file: path.to_string(),
                line,
                rule: "unterminated-comment",
                message: "`/*` never closes".into(),
            }),
        }
    }
    if let Some((file, line)) = first_over {
        out.push(Violation {
            file,
            line,
            rule: "shim-too-large",
            message: format!("{total} code lines in shim.h + shim.c, limit {max} (01 §9)"),
        });
    }
    (total, out)
}
