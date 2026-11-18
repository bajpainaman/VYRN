//! `vx-friction`: the gate that keeps `vx/FRICTION.md` and the code's Vx workaround markers in
//! step (spec/11-build.md §5.6, §5.5).
//!
//! # Contract
//!
//! - **Writers:** humans. A Vx workaround site carries a marker comment, and `vx/FRICTION.md`
//!   carries one table row per workaround ID.
//! - **Reader:** this gate, on every PR (S1, §9.2).
//! - **Marker grammar:** the text `VX-WORKAROUND W-<digits>`, optionally followed by a space and a
//!   parenthesised note. The marker names an upstream issue when the note contains
//!   `vx-lang/Vx#<n>`; otherwise (`(issue to file)`) it names none. Any comment syntax works
//!   (`//`, `#`): the gate matches text, not comments. Files that are not UTF-8 are skipped.
//! - **Scanned files:** every file under the root except [`SKIP_DIRS`] (paths from the root;
//!   `spec` and `site` quote example markers), any directory named `.git`, `target` or
//!   `node_modules` at any depth, and the file `vx/FRICTION.md` itself.
//! - **Entry grammar:** the first Markdown table in `vx/FRICTION.md` whose header has the cells
//!   `ID`, `Files with the marker` and `Status`. One row per ID `W-nn`. The entry's issue is the
//!   first `vx-lang/Vx#<n>` or `github.com/vx-lang/Vx/issues/<n>` anywhere in the row, or none.
//!   Its files are the back-quoted tokens of the files cell that contain `/` or `.`. A status that
//!   starts with `landed` must carry the release date of the vxc release that contains the fix,
//!   as `YYYY-MM-DD`, in the same cell.
//! - **Ordering:** violations are sorted by path, then line, then rule.
//!
//! ```text
//! vx-friction [--root DIR] [--today YYYY-MM-DD]    (defaults: `.` and the system date, UTC)
//! ```
//!
//! Output is one `path:line: rule: message` line per violation on stdout and a summary on
//! stderr. Exit status: 0 clean, 1 violations, 2 the tool could not run. The rule ids are the
//! stable part of the output:
//!
//! | rule | meaning |
//! |---|---|
//! | `marker-without-entry` | a marker whose ID has no row in FRICTION.md |
//! | `issue-mismatch` | a marker's issue number differs from its entry's (or one has none) |
//! | `marker-file-unlisted` | a marker in a file that its entry's files cell does not list |
//! | `entry-file-without-marker` | an entry lists a file that has no marker with its ID |
//! | `landed-marker-stale` | a marker whose entry is `landed` more than [`LANDED_GRACE_DAYS`] days after the release date |
//! | `duplicate-entry` | two rows with one ID |
//! | `bad-entry` | a row whose ID is not `W-<digits>`, or a `landed` status without a date |
//!
//! Conformance vectors: `tools/vx-friction/fixtures/*/` (`tree/`, optional `args.txt`, and
//! `expected.txt`).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// §5.6: markers of a landed fix may stay this many days after the vxc release that has it.
pub const LANDED_GRACE_DAYS: i64 = 60;

/// The friction log, relative to the repository root.
pub const FRICTION: &str = "vx/FRICTION.md";

/// Directories (relative to the root) that are never scanned.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "vendor",
    ".amp",
    "node_modules",
    "spec",
    "site",
    "tools/vx-friction/fixtures",
];

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub file: String,
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// One marker found in a source file.
#[derive(Debug, PartialEq, Eq)]
pub struct Marker {
    pub file: String,
    pub line: usize,
    pub id: String,
    pub issue: Option<u64>,
}

/// One row of the friction table.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub id: String,
    pub issue: Option<u64>,
    pub files: Vec<String>,
    /// `Some(day number)` when the status is `landed` with a date.
    pub landed: Option<Option<i64>>,
}

/// Every marker in one file's text.
pub fn markers(file: &str, text: &str) -> Vec<Marker> {
    const TAG: &str = "VX-WORKAROUND W-";
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(at) = rest.find(TAG) {
            let after = &rest[at + TAG.len()..];
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            rest = &after[digits.len()..];
            if digits.is_empty() {
                continue;
            }
            let issue = rest
                .strip_prefix(" (")
                .and_then(|n| n.split(')').next())
                .and_then(|note| issue_after(note, "vx-lang/Vx#"));
            out.push(Marker {
                file: file.to_owned(),
                line: i + 1,
                id: format!("W-{digits}"),
                issue,
            });
        }
    }
    out
}

fn issue_after(text: &str, prefix: &str) -> Option<u64> {
    let at = text.find(prefix)?;
    let digits: String = text[at + prefix.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn row_issue(row: &str) -> Option<u64> {
    let a = row
        .find("vx-lang/Vx#")
        .map(|i| (i, issue_after(row, "vx-lang/Vx#")));
    let b = row
        .find("github.com/vx-lang/Vx/issues/")
        .map(|i| (i, issue_after(row, "github.com/vx-lang/Vx/issues/")));
    match (a, b) {
        (Some(x), Some(y)) => {
            if x.0 < y.0 {
                x.1
            } else {
                y.1
            }
        }
        (Some(x), None) | (None, Some(x)) => x.1,
        (None, None) => None,
    }
}

/// Splits a Markdown table row on unescaped `|`, without the outer empty cells.
fn cells(row: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = row.trim().chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'|') {
            cur.push('|');
            chars.next();
        } else if c == '|' {
            out.push(cur.trim().to_owned());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    out.push(cur.trim().to_owned());
    if out.first().is_some_and(String::is_empty) {
        out.remove(0);
    }
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date (proleptic Gregorian).
pub fn day_number(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn find_date(cell: &str) -> Option<i64> {
    let b = cell.as_bytes();
    (0..b.len().saturating_sub(9)).find_map(|i| {
        let s = cell.get(i..i + 10)?;
        let shape = s.bytes().enumerate().all(|(k, c)| {
            if k == 4 || k == 7 {
                c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
        if shape { day_number(s) } else { None }
    })
}

/// Parses the friction table. Row-level problems are returned as violations.
pub fn entries(text: &str) -> (Vec<Entry>, Vec<Violation>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    let mut cols: Option<(usize, usize, usize)> = None;
    let mut in_table = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            if in_table && cols.is_some() {
                break;
            }
            in_table = false;
            continue;
        }
        in_table = true;
        let c = cells(t);
        let Some((id_col, files_col, status_col)) = cols else {
            let find = |name: &str| c.iter().position(|x| x == name);
            if let (Some(a), Some(b), Some(s)) =
                (find("ID"), find("Files with the marker"), find("Status"))
            {
                cols = Some((a, b, s));
            }
            continue;
        };
        if c.iter()
            .all(|x| x.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
        {
            continue;
        }
        let get = |k: usize| c.get(k).map(String::as_str).unwrap_or("");
        let id = get(id_col).trim_matches('`').to_owned();
        let ok_id = id
            .strip_prefix("W-")
            .is_some_and(|d| !d.is_empty() && d.chars().all(|ch| ch.is_ascii_digit()));
        if !ok_id {
            bad.push(Violation {
                file: FRICTION.into(),
                line: i + 1,
                rule: "bad-entry",
                message: format!("ID `{id}` is not W-<digits>"),
            });
            continue;
        }
        let files = get(files_col)
            .split('`')
            .skip(1)
            .step_by(2)
            .filter(|f| f.contains('/') || f.contains('.'))
            .map(str::to_owned)
            .collect();
        let status = get(status_col);
        let landed = status
            .to_ascii_lowercase()
            .starts_with("landed")
            .then(|| find_date(status));
        if landed == Some(None) {
            bad.push(Violation {
                file: FRICTION.into(),
                line: i + 1,
                rule: "bad-entry",
                message: format!("{id}: `landed` needs the vxc release date as YYYY-MM-DD"),
            });
        }
        out.push(Entry {
            line: i + 1,
            id,
            issue: row_issue(t),
            files,
            landed,
        });
    }
    (out, bad)
}

fn show(issue: Option<u64>) -> String {
    issue.map_or_else(|| "none".into(), |n| format!("vx-lang/Vx#{n}"))
}

/// Checks markers against entries. `today` is a day number (see [`day_number`]).
pub fn check(markers: &[Marker], friction: &str, today: i64) -> Vec<Violation> {
    let (entries, mut out) = entries(friction);
    let mut by_id: BTreeMap<&str, &Entry> = BTreeMap::new();
    for e in &entries {
        if by_id.insert(&e.id, e).is_some() {
            out.push(Violation {
                file: FRICTION.into(),
                line: e.line,
                rule: "duplicate-entry",
                message: format!("{} has more than one row", e.id),
            });
        }
    }
    for m in markers {
        let v = |rule, message| Violation {
            file: m.file.clone(),
            line: m.line,
            rule,
            message,
        };
        let Some(e) = by_id.get(m.id.as_str()) else {
            out.push(v(
                "marker-without-entry",
                format!("{} has no row in {FRICTION}", m.id),
            ));
            continue;
        };
        if m.issue != e.issue {
            out.push(v(
                "issue-mismatch",
                format!(
                    "{}: marker names {}, entry names {}",
                    m.id,
                    show(m.issue),
                    show(e.issue)
                ),
            ));
        }
        if !e.files.iter().any(|f| f == &m.file) {
            out.push(v(
                "marker-file-unlisted",
                format!(
                    "{}: {FRICTION} line {} does not list {}",
                    m.id, e.line, m.file
                ),
            ));
        }
        if let Some(Some(day)) = e.landed
            && today - day > LANDED_GRACE_DAYS
        {
            out.push(v(
                "landed-marker-stale",
                format!(
                    "{}: landed {} days ago, markers may stay {LANDED_GRACE_DAYS}",
                    m.id,
                    today - day
                ),
            ));
        }
    }
    for e in &entries {
        for f in &e.files {
            if !markers.iter().any(|m| &m.file == f && m.id == e.id) {
                out.push(Violation {
                    file: FRICTION.into(),
                    line: e.line,
                    rule: "entry-file-without-marker",
                    message: format!("{}: {f} has no marker", e.id),
                });
            }
        }
    }
    out.sort();
    out
}
