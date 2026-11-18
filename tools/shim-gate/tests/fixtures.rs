//! Conformance vectors for `shim-gate`. Each directory under `fixtures/` holds a repository `tree/`
//! and the `expected.txt` a conforming implementation prints for it, as `path:line: rule`
//! (messages are free text). In `tree/`, a file named `x.fixture` stands for `x`: the suffix keeps
//! the repository's own gate runs, cargo and rustfmt from seeing the fixture's files. A fixture
//! with an `args.txt` passes its lines as extra arguments, with `@CASE` replaced by the fixture's
//! directory. Exit status is 0 when `expected.txt` is empty and 1 otherwise.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = dst.join(name.strip_suffix(".fixture").unwrap_or(&name));
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// `path:line: rule: message` → `path:line: rule`.
fn key(line: &str) -> String {
    line.splitn(3, ": ").take(2).collect::<Vec<_>>().join(": ")
}

#[test]
fn every_fixture_prints_exactly_its_expected_violations() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut cases: Vec<PathBuf> = fs::read_dir(&fixtures)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    assert!(cases.len() >= 4, "fixtures went missing");
    let mut failures = Vec::new();
    for case in cases {
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        let work = std::env::temp_dir().join(format!("shim-gate-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        copy_tree(&case.join("tree"), &work);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shim-gate"));
        cmd.arg("--root").arg(&work);
        if let Ok(args) = fs::read_to_string(case.join("args.txt")) {
            let dir = case.to_string_lossy().into_owned();
            cmd.args(args.lines().map(|a| a.replace("@CASE", &dir)));
        }
        let out = cmd.output().unwrap();
        fs::remove_dir_all(&work).unwrap();
        let want: Vec<String> = fs::read_to_string(case.join("expected.txt"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let got: Vec<String> = stdout.lines().map(key).collect();
        let code = out.status.code();
        let want_code = Some(i32::from(!want.is_empty()));
        if got != want || code != want_code {
            failures.push(format!(
                "{name}: exit {code:?} (want {want_code:?})\n  got:  {got:?}\n  want: {want:?}\n  stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
