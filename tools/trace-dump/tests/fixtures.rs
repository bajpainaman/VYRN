//! Conformance vectors for `trace-dump`. Each directory under `fixtures/` holds ring files, an
//! optional clock file, `args.txt` (one argument per line, `@CASE` replaced by the fixture's
//! directory), `expected.txt` (the exact stdout) and `exit.txt` (the exit status). An independent
//! decoder, `fixtures-src/make.py`, wrote them from the contract in `lib.rs`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn every_fixture_prints_exactly_its_expected_dump() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut cases: Vec<PathBuf> = fs::read_dir(&fixtures)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    cases.sort();
    assert!(cases.len() >= 5, "fixtures went missing");
    let mut failures = Vec::new();
    for case in cases {
        let name = case.file_name().unwrap().to_string_lossy().into_owned();
        let dir = case.to_string_lossy().into_owned();
        let args = fs::read_to_string(case.join("args.txt")).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_trace-dump"))
            .args(args.lines().map(|a| a.replace("@CASE", &dir)))
            .output()
            .unwrap();
        let want = fs::read_to_string(case.join("expected.txt")).unwrap();
        let want_code: i32 = fs::read_to_string(case.join("exit.txt"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let got = String::from_utf8(out.stdout).unwrap();
        if got != want || out.status.code() != Some(want_code) {
            failures.push(format!(
                "{name}: exit {:?} (want {want_code})\n  got:\n{got}  want:\n{want}  stderr: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
