//! Runs every scenario in tests/golden/scenarios/ against `libvyrn_vx_oracle` (11 §5.2).
//!
//! The library comes from `vx/build.sh`, which needs vxc. Without it this test says so and
//! passes, unless `VYRN_REQUIRE_VX_ORACLE=1`, which makes a missing library a failure.

use std::path::{Path, PathBuf};
use vyrn_sim::scenario;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn golden_responses_parse() {
    let out = std::fs::read_to_string(root().join("tests/golden/vyrn_proto_vectors.out")).unwrap();
    let v = scenario::golden_responses(&out);
    assert_eq!(v["V4"].len(), 4);
    assert_eq!(v["V15"].len(), 3);
    assert_eq!(v["V6"][2][0], 0x85);
}

#[test]
fn scenarios_against_the_vx_oracle() {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let lib = std::env::var_os("VYRN_VX_ORACLE_LIB").map_or_else(
        || root().join(format!("target/vx/libvyrn_vx_oracle.{ext}")),
        PathBuf::from,
    );
    if !lib.exists() {
        assert!(
            std::env::var_os("VYRN_REQUIRE_VX_ORACLE").is_none(),
            "{} is missing",
            lib.display()
        );
        eprintln!("skipped: {} is missing; run vx/build.sh", lib.display());
        return;
    }
    let out = std::fs::read_to_string(root().join("tests/golden/vyrn_proto_vectors.out")).unwrap();
    let vectors = scenario::golden_responses(&out);
    let dir = root().join("tests/golden/scenarios");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "scn"))
        .collect();
    files.sort();
    assert!(!files.is_empty());
    let mut failed = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        match scenario::run(&lib, &text, &vectors) {
            Ok(n) => eprintln!("ok {} ({n} events)", f.display()),
            Err(e) => failed.push(format!("{}: {e}", f.display())),
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n\n"));
}
