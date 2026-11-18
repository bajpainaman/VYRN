//! Runs `tests/golden/sim_checks.txt` (format in that file) through `vyrn_sim::check`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vyrn_sim::check::{Obs, check_all};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/sim_checks.txt"
);

#[test]
fn checker_vectors_hold() {
    let text = std::fs::read_to_string(PATH).unwrap();
    let (mut name, mut obs, mut cases) = (String::new(), Vec::new(), 0);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(n) = line.strip_prefix("case ") {
            name = n.to_owned();
            obs.clear();
        } else if let Some(e) = line.strip_prefix("expect ") {
            let got =
                check_all(&obs).map_or("ok".to_owned(), |v| format!("{} {}", v.check, v.index));
            assert_eq!(got, e, "case {name}");
            cases += 1;
        } else {
            obs.push(Obs::parse(line).unwrap_or_else(|e| panic!("case {name}: {line}: {e}")));
        }
    }
    assert!(cases >= 18, "only {cases} cases");
}
