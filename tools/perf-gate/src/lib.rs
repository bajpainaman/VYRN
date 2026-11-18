//! `perf-gate`: the regression rule of the performance gate (spec/11-build.md §9.3, S3).
//!
//! # Contract
//!
//! - **Writers:** a benchmark run on a lab runner writes one results file (schema below). After
//!   each merge to `main`, the gate's job copies that run's results into
//!   `bench/baselines/<runner>/main/` (§9.3 "updated by the gate itself"). Humans write
//!   `bench/baselines/<runner>/runner.toml` when the runner is qualified.
//! - **Reader:** this gate, per PR, on the runner that produced the results. It reads only the
//!   results file and the baseline directory, so another implementation can rerun a verdict
//!   from the committed files.
//! - **Results file, schema 1 (TOML):** `schema = 1`, `runner` (the runner's name), optional
//!   `commit`, then one `[[metric]]` table per number: `id` (benchmark and metric, such as
//!   `B2.service_ns`), `stat` (`mean` or `p99`), `value` (an unsigned integer in the metric's
//!   unit), `better` (`lower` or `higher`) and optional `limit`, the absolute threshold of §7
//!   (for `lower`, the value must be ≤ `limit`; for `higher`, ≥ `limit`). Metrics must be written
//!   as `[[metric]]` tables, one per header, so that violations can name a line.
//! - **Baseline directory:** `runner.toml` with `schema = 1`, `runner` and `mad_ppm` (the runner's
//!   median absolute deviation from qualification, in parts per million), and `main/*.toml`,
//!   results files of past `main` runs. Files sort by name, oldest first; name them
//!   `<commit time as SOURCE_DATE_EPOCH>-<short sha>.toml`.
//! - **Rule (§9.3):** for each `(id, stat)` of the results, the baseline is the median of that
//!   metric's values in the last [`HISTORY`] files that contain it (for an even count, the floor
//!   of the mean of the two middle values). The metric regresses when it is worse than the
//!   baseline by more than `max(BLD_PERF_REGRESS_MIN, 3 × mad_ppm)`, with
//!   [`BLD_PERF_REGRESS_MIN_PPM`] = 2%. A metric with no history only checks its `limit`.
//!   Integer arithmetic throughout: `lower` regresses when
//!   `value × 10⁶ > median × (10⁶ + tol)`, `higher` when `value × 10⁶ < median × (10⁶ − tol)`.
//! - **Override (§9.3):** `--accept-regression <id>:<stat>` turns that metric's `regression` into
//!   a note. It never turns off `threshold`. The written reason and the two owner approvals live
//!   in the PR, not here.
//! - **Ordering:** violations sorted by results-file line, then rule.
//!
//! ```text
//! perf-gate [--root DIR] --results FILE --baseline DIR [--accept-regression ID:STAT]...
//! ```
//!
//! Relative paths are taken from `--root` (default `.`). Output is one `path:line: rule: message`
//! line per violation on stdout, where `path` is `--results` as given; notes and a summary go to
//! stderr. Exit status: 0 clean, 1 violations, 2 the tool could not run. The rule ids are the
//! stable output:
//!
//! | rule | meaning |
//! |---|---|
//! | `threshold` | a value breaks its absolute `limit` (cannot be overridden) |
//! | `regression` | a value is worse than the `main` median by more than the tolerance |
//! | `missing-stat` | an `id` has `mean` without `p99` or `p99` without `mean` (§9.3 compares both) |
//! | `duplicate-metric` | one `(id, stat)` appears twice |
//! | `runner-mismatch` | the results come from another runner than the baseline's |
//!
//! Conformance vectors: `tools/perf-gate/fixtures/*/`.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// §9.3: the median of the last 10 runs on `main`.
pub const HISTORY: usize = 10;
/// `BLD_PERF_REGRESS_MIN` = 2%, in parts per million.
pub const BLD_PERF_REGRESS_MIN_PPM: u64 = 20_000;
const PPM: u128 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stat {
    Mean,
    P99,
}

impl Stat {
    pub fn name(self) -> &'static str {
        match self {
            Stat::Mean => "mean",
            Stat::P99 => "p99",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Better {
    Lower,
    Higher,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub id: String,
    pub stat: Stat,
    pub value: u64,
    pub better: Better,
    pub limit: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Results {
    pub schema: u32,
    pub runner: String,
    pub commit: Option<String>,
    #[serde(default)]
    pub metric: Vec<Metric>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runner {
    pub schema: u32,
    pub runner: String,
    pub mad_ppm: u64,
}

fn schema1(s: u32) -> Result<(), String> {
    if s == 1 {
        Ok(())
    } else {
        Err(format!("unsupported schema {s} (only 1)"))
    }
}

impl Results {
    pub fn parse(text: &str) -> Result<Results, String> {
        let r: Results = toml::from_str(text).map_err(|e| e.to_string())?;
        schema1(r.schema)?;
        Ok(r)
    }
}

impl Runner {
    pub fn parse(text: &str) -> Result<Runner, String> {
        let r: Runner = toml::from_str(text).map_err(|e| e.to_string())?;
        schema1(r.schema)?;
        Ok(r)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub line: usize,
    pub rule: &'static str,
    pub message: String,
}

/// Lower median: the middle value, or the floor of the mean of the two middle values.
pub fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    let n = values.len();
    let hi = *values.get(n / 2)?;
    if n % 2 == 1 {
        return Some(hi);
    }
    let lo = *values.get(n / 2 - 1)?;
    Some(lo + (hi - lo) / 2)
}

/// The regression tolerance in ppm: `max(2%, 3 × MAD)`.
pub fn tolerance_ppm(mad_ppm: u64) -> u64 {
    BLD_PERF_REGRESS_MIN_PPM.max(mad_ppm.saturating_mul(3))
}

/// Whether `value` is worse than `median` by more than `tol_ppm`.
pub fn regressed(better: Better, value: u64, median: u64, tol_ppm: u64) -> bool {
    let v = u128::from(value) * PPM;
    let m = u128::from(median);
    let tol = u128::from(tol_ppm);
    match better {
        Better::Lower => v > m * (PPM + tol),
        Better::Higher => v < m * (PPM - tol.min(PPM)),
    }
}

/// The 1-based line of each `[[metric]]` header, in order.
fn metric_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "[[metric]]")
        .map(|(i, _)| i + 1)
        .collect()
}

/// Checks `results` against `history` (oldest first) and the runner record. `accepted` holds
/// `id:stat` keys whose regression the PR accepted. Returns violations and notes.
pub fn check(
    results_text: &str,
    results: &Results,
    runner: &Runner,
    history: &[Results],
    accepted: &BTreeSet<String>,
) -> (Vec<Violation>, Vec<String>) {
    let lines = metric_lines(results_text);
    let line_of = |k: usize| lines.get(k).copied().unwrap_or(1);
    let mut out = Vec::new();
    let mut notes = Vec::new();
    if results.runner != runner.runner {
        out.push(Violation {
            line: 1,
            rule: "runner-mismatch",
            message: format!(
                "results from `{}`, baseline of `{}`",
                results.runner, runner.runner
            ),
        });
    }
    let tol = tolerance_ppm(runner.mad_ppm);
    let mut seen: BTreeMap<(&str, Stat), usize> = BTreeMap::new();
    let mut stats: BTreeMap<&str, (BTreeSet<Stat>, usize)> = BTreeMap::new();
    for (k, m) in results.metric.iter().enumerate() {
        let line = line_of(k);
        let key = format!("{}:{}", m.id, m.stat.name());
        if seen.insert((&m.id, m.stat), line).is_some() {
            out.push(Violation {
                line,
                rule: "duplicate-metric",
                message: format!("{key} appears twice"),
            });
            continue;
        }
        let e = stats.entry(&m.id).or_insert((BTreeSet::new(), line));
        e.0.insert(m.stat);
        if let Some(limit) = m.limit {
            let bad = match m.better {
                Better::Lower => m.value > limit,
                Better::Higher => m.value < limit,
            };
            if bad {
                out.push(Violation {
                    line,
                    rule: "threshold",
                    message: format!("{key} = {} breaks its limit {limit}", m.value),
                });
            }
        }
        let mut past: Vec<u64> = history
            .iter()
            .rev()
            .filter_map(|h| h.metric.iter().find(|x| x.id == m.id && x.stat == m.stat))
            .take(HISTORY)
            .map(|x| x.value)
            .collect();
        let n = past.len();
        let Some(med) = median(&mut past) else {
            notes.push(format!(
                "{key}: no history on main, only the limit is checked"
            ));
            continue;
        };
        if regressed(m.better, m.value, med, tol) {
            let msg = format!(
                "{key} = {} against main median {med} of {n} run(s), tolerance {tol} ppm",
                m.value
            );
            if accepted.contains(&key) {
                notes.push(format!("accepted regression: {msg}"));
            } else {
                out.push(Violation {
                    line,
                    rule: "regression",
                    message: msg,
                });
            }
        }
    }
    for (id, (set, line)) in stats {
        if set.len() == 1 {
            let have = set.iter().next().map_or("", |s| s.name());
            out.push(Violation {
                line,
                rule: "missing-stat",
                message: format!("{id} has {have} only; §9.3 compares mean and p99"),
            });
        }
    }
    out.sort();
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerance_boundary_is_strict() {
        // 2% over 1000 is 1020: equal passes, one more fails.
        assert!(!regressed(Better::Lower, 1020, 1000, 20_000));
        assert!(regressed(Better::Lower, 1021, 1000, 20_000));
        assert!(!regressed(Better::Higher, 980, 1000, 20_000));
        assert!(regressed(Better::Higher, 979, 1000, 20_000));
        // 3 × MAD wins over 2% when larger.
        assert_eq!(tolerance_ppm(5_000), 20_000);
        assert_eq!(tolerance_ppm(10_000), 30_000);
    }

    #[test]
    fn median_even_and_odd() {
        assert_eq!(median(&mut [5, 1, 3]), Some(3));
        assert_eq!(median(&mut [4, 1, 3, 10]), Some(3));
        assert_eq!(median(&mut []), None);
    }
}
