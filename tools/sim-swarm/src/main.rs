//! `sim-swarm`: the swarm runner over `vyrn-sim` seeds (spec/11-build.md §6.4 "Swarm testing",
//! "Budgets").
//!
//! # Contract
//!
//! `sim-swarm [--start <hex>] [--seeds <n>] [--jobs <j>] [--classes <mask>] [--seed-file <path>]
//! [--canary]`
//!
//! - Runs seeds `start .. start + n` (default `0x1 .. 0x1 + 500`, `BLD_SIM_SEEDS_PR`) on `j`
//!   threads (default 2), each with its own configuration and generated fault schedule. Every
//!   seed is independent, so the result does not depend on `j` or on thread timing.
//! - `--classes` masks the fault classes every seed may draw (bit 0 network, 1 lane stall,
//!   2 BBO stall; default 7, all). A masked class is removed from the generated schedule.
//! - `--seed-file` (default `tests/seeds.toml`; a missing file is an error, so the pinned seeds
//!   never drop out silently) lists pinned seeds (11 §6.4: "every seed that ever
//!   failed ... runs on every PR"). Each `[[seed]]` has `seed` (hex), optional `faults` (schedule
//!   text; default the seed's own) and `expect`: `"pass"` or the name of the check it must fail
//!   (a known bug that a follow-up fixes). A pinned seed whose result differs from `expect` fails
//!   the swarm, so a fix shows up as a diff to update. A top-level `known = ["CHECK", ...]`
//!   names checks with an open engine bug: a swarm seed that fails one of them is counted and
//!   listed as known, not failed. Any other check fails the swarm.
//! - Simulator determinism: the first seed runs twice and the two trace hashes must be equal.
//! - `--canary` adds SF-24 (`diverge 0 0`: replica 0 gets record 0 changed) to every swarm seed
//!   and inverts the verdict: every seed must fail `INV-DET`. It proves the checker bites.
//!
//! Output: one summary line, then for the lowest failing seed its shrunk schedule
//! (`vyrn_sim::cluster::shrink`) and the `vyrn-sim run` command line that reproduces it. Exit
//! status 0 when every seed meets its expectation, 1 otherwise, 2 on bad arguments.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use vyrn_sim::cluster::{self, Config, Fault, Report, Schedule};

struct Args {
    start: u64,
    seeds: u64,
    jobs: usize,
    classes: u8,
    seed_file: String,
    canary: bool,
}

fn hex(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("{s:?}: {e}"))
}

fn args() -> Result<Args, String> {
    let mut a = Args {
        start: 1,
        seeds: 500,
        jobs: 2,
        classes: 7,
        seed_file: "tests/seeds.toml".into(),
        canary: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().ok_or(format!("{k} needs a value"));
        match k.as_str() {
            "--start" => a.start = hex(&v()?)?,
            "--seeds" => a.seeds = v()?.parse().map_err(|e| format!("--seeds: {e}"))?,
            "--jobs" => a.jobs = v()?.parse().map_err(|e| format!("--jobs: {e}"))?,
            "--classes" => a.classes = v()?.parse().map_err(|e| format!("--classes: {e}"))?,
            "--seed-file" => a.seed_file = v()?,
            "--canary" => a.canary = true,
            _ => return Err(format!("unknown argument {k:?}")),
        }
    }
    Ok(a)
}

/// The schedule a swarm seed runs: its own, without masked classes, plus the canary.
fn swarm_schedule(seed: u64, a: &Args) -> Schedule {
    let mut s = Schedule::generate(seed, &Config::from_seed(seed));
    s.0.retain(|f| {
        let class = match f {
            Fault::Drop { .. } | Fault::Dup { .. } | Fault::Delay { .. } => 0,
            Fault::LaneStall { .. } => 1,
            Fault::BboStall { .. } => 2,
            Fault::Diverge { .. } => return true,
        };
        a.classes & (1 << class) != 0
    });
    if a.canary {
        s.0.push(Fault::Diverge { replica: 0, rec: 0 });
    }
    s
}

struct Pinned {
    seed: u64,
    faults: Option<String>,
    expect: String,
}

/// The pinned seeds and the known checks of a seed file.
fn pinned(path: &str) -> Result<(Vec<Pinned>, Vec<String>), String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let v: toml::Table = text.parse().map_err(|e| format!("{path}: {e}"))?;
    let known = v
        .get("known")
        .and_then(|k| k.as_array())
        .into_iter()
        .flatten()
        .filter_map(|k| k.as_str().map(str::to_owned))
        .collect();
    let mut out = Vec::new();
    for e in v
        .get("seed")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
    {
        let get = |k: &str| e.get(k).and_then(|x| x.as_str());
        out.push(Pinned {
            seed: hex(get("seed").ok_or(format!("{path}: a [[seed]] has no seed"))?)?,
            faults: get("faults").map(str::to_owned),
            expect: get("expect").unwrap_or("pass").to_owned(),
        });
    }
    Ok((out, known))
}

fn verdict(r: &Report) -> &str {
    r.violation.as_ref().map_or("pass", |v| v.check)
}

fn main() -> ExitCode {
    let a = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sim-swarm: {e}");
            return ExitCode::from(2);
        }
    };
    let (pins, known) = match pinned(&a.seed_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sim-swarm: {e}");
            return ExitCode::from(2);
        }
    };
    let mut ok = true;

    // Simulator determinism: one seed twice.
    let s0 = swarm_schedule(a.start, &a);
    let (r1, r2) = (cluster::run(a.start, &s0), cluster::run(a.start, &s0));
    if r1.trace != r2.trace {
        println!(
            "FAIL determinism: seed {:016x} traces {} and {}",
            a.start,
            r1.trace_hex(),
            r2.trace_hex()
        );
        ok = false;
    }

    // Pinned seeds.
    for p in &pins {
        let s = match &p.faults {
            Some(f) => match Schedule::parse(f) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("sim-swarm: seed {:016x}: {e}", p.seed);
                    return ExitCode::from(2);
                }
            },
            None => Schedule::generate(p.seed, &Config::from_seed(p.seed)),
        };
        let r = cluster::run(p.seed, &s);
        if verdict(&r) != p.expect {
            println!(
                "FAIL pinned seed {:016x}: expected {}, got {} ({})",
                p.seed,
                p.expect,
                verdict(&r),
                r.violation.as_ref().map_or("", |v| v.detail.as_str())
            );
            ok = false;
        }
    }

    // The swarm.
    let next = AtomicU64::new(0);
    let failed: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
    let known_hits: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
    let (events, fills) = (AtomicU64::new(0), AtomicU64::new(0));
    let multi = AtomicU64::new(0);
    std::thread::scope(|sc| {
        for _ in 0..a.jobs.max(1) {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= a.seeds {
                        break;
                    }
                    let seed = a.start.wrapping_add(i);
                    let r = cluster::run(seed, &swarm_schedule(seed, &a));
                    events.fetch_add(r.stats.events, Ordering::Relaxed);
                    fills.fetch_add(r.stats.fills, Ordering::Relaxed);
                    multi.fetch_add(r.stats.multi_auction_drains, Ordering::Relaxed);
                    let bad = match (&r.violation, a.canary) {
                        (None, false) => None,
                        (Some(v), _) if known.iter().any(|k| k == v.check) => {
                            if let Ok(mut k) = known_hits.lock() {
                                k.push((seed, format!("{} at event {}", v.check, v.index)));
                            }
                            None
                        }
                        (Some(v), false) => {
                            Some(format!("{} at event {}: {}", v.check, v.index, v.detail))
                        }
                        (Some(v), true) if v.check == "INV-DET" => None,
                        (v, true) => Some(format!(
                            "canary not caught: {}",
                            v.as_ref().map_or("pass", |v| v.check)
                        )),
                    };
                    if let Some(b) = bad
                        && let Ok(mut f) = failed.lock()
                    {
                        f.push((seed, b));
                    }
                }
            });
        }
    });
    let mut failed = failed.into_inner().unwrap_or_default();
    failed.sort();
    let mut known_hits = known_hits.into_inner().unwrap_or_default();
    known_hits.sort();
    println!(
        "sim-swarm: {} seeds from {:016x}, {} failed, {} known, {} pinned, {} events, {} fills, classes {}{}",
        a.seeds,
        a.start,
        failed.len(),
        known_hits.len(),
        pins.len(),
        events.load(Ordering::Relaxed),
        fills.load(Ordering::Relaxed),
        a.classes,
        if a.canary { ", canary" } else { "" }
    );
    // Shown only when it happens: boundaries that drained 2..=ENG_AUCTION_DRAIN uncrosses.
    let m = multi.load(Ordering::Relaxed);
    if m > 0 {
        println!("  multi-auction boundaries: {m}");
    }
    for (seed, why) in known_hits.iter().take(5) {
        println!("  known seed {seed:016x}: {why}");
    }
    for (seed, why) in failed.iter().take(10) {
        println!("  seed {seed:016x}: {why}");
    }
    if let Some((seed, _)) = failed.first() {
        ok = false;
        if !a.canary
            && let Some(r) = cluster::shrink(*seed, &swarm_schedule(*seed, &a))
        {
            let v = r.violation.as_ref().map_or("", |v| v.check);
            println!(
                "first failing seed {seed:016x}, shrunk to {} fault(s), {v}",
                r.schedule.0.len()
            );
            println!(
                "repro: cargo run --locked -q -p vyrn-sim -- run --seed {seed:016x} --faults '{}'",
                r.schedule.render()
            );
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
