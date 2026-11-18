//! The cluster run's contract (crate docs): determinism, replay equality, the SF-24 canary and
//! shrinking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vyrn_sim::cluster::{Config, Fault, Schedule, run, run_seed, shrink};

/// Seed 3 passes with its own schedule and trades (tests/seeds.toml pins it).
const GOOD: u64 = 3;

#[test]
fn a_seed_replays_byte_for_byte() {
    let a = run_seed(GOOD);
    let b = run_seed(GOOD);
    assert_eq!(a, b);
    assert_eq!(a.violation, None, "{:?}", a.violation);
    assert!(a.stats.fills > 0 && a.stats.steps > 0, "{:?}", a.stats);
    assert_ne!(a.trace, run_seed(GOOD + 1).trace);
}

#[test]
fn every_seed_under_network_faults_and_lane_stalls_passes_or_fails_a_known_check() {
    // The two known engine bugs (tests/seeds.toml) stop some seeds; nothing else may.
    for seed in 1..=40u64 {
        let cfg = Config::from_seed(seed);
        let mut s = Schedule::generate(seed, &cfg);
        s.0.retain(|f| !matches!(f, Fault::BboStall { .. }));
        let r = run(seed, &s);
        if let Some(v) = &r.violation {
            assert_eq!(v.check, "BBO-QUIESCE", "seed {seed}: {v:?}");
        }
    }
}

#[test]
fn an_injected_divergence_fails_inv_det_and_shrinks_to_itself() {
    let cfg = Config::from_seed(GOOD);
    let mut s = Schedule::generate(GOOD, &cfg);
    s.0.push(Fault::Drop { pkt: 2 });
    s.0.push(Fault::Diverge { replica: 1, rec: 5 });
    let r = run(GOOD, &s);
    let v = r.violation.expect("SF-24 must be caught");
    assert_eq!(v.check, "INV-DET");
    assert!(v.detail.starts_with("replica 1 "), "{}", v.detail);
    let small = shrink(GOOD, &s).unwrap();
    assert_eq!(
        small.schedule.0,
        vec![Fault::Diverge { replica: 1, rec: 5 }]
    );
}

#[test]
fn schedules_round_trip_through_text() {
    let s = Schedule::parse(
        "drop 1; dup 2; delay 3 400; lane-stall 1 500 600; bbo-stall 700 800; diverge 0 9",
    )
    .unwrap();
    assert_eq!(s.0.len(), 6);
    assert_eq!(Schedule::parse(&s.render()).unwrap(), s);
    assert_eq!(Schedule::parse("").unwrap(), Schedule::default());
    assert!(Schedule::parse("drop").is_err());
    assert!(Schedule::parse("explode 1").is_err());
}
