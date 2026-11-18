//! Golden lane streams (tests/golden/lane/README.md): each scenario's inputs, packets and
//! schedule, with every output of the lanes and the BBO core, in a language-neutral text file.
//! The test replays the scenarios and compares the transcript byte for byte. Every expected
//! record in the file is also asserted from the spec in `tests/lane.rs` (named per scenario).
//! On a mismatch the actual transcript is written next to the build for review.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod harness;

use harness::*;
use vyrn_bbo::{Bbo, Side};
use vyrn_types::{Handle, Qty};
use vyrn_wire::Msg;

const FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/golden/lane/streams.txt"
);

type Scenario = (&'static str, &'static str, fn(&mut Rig<'_>, &mut Bbo));

fn ask_105(x: &mut Rig<'_>, bbo: &mut Bbo) -> Handle {
    x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 5, 11)]);
    x.settle(bbo);
    x.last_ack(0, 1)
}

const SCENARIOS: &[Scenario] = &[
    (
        "improve-ack",
        "05 §6.5 Improve, §8.10 rule 1; rule F. tests/lane.rs rule_f_fwd_pend_is_the_floor_until_the_first_step_event",
        |x, bbo| {
            ask_105(x, bbo);
        },
    ),
    (
        "local-join-ack-after-cut",
        "INV-ACK-AFTER-CUT, 05 §7.6. tests/lane.rs a_local_join_is_acked_only_after_the_first_cut_that_covers_it",
        |x, bbo| {
            ask_105(x, bbo);
            x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]);
            x.settle(bbo);
        },
    ),
    (
        "cross-with-join-dependency",
        "05 §6.6, §8.10 rule 1. tests/lane.rs a_cross_with_a_join_dependency_and_the_index_follow_up",
        |x, bbo| {
            ask_105(x, bbo);
            x.send(
                1,
                1,
                3_000,
                &[
                    new(day(Side::Sell), 106, 1, 21),
                    new(day(Side::Buy), 106, 3, 22),
                ],
            );
            x.settle(bbo);
        },
    ),
    (
        "dependency-index-across-heartbeat",
        "spec follow-up: index = source - back. tests/lane.rs pin_fwddep_index_is_source_minus_back_across_a_session_only_message",
        |x, bbo| {
            ask_105(x, bbo);
            let m = [
                new(day(Side::Sell), 106, 1, 21),
                Msg::Heartbeat,
                new(day(Side::Buy), 106, 3, 22),
            ];
            x.send(1, 1, 3_000, &m);
            x.settle(bbo);
        },
    ),
    (
        "batch-taker-three-steps",
        "05 D14, §8.6, §8.10 rule 4; rule B. tests/lane.rs rule_b_a_batch_taker_spanning_three_steps",
        |x, bbo| {
            x.send(2, 1, 100, &[new(day(Side::Buy), 105, 1, 1)]);
            x.settle(bbo);
            x.hold(1);
            let h = x.last_ack(2, 1);
            x.send(2, 1, 200, &[cancel(h, 2)]);
            x.settle(bbo);
            for a in 1..=8u32 {
                x.send(0, a, 300 + u64::from(a), &[new(day(Side::Sell), 102, 1, a)]);
                x.settle(bbo);
            }
            x.send(0, 9, 400, &[new(day(Side::Sell), 103, 1, 9)]);
            x.settle(bbo);
            let ninth = x.last_ack(0, 9);
            x.send(1, 1, 500, &[new(day(Side::Buy), 103, 20, 77)]);
            x.send(0, 9, 600, &[cancel(ninth, 99)]);
            x.bbo_step(bbo);
            for l in 0..N {
                x.lane_poll(l);
            }
            x.settle(bbo);
        },
    ),
    (
        "deadline-shed-at-the-lane",
        "05 §6.8, 01 §14.17.1. tests/lane.rs deadline_admission_at_the_threshold",
        |x, _| {
            let m = [new(day(Side::Sell), 300, 1, 9)];
            x.send_at(0, 1, 10_000, 10_462, &m, &[]);
            x.send_at(0, 1, 20_000, 20_461, &m, &[]);
        },
    ),
    (
        "shed-step-with-dependency",
        "05 §6.8 Shed, 10 §3.11. tests/lane.rs a_shed_entry_with_dependencies_answers_busy_without_a_fault",
        |x, bbo| {
            ask_105(x, bbo);
            x.send(
                1,
                1,
                3_000,
                &[
                    new(day(Side::Sell), 106, 1, 21),
                    new(day(Side::Buy), 106, 3, 22),
                ],
            );
            x.bbo_step_at(bbo, 1_000_000);
            x.settle(bbo);
        },
    ),
    (
        "reduce-before-successor-fill",
        "05 §2.3, 04 §6.4. tests/lane.rs a_reduce_settles_even_when_its_successor_filled_first",
        |x, bbo| {
            x.send(0, 1, 1_000, &[new(day(Side::Sell), 106, 10, 11)]);
            x.settle(bbo);
            let h = x.last_ack(0, 1);
            x.send(
                0,
                1,
                2_000,
                &[Msg::Reduce {
                    handle: h,
                    by: Qty(4),
                    client_tag: 44,
                }],
            );
            x.send(1, 1, 3_000, &[new(day(Side::Buy), 106, 6, 1)]);
            x.settle(bbo);
        },
    ),
];

fn transcript() -> String {
    let mut out = String::new();
    for (name, about, run) in SCENARIOS {
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        x.tr = Some(Vec::new());
        run(&mut x, &mut bbo);
        out += &format!("\nscenario {name}\n# {about}\n");
        for l in x.tr.take().unwrap() {
            out += &l;
            out.push('\n');
        }
    }
    out
}

#[test]
fn lane_streams_match_the_golden_file() {
    let got = transcript();
    let want = std::fs::read_to_string(FILE).unwrap_or_default();
    let body = want.split_once("\nscenario ").map_or("", |(_, b)| b);
    if format!("\nscenario {body}") != got {
        let path = concat!(env!("CARGO_TARGET_TMPDIR"), "/lane-streams.txt");
        std::fs::write(path, &got).unwrap();
        panic!("lane streams differ from {FILE}; the actual transcript is in {path}");
    }
}

#[test]
fn the_transcript_is_deterministic() {
    assert_eq!(transcript(), transcript());
}
