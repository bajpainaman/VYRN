//! Engine conformance (05 §10, 11 §1.3): a scripted live run produces an order stream; replay
//! of that stream on a fresh box must reproduce every record, response and fill TX packet, and
//! must reject a changed record at its index. `tests/golden/engine/basic.txt` carries the script
//! inputs and the expected order stream so another implementation can run the same vector.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod harness;

use harness::*;
use vyrn_bbo::{Side, Tif};
use vyrn_engine::{Diverged, OwnedRec, Why};
use vyrn_lane::Rx;
use vyrn_types::{Handle, LaneSeq, PacketFlags, StepKind};

/// One scenario touching every replay rule: forwarded improve and cross, a cross the maker's
/// lane has not applied when its next packet arrives (a `MID` boundary inside that packet),
/// a forwarded op late at the BBO (a `Shed` step), a packet late at the lane (`SHED`) and its
/// resend, and a cancel.
fn script() -> Vec<Act> {
    use Side::{Buy, Sell};
    use Tif::{Day, Ioc};
    let p = |l, a, rx_ts, now, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now,
        msgs,
    };
    vec![
        p(0, 1, 1_000, 1_000, vec![new(Sell, Day, 105, 5, 11)]),
        Act::Run,
        p(1, 1, 2_000, 2_000, vec![new(Buy, Day, 105, 2, 1)]),
        Act::Step(None),
        p(
            0,
            2,
            3_000,
            3_000,
            vec![new(Sell, Day, 110, 1, 2), new(Sell, Day, 111, 1, 3)],
        ),
        Act::Run,
        p(2, 1, 5_000, 5_000, vec![new(Buy, Ioc, 105, 1, 7)]),
        // Late by 1 ns at the BBO core: 05 §8.2's signed test, deadline = rx_ts + 615.
        Act::Step(Some(5_000 + u64::from(FWD_DL) + 1)),
        Act::Run,
        // 05 §6.8: one New, age 462 at dequeue is late (path 519 + 462 > 980).
        p(0, 3, 10_000, 10_462, vec![new(Sell, Day, 300, 1, 9)]),
        p(0, 3, 20_000, 20_461, vec![new(Sell, Day, 300, 1, 9)]),
        Act::Run,
        p(
            0,
            1,
            30_000,
            30_000,
            vec![cancel(Handle::new(1, 1).unwrap(), 12)],
        ),
        Act::Poll,
        Act::Run,
    ]
}

fn packets(recs: &[OwnedRec]) -> impl Iterator<Item = &vyrn_types::PacketRecord> {
    recs.iter().filter_map(|r| match r {
        OwnedRec::Packet(p) => Some(p),
        OwnedRec::Step(..) => None,
    })
}

/// Records with the half-cut publication ids cleared: those are physical (see `Why::Mismatch`).
fn logical(recs: &[OwnedRec]) -> Vec<OwnedRec> {
    recs.iter()
        .map(|r| match *r {
            OwnedRec::Step(e, d) => OwnedRec::Step(
                vyrn_bbo::StepEntry {
                    pub_a: 0,
                    pub_b: 0,
                    ..e
                },
                d,
            ),
            p => p,
        })
        .collect()
}

fn steps(recs: &[OwnedRec]) -> impl Iterator<Item = &vyrn_bbo::StepEntry> {
    recs.iter().filter_map(|r| match r {
        OwnedRec::Step(e, _) => Some(e),
        OwnedRec::Packet(_) => None,
    })
}

#[test]
fn the_script_reaches_every_replay_rule() {
    let (j, _, rxs, _) = live(&script());
    assert_eq!(rxs[4], Rx::Shed, "age 462 at dequeue is late");
    assert_eq!(rxs[5], Rx::Accepted, "age 461 is on time");
    let kinds: Vec<_> = steps(&j.recs)
        .map(|e| StepKind::from_code(e.kind))
        .collect();
    assert!(kinds.contains(&Some(StepKind::Improve)), "{kinds:?}");
    assert!(kinds.contains(&Some(StepKind::Cross)), "{kinds:?}");
    assert!(kinds.contains(&Some(StepKind::Shed)), "{kinds:?}");
    let pk: Vec<_> = packets(&j.recs).collect();
    assert!(pk.iter().any(|p| p.flags == PacketFlags::SHED));
    assert!(
        pk.iter()
            .any(|p| p.flags & PacketFlags::MID != 0 && p.lane.0 == 0),
        "lane 0 meets the unapplied cross inside its next packet"
    );
    assert!(
        pk.iter()
            .any(|p| p.flags == PacketFlags::ADVANCE && p.count == 0),
        "an idle-poll boundary"
    );
    // The shed step's source is lane 2's IOC, LaneSeq 1.
    let shed = steps(&j.recs)
        .find(|e| e.kind == StepKind::Shed.code())
        .unwrap();
    assert_eq!((shed.src_lane.0, shed.src_lane_seq), (2, LaneSeq(1)));
}

#[test]
fn replay_reproduces_every_record_response_and_fill_packet() {
    let (live_j, store, _, _) = live(&script());
    let (r, rep) = replay(&live_j.recs, &store);
    assert_eq!(r, Ok(()));
    assert_eq!(logical(&rep.recs), logical(&live_j.recs));
    assert_eq!(rep.resp, live_j.resp);
    assert_eq!(rep.tx, live_j.tx);
}

#[test]
fn replay_rejects_a_changed_record_at_its_index() {
    let (j, store, _, _) = live(&script());
    // A packet record whose fills_applied differs from the replayed lane's.
    let mut recs = j.recs.clone();
    let k = recs
        .iter()
        .position(|r| matches!(r, OwnedRec::Packet(p) if p.count > 0 && p.fills_applied.0 > 0))
        .unwrap();
    if let OwnedRec::Packet(p) = &mut recs[k] {
        p.fills_applied.0 += 1;
    }
    assert_eq!(
        replay(&recs, &store).0,
        Err(Diverged {
            index: k,
            why: Why::Mismatch
        })
    );
    // A step whose logged kind is not what the replayed BBO core decides.
    let mut recs = j.recs.clone();
    let k = recs
        .iter()
        .position(|r| matches!(r, OwnedRec::Step(e, _) if e.kind == StepKind::Cross.code()))
        .unwrap();
    if let OwnedRec::Step(e, _) = &mut recs[k] {
        e.n_fills += 1;
    }
    assert_eq!(
        replay(&recs, &store).0,
        Err(Diverged {
            index: k,
            why: Why::Mismatch
        })
    );
    // A packet without payload.
    let first = j
        .recs
        .iter()
        .position(|r| matches!(r, OwnedRec::Packet(p) if p.count > 0))
        .unwrap();
    assert_eq!(
        replay(&j.recs, &Store::default()).0,
        Err(Diverged {
            index: first,
            why: Why::NoPayload
        })
    );
    // A truncated stream replays as far as it goes.
    assert_eq!(replay(&j.recs[..first + 1], &store).0, Ok(()));
}

#[test]
fn the_same_script_gives_the_same_bytes() {
    let a = live(&script());
    let b = live(&script());
    assert_eq!(a.0.recs, b.0.recs);
    assert_eq!(a.0.resp, b.0.resp);
    assert_eq!(a.0.tx, b.0.tx);
}

fn golden_text() -> String {
    let (j, _, _, inputs) = live(&script());
    let mut s = String::from(
        "# vyrn-engine golden vector v1: spec/05-engine.md §10, spec/11-build.md §1.3.\n\
         # Box: 3 lanes, book 7, ticks 1..512, sessions (1<<20)|(lane<<12)|a with k_seq\n\
         # [lane, a, 0 x 13, 0x5A]; fwd_deadline_ns 615; path table 05 §6.8.\n\
         # I lines: the inputs in order (pkt <lane> <rx_ts> <lane clock> <bytes>, step <BBO\n\
         # clock or - for on time>, poll = every lane's idle poll, run = step and poll until\n\
         # quiet). P and S lines: the order stream the engine must emit, in order. S pub=a/b are\n\
         # half-cut publication ids: physical, compare them only against this schedule.\n",
    );
    s.push_str(&inputs);
    for r in &j.recs {
        s.push_str(&rec_line(r));
        s.push('\n');
    }
    s
}

fn golden_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/golden/engine/basic.txt")
}

#[test]
fn golden_order_stream() {
    let want = std::fs::read_to_string(golden_path())
        .expect("run `cargo test -p vyrn-engine -- --ignored bless`");
    assert_eq!(golden_text(), want);
}

/// Rewrites the golden file after a deliberate change.
#[test]
#[ignore]
fn bless() {
    let p = golden_path();
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, golden_text()).unwrap();
}

#[test]
fn core_role_table() {
    use vyrn_engine::role::{Half, Role, role_of};
    use vyrn_types::LaneId;
    assert_eq!(role_of(0), Role::Control);
    assert_eq!(role_of(1), Role::CutCore(Half::A));
    assert_eq!(role_of(6), Role::CutCore(Half::B));
    assert_eq!(role_of(2), Role::Bbo);
    assert_eq!(role_of(8), Role::Lane(LaneId(0)));
    assert_eq!(role_of(49), Role::Lane(LaneId(41)));
    assert_eq!(role_of(56), Role::PoolLane(LaneId(42)));
    assert_eq!(role_of(62), Role::PoolLane(LaneId(48)));
    assert_eq!(role_of(51), Role::Spare);
    assert_eq!(role_of(63), Role::Spare);
}
