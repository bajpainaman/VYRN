//! Drives a real `Lane` through every row of the session-state table (04 §4.3) from the JSON form
//! of the session vectors (`tests/golden/vyrn_session_vectors.json`), and checks the lane's
//! behaviour: the verdict, the reject reason and the detail it emits. It also checks that each
//! close cause's final in-stream record is byte for byte the vector's `close` row.
//!
//! *Reading (spec gap, labelled):* the lane has no `OPENING` slot state. A session the control path
//! has not installed yet is not on the lane at all, so `OPENING` and `FREE` rows both send from a
//! session the lane never opened, and V2 drops them with no response (the generator's reading).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod harness;
mod json;

use harness::*;
use vyrn_bbo::{Record, Side};
use vyrn_lane::Rx;
use vyrn_lane::lane::PROTO_D_BAD_MAC;
use vyrn_types::{Handle, Qty, RejectReason, Tick};
use vyrn_wire::Msg;

/// The session under test, opened by the harness for every non-`FREE` row.
const A: u32 = 1;
/// A session the lane never opened (`OPENING`, `FREE`).
const UNOPENED: u32 = 30;

fn msg(name: &str, h: Handle) -> Msg {
    match name {
        "New" => new(day(Side::Buy), 100, 5, 7),
        "Cancel" => cancel(h, 7),
        "Reduce" => Msg::Reduce {
            handle: h,
            by: Qty(1),
            client_tag: 7,
        },
        "Replace" => Msg::Replace {
            flags: wire_flags(day(Side::Buy)),
            handle: h,
            tick: Tick(99),
            qty: Qty(5),
        },
        "Heartbeat" => Msg::Heartbeat,
        "ResendReq" => Msg::ResendReq { from: 1, to: 1 },
        "CancelAll" => Msg::CancelAll { client_tag: 7 },
        n => panic!("message {n}"),
    }
}

fn reason(name: &str) -> RejectReason {
    match name {
        "SESSION_CLOSED" => RejectReason::SessionClosed,
        n => panic!("reason {n}"),
    }
}

fn session_closed(r: &Record) -> Option<(u32, u32)> {
    match *r {
        Record::Reject {
            index,
            reason: RejectReason::SessionClosed,
            detail,
            ..
        } => Some((u32::from(index), detail)),
        _ => None,
    }
}

#[test]
fn every_session_state_row_drives_the_lane() {
    let doc = json::load(env!("CARGO_MANIFEST_DIR"), "vyrn_session_vectors.json");
    let closed_cause = u32::try_from(doc.n("closed_cause")).unwrap();
    let rows = doc.arr("states");
    assert_eq!(rows.len(), 35, "5 states × 7 messages");
    for row in rows {
        let (id, state, m, verdict) = (
            row.s("id"),
            row.s("state"),
            row.s("message"),
            row.s("verdict"),
        );
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        // A resting order, so Cancel, Reduce and Replace name a live handle.
        x.send(0, A, 1_000, &[new(day(Side::Buy), 100, 5, 1)]);
        x.settle(&mut bbo);
        let h = x.last_ack(0, A);
        let a = match state {
            "OPENING" | "FREE" => UNOPENED,
            "ACTIVE" => A,
            "DRAINING" => {
                assert!(x.lanes[0].drain_session(sid(0, A)), "{id}");
                A
            }
            "CLOSED" => {
                assert!(x.close_session(0, A, closed_cause), "{id}");
                A
            }
            s => panic!("{id}: state {s}"),
        };
        let (n_in, n_all) = (x.records(0, a).len(), x.resp[0].len());
        let rx = x.send(0, a, 2_000, &[msg(m, h)]);
        let fresh: Vec<Record> = x.records(0, a)[n_in..].to_vec();
        match verdict {
            "drop" => {
                assert_eq!(rx, Rx::Dropped, "{id}");
                assert_eq!(x.resp[0].len(), n_all, "{id}: a drop sends nothing");
            }
            "accept" => {
                assert_eq!(rx, Rx::Accepted, "{id}");
                assert!(
                    fresh.iter().all(|r| session_closed(r).is_none()),
                    "{id}: {fresh:?}"
                );
            }
            "reject" => {
                assert_eq!(rx, Rx::Accepted, "{id}: the packet is in stream");
                assert_eq!(reason(row.s("reason")), RejectReason::SessionClosed, "{id}");
                let want = u32::try_from(row.n("detail")).unwrap();
                assert_eq!(
                    fresh.iter().find_map(session_closed),
                    Some((0, want)),
                    "{id}: the message's Reject, at index 0: {fresh:?}"
                );
            }
            "oos" => {
                assert_eq!(rx, Rx::OutOfStream(reason(row.s("reason"))), "{id}");
                assert!(fresh.is_empty(), "{id}: nothing in stream");
                let p = x.resp[0].last().unwrap();
                assert_eq!((p.session, p.resp_seq), (sid(0, a), 0), "{id}");
                let want = u32::try_from(row.n("detail")).unwrap();
                assert_eq!(
                    p.records().iter().find_map(session_closed).map(|d| d.1),
                    Some(want),
                    "{id}: V7 detail is the close cause"
                );
            }
            v => panic!("{id}: verdict {v}"),
        }
    }
}

/// Each close cause makes the lane emit its final in-stream record, byte for byte the vector:
/// `close_session` for the control-path causes, a bad tag at `pkt_seq` 42 for `BAD_MAC` (V6).
#[test]
fn close_causes_emit_the_vector_records() {
    let doc = json::load(env!("CARGO_MANIFEST_DIR"), "vyrn_session_vectors.json");
    let causes = [
        ("LOGOUT", 1),
        ("BAD_MAC", PROTO_D_BAD_MAC),
        ("EQUIVOCATION", 3),
        ("ADMIN_KILL", 4),
        ("LANE_MOVED", 5),
        ("BOND", 6),
    ];
    let rows = doc.arr("close");
    assert_eq!(rows.len(), causes.len());
    for (row, (name, cause)) in rows.iter().zip(causes) {
        assert_eq!(row.s("cause"), name);
        let (_bbo, mut w) = setup();
        let mut x = w.rig();
        // Packets 1..=41 accepted first, so a wrong echo (the last accepted one) shows.
        for t in 1..42 {
            assert_eq!(x.send(0, A, t * 1_000, &[Msg::Heartbeat]), Rx::Accepted);
        }
        if name == "BAD_MAC" {
            let rx = x.send_keyed(0, A, 50_000, &[Msg::Heartbeat], &[0xEE; 16]);
            assert_eq!(rx, Rx::Closed, "{name}");
        } else {
            assert!(x.close_session(0, A, cause), "{name}");
        }
        let last = *x.records(0, A).last().expect("a final record");
        assert_eq!(hex(&last.encode()), row.s("hex"), "{name}");
        // R-ECHO (04 §7.2): BAD_MAC answers the offending packet 42; a control-path close
        // answers no request, so it goes in a packet with echo_pkt = 0.
        let echo = x.resp[0].last().unwrap().echo_pkt;
        assert_eq!(echo, if name == "BAD_MAC" { 42 } else { 0 }, "{name}");
        // From then on V7 answers out of stream with the cause as detail.
        let rx = x.send(0, A, 60_000, &[Msg::Heartbeat]);
        assert_eq!(rx, Rx::OutOfStream(RejectReason::SessionClosed), "{name}");
        let p = x.resp[0].last().unwrap();
        assert_eq!(
            p.records().iter().find_map(session_closed).map(|d| d.1),
            Some(cause),
            "{name}"
        );
        // A bad tag after the close is dropped with no answer and keeps the first cause
        // (Codex on #207): V7 still answers with `cause`, not BAD_MAC.
        let n_resp = x.resp[0].len();
        let rx = x.send_keyed(0, A, 61_000, &[Msg::Heartbeat], &[0xEE; 16]);
        assert_eq!(rx, Rx::Dropped, "{name}");
        assert_eq!(x.resp[0].len(), n_resp, "{name}: nothing sent");
        x.send(0, A, 62_000, &[Msg::Heartbeat]);
        let p = x.resp[0].last().unwrap();
        assert_eq!(
            p.records().iter().find_map(session_closed).map(|d| d.1),
            Some(cause),
            "{name}: the first cause stays"
        );
    }
}
