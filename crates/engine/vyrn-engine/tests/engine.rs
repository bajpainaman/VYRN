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
use vyrn_engine::{Diverged, OwnedRec, Why, WireAt, WireDiverged};
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
        OwnedRec::Step(..) | OwnedRec::Route(_) => None,
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
        OwnedRec::Packet(_) | OwnedRec::Route(_) => None,
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
fn replay_reproduces_shed_steps_after_a_heartbeat_and_a_backward_rx_ts() {
    // Two BBO Shed steps whose live deadlines depend on lane state (05 §6.3, §6.8); replay
    // takes the kind from the record, so it needs no deadline at all (05 §10):
    // - lane 2: a Heartbeat-only packet (no LaneSeq) at rx 1000, then an IOC (LaneSeq 1) at
    //   rx 3000. The IOC's deadline is 3000 + 615, not the heartbeat's 1000 + 615.
    // - lane 1: a join at rx 8000, then an IOC at rx 7000. prio_ts = max(7000, 8000) = 8000,
    //   so the deadline is 8615, not 7615.
    use Side::Buy;
    use Tif::{Day, Ioc};
    let p = |l, a, rx_ts, msgs| Act::Pkt {
        l,
        a,
        rx_ts,
        now: rx_ts,
        msgs,
    };
    let dl = u64::from(FWD_DL);
    let s = vec![
        p(2, 1, 1_000, vec![vyrn_wire::Msg::Heartbeat]),
        p(2, 1, 3_000, vec![new(Buy, Ioc, 105, 1, 1)]),
        Act::Step(Some(3_000 + dl + 1)),
        Act::Run,
        p(1, 1, 8_000, vec![new(Buy, Day, 50, 1, 2)]),
        Act::Run,
        p(1, 1, 7_000, vec![new(Buy, Ioc, 105, 1, 3)]),
        Act::Step(Some(8_000 + dl + 1)),
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    let shed: Vec<_> = steps(&j.recs)
        .filter(|e| e.kind == StepKind::Shed.code())
        .map(|e| (e.src_lane.0, e.src_lane_seq))
        .collect();
    assert_eq!(shed, vec![(2, LaneSeq(1)), (1, LaneSeq(2))]);
    assert_eq!(replay(&j.recs, &store).0, Ok(()));
}

#[test]
fn replay_takes_kind_and_source_from_the_record() {
    // 05 §10 rows 4–5: replay executes the logged step, so the BBO core refuses a record that
    // cannot be its next step instead of re-deciding it.
    let (j, store, _, _) = live(&script());
    let shed = j
        .recs
        .iter()
        .position(|r| matches!(r, OwnedRec::Step(e, _) if e.kind == StepKind::Shed.code()))
        .unwrap();
    // The logged source of the Shed step is lane 2's LaneSeq 1; name LaneSeq 2 instead.
    let mut recs = j.recs.clone();
    if let OwnedRec::Step(e, _) = &mut recs[shed] {
        e.src_lane_seq = LaneSeq(2);
    }
    assert_eq!(
        replay(&recs, &store).0,
        Err(Diverged {
            index: shed,
            why: Why::Step(vyrn_bbo::Diverge::Source)
        })
    );
    // An unknown kind code does not decode.
    let mut recs = j.recs.clone();
    if let OwnedRec::Step(e, _) = &mut recs[shed] {
        e.kind = 0xEE;
    }
    assert_eq!(
        replay(&recs, &store).0,
        Err(Diverged {
            index: shed,
            why: Why::BadStep
        })
    );
}

#[test]
fn replay_checks_responses_against_a_response_log() {
    // 07 §7.1: replay outputs every response record. With a log, a changed response is caught
    // instead of passing silently (the G9 interim check).
    let (j, store, _, _) = live(&script());
    assert_eq!(replay_checked(&j.recs, &store, &j).0, Ok(()));
    // One lane response changed.
    let mut bad = Journal {
        recs: j.recs.clone(),
        resp: j.resp.clone(),
        tx: j.tx.clone(),
    };
    bad.resp[0].1.resp_seq += 1;
    assert!(matches!(
        replay_checked(&j.recs, &store, &bad).0,
        Err(Diverged {
            why: Why::Response,
            ..
        })
    ));
    // One fill TX packet changed.
    let mut bad = Journal {
        recs: j.recs.clone(),
        resp: j.resp.clone(),
        tx: j.tx.clone(),
    };
    bad.tx[0].0.resp_seq += 1;
    assert!(matches!(
        replay_checked(&j.recs, &store, &bad).0,
        Err(Diverged {
            why: Why::Response,
            ..
        })
    ));
    // A logged response replay never produces: caught at the end.
    let mut extra = Journal {
        recs: j.recs.clone(),
        resp: j.resp.clone(),
        tx: j.tx.clone(),
    };
    extra.resp.push(extra.resp[0]);
    assert_eq!(
        replay_checked(&j.recs, &store, &extra).0,
        Err(Diverged {
            index: j.recs.len(),
            why: Why::Response
        })
    );
}

#[test]
fn replay_from_07_fields_only_in_canonical_order() {
    // 07 §7.1 REP_MERGE: lane records and steps reduced to what 07 carries (kind, source, cut,
    // Rescan band), merged by fills_applied. Every lane record, response and fill TX packet of
    // the live run must come out again.
    let (j, store, _, _) = live(&script());
    let (lanes, routes, steps) = to_wire(&j.recs);
    let (r, rep) = replay_wire(&lanes, &routes, &steps, &store, Some(&j));
    assert_eq!(r, Ok(()));
    // REP_MERGE is not the live interleaving across lanes (07 §7.1); each lane's records match.
    for l in 0..N as u8 {
        let pk = |x: &[OwnedRec]| {
            packets(x)
                .filter(|p| p.lane.0 == l)
                .copied()
                .collect::<Vec<_>>()
        };
        assert_eq!(pk(&rep.recs), pk(&j.recs), "lane {l}");
    }
    let resp = |x: &Journal, l: u8| {
        x.resp
            .iter()
            .filter(|r| r.0.0 == l)
            .copied()
            .collect::<Vec<_>>()
    };
    for l in 0..N as u8 {
        assert_eq!(resp(&rep, l), resp(&j, l), "lane {l} responses");
    }
    assert_eq!(rep.tx, j.tx);
    // The derived StepEntry fields (n_tx, n_fills, fill_lanes, flags, band) match live.
    assert_eq!(
        logical(&rep.recs)
            .iter()
            .filter(|r| matches!(r, OwnedRec::Step(..)))
            .collect::<Vec<_>>(),
        logical(&j.recs)
            .iter()
            .filter(|r| matches!(r, OwnedRec::Step(..)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn replay_from_07_derives_cont_for_a_capped_sweep() {
    // 05 §8.5, D14: a sweep stops after ENG_STEP_FILLS = 8 maker fills and continues in a CONT
    // step. 07 carries no CONT bit, so replay takes it from the BBO core (Bbo::continuing).
    use Side::{Buy, Sell};
    use Tif::Day;
    let mut s: Vec<Act> = (1..=9u32)
        .map(|a| Act::Pkt {
            l: 0,
            a,
            rx_ts: 1_000 * u64::from(a),
            now: 1_000 * u64::from(a),
            msgs: vec![new(Sell, Day, 105, 1, a)],
        })
        .collect();
    s.push(Act::Run);
    s.push(Act::Pkt {
        l: 1,
        a: 1,
        rx_ts: 20_000,
        now: 20_000,
        msgs: vec![new(Buy, Day, 105, 9, 99)],
    });
    s.push(Act::Run);
    let (j, store, _, _) = live(&s);
    let n_cont = steps(&j.recs)
        .filter(|e| e.flags & vyrn_bbo::STEP_CONT != 0)
        .count();
    assert_eq!(n_cont, 1, "9 makers: 8 fills, then one CONT step");
    let (lanes, routes, ws) = to_wire(&j.recs);
    let (r, rep) = replay_wire(&lanes, &routes, &ws, &store, Some(&j));
    assert_eq!(r, Ok(()));
    assert_eq!(
        steps(&rep.recs).map(|e| e.flags).collect::<Vec<_>>(),
        steps(&j.recs).map(|e| e.flags).collect::<Vec<_>>()
    );
}

#[test]
fn replay_from_07_rejects_what_07_carries() {
    let (j, store, _, _) = live(&script());
    let (lanes, routes, steps) = to_wire(&j.recs);
    // A changed source is refused by the BBO core at that step.
    let k = steps.iter().position(|s| s.1 == StepKind::Shed).unwrap();
    let mut bad = steps.clone();
    bad[k].2 = Some((vyrn_types::LaneId(2), LaneSeq(2)));
    assert_eq!(
        replay_wire(&lanes, &routes, &bad, &store, None).0,
        Err(WireDiverged {
            at: WireAt::Step(steps[k].0),
            why: Why::Step(vyrn_bbo::Diverge::Source)
        })
    );
    // A cut above what its lane has replayed cannot be ordered (REP_E_ORDER).
    let mut bad = steps.clone();
    bad[0].4[1] = LaneSeq(99);
    assert_eq!(
        replay_wire(&lanes, &routes, &bad, &store, None).0,
        Err(WireDiverged {
            at: WireAt::Step(steps[0].0),
            why: Why::Order
        })
    );
    // A lane record due at a step the block lacks is carried, not replayed (REP_MERGE item 3).
    let k = steps.len() - 1;
    let (r, _, carried) = replay_blocks(&[(&lanes, &routes, &steps[..k])], &store, None);
    assert_eq!(r, Ok(()));
    assert!(carried > 0);
}

#[test]
fn replay_from_07_carries_unsettled_records_across_blocks() {
    // 07 §7.1 REP_MERGE item 3: split the run into two blocks at every step. A packet whose op is
    // stepped in the second block (forwarded, then Cross/Improve/Shed later) must carry, not be
    // replayed as local at the end of the first. Each split must reproduce the one-block replay.
    let (j, store, _, _) = live(&script());
    let (lanes, routes, steps) = to_wire(&j.recs);
    let (r, one) = replay_wire(&lanes, &routes, &steps, &store, Some(&j));
    assert_eq!(r, Ok(()));
    // Lane records before each step in journal order: block 1 holds exactly what 07 would.
    let mut before = Vec::new();
    let (mut n, mut nr) = (0, 0);
    for x in &j.recs {
        match x {
            OwnedRec::Packet(_) => n += 1,
            OwnedRec::Route(_) => nr += 1,
            OwnedRec::Step(..) => before.push((n, nr)),
        }
    }
    for k in 1..steps.len() {
        let (n, nr) = before[k];
        let b1 = (&lanes[..n], &routes[..nr], &steps[..k]);
        let b2 = (&lanes[n..], &routes[nr..], &steps[k..]);
        let (r, rep, left) = replay_blocks(&[b1, b2], &store, Some(&j));
        assert_eq!(r, Ok(()), "split at step {k}");
        assert_eq!(left, 0, "split at step {k}");
        // Carrying moves records relative to other lanes, never within a lane (07 §7.1).
        for l in 0..N as u8 {
            let pk = |x: &[OwnedRec]| {
                packets(x)
                    .filter(|p| p.lane.0 == l)
                    .copied()
                    .collect::<Vec<_>>()
            };
            assert!(
                pk(&rep.recs) == pk(&one.recs),
                "split at step {k}, lane {l}"
            );
        }
        let st = |x: &[OwnedRec]| {
            logical(x)
                .into_iter()
                .filter(|r| matches!(r, OwnedRec::Step(..)))
                .collect::<Vec<_>>()
        };
        assert!(st(&rep.recs) == st(&one.recs), "split at step {k}: steps");
        assert!(rep.tx == one.tx, "split at step {k}: fill TX");
    }
}

#[test]
fn replay_routes_a_post_only_cross_from_its_route_record() {
    // G12 (07 §3.6): a post-only buy @ 105 against ask 105 is a Cross. The lane forwards it and
    // the BBO core kills it (POST_ONLY_WOULD_CROSS, detail the live ask: 03 ARC-D6, 05 §2.4).
    // Both entry points must replay its route from the RouteRecord; without it the op replays
    // as a Join, which the lane applies itself: the divergence must be detected, not pass.
    use Side::{Buy, Sell};
    use Tif::Day;
    let po = vyrn_wire::Msg::New {
        flags: vyrn_wire::OrderFlags::from_byte(
            vyrn_bbo::OrderFlags::new(Buy, Day, true, vyrn_bbo::Stp::None).0,
        )
        .unwrap(),
        tick: vyrn_types::Tick(105),
        qty: vyrn_types::Qty(1),
        client_tag: 22,
    };
    let s = vec![
        Act::Pkt {
            l: 0,
            a: 1,
            rx_ts: 1_000,
            now: 1_000,
            msgs: vec![new(Sell, Day, 105, 1, 11)],
        },
        Act::Run,
        // A heartbeat-only packet takes no LaneSeq, so its record shares the next packet's
        // first_lane_seq; the route records belong to the next packet only.
        Act::Pkt {
            l: 0,
            a: 2,
            rx_ts: 1_500,
            now: 1_500,
            msgs: vec![vyrn_wire::Msg::Heartbeat],
        },
        Act::Pkt {
            l: 0,
            a: 2,
            rx_ts: 2_000,
            now: 2_000,
            msgs: vec![po, new(Buy, Day, 100, 1, 23), po],
        },
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    let routes: Vec<_> = j
        .recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Route(x) => Some(*x),
            _ => None,
        })
        .collect();
    let route = |q| vyrn_types::RouteRecord {
        lane: vyrn_types::LaneId(0),
        lane_seq: LaneSeq(q),
        cross: true,
    };
    // G12: every classified op has a route record; the two post-only crosses are the rejects.
    let cross: Vec<_> = routes.iter().filter(|x| x.cross).copied().collect();
    assert_eq!(cross, [route(2), route(4)]);
    let killed =
        j.tx.iter()
            .flat_map(|(_, r)| r)
            .filter(|r| {
                matches!(
                    r,
                    vyrn_bbo::Record::Reject {
                        reason: vyrn_types::RejectReason::PostOnlyWouldCross,
                        detail: 105,
                        ..
                    }
                )
            })
            .count();
    assert_eq!(
        killed, 2,
        "the BBO core kills both at the live ask: {:?}",
        j.tx
    );
    // Journal replay reproduces it, route record included.
    let (r, rep) = replay(&j.recs, &store);
    assert_eq!(r, Ok(()));
    assert!(logical(&rep.recs) == logical(&j.recs));
    let no_route: Vec<_> = j
        .recs
        .iter()
        .filter(|r| !matches!(r, OwnedRec::Route(x) if x.cross))
        .copied()
        .collect();
    // Without it the op replays as a Join: the step that names it finds no forwarded source.
    let r = replay_checked(&no_route, &store, &j).0;
    assert!(
        matches!(
            r,
            Err(Diverged {
                why: Why::Step(_) | Why::Response,
                ..
            })
        ),
        "{r:?}"
    );
    // 07 replay reproduces it from the RouteRecord, and detects its absence.
    let (lanes, wr, steps) = to_wire(&j.recs);
    let (r, rep) = replay_wire(&lanes, &wr, &steps, &store, Some(&j));
    assert_eq!(r, Ok(()));
    assert_eq!(rep.resp, j.resp);
    // Route records may come in any order (07 §3.6): they match their ops by lane_seq.
    let rev: Vec<_> = wr.iter().rev().copied().collect();
    assert_eq!(
        replay_wire(&lanes, &rev, &steps, &store, Some(&j)).0,
        Ok(())
    );
    let (r, _) = replay_wire(&lanes, &[], &steps, &store, Some(&j));
    assert!(r.is_err(), "{r:?}");
    // A missing, repeated or conflicting route record is refused.
    let without = |q| {
        wr.iter()
            .filter(|x| **x != route(q))
            .copied()
            .collect::<Vec<_>>()
    };
    let with = |x| wr.iter().copied().chain([x]).collect::<Vec<_>>();
    for bad in [
        without(4),
        with(route(4)),
        with(vyrn_types::RouteRecord {
            cross: false,
            ..route(4)
        }),
    ] {
        let (r, _) = replay_wire(&lanes, &bad, &steps, &store, Some(&j));
        assert!(r.is_err(), "{bad:?}: {r:?}");
    }
}

#[test]
fn replay_routes_a_forwarded_op_by_its_cross_bit_not_its_step_kind() {
    // #69: the live BBO copies the lane's route into StepEntry.flags (STEP_CROSS) and
    // replay_step compares it. Lanes 1 and 2 both see ask 105 in their snapshot and classify a
    // buy @ 105 as Cross. The first takes the ask; the second finds nothing left and rests, so
    // it logs as an Improve step with STEP_CROSS set. Replay must route it Cross from the bit.
    use Side::{Buy, Sell};
    use Tif::Day;
    let s = vec![
        Act::Pkt {
            l: 0,
            a: 1,
            rx_ts: 1_000,
            now: 1_000,
            msgs: vec![new(Sell, Day, 105, 1, 11)],
        },
        Act::Run,
        Act::Pkt {
            l: 1,
            a: 1,
            rx_ts: 2_000,
            now: 2_000,
            msgs: vec![new(Buy, Day, 105, 1, 21)],
        },
        Act::Pkt {
            l: 2,
            a: 1,
            rx_ts: 3_000,
            now: 3_000,
            msgs: vec![new(Buy, Day, 105, 1, 31)],
        },
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    assert!(
        steps(&j.recs)
            .any(|e| e.kind == StepKind::Improve.code() && e.flags & vyrn_bbo::STEP_CROSS != 0),
        "the script must log a Cross-classified op as an Improve step: {:?}",
        steps(&j.recs)
            .map(|e| (e.kind, e.flags))
            .collect::<Vec<_>>()
    );
    let (r, rep) = replay(&j.recs, &store);
    assert_eq!(r, Ok(()));
    assert_eq!(logical(&rep.recs), logical(&j.recs));
}

#[test]
fn replay_takes_the_logged_route_not_a_newer_snapshot() {
    // Found by #84: Sell 97 rests on lane 1, then one lane-0 packet holds Buy 98 and Buy 99.
    // The lane classifies both as Cross against its snapshot; Buy 98 takes the ask, so Buy 99
    // logs as an Improve step with STEP_CROSS. Replay must take that logged route (before
    // #86 it re-derived Improve and failed with Step(Kind)).
    use Side::{Buy, Sell};
    use Tif::Day;
    let s = vec![
        Act::Pkt {
            l: 1,
            a: 1,
            rx_ts: 1_000,
            now: 1_000,
            msgs: vec![new(Sell, Day, 97, 1, 11)],
        },
        Act::Run,
        Act::Pkt {
            l: 0,
            a: 1,
            rx_ts: 2_000,
            now: 2_000,
            msgs: vec![new(Buy, Day, 98, 1, 21), new(Buy, Day, 99, 1, 22)],
        },
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    let (r, rep) = replay_checked(&j.recs, &store, &j);
    assert_eq!(r, Ok(()));
    assert!(logical(&rep.recs) == logical(&j.recs));
    let (lanes, routes, steps) = to_wire(&j.recs);
    assert_eq!(
        replay_wire(&lanes, &routes, &steps, &store, Some(&j)).0,
        Ok(())
    );
}

#[test]
fn replay_from_07_does_not_count_session_only_messages_as_ops() {
    // Codex P1 on #66: a packet's `count` includes Heartbeat/ResendReq, which take no LaneSeq.
    // [Heartbeat, Sell @ 110] takes one LaneSeq and no step names it, so the block settles it;
    // counting two ops held it back and the step covering its one op failed with Order.
    use Side::Sell;
    use Tif::Day;
    let s = vec![
        Act::Pkt {
            l: 0,
            a: 1,
            rx_ts: 1_000,
            now: 1_000,
            msgs: vec![new(Sell, Day, 105, 1, 11)],
        },
        Act::Run,
        Act::Pkt {
            l: 1,
            a: 1,
            rx_ts: 2_000,
            now: 2_000,
            msgs: vec![vyrn_wire::Msg::Heartbeat, new(Sell, Day, 110, 1, 21)],
        },
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    let (lanes, routes, steps) = to_wire(&j.recs);
    let (r, _, carried) = replay_blocks(&[(&lanes, &routes, &steps)], &store, Some(&j));
    assert_eq!(r, Ok(()));
    assert_eq!(carried, 0);
}

#[test]
fn replay_from_07_routes_a_packet_whose_sources_span_two_blocks() {
    // G12 (07 §3.6): asks 97 and 98 rest on lane 1, then one lane-0 packet sends Buy 97 and
    // Buy 98. Both are forwarded Cross, and two steps name them. A block that ends between
    // those steps must not replay the packet with only the first op's route known. With a
    // RouteRecord for every classified op, every split reproduces the one-block replay.
    use Side::{Buy, Sell};
    use Tif::Day;
    let s = vec![
        Act::Pkt {
            l: 1,
            a: 1,
            rx_ts: 1_000,
            now: 1_000,
            msgs: vec![new(Sell, Day, 97, 1, 11), new(Sell, Day, 98, 1, 12)],
        },
        Act::Run,
        Act::Pkt {
            l: 0,
            a: 1,
            rx_ts: 2_000,
            now: 2_000,
            msgs: vec![new(Buy, Day, 97, 1, 21), new(Buy, Day, 98, 1, 22)],
        },
        Act::Run,
    ];
    let (j, store, _, _) = live(&s);
    let (lanes, routes, steps) = to_wire(&j.recs);
    // Two steps name ops of the same lane-0 packet.
    let srcs: Vec<_> = steps
        .iter()
        .filter_map(|w| w.2)
        .filter(|(l, _)| l.0 == 0)
        .collect();
    assert!(srcs.len() >= 2, "{srcs:?}");
    let (r, one) = replay_wire(&lanes, &routes, &steps, &store, Some(&j));
    assert_eq!(r, Ok(()));
    let mut before = Vec::new();
    let (mut n, mut nr) = (0, 0);
    for x in &j.recs {
        match x {
            OwnedRec::Packet(_) => n += 1,
            OwnedRec::Route(_) => nr += 1,
            OwnedRec::Step(..) => before.push((n, nr)),
        }
    }
    for k in 1..steps.len() {
        let (n, nr) = before[k];
        let b1 = (&lanes[..n], &routes[..nr], &steps[..k]);
        let b2 = (&lanes[n..], &routes[nr..], &steps[k..]);
        let (r, rep, left) = replay_blocks(&[b1, b2], &store, Some(&j));
        assert_eq!(r, Ok(()), "split at step {k}");
        assert_eq!(left, 0, "split at step {k}");
        assert!(rep.tx == one.tx, "split at step {k}: fill TX");
    }
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
fn a_join_dependency_matches_on_entry() {
    // vyrn-sim livelock (spec follow-up F4): lane 1 rests Sell 97; one lane-0 packet sends Buy
    // 98 (forwarded), Sell 97 (a join against the stale ask, so a Join dependency of the Buy
    // 101 after it) and Buy 101. Resting the dependency without matching left 98/97 crossed and
    // `Rescan` found nothing to do, forever. The sequential outcome (05 §3.7, the oracle) has
    // Sell 97 trade on entry. Expected records, by hand: (index, Fill or Ack, tick, qty).
    use Side::{Buy, Sell};
    use Tif::Day;
    use vyrn_bbo::Record;
    let run = |asks: Vec<vyrn_wire::Msg>, pkt: Vec<vyrn_wire::Msg>| {
        let p = |l, a, rx_ts, msgs| Act::Pkt {
            l,
            a,
            rx_ts,
            now: rx_ts,
            msgs,
        };
        let s = vec![
            p(1, 3, 1_000, asks),
            Act::Run,
            p(0, 1, 2_000, pkt),
            Act::Run,
        ];
        let (j, store, _, _) = live(&s);
        let (r, rep) = replay(&j.recs, &store);
        assert_eq!(r, Ok(()));
        assert_eq!(rep.tx, j.tx);
        j.tx.iter()
            .filter(|(h, _)| h.session == sid(0, 1))
            .flat_map(|(_, r)| r.iter())
            .filter_map(|r| match *r {
                Record::Fill {
                    index, tick, qty, ..
                } if index != vyrn_bbo::INDEX_MAKER => Some((index, 'F', tick.0, qty.0)),
                Record::Ack { index, tick, .. } => Some((index, 'A', tick.0, 0)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        run(
            vec![new(Sell, Day, 97, 7, 1)],
            vec![
                new(Buy, Day, 98, 18, 2),
                new(Sell, Day, 97, 18, 3),
                new(Buy, Day, 101, 1, 4),
            ]
        ),
        vec![
            (0, 'F', 97, 7),
            (0, 'A', 98, 0),
            (1, 'F', 98, 11),
            (1, 'A', 97, 0),
            (2, 'F', 97, 1),
        ]
    );
    // Two levels to cross: the dependency's sweep is capped (D14) and resumes in a CONT step.
    // Lane 1 also rests Sell 99, so Buy 99 is a Cross by every snapshot replay may show it.
    assert_eq!(
        run(
            vec![new(Sell, Day, 97, 7, 1), new(Sell, Day, 99, 1, 6)],
            vec![
                new(Buy, Day, 98, 18, 2),
                new(Buy, Day, 99, 2, 3),
                new(Sell, Day, 97, 18, 4),
                new(Buy, Day, 101, 1, 5),
            ]
        ),
        vec![
            (0, 'F', 97, 7),
            (0, 'A', 98, 0),
            (1, 'F', 99, 1),
            (1, 'A', 99, 0),
            (2, 'F', 99, 1),
            (2, 'F', 98, 11),
            (2, 'A', 97, 0),
            (3, 'F', 97, 1),
        ]
    );
    // A cancel between the capped dependency and its source stays out of the CONT steps' cut:
    // in index order Sell 97 sweeps the 11 at 98 before the Buy 98 is canceled (the cancel's
    // record is the lane's).
    assert_eq!(
        run(
            vec![new(Sell, Day, 97, 7, 1), new(Sell, Day, 99, 1, 6)],
            vec![
                new(Buy, Day, 98, 18, 2),
                new(Buy, Day, 99, 2, 3),
                new(Sell, Day, 97, 18, 4),
                cancel(Handle::new(1, 1).unwrap(), 7),
                new(Buy, Day, 101, 1, 5),
            ]
        ),
        vec![
            (0, 'F', 97, 7),
            (0, 'A', 98, 0),
            (1, 'F', 99, 1),
            (1, 'A', 99, 0),
            (2, 'F', 99, 1),
            (2, 'F', 98, 11),
            (2, 'A', 97, 0),
            (4, 'F', 97, 1),
        ]
    );
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
