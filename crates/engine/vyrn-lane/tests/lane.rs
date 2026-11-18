//! Lane conformance scenarios: real lanes and a real BBO core (05 §3, §6, §7, §8). Every
//! expected value is worked out by hand from the spec rule quoted in the test, not read back
//! from the code. A Vx oracle can replay the same packet streams and compare the same records.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod harness;

use harness::*;
use vyrn_bbo::mem::{MemBook, MemOrder};
use vyrn_bbo::{BookSource, FillKind, LIQ_TAKER, RESTED_DONE, RESTED_IN_FLIGHT, Record, Side};
use vyrn_lane::{Gate, LogRec, Mid, Rx};
use vyrn_types::{
    Handle, LaneSeq, Nanos, PacketFlags, PacketRecord, Qty, RejectReason, StepId, StepKind, Tick,
};
use vyrn_wire::Msg;

/// Lane 0, session 1 rests an ask of 5 @ 105 (an Improve, forwarded) and returns its handle.
fn ask_105(x: &mut Rig<'_>, bbo: &mut vyrn_bbo::Bbo) -> Handle {
    assert_eq!(
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 5, 11)]),
        Rx::Accepted
    );
    x.settle(bbo);
    x.last_ack(0, 1)
}

fn packets(x: &Rig<'_>, l: usize) -> Vec<PacketRecord> {
    x.log[l]
        .iter()
        .filter_map(|r| match r {
            LogRec::Packet(p) => Some(*p),
            LogRec::Route(_) => None,
        })
        .collect()
}

#[test]
fn rule_f_fwd_pend_is_the_floor_until_the_first_step_event() {
    // 05 §3.3: fwd_pend bounds the BBO's dependency floor; rule F: an entry stays pending until
    // B1 applies an event of its first step. One forwarded New, no deps: floor = its LaneSeq 1.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 5, 11)]);
    assert_eq!(x.counter(0).fwd_pend, LaneSeq(1));
    let s = x.bbo_step(&mut bbo).unwrap();
    assert_eq!(StepKind::from_code(s.entry.kind), Some(StepKind::Improve));
    // The step ran but the lane has not applied it: still pending (not derived from FwdCons).
    assert_eq!(x.counter(0).fwd_pend, LaneSeq(1));
    x.lane_poll(0);
    assert_eq!(x.counter(0).fwd_pend, LaneSeq(0));
    assert_eq!(x.counter(0).f_lo, 1);
    // The Ack of a forwarded source is the fill TX core's (05 §8.10 rule 1), resp_seq 1.
    assert_eq!(
        x.packets(0, 1),
        vec![(
            1,
            vec![Record::Ack {
                index: 0,
                handle: Handle::new(1, 1).unwrap(),
                tick: Tick(105),
                client_tag: 11
            }]
        )]
    );
}

#[test]
fn a_local_join_is_acked_only_after_the_first_cut_that_covers_it() {
    // INV-ACK-AFTER-CUT (05 §7.6): the lane settles op q at the first boundary (f, C_f) with
    // C_f ≥ q, and its packet is gated on step f.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    // Sell 3 @ 110 ≥ ask 105: not an improve, so a local join (05 §6.5), LaneSeq 2.
    assert_eq!(
        x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]),
        Rx::Accepted
    );
    assert!(
        x.records(0, 2).is_empty(),
        "no Ack before a cut covers LaneSeq 2"
    );
    x.settle(&mut bbo);
    let pk: Vec<_> = x.resp[0]
        .iter()
        .filter(|p| p.session == sid(0, 2))
        .collect();
    assert_eq!(pk.len(), 1);
    let Gate::Step(f) = pk[0].gate else {
        panic!("{:?}", pk[0].gate)
    };
    let first = x.steps.iter().find(|s| s.cuts[0] >= LaneSeq(2)).unwrap();
    assert_eq!(
        f, first.entry.step,
        "gated on the first step whose cut covers it"
    );
    assert_eq!(
        pk[0].records(),
        &[Record::Ack {
            index: 0,
            handle: Handle::new(2, 1).unwrap(),
            tick: Tick(110),
            client_tag: 12
        }]
    );
}

#[test]
fn a_cross_with_a_join_dependency_and_the_index_follow_up() {
    // Lane 1 packet [sell 1 @ 106, buy 3 @ 106]. The buy crosses ask 105 (05 §6.5); the sell is
    // in its range (≥ … ≤ 106 for a buy taker), so it becomes a Join dependency with back 1
    // (05 §6.6). The deps packet takes resp_seq 1, the source's resp_seq 2 (§8.10 rule 1).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(
        1,
        1,
        3_000,
        &[
            new(day(Side::Sell), 106, 1, 21),
            new(day(Side::Buy), 106, 3, 22),
        ],
    );
    // Floor = source LaneSeq 2 − back 1 = 1 (rule F).
    assert_eq!(x.counter(1).fwd_pend, LaneSeq(1));
    x.settle(&mut bbo);
    assert_eq!(x.counter(1).fwd_pend, LaneSeq(0));
    assert_eq!(
        x.packets(1, 1),
        vec![
            (
                1,
                vec![Record::Ack {
                    index: 0,
                    handle: Handle::new(1, 1).unwrap(),
                    tick: Tick(106),
                    client_tag: 21
                }]
            ),
            (
                2,
                vec![Record::Fill {
                    index: 1,
                    liq: 1,
                    handle: Handle::new(2, 1).unwrap(),
                    tick: Tick(105),
                    qty: Qty(3)
                }]
            ),
        ]
    );
    assert_eq!(
        x.maker_records(0, 1),
        vec![Record::Fill {
            index: 0xFF,
            liq: 0,
            handle: Handle::new(1, 1).unwrap(),
            tick: Tick(105),
            qty: Qty(3)
        }]
    );
}

#[test]
fn pin_fwddep_index_is_source_minus_back_across_a_session_only_message() {
    // Spec follow-up: FwdDep has no message index, so the dependency's record index is
    // `source index − back`. With a Heartbeat (no LaneSeq, 05 §3.1) between them the true index
    // is 0, but 2 − 1 = 1 is reported. This pins today's behaviour; fix the spec, then flip it.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(
        1,
        1,
        3_000,
        &[
            new(day(Side::Sell), 106, 1, 21),
            Msg::Heartbeat,
            new(day(Side::Buy), 106, 3, 22),
        ],
    );
    x.settle(&mut bbo);
    let p = x.packets(1, 1);
    assert!(
        matches!(
            p[0].1[0],
            Record::Ack {
                index: 1,
                client_tag: 21,
                ..
            }
        ),
        "{p:?}"
    );
    assert!(matches!(p[1].1[0], Record::Fill { index: 2, .. }), "{p:?}");
}

#[test]
fn a_join_dependency_in_range_is_matched_in_the_cont_step() {
    // Lane 1 packet [sell 1 @ 106, buy 6 @ 106]. The sequential spec (05 §2.3) rests the sell
    // first, then the buy matches 5 @ 105 and 1 @ 106 (its own packet's sell). The engine: the
    // source's step takes the 105 level (one level per step, D14) while the dependency rests
    // (§8.5); the CONT step then fills the dependency. Same trades as §2.3. The CONT records are
    // TX-core packets without a reservation (MakerSeq, §8.10 rule 2).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(
        1,
        1,
        3_000,
        &[
            new(day(Side::Sell), 106, 1, 21),
            new(day(Side::Buy), 106, 6, 22),
        ],
    );
    x.settle(&mut bbo);
    let (dep, src) = (Handle::new(1, 1).unwrap(), Handle::new(2, 1).unwrap());
    assert_eq!(
        x.records(1, 1),
        vec![
            Record::Ack {
                index: 0,
                handle: dep,
                tick: Tick(106),
                client_tag: 21
            },
            Record::Fill {
                index: 1,
                liq: 1,
                handle: src,
                tick: Tick(105),
                qty: Qty(5)
            },
        ]
    );
    assert_eq!(
        x.maker_records(1, 1),
        vec![
            Record::Fill {
                index: 1,
                liq: 1,
                handle: src,
                tick: Tick(106),
                qty: Qty(1)
            },
            Record::Fill {
                index: 0xFF,
                liq: 0,
                handle: dep,
                tick: Tick(106),
                qty: Qty(1)
            },
        ]
    );
}

/// The multi-step batch taker of rule B: lane 1 joins a buy of 20 @ 103 against a stale
/// snapshot (bid 105) while lane 0 has 8 one-lot asks @ 102 and one @ 103. Returns the rig
/// state after the join's packet; `extra` runs between the Rescan and its first CONT step.
fn batch(
    x: &mut Rig<'_>,
    bbo: &mut vyrn_bbo::Bbo,
    extra: impl FnOnce(&mut Rig<'_>, &mut vyrn_bbo::Bbo),
) -> Handle {
    x.send(2, 1, 100, &[new(day(Side::Buy), 105, 1, 1)]);
    x.settle(bbo);
    x.hold[1] = true; // lane 1 keeps the snapshot with bid 105
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
    // Buy 103 ≤ stale bid 105: a local join (05 §6.5), LaneSeq 1 of lane 1.
    assert_eq!(
        x.send(1, 1, 500, &[new(day(Side::Buy), 103, 20, 77)]),
        Rx::Accepted
    );
    // Lane 0 cancels the ask @ 103 later (key ts 600 > 500).
    x.send(0, 9, 600, &[cancel(ninth, 99)]);
    let r = x.bbo_step(bbo).unwrap();
    assert_eq!(StepKind::from_code(r.entry.kind), Some(StepKind::Rescan));
    for l in 0..N {
        x.lane_poll(l);
    }
    extra(x, bbo);
    x.settle(bbo);
    ninth
}

#[test]
fn rule_b_a_batch_taker_spanning_three_steps() {
    // 05 D14: a sweep stops after ENG_STEP_FILLS = 8 fills or one level. Step s: 8 × 1 @ 102,
    // capped (RESTED_IN_FLIGHT, 12 open). CONT s+1: 1 @ 103, level done (RESTED_IN_FLIGHT, 11).
    // CONT s+2: nothing left within 103 (RESTED_DONE, 11).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    batch(&mut x, &mut bbo, |_, _| {});
    let st: Vec<_> = x
        .steps
        .iter()
        .filter(|s| s.events.iter().any(|(l, e)| *l == 1 && e.liq == LIQ_TAKER))
        .collect();
    let status: Vec<Vec<(u16, u32)>> = st
        .iter()
        .map(|s| {
            s.of(FillKind::Rested)
                .iter()
                .filter(|(l, _)| *l == 1)
                .map(|(_, e)| (e.cause, e.qty))
                .collect()
        })
        .collect();
    assert_eq!(
        status,
        vec![
            vec![(RESTED_IN_FLIGHT, 12)],
            vec![(RESTED_IN_FLIGHT, 11)],
            vec![(RESTED_DONE, 11)]
        ]
    );
    let s = st[0].entry.step;
    // 05 §8.10 rule 4.1: the liq = 1 events of the version a settle created precede its record;
    // rule B holds the Ack until the taker is done, so each step's fills go out at that step's
    // boundary (rule 4.2) and the Ack last, resting 20 − 9 = 11 @ 103 (04 R-ACK).
    let pk: Vec<_> = x.resp[1]
        .iter()
        .filter(|p| p.session == sid(1, 1))
        .collect();
    let got: Vec<(u32, Gate, Vec<Record>)> = pk
        .iter()
        .map(|p| (p.resp_seq, p.gate, p.records().to_vec()))
        .collect();
    let h = Handle::new(1, 1).unwrap();
    assert_eq!(
        got,
        vec![
            (
                1,
                Gate::Step(s),
                vec![Record::Fill {
                    index: 0,
                    liq: 1,
                    handle: h,
                    tick: Tick(102),
                    qty: Qty(8)
                }]
            ),
            (
                2,
                Gate::Step(StepId(s.0 + 1)),
                vec![Record::Fill {
                    index: 0,
                    liq: 1,
                    handle: h,
                    tick: Tick(103),
                    qty: Qty(1)
                }]
            ),
            (
                3,
                Gate::Step(StepId(s.0 + 2)),
                vec![Record::Ack {
                    index: 0,
                    handle: h,
                    tick: Tick(103),
                    client_tag: 77
                }]
            ),
        ]
    );
    // The cancel keyed after the taker stays out of the cuts until it is done (bbo febe805), so
    // lane 0 sees the fill first and answers TOO_LATE (filled), with no hold of its own.
    assert_eq!(
        x.records(0, 9)[1],
        Record::Reject {
            index: 0,
            reason: RejectReason::TooLate,
            detail: vyrn_lane::lane::PROTO_D_FILLED,
            client_tag: 99
        }
    );
    assert_eq!(x.maker_records(0, 9).len(), 1);
    // Lane 1 has applied the last step with its events; later steps carry no work for it, so
    // no boundary is due (rule G).
    assert_eq!(x.fills_applied(1), st[2].entry.step);
}

#[test]
fn rule_f_holds_a_forward_sent_while_a_batch_taker_is_in_flight() {
    // While the taker is in flight lane 1 forwards an IOC buy of 1 @ 50 (IOC is always Cross,
    // 05 §6.5; LaneSeq 2, floor 2). Its key is after the taker's, so the BBO's cut keeps it out
    // until the taker is done; fwd_pend stays 2 until its own step's event (rule F). Nothing
    // asks ≤ 50, so it ends Out IOC_REST.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    let mut seen = Vec::new();
    batch(&mut x, &mut bbo, |x, bbo| {
        x.send(1, 2, 550, &[new(ioc(Side::Buy), 50, 1, 5)]);
        seen.push(x.counter(1).fwd_pend);
        let c = x.bbo_step(bbo).unwrap();
        assert_eq!(c.entry.flags & 1, 1, "a CONT step of the taker");
        x.lane_poll(1);
        seen.push(x.counter(1).fwd_pend);
    });
    assert_eq!(seen, vec![LaneSeq(2), LaneSeq(2)]);
    assert_eq!(x.counter(1).fwd_pend, LaneSeq(0));
    assert!(
        matches!(x.records(1, 2)[..], [Record::Out { index: 0, .. }]),
        "{:?}",
        x.records(1, 2)
    );
    // The taker's records are unchanged by the forward in between.
    assert_eq!(x.records(1, 1).len(), 3);
}

#[test]
fn the_same_streams_give_the_same_bytes() {
    // INV-DET: two runs of one scenario produce identical responses, logs and steps.
    let run = || {
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        batch(&mut x, &mut bbo, |x, _| {
            x.send(1, 2, 550, &[new(ioc(Side::Buy), 50, 1, 5)]);
        });
        format!("{:?}{:?}{:?}", x.resp, x.log, x.steps)
    };
    assert_eq!(run(), run());
}

#[test]
fn deadline_admission_at_the_threshold() {
    // 05 §6.8, 01 §14.17.1: late iff age + path(n, class) > LAT_MAX_NS − DEADLINE_GUARD_NS =
    // 1000 − 20 = 980. One New (Order class): path = max(510 + 5, 505 + 14) = 519, so at
    // dequeue age 461 is on time and age 462 is late.
    let (_bbo, mut w) = setup();
    let mut x = w.rig();
    let m = [new(day(Side::Sell), 300, 1, 9)];
    assert_eq!(x.send_at(0, 1, 10_000, 10_462, &m, &[]), Rx::Shed);
    assert_eq!(
        x.lanes[0].seq(),
        LaneSeq(1),
        "a shed packet keeps its LaneSeqs (07 §3.5)"
    );
    assert_eq!(
        x.records(0, 1),
        vec![Record::Reject {
            index: 0,
            reason: RejectReason::Busy,
            detail: 1,     // 04 §3.5: the session's `expected`; a BBO shed has 0
            client_tag: 0  // 04 §3.5, 05 §18 Q17: from the record alone, not the message's tag 9
        }]
    );
    let p = packets(&x, 0);
    assert_eq!(p[0].flags, PacketFlags::SHED);
    assert_eq!(p[0].first_lane_seq, LaneSeq(1));
    assert_ne!(
        p[0].pkt_hash,
        vyrn_types::PktHash(0),
        "hashed (07 §3.6), not joined"
    );
    // The client resends the same pkt_seq; on time now. It takes the next LaneSeq.
    assert_eq!(x.send_at(0, 1, 20_000, 20_461, &m, &[]), Rx::Accepted);
    assert_eq!(x.lanes[0].seq(), LaneSeq(2));
    let q = packets(&x, 0);
    assert_eq!(q[1].pkt_seq, p[0].pkt_seq);
    assert_eq!(q[1].first_lane_seq, LaneSeq(2));
}

/// The 04 §11 vector V22's records, from `tests/golden/vyrn_proto_vectors.out`.
fn v22_records() -> Vec<[u8; 16]> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/golden/vyrn_proto_vectors.out"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut bytes = Vec::new();
    let mut on = false;
    for line in text.lines() {
        if line.starts_with('V') || line.starts_with("check") {
            on = line.starts_with("V22 ");
        } else if let (true, Some((_, hex))) = (on, line.trim().split_once(": ")) {
            bytes.extend(hex.split(' ').map(|h| u8::from_str_radix(h, 16).unwrap()));
        }
    }
    let n = usize::from(bytes[8]);
    bytes[16..16 + 16 * n]
        .chunks(16)
        .map(|c| c.try_into().unwrap())
        .collect()
}

#[test]
fn a_shed_new_and_heartbeat_answer_v22_byte_for_byte() {
    // 04 §3.5, §11 V21/V22: the lane sheds `pkt_seq` 7 (a New and a Heartbeat) with `expected` = 7.
    // Its BUSY run has one record per message, the Heartbeat's included, each with detail 7 and
    // `client_tag` 0, so its record bytes are V22's whatever the session or keys.
    let (_bbo, mut w) = setup();
    let mut x = w.rig();
    for i in 0..6u64 {
        let t = 1_000 + 1_000 * i;
        assert_eq!(x.send(0, 1, t, &[Msg::Heartbeat]), Rx::Accepted);
    }
    let m = [
        new(day(Side::Sell), 100_005, 1, 0x9999_9999),
        Msg::Heartbeat,
    ];
    assert_eq!(x.send_at(0, 1, 10_000, 20_000, &m, &[]), Rx::Shed);
    let last = x.packets(0, 1).pop().unwrap().1;
    let got: Vec<[u8; 16]> = last.iter().map(Record::encode).collect();
    assert_eq!(got, v22_records());
    let p = packets(&x, 0);
    let shed = p.last().unwrap();
    assert_eq!(
        (shed.flags, shed.pkt_seq, shed.count),
        (PacketFlags::SHED, 7, 2)
    );
}

/// Lane 1 crosses lane 0's ask; the BBO runs the step but lane 0 has not applied it. Lane 0 then
/// sends `[sell 1 @ 110, sell 1 @ 111]` (LaneSeq 2, 3) with `mids`. Returns lane 0's log.
fn mid_run(mids: impl Fn(vyrn_cut::LaneCutEntry) -> Vec<Mid>) -> (StepId, Vec<PacketRecord>) {
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(1, 1, 2_000, &[new(day(Side::Buy), 105, 2, 1)]);
    let cross = x.bbo_step(&mut bbo).unwrap().entry.step;
    let at = x.lane_cut(0);
    assert_eq!(at.step, cross);
    assert!(
        x.lanes[0].fills_applied() < cross,
        "lane 0 has not applied the cross"
    );
    let n = packets(&x, 0).len();
    let m = [
        new(day(Side::Sell), 110, 1, 2),
        new(day(Side::Sell), 111, 1, 3),
    ];
    assert_eq!(x.send_at(0, 2, 3_000, 3_000, &m, &mids(at)), Rx::Accepted);
    (cross, packets(&x, 0).split_off(n))
}

#[test]
fn mid_packet_boundaries_land_before_the_named_op() {
    // 05 §6.2: a boundary inside a packet is logged as an Advance record with MID (and PASS2 in
    // pass 2) whose first_lane_seq is the op it precedes.
    let adv = PacketFlags::ADVANCE | PacketFlags::MID;
    let (cross, p1) = mid_run(|at| {
        vec![Mid {
            pass: 1,
            next: LaneSeq(3),
            at,
        }]
    });
    assert_eq!(p1.len(), 2);
    assert_eq!((p1[0].count, p1[0].first_lane_seq), (2, LaneSeq(2)));
    assert_eq!((p1[1].flags, p1[1].first_lane_seq), (adv, LaneSeq(3)));
    assert_eq!(
        p1[1].fills_applied, cross,
        "the boundary applied the cross step"
    );
    let (_, p2) = mid_run(|at| {
        vec![Mid {
            pass: 2,
            next: LaneSeq(2),
            at,
        }]
    });
    assert_eq!(
        (p2[1].flags, p2[1].first_lane_seq),
        (adv | PacketFlags::PASS2, LaneSeq(2))
    );
    // Off by one: no op 4 in this packet, so no boundary runs inside it.
    let (_, p3) = mid_run(|at| {
        vec![Mid {
            pass: 1,
            next: LaneSeq(4),
            at,
        }]
    });
    assert_eq!(p3.len(), 1);
}

/// Every live or pending position of one level, as `(slot, qty, prio_ts, active)`, by walking
/// the FIFO through any `BookSource`.
fn level<B: BookSource>(b: &B, side: Side, tick: u32) -> Vec<(u32, u32, u64, bool)> {
    let mut out = Vec::new();
    let mut seg = b.head(lid(0), side, Tick(tick));
    while seg != 0 {
        let s = b.segment(lid(0), seg).unwrap();
        for i in 0..16 {
            let (a, p) = (s.mask >> i & 1 == 1, s.mask >> (16 + i) & 1 == 1);
            if a || p {
                out.push((s.slot[i], s.qty[i], s.base_ts.0 + u64::from(s.dts[i]), a));
            }
        }
        seg = s.succ;
    }
    out
}

#[test]
fn lane_book_reads_like_mem_book() {
    // The same ops on lane 0, applied by the lane to its arena and by hand to MemBook (the
    // reference BookSource): one forwarded ask @ 105, three local joins @ 110, a cancel of the
    // second. Both books must read the same through BookSource.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    for (a, ts) in [(2u32, 2_000u64), (3, 2_100), (4, 2_200)] {
        x.send(0, a, ts, &[new(day(Side::Sell), 110, a, a)]);
    }
    x.settle(&mut bbo);
    let second = x.last_ack(0, 3);
    x.send(0, 3, 2_300, &[cancel(second, 33)]);
    x.settle(&mut bbo);

    let mut m = MemBook::new(N);
    let o = |seq: u64, ts: u64, qty: u32, a: u32, tick: u32| MemOrder {
        flags: day(Side::Sell),
        tick: Tick(tick),
        qty,
        seq: LaneSeq(seq),
        ts: Nanos(ts),
        acct_ix: a,
        session: sid(0, a),
        client_tag: if a == 1 { 11 } else { a },
    };
    let s1 = m.new_slot(lid(0), &o(1, 1_000, 5, 1, 105));
    m.place(lid(0), s1);
    let s2 = m.rest(lid(0), &o(2, 2_000, 2, 2, 110));
    let s3 = m.rest(lid(0), &o(3, 2_100, 3, 3, 110));
    let s4 = m.rest(lid(0), &o(4, 2_200, 4, 4, 110));
    m.tombstone(lid(0), s3, LaneSeq(5), Nanos(2_300));
    assert_eq!((s1, s2, s3, s4), (1, 2, 3, 4));

    let lb = vyrn_lane::LaneBook::new(&x.views);
    for t in [105, 110] {
        assert_eq!(
            level(&lb, Side::Sell, t),
            level(&m, Side::Sell, t),
            "level {t}"
        );
    }
    for s in 1..=4 {
        assert_eq!(lb.slot(lid(0), s), m.slot(lid(0), s), "slot {s}");
        assert_eq!(lb.session(lid(0), s), m.session(lid(0), s));
        assert_eq!(lb.client_tag(lid(0), s), m.client_tag(lid(0), s));
    }
    let j = |b: &dyn Fn(&mut Vec<vyrn_bbo::JEnt>)| {
        let mut v = Vec::new();
        b(&mut v);
        v
    };
    assert_eq!(
        j(&|v| lb.journal(lid(0), LaneSeq(0), LaneSeq(5), |e| v.push(e))),
        j(&|v| m.journal(lid(0), LaneSeq(0), LaneSeq(5), |e| v.push(e)))
    );
    for t in [104, 105, 109, 110, 111] {
        assert_eq!(
            lb.occ(Side::Sell, Tick(t)),
            m.occ(Side::Sell, Tick(t)),
            "occ {t}"
        );
        assert_eq!(
            lb.occ_next(Side::Sell, Tick(t)),
            m.occ_next(Side::Sell, Tick(t))
        );
        assert_eq!(
            lb.lane_next(lid(0), Side::Sell, Tick(t)),
            m.lane_next(lid(0), Side::Sell, Tick(t))
        );
    }
}

fn base_resv(x: &mut Rig<'_>, l: usize, a: u32) -> u64 {
    x.lanes[l]
        .account_mut(vyrn_risk::AcctSlot(a))
        .unwrap()
        .1
        .base_resv
}

/// Active positions of lane 0's level, as slots.
fn active(x: &Rig<'_>, side: Side, tick: u32) -> Vec<u32> {
    let lb = vyrn_lane::LaneBook::new(&x.views);
    level(&lb, side, tick)
        .into_iter()
        .filter(|p| p.3)
        .map(|p| p.0)
        .collect()
}

fn replace(h: Handle, side: Side, tick: u32, qty: u32) -> Msg {
    Msg::Replace {
        flags: wire_flags(day(side)),
        handle: h,
        tick: Tick(tick),
        qty: Qty(qty),
    }
}

#[test]
fn a_chain_of_two_pending_replaces_ends_each_predecessor() {
    // Codex P1: sell 3 @ 110 (local, under ask 105), then one packet replaces it to 104 and
    // to 103 (both improve on ask 105, forwarded). 05 §2.3: each replace ends the version
    // before it, so only the order @ 103 is live and only its 3 lots are reserved.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 2);
    x.send(
        0,
        2,
        3_000,
        &[
            replace(h, Side::Sell, 104, 3),
            replace(h, Side::Sell, 103, 3),
        ],
    );
    x.settle(&mut bbo);
    assert!(active(&x, Side::Sell, 110).is_empty(), "v0 ended");
    assert!(active(&x, Side::Sell, 104).is_empty(), "v1 ended");
    assert_eq!(active(&x, Side::Sell, 103).len(), 1);
    assert_eq!(base_resv(&mut x, 0, 2), 3);
}

#[test]
fn a_replace_that_fills_completely_releases_its_predecessor() {
    // Vercel: lane 1 bids 3 @ 100; lane 0 rests sell 3 @ 110, then replaces it to sell 3 @ 100
    // (a Cross, forwarded). It fills 3 and never rests or goes out; the old version still ends
    // at the replace (05 §2.3), so nothing stays reserved or visible.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.send(1, 1, 500, &[new(day(Side::Buy), 100, 3, 1)]);
    x.settle(&mut bbo);
    x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 2);
    x.send(0, 2, 3_000, &[replace(h, Side::Sell, 100, 3)]);
    x.settle(&mut bbo);
    assert!(
        x.records(0, 2)
            .iter()
            .any(|r| matches!(r, Record::Fill { qty: Qty(3), .. }))
    );
    assert!(active(&x, Side::Sell, 110).is_empty());
    assert_eq!(base_resv(&mut x, 0, 2), 0);
}

#[test]
fn a_replace_after_partial_fills_reserves_only_what_can_still_trade() {
    // Codex P1: sell 10 @ 106 (improve), lane 1 buys 4. A local Replace to 10 @ 107 leaves
    // 10 − 4 = 6 open (05 §2.3: qty' counts the fills). Lane 1 buys 6 @ 107: the order is
    // filled, so nothing stays reserved (10 §4.4).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.send(0, 2, 1_000, &[new(day(Side::Sell), 106, 10, 12)]);
    x.settle(&mut bbo);
    x.send(1, 1, 2_000, &[new(day(Side::Buy), 106, 4, 1)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 2);
    x.send(0, 2, 3_000, &[replace(h, Side::Sell, 107, 10)]);
    x.settle(&mut bbo);
    assert_eq!(base_resv(&mut x, 0, 2), 6);
    x.send(1, 2, 4_000, &[new(day(Side::Buy), 107, 6, 2)]);
    x.settle(&mut bbo);
    assert_eq!(base_resv(&mut x, 0, 2), 0);
}

#[test]
fn fills_before_a_pending_reduce_are_counted_against_the_version_that_traded() {
    // Codex P1: sell 10 @ 106; lane 1 buys 6 (step runs); lane 0 then reduces by 4 before it
    // has applied that step (no boundary inside the packet). Sequentially the 6 fills come
    // first, so the reduce by 4 = the open 4 ends the order: CancelAck 4 (04 §6.4), and
    // nothing stays reserved.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.send(0, 1, 1_000, &[new(day(Side::Sell), 106, 10, 11)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 1);
    x.send(1, 1, 2_000, &[new(day(Side::Buy), 106, 6, 1)]);
    x.bbo_step(&mut bbo).unwrap();
    let at = x.lane_cut(0);
    let none = [Mid {
        pass: 1,
        next: LaneSeq(99),
        at,
    }];
    let m = [Msg::Reduce {
        handle: h,
        by: Qty(4),
        client_tag: 44,
    }];
    assert_eq!(x.send_at(0, 1, 3_000, 3_000, &m, &none), Rx::Accepted);
    x.settle(&mut bbo);
    assert_eq!(
        x.records(0, 1).last(),
        Some(&Record::CancelAck {
            index: 0,
            handle: h,
            canceled: Qty(4),
            client_tag: 44
        })
    );
    assert_eq!(base_resv(&mut x, 0, 1), 0);
}

#[test]
fn a_second_cancel_all_keeps_the_first_kill_as_tombstones() {
    // Codex P1, 05 §4.7: one session per account, so CancelAll #1 (LaneSeq 2) is an AcctKill.
    // Before CancelAll #2 (LaneSeq 3) overwrites it, every order the first one covered gets
    // its tombstone at LaneSeq 2, also the ones B2 already ended.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(0, 1, 2_000, &[Msg::CancelAll { client_tag: 1 }]);
    x.settle(&mut bbo);
    x.send(0, 1, 3_000, &[Msg::CancelAll { client_tag: 2 }]);
    let lb = vyrn_lane::LaneBook::new(&x.views);
    assert_eq!(lb.slot(lid(0), 1).unwrap().tomb_seq, LaneSeq(2));
    assert_eq!(lb.acct_kill(lid(0), 1).kill_seq, LaneSeq(3));
}

#[test]
fn canceling_a_pending_replace_writes_one_journal_entry() {
    // Vercel, 05 §4.9 (one entry per independent op). Seqs: 1 ask_105 (forwarded), 2 local
    // join @ 110, 3 Replace to 104 (forwarded), 4 its Cancel (local), 5 local join @ 120. The
    // journal holds 2, 4, 5, and a reader sees all three.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 2);
    x.send(
        0,
        2,
        3_000,
        &[replace(h, Side::Sell, 104, 3), cancel(h, 13)],
    );
    x.send(0, 3, 3_100, &[new(day(Side::Sell), 120, 1, 14)]);
    let lb = vyrn_lane::LaneBook::new(&x.views);
    let mut seqs = Vec::new();
    lb.journal(lid(0), LaneSeq(0), LaneSeq(5), |j| seqs.push(j.seq.0));
    assert_eq!(seqs, vec![2, 4, 5]);
}

#[test]
fn pooled_lanes_hand_the_bbo_the_pool_wide_account_index() {
    // 05 §6.9: STP across the pool compares the pool-wide account index. Lanes 0 and 1 are
    // pooled; lane 0's account 1 and lane 1's account 2 are one pooled account, index 7. Lane 0
    // rests sell 1 @ 105; lane 1 sends a CancelNewest buy 1 @ 105. Same account: Reject STP with
    // the resting handle, no trade (04 §6.8). With lane-local indices (1 and 2) they would trade.
    let run = |pool_ix: bool| {
        let (mut bbo, mut w) = setup_pool(0b011);
        let mut x = w.rig();
        if pool_ix {
            assert!(x.lanes[0].set_pool_index(vyrn_risk::AcctSlot(1), 7));
            assert!(x.lanes[1].set_pool_index(vyrn_risk::AcctSlot(2), 7));
        }
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 1, 11)]);
        x.settle(&mut bbo);
        let f = vyrn_bbo::OrderFlags::new(
            Side::Buy,
            vyrn_bbo::Tif::Day,
            false,
            vyrn_bbo::Stp::CancelNewest,
        );
        x.send(1, 2, 2_000, &[new(f, 105, 1, 22)]);
        x.settle(&mut bbo);
        let lb = vyrn_lane::LaneBook::new(&x.views);
        let ix = lb.slot(lid(0), 1).unwrap().acct_ix;
        (ix, x.records(1, 2))
    };
    let (ix, taker) = run(true);
    assert_eq!(ix, 7, "OrderSlot.acct_ix is the pool-wide index");
    // The resting order is lane 0's slot 1; the taker is lane 1's slot 1.
    assert_eq!(
        taker,
        vec![Record::Reject {
            index: 0,
            reason: RejectReason::Stp,
            detail: Handle::new(1, 1).unwrap().0,
            client_tag: 22
        }]
    );
    let (ix, taker) = run(false);
    assert_eq!(ix, 1);
    assert!(
        taker.iter().any(|r| matches!(r, Record::Fill { .. })),
        "control: {taker:?}"
    );
}

#[test]
fn a_cancel_after_reject_stp_is_too_late_with_detail_out() {
    // 04 §6.8, §6.4: a CancelNewest aggressor that meets its own resting order before any fill
    // gets `Reject STP`, but the order was in the matching step and the exchange ended it, so a
    // later `Cancel` of its handle is `TOO_LATE` with `PROTO_D_OUT` (3), as the vx oracle's
    // `stp_end` records (END_OUT), not `PROTO_D_CANCELED` (2).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.open(0, 30, 1, vyrn_risk::SessionBuckets::default());
    x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 1, 11)]);
    x.settle(&mut bbo);
    let f = vyrn_bbo::OrderFlags::new(
        Side::Buy,
        vyrn_bbo::Tif::Day,
        false,
        vyrn_bbo::Stp::CancelNewest,
    );
    x.send(0, 30, 2_000, &[new(f, 105, 1, 22)]);
    x.settle(&mut bbo);
    let taker = Handle::new(2, 1).unwrap();
    assert_eq!(
        x.records(0, 30),
        vec![Record::Reject {
            index: 0,
            reason: RejectReason::Stp,
            detail: Handle::new(1, 1).unwrap().0,
            client_tag: 22
        }]
    );
    x.send(0, 30, 3_000, &[cancel(taker, 33)]);
    x.settle(&mut bbo);
    assert_eq!(
        x.records(0, 30)[1],
        Record::Reject {
            index: 0,
            reason: RejectReason::TooLate,
            detail: vyrn_lane::lane::PROTO_D_OUT,
            client_tag: 33
        }
    );
}

#[test]
fn a_replayed_log_reproduces_the_original_forwarding() {
    // 05 §10: in replay, op (l, q) is forwarded iff a StepRecord has src = (l, q). Original run:
    // with no ask, sell 5 @ 110 improves and is forwarded (05 §6.5): Improve step, src (0, 1).
    // Replay: lane 0's snapshot says ask 100, so classify would make the sell a local join; the
    // forced route still forwards it, and the step and records are the original's.
    let original = {
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 110, 5, 11)]);
        x.settle(&mut bbo);
        let s = x.steps[0].entry;
        ((s.kind, s.src_lane.0, s.src_lane_seq), x.records(0, 1))
    };
    assert_eq!(original.0, (StepKind::Improve.code(), 0, LaneSeq(1)));
    let doctored = |x: &Rig<'_>| vyrn_cut::Snapshot {
        ask: Tick(100),
        ..x.snapshot()
    };
    // Control: the live path on the doctored snapshot keeps the op local.
    {
        let (_bbo, mut w) = setup();
        let mut x = w.rig();
        let s = doctored(&x);
        x.pin_snapshot(0, &s);
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 110, 5, 11)]);
        assert_eq!(x.counter(0).fwd_pend, LaneSeq(0), "classified local");
    }
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    let s = doctored(&x);
    x.pin_snapshot(0, &s);
    let r = x.replay(
        0,
        1,
        1_000,
        &[new(day(Side::Sell), 110, 5, 11)],
        &[],
        &[(LaneSeq(1), vyrn_risk::Route::Improve)],
    );
    assert_eq!(r, Rx::Accepted);
    assert_eq!(x.counter(0).fwd_pend, LaneSeq(1), "forwarded");
    x.settle(&mut bbo);
    let s = x.steps[0].entry;
    assert_eq!(
        ((s.kind, s.src_lane.0, s.src_lane_seq), x.records(0, 1)),
        original
    );
}

#[test]
fn replay_charges_the_lane_route_not_the_step_kind() {
    // 10 M8: a Cross takes the account and lane cross buckets; an Improve takes the lane
    // improve bucket. Lane 0 rests sell 1 @ 105 (session 1, account 1); session 30 on the same
    // account sends a CancelNewest buy 1 @ 105. Lane classifies it Cross (105 ≥ ask 105, 05
    // §6.5), but STP leaves no fill, so the BBO logs an Improve step. A replay given the step
    // kind would charge Improve; given the route the step logs (StepEntry CROSS, from the
    // FwdEntry route bit, 05 §4.12, §4.15) it reproduces the account state.
    let f = vyrn_bbo::OrderFlags::new(
        Side::Buy,
        vyrn_bbo::Tif::Day,
        false,
        vyrn_bbo::Stp::CancelNewest,
    );
    let run = |route: Option<vyrn_risk::Route>| {
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        x.open(0, 30, 1, vyrn_risk::SessionBuckets::default());
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 1, 11)]);
        x.settle(&mut bbo);
        let m = [new(f, 105, 1, 22)];
        let rx = match route {
            None => x.send(0, 30, 2_000, &m),
            Some(r) => x.replay(0, 30, 2_000, &m, &[], &[(LaneSeq(2), r)]),
        };
        assert_eq!(rx, Rx::Accepted);
        x.settle(&mut bbo);
        let step = x.steps.iter().find(|s| s.entry.src_lane_seq == LaneSeq(2));
        let e = step.unwrap().entry;
        let cross = x.lanes[0]
            .account_mut(vyrn_risk::AcctSlot(1))
            .unwrap()
            .0
            .buckets
            .cross
            .tat;
        (e.kind, e.flags, cross, x.records(0, 30))
    };
    let original = run(None);
    assert_eq!(
        (original.0, original.1),
        (StepKind::Improve.code(), vyrn_bbo::STEP_CROSS),
        "no fill: an Improve step that logs the lane's Cross route"
    );
    let from_kind = run(Some(vyrn_risk::Route::Improve));
    assert_ne!(
        from_kind.2, original.2,
        "the step kind loses the Cross charge"
    );
    assert_eq!(from_kind.1, 0, "an Improve route logs CROSS clear");
    let logged = if original.1 & vyrn_bbo::STEP_CROSS != 0 {
        vyrn_risk::Route::Cross
    } else {
        vyrn_risk::Route::Improve
    };
    assert_eq!(run(Some(logged)), original);
}

#[test]
fn a_locally_rejected_cross_logs_its_route_and_replays_with_it() {
    // G9: a post-only buy @ 105 against ask 105 is a Cross (05 §6.5) that lane risk rejects
    // POST_ONLY_WOULD_CROSS (10 M8 row 12), so no step names it. The lane logs a RouteRecord
    // after the packet's PacketRecord. Replay given that route rejects it again; replay that
    // routes it as a Join (no record) accepts it, which is the silent divergence.
    let po = vyrn_bbo::OrderFlags::new(Side::Buy, vyrn_bbo::Tif::Day, true, vyrn_bbo::Stp::None);
    let run = |routes: Option<&[(LaneSeq, vyrn_risk::Route)]>| {
        let (mut bbo, mut w) = setup();
        let mut x = w.rig();
        x.send(0, 1, 1_000, &[new(day(Side::Sell), 105, 1, 11)]);
        x.settle(&mut bbo);
        let m = [new(po, 105, 1, 22)];
        match routes {
            None => x.send(0, 2, 2_000, &m),
            Some(rt) => x.replay(0, 2, 2_000, &m, &[], rt),
        };
        x.settle(&mut bbo);
        let routes: Vec<_> = x.log[0]
            .iter()
            .filter_map(|r| match r {
                LogRec::Route(r) => Some(*r),
                LogRec::Packet(_) => None,
            })
            .collect();
        (routes, x.records(0, 2))
    };
    let live = run(None);
    // G12: every classified op logs its route (the resting ask too); this one is the reject's.
    assert_eq!(
        live.0
            .iter()
            .filter(|r| r.lane_seq == LaneSeq(2))
            .copied()
            .collect::<Vec<_>>(),
        [vyrn_types::RouteRecord {
            lane: vyrn_types::LaneId(0),
            lane_seq: LaneSeq(2),
            cross: true
        }]
    );
    assert!(
        live.1.iter().any(|r| matches!(
            r,
            Record::Reject {
                index: 0,
                reason: RejectReason::PostOnlyWouldCross,
                ..
            }
        )),
        "{:?}",
        live.1
    );
    assert_eq!(run(Some(&[(LaneSeq(2), vyrn_risk::Route::Cross)])), live);
    assert_ne!(
        run(Some(&[])).1,
        live.1,
        "without the record replay accepts it"
    );
}

#[test]
fn a_reduce_settles_even_when_its_successor_filled_first() {
    // Codex review 2: sell 10 @ 106, then reduce by 4 (LaneSeq 2, local), then lane 1 buys 6
    // @ 106. In L the reduce comes first: CancelAck 4, then the 6 remaining lots fill
    // (04 §6.4), and nothing stays reserved (10 §4.4).
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.send(0, 1, 1_000, &[new(day(Side::Sell), 106, 10, 11)]);
    x.settle(&mut bbo);
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
    x.settle(&mut bbo);
    assert!(
        x.records(0, 1).contains(&Record::CancelAck {
            index: 0,
            handle: h,
            canceled: Qty(4),
            client_tag: 44
        }),
        "{:?}",
        x.records(0, 1)
    );
    assert_eq!(base_resv(&mut x, 0, 1), 0);
}

#[test]
fn a_shed_entry_with_dependencies_answers_busy_without_a_fault() {
    // Codex review 2: lane 1 [sell 1 @ 106, buy 3 @ 106] forwards the buy with a Join
    // dependency; the BBO core's clock is past FwdEntry.deadline, so it runs a Shed step
    // (05 §6.8): both are answered BUSY, nothing trades, and both reservations come back
    // (10 §3.11). The Dep(BUSY) event has no handle; the lane must not fault on it.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(
        1,
        1,
        3_000,
        &[
            new(day(Side::Sell), 106, 1, 21),
            new(day(Side::Buy), 106, 3, 22),
        ],
    );
    let s = x.bbo_step_at(&mut bbo, 1_000_000).unwrap();
    assert_eq!(StepKind::from_code(s.entry.kind), Some(StepKind::Shed));
    x.settle(&mut bbo);
    let busy: Vec<u8> = x
        .records(1, 1)
        .iter()
        .filter_map(|r| match r {
            Record::Reject {
                index,
                reason: RejectReason::Busy,
                ..
            } => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(busy, vec![0, 1], "{:?}", x.records(1, 1));
    assert_eq!(base_resv(&mut x, 1, 1), 0);
    assert_eq!(
        x.lanes[1]
            .account_mut(vyrn_risk::AcctSlot(1))
            .unwrap()
            .1
            .quote_resv,
        0
    );
}

#[test]
fn a_per_session_cancel_all_tombstones_a_pending_replace_predecessor() {
    // Codex review 2, 05 §4.7: account 2 has two sessions, so CancelAll writes tombstones.
    // Seqs: 1 ask_105, 2 sell 3 @ 110 (local), 3 Replace to 104 (forwarded, pending), 4
    // CancelAll. Both versions of the order get tomb_seq 4: if the BBO sheds the replace, the
    // version @ 110 is current again and must already be canceled.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.open(0, 20, 2, vyrn_risk::SessionBuckets::default());
    ask_105(&mut x, &mut bbo);
    x.send(0, 2, 2_000, &[new(day(Side::Sell), 110, 3, 12)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 2);
    x.send(
        0,
        2,
        3_000,
        &[
            replace(h, Side::Sell, 104, 3),
            Msg::CancelAll { client_tag: 9 },
        ],
    );
    let lb = vyrn_lane::LaneBook::new(&x.views);
    assert_eq!(
        lb.slot(lid(0), 2).unwrap().tomb_seq,
        LaneSeq(4),
        "the version @ 110"
    );
    assert_eq!(
        lb.slot(lid(0), 3).unwrap().tomb_seq,
        LaneSeq(4),
        "the pending replace"
    );
}

#[test]
fn a_local_replace_out_of_range_is_applied_before_a_later_forward() {
    // Codex review 2, 05 §6.6: packet [Replace sell 105 → 110 (local join, LaneSeq 2), buy 3 @
    // 106 (cross, LaneSeq 3)]. The old version @ 105 is in the buy's range and the new one is
    // not, so pass 2 applies the replace before the push: applied_back = 3 − 2 = 1.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    let h = ask_105(&mut x, &mut bbo);
    x.send(
        0,
        1,
        2_000,
        &[
            replace(h, Side::Sell, 110, 5),
            new(day(Side::Buy), 106, 3, 13),
        ],
    );
    let e = x.peek_fwd(0);
    assert_eq!((e.lane_seq, e.applied_back), (LaneSeq(3), 1));
}

#[test]
fn scripted_boundaries_stay_scripted_after_the_last_one() {
    // Codex review 2, 05 §10: with `mids` the packet's boundaries are exactly the listed ones.
    // Lane 1 crosses lane 0's ask twice (steps a, b); lane 0 has applied neither. Lane 0's
    // packet names one boundary at (a, C_a) before op 3; step b must not run inside it.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    ask_105(&mut x, &mut bbo);
    x.send(1, 1, 2_000, &[new(day(Side::Buy), 105, 1, 1)]);
    let a = x.bbo_step(&mut bbo).unwrap();
    let at = x.lane_cut(0);
    assert_eq!((at.step, at.cut), (a.entry.step, a.cuts[0]));
    x.send(1, 1, 2_100, &[new(day(Side::Buy), 105, 1, 2)]);
    let b = x.bbo_step(&mut bbo).unwrap();
    assert!(b.entry.step > a.entry.step);
    x.publish(); // lane 0's snapshot line now has done_step = b: a live poll would run b
    let n = x.log[0].len();
    let m = [
        new(day(Side::Sell), 110, 1, 2),
        new(day(Side::Sell), 111, 1, 3),
    ];
    x.send_at(
        0,
        2,
        3_000,
        3_000,
        &m,
        &[Mid {
            pass: 1,
            next: LaneSeq(3),
            at,
        }],
    );
    let adv: Vec<StepId> = packets(&x, 0)[n..]
        .iter()
        .filter(|p| p.flags & PacketFlags::ADVANCE != 0)
        .map(|p| p.fills_applied)
        .collect();
    assert_eq!(adv, vec![a.entry.step]);
}

#[test]
fn a_same_tick_replace_reduction_pays_the_reduce_message_bucket() {
    // Codex review 1 P2 (test 16), 04 §9.1: session MSG bucket of burst 4, one token per second.
    // The New takes 1; three same-tick Replace reductions take the other 3; the fourth is
    // Reject RATE_LIMIT with the session MSG bucket id 2, and the order keeps 10 − 3 = 7.
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    let b = vyrn_risk::SessionBuckets {
        msg: vyrn_risk::Gcra::new(1_000_000_000, 4),
        ..Default::default()
    };
    x.open(0, 30, 3, b);
    x.send(0, 30, 1_000, &[new(day(Side::Sell), 110, 10, 7)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 30);
    let m: Vec<Msg> = [9, 8, 7, 6]
        .iter()
        .map(|q| replace(h, Side::Sell, 110, *q))
        .collect();
    x.send(0, 30, 2_000, &m);
    x.settle(&mut bbo);
    let recs = x.records(0, 30);
    assert!(
        recs.contains(&Record::Reject {
            index: 3,
            reason: RejectReason::RateLimit,
            detail: 2,
            client_tag: 7
        }),
        "{recs:?}"
    );
    let acks = recs.iter().filter(|r| {
        matches!(
            r,
            Record::CancelAck {
                canceled: Qty(1),
                ..
            }
        )
    });
    assert_eq!(acks.count(), 3);
    assert_eq!(base_resv(&mut x, 0, 3), 7);
}

#[test]
fn ops_before_the_freeze_settle_before_the_auction_out() {
    // 05 §8.8 item 6 (#193 review 1): a reduce and a cancel of auction-only orders, both before
    // the freeze cut C*, settle in the same boundary as the last uncross chunk (the lane polls
    // no boundary between them). Sequentially they come first: the reduce by 4 of the 10 is
    // `CancelAck(4)` and its remainder `Out AUCTION(6)`; the canceled order is `CancelAck(2)`
    // with no `Out`. The `Out` follows the lane's auction fill (05 §8.10 rule 4.2).
    use vyrn_bbo::{ControlCmd, OrderFlags, Phase, Stp, Tif};
    let ao = |side| OrderFlags::new(side, Tif::AuctionOnly, false, Stp::None);
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.command(&ControlCmd::Phase {
        phase: Phase::Auction,
        lo: Tick(0),
        hi: Tick(0),
    });
    x.settle(&mut bbo);
    x.send(1, 1, 1_000, &[new(day(Side::Sell), 104, 1, 1)]);
    x.send(
        0,
        1,
        2_000,
        &[
            new(ao(Side::Buy), 101, 10, 4),
            new(ao(Side::Buy), 99, 2, 5),
            new(ao(Side::Buy), 106, 1, 8),
        ],
    );
    x.settle(&mut bbo);
    let acks: Vec<_> = x
        .records(0, 1)
        .into_iter()
        .filter_map(|r| match r {
            Record::Ack { handle, .. } => Some(handle),
            _ => None,
        })
        .collect();
    assert_eq!(acks.len(), 3);
    let m = [
        Msg::Reduce {
            handle: acks[0],
            by: Qty(4),
            client_tag: 6,
        },
        cancel(acks[1], 7),
    ];
    assert_eq!(x.send(0, 1, 3_000, &m), Rx::Accepted);
    x.command(&ControlCmd::Phase {
        phase: Phase::Frozen,
        lo: Tick(1),
        hi: Tick(u32::MAX - 1),
    });
    x.command(&ControlCmd::Uncross {
        price: Tick(105),
        qty: 1,
    });
    while x.bbo_step(&mut bbo).is_some() {}
    x.settle(&mut bbo);
    let recs: Vec<_> = x
        .records(0, 1)
        .into_iter()
        .filter(|r| !matches!(r, Record::Ack { .. }))
        .collect();
    let auction_out = |h: Handle, q: u32| Record::Out {
        index: vyrn_bbo::INDEX_MAKER,
        cause: vyrn_bbo::OUT_AUCTION,
        handle: h,
        qty: Qty(q),
        client_tag: 4,
    };
    assert!(
        recs.contains(&Record::CancelAck {
            index: 0,
            handle: acks[0],
            canceled: Qty(4),
            client_tag: 6
        }),
        "{recs:?}"
    );
    assert!(
        recs.contains(&Record::CancelAck {
            index: 1,
            handle: acks[1],
            canceled: Qty(2),
            client_tag: 7
        }),
        "{recs:?}"
    );
    let outs: Vec<_> = recs
        .iter()
        .filter(|r| matches!(r, Record::Out { .. }))
        .copied()
        .collect();
    assert_eq!(outs, vec![auction_out(acks[0], 6)], "{recs:?}");
    let fill = recs.iter().position(|r| matches!(r, Record::Fill { .. }));
    let out = recs.iter().position(|r| matches!(r, Record::Out { .. }));
    assert!(fill.is_some() && fill < out, "{recs:?}");
}

#[test]
fn a_reduce_admitted_after_the_freeze_does_not_keep_the_auction_reservation() {
    // 05 §8.8 item 6 (#193 review 2): a Reduce admitted after the freeze cut C*, before the
    // lane applies the uncross, moves the order to a new version with `ins_seq > C*`. The
    // order was visible at C* through its older version, so it is still Out AUCTION for the
    // open quantity at C* (10), its reservation is released, and the later reduce is
    // `TOO_LATE` with detail OUT.
    use vyrn_bbo::{ControlCmd, OrderFlags, Phase, Stp, Tif};
    let ao = |side| OrderFlags::new(side, Tif::AuctionOnly, false, Stp::None);
    let (mut bbo, mut w) = setup();
    let mut x = w.rig();
    x.command(&ControlCmd::Phase {
        phase: Phase::Auction,
        lo: Tick(0),
        hi: Tick(0),
    });
    x.settle(&mut bbo);
    // p* = 105 for 1 on lane 1; the auction-only sell at 110 on lane 0 does not fill.
    x.send(
        1,
        1,
        1_000,
        &[
            new(day(Side::Sell), 104, 1, 1),
            new(day(Side::Buy), 106, 1, 2),
        ],
    );
    x.send(0, 1, 2_000, &[new(ao(Side::Sell), 110, 10, 4)]);
    x.settle(&mut bbo);
    let h = x.last_ack(0, 1);
    assert_eq!(base_resv(&mut x, 0, 1), 10, "the sell reserves its 10");
    x.command(&ControlCmd::Phase {
        phase: Phase::Frozen,
        lo: Tick(1),
        hi: Tick(u32::MAX - 1),
    });
    while x.bbo_step(&mut bbo).is_some() {}
    // The lane has not applied the freeze: it admits the reduce, after C*.
    let at = x.lane_cut(0);
    let none = [Mid {
        pass: 1,
        next: LaneSeq(99),
        at,
    }];
    let m = [Msg::Reduce {
        handle: h,
        by: Qty(4),
        client_tag: 6,
    }];
    assert_eq!(x.send_at(0, 1, 3_000, 3_000, &m, &none), Rx::Accepted);
    x.command(&ControlCmd::Uncross {
        price: Tick(105),
        qty: 1,
    });
    x.settle(&mut bbo);
    let recs: Vec<_> = x
        .records(0, 1)
        .into_iter()
        .filter(|r| !matches!(r, Record::Ack { .. }))
        .collect();
    assert_eq!(
        recs,
        vec![
            Record::Out {
                index: vyrn_bbo::INDEX_MAKER,
                cause: vyrn_bbo::OUT_AUCTION,
                handle: h,
                qty: Qty(10),
                client_tag: 4
            },
            Record::Reject {
                index: 0,
                reason: RejectReason::TooLate,
                detail: 3,
                client_tag: 6
            },
        ],
        "{recs:?}"
    );
    assert_eq!(base_resv(&mut x, 0, 1), 0, "nothing stays reserved");
    // The reduced version (ins_seq > C*) is dead to the BBO too: the next auction fills the
    // lane-1 sell behind it at 110, not the ended order.
    x.command(&ControlCmd::Phase {
        phase: Phase::Auction,
        lo: Tick(0),
        hi: Tick(0),
    });
    x.settle(&mut bbo);
    x.send(
        1,
        1,
        4_000,
        &[
            new(day(Side::Sell), 110, 6, 8),
            new(day(Side::Buy), 110, 6, 9),
        ],
    );
    x.settle(&mut bbo);
    x.command(&ControlCmd::Phase {
        phase: Phase::Frozen,
        lo: Tick(1),
        hi: Tick(u32::MAX - 1),
    });
    x.command(&ControlCmd::Uncross {
        price: Tick(110),
        qty: 6,
    });
    x.settle(&mut bbo);
    assert!(
        x.records(0, 1)
            .iter()
            .all(|r| !matches!(r, Record::Fill { .. })),
        "the ended order does not trade"
    );
    let at_110: Vec<_> = x
        .records(1, 1)
        .into_iter()
        .filter_map(|r| match r {
            Record::Fill {
                tick: Tick(110),
                qty,
                ..
            } => Some(qty),
            _ => None,
        })
        .collect();
    assert_eq!(
        at_110,
        vec![Qty(6), Qty(6)],
        "the lane-1 sell fills instead"
    );
}
