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
        .map(|r| match r {
            LogRec::Packet(p) => *p,
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
        LaneSeq(0),
        "a shed packet takes no LaneSeq"
    );
    assert_eq!(
        x.records(0, 1),
        vec![Record::Reject {
            index: 0,
            reason: RejectReason::Busy,
            detail: 0,
            client_tag: 9
        }]
    );
    let p = packets(&x, 0);
    assert_eq!(p[0].flags, PacketFlags::SHED);
    assert_eq!(p[0].pkt_hash, vyrn_types::PktHash(0));
    // The client resends the same pkt_seq; on time now.
    assert_eq!(x.send_at(0, 1, 20_000, 20_461, &m, &[]), Rx::Accepted);
    assert_eq!(x.lanes[0].seq(), LaneSeq(1));
    assert_eq!(packets(&x, 0)[1].pkt_seq, p[0].pkt_seq);
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
    let n = x.log[0].len();
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
