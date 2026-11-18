//! Follow-up F4 of #39: pooled lanes (`AcctTake`, 01 §14.17.4, 05 §6.9) and control and
//! auction steps through the engine's control role (05 §8.8).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod harness;

use harness::*;
use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{Bbo, ControlCmd, OrderFlags, Phase, Record, Side, Stp, Tif, TxEntry};
use vyrn_cut::{Hw, PoolTok};
use vyrn_engine::{Diverged, Engine, Fault, NoResponses, OwnedRec, Rec, Shared, Sink, Why};
use vyrn_lane::{RespPkt, RxIn};
use vyrn_risk::AcctSlot;
use vyrn_types::{AccountId, AcctTake, Epoch, LaneId, MAX_REQ_PAYLOAD, Nanos, Qty, StepKind, Tick};
use vyrn_wire::{Msg, ReqHeader, encode_request};

/// The harness journal plus every take, with the number of records logged before it.
#[derive(Default)]
struct Takes {
    j: Journal,
    takes: Vec<(usize, AcctTake)>,
}

impl Sink for Takes {
    fn record(&mut self, r: &Rec<'_>) {
        self.j.record(r);
    }
    fn lane_resp(&mut self, lane: LaneId, p: &RespPkt) {
        self.j.lane_resp(lane, p);
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        self.j.tx(h, recs);
    }
    fn take(&mut self, t: &AcctTake) {
        self.takes.push((self.j.recs.len(), *t));
        self.j.take(t);
    }
}

fn box_shared() -> Box<Shared<Hw>> {
    let bbo = Bbo::new(bbo_cfg());
    Shared::new(&Hw, N, arena_cfg(), &bbo.initial_snapshot()).unwrap()
}

fn packet(l: usize, a: u32, pkt_seq: u32, msgs: &[Msg]) -> Vec<u8> {
    let hdr = ReqHeader::new(sid(l, a), pkt_seq, Epoch(0).low16(), BOOK, false);
    let mut buf = [0u8; MAX_REQ_PAYLOAD];
    let n = encode_request(&mut buf, hdr, msgs, &kseq(l, a), None).unwrap();
    buf[..n].to_vec()
}

fn order(side: Side, tif: Tif, stp: Stp, tick: u32, qty: u32, tag: u32) -> Msg {
    Msg::New {
        flags: vyrn_wire::OrderFlags::from_byte(OrderFlags::new(side, tif, false, stp).0).unwrap(),
        tick: Tick(tick),
        qty: Qty(qty),
        client_tag: tag,
    }
}

/// Feeds `pkts` (lane, session, message) in order, running the engine to quiescence after
/// each; packet `k` arrives at `1000·(k+1)`.
fn feed<S: Sink>(e: &mut Engine<'_, Hw, NA>, pkts: &[(usize, u32, Msg)], sink: &mut S) -> Store {
    let mut seq = [[0u32; NA]; N];
    let mut store = Store::default();
    for (k, (l, a, m)) in pkts.iter().enumerate() {
        let (l, a) = (*l, *a);
        seq[l][a as usize] += 1;
        let b = packet(l, a, seq[l][a as usize], core::slice::from_ref(m));
        let rx = 1000 * (k as u64 + 1);
        let p = RxIn {
            bytes: &b,
            rx_ts: Nanos(rx),
            pkt_hash: fake_hash(&b),
        };
        e.ingest(l, p, &FixedClock(rx), sink).unwrap();
        assert!(e.run(&NeverLate, sink, 64).unwrap(), "quiet");
        store
            .0
            .push(((LaneId(l as u8), sid(l, a), seq[l][a as usize], rx), b));
    }
    store
}

/// `Fill` records sent: fill TX packets (continuous) and lane responses (an uncross, 05 §8.8).
fn fills(j: &Journal) -> usize {
    let tx = j.tx.iter().flat_map(|(_, r)| r);
    let resp = j.resp.iter().flat_map(|(_, p)| p.records());
    tx.chain(resp)
        .filter(|r| matches!(r, Record::Fill { .. }))
        .count()
}

#[test]
fn a_pooled_session_logs_one_take_before_each_of_its_records() {
    use Side::{Buy, Sell};
    use Tif::Day;
    let tok = PoolTok::new();
    let mut sh = box_shared();
    let mut e = pooled_engine(&mut sh, &tok, true);
    let mut s = Takes::default();
    let store = feed(
        &mut e,
        &[
            (1, 1, order(Sell, Day, Stp::None, 200, 1, 1)),
            (0, 1, order(Sell, Day, Stp::None, 201, 1, 2)), // dedicated lane: no take
            (2, 1, order(Sell, Day, Stp::None, 202, 1, 3)),
            (2, 2, order(Sell, Day, Stp::None, 203, 1, 4)), // pool lane, unpooled session
            (1, 1, order(Buy, Day, Stp::None, 50, 1, 5)),
        ],
        &mut s,
    );
    // `ver` counts takes across the pool, gapless from 1; each take names its lane and the
    // record's first LaneSeq, and comes right before that record.
    let got: Vec<_> = s
        .takes
        .iter()
        .map(|(_, t)| (t.lane.0, t.account, t.ver, t.lane_seq.0))
        .collect();
    assert_eq!(
        got,
        vec![(1, POOLED, 1, 1), (2, POOLED, 2, 1), (1, POOLED, 3, 2)]
    );
    for (at, t) in &s.takes {
        assert_eq!(
            s.j.recs[*at],
            OwnedRec::Take(*t),
            "the journal holds the take"
        );
        let OwnedRec::Packet(p) = s.j.recs[*at + 1] else {
            panic!("take {t:?} is not followed by a packet record");
        };
        assert_eq!(
            (p.lane, p.session, p.first_lane_seq),
            (t.lane, sid(usize::from(t.lane.0), 1), t.lane_seq)
        );
    }
    assert_eq!(tok.peek(), (None, 3), "released after each take");

    // Replay on a pooled box hands the caller's sink the same takes at the same places.
    let rtok = PoolTok::new();
    let mut rsh = box_shared();
    let mut r = pooled_engine(&mut rsh, &rtok, true);
    let mut rs = Takes::default();
    assert_eq!(
        r.replay(&s.j.recs, &store, &mut NoResponses, &mut rs),
        Ok(())
    );
    assert_eq!(rs.takes, s.takes);

    // F4a: each `AcctTake` is part of its record's lane call and must be reproduced in place
    // (05 §6.9, 01 §14.17.4). A changed `ver`, a dropped take, or a take moved after its record
    // diverges at the take's index.
    let (first, _) = s.takes[0];
    let replay = |recs: &[OwnedRec]| {
        let rtok = PoolTok::new();
        let mut rsh = box_shared();
        let mut r = pooled_engine(&mut rsh, &rtok, true);
        r.replay(recs, &store, &mut NoResponses, &mut Journal::default())
    };
    let mismatch = |index| {
        Err(Diverged {
            index,
            why: Why::Mismatch,
        })
    };
    let mut bad_ver = s.j.recs.clone();
    if let OwnedRec::Take(t) = &mut bad_ver[first] {
        t.ver += 1;
    }
    assert_eq!(replay(&bad_ver), mismatch(first));
    let mut dropped = s.j.recs.clone();
    dropped.remove(first);
    assert_eq!(replay(&dropped), mismatch(first));
    let mut moved = s.j.recs.clone();
    moved.swap(first, first + 1);
    assert_eq!(replay(&moved), mismatch(first));
}

#[test]
fn a_take_must_sit_right_before_its_record_not_before_its_route() {
    // A pooled IOC that crosses the resting ask is forwarded with a route record (07 §3.6),
    // logged as `[Take, Packet, Route]`. Moving the route between the take and its packet
    // record keeps every record and each kind's order, but breaks "right before the record it
    // covers" (05 §6.9), so replay diverges at the take (#135 review).
    let tok = PoolTok::new();
    let mut sh = box_shared();
    let mut e = pooled_engine(&mut sh, &tok, true);
    let mut s = Takes::default();
    let store = feed(
        &mut e,
        &[
            (0, 1, order(Side::Sell, Tif::Day, Stp::None, 200, 1, 1)),
            (1, 1, order(Side::Buy, Tif::Ioc, Stp::None, 200, 1, 2)),
        ],
        &mut s,
    );
    let recs = &s.j.recs;
    let at = (0..recs.len() - 2)
        .find(|&i| {
            matches!(
                (&recs[i], &recs[i + 1], &recs[i + 2]),
                (OwnedRec::Take(_), OwnedRec::Packet(_), OwnedRec::Route(_))
            )
        })
        .expect("the pooled IOC logs [Take, Packet, Route]");
    let replay = |recs: &[OwnedRec]| {
        let rtok = PoolTok::new();
        let mut rsh = box_shared();
        let mut r = pooled_engine(&mut rsh, &rtok, true);
        r.replay(recs, &store, &mut NoResponses, &mut Journal::default())
    };
    assert_eq!(replay(recs), Ok(()));
    let mut moved = recs.clone();
    moved.swap(at + 1, at + 2);
    assert_eq!(
        replay(&moved),
        Err(Diverged {
            index: at,
            why: Why::Mismatch
        })
    );
}

#[test]
fn a_foreign_route_between_a_take_and_its_packet_diverges_at_the_take() {
    // Coordinator ruling on #135: a take sits right before its packet's group (the packet's
    // own route records and the packet). A route record of another packet between them is
    // `Why::Mismatch` at the take's index, whether that route is from the same lane or not.
    let tok = PoolTok::new();
    let mut sh = box_shared();
    let mut e = pooled_engine(&mut sh, &tok, true);
    let mut s = Takes::default();
    let store = feed(
        &mut e,
        &[
            (0, 1, order(Side::Sell, Tif::Day, Stp::None, 200, 2, 1)),
            (1, 1, order(Side::Buy, Tif::Ioc, Stp::None, 200, 1, 2)),
            (1, 1, order(Side::Buy, Tif::Ioc, Stp::None, 200, 1, 3)),
        ],
        &mut s,
    );
    let recs = &s.j.recs;
    let groups: Vec<usize> = (0..recs.len() - 2)
        .filter(|&i| {
            matches!(
                (&recs[i], &recs[i + 1], &recs[i + 2]),
                (OwnedRec::Take(_), OwnedRec::Packet(_), OwnedRec::Route(_))
            )
        })
        .collect();
    assert_eq!(
        groups.len(),
        2,
        "each pooled IOC logs [Take, Packet, Route]"
    );
    let (first, second) = (groups[0], groups[1]);
    let OwnedRec::Route(foreign) = recs[first + 2] else {
        unreachable!()
    };
    let replay = |recs: &[OwnedRec]| {
        let rtok = PoolTok::new();
        let mut rsh = box_shared();
        let mut r = pooled_engine(&mut rsh, &rtok, true);
        r.replay(recs, &store, &mut NoResponses, &mut Journal::default())
    };
    assert_eq!(replay(recs), Ok(()));
    let other_lane = vyrn_types::RouteRecord {
        lane: LaneId(2),
        ..foreign
    };
    for r in [foreign, other_lane] {
        let mut bad = recs.clone();
        bad.insert(second + 1, OwnedRec::Route(r));
        assert_eq!(
            replay(&bad),
            Err(Diverged {
                index: second,
                why: Why::Mismatch
            }),
            "foreign route on lane {}",
            r.lane.0
        );
    }
}

#[test]
fn a_held_token_fail_stops_the_lane() {
    let tok = PoolTok::new();
    let mut sh = box_shared();
    let mut e = pooled_engine(&mut sh, &tok, true);
    // Another pool core holds the account: the engine must not log the record as its own.
    tok.try_take(LaneId(5)).unwrap();
    let b = packet(
        1,
        1,
        1,
        &[order(Side::Sell, Tif::Day, Stp::None, 200, 1, 1)],
    );
    let p = RxIn {
        bytes: &b,
        rx_ts: Nanos(1000),
        pkt_hash: fake_hash(&b),
    };
    let mut s = Takes::default();
    assert_eq!(
        e.ingest(1, p, &FixedClock(1000), &mut s),
        Err(Fault::Pool(LaneId(1)))
    );
    assert!(s.takes.is_empty() && s.j.recs.is_empty());
}

#[test]
fn stp_compares_a_pooled_account_across_pool_lanes() {
    // The same account rests a sell on lane 1 and sends a crossing buy with STP from lane 2.
    use Side::{Buy, Sell};
    use Tif::Day;
    let pkts = [
        (1, 1, order(Sell, Day, Stp::None, 105, 1, 1)),
        (2, 1, order(Buy, Day, Stp::CancelNewest, 105, 1, 2)),
    ];
    let tok = PoolTok::new();
    let (mut sh_a, mut sh_b) = (box_shared(), box_shared());
    let mut pooled = Takes::default();
    feed(
        &mut pooled_engine(&mut sh_a, &tok, true),
        &pkts,
        &mut pooled,
    );
    let mut apart = Takes::default();
    feed(
        &mut pooled_engine(&mut sh_b, &tok, false),
        &pkts,
        &mut apart,
    );
    assert!(fills(&apart.j) > 0, "two lane-local accounts trade");
    assert_eq!(
        fills(&pooled.j),
        0,
        "one pooled account does not trade with itself"
    );
}

#[test]
fn an_auction_runs_through_control_steps_and_replays() {
    use Side::{Buy, Sell};
    use Tif::Day;
    let cmds = [
        ControlCmd::Phase {
            phase: Phase::Auction,
            lo: Tick(0),
            hi: Tick(0),
        },
        ControlCmd::Phase {
            phase: Phase::Frozen,
            lo: Tick(1),
            hi: Tick(TICK_MAX),
        },
        ControlCmd::Uncross {
            price: Tick(105),
            qty: 2,
        },
        ControlCmd::Phase {
            phase: Phase::Continuous,
            lo: Tick(0),
            hi: Tick(0),
        },
    ];
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    assert!(e.command(&cmds[0]));
    assert!(e.run(&NeverLate, &mut j, 64).unwrap());
    let store = feed(
        &mut e,
        &[
            (0, 1, order(Sell, Day, Stp::None, 104, 2, 1)),
            (1, 1, order(Buy, Day, Stp::None, 106, 2, 2)),
        ],
        &mut j,
    );
    assert_eq!(fills(&j), 0, "no trade in the auction phase");
    for c in &cmds[1..] {
        assert!(e.command(c));
        assert!(e.run(&NeverLate, &mut j, 64).unwrap());
    }
    let kinds: Vec<_> = j
        .recs
        .iter()
        .filter_map(|r| match r {
            OwnedRec::Step(s, _) => StepKind::from_code(s.kind),
            OwnedRec::Packet(_) | OwnedRec::Route(_) | OwnedRec::Take(_) => None,
        })
        .filter(|k| matches!(k, StepKind::Control | StepKind::Uncross))
        .collect();
    assert_eq!(
        kinds,
        vec![
            StepKind::Control,
            StepKind::Control,
            StepKind::Uncross,
            StepKind::Control
        ]
    );
    assert_eq!(fills(&j), 2, "both sides fill at p* = 105");
    let unc = j.recs.iter().find_map(|r| match r {
        OwnedRec::Step(s, _) if s.kind == StepKind::Uncross.code() => Some(s.n_fills),
        _ => None,
    });
    assert_eq!(unc, Some(2));
    assert_eq!(e.snapshot().unwrap().phase, Phase::Continuous.code());

    // Replay: the stream names each control step's kind, not its command, so the replayer
    // queues the commands before the stream (the BBO core holds each until its step).
    let (bbo, mut sh) = new_box();
    let mut r = engine(bbo, &mut sh);
    for c in &cmds {
        assert!(r.command(c));
    }
    let mut rj = Journal::default();
    assert_eq!(r.replay(&j.recs, &store, &mut NoResponses, &mut rj), Ok(()));
    assert_eq!(rj.tx, j.tx);
    assert_eq!(rj.resp, j.resp);

    // 07-only replay (07 §3.8): each Control step carries its command and the opening Uncross
    // step carries p* and Q, so `replay_wire` needs no hand-queued commands.
    let (lanes, routes, mut ws) = to_wire(&j.recs);
    let mut ctl = cmds
        .iter()
        .filter(|c| matches!(c, ControlCmd::Phase { .. }));
    for w in ws.iter_mut().filter(|w| w.1 == StepKind::Control) {
        w.5 = vyrn_engine::control_payload(ctl.next().unwrap())
            .unwrap()
            .to_vec();
    }
    assert!(ctl.next().is_none(), "one Control step per Phase command");
    let opening = ws.iter().position(|w| w.1 == StepKind::Uncross).unwrap();
    let unc_at = ws[opening].0;
    let with = |price: u32, qty: u64| {
        let mut ws = ws.clone();
        ws[opening].5 = vyrn_engine::uncross_payload(Tick(price), qty).to_vec();
        ws
    };
    let (r, rep) = replay_wire(&lanes, &routes, &with(105, 2), &store, Some(&j));
    assert_eq!(r, Ok(()));
    assert_eq!(rep.tx, j.tx);
    assert_eq!(rep.resp, j.resp);
    // The payload is a checked log of the uncross, not an input that overrides it.
    let at = |why| {
        Err(vyrn_engine::WireDiverged {
            at: vyrn_engine::WireAt::Step(unc_at),
            why,
        })
    };
    for (p, q) in [(105, 3), (103, 2)] {
        assert_eq!(
            replay_wire(&lanes, &routes, &with(p, q), &store, None).0,
            at(Why::Mismatch),
            "p* {p}, Q {q}"
        );
    }
    // An opening Uncross step without its payload is malformed.
    assert_eq!(
        replay_wire(&lanes, &routes, &ws, &store, None).0,
        at(Why::BadStep)
    );
}

/// Replays 07-only blocks (`Engine::replay_wire`) on a fresh box, pooled as `pool` says; each
/// block is `(packet records, route records, AcctTakes with their packet's index, steps)`.
type PoolBlock<'a> = (
    &'a [vyrn_types::PacketRecord],
    &'a [vyrn_types::RouteRecord],
    &'a [(usize, AcctTake)],
    &'a [Wire],
);

fn replay_wire_pooled(
    blocks: &[PoolBlock<'_>],
    store: &Store,
    pool: bool,
) -> Result<(), vyrn_engine::WireDiverged> {
    let rtok = PoolTok::new();
    let mut rsh = box_shared();
    let mut r = pooled_engine(&mut rsh, &rtok, pool);
    for (lanes, routes, takes, steps) in blocks {
        let ws: Vec<vyrn_engine::WireStep<'_>> = steps
            .iter()
            .map(
                |(step, kind, src, cross, cut, payload, lowver)| vyrn_engine::WireStep {
                    step: *step,
                    kind: *kind,
                    src: *src,
                    cross: *cross,
                    cut,
                    payload,
                    lowver: *lowver,
                },
            )
            .collect();
        r.replay_wire(
            lanes,
            routes,
            takes,
            &ws,
            store,
            &mut NoResponses,
            &mut Journal::default(),
        )?;
    }
    Ok(())
}

#[test]
fn replay_wire_reproduces_each_take_and_carries_it_with_its_packet() {
    // F4b: `Engine::replay_wire` takes the block's `AcctTake`s and checks each against the take
    // its packet's lane call emits (05 §6.9, 07 §7.1). A take carries with its packet.
    use Side::{Buy, Sell};
    use Tif::Day;
    let tok = PoolTok::new();
    let mut sh = box_shared();
    let mut e = pooled_engine(&mut sh, &tok, true);
    let mut s = Takes::default();
    let store = feed(
        &mut e,
        &[
            (1, 1, order(Sell, Day, Stp::None, 200, 1, 1)),
            (0, 1, order(Sell, Day, Stp::None, 201, 1, 2)),
            (2, 1, order(Sell, Day, Stp::None, 202, 1, 3)),
            (2, 2, order(Sell, Day, Stp::None, 203, 1, 4)),
            (1, 1, order(Buy, Day, Stp::None, 50, 1, 5)),
        ],
        &mut s,
    );
    let (lanes, routes, steps) = to_wire(&s.j.recs);
    let takes = takes_of(&s.j.recs);
    assert_eq!(takes.len(), 3);
    let one =
        |t: &[(usize, AcctTake)]| replay_wire_pooled(&[(&lanes, &routes, t, &steps)], &store, true);
    let why = |r: Result<(), vyrn_engine::WireDiverged>| r.map_err(|d| (d.at, d.why));
    assert_eq!(why(one(&takes)), Ok(()));
    // Any order in the input: each take is bound to its packet by index.
    let mut rev = takes.clone();
    rev.reverse();
    assert_eq!(why(one(&rev)), Ok(()));

    // Where the first take's packet sits among the packet records.
    let (at0, t0) = takes[0];
    assert_eq!(
        (lanes[at0].lane, lanes[at0].first_lane_seq),
        (t0.lane, t0.lane_seq)
    );
    // The last take's `ver` changed (no reordering: it stays the account's highest).
    let (atl, _) = *takes.last().unwrap();
    let mut bad_ver = takes.clone();
    bad_ver.last_mut().unwrap().1.ver += 10;
    assert_eq!(
        why(one(&bad_ver)),
        Err((vyrn_engine::WireAt::Lane(atl), Why::Mismatch))
    );
    let mut bad_acct = takes.clone();
    bad_acct[0].1.account = AccountId(78);
    assert_eq!(
        why(one(&bad_acct)),
        Err((vyrn_engine::WireAt::Lane(at0), Why::Mismatch))
    );
    // A dropped take: the lane call emits one the input lacks.
    assert_eq!(
        why(one(&takes[1..])),
        Err((vyrn_engine::WireAt::Lane(at0), Why::Mismatch))
    );
    // Review 1: a duplicate of a valid take, a second take on one record, or a take bound to
    // a record that is not its packet (another lane_seq, an Advance record) is malformed.
    let bad = |t: Vec<(usize, AcctTake)>| why(one(&t));
    let end = Err((vyrn_engine::WireAt::End, Why::BadRecord));
    let mut dup = takes.clone();
    dup.push(takes[0]);
    assert_eq!(bad(dup), end);
    let mut second = takes.clone();
    second.push((at0, AcctTake { ver: 99, ..t0 }));
    assert_eq!(bad(second), end);
    let adv = lanes
        .iter()
        .position(|p| p.lane == t0.lane && p.count == 0)
        .unwrap();
    let mut wrong = takes.clone();
    wrong[0].0 = adv;
    assert_eq!(bad(wrong), end);
    // A box without the pool emits no take where the input holds one.
    assert_eq!(
        why(replay_wire_pooled(
            &[(&lanes, &routes, &takes, &steps)],
            &store,
            false
        )),
        Err((vyrn_engine::WireAt::Lane(at0), Why::Mismatch))
    );

    // Split before the last take's step: its packet and take carry into the second block.
    let (_, last) = *takes.last().unwrap();
    let cut_at = steps
        .iter()
        .position(|w| {
            w.2.is_some_and(|(l, q)| l == last.lane && q == last.lane_seq)
        })
        .unwrap();
    let split = lanes
        .iter()
        .position(|p| p.lane == last.lane && p.count > 0 && p.first_lane_seq == last.lane_seq)
        .unwrap();
    let (la, lb) = lanes.split_at(split);
    let (sa, sb) = steps.split_at(cut_at);
    let (ta, tb) = takes.split_at(2);
    // Block 2's takes index into block 2's records.
    let tb: Vec<_> = tb.iter().map(|&(i, t)| (i - split, t)).collect();
    // Each route record goes in the block of its packet.
    let in_b = |x: &vyrn_types::RouteRecord| x.lane == last.lane && x.lane_seq >= last.lane_seq;
    let ra: Vec<_> = routes.iter().copied().filter(|x| !in_b(x)).collect();
    let rb: Vec<_> = routes.iter().copied().filter(in_b).collect();
    // Lane records of other lanes after `split` would go in block 2 as well; the scenario's
    // last packet is the last lane record.
    assert_eq!(lb.len(), lanes.len() - split);
    assert_eq!(
        why(replay_wire_pooled(
            &[(la, &ra, ta, sa), (lb, &rb, &tb, sb)],
            &store,
            true
        )),
        Ok(())
    );
    // A first block with no steps replays only what is due at step 0 (lane 1's first packet
    // and its take); the later pooled packets carry, each with its take, into the next block.
    let empty: [Wire; 0] = [];
    assert_eq!(
        why(replay_wire_pooled(
            &[(&lanes, &routes, &takes, &empty), (&[], &[], &[], &steps)],
            &store,
            true
        )),
        Ok(())
    );
    // A take in an earlier block than its packet is malformed (on the wire it sits right
    // before its packet): its index names no packet record of that block.
    assert_eq!(
        why(replay_wire_pooled(
            &[(la, &ra, &takes, sa), (lb, &rb, &[], sb)],
            &store,
            true
        )),
        Err((vyrn_engine::WireAt::End, Why::BadRecord))
    );
}

#[test]
fn takes_of_two_accounts_sharing_a_lane_seq_bind_to_their_own_packets() {
    // #157 review 1 (P1): a heartbeat-only packet takes no LaneSeq, so the next packet of the
    // lane has the same `first_lane_seq`. With two pooled accounts, each with its own token
    // and `ver` counter, the two takes share `(lane, lane_seq)`: account 77's heartbeat take has
    // a higher `ver` than account 88's first take. Each take must bind to its own packet, not to
    // the lowest `ver` at that `lane_seq` (05 §6.9, 07 §7.1 item 2).
    use Side::Sell;
    use Tif::Day;
    const OTHER: AccountId = AccountId(88);
    let (tok, tok2) = (PoolTok::new(), PoolTok::new());
    fn two<'a>(sh: &'a mut Shared<Hw>, a: &'a PoolTok, b: &'a PoolTok) -> Engine<'a, Hw, NA> {
        let mut e = pooled_engine(sh, a, true);
        for l in [1, 2] {
            assert!(e.lane_mut(l).unwrap().set_pool_index(AcctSlot(2), 10));
        }
        assert!(e.pool_session(1, sid(1, 2), OTHER, b));
        e
    }
    let mut sh = box_shared();
    let mut e = two(&mut sh, &tok, &tok2);
    let mut s = Takes::default();
    let store = feed(
        &mut e,
        &[
            (1, 1, order(Sell, Day, Stp::None, 200, 1, 1)),
            (2, 1, order(Sell, Day, Stp::None, 201, 1, 2)),
            (1, 1, Msg::Heartbeat),
            (1, 2, order(Sell, Day, Stp::None, 202, 1, 3)),
        ],
        &mut s,
    );
    let takes = takes_of(&s.j.recs);
    let got: Vec<_> = takes
        .iter()
        .map(|(_, t)| (t.lane.0, t.account, t.ver, t.lane_seq.0))
        .collect();
    // The heartbeat (77, ver 3) and the next order (88, ver 1) share lane 1's LaneSeq 2.
    assert_eq!(
        got,
        vec![
            (1, POOLED, 1, 1),
            (2, POOLED, 2, 1),
            (1, POOLED, 3, 2),
            (1, OTHER, 1, 2)
        ]
    );
    // Journal replay and 07 replay both reproduce the live run.
    let rtok = (PoolTok::new(), PoolTok::new());
    let mut rsh = box_shared();
    let mut r = two(&mut rsh, &rtok.0, &rtok.1);
    assert_eq!(
        r.replay(&s.j.recs, &store, &mut NoResponses, &mut Journal::default()),
        Ok(())
    );
    let (lanes, routes, steps) = to_wire(&s.j.recs);
    let rtok = (PoolTok::new(), PoolTok::new());
    let mut rsh = box_shared();
    let mut r = two(&mut rsh, &rtok.0, &rtok.1);
    let ws: Vec<vyrn_engine::WireStep<'_>> = steps
        .iter()
        .map(
            |(step, kind, src, cross, cut, payload, lowver)| vyrn_engine::WireStep {
                step: *step,
                kind: *kind,
                src: *src,
                cross: *cross,
                cut,
                payload,
                lowver: *lowver,
            },
        )
        .collect();
    let r = r.replay_wire(
        &lanes,
        &routes,
        &takes,
        &ws,
        &store,
        &mut NoResponses,
        &mut Journal::default(),
    );
    assert_eq!(r.map_err(|d| (d.at, d.why)), Ok(()));
}
