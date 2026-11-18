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
use vyrn_engine::{Engine, Fault, NoResponses, OwnedRec, Rec, Shared, Sink};
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
    }
}

/// Pooled account 77: session 1 of lanes 1 and 2, lane-local slot 1, pool-wide index 9.
const POOLED: AccountId = AccountId(77);

/// The harness box with lanes 1 and 2 pooled (`pool` false: the same box, nothing pooled).
fn pooled_engine<'a>(sh: &'a mut Shared<Hw>, tok: &'a PoolTok, pool: bool) -> Engine<'a, Hw, NA> {
    let bbo = Bbo::new(vyrn_bbo::Config {
        pool: if pool { 0b110 } else { 0 },
        ..bbo_cfg()
    });
    let mut e = engine(bbo, sh);
    if pool {
        for l in [1, 2] {
            assert!(e.lane_mut(l).unwrap().set_pool_index(AcctSlot(1), 9));
            assert!(e.pool_session(l, sid(l, 1), POOLED, tok));
        }
    }
    e
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
        let OwnedRec::Packet(p) = s.j.recs[*at] else {
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
            OwnedRec::Packet(_) | OwnedRec::Route(_) => None,
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
}
