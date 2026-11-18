//! The engine on the `Sim` visibility backend (11 §6.4, `vyrn-sim`'s virtual clock): every
//! shared line is published with a seeded delay, so a reader may see an older value or an
//! empty ring. The order stream must not depend on those delays.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod harness;

use harness::*;
use vyrn_bbo::admit::NeverLate;
use vyrn_bbo::{Bbo, Side, StepEntry, Tif};
use vyrn_cut::{Sim, Visibility};
use vyrn_engine::{Engine, OwnedRec, Shared, Why};
use vyrn_lane::{Lane, RxIn, SessionSpec};
use vyrn_risk::{AcctRisk, AcctSlot, SessionBuckets};
use vyrn_types::{AccountId, Epoch, LaneId, MAX_REQ_PAYLOAD, Nanos, PacketFlags};
use vyrn_wire::{Msg, ReqHeader, encode_request};

/// [`harness::engine`] on any backend.
pub fn engine_on<'a, V: Visibility>(
    vis: &'a V,
    bbo: Bbo,
    sh: &'a mut Shared<V>,
) -> Engine<'a, V, NA> {
    Engine::new(vis, sh, bbo, &lane_cfgs(), |cfg, aw, ports| {
        let l = usize::from(cfg.lane.0);
        let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
        acct.max_open_orders = 1000;
        let mut lane = Lane::<V, NA>::new(cfg, aw, ports, acct);
        for a in 1..NA as u32 {
            let (_, bal) = lane.account_mut(AcctSlot(a)).unwrap();
            bal.quote_free = 1 << 60;
            bal.base_free = 1 << 40;
            assert!(lane.open_session(&SessionSpec {
                id: sid(l, a),
                acct: AcctSlot(a),
                k_seq: kseq(l, a),
                book: BOOK,
                buckets: SessionBuckets::default(),
            }));
        }
        lane
    })
    .unwrap()
}

/// Encodes packet `pkt_seq` of session `a` on lane `l`.
pub fn packet(l: usize, a: u32, pkt_seq: u32, msgs: &[Msg]) -> Vec<u8> {
    let hdr = ReqHeader::new(sid(l, a), pkt_seq, Epoch(0).low16(), BOOK, false);
    let mut buf = [0u8; MAX_REQ_PAYLOAD];
    let n = encode_request(&mut buf, hdr, msgs, &kseq(l, a), None).unwrap();
    buf[..n].to_vec()
}

/// A rest, a cross against it from another lane, and a third lane's improve; the engine is run
/// for 16 rounds of 100 ns after each packet. `tick` moves `Sim` time forward before every call.
fn run_on<V: Visibility>(vis: &V, tick: impl Fn(u64)) -> (Journal, Store) {
    use Side::{Buy, Sell};
    use Tif::Day;
    let bbo = Bbo::new(bbo_cfg());
    let mut sh = Shared::new(vis, N, arena_cfg(), &bbo.initial_snapshot()).unwrap();
    let mut e = engine_on(vis, bbo, &mut sh);
    let mut j = Journal::default();
    let mut store = Store::default();
    let pkts = [
        (0, 1, 1_000, new(Sell, Day, 105, 5, 1)),
        (1, 1, 2_000, new(Buy, Day, 105, 2, 2)),
        (2, 1, 3_000, new(Buy, Day, 100, 1, 3)),
        (1, 1, 4_000, new(Buy, Day, 105, 3, 4)),
    ];
    let mut seq = [[0u32; NA]; N];
    for (l, a, rx, m) in pkts {
        seq[l][a as usize] += 1;
        let b = packet(l, a, seq[l][a as usize], &[m]);
        let mut t = rx;
        tick(t);
        let p = RxIn {
            bytes: &b,
            rx_ts: Nanos(rx),
            pkt_hash: fake_hash(&b),
        };
        e.ingest(l, p, &vyrn_bbo::admit::FixedClock(rx), &mut j)
            .unwrap();
        store
            .0
            .push(((LaneId(l as u8), sid(l, a), seq[l][a as usize], rx), b));
        // `run` is quiet when no visible line has work; a line still in flight is not visible,
        // so the driver keeps virtual time moving for a fixed number of rounds.
        for _ in 0..16 {
            t += 100;
            tick(t);
            e.run(&NeverLate, &mut j, 1).unwrap();
        }
    }
    (j, store)
}

/// Records with the half-cut publication ids cleared: those count publications, which a
/// delayed backend changes (spec gap G1 of #39).
fn logical(recs: &[OwnedRec]) -> Vec<OwnedRec> {
    recs.iter()
        .map(|r| match *r {
            OwnedRec::Step(e, d) => OwnedRec::Step(
                StepEntry {
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

#[test]
fn sim_without_delay_matches_hw() {
    let (hw, _) = run_on(&vyrn_cut::Hw, |_| {});
    let sim = Sim::new(1, 0);
    let (s, _) = run_on(&sim, |t| sim.advance_to(t));
    assert!(s.recs == hw.recs, "order stream");
    assert!(s.resp == hw.resp && s.tx == hw.tx, "responses and fill TX");
}

#[test]
fn sim_with_delays_trades_the_same_without_a_fault() {
    // A delayed half-cut, step log or `LaneCut` changes the schedule (which step sees which
    // cut, which `LaneCut` a lane's idle poll reads), not the trades: every seed runs without
    // a fault and fills the same orders.
    let (hw, _) = run_on(&vyrn_cut::Hw, |_| {});
    let fills = |j: &Journal| {
        let mut f: Vec<_> = j.tx.iter().flat_map(|(_, r)| r.iter().copied()).collect();
        f.sort_by_key(|r| format!("{r:?}"));
        f
    };
    let (mut changed, mut stale_polls) = (0, 0);
    for seed in 0..32 {
        let sim = Sim::new(seed, 150);
        let (s, store) = run_on(&sim, |t| sim.advance_to(t));
        assert!(fills(&s) == fills(&hw), "seed {seed}: fills");
        changed += usize::from(logical(&s.recs) != logical(&hw.recs));
        // Known gap (PR follow-up): replay runs a non-`MID` Advance record as the lane's idle
        // poll, which reads the newest `LaneCut`; live, the poll may have read an older one.
        // Replay must then stop at that record and nowhere else.
        if let Err(d) = replay(&s.recs, &store).0 {
            assert_eq!(d.why, Why::Mismatch, "seed {seed}");
            let OwnedRec::Packet(p) = s.recs[d.index] else {
                panic!("seed {seed}: replay stopped at a step");
            };
            assert_eq!(p.flags, PacketFlags::ADVANCE, "seed {seed}: {p:?}");
            stale_polls += 1;
        }
    }
    assert!(changed > 0, "the delays change some schedule");
    assert!(stale_polls < 32, "most schedules replay");
}
