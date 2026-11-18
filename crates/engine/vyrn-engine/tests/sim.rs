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
use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{Bbo, Side, StepEntry, Tif};
use vyrn_cut::{Sim, Visibility};
use vyrn_engine::{Engine, OwnedRec, Shared};
use vyrn_lane::{Lane, RxIn, SessionSpec};
use vyrn_risk::{AcctRisk, AcctSlot, SessionBuckets};
use vyrn_types::{AccountId, Epoch, LaneId, MAX_REQ_PAYLOAD, Nanos};
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
    let mut changed = 0;
    for seed in 0..32 {
        let sim = Sim::new(seed, 150);
        let (s, store) = run_on(&sim, |t| sim.advance_to(t));
        assert!(fills(&s) == fills(&hw), "seed {seed}: fills");
        changed += usize::from(logical(&s.recs) != logical(&hw.recs));
        // F3a: a non-`MID` Advance record replays as the boundary at the `(f, C_f[l])` it
        // logs, so a live idle poll that read an older `LaneCut` replays exactly too.
        let (r, rep) = replay(&s.recs, &store);
        assert_eq!(r, Ok(()), "seed {seed}");
        assert!(
            logical(&rep.recs) == logical(&s.recs),
            "seed {seed}: records"
        );
    }
    assert!(changed > 0, "the delays change some schedule");
}

/// Seeded packets on all three lanes on a `Sim` box whose lines lag up to `delay` ns, the engine
/// run in short bursts between them, then until quiet.
fn interleaved_on_sim(seed: u64, delay: u64) -> (Journal, Store) {
    let sim = Sim::new(seed, delay);
    let bbo = Bbo::new(bbo_cfg());
    let mut sh = Shared::new(&sim, N, arena_cfg(), &bbo.initial_snapshot()).unwrap();
    let mut e = engine_on(&sim, bbo, &mut sh);
    let (mut j, mut store) = (Journal::default(), Store::default());
    let mut r = Rng::new(seed);
    let (mut seq, mut t, mut tag) = ([0u32; N], 1_000u64, 0u32);
    for _ in 0..10 + r.below(30) {
        let l = r.below(N as u64) as usize;
        let msgs = r.orders(&mut tag, 96);
        seq[l] += 1;
        let b = packet(l, 1, seq[l], &msgs);
        t += 50 + r.below(200);
        sim.advance_to(t);
        let p = RxIn {
            bytes: &b,
            rx_ts: Nanos(t),
            pkt_hash: fake_hash(&b),
        };
        e.ingest(l, p, &FixedClock(t), &mut j).unwrap();
        store.0.push(((LaneId(l as u8), sid(l, 1), seq[l], t), b));
        for _ in 0..r.below(6) {
            t += 20 + r.below(80);
            sim.advance_to(t);
            e.run(&NeverLate, &mut j, 1).unwrap();
        }
    }
    for _ in 0..400 {
        t += 100;
        sim.advance_to(t);
        e.run(&NeverLate, &mut j, 1).unwrap();
    }
    (j, store)
}

#[test]
fn replay_takes_the_lowver_lanes_the_live_step_logged() {
    // The WL-SMOKE replay flake: a step sets a lane's `lowver` (05 §8.6) when its cut lands on
    // the lane's half-cut entry. A lagging half-cut put live's entry at the cut while replay's
    // lanes, which replay every record due before the step, were already past it, so replay
    // kept an older `lowver` (live step 4: lane 1's became 1, replay's stayed 0), a wider band
    // envelope and different bounds. Each step now logs the lanes it updated (07 §3.8
    // `LOWVER`) and replay derives their versions from its own packet records (07 §7.1).
    // Before the fix seeds 7, 9, 10 and 14 replayed other `lowver` lanes than live logged.
    let mut taken = 0;
    for seed in 1..=16 {
        let (j, store) = interleaved_on_sim(seed, 150);
        let (lanes, routes, steps) = to_wire(&j.recs);
        let (r, rep) = replay_wire(&lanes, &routes, &steps, &store, Some(&j));
        assert_eq!(r, Ok(()), "seed {seed}");
        let low = |recs: &[OwnedRec]| -> Vec<(u64, u64)> {
            recs.iter()
                .filter_map(|r| match r {
                    OwnedRec::Step(e, _) => Some((e.step.0, e.lowver)),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(low(&rep.recs), low(&j.recs), "seed {seed}: lowver lanes");
        taken += low(&j.recs).iter().filter(|(_, m)| *m != 0).count();
    }
    assert!(taken > 0, "some steps take a lowver");
}
