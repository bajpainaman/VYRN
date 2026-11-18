//! The `snap_lag` window against the replay ring (05 §6.5, 07 §3.6, §7.1). This crate's unit
//! tests shrink `REPLAY_SNAP_HIST` to 16, so the engine's lanes use a window of 15 and a few
//! improves are enough to leave it.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

#[path = "../tests/harness/mod.rs"]
mod harness;

use harness::{Act, Journal, N, live, new, replay, replay_blocks, replay_wire, sid, to_wire};
use vyrn_bbo::{Side, Tif};
use vyrn_types::{LaneId, LaneSeq, PacketFlags, PacketRecord};

use crate::{OwnedRec, REPLAY_SNAP_HIST, SNAP_LAG_WINDOW, Why};

const IMPROVES: u32 = 20;

/// Lane 1 moves the bid `IMPROVES` times (one snapshot version each) while lane 0 has no work,
/// so lane 0 takes no boundary; then lane 0 sends a join.
fn script() -> Vec<Act> {
    let p = |l, rx_ts, msgs| Act::Pkt {
        l,
        a: 1,
        rx_ts,
        now: rx_ts,
        msgs,
    };
    let mut s = Vec::new();
    for k in 0..IMPROVES {
        let t = 1_000 * u64::from(k + 1);
        s.push(p(1, t, vec![new(Side::Buy, Tif::Day, 80 + k, 1, k + 1)]));
        s.push(Act::Run);
    }
    s.push(p(0, 100_000, vec![new(Side::Buy, Tif::Day, 50, 1, 99)]));
    s.push(Act::Run);
    s
}

fn lane0_packets(j: &Journal) -> Vec<(usize, PacketRecord)> {
    j.recs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| match r {
            OwnedRec::Packet(p) if p.lane.0 == 0 => Some((i, *p)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_lagging_lane_catches_up_before_its_lag_leaves_the_replay_window() {
    assert_eq!(usize::from(SNAP_LAG_WINDOW), REPLAY_SNAP_HIST - 1);
    let (j, store, _, _) = live(&script());
    // Lane 0's join is preceded by its catch-up Advance record.
    let recs = lane0_packets(&j);
    let k = recs.iter().position(|(_, p)| p.count > 0).unwrap();
    let (i, pkt) = recs[k];
    let adv = k > 0 && recs[k - 1].1.flags & PacketFlags::ADVANCE != 0 && recs[k - 1].0 + 1 == i;
    assert!(adv, "no catch-up boundary right before the join: {recs:?}");
    // Every logged lag is inside the window, so the version is still in the ring.
    for r in &j.recs {
        if let OwnedRec::Packet(p) = r {
            assert!(p.snap_lag <= SNAP_LAG_WINDOW, "{p:?}");
        }
    }
    assert!(pkt.fills_applied.0 > 0, "{pkt:?}");
    // Both replays reproduce the log.
    let (r, out) = replay(&j.recs, &store);
    assert_eq!(r, Ok(()));
    assert_eq!(out.resp, j.resp);
    let (lanes, routes, steps) = to_wire(&j.recs);
    let (r, _) = replay_wire(&lanes, &routes, &steps, &store, Some(&j));
    assert_eq!(r.map_err(|e| e.why), Ok(()));
}

#[test]
fn a_packet_naming_an_evicted_snapshot_is_no_snapshot() {
    let (j, store, _, _) = live(&script());
    let (lanes, routes, steps) = to_wire(&j.recs);
    // Lane 2 never took a boundary, so its base is version 0, which the ring evicted after
    // `IMPROVES` > 16 versions. A packet record that names it, in a later block, is replayed
    // after every one of those steps.
    assert!(IMPROVES as usize > REPLAY_SNAP_HIST);
    let l = N - 1;
    let evicted = PacketRecord {
        lane: LaneId(l as u8),
        count: 1,
        flags: 0,
        session: sid(l, 1),
        pkt_seq: 1,
        rx_ts: vyrn_types::Nanos(200_000),
        pkt_hash: vyrn_types::PktHash(0),
        first_lane_seq: LaneSeq(1),
        fills_applied: vyrn_types::StepId(0),
        snap_lag: 0,
    };
    let later = [evicted];
    let (r, _, _) = replay_blocks(
        &[(&lanes, &routes, &steps), (&later, &[], &[])],
        &store,
        None,
    );
    assert_eq!(r.map_err(|e| e.why), Err(Why::NoSnapshot));
}
