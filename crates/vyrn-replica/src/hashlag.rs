//! The `REP_E_HASHLAG` timer (07 §3.7, INV-REP-8).
//!
//! The sequencer sends a record's `pkt_hash` at most `REP_HASH_LAG_NS` = 4 µs (budget) after the
//! record. A replica raises `REP_E_HASHLAG` when a record waits more than 1 ms. That is a
//! sequencer fault. The wait runs from the receive time of the record's ORDER frame on the
//! replica's own monotonic clock. It is an alarm input, never a replay input.

use vyrn_types::LaneId;

use crate::lane::{Awaiting, LaneState};

/// The longest a record may wait for its `pkt_hash`: 1 ms (07 §3.7).
pub const REP_HASHLAG_MAX_NS: u64 = 1_000_000;

/// A record that waited too long: its lane, its record and how long it waited, in ns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashLag {
    pub lane: LaneId,
    pub rec: Awaiting,
    pub waited: u64,
}

/// The oldest record of `lanes` that has waited more than `max_ns` at `now`. `max_ns` is
/// [`REP_HASHLAG_MAX_NS`] except under the validator's DEV-only `[replay] hashlag_us`.
/// `first_lane` is the lane id of `lanes[0]`. The FIFO of each lane is in arrival order, so only
/// the heads need to be checked.
pub fn check_hashlag(
    lanes: &[LaneState],
    first_lane: u8,
    now: u64,
    max_ns: u64,
) -> Result<(), HashLag> {
    let late = lanes
        .iter()
        .zip(first_lane..)
        .filter_map(|(st, l)| st.oldest_awaiting().map(|a| (l, *a)))
        .map(|(l, a)| (l, a, now.saturating_sub(a.arrived)))
        .filter(|&(_, _, w)| w > max_ns)
        .max_by_key(|&(_, _, w)| w);
    match late {
        Some((l, rec, waited)) => Err(HashLag {
            lane: LaneId(l),
            rec,
            waited,
        }),
        None => Ok(()),
    }
}
