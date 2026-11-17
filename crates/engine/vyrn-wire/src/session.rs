//! `SessionId` bits (04 §4.1): slot u12 in bits 0–11, `LaneId` in 12–19, generation u12 in 20–31.

use vyrn_types::{LaneId, SessionId};

const SLOT_MASK: u32 = 0xFFF;
const GEN_MAX: u16 = 0xFFF;

/// None if `slot` or `generation` does not fit in 12 bits.
pub fn session_id(slot: u16, lane: LaneId, generation: u16) -> Option<SessionId> {
    if u32::from(slot) > SLOT_MASK || generation > GEN_MAX {
        return None;
    }
    Some(SessionId(
        u32::from(slot) | u32::from(lane.0) << 12 | u32::from(generation) << 20,
    ))
}

pub fn session_slot(s: SessionId) -> u16 {
    u16::try_from(s.0 & SLOT_MASK).unwrap_or(0)
}

pub fn session_lane(s: SessionId) -> LaneId {
    LaneId(u8::try_from((s.0 >> 12) & 0xFF).unwrap_or(0))
}

pub fn session_generation(s: SessionId) -> u16 {
    u16::try_from(s.0 >> 20).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_and_do_not_overlap() {
        let s = session_id(0xABC, LaneId(0x5D), 0x123);
        assert_eq!(s, Some(SessionId(0x1235_DABC)));
        let s = s.unwrap_or_default();
        assert_eq!(
            (session_slot(s), session_lane(s), session_generation(s)),
            (0xABC, LaneId(0x5D), 0x123)
        );
        assert_eq!(session_id(0x1000, LaneId(0), 0), None);
        assert_eq!(session_id(0, LaneId(0), 0x1000), None);
    }
}
