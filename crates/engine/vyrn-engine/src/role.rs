//! The core-role table (11 §1.3, 05 §1.1, 01 §10): which engine role a core of the reference
//! box runs. The binary pins one thread per role; the engine itself never spawns (11 §3.3).

use vyrn_types::LaneId;

/// One core's role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Core 0: auction control, `uncross_price`, the control ring.
    Control,
    /// Cores 1 (A, lanes 0–24) and 6 (B, lanes 25–48).
    CutCore(Half),
    /// Core 2.
    Bbo,
    /// Cores 3 (A) and 5 (B).
    FillTx(Half),
    /// Cores 4 (A) and 7 (B): order stream, frames, `LaneCut`.
    Stream(Half),
    /// Cores 8–49: dedicated lanes 0–41.
    Lane(LaneId),
    /// Core 50.
    Hasher,
    /// Cores 56–62: the pooled lanes 42–48 (05 §6.9).
    PoolLane(LaneId),
    /// Any core not listed above. 05 D12 names cores 57 and 59–63 as spares, which overlaps
    /// the pool (56–62, D15, §16.1); this table follows D15 (spec gap, PR body).
    Spare,
}

/// Half of the box: lanes `0..25` (A) or `25..` (B).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    A,
    B,
}

/// First core of the dedicated lanes, and of the pool.
pub const LANE_CORE0: u16 = 8;
pub const POOL_CORE0: u16 = 56;
/// Dedicated lanes (0–41) and pooled lanes (42–48), 05 D15.
pub const N_DEDICATED: u16 = 42;
pub const N_POOLED: u16 = 7;

/// The role of `core` on the reference core map.
pub fn role_of(core: u16) -> Role {
    let lane = |base: u16, off: u16| {
        core.checked_sub(base)
            .and_then(|d| d.checked_add(off))
            .and_then(|l| u8::try_from(l).ok())
            .map(LaneId)
    };
    match core {
        0 => Role::Control,
        1 => Role::CutCore(Half::A),
        6 => Role::CutCore(Half::B),
        2 => Role::Bbo,
        3 => Role::FillTx(Half::A),
        5 => Role::FillTx(Half::B),
        4 => Role::Stream(Half::A),
        7 => Role::Stream(Half::B),
        50 => Role::Hasher,
        8..=49 => lane(LANE_CORE0, 0).map_or(Role::Spare, Role::Lane),
        56..=62 => lane(POOL_CORE0, N_DEDICATED).map_or(Role::Spare, Role::PoolLane),
        _ => Role::Spare,
    }
}

/// The half of lane `l` (cut core, stream core and fill TX core assignment).
pub fn half_of(l: LaneId) -> Half {
    if usize::from(l.0) < vyrn_cut::LANES_PER_HALF {
        Half::A
    } else {
        Half::B
    }
}
