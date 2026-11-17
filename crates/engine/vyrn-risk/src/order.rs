//! The inputs the checks read: the order's fields (01 §6.2), the snapshot (05), and the risk part of
//! the lane's order record (10 §4.3).

use vyrn_types::{Qty, Tick};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

/// Time in force, 01 §6.2 flags bits 1–2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tif {
    Day,
    Ioc,
    Fok,
    AuctionOnly,
}

/// The class 05 gives an order against the lane's snapshot (10 §3.1 check 10). In the auction
/// phase an order is not classified and the caller passes `Join`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Join,
    Improve,
    Cross,
}

/// Book phase other than halted (04 §6.9). A halt is the snapshot's `halted` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Continuous,
    Auction,
}

/// The fields of the BBO snapshot that risk reads (10 §3.1, §3.5). Tick 0 is an empty side; a
/// `ref_tick` of 0 means the book has no reference price yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub halted: bool,
    pub phase: Phase,
    pub bid: Tick,
    pub ask: Tick,
    pub ref_tick: Tick,
}

/// A `New`, or the new order of a priority-losing `Replace` (10 §3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewOrder {
    pub side: Side,
    pub tif: Tif,
    pub post_only: bool,
    pub tick: Tick,
    pub qty: Qty,
}

/// The risk fields of a lane order record (10 §4.3). `settled` counts the lots whose fill events
/// this lane applied, so `rem_u = qty − settled`; `closed` means the open remainder was released.
///
/// Two fields go beyond 10 §4.3: `fee_mul` and `msg_fee` are copied from the account at entry, so
/// a release or a `Shed` refund uses exactly what entry reserved and charged even after a
/// `CtlSetFees` (10 §5.2 rule 2). `route` is the route the order was charged as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderRisk {
    pub side: Side,
    pub tick: Tick,
    pub qty: Qty,
    pub settled: Qty,
    pub closed: bool,
    pub route: Route,
    pub fee_mul: u64,
    pub msg_fee: u32,
}
