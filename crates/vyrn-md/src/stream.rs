//! The replicated record stream that `vyrn-md` consumes: the seam to `vyrn-replica`.
//!
//! The observer's replay engine is the only writer. It hands over one book's events in replay
//! order (crate docs, "Input ordering"). This trait is all `vyrn-md` needs from the replica, so
//! the replica crate can land, and change, without this crate depending on it.

use vyrn_types::{Epoch, LaneId, Nanos, Qty, StepId, StepKind, Tick};

use crate::record::{AttestKind, BookStatus, DeleteCause, Side};

/// `oid = (lane << 24) | slot` (10 §7.5). `slot` keeps its low 24 bits.
pub const fn oid(lane: LaneId, slot: u32) -> u32 {
    ((lane.0 as u32) << 24) | (slot & 0x00FF_FFFF)
}

/// A change to one resting order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookOp {
    /// `prio_ts` is the order's time priority (its packet's `rx_ts`), not the event's.
    Add {
        oid: u32,
        side: Side,
        tick: Tick,
        qty: Qty,
        prio_ts: Nanos,
        via_bbo: bool,
        auction: bool,
    },
    /// Removes what is left of the order; `qty` is that remainder.
    Delete {
        oid: u32,
        cause: DeleteCause,
        tick: Tick,
        qty: Qty,
    },
    Reduce {
        oid: u32,
        tick: Tick,
        qty_after: Qty,
    },
}

impl BookOp {
    pub const fn oid(&self) -> u32 {
        match *self {
            BookOp::Add { oid, .. } | BookOp::Delete { oid, .. } | BookOp::Reduce { oid, .. } => {
                oid
            }
        }
    }
}

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A lane op (join, cancel, reduce) of the lane in the oid's high byte, ordered after the
    /// open step and before the next one. It goes to lane channel `lane mod 4`.
    LaneOp(BookOp),
    /// A BBO-core step that changes the book. Its `n_exec` execs follow before the next step.
    Step {
        step: StepId,
        kind: StepKind,
        n_exec: u16,
        taker: u32,
    },
    Exec {
        aggressor: Side,
        ordinal: u16,
        maker: u32,
        tick: Tick,
        qty: Qty,
    },
    /// A book change made by the open step: an improve or resting residual, an STP delete.
    StepOp(BookOp),
    /// A status change at the open step.
    Status { status: BookStatus, epoch: Epoch },
    Attest {
        kind: AttestKind,
        height_low: u32,
        last_step: StepId,
    },
    /// The `CtlTimerTick` boundary (every `MD_HEARTBEAT_MS`).
    TimerTick,
}

/// One replayed event. `rx_ts` is order-stream time and never decreases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub rx_ts: Nanos,
    pub kind: EventKind,
}

/// The replicated record stream of one book and one epoch. `None` ends the epoch.
pub trait ReplayStream {
    fn next_event(&mut self) -> Option<Event>;
}

impl<I: Iterator<Item = Event>> ReplayStream for I {
    fn next_event(&mut self) -> Option<Event> {
        self.next()
    }
}
