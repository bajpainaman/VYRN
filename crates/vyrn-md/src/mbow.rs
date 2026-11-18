//! `MBO-W` (10 §7.7): `MBO` of the orders within `MD_MBO_W_TICKS` of the touch.
//!
//! [`MboWindow`] keeps the full book and rewrites the replay stream: ops on orders outside the
//! window are dropped, an order that enters gets a synthetic `MD_ADD` (its own priority
//! `rx_ts`), and one that leaves gets `MD_DELETE(cause 9)`. The rewritten stream goes through the
//! ordinary [`MboEncoder`] under feed `MBO-W`, so it keeps the `MBO` channels, flush rules and
//! merge rule, and all subscribers of one window size get identical bytes.
//!
//! Readings (\[Guessing\], 10 §7.7 does not fix them):
//! - The touch of a side is that side's best tick. A bid is in the window when
//!   `tick + W ≥ best bid`, an ask when `tick ≤ best ask + W`.
//! - The window is recomputed after every event. Entries and exits caused by a lane op go out
//!   as lane ops of the moved order's lane; those caused by a step go out as step ops after the
//!   event that caused them.
//! - An `MD_EXEC` on a maker outside the window (possible in an uncross) is preceded by its
//!   synthetic `MD_ADD`, so every exec of the full feed appears and `n_exec` is unchanged.

use std::collections::{BTreeMap, BTreeSet};

use vyrn_types::{BookId, Epoch, Nanos, Qty, Tick};

use crate::mbo::{MboEncoder, PacketSink, StreamError};
use crate::packet::Feed;
use crate::record::{DeleteCause, Side};
use crate::stream::{BookOp, Event, EventKind, ReplayStream};

/// The `MBO-W` window, ticks from the touch (10, constants).
pub const MD_MBO_W_TICKS: u32 = 256;

#[derive(Clone, Copy)]
struct Rest {
    side: Side,
    tick: u32,
    qty: u32,
    prio_ts: Nanos,
    via_bbo: bool,
    auction: bool,
    visible: bool,
}

/// The full book and the window over it. Feed it the replay stream; it writes the `MBO-W`
/// stream.
pub struct MboWindow {
    width: u32,
    orders: BTreeMap<u32, Rest>,
    /// Live oids by side and tick.
    ticks: [BTreeMap<u32, BTreeSet<u32>>; 2],
    open_step: u64,
}

impl MboWindow {
    pub fn new(width: u32) -> Self {
        MboWindow {
            width,
            orders: BTreeMap::new(),
            ticks: Default::default(),
            open_step: 0,
        }
    }

    fn in_window(&self, side: Side, tick: u32) -> bool {
        let t = &self.ticks[side as usize];
        match side {
            Side::Buy => t
                .keys()
                .next_back()
                .is_none_or(|&b| tick.saturating_add(self.width) >= b),
            Side::Sell => t
                .keys()
                .next()
                .is_none_or(|&a| tick <= a.saturating_add(self.width)),
        }
    }

    fn synth(&self, oid: u32, r: &Rest, enter: bool) -> BookOp {
        if enter {
            BookOp::Add {
                oid,
                side: r.side,
                tick: Tick(r.tick),
                qty: Qty(r.qty),
                prio_ts: r.prio_ts,
                via_bbo: r.via_bbo,
                auction: r.auction,
            }
        } else {
            BookOp::Delete {
                oid,
                cause: DeleteCause::WindowExit,
                tick: Tick(r.tick),
                qty: Qty(r.qty),
            }
        }
    }

    /// Rewrites one replay event into zero or more `MBO-W` events, appended to `out`.
    pub fn push(&mut self, ev: &Event, out: &mut Vec<Event>) -> Result<(), StreamError> {
        let at = |kind| Event {
            rx_ts: ev.rx_ts,
            kind,
        };
        let by_step;
        match ev.kind {
            EventKind::LaneOp(op) | EventKind::StepOp(op) => {
                by_step = matches!(ev.kind, EventKind::StepOp(_));
                if let Some(op) = self.apply(&op)? {
                    out.push(at(if by_step {
                        EventKind::StepOp(op)
                    } else {
                        EventKind::LaneOp(op)
                    }));
                }
            }
            EventKind::Exec {
                maker, tick, qty, ..
            } => {
                by_step = true;
                let r = *self.orders.get(&maker).ok_or(StreamError::Book)?;
                if r.tick != tick.0 || qty.0 == 0 || qty.0 > r.qty {
                    return Err(StreamError::Book);
                }
                if !r.visible {
                    out.push(at(EventKind::StepOp(self.synth(maker, &r, true))));
                }
                out.push(*ev);
                if qty.0 == r.qty {
                    self.remove(maker, r.side, r.tick);
                } else if let Some(o) = self.orders.get_mut(&maker) {
                    o.qty -= qty.0;
                    o.visible = true;
                }
            }
            EventKind::Step { step, .. } => {
                self.open_step = step.0;
                out.push(*ev);
                return Ok(());
            }
            _ => {
                out.push(*ev);
                return Ok(());
            }
        }
        // Moves in and out of the window after this event.
        let step_op = by_step && self.open_step > 0;
        let mut moved: Vec<(u32, bool)> = vec![];
        for (oid, r) in &self.orders {
            let inside = self.in_window(r.side, r.tick);
            if inside != r.visible {
                moved.push((*oid, inside));
            }
        }
        // Emit in (side, tick, oid) order.
        moved.sort_by_key(|&(oid, _)| {
            let r = &self.orders[&oid];
            (r.side, r.tick, oid)
        });
        for (oid, inside) in moved {
            let r = self.orders[&oid];
            let op = self.synth(oid, &r, inside);
            out.push(at(if step_op {
                EventKind::StepOp(op)
            } else {
                EventKind::LaneOp(op)
            }));
            if let Some(o) = self.orders.get_mut(&oid) {
                o.visible = inside;
            }
        }
        Ok(())
    }

    fn remove(&mut self, oid: u32, side: Side, tick: u32) {
        self.orders.remove(&oid);
        let t = &mut self.ticks[side as usize];
        if let Some(s) = t.get_mut(&tick) {
            s.remove(&oid);
            if s.is_empty() {
                t.remove(&tick);
            }
        }
    }

    /// Applies `op` to the full book; returns it if the window shows it.
    fn apply(&mut self, op: &BookOp) -> Result<Option<BookOp>, StreamError> {
        match *op {
            BookOp::Add {
                oid,
                side,
                tick,
                qty,
                prio_ts,
                via_bbo,
                auction,
            } => {
                if qty.0 == 0 || self.orders.contains_key(&oid) {
                    return Err(StreamError::Book);
                }
                self.ticks[side as usize]
                    .entry(tick.0)
                    .or_default()
                    .insert(oid);
                let visible = self.in_window(side, tick.0);
                self.orders.insert(
                    oid,
                    Rest {
                        side,
                        tick: tick.0,
                        qty: qty.0,
                        prio_ts,
                        via_bbo,
                        auction,
                        visible,
                    },
                );
                Ok(visible.then_some(*op))
            }
            BookOp::Delete { oid, tick, qty, .. } => {
                let r = *self.orders.get(&oid).ok_or(StreamError::Book)?;
                if r.tick != tick.0 || r.qty != qty.0 {
                    return Err(StreamError::Book);
                }
                self.remove(oid, r.side, r.tick);
                Ok(r.visible.then_some(*op))
            }
            BookOp::Reduce {
                oid,
                tick,
                qty_after,
            } => {
                let o = self.orders.get_mut(&oid).ok_or(StreamError::Book)?;
                if o.tick != tick.0 || qty_after.0 == 0 || qty_after.0 >= o.qty {
                    return Err(StreamError::Book);
                }
                o.qty = qty_after.0;
                Ok(o.visible.then_some(*op))
            }
        }
    }
}

/// `MBO-W` of one book and one epoch: [`MboWindow`] in front of an [`MboEncoder`].
pub struct MboWEncoder {
    window: MboWindow,
    enc: MboEncoder,
    buf: Vec<Event>,
}

impl MboWEncoder {
    pub fn new(book: BookId, epoch: Epoch, width: u32) -> Self {
        MboWEncoder {
            window: MboWindow::new(width),
            enc: MboEncoder::with_feed(Feed::MboW, book, epoch),
            buf: vec![],
        }
    }

    pub fn run(
        &mut self,
        stream: &mut impl ReplayStream,
        sink: &mut impl PacketSink,
    ) -> Result<(), StreamError> {
        while let Some(ev) = stream.next_event() {
            self.push(&ev, sink)?;
        }
        self.finish(sink)
    }

    pub fn push(&mut self, ev: &Event, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        self.buf.clear();
        self.window.push(ev, &mut self.buf)?;
        for e in &self.buf {
            self.enc.push(e, sink)?;
        }
        Ok(())
    }

    pub fn finish(&mut self, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        self.enc.finish(sink)
    }
}
