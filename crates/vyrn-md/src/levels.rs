//! `MBP-10` and `TOB` (10 §7.2): price levels from the replayed order events, conflated on
//! order-stream time, as `MD_LEVEL` records.

use std::collections::BTreeMap;

use vyrn_types::{BookId, Epoch, Qty};

use crate::chan::{OrderCheck, Packer, ends_group};
use crate::mbo::{PacketSink, StreamError};
use crate::packet::{Channel, Feed};
use crate::record::{Record, Side};
use crate::stream::{BookOp, Event, EventKind, ReplayStream};

/// `MBP-10` conflation window, ns of order-stream time (10, constants).
pub const MD_MBP_WINDOW_NS: u64 = 10_000;
/// `TOB` window for quantity-only changes (10, constants).
pub const MD_TOB_WINDOW_NS: u64 = 1_000;
/// Levels per side of `MBP-10`.
pub const MBP_DEPTH: usize = 10;

/// One aggregated level: tick, total quantity, live orders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Level {
    pub tick: u32,
    pub qty: u64,
    pub orders: u32,
}

/// Live orders and their levels, both sides. The derived encoders keep one each.
#[derive(Clone, Debug, Default)]
pub struct LevelBook {
    orders: BTreeMap<u32, (Side, u32, u32)>,
    /// By side; ticks ascending.
    levels: [BTreeMap<u32, Level>; 2],
}

impl LevelBook {
    /// Applies an add, delete or reduce. `StreamError::Book` when it does not fit the book.
    pub fn apply(&mut self, op: &BookOp) -> Result<(), StreamError> {
        match *op {
            BookOp::Add {
                oid,
                side,
                tick,
                qty,
                ..
            } => {
                if qty.0 == 0 || self.orders.contains_key(&oid) {
                    return Err(StreamError::Book);
                }
                self.orders.insert(oid, (side, tick.0, qty.0));
                let l = self.levels[side as usize].entry(tick.0).or_insert(Level {
                    tick: tick.0,
                    ..Level::default()
                });
                l.qty += u64::from(qty.0);
                l.orders += 1;
            }
            BookOp::Delete { oid, tick, qty, .. } => {
                let &(side, t, q) = self.orders.get(&oid).ok_or(StreamError::Book)?;
                if t != tick.0 || q != qty.0 {
                    return Err(StreamError::Book);
                }
                self.take(oid, side, t, q, true);
            }
            BookOp::Reduce {
                oid,
                tick,
                qty_after,
            } => {
                let &(side, t, q) = self.orders.get(&oid).ok_or(StreamError::Book)?;
                if t != tick.0 || qty_after.0 == 0 || qty_after.0 >= q {
                    return Err(StreamError::Book);
                }
                self.take(oid, side, t, q - qty_after.0, false);
            }
        }
        Ok(())
    }

    /// Fills `qty` of resting `maker` at `tick`.
    pub fn exec(&mut self, maker: u32, tick: u32, qty: Qty) -> Result<(), StreamError> {
        let &(side, t, q) = self.orders.get(&maker).ok_or(StreamError::Book)?;
        if t != tick || qty.0 == 0 || qty.0 > q {
            return Err(StreamError::Book);
        }
        self.take(maker, side, t, qty.0, qty.0 == q);
        Ok(())
    }

    fn take(&mut self, oid: u32, side: Side, tick: u32, qty: u32, gone: bool) {
        if gone {
            self.orders.remove(&oid);
        } else if let Some(o) = self.orders.get_mut(&oid) {
            o.2 -= qty;
        }
        let levels = &mut self.levels[side as usize];
        if let Some(l) = levels.get_mut(&tick) {
            l.qty -= u64::from(qty);
            l.orders -= u32::from(gone);
            if l.orders == 0 {
                levels.remove(&tick);
            }
        }
    }

    /// The best `n` levels of `side`, best first: bids from the highest tick, asks from the
    /// lowest.
    pub fn top(&self, side: Side, n: usize) -> impl Iterator<Item = Level> + '_ {
        let l = &self.levels[side as usize];
        let it: Box<dyn Iterator<Item = &Level>> = match side {
            Side::Buy => Box::new(l.values().rev()),
            Side::Sell => Box::new(l.values()),
        };
        it.take(n).copied()
    }

    /// The best level of `side`.
    pub fn best(&self, side: Side) -> Option<Level> {
        match side {
            Side::Buy => self.levels[0].values().next_back().copied(),
            Side::Sell => self.levels[1].values().next().copied(),
        }
    }
}

/// `MD_LEVEL` for level `i` of `side`; `None` is an empty level (tick, orders, qty 0).
fn level_record(side: Side, i: usize, l: Option<Level>) -> Record {
    let l = l.unwrap_or_default();
    Record::Level {
        side,
        level: u8::try_from(i).unwrap_or(0),
        empty: l.orders == 0,
        orders: u16::try_from(l.orders).unwrap_or(u16::MAX),
        tick: vyrn_types::Tick(l.tick),
        qty: l.qty,
    }
}

/// Encodes `MBP-10` (depth 10) or `TOB` (depth 1) for one book and one epoch, on channel 0 of
/// its feed.
///
/// Evaluation points are the events that end the open step's group (any event but `Exec` and
/// `StepOp`) and the epoch end; the book is read just before the event is applied.
/// - `MBP-10`: at the first evaluation point in a later `MD_MBP_WINDOW_NS` window, one
///   `MD_LEVEL` for each of the 20 levels that differs from what was last published.
/// - `TOB`: at every evaluation point, a side whose best tick (or emptiness) changed; at the first
///   evaluation point in a later `MD_TOB_WINDOW_NS` window, a side whose quantity or order count
///   changed. Windows are `rx_ts / window`, so every observer cuts them alike. \[Guessing\]
pub struct LevelEncoder {
    depth: usize,
    window_ns: u64,
    book: LevelBook,
    /// Last published level, per side and level.
    published: [[Option<Level>; MBP_DEPTH]; 2],
    window: u64,
    order: OrderCheck,
    packer: Packer,
}

impl LevelEncoder {
    /// `MBP-10`.
    pub fn mbp10(book: BookId, epoch: Epoch) -> Self {
        Self::new(Feed::Mbp10, MBP_DEPTH, MD_MBP_WINDOW_NS, book, epoch)
    }

    /// `TOB`: `MD_LEVEL` level 0 (10 §7.5).
    pub fn tob(book: BookId, epoch: Epoch) -> Self {
        Self::new(Feed::Tob, 1, MD_TOB_WINDOW_NS, book, epoch)
    }

    fn new(feed: Feed, depth: usize, window_ns: u64, book: BookId, epoch: Epoch) -> Self {
        LevelEncoder {
            depth,
            window_ns,
            book: LevelBook::default(),
            published: [[None; MBP_DEPTH]; 2],
            window: 0,
            order: OrderCheck::default(),
            packer: Packer::new(Channel { feed, index: 0 }, book, epoch.low16()),
        }
    }

    /// The book as the encoder holds it.
    pub fn book(&self) -> &LevelBook {
        &self.book
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

    /// Encodes one event. On error the encoder must not be used again.
    pub fn push(&mut self, ev: &Event, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        let (newest, step) = (self.order.newest, self.order.open_step);
        self.order.check(ev)?;
        if ends_group(&ev.kind) {
            self.evaluate(ev.rx_ts.0, newest, step, sink);
        }
        match ev.kind {
            EventKind::Step { .. } => self.packer.end_interval(newest, sink),
            EventKind::LaneOp(op) | EventKind::StepOp(op) => self.book.apply(&op)?,
            EventKind::Exec {
                maker, tick, qty, ..
            } => self.book.exec(maker, tick.0, qty)?,
            EventKind::TimerTick => {
                self.packer
                    .tick(self.order.newest, self.order.open_step, sink);
            }
            _ => {}
        }
        Ok(())
    }

    /// Publishes what is pending, then the epoch's last packet (a heartbeat if empty).
    pub fn finish(&mut self, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        self.order.finish()?;
        let t = self.order.newest;
        self.publish(true, t, self.order.open_step, sink);
        self.packer.finish(t, self.order.open_step, sink);
        Ok(())
    }

    /// `t` is the event's `rx_ts`; records go out at the newest `rx_ts` before it.
    /// `step` is the step open before the event.
    fn evaluate(&mut self, t: u64, newest: u64, step: u64, sink: &mut impl PacketSink) {
        let w = t / self.window_ns;
        let new_window = w > self.window;
        self.window = w;
        self.publish(new_window, newest, step, sink);
    }

    fn publish(&mut self, all: bool, newest: u64, step: u64, sink: &mut impl PacketSink) {
        for side in [Side::Buy, Side::Sell] {
            let s = side as usize;
            let mut cur = [None; MBP_DEPTH];
            for (i, l) in self.book.top(side, self.depth).enumerate() {
                cur[i] = Some(l);
            }
            if self.depth == 1 {
                let (c, p) = (cur[0], self.published[s][0]);
                let price = c.map(|l| l.tick) != p.map(|l| l.tick);
                if c != p && (price || all) {
                    self.packer
                        .put(&level_record(side, 0, c), newest, step, sink);
                    self.published[s][0] = c;
                }
                continue;
            }
            if !all {
                continue;
            }
            for i in 0..self.depth {
                if cur[i] != self.published[s][i] {
                    self.packer
                        .put(&level_record(side, i, cur[i]), newest, step, sink);
                    self.published[s][i] = cur[i];
                }
            }
        }
    }
}
