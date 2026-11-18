//! `TRADES` and `STATS` (10 §7.2): one record per maker match, and per-second statistics.

use vyrn_types::{BookId, Epoch, Nanos, StepKind};

use crate::chan::{OrderCheck, Packer, ends_group};
use crate::mbo::{PacketSink, StreamError};
use crate::packet::{Channel, Feed};
use crate::record::{BookStatus, Record};
use crate::stream::{Event, EventKind, ReplayStream};

/// Encodes `TRADES` for one book and one epoch on channel 0: one `MD_TRADE` per `MD_EXEC`.
/// Its execution ID is (`step_base + step_delta`, `ordinal`). `auction` is set for the execs of
/// an `Uncross` step. \[Guessing\] 10 §7.5 does not say which steps are auction trades.
pub struct TradesEncoder {
    order: OrderCheck,
    auction: bool,
    packer: Packer,
}

impl TradesEncoder {
    pub fn new(book: BookId, epoch: Epoch) -> Self {
        TradesEncoder {
            order: OrderCheck::default(),
            auction: false,
            packer: Packer::new(
                Channel {
                    feed: Feed::Trades,
                    index: 0,
                },
                book,
                epoch.low16(),
            ),
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
        let newest = self.order.newest;
        self.order.check(ev)?;
        let ts = ev.rx_ts.0;
        match ev.kind {
            EventKind::Step { kind, .. } => {
                self.packer.end_interval(newest, sink);
                self.auction = kind == StepKind::Uncross;
            }
            EventKind::Exec {
                aggressor,
                ordinal,
                tick,
                qty,
                ..
            } => {
                let auction = self.auction;
                self.packer.put_delta(
                    ts,
                    self.order.open_step,
                    ts,
                    sink,
                    |ts_delta, step_delta| Record::Trade {
                        aggressor,
                        auction,
                        ts_delta,
                        step_delta,
                        ordinal,
                        tick,
                        qty,
                    },
                );
            }
            EventKind::Bust {
                step,
                ordinal,
                tick,
                qty,
            } => {
                // step_delta counts from the packet's step_base, so a bust of a step older than
                // the open packet's base closes it and opens one based at the busted step.
                self.packer
                    .put_delta(ts, step.0, ts, sink, |_, step_delta| Record::TradeBust {
                        step_delta,
                        ordinal,
                        tick,
                        qty,
                    });
            }
            EventKind::TimerTick => self.packer.tick(ts, self.order.open_step, sink),
            _ => {}
        }
        Ok(())
    }

    pub fn finish(&mut self, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        self.order.finish()?;
        self.packer
            .finish(self.order.newest, self.order.open_step, sink);
        Ok(())
    }
}

code_enum!(
    /// `MD_STAT` stat ids. 10 §7.2 names the statistics but assigns no codes; these are this
    /// crate's. \[Guessing\]
    StatId {
        /// First trade tick of the second.
        Open = 1,
        High = 2,
        Low = 3,
        /// Last trade tick of the second.
        Close = 4,
        /// Quantity traded in the second.
        Volume = 5,
        /// Volume-weighted average tick, unsigned 32.32 fixed point, rounded down.
        Vwap = 6,
        /// `MD_EXEC`s in the second.
        Trades = 7,
        /// `Cross` steps in the second: `crosses(s)` of 10 §9.3.
        Crosses = 8,
        /// The book status at the end of the second, as its `MD_STATUS` code.
        Status = 9,
    }
);

const SEC_NS: u64 = 1_000_000_000;

#[derive(Default)]
struct Second {
    open: u32,
    high: u32,
    low: u32,
    close: u32,
    volume: u64,
    notional: u128,
    trades: u64,
    crosses: u64,
}

/// Encodes `STATS` for one book and one epoch on channel 0.
///
/// Second `s` covers `rx_ts` in `epoch_start + s × 10^9 …`, where `epoch_start` is the epoch's
/// first order-stream time, given by the caller. \[Guessing\] At the first evaluation point
/// (as for `MBP-10`) in a later second, and at epoch end, the second's records go out in
/// `StatId` order: the trade statistics if it had a trade, then `Crosses`, then `Status` once a
/// status is known.
pub struct StatsEncoder {
    epoch_start: u64,
    order: OrderCheck,
    second: u64,
    cur: Second,
    status: Option<BookStatus>,
    packer: Packer,
}

impl StatsEncoder {
    pub fn new(book: BookId, epoch: Epoch, epoch_start: Nanos) -> Self {
        StatsEncoder {
            epoch_start: epoch_start.0,
            order: OrderCheck::default(),
            second: 0,
            cur: Second::default(),
            status: None,
            packer: Packer::new(
                Channel {
                    feed: Feed::Stats,
                    index: 0,
                },
                book,
                epoch.low16(),
            ),
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
        let (newest, step) = (self.order.newest, self.order.open_step);
        self.order.check(ev)?;
        if ends_group(&ev.kind) {
            let s = ev.rx_ts.0.saturating_sub(self.epoch_start) / SEC_NS;
            if s > self.second {
                self.emit(newest, step, sink);
                self.second = s;
            }
        }
        match ev.kind {
            EventKind::Step { kind, .. } => {
                self.packer.end_interval(newest, sink);
                if kind == StepKind::Cross {
                    self.cur.crosses += 1;
                }
            }
            EventKind::Exec { tick, qty, .. } => {
                let (t, c) = (tick.0, &mut self.cur);
                if c.trades == 0 {
                    (c.open, c.high, c.low) = (t, t, t);
                }
                c.high = c.high.max(t);
                c.low = c.low.min(t);
                c.close = t;
                c.volume += u64::from(qty.0);
                c.notional += u128::from(t) * u128::from(qty.0);
                c.trades += 1;
            }
            EventKind::Status { status, .. } => self.status = Some(status),
            EventKind::TimerTick => {
                self.packer
                    .tick(self.order.newest, self.order.open_step, sink);
            }
            _ => {}
        }
        Ok(())
    }

    /// Emits the open second, then the epoch's last packet.
    pub fn finish(&mut self, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        self.order.finish()?;
        let (t, step) = (self.order.newest, self.order.open_step);
        self.emit(t, step, sink);
        self.packer.finish(t, step, sink);
        Ok(())
    }

    fn emit(&mut self, newest: u64, step: u64, sink: &mut impl PacketSink) {
        let c = core::mem::take(&mut self.cur);
        let second = u32::try_from(self.second).unwrap_or(u32::MAX);
        let mut put = |id: StatId, value: u64| {
            let rec = Record::Stat {
                stat: id.code(),
                second,
                value,
            };
            self.packer.put(&rec, newest, step, sink);
        };
        if c.trades > 0 {
            let vwap = (c.notional << 32) / u128::from(c.volume);
            put(StatId::Open, u64::from(c.open));
            put(StatId::High, u64::from(c.high));
            put(StatId::Low, u64::from(c.low));
            put(StatId::Close, u64::from(c.close));
            put(StatId::Volume, c.volume);
            put(StatId::Vwap, u64::try_from(vwap).unwrap_or(u64::MAX));
            put(StatId::Trades, c.trades);
        }
        put(StatId::Crosses, c.crosses);
        if let Some(s) = self.status {
            put(StatId::Status, u64::from(s.code()));
        }
    }
}
