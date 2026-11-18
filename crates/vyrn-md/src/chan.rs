//! One single-channel packetizer and the stream-order check, shared by the derived feeds
//! (`MBP-10`, `TOB`, `TRADES`, `STATS`). The five-channel `MBO` encoder keeps its own copy of the
//! same rules (crate docs, "Output").

use vyrn_types::{BookId, Nanos};

use crate::mbo::{PacketSink, StreamError};
use crate::packet::{Channel, HEADER_BYTES, Header};
use crate::record::{REC_BYTES, Record};
use crate::stream::{Event, EventKind};
use crate::{MD_FLUSH_NS, MD_MAX_RECS_PER_PKT};

const PKT_MAX: usize = HEADER_BYTES + MD_MAX_RECS_PER_PKT * REC_BYTES;

/// The input-ordering rules 1 and 2 of the crate docs, as the `MBO` encoder checks them.
#[derive(Default)]
pub(crate) struct OrderCheck {
    pub open_step: u64,
    n_exec: u16,
    execs: u16,
    pub newest: u64,
    finished: bool,
}

impl OrderCheck {
    /// Checks `ev` and, when it is valid, advances the open step and the newest `rx_ts`.
    pub fn check(&mut self, ev: &Event) -> Result<(), StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        if ev.rx_ts.0 < self.newest {
            return Err(StreamError::TimeBackwards);
        }
        match ev.kind {
            EventKind::Step { step, n_exec, .. } => {
                if Some(step.0) != self.open_step.checked_add(1) {
                    return Err(StreamError::StepOrder);
                }
                self.check_execs()?;
                self.open_step = step.0;
                self.n_exec = n_exec;
                self.execs = 0;
            }
            EventKind::Exec { .. } if self.open_step == 0 => return Err(StreamError::OutsideStep),
            EventKind::Exec { .. } if self.execs >= self.n_exec => {
                return Err(StreamError::ExecCount);
            }
            EventKind::Exec { .. } => self.execs += 1,
            EventKind::StepOp(_) if self.open_step == 0 => return Err(StreamError::OutsideStep),
            EventKind::Bust { step, .. } if step.0 > self.open_step => {
                return Err(StreamError::BustAhead);
            }
            _ => {}
        }
        self.newest = ev.rx_ts.0;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        self.check_execs()?;
        self.finished = true;
        Ok(())
    }

    fn check_execs(&self) -> Result<(), StreamError> {
        if self.open_step > 0 && self.execs != self.n_exec {
            return Err(StreamError::ExecCount);
        }
        Ok(())
    }
}

/// An evaluation point (crate docs, "Derived feeds"): an event that is not part of the open
/// step's group, so the book before it is a state the replica held between groups.
pub(crate) const fn ends_group(kind: &EventKind) -> bool {
    !matches!(kind, EventKind::Exec { .. } | EventKind::StepOp(_))
}

/// One channel of a derived feed: flush rules (a)–(d) of 10 §7.3 and heartbeats.
/// `step_base` is the step open when the packet's first record was written.
pub(crate) struct Packer {
    channel: Channel,
    book: BookId,
    epoch16: u16,
    buf: [u8; PKT_MAX],
    count: usize,
    seq: u64,
    ts_base: u64,
    step_base: u64,
    opened_at: u64,
    added: bool,
    sent: bool,
}

impl Packer {
    pub fn new(channel: Channel, book: BookId, epoch16: u16) -> Self {
        Packer {
            channel,
            book,
            epoch16,
            buf: [0; PKT_MAX],
            count: 0,
            seq: 1,
            ts_base: 0,
            step_base: 0,
            opened_at: 0,
            added: false,
            sent: false,
        }
    }

    /// Appends a record without delta fields. An empty packet opens with
    /// `ts_base = newest` and `step_base = open_step`.
    pub fn put(&mut self, rec: &Record, newest: u64, open_step: u64, sink: &mut impl PacketSink) {
        if self.count == 0 {
            self.open(newest, open_step, newest);
        }
        self.write(rec, sink);
    }

    /// Appends the record `f(ts_delta, step_delta)` for an event at `ts` in step `step`.
    /// Rule (d): when either delta does not fit in `u16` against the open packet's bases, the
    /// packet closes and the record opens the next one with deltas 0.
    pub fn put_delta(
        &mut self,
        ts: u64,
        step: u64,
        newest: u64,
        sink: &mut impl PacketSink,
        f: impl FnOnce(u16, u16) -> Record,
    ) {
        let fits = |base: u64, v: u64| v.checked_sub(base).and_then(|d| u16::try_from(d).ok());
        if self.count > 0 {
            if let (Some(dt), Some(ds)) = (fits(self.ts_base, ts), fits(self.step_base, step)) {
                return self.write(&f(dt, ds), sink);
            }
            self.close(sink);
        }
        self.open(ts, step, newest);
        self.write(&f(0, 0), sink);
    }

    /// Rules (b) and (c) at the end of a step interval.
    pub fn end_interval(&mut self, newest: u64, sink: &mut impl PacketSink) {
        let old = newest.saturating_sub(self.opened_at) >= MD_FLUSH_NS;
        if self.count > 0 && (!self.added || old) {
            self.close(sink);
        }
        self.added = false;
    }

    /// The `CtlTimerTick` boundary: a heartbeat if the channel is idle and sent nothing since
    /// the last tick (spec gap 6 of #40, applied the same way).
    pub fn tick(&mut self, newest: u64, open_step: u64, sink: &mut impl PacketSink) {
        if self.count == 0 && !self.sent {
            self.open(newest, open_step, newest);
            self.close(sink);
        }
        self.sent = false;
    }

    /// Closes the open packet, if any.
    pub fn flush(&mut self, sink: &mut impl PacketSink) {
        if self.count > 0 {
            self.close(sink);
        }
    }

    /// Epoch end: the open packet, or a heartbeat.
    pub fn finish(&mut self, newest: u64, open_step: u64, sink: &mut impl PacketSink) {
        if self.count == 0 {
            self.open(newest, open_step, newest);
        }
        self.close(sink);
    }

    fn open(&mut self, ts_base: u64, step_base: u64, newest: u64) {
        self.ts_base = ts_base;
        self.step_base = step_base;
        self.opened_at = newest;
    }

    fn write(&mut self, rec: &Record, sink: &mut impl PacketSink) {
        let at = HEADER_BYTES + self.count * REC_BYTES;
        self.buf[at..at + REC_BYTES].copy_from_slice(&rec.encode());
        self.count += 1;
        self.added = true;
        if self.count == MD_MAX_RECS_PER_PKT {
            self.close(sink);
        }
    }

    fn close(&mut self, sink: &mut impl PacketSink) {
        let header = Header {
            channel: self.channel,
            count: u16::try_from(self.count).unwrap_or(u16::MAX),
            book: self.book,
            epoch16: self.epoch16,
            seq: self.seq,
            ts_base: Nanos(self.ts_base),
            step_base: self.step_base,
        };
        let mut hb = [0; HEADER_BYTES];
        header.write(&mut hb);
        self.buf[..HEADER_BYTES].copy_from_slice(&hb);
        sink.emit(
            self.channel,
            &self.buf[..HEADER_BYTES + self.count * REC_BYTES],
        );
        self.seq += 1;
        self.count = 0;
        self.sent = true;
    }
}
