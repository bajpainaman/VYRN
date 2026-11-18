//! The `MBO` encoder (10 §7.3, §7.4): replay events in, packets out, a pure function of the log.
//!
//! Each channel writes records straight into one fixed packet buffer, so encoding allocates
//! nothing.

use vyrn_types::{BookId, Epoch, Nanos, StepId};

use crate::packet::{Channel, Feed, HEADER_BYTES, Header, NO_WATERMARK};
use crate::record::{REC_BYTES, Record};
use crate::stream::{BookOp, Event, EventKind, ReplayStream};
use crate::{MD_FLUSH_NS, MD_MAX_RECS_PER_PKT, MD_MBO_LANE_CHANNELS, MD_MBO_STEP_CHANNEL};

const PKT_MAX: usize = HEADER_BYTES + MD_MAX_RECS_PER_PKT * REC_BYTES;
const N_CHAN: usize = MD_MBO_LANE_CHANNELS + 1;
const STEP: usize = MD_MBO_STEP_CHANNEL as usize;

/// Where finished packets go: a NIC TX ring, a test vector, a relay.
pub trait PacketSink {
    /// `bytes` is one whole UDP payload of `channel`.
    fn emit(&mut self, channel: Channel, bytes: &[u8]);
}

impl PacketSink for Vec<Vec<u8>> {
    fn emit(&mut self, _: Channel, bytes: &[u8]) {
        self.push(bytes.to_vec());
    }
}

/// Why the encoder refused an event: the stream broke its ordering contract (crate docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// `rx_ts` decreased.
    TimeBackwards,
    /// A step that is not the open step + 1.
    StepOrder,
    /// More execs than the step's `n_exec`, or fewer before the next step or the end.
    ExecCount,
    /// An exec or step op before the first step.
    OutsideStep,
    /// An event after [`MboEncoder::finish`].
    Finished,
}

struct Chan {
    index: u8,
    buf: [u8; PKT_MAX],
    count: usize,
    seq: u64,
    ts_base: u64,
    /// The newest `rx_ts` when the packet's first record was written (flush rule c).
    opened_at: u64,
    /// Step channel: the step open when the packet's first record was written.
    step_base: u64,
    /// A record went into this channel during the current interval (flush rule b).
    added: bool,
    /// A packet left since the last timer tick.
    sent: bool,
    /// Lane channels: the interval of the last `MD_SYNC` (0 at epoch start, so no `MD_SYNC(0)`).
    synced: u64,
}

impl Chan {
    fn new(index: u8) -> Self {
        Chan {
            index,
            buf: [0; PKT_MAX],
            count: 0,
            seq: 1,
            ts_base: 0,
            opened_at: 0,
            step_base: 0,
            added: false,
            sent: false,
            synced: 0,
        }
    }
}

/// Encodes one book's `MBO` feed for one epoch.
pub struct MboEncoder {
    book: BookId,
    epoch16: u16,
    open_step: u64,
    n_exec: u16,
    execs: u16,
    newest: u64,
    chans: [Chan; N_CHAN],
    finished: bool,
}

impl MboEncoder {
    pub fn new(book: BookId, epoch: Epoch) -> Self {
        MboEncoder {
            book,
            epoch16: epoch.low16(),
            open_step: 0,
            n_exec: 0,
            execs: 0,
            newest: 0,
            chans: core::array::from_fn(|i| Chan::new(u8::try_from(i).unwrap_or(u8::MAX))),
            finished: false,
        }
    }

    /// Encodes the whole stream, then [`finish`](Self::finish)es the epoch.
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

    /// Encodes one event. On error nothing was written for it.
    pub fn push(&mut self, ev: &Event, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        let ts = ev.rx_ts.0;
        if ts < self.newest {
            return Err(StreamError::TimeBackwards);
        }
        match ev.kind {
            EventKind::Step { step, .. } => {
                if Some(step.0) != self.open_step.checked_add(1) {
                    return Err(StreamError::StepOrder);
                }
                self.check_execs()?;
                // The open interval ends here, judged by the newest rx_ts in it (spec gap 5).
                self.end_interval(sink);
            }
            EventKind::Exec { .. } if self.open_step == 0 => return Err(StreamError::OutsideStep),
            EventKind::Exec { .. } if self.execs >= self.n_exec => {
                return Err(StreamError::ExecCount);
            }
            EventKind::StepOp(_) if self.open_step == 0 => return Err(StreamError::OutsideStep),
            _ => {}
        }
        self.newest = ts;
        match ev.kind {
            EventKind::LaneOp(op) => {
                let c = usize::try_from(op.oid() >> 24).unwrap_or(0) % MD_MBO_LANE_CHANNELS;
                if self.chans[c].synced != self.open_step {
                    self.chans[c].synced = self.open_step;
                    let sync = Record::Sync {
                        step: StepId(self.open_step),
                    };
                    self.put(c, &sync, ts, sink);
                }
                self.put_op(c, &op, ts, sink);
            }
            EventKind::Step {
                step,
                kind,
                n_exec,
                taker,
            } => {
                self.open_step = step.0;
                self.n_exec = n_exec;
                self.execs = 0;
                let rec = Record::Step {
                    kind,
                    n_exec,
                    step,
                    taker,
                };
                self.put(STEP, &rec, ts, sink);
            }
            EventKind::Exec {
                aggressor,
                ordinal,
                maker,
                tick,
                qty,
            } => {
                self.execs += 1;
                let rec = Record::Exec {
                    aggressor,
                    ordinal,
                    maker,
                    tick,
                    qty,
                };
                self.put(STEP, &rec, ts, sink);
            }
            EventKind::StepOp(op) => self.put_op(STEP, &op, ts, sink),
            EventKind::Status { status, epoch } => {
                let rec = Record::Status {
                    status,
                    epoch,
                    step: StepId(self.open_step),
                };
                self.put(STEP, &rec, ts, sink);
            }
            EventKind::Attest {
                kind,
                height_low,
                last_step,
            } => {
                let rec = Record::Attest {
                    kind,
                    height_low,
                    last_step,
                };
                self.put(STEP, &rec, ts, sink);
            }
            EventKind::TimerTick => {
                let w = self.mid_watermark();
                for c in 0..N_CHAN {
                    if self.chans[c].count == 0 && !self.chans[c].sent {
                        self.heartbeat(c, w, sink);
                    }
                }
                for ch in &mut self.chans {
                    ch.sent = false;
                }
            }
        }
        Ok(())
    }

    /// Ends the epoch: every channel sends one last packet (a heartbeat if empty) whose
    /// watermark is the last step (spec gap 4).
    pub fn finish(&mut self, sink: &mut impl PacketSink) -> Result<(), StreamError> {
        if self.finished {
            return Err(StreamError::Finished);
        }
        self.check_execs()?;
        for c in 0..N_CHAN {
            if self.chans[c].count > 0 {
                self.close(c, self.open_step, sink);
            } else {
                self.heartbeat(c, self.open_step, sink);
            }
        }
        self.finished = true;
        Ok(())
    }

    fn check_execs(&self) -> Result<(), StreamError> {
        if self.open_step > 0 && self.execs != self.n_exec {
            return Err(StreamError::ExecCount);
        }
        Ok(())
    }

    /// The watermark of a lane packet closed inside interval `T`: `T − 1`.
    fn mid_watermark(&self) -> u64 {
        self.open_step.checked_sub(1).unwrap_or(NO_WATERMARK)
    }

    /// Flush rules (b) and (c) at the end of the open interval.
    fn end_interval(&mut self, sink: &mut impl PacketSink) {
        for c in 0..N_CHAN {
            let ch = &self.chans[c];
            let old = self.newest.saturating_sub(ch.opened_at) >= MD_FLUSH_NS;
            if ch.count > 0 && (!ch.added || old) {
                self.close(c, self.open_step, sink);
            }
            self.chans[c].added = false;
        }
    }

    fn put_op(&mut self, c: usize, op: &BookOp, ts: u64, sink: &mut impl PacketSink) {
        let rec = match *op {
            BookOp::Add {
                oid,
                side,
                tick,
                qty,
                prio_ts,
                via_bbo,
                auction,
            } => {
                let p = prio_ts.0;
                let ch = &self.chans[c];
                let delta = if ch.count == 0 {
                    Some(0)
                } else {
                    p.checked_sub(ch.ts_base)
                        .and_then(|d| u16::try_from(d).ok())
                };
                // Rule (d): close early when the ts_delta does not fit.
                let ts_delta = match delta {
                    Some(d) => d,
                    None => {
                        self.close(c, self.mid_watermark(), sink);
                        0
                    }
                };
                let rec = Record::Add {
                    side,
                    via_bbo,
                    auction,
                    ts_delta,
                    oid,
                    tick,
                    qty,
                };
                self.put(c, &rec, p, sink);
                return;
            }
            BookOp::Delete {
                oid,
                cause,
                tick,
                qty,
            } => Record::Delete {
                cause,
                oid,
                tick,
                qty,
            },
            BookOp::Reduce {
                oid,
                tick,
                qty_after,
            } => Record::Reduce {
                oid,
                tick,
                qty: qty_after,
            },
        };
        self.put(c, &rec, ts, sink);
    }

    /// Appends `rec`, opening a packet with `ts_base = base_ts` if none is open. Rule (a).
    fn put(&mut self, c: usize, rec: &Record, base_ts: u64, sink: &mut impl PacketSink) {
        let (newest, open_step) = (self.newest, self.open_step);
        let ch = &mut self.chans[c];
        if ch.count == 0 {
            ch.ts_base = base_ts;
            ch.opened_at = newest;
            ch.step_base = open_step;
        }
        let at = HEADER_BYTES + ch.count * REC_BYTES;
        ch.buf[at..at + REC_BYTES].copy_from_slice(&rec.encode());
        ch.count += 1;
        ch.added = true;
        if ch.count == MD_MAX_RECS_PER_PKT {
            self.close(c, self.mid_watermark(), sink);
        }
    }

    fn heartbeat(&mut self, c: usize, watermark: u64, sink: &mut impl PacketSink) {
        let ch = &mut self.chans[c];
        ch.ts_base = self.newest;
        ch.step_base = self.open_step;
        self.close(c, watermark, sink);
    }

    /// Sends the open packet. `watermark` is the lane channels' `step_base`.
    fn close(&mut self, c: usize, watermark: u64, sink: &mut impl PacketSink) {
        let ch = &mut self.chans[c];
        let header = Header {
            channel: Channel {
                feed: Feed::Mbo,
                index: ch.index,
            },
            count: u16::try_from(ch.count).unwrap_or(u16::MAX),
            book: self.book,
            epoch16: self.epoch16,
            seq: ch.seq,
            ts_base: Nanos(ch.ts_base),
            step_base: if c == STEP { ch.step_base } else { watermark },
        };
        let mut hb = [0; HEADER_BYTES];
        header.write(&mut hb);
        ch.buf[..HEADER_BYTES].copy_from_slice(&hb);
        sink.emit(
            header.channel,
            &ch.buf[..HEADER_BYTES + ch.count * REC_BYTES],
        );
        ch.seq += 1;
        ch.count = 0;
        ch.sent = true;
    }
}
