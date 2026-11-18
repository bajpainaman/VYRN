//! The reference `MBO` reader: the merge rule of 10 §7.4 over a simple order book.
//!
//! The snapshotter (10 §7.6) and conformance tests use it; a production subscriber may keep a
//! faster book but must apply records in an order this reader accepts.

use std::collections::{BTreeMap, VecDeque};

use vyrn_types::{BookId, Epoch, Nanos, Qty, StepId, Tick};

use crate::packet::{Feed, NO_WATERMARK, Packet, PacketError};
use crate::record::{Record, Side};
use crate::{MD_MBO_LANE_CHANNELS, MD_MBO_STEP_CHANNEL};

const N_CHAN: usize = MD_MBO_LANE_CHANNELS + 1;
const STEP: usize = MD_MBO_STEP_CHANNEL as usize;

/// One resting order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    pub side: Side,
    pub tick: Tick,
    pub qty: Qty,
    /// Priority `rx_ts`, from the `MD_ADD`.
    pub prio_ts: Nanos,
}

/// Live orders by oid.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    orders: BTreeMap<u32, Order>,
}

/// Why a record does not apply to the book.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookError {
    /// `MD_ADD` of a live oid.
    DuplicateOid,
    /// A record on an oid that is not live.
    UnknownOid,
    /// Tick, side or quantity disagree with the live order.
    Mismatch,
    /// An exec larger than what rests.
    OverFill,
}

impl Book {
    pub fn orders(&self) -> &BTreeMap<u32, Order> {
        &self.orders
    }

    /// Applies one record. Records that do not change orders are accepted and ignored.
    pub fn apply(&mut self, rec: &Record, ts_base: Nanos) -> Result<(), BookError> {
        match *rec {
            Record::Add {
                side,
                ts_delta,
                oid,
                tick,
                qty,
                ..
            } => {
                if qty.0 == 0 {
                    return Err(BookError::Mismatch);
                }
                let prio_ts = Nanos(ts_base.0.saturating_add(u64::from(ts_delta)));
                let o = Order {
                    side,
                    tick,
                    qty,
                    prio_ts,
                };
                if self.orders.insert(oid, o).is_some() {
                    return Err(BookError::DuplicateOid);
                }
            }
            Record::Delete { oid, tick, qty, .. } => {
                let o = self.orders.get(&oid).ok_or(BookError::UnknownOid)?;
                if o.tick != tick || o.qty != qty {
                    return Err(BookError::Mismatch);
                }
                self.orders.remove(&oid);
            }
            Record::Reduce { oid, tick, qty } => {
                let o = self.orders.get_mut(&oid).ok_or(BookError::UnknownOid)?;
                if o.tick != tick || qty.0 == 0 || qty >= o.qty {
                    return Err(BookError::Mismatch);
                }
                o.qty = qty;
            }
            Record::Exec {
                aggressor,
                maker,
                tick,
                qty,
                ..
            } => {
                let o = self.orders.get_mut(&maker).ok_or(BookError::UnknownOid)?;
                if o.tick != tick || o.side == aggressor || qty.0 == 0 {
                    return Err(BookError::Mismatch);
                }
                o.qty = o.qty.checked_sub(qty).ok_or(BookError::OverFill)?;
                if o.qty.0 == 0 {
                    self.orders.remove(&maker);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Why the subscriber refused a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubError {
    Packet(PacketError),
    /// Not an `MBO` packet.
    WrongFeed,
    WrongBook,
    WrongEpoch,
    /// A `seq` other than the channel's next one: recover from retransmit or snapshot.
    Gap {
        channel: u8,
    },
    /// A channel index above 4, or a record type that its channel does not carry.
    WrongChannel,
    /// An `MD_SYNC` or a watermark that went backwards.
    Backwards,
    /// An `MD_STEP` that is not the last applied step + 1.
    StepOrder,
    Book(BookError),
    /// [`MboSubscriber::finish`] before every channel's final watermark arrived.
    Incomplete,
}

impl From<BookError> for SubError {
    fn from(e: BookError) -> Self {
        SubError::Book(e)
    }
}

/// Rebuilds one book from its `MBO` channels, received in any interleaving.
pub struct MboSubscriber {
    book_id: BookId,
    epoch16: u16,
    next_seq: [u64; N_CHAN],
    /// Lane-channel watermarks; `None` until a packet carries one.
    lane_w: [Option<u64>; MD_MBO_LANE_CHANNELS],
    /// Lane-channel `MD_SYNC` position.
    lane_pos: [u64; MD_MBO_LANE_CHANNELS],
    /// Lane ops not yet applied: (position, record, ts_base).
    pending: [VecDeque<(u64, Record, Nanos)>; MD_MBO_LANE_CHANNELS],
    /// Step-channel records not yet applied.
    steps: VecDeque<(Record, Nanos)>,
    last_step: u64,
    book: Book,
}

impl MboSubscriber {
    /// A subscriber that joins at epoch start (seq 1 on every channel).
    pub fn new(book: BookId, epoch: Epoch) -> Self {
        MboSubscriber {
            book_id: book,
            epoch16: epoch.low16(),
            next_seq: [1; N_CHAN],
            lane_w: [None; MD_MBO_LANE_CHANNELS],
            lane_pos: [0; MD_MBO_LANE_CHANNELS],
            pending: Default::default(),
            steps: VecDeque::new(),
            last_step: 0,
            book: Book::default(),
        }
    }

    /// The book after the last applied step and the lane ops released before it.
    pub fn book(&self) -> &Book {
        &self.book
    }

    pub fn last_step(&self) -> StepId {
        StepId(self.last_step)
    }

    /// Takes one UDP payload of any of the five `MBO` channels.
    pub fn on_packet(&mut self, bytes: &[u8]) -> Result<(), SubError> {
        let p = Packet::decode(bytes).map_err(SubError::Packet)?;
        let h = p.header;
        if h.channel.feed != Feed::Mbo {
            return Err(SubError::WrongFeed);
        }
        if h.book != self.book_id {
            return Err(SubError::WrongBook);
        }
        if h.epoch16 != self.epoch16 {
            return Err(SubError::WrongEpoch);
        }
        let c = usize::from(h.channel.index);
        if c >= N_CHAN {
            return Err(SubError::WrongChannel);
        }
        if h.seq != self.next_seq[c] {
            return Err(SubError::Gap {
                channel: h.channel.index,
            });
        }
        self.next_seq[c] += 1;
        if c == STEP {
            for r in p.records {
                if !matches!(
                    r,
                    Record::Step { .. }
                        | Record::Exec { .. }
                        | Record::Add { .. }
                        | Record::Delete { .. }
                        | Record::Reduce { .. }
                        | Record::Status { .. }
                        | Record::Attest { .. }
                        | Record::Bust { .. }
                ) {
                    return Err(SubError::WrongChannel);
                }
                self.steps.push_back((r, h.ts_base));
            }
        } else {
            for r in p.records {
                match r {
                    Record::Sync { step } => {
                        if step.0 < self.lane_pos[c] {
                            return Err(SubError::Backwards);
                        }
                        self.lane_pos[c] = step.0;
                    }
                    Record::Add { .. } | Record::Delete { .. } | Record::Reduce { .. } => {
                        self.pending[c].push_back((self.lane_pos[c], r, h.ts_base));
                    }
                    _ => return Err(SubError::WrongChannel),
                }
            }
            if h.step_base != NO_WATERMARK {
                if self.lane_w[c].is_some_and(|w| h.step_base < w) {
                    return Err(SubError::Backwards);
                }
                self.lane_w[c] = Some(h.step_base);
            }
        }
        self.pump()
    }

    /// Ends the epoch: applies the lane ops after the last step. Call it once every channel's
    /// final packet arrived; it fails with `Incomplete` otherwise.
    pub fn finish(&mut self) -> Result<(), SubError> {
        let done = self
            .lane_w
            .iter()
            .all(|w| w.is_some_and(|w| w >= self.last_step));
        if !done || !self.steps.is_empty() {
            return Err(SubError::Incomplete);
        }
        self.release(self.last_step + 1)?;
        if self.pending.iter().any(|q| !q.is_empty()) {
            return Err(SubError::Incomplete);
        }
        Ok(())
    }

    /// The merge rule: apply step `T` only when `W_k ≥ T − 1` for every lane channel, after the
    /// lane ops whose position is `< T`.
    fn pump(&mut self) -> Result<(), SubError> {
        while let Some(&(rec, ts_base)) = self.steps.front() {
            if let Record::Step { step, .. } = rec {
                if step.0 != self.last_step + 1 {
                    return Err(SubError::StepOrder);
                }
                let need = self.last_step;
                if !self.lane_w.iter().all(|w| w.is_some_and(|w| w >= need)) {
                    break;
                }
                self.release(step.0)?;
                self.last_step = step.0;
            } else {
                self.book.apply(&rec, ts_base)?;
            }
            self.steps.pop_front();
        }
        Ok(())
    }

    /// Applies every pending lane op whose position is `< before`.
    fn release(&mut self, before: u64) -> Result<(), SubError> {
        for q in &mut self.pending {
            while let Some(&(pos, rec, ts_base)) = q.front() {
                if pos >= before {
                    break;
                }
                self.book.apply(&rec, ts_base)?;
                q.pop_front();
            }
        }
        Ok(())
    }
}
