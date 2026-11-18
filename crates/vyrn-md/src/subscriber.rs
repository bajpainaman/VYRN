//! The reference `MBO` reader: the merge rule of 10 §7.4 over a simple order book.
//!
//! The snapshotter (10 §7.6) and conformance tests use it; a production subscriber may keep a
//! faster book but must apply records in an order this reader accepts.

use std::collections::btree_map::Entry;
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
                match self.orders.entry(oid) {
                    Entry::Occupied(_) => return Err(BookError::DuplicateOid),
                    Entry::Vacant(v) => {
                        v.insert(o);
                    }
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

/// Where a joining reader starts on one channel: record `record` of packet `seq`
/// (`MD_SNAP_RESUME`, 10 §7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    pub channel: u8,
    pub record: u16,
    pub seq: u64,
}

/// A book as of the end of step `as_of`'s interval: every record ordered before step
/// `as_of + 1` is in it, none after (10 §7.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub as_of: StepId,
    /// Level-FIFO order: buys then sells, best level first, then priority `(prio_ts, lane)`.
    pub orders: Vec<(u32, Order)>,
    /// One per channel, channel order.
    pub resume: Vec<Resume>,
}

/// Rebuilds one book from its `MBO` channels, received in any interleaving.
pub struct MboSubscriber {
    feed: Feed,
    book_id: BookId,
    epoch16: u16,
    next_seq: [u64; N_CHAN],
    /// Records to drop from the packet `next_seq[c]` (a resume point inside a packet).
    skip: [u16; N_CHAN],
    /// Records in the last packet taken on each channel.
    last_count: [u16; N_CHAN],
    /// Lane-channel watermarks; `None` until a packet carries one.
    lane_w: [Option<u64>; MD_MBO_LANE_CHANNELS],
    /// Lane-channel `MD_SYNC` position.
    lane_pos: [u64; MD_MBO_LANE_CHANNELS],
    /// Lane ops not yet applied: (position, record, ts_base).
    pending: [VecDeque<(u64, Record, Nanos)>; MD_MBO_LANE_CHANNELS],
    /// Where each `MD_SYNC` not yet behind the applied steps was: (step, seq, record index).
    syncs: [VecDeque<(u64, u64, u16)>; MD_MBO_LANE_CHANNELS],
    /// Step-channel records not yet applied, with their seq and record index.
    steps: VecDeque<(Record, Nanos, u64, u16)>,
    last_step: u64,
    /// `MD_EXEC`s of the last applied step not yet applied.
    exec_left: u16,
    /// Pause once the book is as of this step ([`snapshot_at`](Self::snapshot_at)).
    pause_at: Option<u64>,
    paused: bool,
    book: Book,
}

impl MboSubscriber {
    /// A subscriber that joins at epoch start (seq 1 on every channel).
    pub fn new(book: BookId, epoch: Epoch) -> Self {
        Self::with_feed(Feed::Mbo, book, epoch)
    }

    /// A subscriber of another feed with the `MBO` structure: `MBO-W` (10 §7.7).
    pub fn with_feed(feed: Feed, book: BookId, epoch: Epoch) -> Self {
        MboSubscriber {
            feed,
            book_id: book,
            epoch16: epoch.low16(),
            next_seq: [1; N_CHAN],
            skip: [0; N_CHAN],
            last_count: [0; N_CHAN],
            lane_w: [None; MD_MBO_LANE_CHANNELS],
            lane_pos: [0; MD_MBO_LANE_CHANNELS],
            pending: Default::default(),
            syncs: Default::default(),
            steps: VecDeque::new(),
            last_step: 0,
            exec_left: 0,
            pause_at: None,
            paused: false,
            book: Book::default(),
        }
    }

    /// A subscriber that joins mid-stream from a snapshot (10 §7.6 recovery). Feed it the
    /// buffered packets and then the live ones: packets before each channel's resume point are
    /// dropped, and so are the records before it in the resume packet.
    pub fn from_snapshot(feed: Feed, book: BookId, epoch: Epoch, snap: &Snapshot) -> Self {
        let mut s = Self::with_feed(feed, book, epoch);
        for r in &snap.resume {
            let c = usize::from(r.channel);
            if c < N_CHAN {
                s.next_seq[c] = r.seq;
                s.skip[c] = r.record;
            }
        }
        s.last_step = snap.as_of.0;
        s.lane_pos = [snap.as_of.0; MD_MBO_LANE_CHANNELS];
        s.book.orders = snap.orders.iter().copied().collect();
        s
    }

    /// The book after the last applied step and the lane ops released before it.
    pub fn book(&self) -> &Book {
        &self.book
    }

    pub fn last_step(&self) -> StepId {
        StepId(self.last_step)
    }

    /// Asks the subscriber to stop once its book is as of step `as_of` (the snapshotter's pause
    /// point, 10 §7.6). Packets keep buffering; [`take_snapshot`](Self::take_snapshot) then
    /// serializes and resumes.
    pub fn snapshot_at(&mut self, as_of: StepId) {
        self.pause_at = Some(as_of.0);
    }

    /// The snapshot, once the pause point is reached; then the subscriber catches up from what
    /// it buffered.
    pub fn take_snapshot(&mut self) -> Result<Option<Snapshot>, SubError> {
        if !self.paused {
            return Ok(None);
        }
        let as_of = self.last_step;
        let mut resume = Vec::with_capacity(N_CHAN);
        for c in 0..MD_MBO_LANE_CHANNELS {
            // The first record ordered after step `as_of + 1` is always an `MD_SYNC`. With none
            // buffered, resume past every record of the last packet taken, so a joiner still
            // reads that packet's watermark (spec gap 7).
            let (seq, record) = self.syncs[c].iter().find(|s| s.0 > as_of).map_or(
                if self.next_seq[c] > 1 {
                    (self.next_seq[c] - 1, self.last_count[c])
                } else {
                    (1, 0)
                },
                |s| (s.1, s.2),
            );
            resume.push(Resume {
                channel: c as u8,
                record,
                seq,
            });
        }
        let (seq, record) = self
            .steps
            .front()
            .map_or((self.next_seq[STEP], self.skip[STEP]), |s| (s.2, s.3));
        resume.push(Resume {
            channel: MD_MBO_STEP_CHANNEL,
            record,
            seq,
        });
        let mut orders: Vec<(u32, Order)> =
            self.book.orders.iter().map(|(o, v)| (*o, *v)).collect();
        orders.sort_by_key(|(oid, o)| {
            let best_first = match o.side {
                Side::Buy => u32::MAX - o.tick.0,
                Side::Sell => o.tick.0,
            };
            (o.side, best_first, o.prio_ts, oid >> 24, *oid)
        });
        self.paused = false;
        self.pause_at = None;
        let snap = Snapshot {
            as_of: StepId(as_of),
            orders,
            resume,
        };
        self.pump()?;
        Ok(Some(snap))
    }

    /// Takes one UDP payload of any of the five channels. A packet older than the channel's
    /// next `seq` is a duplicate (the other of A and B, or a buffered packet before a resume
    /// point) and is dropped.
    pub fn on_packet(&mut self, bytes: &[u8]) -> Result<(), SubError> {
        let p = Packet::decode(bytes).map_err(SubError::Packet)?;
        let h = p.header;
        if h.channel.feed != self.feed {
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
        if h.seq < self.next_seq[c] {
            return Ok(());
        }
        if h.seq != self.next_seq[c] {
            return Err(SubError::Gap {
                channel: h.channel.index,
            });
        }
        self.next_seq[c] += 1;
        self.last_count[c] = h.count;
        let skip = usize::from(core::mem::take(&mut self.skip[c]));
        let records = p.records.into_iter().enumerate().skip(skip);
        if c == STEP {
            for (i, r) in records {
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
                self.steps.push_back((r, h.ts_base, h.seq, i as u16));
            }
        } else {
            for (i, r) in records {
                match r {
                    Record::Sync { step } => {
                        if step.0 < self.lane_pos[c] {
                            return Err(SubError::Backwards);
                        }
                        self.lane_pos[c] = step.0;
                        self.syncs[c].push_back((step.0, h.seq, i as u16));
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
    ///
    /// Complete means: every lane channel has the same watermark, and every step up to it
    /// is applied with all its `MD_EXEC`s. A step op that
    /// trails its execs in a later step-channel packet is not detectable here (spec gap 4).
    pub fn finish(&mut self) -> Result<(), SubError> {
        // Every lane's final packet carries W = the last step, so all must agree with it.
        let (mut lo, mut hi) = (u64::MAX, 0);
        for w in self.lane_w {
            let w = w.ok_or(SubError::Incomplete)?;
            (lo, hi) = (lo.min(w), hi.max(w));
        }
        if lo < hi || self.last_step < hi || self.exec_left > 0 || !self.steps.is_empty() {
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
        if self.paused {
            return Ok(());
        }
        while let Some(&(rec, ts_base, _, _)) = self.steps.front() {
            if let Record::Step { step, .. } = rec {
                if step.0 != self.last_step + 1 {
                    return Err(SubError::StepOrder);
                }
                let need = self.last_step;
                if !self.lane_w.iter().all(|w| w.is_some_and(|w| w >= need)) {
                    break;
                }
                self.release(step.0)?;
                if self.pause_at == Some(self.last_step) {
                    self.paused = true;
                    return Ok(());
                }
                self.last_step = step.0;
                self.exec_left = match rec {
                    Record::Step { n_exec, .. } => n_exec,
                    _ => 0,
                };
                for q in &mut self.syncs {
                    while q.front().is_some_and(|s| s.0 < self.last_step) {
                        q.pop_front();
                    }
                }
            } else {
                self.book.apply(&rec, ts_base)?;
                if let Record::Exec { .. } = rec {
                    self.exec_left = self.exec_left.saturating_sub(1);
                }
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
