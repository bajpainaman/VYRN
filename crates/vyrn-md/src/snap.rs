//! Snapshots (10 §7.6): the snapshotter's book as `MD_SNAP_*` records on the `SNAP` feed, and
//! the reader that turns them back into a [`Snapshot`].
//!
//! # Layout (choices labeled \[Guessing\] where 10 §7.6 is silent)
//!
//! - Channel: feed `SNAP`, index = the `MD_FEED_*` code of the snapshotted feed (1 for `MBO`).
//! - Records: `MD_SNAP_BEGIN(feed, n, as_of)`, the orders as `MD_ADD` (ts_delta 0, flags only the
//!   side), one `MD_SNAP_RESUME` per channel in channel order, `MD_SNAP_END`.
//! - `n` counts the records between `MD_SNAP_BEGIN` and `MD_SNAP_END`.
//! - The body hashed for `MD_SNAP_END` is the 16-byte records from `MD_SNAP_BEGIN` through the
//!   last `MD_SNAP_RESUME`, inclusive.
//! - Packets: header `step_base` = `as_of`, `ts_base` = the publish time; each snapshot closes
//!   its last packet, so the next starts a new one.
//! - A reader gives the `i`-th order of the snapshot `prio_ts = i`: the level-FIFO order is the
//!   priority, and this rank keeps it through a rebuilt book and the next snapshot. Every
//!   snapshot order then ranks ahead of any later add (whose `prio_ts` is a real time); 10 §7.6
//!   puts no timestamps on the wire, so a later step residual with an older priority cannot be
//!   placed among them.

use vyrn_types::{BookId, Epoch, Nanos};

use crate::chan::Packer;
use crate::mbo::PacketSink;
use crate::packet::{Channel, Feed, Packet, PacketError};
use crate::record::Record;
use crate::subscriber::{Order, Resume, Snapshot};

fn hash8(body: &[u8]) -> [u8; 8] {
    let h = blake3::hash(body);
    let mut out = [0; 8];
    out.copy_from_slice(&h.as_bytes()[..8]);
    out
}

/// The records of one snapshot of `feed`, in order.
pub fn snapshot_records(feed: Feed, snap: &Snapshot) -> Vec<Record> {
    let n = snap.orders.len() + snap.resume.len();
    let mut out = Vec::with_capacity(n + 2);
    out.push(Record::SnapBegin {
        feed,
        n_records: u32::try_from(n).unwrap_or(u32::MAX),
        as_of: snap.as_of,
    });
    for &(oid, o) in &snap.orders {
        out.push(Record::Add {
            side: o.side,
            via_bbo: false,
            auction: false,
            ts_delta: 0,
            oid,
            tick: o.tick,
            qty: o.qty,
        });
    }
    for r in &snap.resume {
        out.push(Record::SnapResume {
            channel: r.channel,
            record: r.record,
            seq: r.seq,
        });
    }
    let body: Vec<u8> = out.iter().flat_map(|r| r.encode()).collect();
    out.push(Record::SnapEnd {
        hash8: hash8(&body),
    });
    out
}

/// Publishes snapshots of one book's `feed` on its `SNAP` channel.
pub struct SnapEncoder {
    feed: Feed,
    packer: Packer,
}

impl SnapEncoder {
    pub fn new(feed: Feed, book: BookId, epoch: Epoch) -> Self {
        let channel = Channel {
            feed: Feed::Snap,
            index: feed.code(),
        };
        SnapEncoder {
            feed,
            packer: Packer::new(channel, book, epoch.low16()),
        }
    }

    /// Sends one snapshot. `now` is the order-stream time it goes out at.
    pub fn publish(&mut self, snap: &Snapshot, now: Nanos, sink: &mut impl PacketSink) {
        for r in snapshot_records(self.feed, snap) {
            self.packer.put(&r, now.0, snap.as_of.0, sink);
        }
        self.packer.flush(sink);
    }
}

/// Why the snapshot reader refused a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapError {
    Packet(PacketError),
    /// Not this reader's `SNAP` channel, book or epoch.
    WrongChannel,
    /// A record a snapshot does not hold, or one out of place.
    Unexpected,
    /// `MD_SNAP_END` came after a record count other than `MD_SNAP_BEGIN`'s `n`.
    Count,
    /// `MD_SNAP_END`'s hash is not the body's.
    Hash,
}

struct Partial {
    n: u32,
    snap: Snapshot,
    body: Vec<u8>,
}

/// Reads one book's `SNAP` channel. A gap drops the snapshot in progress; the next
/// `MD_SNAP_BEGIN` starts over.
pub struct SnapReader {
    channel: Channel,
    book: BookId,
    epoch16: u16,
    next_seq: Option<u64>,
    cur: Option<Partial>,
}

impl SnapReader {
    pub fn new(feed: Feed, book: BookId, epoch: Epoch) -> Self {
        SnapReader {
            channel: Channel {
                feed: Feed::Snap,
                index: feed.code(),
            },
            book,
            epoch16: epoch.low16(),
            next_seq: None,
            cur: None,
        }
    }

    /// Takes one `SNAP` packet; returns each snapshot it completes (at most one per packet,
    /// since a snapshot ends its packet).
    pub fn on_packet(&mut self, bytes: &[u8]) -> Result<Option<Snapshot>, SnapError> {
        let p = Packet::decode(bytes).map_err(SnapError::Packet)?;
        let h = p.header;
        if h.channel != self.channel || h.book != self.book || h.epoch16 != self.epoch16 {
            return Err(SnapError::WrongChannel);
        }
        match self.next_seq {
            // A duplicate (the other of A and B): already taken.
            Some(next) if h.seq < next => return Ok(None),
            // A gap: the snapshot in progress lost a packet.
            Some(next) if h.seq > next => self.cur = None,
            _ => {}
        }
        self.next_seq = Some(h.seq + 1);
        let mut done = None;
        for r in p.records {
            match (r, &mut self.cur) {
                (
                    Record::SnapBegin {
                        feed,
                        n_records,
                        as_of,
                    },
                    _,
                ) => {
                    if feed.code() != self.channel.index {
                        self.cur = None;
                        return Err(SnapError::Unexpected);
                    }
                    self.cur = Some(Partial {
                        n: n_records,
                        snap: Snapshot {
                            as_of,
                            orders: vec![],
                            resume: vec![],
                        },
                        body: r.encode().to_vec(),
                    });
                }
                (_, None) => {}
                (
                    Record::Add {
                        side,
                        ts_delta: 0,
                        oid,
                        tick,
                        qty,
                        ..
                    },
                    Some(c),
                ) if c.snap.resume.is_empty() => {
                    c.body.extend_from_slice(&r.encode());
                    let prio_ts = Nanos(c.snap.orders.len() as u64);
                    c.snap.orders.push((
                        oid,
                        Order {
                            side,
                            tick,
                            qty,
                            prio_ts,
                        },
                    ));
                }
                (
                    Record::SnapResume {
                        channel,
                        record,
                        seq,
                    },
                    Some(c),
                ) => {
                    c.body.extend_from_slice(&r.encode());
                    c.snap.resume.push(Resume {
                        channel,
                        record,
                        seq,
                    });
                }
                (Record::SnapEnd { hash8: got }, Some(_)) => {
                    let c = self.cur.take().ok_or(SnapError::Unexpected)?;
                    if (c.snap.orders.len() + c.snap.resume.len()) as u64 != u64::from(c.n) {
                        return Err(SnapError::Count);
                    }
                    if hash8(&c.body) != got {
                        return Err(SnapError::Hash);
                    }
                    done = Some(c.snap);
                }
                _ => {
                    self.cur = None;
                    return Err(SnapError::Unexpected);
                }
            }
        }
        Ok(done)
    }
}

/// `MD_SNAP_EVERY_BLOCKS` (10 §7.6): a snapshot after the last step of every block whose height
/// is a multiple of it.
pub const MD_SNAP_EVERY_BLOCKS: u64 = 1_000;

/// Whether the block at `height` is a snapshot point.
pub const fn is_snapshot_height(height: u64) -> bool {
    height.is_multiple_of(MD_SNAP_EVERY_BLOCKS)
}
