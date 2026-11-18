//! Packet framing (10 §7.3): a 32-byte header and up to 88 records.

use vyrn_types::{BookId, Nanos};

use crate::MD_MAX_RECS_PER_PKT;
use crate::record::{REC_BYTES, Record, RecordError};

/// Header bytes (10 §7.3).
pub const HEADER_BYTES: usize = 32;

/// Lane-channel `step_base` before any step: not even interval 0 is complete (spec gap 1).
pub const NO_WATERMARK: u64 = u64::MAX;

code_enum!(
    /// `MD_FEED_*`, the channel's high byte (10, constants table).
    Feed {
        Mbo = 1,
        MboC = 2,
        Mbp10 = 3,
        Tob = 4,
        Trades = 5,
        Stats = 6,
        Snap = 7,
        MboW = 8,
    }
);

/// A feed and a channel index within it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Channel {
    pub feed: Feed,
    pub index: u8,
}

impl Channel {
    /// The header's `channel` field: feed in the high byte, index in the low byte.
    pub const fn code(self) -> u16 {
        u16::from_le_bytes([self.index, self.feed.code()])
    }

    pub const fn from_code(c: u16) -> Option<Self> {
        let [index, feed] = c.to_le_bytes();
        match Feed::from_code(feed) {
            Some(feed) => Some(Channel { feed, index }),
            None => None,
        }
    }
}

/// The 32-byte packet header (10 §7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub channel: Channel,
    /// Records in the packet; 0 is a heartbeat.
    pub count: u16,
    pub book: BookId,
    pub epoch16: u16,
    /// Per channel, from 1 each epoch, +1 per packet, gapless.
    pub seq: u64,
    pub ts_base: Nanos,
    /// MBO lane channels: the watermark (or [`NO_WATERMARK`]); other channels: the open step.
    pub step_base: u64,
}

impl Header {
    pub fn write(&self, out: &mut [u8; HEADER_BYTES]) {
        out[0..2].copy_from_slice(&self.channel.code().to_le_bytes());
        out[2..4].copy_from_slice(&self.count.to_le_bytes());
        out[4..6].copy_from_slice(&self.book.0.to_le_bytes());
        out[6..8].copy_from_slice(&self.epoch16.to_le_bytes());
        out[8..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16..24].copy_from_slice(&self.ts_base.0.to_le_bytes());
        out[24..32].copy_from_slice(&self.step_base.to_le_bytes());
    }

    pub fn read(b: &[u8; HEADER_BYTES]) -> Result<Self, PacketError> {
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let u64_at = |at: usize| {
            let mut a = [0; 8];
            a.copy_from_slice(&b[at..at + 8]);
            u64::from_le_bytes(a)
        };
        Ok(Header {
            channel: Channel::from_code(u16_at(0)).ok_or(PacketError::UnknownFeed)?,
            count: u16_at(2),
            book: BookId(u16_at(4)),
            epoch16: u16_at(6),
            seq: u64_at(8),
            ts_base: Nanos(u64_at(16)),
            step_base: u64_at(24),
        })
    }
}

/// Why bytes are not a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Fewer than 32 bytes.
    Short,
    /// The channel's high byte is not an `MD_FEED_*` code.
    UnknownFeed,
    /// `count > MD_MAX_RECS_PER_PKT`.
    TooManyRecords,
    /// The length is not `32 + 16 × count`.
    Length,
    /// Record `n` (from 0) is not a record.
    Record(usize, RecordError),
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub records: Vec<Record>,
}

impl Packet {
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let (h, body) = bytes
            .split_first_chunk::<HEADER_BYTES>()
            .ok_or(PacketError::Short)?;
        let header = Header::read(h)?;
        let count = usize::from(header.count);
        if count > MD_MAX_RECS_PER_PKT {
            return Err(PacketError::TooManyRecords);
        }
        if body.len() != count * REC_BYTES {
            return Err(PacketError::Length);
        }
        let records = body
            .as_chunks::<REC_BYTES>()
            .0
            .iter()
            .enumerate()
            .map(|(i, r)| Record::decode(r).map_err(|e| PacketError::Record(i, e)))
            .collect::<Result<_, _>>()?;
        Ok(Packet { header, records })
    }

    /// The wire bytes. `count` is taken from `records`.
    pub fn encode(&self) -> Vec<u8> {
        let mut h = self.header;
        h.count = u16::try_from(self.records.len()).unwrap_or(u16::MAX);
        let mut hb = [0; HEADER_BYTES];
        h.write(&mut hb);
        let mut out = hb.to_vec();
        for r in &self.records {
            out.extend_from_slice(&r.encode());
        }
        out
    }
}
