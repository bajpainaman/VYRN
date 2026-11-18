//! The retransmit service (10 §7.6): packets by channel and seq range over TCP, kept for
//! `MD_RETX_SECS`.
//!
//! # Wire (\[Guessing\], 10 §7.6 says only "TCP, by channel and seq range")
//!
//! Request, 24 bytes little-endian: `channel u16` (as in the packet header), `book u16`,
//! `epoch16 u16`, `0 u16`, `from_seq u64`, `to_seq u64` (inclusive). Response: each held packet
//! of the range in seq order as `len u16 | packet`, then `len = 0`. Packets no longer held, or
//! not sent yet, are left out; the reader sees which seqs came from their headers. The server
//! answers every request on a connection until the client closes it.
//!
//! Age is order-stream time, so A and B hold the same packets. A packet is stamped with the
//! highest `ts_base` stored so far (any channel), not its own: a packet's `ts_base` can be an old
//! priority time (a residual or an `MBO-W` synthetic add), but it was published no earlier than
//! every packet before it. A packet is held while the newest stamp is at most `retain_ns` past
//! its own.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};

use vyrn_types::BookId;

use crate::mbo::PacketSink;
use crate::packet::{Channel, HEADER_BYTES, Header};

/// Seconds of packets the service holds (10, constants).
pub const MD_RETX_SECS: u64 = 30;
/// Request bytes.
pub const RETX_REQ_BYTES: usize = 24;

/// One retransmit request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetxRequest {
    pub channel: Channel,
    pub book: BookId,
    pub epoch16: u16,
    pub from_seq: u64,
    pub to_seq: u64,
}

impl RetxRequest {
    pub fn encode(&self) -> [u8; RETX_REQ_BYTES] {
        let mut b = [0; RETX_REQ_BYTES];
        b[0..2].copy_from_slice(&self.channel.code().to_le_bytes());
        b[2..4].copy_from_slice(&self.book.0.to_le_bytes());
        b[4..6].copy_from_slice(&self.epoch16.to_le_bytes());
        b[8..16].copy_from_slice(&self.from_seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.to_seq.to_le_bytes());
        b
    }

    /// `None` for an unknown feed or non-zero padding.
    pub fn decode(b: &[u8; RETX_REQ_BYTES]) -> Option<Self> {
        let u16_at = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        let u64_at = |at: usize| {
            let mut a = [0; 8];
            a.copy_from_slice(&b[at..at + 8]);
            u64::from_le_bytes(a)
        };
        if u16_at(6) != 0 {
            return None;
        }
        Some(RetxRequest {
            channel: Channel::from_code(u16_at(0))?,
            book: BookId(u16_at(2)),
            epoch16: u16_at(4),
            from_seq: u64_at(8),
            to_seq: u64_at(16),
        })
    }
}

type Key = (u16, u16, u16);

/// The packets of the last `retain_ns` per channel. As a [`PacketSink`] it stores what the
/// encoders emit.
pub struct RetxStore {
    retain_ns: u64,
    /// The highest `ts_base` stored.
    now: u64,
    /// By (channel code, book, epoch16): (seq, stamp, bytes), seq ascending.
    chans: BTreeMap<Key, VecDeque<(u64, u64, Vec<u8>)>>,
}

impl RetxStore {
    pub fn new(retain_ns: u64) -> Self {
        RetxStore {
            retain_ns,
            now: 0,
            chans: BTreeMap::new(),
        }
    }

    /// Stores one packet. Packets that are not a valid header, or whose seq is not above the
    /// channel's last, are ignored.
    pub fn store(&mut self, bytes: &[u8]) {
        let Some(h) = bytes.first_chunk::<HEADER_BYTES>() else {
            return;
        };
        let Ok(h) = Header::read(h) else { return };
        let q = self
            .chans
            .entry((h.channel.code(), h.book.0, h.epoch16))
            .or_default();
        if q.back().is_some_and(|b| b.0 >= h.seq) {
            return;
        }
        self.now = self.now.max(h.ts_base.0);
        let now = self.now;
        q.push_back((h.seq, now, bytes.to_vec()));
        while q
            .front()
            .is_some_and(|f| now.saturating_sub(f.1) > self.retain_ns)
        {
            q.pop_front();
        }
    }

    /// The held packets of the request's range, in seq order.
    pub fn range(&self, r: &RetxRequest) -> impl Iterator<Item = &[u8]> {
        self.chans
            .get(&(r.channel.code(), r.book.0, r.epoch16))
            .into_iter()
            .flatten()
            .filter(move |p| {
                p.0 >= r.from_seq && p.0 <= r.to_seq && self.now - p.1 <= self.retain_ns
            })
            .map(|p| p.2.as_slice())
    }

    /// Serves requests from `conn` until it closes.
    pub fn serve(&self, conn: &mut (impl Read + Write)) -> io::Result<()> {
        let mut req = [0; RETX_REQ_BYTES];
        loop {
            match conn.read_exact(&mut req) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e),
            }
            if let Some(r) = RetxRequest::decode(&req) {
                for p in self.range(&r) {
                    let len = u16::try_from(p.len()).unwrap_or(0);
                    conn.write_all(&len.to_le_bytes())?;
                    conn.write_all(p)?;
                }
            }
            conn.write_all(&0u16.to_le_bytes())?;
            conn.flush()?;
        }
    }
}

impl PacketSink for RetxStore {
    fn emit(&mut self, _: Channel, bytes: &[u8]) {
        self.store(bytes);
    }
}

/// The client side: sends `req` and reads the packets of the response.
pub fn retx_fetch(conn: &mut (impl Read + Write), req: &RetxRequest) -> io::Result<Vec<Vec<u8>>> {
    conn.write_all(&req.encode())?;
    conn.flush()?;
    let mut out = vec![];
    loop {
        let mut l = [0; 2];
        conn.read_exact(&mut l)?;
        let len = usize::from(u16::from_le_bytes(l));
        if len == 0 {
            return Ok(out);
        }
        let mut p = vec![0; len];
        conn.read_exact(&mut p)?;
        out.push(p);
    }
}
