//! `MBO-C` (10 §7.5): `MBO` with each record varint delta-encoded.
//!
//! An `MBO-C` packet is a transcoding of one `MBO` packet: the same channel index, header and
//! `seq`, so the same packet boundaries and the same merge rule; only the feed byte and the
//! record encoding differ. Each packet decodes on its own.
//!
//! # Record encoding (reading of 10 §7.5, labeled \[Guessing\] where the spec is silent)
//!
//! A record is its type byte, its flag byte (byte 1 of the 16-byte form, which carries the side,
//! cause, kind or status), then LEB128 varints. `zz(x)` is the zigzag of a signed difference.
//! `prev_oid` and `prev_tick` start at 0 in every packet and become the oid and tick of each
//! record that has both.
//!
//! | Type | Varints after the flag byte |
//! |---|---|
//! | `MD_ADD` | `zz(oid − prev_oid)`, `zz(tick − prev_tick)`, `qty`, `ts_delta` |
//! | `MD_DELETE`, `MD_REDUCE` | `zz(oid − prev_oid)`, `zz(tick − prev_tick)`, `qty` |
//! | `MD_EXEC` | `zz(maker − prev_oid)`, `zz(tick − prev_tick)`, `qty`, `ordinal` |
//! | `MD_SYNC` | `step` |
//! | `MD_STEP` | `n_exec`, `step`, `taker` |
//! | `MD_BUST` | `ordinal`, `step` |
//! | `MD_STATUS` | `epoch`, `step` |
//! | `MD_ATTEST` | `height low`, `last step` |
//!
//! 10 §7.5 says `tick − touch`. A packet cannot carry the touch (lane channels are read in merge
//! order, so a reader does not know it when it decodes), so `prev_tick` stands in for it.
//! \[Guessing\] The flag byte is not in 10 §7.5's list but no record decodes without it.

use crate::MD_MAX_RECS_PER_PKT;
use crate::mbo::PacketSink;
use crate::packet::{Channel, Feed, HEADER_BYTES, Header, Packet, PacketError};
use crate::record::{REC_BYTES, Record};

/// Why bytes are not an `MBO-C` packet, or an `MBO` packet has no `MBO-C` form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MboCError {
    /// The header, or (when encoding) the `MBO` packet, is not valid.
    Packet(PacketError),
    /// Not the feed this direction expects (`MBO` to encode, `MBO-C` to decode).
    WrongFeed,
    /// A record type that `MBO` channels do not carry.
    NotMbo,
    /// The body ends inside a record.
    Truncated,
    /// A varint longer than 10 bytes, or a value that does not fit its field.
    Overflow,
    /// Bytes after the last of `count` records.
    Trailing,
    /// Record `n` (from 0) decodes to bytes that are not a record.
    Record(usize),
}

fn put_var(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zz(d: i64) -> u64 {
    ((d << 1) ^ (d >> 63)) as u64
}

fn unzz(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Appends the `MBO-C` form of `rec`, whose 16-byte form is `b`.
fn encode_record(
    b: &[u8; REC_BYTES],
    rec: &Record,
    prev: &mut (u32, u32),
    out: &mut Vec<u8>,
) -> Result<(), MboCError> {
    out.extend_from_slice(&b[..2]);
    let mut keyed = |out: &mut Vec<u8>, oid: u32, tick: u32| {
        put_var(out, zz(i64::from(oid) - i64::from(prev.0)));
        put_var(out, zz(i64::from(tick) - i64::from(prev.1)));
        *prev = (oid, tick);
    };
    match *rec {
        Record::Add {
            ts_delta,
            oid,
            tick,
            qty,
            ..
        } => {
            keyed(out, oid, tick.0);
            put_var(out, u64::from(qty.0));
            put_var(out, u64::from(ts_delta));
        }
        Record::Delete { oid, tick, qty, .. } | Record::Reduce { oid, tick, qty } => {
            keyed(out, oid, tick.0);
            put_var(out, u64::from(qty.0));
        }
        Record::Exec {
            ordinal,
            maker,
            tick,
            qty,
            ..
        } => {
            keyed(out, maker, tick.0);
            put_var(out, u64::from(qty.0));
            put_var(out, u64::from(ordinal));
        }
        Record::Sync { step } => put_var(out, step.0),
        Record::Step {
            n_exec,
            step,
            taker,
            ..
        } => {
            put_var(out, u64::from(n_exec));
            put_var(out, step.0);
            put_var(out, u64::from(taker));
        }
        Record::Bust { ordinal, step } => {
            put_var(out, u64::from(ordinal));
            put_var(out, step.0);
        }
        Record::Status { epoch, step, .. } => {
            put_var(out, u64::from(epoch.0));
            put_var(out, step.0);
        }
        Record::Attest {
            height_low,
            last_step,
            ..
        } => {
            put_var(out, u64::from(height_low));
            put_var(out, last_step.0);
        }
        _ => return Err(MboCError::NotMbo),
    }
    Ok(())
}

/// Writes the `MBO-C` packet for one `MBO` packet to `out`, replacing its contents.
pub fn mbo_c_encode(mbo: &[u8], out: &mut Vec<u8>) -> Result<(), MboCError> {
    let (h, body) = mbo
        .split_first_chunk::<HEADER_BYTES>()
        .ok_or(MboCError::Packet(PacketError::Short))?;
    let mut header = Header::read(h).map_err(MboCError::Packet)?;
    if header.channel.feed != Feed::Mbo {
        return Err(MboCError::WrongFeed);
    }
    let count = usize::from(header.count);
    if count > MD_MAX_RECS_PER_PKT {
        return Err(MboCError::Packet(PacketError::TooManyRecords));
    }
    if body.len() != count * REC_BYTES {
        return Err(MboCError::Packet(PacketError::Length));
    }
    out.clear();
    header.channel.feed = Feed::MboC;
    let mut hb = [0; HEADER_BYTES];
    header.write(&mut hb);
    out.extend_from_slice(&hb);
    let mut prev = (0, 0);
    for (i, b) in body.as_chunks::<REC_BYTES>().0.iter().enumerate() {
        let r = Record::decode(b).map_err(|e| MboCError::Packet(PacketError::Record(i, e)))?;
        encode_record(b, &r, &mut prev, out)?;
    }
    Ok(())
}

struct Reader<'a> {
    b: &'a [u8],
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, MboCError> {
        let (&x, rest) = self.b.split_first().ok_or(MboCError::Truncated)?;
        self.b = rest;
        Ok(x)
    }

    fn var(&mut self) -> Result<u64, MboCError> {
        let mut v = 0u64;
        for i in 0..10 {
            let x = self.byte()?;
            let part = u64::from(x & 0x7F);
            if i == 9 && part > 1 {
                return Err(MboCError::Overflow);
            }
            v |= part << (7 * i);
            if x & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(MboCError::Overflow)
    }

    fn var_as<T: TryFrom<u64>>(&mut self) -> Result<T, MboCError> {
        T::try_from(self.var()?).map_err(|_| MboCError::Overflow)
    }

    /// `zz(x − base)` back to `x`.
    fn keyed(&mut self, base: u32) -> Result<u32, MboCError> {
        let d = unzz(self.var()?);
        u32::try_from(i64::from(base) + d).map_err(|_| MboCError::Overflow)
    }
}

/// Decodes one `MBO-C` packet into the `MBO` records it carries. The header's feed stays
/// `MBO-C`.
pub fn mbo_c_decode(bytes: &[u8]) -> Result<Packet, MboCError> {
    let (h, body) = bytes
        .split_first_chunk::<HEADER_BYTES>()
        .ok_or(MboCError::Packet(PacketError::Short))?;
    let header = Header::read(h).map_err(MboCError::Packet)?;
    if header.channel.feed != Feed::MboC {
        return Err(MboCError::WrongFeed);
    }
    let count = usize::from(header.count);
    if count > MD_MAX_RECS_PER_PKT {
        return Err(MboCError::Packet(PacketError::TooManyRecords));
    }
    let mut r = Reader { b: body };
    let mut prev = (0u32, 0u32);
    let mut records = Vec::with_capacity(count);
    for n in 0..count {
        let mut b = [0u8; REC_BYTES];
        b[0] = r.byte()?;
        b[1] = r.byte()?;
        let put = |b: &mut [u8; REC_BYTES], at: usize, v: &[u8]| {
            b[at..at + v.len()].copy_from_slice(v);
        };
        match b[0] {
            0x01 | 0x02 | 0x03 | 0x11 => {
                let oid = r.keyed(prev.0)?;
                let tick = r.keyed(prev.1)?;
                prev = (oid, tick);
                let qty: u32 = r.var_as()?;
                put(&mut b, 4, &oid.to_le_bytes());
                put(&mut b, 8, &tick.to_le_bytes());
                put(&mut b, 12, &qty.to_le_bytes());
                if b[0] == 0x01 || b[0] == 0x11 {
                    let v: u16 = r.var_as()?;
                    put(&mut b, 2, &v.to_le_bytes());
                }
            }
            0x0E => put(&mut b, 8, &r.var()?.to_le_bytes()),
            0x10 => {
                let n_exec: u16 = r.var_as()?;
                let step = r.var()?;
                let taker: u32 = r.var_as()?;
                put(&mut b, 2, &n_exec.to_le_bytes());
                put(&mut b, 4, &step.to_le_bytes());
                put(&mut b, 12, &taker.to_le_bytes());
            }
            0x12 => {
                let ordinal: u16 = r.var_as()?;
                put(&mut b, 2, &ordinal.to_le_bytes());
                put(&mut b, 8, &r.var()?.to_le_bytes());
            }
            0x20 | 0x21 => {
                let low: u32 = r.var_as()?;
                put(&mut b, 4, &low.to_le_bytes());
                put(&mut b, 8, &r.var()?.to_le_bytes());
            }
            _ => return Err(MboCError::NotMbo),
        }
        records.push(Record::decode(&b).map_err(|_| MboCError::Record(n))?);
    }
    if !r.b.is_empty() {
        return Err(MboCError::Trailing);
    }
    Ok(Packet { header, records })
}

/// A sink that sends each `MBO` packet on to `inner` and its `MBO-C` form after it, so one
/// encoder run feeds both (10 §7.2). Non-`MBO` packets pass through alone.
pub struct WithMboC<S> {
    pub inner: S,
    buf: Vec<u8>,
}

impl<S> WithMboC<S> {
    pub fn new(inner: S) -> Self {
        WithMboC {
            inner,
            buf: Vec::with_capacity(HEADER_BYTES + MD_MAX_RECS_PER_PKT * REC_BYTES),
        }
    }
}

impl<S: PacketSink> PacketSink for WithMboC<S> {
    fn emit(&mut self, channel: Channel, bytes: &[u8]) {
        self.inner.emit(channel, bytes);
        if channel.feed == Feed::Mbo && mbo_c_encode(bytes, &mut self.buf).is_ok() {
            let c = Channel {
                feed: Feed::MboC,
                index: channel.index,
            };
            self.inner.emit(c, &self.buf);
        }
    }
}
