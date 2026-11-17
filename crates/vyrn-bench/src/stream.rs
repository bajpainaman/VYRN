//! The generator's output format, `VYRN-GEN` v1 (`bench/workloads/FORMAT.md`).
//!
//! ```text
//! header (68 bytes, little-endian)        record (12 bytes + packet)
//!   0  magic "VYRNGEN\0"                    0  len      u16   packet bytes that follow
//!   8  version u16 = 1                      2  send_ns  u64   ns after the start of the run
//!  10  header_len u16 = 68                 10 lane     u8
//!  12  mode u8 (0 base, 1 chain)           11 class    u8    0 MM, 1 TK, 2 RT
//!  13  reserved u8 = 0
//!  14  book u16   16 epoch16 u16
//!  18  reserved u16 = 0
//!  20  run_seed u64   28 rate_msgs_per_s u64
//!  36  config digest, BLAKE3 of the config file, 32 bytes
//! ```
//!
//! A reader skips to `header_len` before the first record, so later versions can append header
//! fields, and rejects a `version` it does not know. A packet is sent twice on the two paths
//! (04 §2.4); that is the sender's job, not part of the stream.

use std::io::{self, Write};

use thiserror::Error;

use crate::config::{Config, ConfigError, Mode};
use crate::generator::{GenOptions, Generator, Packet, Stats};

pub const MAGIC: [u8; 8] = *b"VYRNGEN\0";
pub const STREAM_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 68;
pub const RECORD_HEADER_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum GenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("write failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamError {
    #[error("not a VYRN-GEN stream")]
    BadMagic,
    #[error("unsupported stream version {0}")]
    Version(u16),
    #[error("truncated stream")]
    Truncated,
    #[error("malformed header")]
    BadHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    pub mode: Mode,
    pub book: u16,
    pub epoch16: u16,
    pub run_seed: u64,
    pub rate_msgs_per_s: u64,
    pub config_digest: [u8; 32],
}

impl StreamHeader {
    pub fn new(cfg: &Config, opts: &GenOptions) -> Self {
        Self {
            mode: cfg.mode,
            book: cfg.book,
            epoch16: cfg.epoch16,
            run_seed: opts.seed,
            rate_msgs_per_s: opts.rate_override.unwrap_or(cfg.rate_msgs_per_s),
            config_digest: cfg.digest,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&STREAM_VERSION.to_le_bytes());
        b[10..12].copy_from_slice(&u16::try_from(HEADER_LEN).unwrap_or(0).to_le_bytes());
        b[12] = u8::from(self.mode == Mode::Chain);
        b[14..16].copy_from_slice(&self.book.to_le_bytes());
        b[16..18].copy_from_slice(&self.epoch16.to_le_bytes());
        b[20..28].copy_from_slice(&self.run_seed.to_le_bytes());
        b[28..36].copy_from_slice(&self.rate_msgs_per_s.to_le_bytes());
        b[36..68].copy_from_slice(&self.config_digest);
        b
    }

    /// The header and the offset of the first record.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), StreamError> {
        if bytes.get(0..8) != Some(&MAGIC[..]) {
            return Err(StreamError::BadMagic);
        }
        let version = u16::from_le_bytes(rd(bytes, 8).ok_or(StreamError::Truncated)?);
        if version != STREAM_VERSION {
            return Err(StreamError::Version(version));
        }
        let len = usize::from(u16::from_le_bytes(
            rd(bytes, 10).ok_or(StreamError::Truncated)?,
        ));
        if len < HEADER_LEN || bytes.len() < len {
            return Err(StreamError::Truncated);
        }
        let mode = match bytes.get(12) {
            Some(0) => Mode::Base,
            Some(1) => Mode::Chain,
            _ => return Err(StreamError::BadHeader),
        };
        let t = StreamError::Truncated;
        Ok((
            Self {
                mode,
                book: u16::from_le_bytes(rd(bytes, 14).ok_or(t)?),
                epoch16: u16::from_le_bytes(rd(bytes, 16).ok_or(StreamError::Truncated)?),
                run_seed: u64::from_le_bytes(rd(bytes, 20).ok_or(StreamError::Truncated)?),
                rate_msgs_per_s: u64::from_le_bytes(rd(bytes, 28).ok_or(StreamError::Truncated)?),
                config_digest: rd(bytes, 36).ok_or(StreamError::Truncated)?,
            },
            len,
        ))
    }
}

fn rd<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// One record of a parsed stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub send_ns: u64,
    pub lane: u8,
    pub class: u8,
    pub bytes: &'a [u8],
}

pub fn record_header(p: &Packet) -> [u8; RECORD_HEADER_LEN] {
    let mut h = [0u8; RECORD_HEADER_LEN];
    h[0..2].copy_from_slice(&u16::try_from(p.bytes().len()).unwrap_or(0).to_le_bytes());
    h[2..10].copy_from_slice(&p.send_ns.to_le_bytes());
    h[10] = p.lane.0;
    h[11] = p.class.code();
    h
}

/// Parses a whole stream: the header and every record.
pub fn parse_stream(bytes: &[u8]) -> Result<(StreamHeader, Vec<Record<'_>>), StreamError> {
    let (header, mut at) = StreamHeader::parse(bytes)?;
    let mut out = Vec::new();
    while at < bytes.len() {
        let len = usize::from(u16::from_le_bytes(
            rd(bytes, at).ok_or(StreamError::Truncated)?,
        ));
        let send_ns = u64::from_le_bytes(rd(bytes, at + 2).ok_or(StreamError::Truncated)?);
        let [lane, class] = rd::<2>(bytes, at + 10).ok_or(StreamError::Truncated)?;
        let start = at + RECORD_HEADER_LEN;
        let end = start.checked_add(len).ok_or(StreamError::Truncated)?;
        let body = bytes.get(start..end).ok_or(StreamError::Truncated)?;
        out.push(Record {
            send_ns,
            lane,
            class,
            bytes: body,
        });
        at = end;
    }
    Ok((header, out))
}

/// Writes the stream of `cfg` and `opts`, at most `max_packets` packets. Returns the run's stats.
pub fn write_stream<W: Write>(
    cfg: &Config,
    opts: &GenOptions,
    max_packets: Option<u64>,
    out: &mut W,
) -> Result<Stats, GenError> {
    let mut generator = Generator::new(cfg, opts)?;
    out.write_all(&StreamHeader::new(cfg, opts).encode())?;
    let limit = max_packets.unwrap_or(u64::MAX);
    let mut n = 0u64;
    while n < limit {
        let Some(p) = generator.next() else { break };
        out.write_all(&record_header(&p))?;
        out.write_all(p.bytes())?;
        n += 1;
    }
    Ok(generator.stats().clone())
}
