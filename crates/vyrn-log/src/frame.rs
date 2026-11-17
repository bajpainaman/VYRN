//! Order-stream frames (07 §3.2, §3.3) and the per-substream encoder and decoder.
//!
//! # Frame header (24 bytes, little-endian)
//!
//! ```text
//! off size field
//!   0   2  magic       0x4250 (bytes 50 42)
//!   2   1  version     1
//!   3   1  kind        1 ORDER, 2 HASH, 3 HEADER, 4 HEARTBEAT
//!   4   2  book        BookId
//!   6   2  epoch16     low 16 bits of the epoch
//!   8   8  frame_seq   ≥ 1, +1 per frame of any kind on the substream
//!  16   1  flags       bit0 path B, bit1 retransmit, bit2 peer-repaired; other bits 0
//!  17   1  tenure
//!  18   2  body_len    bytes after the header; exactly the rest of the datagram
//!  20   1  sender      sequencer index
//!  21   1  stream      0 A, 1 B
//!  22   2  reserved    0
//! ```
//!
//! Bodies: ORDER and HASH carry sections ([`crate::stream`]); frame 1 of a substream is an
//! ORDER frame whose first section is `TenureStart`. HEADER carries one 190-byte `BlockHeader`
//! ([`crate::block`]) and is sent on substream A only. HEARTBEAT carries `last_step` u64,
//! `last_height` u64 and `ptp_now` u64. Every header field except `flags` is identical on both
//! paths and in every retransmission (INV-REP-3), and `book`, `epoch16`, `tenure` and `sender`
//! stay fixed for the tenure that frame 1 opens. Any other header is `RepErr::Header`.

use vyrn_types::{BlockHeader, BookId, Epoch, Height, Nanos, StepId};

use crate::block::{HEADER_BYTES, decode_header, encode_header};
use crate::leb::Reader;
use crate::stream::{BodyKind, HalfBlock, Section, SubstreamState, TenureStart};
use crate::{Layout, RepErr};

pub const FRAME_MAGIC: u16 = 0x4250;
pub const FRAME_VERSION: u8 = 1;
pub const FRAME_HEADER_BYTES: usize = 24;
/// The ORDER body cap of the flush rule (07 §4.5). The encoder and decoder do not enforce it:
/// frame 1's `TenureStart` alone exceeds it on REF.
pub const REP_ORDER_FRAME_MAX: usize = 160;

/// `flags` bits.
pub struct FrameFlags;

impl FrameFlags {
    pub const PATH_B: u8 = 1 << 0;
    pub const RETRANSMIT: u8 = 1 << 1;
    pub const PEER_REPAIRED: u8 = 1 << 2;
    const ALL: u8 = 0x07;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Order = 1,
    Hash = 2,
    Header = 3,
    Heartbeat = 4,
}

impl FrameKind {
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Order,
            2 => Self::Hash,
            3 => Self::Header,
            4 => Self::Heartbeat,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub book: BookId,
    pub epoch16: u16,
    pub frame_seq: u64,
    pub flags: u8,
    pub tenure: u8,
    pub body_len: u16,
    pub sender: u8,
    pub stream: u8,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_BYTES] {
        let mut v = Vec::with_capacity(FRAME_HEADER_BYTES);
        v.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        v.extend_from_slice(&[FRAME_VERSION, self.kind as u8]);
        v.extend_from_slice(&self.book.0.to_le_bytes());
        v.extend_from_slice(&self.epoch16.to_le_bytes());
        v.extend_from_slice(&self.frame_seq.to_le_bytes());
        v.extend_from_slice(&[self.flags, self.tenure]);
        v.extend_from_slice(&self.body_len.to_le_bytes());
        v.extend_from_slice(&[self.sender, self.stream, 0, 0]);
        let mut b = [0u8; FRAME_HEADER_BYTES];
        b.iter_mut().zip(&v).for_each(|(d, s)| *d = *s);
        b
    }

    /// Parses and checks a datagram's header; returns it and the body.
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), RepErr> {
        let mut r = Reader::new(bytes);
        let magic = r.u16().map_err(|_| RepErr::Header)?;
        let version = r.u8().map_err(|_| RepErr::Header)?;
        let kind = r.u8().map_err(|_| RepErr::Header)?;
        let h = Self {
            kind: FrameKind::from_code(kind).ok_or(RepErr::Header)?,
            book: BookId(r.u16().map_err(|_| RepErr::Header)?),
            epoch16: r.u16().map_err(|_| RepErr::Header)?,
            frame_seq: r.u64().map_err(|_| RepErr::Header)?,
            flags: r.u8().map_err(|_| RepErr::Header)?,
            tenure: r.u8().map_err(|_| RepErr::Header)?,
            body_len: r.u16().map_err(|_| RepErr::Header)?,
            sender: r.u8().map_err(|_| RepErr::Header)?,
            stream: r.u8().map_err(|_| RepErr::Header)?,
        };
        let reserved = r.u16().map_err(|_| RepErr::Header)?;
        let body = r.rest();
        if magic != FRAME_MAGIC
            || version != FRAME_VERSION
            || h.flags & !FrameFlags::ALL != 0
            || reserved != 0
            || h.frame_seq == 0
            || usize::from(h.body_len) != body.len()
        {
            return Err(RepErr::Header);
        }
        Ok((h, body))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    pub last_step: StepId,
    pub last_height: Height,
    pub ptp_now: Nanos,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// `tenure_start` is `Some` exactly in frame 1.
    Order {
        tenure_start: Option<TenureStart>,
        sections: Vec<Section>,
    },
    Hash(Vec<Section>),
    Header(BlockHeader),
    Heartbeat(Heartbeat),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub body: Body,
}

/// The fixed header fields of one tenure on one substream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    pub book: BookId,
    pub epoch: Epoch,
    pub tenure: u8,
    pub sender: u8,
}

/// Frames one substream (the stream core's side).
#[derive(Clone, Debug)]
pub struct StreamEncoder {
    state: SubstreamState,
    ident: Ident,
    next_seq: u64,
}

impl StreamEncoder {
    pub fn new(layout: Layout, stream: u8, ident: Ident) -> Result<Self, RepErr> {
        Ok(Self {
            state: SubstreamState::new(layout, stream)?,
            ident,
            next_seq: 1,
        })
    }

    pub const fn state(&self) -> &SubstreamState {
        &self.state
    }

    pub fn take_closed(&mut self) -> Vec<HalfBlock> {
        self.state.take_closed()
    }

    /// The encoder side of [`StreamDecoder::next_tenure`]: `ident` is a later tenure of the same
    /// epoch, `frame_seq` restarts at 1, and session slots carry over.
    pub fn next_tenure(&mut self, ident: Ident) -> Result<(), RepErr> {
        if ident.epoch != self.ident.epoch || ident.tenure <= self.ident.tenure {
            return Err(RepErr::Tenure);
        }
        self.ident = ident;
        self.next_seq = 1;
        Ok(())
    }

    /// Encodes the next frame, path A copy (`flags` = 0). [`with_flags`] makes the other copies.
    pub fn encode(&mut self, body: &Body) -> Result<Vec<u8>, RepErr> {
        let first = self.next_seq == 1;
        let (kind, bytes) = match body {
            Body::Order {
                tenure_start,
                sections,
            } => {
                let mut out = Vec::new();
                match (first, tenure_start) {
                    (true, Some(ts)) => {
                        if ts.epoch != self.ident.epoch
                            || ts.tenure != self.ident.tenure
                            || ts.sender != self.ident.sender
                        {
                            return Err(RepErr::Tenure);
                        }
                        out = self.state.encode_tenure_start(ts)?;
                    }
                    (false, None) => {}
                    _ => return Err(RepErr::Tenure),
                }
                out.extend(self.state.encode_sections(sections, BodyKind::Order)?);
                (FrameKind::Order, out)
            }
            _ if first => return Err(RepErr::Tenure),
            Body::Hash(sections) => (
                FrameKind::Hash,
                self.state.encode_sections(sections, BodyKind::Hash)?,
            ),
            Body::Header(h) => {
                if self.state.stream() != 0 {
                    return Err(RepErr::Header);
                }
                (FrameKind::Header, encode_header(h).to_vec())
            }
            Body::Heartbeat(hb) => (FrameKind::Heartbeat, heartbeat_bytes(hb)),
        };
        let header = FrameHeader {
            kind,
            book: self.ident.book,
            epoch16: self.ident.epoch.low16(),
            frame_seq: self.next_seq,
            flags: 0,
            tenure: self.ident.tenure,
            body_len: u16::try_from(bytes.len()).map_err(|_| RepErr::Header)?,
            sender: self.ident.sender,
            stream: self.state.stream(),
        };
        self.next_seq = self.next_seq.checked_add(1).ok_or(RepErr::Range)?;
        let mut out = header.encode().to_vec();
        out.extend(bytes);
        Ok(out)
    }
}

/// A copy of `frame` with `flags` replaced, such as [`FrameFlags::PATH_B`] for path B.
pub fn with_flags(frame: &[u8], flags: u8) -> Vec<u8> {
    let mut out = frame.to_vec();
    if let Some(f) = out.get_mut(16) {
        *f = flags;
    }
    out
}

fn heartbeat_bytes(hb: &Heartbeat) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&hb.last_step.0.to_le_bytes());
    out.extend_from_slice(&hb.last_height.0.to_le_bytes());
    out.extend_from_slice(&hb.ptp_now.0.to_le_bytes());
    out
}

/// Decodes one substream in `frame_seq` order (the replica's side, 07 §3.12). The caller
/// deduplicates the two paths and repairs gaps; a frame whose `frame_seq` is not
/// [`next_frame_seq`](Self::next_frame_seq) is `RepErr::Seq`. After any other error the
/// substream is faulty and every later call returns `RepErr::Poisoned`; a frame whose header
/// does not parse counts as such an error.
#[derive(Clone, Debug)]
pub struct StreamDecoder {
    state: SubstreamState,
    next_seq: u64,
    ident: Option<(BookId, u16, u8, u8)>,
    /// `(epoch16, tenure)` of the tenure before [`next_tenure`](Self::next_tenure).
    prior: Option<(u16, u8)>,
    poisoned: bool,
}

impl StreamDecoder {
    pub fn new(layout: Layout, stream: u8) -> Result<Self, RepErr> {
        Ok(Self {
            state: SubstreamState::new(layout, stream)?,
            next_seq: 1,
            ident: None,
            prior: None,
            poisoned: false,
        })
    }

    /// Starts the next tenure of the same epoch after a failover (07 §9.5): `frame_seq` restarts
    /// at 1 and the next frame must open with a `TenureStart` of a later tenure in this epoch.
    /// Session slots and their `pkt_seq` predictions are epoch-scoped (07 §3.5) and carry over;
    /// `TenureStart` resets every other base. A new epoch takes a new decoder. A faulty
    /// substream cannot continue: its state past the sealed prefix is undefined, so the caller
    /// rebuilds it by decoding the final prefix again.
    pub fn next_tenure(&mut self) -> Result<(), RepErr> {
        if self.poisoned {
            return Err(RepErr::Poisoned);
        }
        let (_, epoch16, tenure, _) = self.ident.ok_or(RepErr::Tenure)?;
        self.prior = Some((epoch16, tenure));
        self.ident = None;
        self.next_seq = 1;
        Ok(())
    }

    pub const fn state(&self) -> &SubstreamState {
        &self.state
    }

    pub const fn next_frame_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn take_closed(&mut self) -> Vec<HalfBlock> {
        self.state.take_closed()
    }

    pub fn decode(&mut self, bytes: &[u8]) -> Result<Frame, RepErr> {
        if self.poisoned {
            return Err(RepErr::Poisoned);
        }
        let (header, body) = match FrameHeader::parse(bytes) {
            Ok(x) => x,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        if header.frame_seq != self.next_seq {
            return Err(RepErr::Seq);
        }
        let out = self.decode_body(header, body);
        match out {
            Ok(_) => self.next_seq = self.next_seq.saturating_add(1),
            Err(_) => self.poisoned = true,
        }
        out
    }

    fn decode_body(&mut self, header: FrameHeader, body: &[u8]) -> Result<Frame, RepErr> {
        let id = (header.book, header.epoch16, header.tenure, header.sender);
        if header.stream != self.state.stream() || self.ident.is_some_and(|i| i != id) {
            return Err(RepErr::Header);
        }
        let first = header.frame_seq == 1;
        if first && header.kind != FrameKind::Order {
            return Err(RepErr::Tenure);
        }
        let body = match header.kind {
            FrameKind::Order => {
                let mut r = Reader::new(body);
                let tenure_start = if first {
                    let ts = self.state.decode_tenure_start(&mut r)?;
                    let later = self
                        .prior
                        .is_none_or(|(e, t)| e == header.epoch16 && ts.tenure > t);
                    if ts.epoch.low16() != header.epoch16
                        || ts.tenure != header.tenure
                        || ts.sender != header.sender
                        || !later
                    {
                        return Err(RepErr::Tenure);
                    }
                    self.ident = Some(id);
                    Some(ts)
                } else {
                    None
                };
                let sections = self.state.decode_sections(r.rest(), BodyKind::Order)?;
                Body::Order {
                    tenure_start,
                    sections,
                }
            }
            FrameKind::Hash => Body::Hash(self.state.decode_sections(body, BodyKind::Hash)?),
            FrameKind::Header => {
                let b: &[u8; HEADER_BYTES] = body.try_into().map_err(|_| RepErr::Header)?;
                if header.stream != 0 {
                    return Err(RepErr::Header);
                }
                Body::Header(decode_header(b))
            }
            FrameKind::Heartbeat => {
                let mut r = Reader::new(body);
                let hb = Heartbeat {
                    last_step: StepId(r.u64().map_err(|_| RepErr::Header)?),
                    last_height: Height(r.u64().map_err(|_| RepErr::Header)?),
                    ptp_now: Nanos(r.u64().map_err(|_| RepErr::Header)?),
                };
                if !r.is_empty() {
                    return Err(RepErr::Header);
                }
                Body::Heartbeat(hb)
            }
        };
        Ok(Frame { header, body })
    }
}
