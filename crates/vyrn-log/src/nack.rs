//! Sequencer retransmit on the wire (07 §4.10): `Nack` and `NackTooOld`.
//!
//! ```text
//! Nack (24 B)                         NackTooOld (16 B)
//! off size field                      off size field
//!   0   1  type      0x31               0   1  type        0x32
//!   1   1  path      0 A, 1 B           1   1  path        0 A, 1 B
//!   2   2  epoch16                      2   2  epoch16
//!   4   1  tenure                       4   1  tenure
//!   5   1  stream    0 A, 1 B           5   1  stream
//!   6   2  port      requester's ORDER  6   2  reserved    0
//!                    port on `path`
//!   8   8  from_seq  ≥ 1                8   8  oldest_seq  oldest frame the ring holds
//!  16   8  to_seq    from ≤ to < from + NACK_SPAN_MAX
//! ```
//!
//! Every integer is little-endian. A datagram of another length, type, path or stream, a
//! nonzero reserved field, or a range outside those bounds is refused. These layouts are a
//! reading of 07 §4.10, which names the fields but gives no bytes; `port` is added so a box can
//! name which of its configured replicas it is when several share one IPv4 (DEV), and the
//! sequencer sends the retransmit to that configured address, never to the datagram's source.

/// Path A or B: the replication port a datagram arrived on, or a Nack asks about (07 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A,
    B,
}

pub const NACK_TYPE: u8 = 0x31;
pub const NACK_TOO_OLD_TYPE: u8 = 0x32;
pub const NACK_BYTES: usize = 24;
pub const NACK_TOO_OLD_BYTES: usize = 16;
/// The most frames one `Nack` asks for; a longer hole takes several.
pub const NACK_SPAN_MAX: u64 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nack {
    pub path: Path,
    pub epoch16: u16,
    pub tenure: u8,
    pub stream: u8,
    pub port: u16,
    pub from_seq: u64,
    pub to_seq: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NackTooOld {
    pub path: Path,
    pub epoch16: u16,
    pub tenure: u8,
    pub stream: u8,
    pub oldest_seq: u64,
}

fn path_byte(p: Path) -> u8 {
    u8::from(p == Path::B)
}

fn path_of(b: u8) -> Option<Path> {
    match b {
        0 => Some(Path::A),
        1 => Some(Path::B),
        _ => None,
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*b.get(at..)?.first_chunk::<2>()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*b.get(at..)?.first_chunk::<8>()?))
}

impl Nack {
    pub fn encode(&self) -> [u8; NACK_BYTES] {
        let [e0, e1] = self.epoch16.to_le_bytes();
        let [p0, p1] = self.port.to_le_bytes();
        let [f0, f1, f2, f3, f4, f5, f6, f7] = self.from_seq.to_le_bytes();
        let [t0, t1, t2, t3, t4, t5, t6, t7] = self.to_seq.to_le_bytes();
        [
            NACK_TYPE,
            path_byte(self.path),
            e0,
            e1,
            self.tenure,
            self.stream,
            p0,
            p1,
            f0,
            f1,
            f2,
            f3,
            f4,
            f5,
            f6,
            f7,
            t0,
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
            t7,
        ]
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != NACK_BYTES || b.first() != Some(&NACK_TYPE) {
            return None;
        }
        let n = Self {
            path: path_of(*b.get(1)?)?,
            epoch16: u16_at(b, 2)?,
            tenure: *b.get(4)?,
            stream: *b.get(5)?,
            port: u16_at(b, 6)?,
            from_seq: u64_at(b, 8)?,
            to_seq: u64_at(b, 16)?,
        };
        let span_ok = n.from_seq >= 1
            && n.from_seq <= n.to_seq
            && n.to_seq.saturating_sub(n.from_seq) < NACK_SPAN_MAX;
        (n.stream <= 1 && span_ok).then_some(n)
    }
}

impl NackTooOld {
    pub fn encode(&self) -> [u8; NACK_TOO_OLD_BYTES] {
        let [e0, e1] = self.epoch16.to_le_bytes();
        let [o0, o1, o2, o3, o4, o5, o6, o7] = self.oldest_seq.to_le_bytes();
        [
            NACK_TOO_OLD_TYPE,
            path_byte(self.path),
            e0,
            e1,
            self.tenure,
            self.stream,
            0,
            0,
            o0,
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
            o7,
        ]
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != NACK_TOO_OLD_BYTES
            || b.first() != Some(&NACK_TOO_OLD_TYPE)
            || u16_at(b, 6)? != 0
        {
            return None;
        }
        let t = Self {
            path: path_of(*b.get(1)?)?,
            epoch16: u16_at(b, 2)?,
            tenure: *b.get(4)?,
            stream: *b.get(5)?,
            oldest_seq: u64_at(b, 8)?,
        };
        (t.stream <= 1).then_some(t)
    }
}
