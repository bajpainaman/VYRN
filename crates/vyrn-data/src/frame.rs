//! Data frames (07 §5.3) and fetch requests (this crate's bytes for 07 §5.5's `DataFetch`).
//! The layouts are in the crate docs.

use vyrn_nic::frame::MAX_PAYLOAD;
use vyrn_types::{BookId, Height, SessionId};

pub const DATA_MAGIC: u16 = 0x4450;
pub const FETCH_MAGIC: u16 = 0x4650;
pub const VERSION: u8 = 1;
pub const HDR_BYTES: usize = 24;
pub const FETCH_BYTES: usize = 32;
/// An authenticated fetch: the 32 bytes, then `tag` u64 = SipHash-2-4 under the requester's
/// `K_fetch` of bytes 0..32 (crate docs, § Fetch).
pub const FETCH_AUTH_BYTES: usize = FETCH_BYTES + 8;
/// The largest data frame: one UDP payload of a 1514-byte fast-path frame.
pub const MAX_FRAME: usize = MAX_PAYLOAD;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Data = 1,
    DataHb = 2,
    FetchResp = 3,
}

/// The 24-byte header of a data frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataHdr {
    pub kind: Kind,
    pub book: BookId,
    pub epoch16: u16,
    pub data_seq: u64,
    pub src: u8,
}

/// Why a data frame or fetch request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameErr {
    #[error("shorter than its header, or a fetch other than 32 bytes")]
    Short,
    #[error("bad magic")]
    Magic,
    #[error("bad version")]
    Version,
    #[error("unknown kind")]
    Kind,
    #[error("reserved bytes are not zero")]
    Reserved,
    #[error("body_len is not the bytes after the header")]
    BodyLen,
    #[error("a packet runs past the body")]
    Truncated,
    #[error("padding is not zero")]
    Pad,
    #[error("n_pkts is not the number of entries")]
    Count,
    #[error("a heartbeat carries packets")]
    HbBody,
    #[error("an authenticated fetch whose tag does not verify")]
    Tag,
    #[error("a REDIRECT whose down or to is not below 8, or both are the same position")]
    Position,
    #[error("REDIRECT_BATCH sessions are not strictly ascending (a duplicate or out of order)")]
    Order,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    let mut a = [0u8; 2];
    if let Some(s) = b.get(at..at.saturating_add(2)) {
        a.copy_from_slice(s);
    }
    u16::from_le_bytes(a)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    if let Some(s) = b.get(at..at.saturating_add(4)) {
        a.copy_from_slice(s);
    }
    u32::from_le_bytes(a)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    if let Some(s) = b.get(at..at.saturating_add(8)) {
        a.copy_from_slice(s);
    }
    u64::from_le_bytes(a)
}

/// Builds one data frame in a fixed buffer. Never allocates after `new`.
#[derive(Clone, Debug)]
pub struct FrameBuf {
    buf: Box<[u8; MAX_FRAME]>,
    len: usize,
    n_pkts: u8,
}

impl Default for FrameBuf {
    fn default() -> Self {
        Self {
            buf: Box::new([0u8; MAX_FRAME]),
            len: HDR_BYTES,
            n_pkts: 0,
        }
    }
}

/// The bytes one packet takes in a body.
pub const fn entry_len(pkt_len: usize) -> usize {
    2 + pkt_len + (pkt_len & 1)
}

impl FrameBuf {
    pub fn n_pkts(&self) -> u8 {
        self.n_pkts
    }

    pub fn is_empty(&self) -> bool {
        self.n_pkts == 0
    }

    /// True if a packet of `pkt_len` bytes fits.
    pub fn fits(&self, pkt_len: usize) -> bool {
        self.n_pkts < u8::MAX && self.len.saturating_add(entry_len(pkt_len)) <= MAX_FRAME
    }

    /// Appends one packet; false (and nothing written) if it does not fit.
    pub fn push(&mut self, pkt: &[u8]) -> bool {
        let Ok(l) = u16::try_from(pkt.len()) else {
            return false;
        };
        if !self.fits(pkt.len()) {
            return false;
        }
        let at = self.len;
        let end = at.saturating_add(entry_len(pkt.len()));
        let Some(dst) = self.buf.get_mut(at..end) else {
            return false;
        };
        dst.fill(0);
        let (len_b, rest) = dst.split_at_mut(2);
        len_b.copy_from_slice(&l.to_le_bytes());
        if let Some(d) = rest.get_mut(..pkt.len()) {
            d.copy_from_slice(pkt);
        }
        self.len = end;
        self.n_pkts = self.n_pkts.saturating_add(1);
        true
    }

    /// Writes the header and returns the frame; the buffer then starts empty again.
    pub fn finish(&mut self, hdr: &DataHdr) -> &[u8] {
        let body = u16::try_from(self.len.saturating_sub(HDR_BYTES)).unwrap_or(u16::MAX);
        let mut h = [0u8; HDR_BYTES];
        h[0..2].copy_from_slice(&DATA_MAGIC.to_le_bytes());
        h[2] = VERSION;
        h[3] = hdr.kind as u8;
        h[4..6].copy_from_slice(&hdr.book.0.to_le_bytes());
        h[6..8].copy_from_slice(&hdr.epoch16.to_le_bytes());
        h[8..16].copy_from_slice(&hdr.data_seq.to_le_bytes());
        h[16] = hdr.src;
        h[17] = self.n_pkts;
        h[18..20].copy_from_slice(&body.to_le_bytes());
        if let Some(d) = self.buf.get_mut(..HDR_BYTES) {
            d.copy_from_slice(&h);
        }
        let len = self.len;
        self.len = HDR_BYTES;
        self.n_pkts = 0;
        self.buf.get(..len).unwrap_or(&[])
    }
}

/// A data frame that decoded: its header and an iterator over its packets.
#[derive(Clone, Copy, Debug)]
pub struct DataFrame<'a> {
    pub hdr: DataHdr,
    pub n_pkts: u8,
    body: &'a [u8],
}

impl<'a> DataFrame<'a> {
    /// The packets, in frame order. Each entry was checked by [`decode`].
    pub fn packets(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut rest = self.body;
        core::iter::from_fn(move || {
            let l = usize::from(u16_at(rest, 0));
            let pkt = rest.get(2..2usize.saturating_add(l))?;
            rest = rest.get(entry_len(l)..).unwrap_or(&[]);
            Some(pkt)
        })
    }
}

/// Decodes one data frame strictly.
pub fn decode(b: &[u8]) -> Result<DataFrame<'_>, FrameErr> {
    if b.len() < HDR_BYTES {
        return Err(FrameErr::Short);
    }
    if u16_at(b, 0) != DATA_MAGIC {
        return Err(FrameErr::Magic);
    }
    if b.get(2) != Some(&VERSION) {
        return Err(FrameErr::Version);
    }
    let kind = match b.get(3) {
        Some(1) => Kind::Data,
        Some(2) => Kind::DataHb,
        Some(3) => Kind::FetchResp,
        _ => return Err(FrameErr::Kind),
    };
    if u32_at(b, 20) != 0 {
        return Err(FrameErr::Reserved);
    }
    let body = b.get(HDR_BYTES..).unwrap_or(&[]);
    if usize::from(u16_at(b, 18)) != body.len() {
        return Err(FrameErr::BodyLen);
    }
    let n_pkts = b.get(17).copied().unwrap_or(0);
    if kind == Kind::DataHb && (n_pkts != 0 || !body.is_empty()) {
        return Err(FrameErr::HbBody);
    }
    let mut rest = body;
    let mut n = 0u32;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(FrameErr::Truncated);
        }
        let l = usize::from(u16_at(rest, 0));
        let e = entry_len(l);
        let Some(entry) = rest.get(..e) else {
            return Err(FrameErr::Truncated);
        };
        if l & 1 == 1 && entry.last() != Some(&0) {
            return Err(FrameErr::Pad);
        }
        rest = rest.get(e..).unwrap_or(&[]);
        n = n.saturating_add(1);
    }
    if n != u32::from(n_pkts) {
        return Err(FrameErr::Count);
    }
    Ok(DataFrame {
        hdr: DataHdr {
            kind,
            book: BookId(u16_at(b, 4)),
            epoch16: u16_at(b, 6),
            data_seq: u64_at(b, 8),
            src: b.get(16).copied().unwrap_or(0),
        },
        n_pkts,
        body,
    })
}

/// A fetch request (crate docs, § Fetch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetch {
    Key {
        session: SessionId,
        pkt_seq: u32,
    },
    Range {
        dst: u8,
        from: u64,
        to: u64,
    },
    Block {
        height: Height,
    },
    /// *Reading* (07 §5.7 step 3, wire): a replica's `resend_from` for one session homed on
    /// the down box, which this box turns into the session's `DataRedirect{down → to,
    /// resend_from}` (04 §7.6). `down` and `to` are `KeyBundle.data` positions, as there.
    Redirect {
        session: SessionId,
        resend_from: u32,
        down: u8,
        to: u8,
    },
}

/// The most entries a session's `KeyBundle.data` list has (04 §7.6 DR1: `down`, `to` < 8).
pub const MAX_DATA_POS: u8 = 8;

impl Fetch {
    pub fn encode(&self) -> [u8; FETCH_BYTES] {
        let mut b = [0u8; FETCH_BYTES];
        b[0..2].copy_from_slice(&FETCH_MAGIC.to_le_bytes());
        b[2] = VERSION;
        match *self {
            Self::Key { session, pkt_seq } => {
                b[3] = 1;
                b[8..12].copy_from_slice(&session.0.to_le_bytes());
                b[12..16].copy_from_slice(&pkt_seq.to_le_bytes());
            }
            Self::Range { dst, from, to } => {
                b[3] = 2;
                b[8] = dst;
                b[16..24].copy_from_slice(&from.to_le_bytes());
                b[24..32].copy_from_slice(&to.to_le_bytes());
            }
            Self::Block { height } => {
                b[3] = 3;
                b[8..16].copy_from_slice(&height.0.to_le_bytes());
            }
            Self::Redirect {
                session,
                resend_from,
                down,
                to,
            } => {
                b[3] = 4;
                b[8..12].copy_from_slice(&session.0.to_le_bytes());
                b[12..16].copy_from_slice(&resend_from.to_le_bytes());
                b[16] = down;
                b[17] = to;
            }
        }
        b
    }

    /// Decodes strictly: exactly 32 bytes, every unused byte 0.
    pub fn decode(b: &[u8]) -> Result<Self, FrameErr> {
        if b.len() != FETCH_BYTES {
            return Err(FrameErr::Short);
        }
        if u16_at(b, 0) != FETCH_MAGIC {
            return Err(FrameErr::Magic);
        }
        if b.get(2) != Some(&VERSION) {
            return Err(FrameErr::Version);
        }
        let zero = |r: core::ops::Range<usize>| b.get(r).is_some_and(|s| s.iter().all(|&x| x == 0));
        if !zero(4..8) {
            return Err(FrameErr::Reserved);
        }
        let (f, unused) = match b.get(3) {
            Some(1) => (
                Self::Key {
                    session: SessionId(u32_at(b, 8)),
                    pkt_seq: u32_at(b, 12),
                },
                16..32,
            ),
            Some(2) => {
                if !zero(9..16) {
                    return Err(FrameErr::Reserved);
                }
                (
                    Self::Range {
                        dst: b.get(8).copied().unwrap_or(0),
                        from: u64_at(b, 16),
                        to: u64_at(b, 24),
                    },
                    32..32,
                )
            }
            Some(3) => (
                Self::Block {
                    height: Height(u64_at(b, 8)),
                },
                16..32,
            ),
            Some(4) => {
                let (down, to) = (
                    b.get(16).copied().unwrap_or(0),
                    b.get(17).copied().unwrap_or(0),
                );
                if !zero(18..32) {
                    return Err(FrameErr::Reserved);
                }
                if down >= MAX_DATA_POS || to >= MAX_DATA_POS || down == to {
                    return Err(FrameErr::Position);
                }
                (
                    Self::Redirect {
                        session: SessionId(u32_at(b, 8)),
                        resend_from: u32_at(b, 12),
                        down,
                        to,
                    },
                    32..32,
                )
            }
            _ => return Err(FrameErr::Kind),
        };
        if !zero(unused) {
            return Err(FrameErr::Reserved);
        }
        Ok(f)
    }
}

impl Fetch {
    /// The 40-byte authenticated form under `key` (`K_fetch` of the requester).
    pub fn seal(&self, key: &[u8; 16]) -> [u8; FETCH_AUTH_BYTES] {
        let body = self.encode();
        let mut b = [0u8; FETCH_AUTH_BYTES];
        let (head, tag) = b.split_at_mut(FETCH_BYTES);
        head.copy_from_slice(&body);
        tag.copy_from_slice(&vyrn_crypto::siphash24(key, &body).0.to_le_bytes());
        b
    }

    /// Decodes a 40-byte authenticated fetch: the tag first, in constant time, then the 32
    /// bytes as [`Fetch::decode`] does.
    pub fn open(b: &[u8], key: &[u8; 16]) -> Result<Self, FrameErr> {
        if b.len() != FETCH_AUTH_BYTES {
            return Err(FrameErr::Short);
        }
        let (body, tag) = b.split_at(FETCH_BYTES);
        let tag = vyrn_types::Tag(u64_at(tag, 0));
        if !vyrn_crypto::siphash::verify(key, body, tag) {
            return Err(FrameErr::Tag);
        }
        Self::decode(body)
    }
}

/// The 40-byte authenticated form of `fetch` under `key`, the requester's `K_fetch` (07 §5.5):
/// what every requester sends to a keyed data box or `vyrn-seq` box.
pub fn seal_fetch(key: &[u8; 16], fetch: &Fetch) -> [u8; FETCH_AUTH_BYTES] {
    fetch.seal(key)
}

/// The REDIRECT_BATCH kind (crate docs, § Fetch; 07 §5.7 step 3).
pub const KIND_REDIRECT_BATCH: u8 = 5;
/// REDIRECT_BATCH: the 16 bytes before the entries.
pub const BATCH_HDR_BYTES: usize = 16;
/// REDIRECT_BATCH: one `(session u32, resend_from u32)` entry.
pub const BATCH_ENTRY_BYTES: usize = 8;
/// The most entries in one REDIRECT_BATCH: 181, so the sealed form (16 + 8n + 8 bytes, 1,472 at
/// 181) is one UDP payload of a 1514-byte frame, the bound a data frame has ([`MAX_FRAME`]).
pub const MAX_BATCH: usize = (MAX_FRAME - BATCH_HDR_BYTES - 8) / BATCH_ENTRY_BYTES;

/// A REDIRECT_BATCH (kind 5): kind 4 for up to [`MAX_BATCH`] sessions of one `down → to` move,
/// read in place from the datagram. Decoding is strict (crate docs, § Fetch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedirectBatch<'a> {
    pub down: u8,
    pub to: u8,
    entries: &'a [u8],
}

impl<'a> RedirectBatch<'a> {
    /// The number of entries, 1 ..= [`MAX_BATCH`].
    pub fn len(&self) -> usize {
        self.entries.len() / BATCH_ENTRY_BYTES
    }

    /// Never true: a decoded batch has at least one entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `(session, resend_from)` in wire order: sessions strictly ascending.
    pub fn entries(&self) -> impl Iterator<Item = (SessionId, u32)> + 'a {
        self.entries
            .as_chunks::<BATCH_ENTRY_BYTES>()
            .0
            .iter()
            .map(|e| (SessionId(u32_at(e, 0)), u32_at(e, 4)))
    }

    /// Decodes strictly: the fetch header with kind 5 and zero reserved bytes, `down` and `to`
    /// as for kind 4 (04 DR1), `count` in 1 ..= [`MAX_BATCH`] and exactly `count` entries after
    /// the header, sessions strictly ascending (so no duplicates).
    pub fn decode(b: &'a [u8]) -> Result<Self, FrameErr> {
        let Some(hdr) = b.get(..BATCH_HDR_BYTES) else {
            return Err(FrameErr::Short);
        };
        if u16_at(hdr, 0) != FETCH_MAGIC {
            return Err(FrameErr::Magic);
        }
        if hdr.get(2) != Some(&VERSION) {
            return Err(FrameErr::Version);
        }
        if hdr.get(3) != Some(&KIND_REDIRECT_BATCH) {
            return Err(FrameErr::Kind);
        }
        let zero =
            |r: core::ops::Range<usize>| hdr.get(r).is_some_and(|s| s.iter().all(|&x| x == 0));
        if !zero(4..8) || !zero(12..16) {
            return Err(FrameErr::Reserved);
        }
        let (down, to) = (
            hdr.get(8).copied().unwrap_or(0),
            hdr.get(9).copied().unwrap_or(0),
        );
        if down >= MAX_DATA_POS || to >= MAX_DATA_POS || down == to {
            return Err(FrameErr::Position);
        }
        let count = usize::from(u16_at(hdr, 10));
        let entries = b.get(BATCH_HDR_BYTES..).unwrap_or(&[]);
        if count == 0 || count > MAX_BATCH || entries.len() != count * BATCH_ENTRY_BYTES {
            return Err(FrameErr::Count);
        }
        let batch = Self { down, to, entries };
        let mut prev = None;
        for (s, _) in batch.entries() {
            if prev.is_some_and(|p| p >= s.0) {
                return Err(FrameErr::Order);
            }
            prev = Some(s.0);
        }
        Ok(batch)
    }

    /// Decodes an authenticated batch: the trailing 8-byte tag over everything before it
    /// first, in constant time, then the bytes as [`RedirectBatch::decode`] does.
    pub fn open(b: &'a [u8], key: &[u8; 16]) -> Result<Self, FrameErr> {
        let Some(split) = b.len().checked_sub(8).filter(|&n| n >= BATCH_HDR_BYTES) else {
            return Err(FrameErr::Short);
        };
        let (body, tag) = b.split_at(split);
        if !vyrn_crypto::siphash::verify(key, body, vyrn_types::Tag(u64_at(tag, 0))) {
            return Err(FrameErr::Tag);
        }
        Self::decode(body)
    }

    /// The plain bytes of a batch, checked as [`RedirectBatch::decode`] checks them. Senders
    /// sort `entries` by session first.
    pub fn encode(down: u8, to: u8, entries: &[(SessionId, u32)]) -> Result<Vec<u8>, FrameErr> {
        // Positions, then the count, before any buffer is built (the order decode reports).
        if down >= MAX_DATA_POS || to >= MAX_DATA_POS || down == to {
            return Err(FrameErr::Position);
        }
        if entries.is_empty() || entries.len() > MAX_BATCH {
            return Err(FrameErr::Count);
        }
        let count = u16::try_from(entries.len()).map_err(|_| FrameErr::Count)?;
        let mut b = Vec::with_capacity(BATCH_HDR_BYTES + entries.len() * BATCH_ENTRY_BYTES + 8);
        b.extend_from_slice(&FETCH_MAGIC.to_le_bytes());
        b.extend_from_slice(&[VERSION, KIND_REDIRECT_BATCH, 0, 0, 0, 0, down, to]);
        b.extend_from_slice(&count.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for &(s, r) in entries {
            b.extend_from_slice(&s.0.to_le_bytes());
            b.extend_from_slice(&r.to_le_bytes());
        }
        RedirectBatch::decode(&b)?;
        Ok(b)
    }

    /// The authenticated form under `key`, the requester's `K_fetch`: the plain bytes, then
    /// `tag` u64 = SipHash-2-4(`K_fetch`, the plain bytes).
    pub fn seal(
        key: &[u8; 16],
        down: u8,
        to: u8,
        entries: &[(SessionId, u32)],
    ) -> Result<Vec<u8>, FrameErr> {
        let mut b = Self::encode(down, to, entries)?;
        let tag = vyrn_crypto::siphash24(key, &b).0;
        b.extend_from_slice(&tag.to_le_bytes());
        Ok(b)
    }
}

/// A decoded fetch datagram: one fixed 32-byte [`Fetch`], or a [`RedirectBatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchMsg<'a> {
    One(Fetch),
    Batch(RedirectBatch<'a>),
}

impl<'a> FetchMsg<'a> {
    fn is_batch(b: &[u8]) -> bool {
        b.get(3) == Some(&KIND_REDIRECT_BATCH)
    }

    /// [`RedirectBatch::decode`] for kind 5, else [`Fetch::decode`].
    pub fn decode(b: &'a [u8]) -> Result<Self, FrameErr> {
        if Self::is_batch(b) {
            RedirectBatch::decode(b).map(Self::Batch)
        } else {
            Fetch::decode(b).map(Self::One)
        }
    }

    /// [`RedirectBatch::open`] for kind 5, else [`Fetch::open`].
    pub fn open(b: &'a [u8], key: &[u8; 16]) -> Result<Self, FrameErr> {
        if Self::is_batch(b) {
            RedirectBatch::open(b, key).map(Self::Batch)
        } else {
            Fetch::open(b, key).map(Self::One)
        }
    }
}

/// `data_seq` of the `FETCH_RESP` that answers a KEY fetch.
pub const fn key_seq(session: SessionId, pkt_seq: u32) -> u64 {
    ((session.0 as u64) << 32) | pkt_seq as u64
}
