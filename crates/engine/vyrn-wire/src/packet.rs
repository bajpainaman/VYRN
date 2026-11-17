//! Request (01 §6.1) and response (01 §6.3) packets: parse into borrowed views, build into a
//! caller's buffer. Neither allocates.

use vyrn_crypto::siphash::{siphash24, verify};
use vyrn_types::{
    BookId, MAX_MSGS_PER_PKT, MAX_REQ_PAYLOAD, MSG_BYTES, PKT_HDR_BYTES, SessionId, TAG_BYTES, Tag,
};
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::msg::Msg;
use crate::record::Record;
use crate::{PROTO_D_BAD_HDR, WireError};

/// Records in one response (01 §6.3).
pub const MAX_RECS_PER_PKT: u8 = 16;
/// 16 + 16 × 16 + 8 (04 §1).
pub const PROTO_RESP_MAX_BYTES: usize = 280;

const RESEND: u8 = 0x01;

fn bad_hdr() -> WireError {
    WireError::bad_type(PROTO_D_BAD_HDR)
}

/// Bytes 0 .. 16 + 16n: the bytes every tag covers.
fn signed_len(n: u8) -> Option<usize> {
    usize::from(n)
        .checked_mul(MSG_BYTES)?
        .checked_add(PKT_HDR_BYTES)
}

fn read_tag(bytes: &[u8], at: usize) -> Option<Tag> {
    let end = at.checked_add(TAG_BYTES)?;
    U64::read_from_bytes(bytes.get(at..end)?)
        .ok()
        .map(|t| Tag(t.get()))
}

/// Bytes 0–15 of a request.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct ReqHeader {
    pub session: U32,
    pub pkt_seq: U32,
    pub count: u8,
    pub flags: u8,
    pub epoch16: U16,
    pub book: U16,
    pub reserved: U16,
}
const _: () = assert!(size_of::<ReqHeader>() == PKT_HDR_BYTES);

impl ReqHeader {
    /// `count` is set by `encode_request`.
    pub fn new(session: SessionId, pkt_seq: u32, epoch16: u16, book: BookId, resend: bool) -> Self {
        Self {
            session: session.0.into(),
            pkt_seq: pkt_seq.into(),
            count: 0,
            flags: u8::from(resend),
            epoch16: epoch16.into(),
            book: book.0.into(),
            reserved: U16::ZERO,
        }
    }

    pub fn session(&self) -> SessionId {
        SessionId(self.session.get())
    }

    pub fn book(&self) -> BookId {
        BookId(self.book.get())
    }
}

/// Bytes 0–15 of a response.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned,
)]
#[repr(C)]
pub struct RespHeader {
    pub session: U32,
    pub resp_seq: U32,
    pub count: u8,
    pub flags: u8,
    pub epoch16: U16,
    pub echo_pkt: U32,
}
const _: () = assert!(size_of::<RespHeader>() == PKT_HDR_BYTES);

impl RespHeader {
    /// `resp_seq` 0 marks an out-of-stream response (04 P6). `count` is set by `encode_response`.
    pub fn new(
        session: SessionId,
        resp_seq: u32,
        epoch16: u16,
        echo_pkt: u32,
        resend: bool,
    ) -> Self {
        Self {
            session: session.0.into(),
            resp_seq: resp_seq.into(),
            count: 0,
            flags: u8::from(resend),
            epoch16: epoch16.into(),
            echo_pkt: echo_pkt.into(),
        }
    }

    pub fn session(&self) -> SessionId {
        SessionId(self.session.get())
    }
}

/// A request whose length and `count` are consistent (04 §3.1 V1). Nothing else is checked yet.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    header: &'a ReqHeader,
    signed: &'a [u8],
    msgs: &'a [[u8; MSG_BYTES]],
    tag_seq: Tag,
    tag_com: Tag,
}

impl<'a> Request<'a> {
    /// V1: payload length = 32 + 16 × `count`, and 1 ≤ `count` ≤ `MAX_MSGS_PER_PKT`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        let (header, _) = ReqHeader::ref_from_prefix(bytes).map_err(|_| bad_hdr())?;
        if !(1..=MAX_MSGS_PER_PKT).contains(&header.count) {
            return Err(bad_hdr());
        }
        let end = signed_len(header.count).ok_or_else(bad_hdr)?;
        if Some(bytes.len()) != end.checked_add(2 * TAG_BYTES) {
            return Err(bad_hdr());
        }
        let signed = bytes.get(..end).ok_or_else(bad_hdr)?;
        let (msgs, _) = signed
            .get(PKT_HDR_BYTES..)
            .ok_or_else(bad_hdr)?
            .as_chunks::<MSG_BYTES>();
        let tag_seq = read_tag(bytes, end).ok_or_else(bad_hdr)?;
        let tag_com =
            read_tag(bytes, end.checked_add(TAG_BYTES).ok_or_else(bad_hdr)?).ok_or_else(bad_hdr)?;
        Ok(Self {
            header,
            signed,
            msgs,
            tag_seq,
            tag_com,
        })
    }

    pub fn header(&self) -> &'a ReqHeader {
        self.header
    }

    pub fn is_resend(&self) -> bool {
        self.header.flags & RESEND != 0
    }

    /// V9, the header half: `flags` bits 1–7 and `reserved` are 0. The book check needs the
    /// session and stays with the lane.
    pub fn check_header(&self) -> Result<(), WireError> {
        if self.header.flags & !RESEND != 0 || self.header.reserved.get() != 0 {
            return Err(bad_hdr());
        }
        Ok(())
    }

    /// Bytes 0 .. 16 + 16n, which both tags and `PktHash` cover.
    pub fn signed_bytes(&self) -> &'a [u8] {
        self.signed
    }

    pub fn tag_seq(&self) -> Tag {
        self.tag_seq
    }

    /// 0 in BASE mode.
    pub fn tag_com(&self) -> Tag {
        self.tag_com
    }

    /// V6, in constant time.
    pub fn verify_seq(&self, k_seq: &[u8; 16]) -> bool {
        verify(k_seq, self.signed, self.tag_seq)
    }

    /// CHAIN mode's second tag (01 §14.19 B).
    pub fn verify_com(&self, k_com: &[u8; 16]) -> bool {
        verify(k_com, self.signed, self.tag_com)
    }

    pub fn raw_msgs(&self) -> &'a [[u8; MSG_BYTES]] {
        self.msgs
    }

    /// M2 and M3 of each message, in index order.
    pub fn msgs(&self) -> impl Iterator<Item = Result<Msg, WireError>> + 'a {
        self.msgs.iter().map(Msg::decode)
    }
}

/// A response whose length, `count` and flags are consistent.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    header: &'a RespHeader,
    signed: &'a [u8],
    recs: &'a [[u8; MSG_BYTES]],
    tag: Tag,
}

impl<'a> Response<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, WireError> {
        let (header, _) = RespHeader::ref_from_prefix(bytes).map_err(|_| bad_hdr())?;
        if !(1..=MAX_RECS_PER_PKT).contains(&header.count) || header.flags & !RESEND != 0 {
            return Err(bad_hdr());
        }
        let end = signed_len(header.count).ok_or_else(bad_hdr)?;
        if Some(bytes.len()) != end.checked_add(TAG_BYTES) {
            return Err(bad_hdr());
        }
        let signed = bytes.get(..end).ok_or_else(bad_hdr)?;
        let (recs, _) = signed
            .get(PKT_HDR_BYTES..)
            .ok_or_else(bad_hdr)?
            .as_chunks::<MSG_BYTES>();
        let tag = read_tag(bytes, end).ok_or_else(bad_hdr)?;
        Ok(Self {
            header,
            signed,
            recs,
            tag,
        })
    }

    pub fn header(&self) -> &'a RespHeader {
        self.header
    }

    pub fn is_resend(&self) -> bool {
        self.header.flags & RESEND != 0
    }

    pub fn is_out_of_stream(&self) -> bool {
        self.header.resp_seq.get() == 0
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn verify(&self, k_out: &[u8; 16]) -> bool {
        verify(k_out, self.signed, self.tag)
    }

    pub fn raw_records(&self) -> &'a [[u8; MSG_BYTES]] {
        self.recs
    }

    pub fn records(&self) -> impl Iterator<Item = Result<Record, WireError>> + 'a {
        self.recs.iter().map(Record::decode)
    }
}

/// Writes header, records and tags into `out`; returns the length. `out` may be larger than the
/// packet. None if `count` is out of range or `out` is too short.
fn encode(
    out: &mut [u8],
    header: &[u8],
    recs: impl ExactSizeIterator<Item = [u8; MSG_BYTES]>,
    keys: &[Option<&[u8; 16]>],
) -> Option<usize> {
    let n = u8::try_from(recs.len()).ok()?;
    let end = signed_len(n)?;
    let total = end.checked_add(TAG_BYTES.checked_mul(keys.len())?)?;
    let out = out.get_mut(..total)?;
    out.get_mut(..PKT_HDR_BYTES)?.copy_from_slice(header);
    *out.get_mut(8)? = n;
    let (chunks, _) = out
        .get_mut(PKT_HDR_BYTES..end)?
        .as_chunks_mut::<MSG_BYTES>();
    for (dst, src) in chunks.iter_mut().zip(recs) {
        *dst = src;
    }
    let (signed, tags) = out.split_at_mut(end);
    let (tag_chunks, _) = tags.as_chunks_mut::<TAG_BYTES>();
    for (dst, key) in tag_chunks.iter_mut().zip(keys) {
        *dst = key.map_or(0, |k| siphash24(k, signed).0).to_le_bytes();
    }
    Some(total)
}

/// Builds a request. `k_com` is None in BASE mode, which writes `tag_com` = 0.
pub fn encode_request(
    out: &mut [u8; MAX_REQ_PAYLOAD],
    header: ReqHeader,
    msgs: &[Msg],
    k_seq: &[u8; 16],
    k_com: Option<&[u8; 16]>,
) -> Option<usize> {
    if !(1..=usize::from(MAX_MSGS_PER_PKT)).contains(&msgs.len()) {
        return None;
    }
    encode(
        out,
        header.as_bytes(),
        msgs.iter().map(|m| m.encode()),
        &[Some(k_seq), k_com],
    )
}

/// Builds a response.
pub fn encode_response(
    out: &mut [u8; PROTO_RESP_MAX_BYTES],
    header: RespHeader,
    recs: &[Record],
    k_out: &[u8; 16],
) -> Option<usize> {
    if !(1..=usize::from(MAX_RECS_PER_PKT)).contains(&recs.len()) {
        return None;
    }
    encode(
        out,
        header.as_bytes(),
        recs.iter().map(|r| r.encode()),
        &[Some(k_out)],
    )
}
