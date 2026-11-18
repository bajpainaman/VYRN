//! The admin-channel messages of 04 §4.4 (BASE session open) and the `CtlDone` control response of
//! 10 §2.4, as bytes.
//!
//! Every admin message on the TLS stream is one frame: `len` u32 (the bytes after it), `type` u16,
//! then the body. Integers are little-endian (01 §6). A `SocketAddrV4` is the IPv4 address in
//! network order, then the port u16 little-endian. [`decode`] refuses, with a 01 §6.5 reason and
//! detail, every frame that 04 §4.4 and VR1 (04 §12) say a receiver must refuse:
//!
//! | Refusal | `WireError` |
//! |---|---|
//! | `len` does not match the body, or the body is cut short | `BAD_TYPE`, `PROTO_D_BAD_HDR` |
//! | unknown `type` | `BAD_TYPE`, `PROTO_D_UNKNOWN_TYPE` |
//! | a nonzero reserved byte | `BAD_TYPE`, `PROTO_D_RESERVED` |
//! | a field outside its table range (`proto_version` ≠ 2, `cod`, `attest`, `rate_tier`, `n_books`, `timeout_ms`, a duplicate book, an unknown home, limit id or reason) | `BAD_TYPE`, `PROTO_D_BAD_HDR` |
//!
//! Reading (spec gap, labelled): 04 §4.4 names no reason for a field outside its range, so the
//! codec uses the VR1 header detail. 04 §4.4 also leaves `N_MAX` undefined, so `n_boxes` is any
//! u8 and `failover_order` is checked only for length.
//!
//! [`encode`] builds the bytes from the same tables and refuses the values [`decode`] would refuse,
//! so `decode(&encode(m)?)? == m` for every message it accepts.
//!
//! Nothing here runs on the 1 µs path: session opens and control responses are rare (04 §4.4,
//! 10 §2.4).

use core::net::{Ipv4Addr, SocketAddrV4};

use vyrn_types::{
    AccountId, BookId, Epoch, HomeCode, LaneId, Nanos, RejectReason, SessionId, StepId,
};
use vyrn_wire::{
    PROTO_D_BAD_HDR, PROTO_D_RESERVED, PROTO_D_UNKNOWN_TYPE, PROTO_VERSION, WireError,
};

/// Frame types (04 §4.4).
pub const T_OPEN_SESSION_REQ: u16 = 0x0001;
pub const T_OPEN_SESSION_RESP: u16 = 0x8001;
pub const T_KEY_BUNDLE: u16 = 0x8002;
pub const T_ERROR: u16 = 0x80FF;

/// `timeout_ms` range (04 §4.8, §14).
pub const PROTO_TIMEOUT_MIN_MS: u32 = 10;
pub const PROTO_TIMEOUT_MAX_MS: u32 = 10_000;
/// Highest rate tier (T0–T3, 10).
pub const RATE_TIER_MAX: u8 = 3;
/// Limit ids of 10 §3.4.
pub const LIMIT_ID_MAX: u8 = 8;

/// `CtlDone` type code and the control op codes it answers (10 §2.4).
pub const T_CTL_DONE: u8 = 0xA2;
pub const CTL_OP_FIRST: u8 = 0x20;
pub const CTL_OP_LAST: u8 = 0x26;

/// `OpenSessionReq` (04 §4.4): 20 + 2 × `books.len()` body bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSessionReq {
    pub account: AccountId,
    /// Must be `PROTO_VERSION` (04 §12; version 1 was never released, vector B08).
    pub proto_version: u16,
    pub cod: bool,
    pub rate_tier: u8,
    pub src: SocketAddrV4,
    pub attest: bool,
    pub timeout_ms: u32,
    /// 1–255 books, no duplicates.
    pub books: Vec<BookId>,
}

/// One per-session limit of the response: a 10 §3.4 limit id and its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub id: u8,
    pub value: u64,
}

/// `OpenSessionResp` (04 §4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenSessionResp {
    pub session: SessionId,
    pub lane: LaneId,
    pub epoch: Epoch,
    pub active_from_step: StepId,
    pub limits: Vec<Limit>,
    pub bundle: KeyBundle,
}

/// `KeyBundle` (04 §4.4), in `OpenSessionResp` and as the 0x8002 push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    pub epoch: Epoch,
    /// End of this epoch, TAI ns.
    pub boundary_ts: Nanos,
    pub home: HomeCode,
    pub seq_index: u8,
    pub next_home: HomeCode,
    /// `None` is 0xFF on the wire.
    pub lane_move: Option<LaneId>,
    /// One entry per box: `failover_order.len() == boxes.len()`.
    pub failover_order: Vec<u8>,
    /// D4 preference order (04 §2.4).
    pub data: [SocketAddrV4; 8],
    pub boxes: Vec<BoxKeys>,
}

/// One box of the home (46 bytes on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoxKeys {
    pub index: u8,
    pub order: SocketAddrV4,
    pub recovery: SocketAddrV4,
    pub k_seq: [u8; 16],
    pub k_out: [u8; 16],
}

/// One admin frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminMsg {
    OpenSessionReq(OpenSessionReq),
    OpenSessionResp(OpenSessionResp),
    KeyBundle(KeyBundle),
    /// Body: a 01 §6.5 reason u16, reserved u16, detail u32.
    Error {
        reason: RejectReason,
        detail: u32,
    },
}

const fn hdr() -> WireError {
    WireError::bad_type(PROTO_D_BAD_HDR)
}

/// The length of the first frame in `buf`, counting its `len` field, once the 4 bytes of `len`
/// have arrived. A stream reader waits for that many bytes and passes them to [`decode`].
pub fn frame_len(buf: &[u8]) -> Option<usize> {
    let len = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?);
    usize::try_from(len).ok()?.checked_add(4)
}

/// Decodes one whole frame. `frame` must be exactly `len` + 4 bytes.
pub fn decode(frame: &[u8]) -> Result<AdminMsg, WireError> {
    let mut r = Rd { b: frame, i: 0 };
    let len = r.u32()?;
    if usize::try_from(len).ok() != frame.len().checked_sub(4) {
        return Err(hdr());
    }
    let msg = match r.u16()? {
        T_OPEN_SESSION_REQ => AdminMsg::OpenSessionReq(open_req(&mut r)?),
        T_OPEN_SESSION_RESP => AdminMsg::OpenSessionResp(open_resp(&mut r)?),
        T_KEY_BUNDLE => AdminMsg::KeyBundle(key_bundle(&mut r)?),
        T_ERROR => {
            let reason = RejectReason::from_code(r.u16()?).ok_or_else(hdr)?;
            r.zero(2)?;
            AdminMsg::Error {
                reason,
                detail: r.u32()?,
            }
        }
        _ => return Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE)),
    };
    if r.i != frame.len() {
        return Err(hdr());
    }
    Ok(msg)
}

/// Encodes one frame, refusing a value that [`decode`] would refuse.
pub fn encode(msg: &AdminMsg) -> Result<Vec<u8>, WireError> {
    let mut w = vec![0u8; 4];
    match msg {
        AdminMsg::OpenSessionReq(m) => {
            put_u16(&mut w, T_OPEN_SESSION_REQ);
            check_req(m)?;
            put_u32(&mut w, m.account.0);
            put_u16(&mut w, m.proto_version);
            w.extend([u8::from(m.cod), m.rate_tier]);
            put_addr(&mut w, m.src);
            w.extend([
                u8::from(m.attest),
                u8::try_from(m.books.len()).map_err(|_| hdr())?,
            ]);
            put_u32(&mut w, m.timeout_ms);
            for b in &m.books {
                put_u16(&mut w, b.0);
            }
        }
        AdminMsg::OpenSessionResp(m) => {
            put_u16(&mut w, T_OPEN_SESSION_RESP);
            put_u32(&mut w, m.session.0);
            w.extend([m.lane.0, 0]);
            put_u16(&mut w, u16::try_from(m.limits.len()).map_err(|_| hdr())?);
            put_u32(&mut w, m.epoch.0);
            put_u64(&mut w, m.active_from_step.0);
            for l in &m.limits {
                if !(1..=LIMIT_ID_MAX).contains(&l.id) {
                    return Err(hdr());
                }
                w.push(l.id);
                w.extend([0u8; 7]);
                put_u64(&mut w, l.value);
            }
            put_bundle(&mut w, &m.bundle)?;
        }
        AdminMsg::KeyBundle(b) => {
            put_u16(&mut w, T_KEY_BUNDLE);
            put_bundle(&mut w, b)?;
        }
        AdminMsg::Error { reason, detail } => {
            put_u16(&mut w, T_ERROR);
            put_u16(&mut w, reason.code());
            put_u16(&mut w, 0);
            put_u32(&mut w, *detail);
        }
    }
    let len = u32::try_from(w.len() - 4).map_err(|_| hdr())?;
    w[..4].copy_from_slice(&len.to_le_bytes());
    Ok(w)
}

fn check_req(m: &OpenSessionReq) -> Result<(), WireError> {
    let books_ok = !m.books.is_empty()
        && m.books.len() <= 255
        && m.books
            .iter()
            .enumerate()
            .all(|(i, b)| !m.books[..i].contains(b));
    let ok = m.proto_version == PROTO_VERSION
        && m.rate_tier <= RATE_TIER_MAX
        && (PROTO_TIMEOUT_MIN_MS..=PROTO_TIMEOUT_MAX_MS).contains(&m.timeout_ms)
        && books_ok;
    if ok { Ok(()) } else { Err(hdr()) }
}

fn open_req(r: &mut Rd<'_>) -> Result<OpenSessionReq, WireError> {
    let account = AccountId(r.u32()?);
    let proto_version = r.u16()?;
    let cod = r.flag()?;
    let rate_tier = r.u8()?;
    let src = r.addr()?;
    let attest = r.flag()?;
    let n_books = r.u8()?;
    let timeout_ms = r.u32()?;
    let books = (0..n_books)
        .map(|_| r.u16().map(BookId))
        .collect::<Result<_, _>>()?;
    let m = OpenSessionReq {
        account,
        proto_version,
        cod,
        rate_tier,
        src,
        attest,
        timeout_ms,
        books,
    };
    check_req(&m)?;
    Ok(m)
}

fn open_resp(r: &mut Rd<'_>) -> Result<OpenSessionResp, WireError> {
    let session = SessionId(r.u32()?);
    let lane = LaneId(r.u8()?);
    r.zero(1)?;
    let n_limits = r.u16()?;
    let epoch = Epoch(r.u32()?);
    let active_from_step = StepId(r.u64()?);
    let mut limits = Vec::with_capacity(usize::from(n_limits).min(r.left() / 16));
    for _ in 0..n_limits {
        let id = r.u8()?;
        r.zero(7)?;
        if !(1..=LIMIT_ID_MAX).contains(&id) {
            return Err(hdr());
        }
        limits.push(Limit {
            id,
            value: r.u64()?,
        });
    }
    let bundle = key_bundle(r)?;
    Ok(OpenSessionResp {
        session,
        lane,
        epoch,
        active_from_step,
        limits,
        bundle,
    })
}

fn key_bundle(r: &mut Rd<'_>) -> Result<KeyBundle, WireError> {
    let epoch = Epoch(r.u32()?);
    let boundary_ts = Nanos(r.u64()?);
    let home = HomeCode::from_code(r.u8()?).ok_or_else(hdr)?;
    let seq_index = r.u8()?;
    let next_home = HomeCode::from_code(r.u8()?).ok_or_else(hdr)?;
    let n_boxes = r.u8()?;
    let lane_move = match r.u8()? {
        0xFF => None,
        l => Some(LaneId(l)),
    };
    r.zero(3)?;
    let failover_order = r.take(usize::from(n_boxes))?.to_vec();
    let mut data = [SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0); 8];
    for d in &mut data {
        *d = r.addr()?;
    }
    let mut boxes = Vec::with_capacity(usize::from(n_boxes));
    for _ in 0..n_boxes {
        let index = r.u8()?;
        r.zero(1)?;
        let (order, recovery) = (r.addr()?, r.addr()?);
        let k_seq = r.take(16)?.try_into().map_err(|_| hdr())?;
        let k_out = r.take(16)?.try_into().map_err(|_| hdr())?;
        boxes.push(BoxKeys {
            index,
            order,
            recovery,
            k_seq,
            k_out,
        });
    }
    Ok(KeyBundle {
        epoch,
        boundary_ts,
        home,
        seq_index,
        next_home,
        lane_move,
        failover_order,
        data,
        boxes,
    })
}

fn put_bundle(w: &mut Vec<u8>, b: &KeyBundle) -> Result<(), WireError> {
    let n_boxes = u8::try_from(b.boxes.len()).map_err(|_| hdr())?;
    if b.failover_order.len() != b.boxes.len() || b.lane_move == Some(LaneId(0xFF)) {
        return Err(hdr());
    }
    put_u32(w, b.epoch.0);
    put_u64(w, b.boundary_ts.0);
    w.extend([b.home.code(), b.seq_index, b.next_home.code(), n_boxes]);
    w.extend([b.lane_move.map_or(0xFF, |l| l.0), 0, 0, 0]);
    w.extend(&b.failover_order);
    for d in b.data {
        put_addr(w, d);
    }
    for k in &b.boxes {
        w.extend([k.index, 0]);
        put_addr(w, k.order);
        put_addr(w, k.recovery);
        w.extend(k.k_seq);
        w.extend(k.k_out);
    }
    Ok(())
}

/// `CtlDone` (10 §2.4): the lane's answer to a control op, sent to the control core. 16 bytes:
/// 0 = 0xA2, 1 = the op code, 2–3 = the reason u16 (0 = done), 4–7 = the account, 8–11 = the
/// detail u32, 12–15 = 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtlDone {
    /// The control op it answers, 0x20–0x26.
    pub op: u8,
    /// `None` = done; otherwise the reject, which changed no state.
    pub reason: Option<RejectReason>,
    pub account: AccountId,
    pub detail: u32,
}

impl CtlDone {
    pub fn encode(&self) -> Result<[u8; 16], WireError> {
        if !(CTL_OP_FIRST..=CTL_OP_LAST).contains(&self.op) {
            return Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE));
        }
        let mut b = [0u8; 16];
        b[0] = T_CTL_DONE;
        b[1] = self.op;
        b[2..4].copy_from_slice(&self.reason.map_or(0, RejectReason::code).to_le_bytes());
        b[4..8].copy_from_slice(&self.account.0.to_le_bytes());
        b[8..12].copy_from_slice(&self.detail.to_le_bytes());
        Ok(b)
    }

    pub fn decode(b: &[u8; 16]) -> Result<Self, WireError> {
        let le32 = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        if b[0] != T_CTL_DONE || !(CTL_OP_FIRST..=CTL_OP_LAST).contains(&b[1]) {
            return Err(WireError::bad_type(PROTO_D_UNKNOWN_TYPE));
        }
        if b[12..] != [0; 4] {
            return Err(WireError::bad_type(PROTO_D_RESERVED));
        }
        let reason = match u16::from_le_bytes([b[2], b[3]]) {
            0 => None,
            c => Some(RejectReason::from_code(c).ok_or_else(hdr)?),
        };
        Ok(Self {
            op: b[1],
            reason,
            account: AccountId(le32(4)),
            detail: le32(8),
        })
    }
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn left(&self) -> usize {
        self.b.len() - self.i
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let s = self
            .b
            .get(self.i..self.i.checked_add(n).ok_or_else(hdr)?)
            .ok_or_else(hdr)?;
        self.i += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?.try_into().map_err(|_| hdr())
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        self.arr().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        self.arr().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        self.arr().map(u64::from_le_bytes)
    }
    fn flag(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(hdr()),
        }
    }
    fn addr(&mut self) -> Result<SocketAddrV4, WireError> {
        let ip: [u8; 4] = self.arr()?;
        Ok(SocketAddrV4::new(Ipv4Addr::from(ip), self.u16()?))
    }
    fn zero(&mut self, n: usize) -> Result<(), WireError> {
        if self.take(n)?.iter().any(|&b| b != 0) {
            return Err(WireError::bad_type(PROTO_D_RESERVED));
        }
        Ok(())
    }
}

fn put_u16(w: &mut Vec<u8>, v: u16) {
    w.extend(v.to_le_bytes());
}
fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend(v.to_le_bytes());
}
fn put_u64(w: &mut Vec<u8>, v: u64) {
    w.extend(v.to_le_bytes());
}
fn put_addr(w: &mut Vec<u8>, a: SocketAddrV4) {
    w.extend(a.ip().octets());
    put_u16(w, a.port());
}
