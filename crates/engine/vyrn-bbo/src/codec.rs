//! Byte layouts of the BBO core's ring entries (05 §4.12, §4.15) and of the response records it
//! builds (01 §6.4). Every layout is little-endian and is the spec table byte for byte; ring
//! lines carry them as `u64` words, word `i` = bytes `8 i .. 8 i + 8`.
//!
//! | Entry | Writer → reader | Ring | Spec |
//! |---|---|---|---|
//! | `FwdEntry` + `FwdDep` lines | lane → BBO | `FwdRing` (`push_all`) | 05 §4.12 |
//! | `FillEvent` | BBO → lane | `FillRing` | 05 §4.12 |
//! | `StepEntry` + delta lines | BBO → stream and fill TX cores | `StepLog` (`push_all`) | 05 §4.15 |
//! | `TxEntry` + records | BBO → fill TX core | `TxRing` (`push_all`) | 05 §4.15, 01 §6.4 |
//! | `ControlCmd` | control role → BBO | `ControlRing` | 05 §4.1, §8.8 |
//!
//! Decoders never panic: unknown codes decode to `None`, reserved bytes are ignored.

use vyrn_cut::{Line32, Line64};
use vyrn_types::{Handle, LaneId, LaneSeq, Nanos, Qty, RejectReason, SessionId, StepId, Tick};

use crate::key::OrderFlags;

/// Fixed-size little-endian byte image with bounds-checked field access.
#[derive(Clone, Copy)]
struct Img<const N: usize>([u8; N]);

impl<const N: usize> Img<N> {
    const fn zero() -> Self {
        Self([0; N])
    }
    fn put<const K: usize>(&mut self, off: usize, b: [u8; K]) {
        if let Some(d) = off.checked_add(K).and_then(|end| self.0.get_mut(off..end)) {
            d.copy_from_slice(&b);
        }
    }
    fn get<const K: usize>(&self, off: usize) -> [u8; K] {
        let mut out = [0u8; K];
        if let Some(s) = off.checked_add(K).and_then(|end| self.0.get(off..end)) {
            out.copy_from_slice(s);
        }
        out
    }
    fn u8(&self, off: usize) -> u8 {
        u8::from_le_bytes(self.get(off))
    }
    fn u16(&self, off: usize) -> u16 {
        u16::from_le_bytes(self.get(off))
    }
    fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.get(off))
    }
    fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.get(off))
    }
}

fn img_from_words<const W: usize, const N: usize>(w: &[u64; W]) -> Img<N> {
    let mut img = Img::<N>::zero();
    for (i, x) in w.iter().enumerate() {
        if let Some(off) = i.checked_mul(8) {
            img.put(off, x.to_le_bytes());
        }
    }
    img
}

fn words_from_img<const W: usize, const N: usize>(img: &Img<N>) -> [u64; W] {
    core::array::from_fn(|i| i.checked_mul(8).map_or(0, |off| img.u64(off)))
}

/// One line as its 64 bytes (for golden vectors and other implementations).
pub fn line_bytes(line: &Line64) -> [u8; 64] {
    img_from_words::<8, 64>(line).0
}

/// A 32-byte line as its bytes.
pub fn line32_bytes(line: &Line32) -> [u8; 32] {
    img_from_words::<4, 32>(line).0
}

/// Message types of 01 §6.2 that the BBO core decodes.
pub const MSG_NEW: u8 = 0x01;
pub const MSG_REPLACE: u8 = 0x04;

// ---------------------------------------------------------------------------------------------
// FwdEntry, FwdDep

/// `FwdEntry` (05 §4.12): one forwarded op. Writer: its lane, which writes `lane_seq` last
/// (the ring's `push_all` publishes the entry and its dependency lines together).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwdEntry {
    pub lane_seq: LaneSeq,
    pub prio_ts: Nanos,
    /// Snapshot version the lane classified the op against (low 32 bits, wrapping).
    pub snap_ver: u32,
    /// Latest BBO step start, low 32 bits of PTP ns (05 §6.8): `rx_ts + FWD_DEADLINE_NS`.
    pub deadline: u32,
    /// The 16-byte message; byte 2 = message index, byte 3 = number of dependencies.
    pub msg: [u8; 16],
    /// Root slot and generation of the order.
    pub handle: Handle,
    /// Version slot the lane wrote for this op (= root for a `New`).
    pub vslot: u32,
    pub session: SessionId,
    /// First of the 1 (no dependencies) or 2 reserved `resp_seq`s (05 §8.10 rule 1).
    pub resp_seq: u32,
    pub pkt_seq: u32,
    pub acct_ix: u16,
    /// `lane_seq − applied` when the lane pushed (05 §3.3).
    pub applied_back: u16,
}

impl FwdEntry {
    pub fn encode(&self) -> Line64 {
        let mut b = Img::<64>::zero();
        b.put(0, self.lane_seq.0.to_le_bytes());
        b.put(8, self.prio_ts.0.to_le_bytes());
        b.put(16, self.snap_ver.to_le_bytes());
        b.put(20, self.deadline.to_le_bytes());
        b.put(24, self.msg);
        b.put(40, self.handle.0.to_le_bytes());
        b.put(44, self.vslot.to_le_bytes());
        b.put(48, self.session.0.to_le_bytes());
        b.put(52, self.resp_seq.to_le_bytes());
        b.put(56, self.pkt_seq.to_le_bytes());
        b.put(60, self.acct_ix.to_le_bytes());
        b.put(62, self.applied_back.to_le_bytes());
        words_from_img(&b)
    }
    pub fn decode(line: &Line64) -> Self {
        let b = img_from_words::<8, 64>(line);
        Self {
            lane_seq: LaneSeq(b.u64(0)),
            prio_ts: Nanos(b.u64(8)),
            snap_ver: b.u32(16),
            deadline: b.u32(20),
            msg: b.get(24),
            handle: Handle(b.u32(40)),
            vslot: b.u32(44),
            session: SessionId(b.u32(48)),
            resp_seq: b.u32(52),
            pkt_seq: b.u32(56),
            acct_ix: b.u16(60),
            applied_back: b.u16(62),
        }
    }
    fn m(&self, i: usize) -> u8 {
        self.msg.get(i).copied().unwrap_or(0)
    }
    fn m32(&self, off: usize) -> u32 {
        let mut x = [0u8; 4];
        if let Some(s) = off.checked_add(4).and_then(|e| self.msg.get(off..e)) {
            x.copy_from_slice(s);
        }
        u32::from_le_bytes(x)
    }
    pub fn msg_type(&self) -> u8 {
        self.m(0)
    }
    pub fn flags(&self) -> OrderFlags {
        OrderFlags(self.m(1))
    }
    pub fn index(&self) -> u8 {
        self.m(2)
    }
    pub fn n_dep(&self) -> u8 {
        self.m(3)
    }
    /// Limit tick: bytes 4–7 of a `New`, 8–11 of a `Replace`.
    pub fn tick(&self) -> Tick {
        Tick(if self.msg_type() == MSG_REPLACE {
            self.m32(8)
        } else {
            self.m32(4)
        })
    }
    /// Order total: bytes 8–11 of a `New`, 12–15 of a `Replace`.
    pub fn qty(&self) -> Qty {
        Qty(if self.msg_type() == MSG_REPLACE {
            self.m32(12)
        } else {
            self.m32(8)
        })
    }
    /// `client_tag` of a `New`; a `Replace` carries none (01 §6.2), so 0.
    pub fn client_tag(&self) -> u32 {
        if self.msg_type() == MSG_NEW {
            self.m32(12)
        } else {
            0
        }
    }
    /// Lines the entry occupies in the ring: itself plus `ceil(n_dep / 4)` dependency lines.
    pub fn lines(&self) -> usize {
        1usize.saturating_add(usize::from(self.n_dep()).div_ceil(4))
    }
    /// Its dependency floor (05 §3.3): `lane_seq` minus the largest dependency offset.
    pub fn floor(&self, deps: &[FwdDep]) -> LaneSeq {
        let back = deps.iter().map(|d| d.back).max().unwrap_or(0);
        LaneSeq(self.lane_seq.0.saturating_sub(u64::from(back)))
    }
}

/// Dependency kinds (05 §4.12).
pub const DEP_JOIN: u8 = 1;
pub const DEP_CANCEL: u8 = 2;

/// `FwdDep` (05 §4.12, 16 B, 4 per line, after their entry).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FwdDep {
    /// `lane_seq − dependency's LaneSeq`, 1..=9.
    pub back: u8,
    /// `DEP_JOIN` or `DEP_CANCEL`.
    pub kind: u8,
    pub flags: OrderFlags,
    /// Position 0–15 in its segment.
    pub pos: u8,
    pub tick: Tick,
    /// Total (Join) or 0 (Cancel).
    pub qty: Qty,
    /// Join: its new slot (written in pass 1). Cancel: the position slot it ends.
    pub slot: u32,
}

impl FwdDep {
    fn put(&self, b: &mut Img<64>, off: usize) {
        b.put(off, [self.back, self.kind, self.flags.0, self.pos]);
        b.put(off.saturating_add(4), self.tick.0.to_le_bytes());
        b.put(off.saturating_add(8), self.qty.0.to_le_bytes());
        b.put(off.saturating_add(12), self.slot.to_le_bytes());
    }
    fn get(b: &Img<64>, off: usize) -> Self {
        Self {
            back: b.u8(off),
            kind: b.u8(off.saturating_add(1)),
            flags: OrderFlags(b.u8(off.saturating_add(2))),
            pos: b.u8(off.saturating_add(3)),
            tick: Tick(b.u32(off.saturating_add(4))),
            qty: Qty(b.u32(off.saturating_add(8))),
            slot: b.u32(off.saturating_add(12)),
        }
    }
    /// Packs up to 4 dependencies into one line, in index order.
    pub fn encode_line(deps: &[FwdDep]) -> Line64 {
        let mut b = Img::<64>::zero();
        for (i, d) in deps.iter().take(4).enumerate() {
            d.put(&mut b, i.saturating_mul(16));
        }
        words_from_img(&b)
    }
    /// The 4 dependency slots of one line; the caller takes the first `n`.
    pub fn decode_line(line: &Line64) -> [FwdDep; 4] {
        let b = img_from_words::<8, 64>(line);
        core::array::from_fn(|i| Self::get(&b, i.saturating_mul(16)))
    }
}

/// Encodes an entry and its dependency lines for one `push_all` (lane side of 05 §6.6).
/// Returns the number of lines written into `out` (≤ 4), or 0 if `deps.len() > 12`.
pub fn encode_fwd(e: &FwdEntry, deps: &[FwdDep], out: &mut [Line64; 4]) -> usize {
    if deps.len() > 12 {
        return 0;
    }
    let mut e = *e;
    if let Some(n) = e.msg.get_mut(3) {
        *n = u8::try_from(deps.len()).unwrap_or(0);
    }
    let mut n = 0usize;
    for (slot, line) in out
        .iter_mut()
        .zip(core::iter::once(e.encode()).chain(deps.chunks(4).map(FwdDep::encode_line)))
    {
        *slot = line;
        n = n.saturating_add(1);
    }
    n
}

// ---------------------------------------------------------------------------------------------
// FillEvent

/// `FillEvent.kind` (05 §16.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FillKind {
    Fill = 1,
    Rested = 2,
    Out = 3,
    Reject = 4,
    Phase = 5,
    Band = 6,
    Uncross = 7,
    Dep = 8,
}

impl FillKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Fill => 1,
            Self::Rested => 2,
            Self::Out => 3,
            Self::Reject => 4,
            Self::Phase => 5,
            Self::Band => 6,
            Self::Uncross => 7,
            Self::Dep => 8,
        }
    }
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Fill,
            2 => Self::Rested,
            3 => Self::Out,
            4 => Self::Reject,
            5 => Self::Phase,
            6 => Self::Band,
            7 => Self::Uncross,
            8 => Self::Dep,
            _ => return None,
        })
    }
}

/// `Fill.liq` (01 §6.4, §14.10).
pub const LIQ_MAKER: u8 = 0;
pub const LIQ_TAKER: u8 = 1;
pub const LIQ_AUCTION: u8 = 2;

/// `Out` causes (01 §14.10).
pub const OUT_IOC_REST: u16 = 1;
pub const OUT_STP: u16 = 2;
pub const OUT_AUCTION: u16 = 3;
/// `Out` event cause 0 (this crate, not a wire cause): a `Replace` with `qty' ≤ filled` finished
/// the order; its record is a `CancelAck` (05 §2.3).
pub const OUT_FINISHED: u16 = 0;
/// `Dep` event cause for a Join dependency that is a `Replace` with `qty' ≤ filled`: the order is
/// finished, `qty` = canceled open (05 §2.3). Other `Dep` causes are 0 or a reject reason.
pub const DEP_ENDED: u16 = 0x8000;

/// `FillEvent` (05 §4.12, 32 B). Writer: the BBO core, `step` last. Reader: the lane at B1.
///
/// Field use by kind (this crate's reading of 05 §4.12, §7.4, §8.8):
///
/// | kind | handle / vslot | tick | qty | liq | cause |
/// |---|---|---|---|---|---|
/// | Fill | root+gen / version that traded | fill price | qty | 0, 1, 2 | 0 |
/// | Rested | source | limit | open | 0 | 0 |
/// | Out | order | limit | qty out | 0 | Out cause |
/// | Reject | source | limit | open released | 0 | reject reason |
/// | Dep | dependency's root+gen / `FwdDep.slot` | its tick | Join: open; Cancel: canceled open (0 = `TOO_LATE`) | `FwdDep.kind` | 0 (rested / canceled), `DEP_ENDED`, or a reject reason (`BUSY`, `BOOK_HALTED`, `AUCTION_PHASE`, `TOO_LATE`) |
/// | Phase | `C*[l]` as `handle | vslot << 32` (Frozen only) | 0 | 0 | 0 | phase code |
/// | Band | 0 | lo | hi | 0 | 0 |
/// | Uncross | `C*[l]` as above | p* | 0 | 0 | 0 |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FillEvent {
    pub step: StepId,
    pub handle: Handle,
    pub vslot: u32,
    pub tick: Tick,
    pub qty: u32,
    pub kind: u8,
    pub liq: u8,
    pub cause: u16,
    pub ordinal: u32,
}

impl FillEvent {
    pub fn encode(&self) -> Line32 {
        let mut b = Img::<32>::zero();
        b.put(0, self.step.0.to_le_bytes());
        b.put(8, self.handle.0.to_le_bytes());
        b.put(12, self.vslot.to_le_bytes());
        b.put(16, self.tick.0.to_le_bytes());
        b.put(20, self.qty.to_le_bytes());
        b.put(24, [self.kind, self.liq]);
        b.put(26, self.cause.to_le_bytes());
        b.put(28, self.ordinal.to_le_bytes());
        words_from_img(&b)
    }
    pub fn decode(line: &Line32) -> Self {
        let b = img_from_words::<4, 32>(line);
        Self {
            step: StepId(b.u64(0)),
            handle: Handle(b.u32(8)),
            vslot: b.u32(12),
            tick: Tick(b.u32(16)),
            qty: b.u32(20),
            kind: b.u8(24),
            liq: b.u8(25),
            cause: b.u16(26),
            ordinal: b.u32(28),
        }
    }
    pub fn fill_kind(&self) -> Option<FillKind> {
        FillKind::from_code(self.kind)
    }
    /// The `LaneSeq` carried in `handle | vslot << 32` by `Phase(Frozen)` and `Uncross`.
    pub fn carried_seq(&self) -> LaneSeq {
        LaneSeq(u64::from(self.handle.0) | (u64::from(self.vslot) << 32))
    }
}

// ---------------------------------------------------------------------------------------------
// StepEntry

/// `StepEntry.flags` bit 0: this step is a continuation (05 §4.15).
pub const STEP_CONT: u8 = 1;

/// `StepEntry` header (05 §4.15). Writer: the BBO core. Readers: stream cores A and B, fill TX
/// cores. The changed cut entries follow as `ceil(n_delta / 4)` delta lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StepEntry {
    pub step: StepId,
    pub kind: u8,
    pub src_lane: LaneId,
    pub n_delta: u8,
    pub n_tx: u8,
    pub n_fills: u32,
    /// 0 = no source.
    pub src_lane_seq: LaneSeq,
    pub pub_a: u32,
    pub pub_b: u32,
    pub band_lo: Tick,
    pub band_hi: Tick,
    /// Bit `l`: lane `l` received fill events in this step.
    pub fill_lanes: u64,
    pub flags: u8,
}

/// One changed cut entry of a `StepEntry` (16 B, 4 per line).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CutDelta {
    pub lane: LaneId,
    pub seq: LaneSeq,
}

impl StepEntry {
    pub fn encode(&self) -> Line64 {
        let mut b = Img::<64>::zero();
        b.put(0, self.step.0.to_le_bytes());
        b.put(8, [self.kind, self.src_lane.0, self.n_delta, self.n_tx]);
        b.put(12, self.n_fills.to_le_bytes());
        b.put(16, self.src_lane_seq.0.to_le_bytes());
        b.put(24, self.pub_a.to_le_bytes());
        b.put(28, self.pub_b.to_le_bytes());
        b.put(32, self.band_lo.0.to_le_bytes());
        b.put(36, self.band_hi.0.to_le_bytes());
        b.put(40, self.fill_lanes.to_le_bytes());
        b.put(48, [self.flags]);
        words_from_img(&b)
    }
    pub fn decode(line: &Line64) -> Self {
        let b = img_from_words::<8, 64>(line);
        Self {
            step: StepId(b.u64(0)),
            kind: b.u8(8),
            src_lane: LaneId(b.u8(9)),
            n_delta: b.u8(10),
            n_tx: b.u8(11),
            n_fills: b.u32(12),
            src_lane_seq: LaneSeq(b.u64(16)),
            pub_a: b.u32(24),
            pub_b: b.u32(28),
            band_lo: Tick(b.u32(32)),
            band_hi: Tick(b.u32(36)),
            fill_lanes: b.u64(40),
            flags: b.u8(48),
        }
    }
}

impl CutDelta {
    pub fn encode_line(ds: &[CutDelta]) -> Line64 {
        let mut b = Img::<64>::zero();
        for (i, d) in ds.iter().take(4).enumerate() {
            let off = i.saturating_mul(16);
            b.put(off, [d.lane.0]);
            b.put(off.saturating_add(8), d.seq.0.to_le_bytes());
        }
        words_from_img(&b)
    }
    pub fn decode_line(line: &Line64) -> [CutDelta; 4] {
        let b = img_from_words::<8, 64>(line);
        core::array::from_fn(|i| {
            let off = i.saturating_mul(16);
            CutDelta {
                lane: LaneId(b.u8(off)),
                seq: LaneSeq(b.u64(off.saturating_add(8))),
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Response records and TxEntry

/// `Record.index` of an unsolicited maker record (01 §6.4).
pub const INDEX_MAKER: u8 = 0xFF;

/// A 16-byte response record (01 §6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    Ack {
        index: u8,
        handle: Handle,
        tick: Tick,
        client_tag: u32,
    },
    Fill {
        index: u8,
        liq: u8,
        handle: Handle,
        tick: Tick,
        qty: Qty,
    },
    Reject {
        index: u8,
        reason: RejectReason,
        detail: u32,
        client_tag: u32,
    },
    CancelAck {
        index: u8,
        handle: Handle,
        canceled: Qty,
        client_tag: u32,
    },
    Out {
        index: u8,
        cause: u16,
        handle: Handle,
        qty: Qty,
        client_tag: u32,
    },
}

impl Default for Record {
    fn default() -> Self {
        Self::Ack {
            index: 0,
            handle: Handle(0),
            tick: Tick(0),
            client_tag: 0,
        }
    }
}

impl Record {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = Img::<16>::zero();
        match *self {
            Self::Ack {
                index,
                handle,
                tick,
                client_tag,
            } => {
                b.put(0, [0x81, index]);
                b.put(4, handle.0.to_le_bytes());
                b.put(8, tick.0.to_le_bytes());
                b.put(12, client_tag.to_le_bytes());
            }
            Self::Fill {
                index,
                liq,
                handle,
                tick,
                qty,
            } => {
                b.put(0, [0x82, index, liq]);
                b.put(4, handle.0.to_le_bytes());
                b.put(8, tick.0.to_le_bytes());
                b.put(12, qty.0.to_le_bytes());
            }
            Self::Reject {
                index,
                reason,
                detail,
                client_tag,
            } => {
                b.put(0, [0x83, index]);
                b.put(2, reason.code().to_le_bytes());
                b.put(4, detail.to_le_bytes());
                b.put(12, client_tag.to_le_bytes());
            }
            Self::CancelAck {
                index,
                handle,
                canceled,
                client_tag,
            } => {
                b.put(0, [0x84, index]);
                b.put(4, handle.0.to_le_bytes());
                b.put(8, canceled.0.to_le_bytes());
                b.put(12, client_tag.to_le_bytes());
            }
            Self::Out {
                index,
                cause,
                handle,
                qty,
                client_tag,
            } => {
                b.put(0, [0x85, index]);
                b.put(2, cause.to_le_bytes());
                b.put(4, handle.0.to_le_bytes());
                b.put(8, qty.0.to_le_bytes());
                b.put(12, client_tag.to_le_bytes());
            }
        }
        b.0
    }
    pub fn decode(bytes: &[u8; 16]) -> Option<Self> {
        let b = Img(*bytes);
        let index = b.u8(1);
        let handle = Handle(b.u32(4));
        Some(match b.u8(0) {
            0x81 => Self::Ack {
                index,
                handle,
                tick: Tick(b.u32(8)),
                client_tag: b.u32(12),
            },
            0x82 => Self::Fill {
                index,
                liq: b.u8(2),
                handle,
                tick: Tick(b.u32(8)),
                qty: Qty(b.u32(12)),
            },
            0x83 => Self::Reject {
                index,
                reason: RejectReason::from_code(b.u16(2))?,
                detail: b.u32(4),
                client_tag: b.u32(12),
            },
            0x84 => Self::CancelAck {
                index,
                handle,
                canceled: Qty(b.u32(8)),
                client_tag: b.u32(12),
            },
            0x85 => Self::Out {
                index,
                cause: b.u16(2),
                handle,
                qty: Qty(b.u32(8)),
                client_tag: b.u32(12),
            },
            _ => return None,
        })
    }
}

/// `TxEntry.role` (05 §4.15).
pub const ROLE_TAKER: u8 = 0;
pub const ROLE_DEPS: u8 = 1;
pub const ROLE_MAKER: u8 = 2;

/// Records per response packet (01 §6.3).
pub const MAX_RECORDS: usize = 16;

/// `TxEntry` header (05 §4.15). Writer: the BBO core. Reader: the fill TX core of the session's
/// lane half. `n_rec` records follow, 4 per line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxEntry {
    pub step: StepId,
    pub session: SessionId,
    /// 0 = take the session's next `MakerSeq` number (05 §8.10 rule 2).
    pub resp_seq: u32,
    /// `echo_pkt`; 0 = unsolicited.
    pub pkt_seq: u32,
    pub lane: LaneId,
    pub n_rec: u8,
    pub role: u8,
}

impl TxEntry {
    pub fn encode(&self) -> Line64 {
        let mut b = Img::<64>::zero();
        b.put(0, self.step.0.to_le_bytes());
        b.put(8, self.session.0.to_le_bytes());
        b.put(12, self.resp_seq.to_le_bytes());
        b.put(16, self.pkt_seq.to_le_bytes());
        b.put(20, [self.lane.0, self.n_rec, self.role]);
        words_from_img(&b)
    }
    pub fn decode(line: &Line64) -> Self {
        let b = img_from_words::<8, 64>(line);
        Self {
            step: StepId(b.u64(0)),
            session: SessionId(b.u32(8)),
            resp_seq: b.u32(12),
            pkt_seq: b.u32(16),
            lane: LaneId(b.u8(20)),
            n_rec: b.u8(21),
            role: b.u8(22),
        }
    }
}

/// Packs up to 4 records into one line.
pub fn encode_records(recs: &[Record]) -> Line64 {
    let mut b = Img::<64>::zero();
    for (i, r) in recs.iter().take(4).enumerate() {
        b.put(i.saturating_mul(16), r.encode());
    }
    words_from_img(&b)
}

/// The 4 record slots of one line (`None` for an unused or unknown slot).
pub fn decode_records(line: &Line64) -> [Option<Record>; 4] {
    let b = img_from_words::<8, 64>(line);
    core::array::from_fn(|i| Record::decode(&b.get(i.saturating_mul(16))))
}

// ---------------------------------------------------------------------------------------------
// Control commands

/// Book phase (05 §2.1, `SnapshotLine.phase` codes of §4.14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    Continuous,
    Auction,
    Halted,
    Frozen,
}

impl Phase {
    pub const fn code(self) -> u8 {
        match self {
            Self::Continuous => 0,
            Self::Auction => 1,
            Self::Halted => 2,
            Self::Frozen => 3,
        }
    }
    pub const fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Self::Continuous,
            1 => Self::Auction,
            2 => Self::Halted,
            3 => Self::Frozen,
            _ => return None,
        })
    }
}

/// A command on the control ring (05 §4.1, §8.8, §13). Writer: the control role on core 0.
/// Reader: the BBO core, which executes at most one per loop pass, before ring heads (§8.4).
///
/// Line layout: byte 0 = op (1 Phase, 2 Band, 3 Uncross, 4 Seal); Phase: byte 8 = phase code,
/// bytes 12–15 auction collar lo, 16–19 hi (used by `Frozen`); Band: bytes 12–15 lo, 16–19 hi;
/// Uncross: bytes 12–15 p*, bytes 24–31 Q.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlCmd {
    Phase { phase: Phase, lo: Tick, hi: Tick },
    Band { lo: Tick, hi: Tick },
    Uncross { price: Tick, qty: u64 },
    Seal,
}

impl ControlCmd {
    pub fn encode(&self) -> Line64 {
        let mut b = Img::<64>::zero();
        match *self {
            Self::Phase { phase, lo, hi } => {
                b.put(0, [1]);
                b.put(8, [phase.code()]);
                b.put(12, lo.0.to_le_bytes());
                b.put(16, hi.0.to_le_bytes());
            }
            Self::Band { lo, hi } => {
                b.put(0, [2]);
                b.put(12, lo.0.to_le_bytes());
                b.put(16, hi.0.to_le_bytes());
            }
            Self::Uncross { price, qty } => {
                b.put(0, [3]);
                b.put(12, price.0.to_le_bytes());
                b.put(24, qty.to_le_bytes());
            }
            Self::Seal => b.put(0, [4]),
        }
        words_from_img(&b)
    }
    pub fn decode(line: &Line64) -> Option<Self> {
        let b = img_from_words::<8, 64>(line);
        let (lo, hi) = (Tick(b.u32(12)), Tick(b.u32(16)));
        Some(match b.u8(0) {
            1 => Self::Phase {
                phase: Phase::from_code(b.u8(8))?,
                lo,
                hi,
            },
            2 => Self::Band { lo, hi },
            3 => Self::Uncross {
                price: lo,
                qty: b.u64(24),
            },
            4 => Self::Seal,
            _ => return None,
        })
    }
}
