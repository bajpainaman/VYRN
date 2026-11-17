//! Sections of the order stream and their delta encoding (07 §3.4–§3.9).
//!
//! The encoding is a delta against state that the encoder and decoder both hold
//! ([`SubstreamState`], 07 §3.5). Both directions run the same state transitions, so a decoder
//! that accepts a body and an encoder started from the same state produce the same bytes again
//! (the canonical-encoding property this crate's tests check). All multi-byte fixed-width
//! integers are little-endian. "LEB" is canonical LEB128 and "ZZ" is LEB128 of ZigZag
//! ([`crate::leb`]).
//!
//! # Sections
//!
//! Every section starts with one tag byte and never straddles a frame.
//!
//! | Tag | Section | Allowed in |
//! |---|---|---|
//! | `0x00–0x3F` | `LaneRun` for lane = tag: `k` LEB (≥ 1), then `k` lane records | ORDER |
//! | `0x40` | `StepRun`: `m` LEB (≥ 1), then `m` step half-records | ORDER |
//! | `0x41` | `HashRun`: `lane` u8, `k` LEB (≥ 1), then `k` × `pkt_hash` u64 | HASH |
//! | `0x42` | `BlockMark` | ORDER |
//! | `0x43` | `SessionBind`: `lane` u8, `slot` LEB (< 4096), `session` u32, `next_pkt_seq` LEB | ORDER |
//! | `0x44` | `TenureStart`, only as the first section of frame 1 | ORDER |
//! | `0x45–0xFE` | reserved: `RepErr::Tag` | — |
//! | `0xFF` | `Pad`: every remaining byte of the body, each `00` | ORDER, HASH |
//!
//! A lane tag, a `HashRun` lane and a `SessionBind` lane must be a lane of this substream's half
//! (`RepErr::Half`).
//!
//! # Lane record (07 §3.6)
//!
//! ```text
//! h        u8   bits 0–3 count (≤ 10), bit 4 SEQ_EXC, bit 5 LSEQ_EXC, bit 6 FA_NZ, bit 7 SHED
//! slot     LEB  < 4096 a session slot; 4096 an Advance record; 4097 an AcctTake
//! — AcctTake (pooled lanes only, h = 0): account LEB (u32), ver LEB (u32); nothing else —
//! rx_ts    ZZ   rx_ts − prev_rx_ts
//! [FA_NZ]  LEB  fills_applied − prev_fills_applied      (≥ 1)
//! [LSEQ]   LEB  first_lane_seq − next_lane_seq          (≥ 1)
//! [SEQ]    LEB  pkt_seq (u32), ≠ the slot's next_pkt_seq; never in an Advance record
//! ```
//!
//! A flag is set exactly when its field differs from the prediction, so a flag with a zero
//! delta, or `SEQ_EXC` with the predicted `pkt_seq`, is `RepErr::Canon`. An Advance record has
//! `count = 0` and only `FA_NZ` may be set (`RepErr::Count`). A record on a slot that no
//! `SessionBind` bound is `RepErr::Range`. `AcctTake.lane_seq` is not on the wire: it is the
//! lane's `next_lane_seq` at the take, the LaneSeq of the first op that may use the token.
//!
//! # Step half-record (07 §3.8)
//!
//! ```text
//! byte 0   bits 0–3 wire kind: 0 Cross, 1 Improve, 2 Depletion, 3 Rescan, 4 Idle, 5 Shed,
//!                   6 Control, 7 Seal, 8 Uncross (9–15: RepErr::Kind)
//!          bit 4 HOME, bits 5–6 mode (0 SAME, 1 DENSE, 2 SPARSE, 3: RepErr::Cut), bit 7 OTHER
//! gap      LEB  step − prev_step − 1
//! [HOME]   src_lane u8 (0xFF = none); [src ≠ 0xFF] ZZ (src_lane_seq − cut[src_lane]), where
//!          cut is this record's new half-cut; [Rescan, Control, Seal, Uncross] plen LEB, bytes
//! [DENSE]  |H| × LEB (cut[l] − prev_cut[l])
//! [SPARSE] bitmap ceil(|H|/8) bytes (bit i of byte i/8, LSB first = lane H.start + 8·(i/8) + i%8),
//!          then LEB (cut[l] − prev_cut[l]) ≥ 1 for each set bit, in lane order
//! ```
//!
//! The wire kind numbering is 07's, not `StepKind::code()` (05 §8.1). The mode is SAME when the
//! half-cut did not move, else SPARSE when it is strictly shorter than DENSE, else DENSE; any
//! other choice is `RepErr::Cut`, as are unused bitmap bits that are set. Cross, Improve and
//! Shed have a source lane in this half; the other kinds have `0xFF`, and their home is
//! substream A (`RepErr::Kind`, `RepErr::Cut`). A cut-only record (HOME = 0) has OTHER = 1 and a
//! mode other than SAME. Steps on a substream increase and are above the last `BlockMark`'s
//! `last_step` (`RepErr::Mark`).
//!
//! # BlockMark and TenureStart (07 §3.9)
//!
//! ```text
//! BlockMark   height LEB (absolute; the next height), last_step LEB (delta from the previous
//!             mark's last_step), bitmap ceil(|H|/8), then LEB delta ≥ 1 per set bit of
//!             lane_bounds[l] = next_lane_seq[l] − 1 at the mark
//! TenureStart epoch u32, tenure u8, sender u8, first_step u64 (≥ 1), first_height u64,
//!             prev_header_hash [32], then per lane of the half: next_lane_seq LEB (≥ 1),
//!             rx_ts_base u64, fills_applied_base LEB; then prev_cut |H| × LEB (absolute)
//! ```
//!
//! TenureStart sets every base: the lanes', `prev_step = first_step − 1`, `prev_cut`, the
//! previous mark (`last_step = first_step − 1`, `lane_bounds = next_lane_seq − 1`) and the next
//! height. Session slots are epoch-scoped and survive it. A mark whose height, step or bounds
//! disagree with the decoded state is `RepErr::Mark`.
//!
//! # Block order bytes (07 §6.1)
//!
//! Block `h`'s order bytes on a substream are the bytes of every ORDER section after
//! `BlockMark(h − 1)` through `BlockMark(h)`, tags included, except `TenureStart` and `Pad`.
//! [`SubstreamState::take_closed`] returns them per block, with the block's packets in O-order.

use std::collections::{BTreeMap, VecDeque};

use vyrn_types::{
    AccountId, AcctTake, Epoch, Hash, Height, LaneId, LaneSeq, MAX_MSGS_PER_PKT,
    MAX_SESSIONS_PER_LANE, Nanos, PacketFlags, PacketRecord, PktHash, SessionId, StepId, StepKind,
};

use crate::leb::{self, Reader};
use crate::{Layout, RepErr};

/// The slot value of an Advance record (`MAX_SESSIONS_PER_LANE`).
pub const REP_SLOT_ADVANCE: u16 = 4096;
/// The slot value of an `AcctTake` (`MAX_SESSIONS_PER_LANE + 1`).
pub const REP_SLOT_TAKE: u16 = 4097;
const _: () = assert!(REP_SLOT_ADVANCE as usize == MAX_SESSIONS_PER_LANE);

/// Section tags (07 §3.4).
pub mod tag {
    pub const LANE_RUN_MAX: u8 = 0x3F;
    pub const STEP_RUN: u8 = 0x40;
    pub const HASH_RUN: u8 = 0x41;
    pub const BLOCK_MARK: u8 = 0x42;
    pub const SESSION_BIND: u8 = 0x43;
    pub const TENURE_START: u8 = 0x44;
    pub const PAD: u8 = 0xFF;
}

const H_COUNT: u8 = 0x0F;
const H_SEQ_EXC: u8 = 0x10;
const H_LSEQ_EXC: u8 = 0x20;
const H_FA_NZ: u8 = 0x40;
const H_SHED: u8 = 0x80;

const S_HOME: u8 = 0x10;
const S_OTHER: u8 = 0x80;
const MODE_SAME: u8 = 0;
const MODE_DENSE: u8 = 1;
const MODE_SPARSE: u8 = 2;
const NO_SRC: u8 = 0xFF;

/// 07's 4-bit wire code of a step kind.
pub const fn wire_kind(k: StepKind) -> u8 {
    match k {
        StepKind::Cross => 0,
        StepKind::Improve => 1,
        StepKind::Depletion => 2,
        StepKind::Rescan => 3,
        StepKind::Idle => 4,
        StepKind::Shed => 5,
        StepKind::Control => 6,
        StepKind::Seal => 7,
        StepKind::Uncross => 8,
    }
}

/// The step kind of a 4-bit wire code, `None` for 9–15.
pub const fn kind_from_wire(code: u8) -> Option<StepKind> {
    Some(match code {
        0 => StepKind::Cross,
        1 => StepKind::Improve,
        2 => StepKind::Depletion,
        3 => StepKind::Rescan,
        4 => StepKind::Idle,
        5 => StepKind::Shed,
        6 => StepKind::Control,
        7 => StepKind::Seal,
        8 => StepKind::Uncross,
        _ => return None,
    })
}

/// Kinds whose home record names a source op (07 §3.8 kind table).
pub const fn has_src(k: StepKind) -> bool {
    matches!(k, StepKind::Cross | StepKind::Improve | StepKind::Shed)
}

/// Kinds whose home record carries `plen` and a payload.
pub const fn has_payload(k: StepKind) -> bool {
    matches!(
        k,
        StepKind::Rescan | StepKind::Control | StepKind::Seal | StepKind::Uncross
    )
}

/// One record of a `LaneRun`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneRec {
    /// A packet or an Advance record. `pkt_hash` is 0 here; the `HashRun` supplies it.
    Pkt(PacketRecord),
    Take(AcctTake),
}

/// The home part of a step half-record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Home {
    /// `LaneId(0xFF)` when the kind has no source.
    pub src_lane: LaneId,
    /// 0 when the kind has no source.
    pub src_lane_seq: LaneSeq,
    /// Empty unless the kind carries a payload (05 owns its bytes).
    pub payload: Vec<u8>,
}

/// One substream's record of a step: its home record or a cut-only record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepHalf {
    pub step: StepId,
    pub kind: StepKind,
    /// The other substream carries a record of this step too.
    pub other: bool,
    /// `Some` for the home record, `None` for a cut-only record.
    pub home: Option<Home>,
    /// This half's cut after the step, absolute, one entry per lane of the half.
    pub cut: Vec<LaneSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockMark {
    pub height: Height,
    pub last_step: StepId,
    /// Per lane of the half: the last LaneSeq whose record precedes the mark.
    pub lane_bounds: Vec<LaneSeq>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionBind {
    pub lane: LaneId,
    pub slot: u16,
    pub session: SessionId,
    pub next_pkt_seq: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneBase {
    pub next_lane_seq: LaneSeq,
    pub rx_ts: Nanos,
    pub fills_applied: StepId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenureStart {
    pub epoch: Epoch,
    pub tenure: u8,
    pub sender: u8,
    pub first_step: StepId,
    pub first_height: Height,
    pub prev_header_hash: Hash,
    /// One per lane of the half.
    pub lanes: Vec<LaneBase>,
    /// One per lane of the half.
    pub prev_cut: Vec<LaneSeq>,
}

/// A decoded section. `TenureStart` is not here: it is only valid at the head of frame 1
/// ([`crate::frame::Body::Order`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Section {
    LaneRun {
        lane: LaneId,
        recs: Vec<LaneRec>,
    },
    StepRun(Vec<StepHalf>),
    /// Each entry pairs the `first_lane_seq` of the awaiting record with its hash.
    HashRun {
        lane: LaneId,
        entries: Vec<(LaneSeq, PktHash)>,
    },
    BlockMark(BlockMark),
    SessionBind(SessionBind),
    /// The number of `00` bytes after the tag.
    Pad(usize),
}

/// The frame kind a body belongs to; it decides which tags are allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyKind {
    Order,
    Hash,
}

/// One substream's share of a closed block (07 §6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HalfBlock {
    pub stream: u8,
    pub height: Height,
    pub last_step: StepId,
    /// The block's ORDER section bytes on this substream, through its `BlockMark`.
    pub order_bytes: Vec<u8>,
    /// Its PacketRecords other than Advance records, in O-order; `data_root` covers them.
    pub packets: Vec<PacketRecord>,
}

#[derive(Clone, Debug)]
struct SlotTable {
    session: Vec<Option<SessionId>>,
    next: Vec<u32>,
    slot_of: BTreeMap<SessionId, u16>,
}

impl SlotTable {
    fn new() -> Self {
        Self {
            session: vec![None; MAX_SESSIONS_PER_LANE],
            next: vec![0; MAX_SESSIONS_PER_LANE],
            slot_of: BTreeMap::new(),
        }
    }

    /// Binds one-to-one: the slot's old session and the session's old slot are unbound.
    fn bind(&mut self, slot: u16, session: SessionId, next: u32) -> Result<(), RepErr> {
        let s = usize::from(slot);
        let old = self.session.get_mut(s).ok_or(RepErr::Range)?.take();
        if let Some(old) = old {
            self.slot_of.remove(&old);
        }
        if let Some(prev_slot) = self.slot_of.insert(session, slot)
            && let Some(e) = self.session.get_mut(usize::from(prev_slot))
        {
            *e = None;
        }
        *self.session.get_mut(s).ok_or(RepErr::Range)? = Some(session);
        *self.next.get_mut(s).ok_or(RepErr::Range)? = next;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LaneDec {
    next_lane_seq: u64,
    prev_rx_ts: u64,
    prev_fa: u64,
    awaiting: VecDeque<u64>,
    table: usize,
}

/// The encoder and decoder state of one substream (07 §3.5): every `LaneDec` of its half, its
/// `StepDec`, the session slots, the last `BlockMark`, and the current block's bytes.
#[derive(Clone, Debug)]
pub struct SubstreamState {
    layout: Layout,
    stream: u8,
    first_lane: u8,
    lanes: Vec<LaneDec>,
    tables: Vec<SlotTable>,
    started: bool,
    prev_step: u64,
    prev_cut: Vec<u64>,
    mark_step: u64,
    mark_bounds: Vec<u64>,
    next_height: u64,
    block_bytes: Vec<u8>,
    block_pkts: Vec<PacketRecord>,
    closed: Vec<HalfBlock>,
}

impl SubstreamState {
    /// The state of substream `stream` before its first `TenureStart`.
    pub fn new(layout: Layout, stream: u8) -> Result<Self, RepErr> {
        if stream >= layout.streams() {
            return Err(RepErr::Layout);
        }
        let half = layout.half(stream);
        let mut tables = Vec::new();
        let mut pool_table = None;
        let mut lanes = Vec::new();
        for l in half.clone() {
            let table = if layout.is_pool(l) {
                *pool_table.get_or_insert_with(|| {
                    tables.push(SlotTable::new());
                    tables.len().saturating_sub(1)
                })
            } else {
                tables.push(SlotTable::new());
                tables.len().saturating_sub(1)
            };
            lanes.push(LaneDec {
                next_lane_seq: 1,
                prev_rx_ts: 0,
                prev_fa: 0,
                awaiting: VecDeque::new(),
                table,
            });
        }
        let n = lanes.len();
        Ok(Self {
            layout,
            stream,
            first_lane: half.start,
            lanes,
            tables,
            started: false,
            prev_step: 0,
            prev_cut: vec![0; n],
            mark_step: 0,
            mark_bounds: vec![0; n],
            next_height: 0,
            block_bytes: Vec::new(),
            block_pkts: Vec::new(),
            closed: Vec::new(),
        })
    }

    pub const fn layout(&self) -> &Layout {
        &self.layout
    }

    pub const fn stream(&self) -> u8 {
        self.stream
    }

    /// Lanes in this substream's half, `|H|`.
    pub fn half_len(&self) -> usize {
        self.lanes.len()
    }

    /// The height the next `BlockMark` must carry.
    pub const fn next_height(&self) -> Height {
        Height(self.next_height)
    }

    /// The last step this substream carried a record of.
    pub const fn prev_step(&self) -> StepId {
        StepId(self.prev_step)
    }

    /// This half's current cut, absolute.
    pub fn half_cut(&self) -> Vec<LaneSeq> {
        self.prev_cut.iter().map(|&c| LaneSeq(c)).collect()
    }

    /// The blocks whose `BlockMark` has passed since the last call, oldest first.
    pub fn take_closed(&mut self) -> Vec<HalfBlock> {
        core::mem::take(&mut self.closed)
    }

    fn lane_index(&self, lane: u8) -> Result<usize, RepErr> {
        if !self.layout.half(self.stream).contains(&lane) {
            return Err(RepErr::Half);
        }
        Ok(usize::from(lane.wrapping_sub(self.first_lane)))
    }

    fn bitmap_len(&self) -> usize {
        self.lanes.len().div_ceil(8)
    }

    // ---- TenureStart ----

    /// Sets every base from `ts` (07 §3.9). Validates its shape.
    pub fn apply_tenure_start(&mut self, ts: &TenureStart) -> Result<(), RepErr> {
        let n = self.lanes.len();
        if ts.lanes.len() != n || ts.prev_cut.len() != n {
            return Err(RepErr::Tenure);
        }
        if ts.first_step.0 == 0 || ts.lanes.iter().any(|b| b.next_lane_seq.0 == 0) {
            return Err(RepErr::Range);
        }
        for (d, b) in self.lanes.iter_mut().zip(&ts.lanes) {
            d.next_lane_seq = b.next_lane_seq.0;
            d.prev_rx_ts = b.rx_ts.0;
            d.prev_fa = b.fills_applied.0;
            d.awaiting.clear();
        }
        self.prev_step = ts.first_step.0.saturating_sub(1);
        self.prev_cut = ts.prev_cut.iter().map(|c| c.0).collect();
        self.mark_step = self.prev_step;
        self.mark_bounds = self
            .lanes
            .iter()
            .map(|d| d.next_lane_seq.saturating_sub(1))
            .collect();
        self.next_height = ts.first_height.0;
        self.block_bytes.clear();
        self.block_pkts.clear();
        self.started = true;
        Ok(())
    }

    /// Encodes `ts` as a section, tag included, and applies it.
    pub fn encode_tenure_start(&mut self, ts: &TenureStart) -> Result<Vec<u8>, RepErr> {
        self.apply_tenure_start(ts)?;
        let mut out = vec![tag::TENURE_START];
        out.extend_from_slice(&ts.epoch.0.to_le_bytes());
        out.push(ts.tenure);
        out.push(ts.sender);
        out.extend_from_slice(&ts.first_step.0.to_le_bytes());
        out.extend_from_slice(&ts.first_height.0.to_le_bytes());
        out.extend_from_slice(&ts.prev_header_hash.0);
        for b in &ts.lanes {
            leb::put_u64(&mut out, b.next_lane_seq.0);
            out.extend_from_slice(&b.rx_ts.0.to_le_bytes());
            leb::put_u64(&mut out, b.fills_applied.0);
        }
        for c in &ts.prev_cut {
            leb::put_u64(&mut out, c.0);
        }
        Ok(out)
    }

    /// Decodes a `TenureStart` section, tag included, from the front of `r` and applies it.
    pub fn decode_tenure_start(&mut self, r: &mut Reader<'_>) -> Result<TenureStart, RepErr> {
        if r.u8()? != tag::TENURE_START {
            return Err(RepErr::Tenure);
        }
        let epoch = Epoch(r.u32()?);
        let tenure = r.u8()?;
        let sender = r.u8()?;
        let first_step = StepId(r.u64()?);
        let first_height = Height(r.u64()?);
        let prev_header_hash = Hash(r.array()?);
        let n = self.lanes.len();
        let mut lanes = Vec::with_capacity(n);
        for _ in 0..n {
            lanes.push(LaneBase {
                next_lane_seq: LaneSeq(r.leb_u64()?),
                rx_ts: Nanos(r.u64()?),
                fills_applied: StepId(r.leb_u64()?),
            });
        }
        let mut prev_cut = Vec::with_capacity(n);
        for _ in 0..n {
            prev_cut.push(LaneSeq(r.leb_u64()?));
        }
        let ts = TenureStart {
            epoch,
            tenure,
            sender,
            first_step,
            first_height,
            prev_header_hash,
            lanes,
            prev_cut,
        };
        self.apply_tenure_start(&ts)?;
        Ok(ts)
    }

    // ---- section bodies ----

    /// Decodes a body of sections. The state advances as it goes; after an error it is
    /// undefined and the stream is faulty (07 §3.12).
    pub fn decode_sections(
        &mut self,
        bytes: &[u8],
        kind: BodyKind,
    ) -> Result<Vec<Section>, RepErr> {
        if !self.started {
            return Err(RepErr::Tenure);
        }
        let mut r = Reader::new(bytes);
        let mut out = Vec::new();
        while !r.is_empty() {
            let start = r.pos();
            let t = r.u8()?;
            let sec = match (t, kind) {
                (0..=tag::LANE_RUN_MAX, BodyKind::Order) => self.decode_lane_run(t, &mut r)?,
                (tag::STEP_RUN, BodyKind::Order) => self.decode_step_run(&mut r)?,
                (tag::HASH_RUN, BodyKind::Hash) => self.decode_hash_run(&mut r)?,
                (tag::BLOCK_MARK, BodyKind::Order) => self.decode_mark(&mut r)?,
                (tag::SESSION_BIND, BodyKind::Order) => self.decode_bind(&mut r)?,
                (tag::TENURE_START, _) => return Err(RepErr::Tenure),
                (tag::PAD, _) => {
                    let rest = r.bytes(r.rest().len())?;
                    if rest.iter().any(|&b| b != 0) {
                        return Err(RepErr::Tag);
                    }
                    Section::Pad(rest.len())
                }
                _ => return Err(RepErr::Tag),
            };
            self.account(&sec, r.since(start), kind);
            out.push(sec);
        }
        Ok(out)
    }

    /// Encodes `sections` as one body, advancing the state exactly as decoding it would.
    pub fn encode_sections(
        &mut self,
        sections: &[Section],
        kind: BodyKind,
    ) -> Result<Vec<u8>, RepErr> {
        if !self.started {
            return Err(RepErr::Tenure);
        }
        let mut out = Vec::new();
        for (i, sec) in sections.iter().enumerate() {
            let start = out.len();
            match (sec, kind) {
                (Section::LaneRun { lane, recs }, BodyKind::Order) => {
                    self.encode_lane_run(*lane, recs, &mut out)?;
                }
                (Section::StepRun(halves), BodyKind::Order) => {
                    self.encode_step_run(halves, &mut out)?;
                }
                (Section::HashRun { lane, entries }, BodyKind::Hash) => {
                    self.encode_hash_run(*lane, entries, &mut out)?;
                }
                (Section::BlockMark(m), BodyKind::Order) => self.encode_mark(m, &mut out)?,
                (Section::SessionBind(b), BodyKind::Order) => self.encode_bind(b, &mut out)?,
                (Section::Pad(n), _) if i.saturating_add(1) == sections.len() => {
                    out.push(tag::PAD);
                    out.resize(out.len().saturating_add(*n), 0);
                }
                _ => return Err(RepErr::Tag),
            }
            let span = out.get(start..).unwrap_or(&[]).to_vec();
            self.account(sec, &span, kind);
        }
        Ok(out)
    }

    /// Adds a section's bytes to the current block and closes it at a mark.
    fn account(&mut self, sec: &Section, span: &[u8], kind: BodyKind) {
        if kind != BodyKind::Order || matches!(sec, Section::Pad(_)) {
            return;
        }
        self.block_bytes.extend_from_slice(span);
        match sec {
            Section::LaneRun { recs, .. } => {
                for r in recs {
                    if let LaneRec::Pkt(p) = r
                        && p.flags & PacketFlags::ADVANCE == 0
                    {
                        self.block_pkts.push(*p);
                    }
                }
            }
            Section::BlockMark(m) => self.closed.push(HalfBlock {
                stream: self.stream,
                height: m.height,
                last_step: m.last_step,
                order_bytes: core::mem::take(&mut self.block_bytes),
                packets: core::mem::take(&mut self.block_pkts),
            }),
            _ => {}
        }
    }

    // ---- LaneRun ----

    fn decode_lane_run(&mut self, lane: u8, r: &mut Reader<'_>) -> Result<Section, RepErr> {
        let i = self.lane_index(lane)?;
        let k = r.leb_u64()?;
        if k == 0 {
            return Err(RepErr::Count);
        }
        let mut recs = Vec::new();
        for _ in 0..k {
            recs.push(self.decode_rec(lane, i, r)?);
        }
        Ok(Section::LaneRun {
            lane: LaneId(lane),
            recs,
        })
    }

    fn encode_lane_run(
        &mut self,
        lane: LaneId,
        recs: &[LaneRec],
        out: &mut Vec<u8>,
    ) -> Result<(), RepErr> {
        let i = self.lane_index(lane.0)?;
        if recs.is_empty() || lane.0 > tag::LANE_RUN_MAX {
            return Err(RepErr::Count);
        }
        out.push(lane.0);
        leb::put_u64(out, recs.len() as u64);
        for rec in recs {
            self.encode_rec(lane.0, i, rec, out)?;
        }
        Ok(())
    }

    fn table(&self, i: usize) -> Result<&SlotTable, RepErr> {
        let t = self.lanes.get(i).ok_or(RepErr::Half)?.table;
        self.tables.get(t).ok_or(RepErr::Half)
    }

    fn decode_rec(&mut self, lane: u8, i: usize, r: &mut Reader<'_>) -> Result<LaneRec, RepErr> {
        let h = r.u8()?;
        let count = h & H_COUNT;
        if count > MAX_MSGS_PER_PKT {
            return Err(RepErr::Count);
        }
        let slot = r.leb_u16()?;
        let d = self.lanes.get(i).ok_or(RepErr::Half)?;
        if slot == REP_SLOT_TAKE {
            if h != 0 || !self.layout.is_pool(lane) {
                return Err(RepErr::Count);
            }
            let account = AccountId(r.leb_u32()?);
            let ver = r.leb_u32()?;
            return Ok(LaneRec::Take(AcctTake {
                lane: LaneId(lane),
                account,
                ver,
                lane_seq: LaneSeq(d.next_lane_seq),
            }));
        }
        if slot > REP_SLOT_TAKE {
            return Err(RepErr::Range);
        }
        let advance = slot == REP_SLOT_ADVANCE;
        if advance && h & !H_FA_NZ != 0 {
            return Err(RepErr::Count);
        }
        let rx_ts = d
            .prev_rx_ts
            .checked_add_signed(r.leb_i64()?)
            .ok_or(RepErr::Ts)?;
        let fa = if h & H_FA_NZ != 0 {
            let delta = nonzero(r.leb_u64()?)?;
            d.prev_fa.checked_add(delta).ok_or(RepErr::Range)?
        } else {
            d.prev_fa
        };
        let first = if h & H_LSEQ_EXC != 0 {
            let delta = nonzero(r.leb_u64()?)?;
            d.next_lane_seq.checked_add(delta).ok_or(RepErr::Range)?
        } else {
            d.next_lane_seq
        };
        let mut rec = PacketRecord {
            lane: LaneId(lane),
            count,
            flags: if h & H_SHED != 0 {
                PacketFlags::SHED
            } else {
                0
            },
            session: SessionId(0),
            pkt_seq: 0,
            rx_ts: Nanos(rx_ts),
            pkt_hash: PktHash(0),
            first_lane_seq: LaneSeq(first),
            fills_applied: StepId(fa),
        };
        if advance {
            rec.flags = PacketFlags::ADVANCE;
        } else {
            let t = self.table(i)?;
            let s = usize::from(slot);
            let session = t.session.get(s).copied().flatten().ok_or(RepErr::Range)?;
            let expected = t.next.get(s).copied().ok_or(RepErr::Range)?;
            let pkt_seq = if h & H_SEQ_EXC != 0 {
                let v = r.leb_u32()?;
                if v == expected {
                    return Err(RepErr::Canon);
                }
                v
            } else {
                expected
            };
            rec.session = session;
            rec.pkt_seq = pkt_seq;
        }
        self.apply_pkt(i, slot, &rec)?;
        Ok(LaneRec::Pkt(rec))
    }

    fn encode_rec(
        &mut self,
        lane: u8,
        i: usize,
        rec: &LaneRec,
        out: &mut Vec<u8>,
    ) -> Result<(), RepErr> {
        let d = self.lanes.get(i).ok_or(RepErr::Half)?;
        let p = match rec {
            LaneRec::Take(t) => {
                if t.lane.0 != lane || !self.layout.is_pool(lane) {
                    return Err(RepErr::Count);
                }
                if t.lane_seq.0 != d.next_lane_seq {
                    return Err(RepErr::Range);
                }
                out.push(0);
                leb::put_u64(out, u64::from(REP_SLOT_TAKE));
                leb::put_u64(out, u64::from(t.account.0));
                leb::put_u64(out, u64::from(t.ver));
                return Ok(());
            }
            LaneRec::Pkt(p) => p,
        };
        let advance = p.flags & PacketFlags::ADVANCE != 0;
        if p.lane.0 != lane || p.pkt_hash.0 != 0 || p.count > MAX_MSGS_PER_PKT {
            return Err(RepErr::Count);
        }
        let mut h = p.count;
        let slot = if advance {
            if p.flags != PacketFlags::ADVANCE
                || p.count != 0
                || p.session.0 != 0
                || p.pkt_seq != 0
                || p.first_lane_seq.0 != d.next_lane_seq
            {
                return Err(RepErr::Count);
            }
            REP_SLOT_ADVANCE
        } else {
            if p.flags & !PacketFlags::SHED != 0 {
                return Err(RepErr::Count);
            }
            if p.flags != 0 {
                h |= H_SHED;
            }
            let t = self.table(i)?;
            let slot = *t.slot_of.get(&p.session).ok_or(RepErr::Range)?;
            if t.next.get(usize::from(slot)).copied() != Some(p.pkt_seq) {
                h |= H_SEQ_EXC;
            }
            if p.first_lane_seq.0 != d.next_lane_seq {
                h |= H_LSEQ_EXC;
            }
            slot
        };
        if p.fills_applied.0 != d.prev_fa {
            h |= H_FA_NZ;
        }
        let drx = i128::from(p.rx_ts.0).wrapping_sub(i128::from(d.prev_rx_ts));
        let drx = i64::try_from(drx).map_err(|_| RepErr::Ts)?;
        let dfa = p
            .fills_applied
            .0
            .checked_sub(d.prev_fa)
            .ok_or(RepErr::Range)?;
        let dls = p
            .first_lane_seq
            .0
            .checked_sub(d.next_lane_seq)
            .ok_or(RepErr::Range)?;
        out.push(h);
        leb::put_u64(out, u64::from(slot));
        leb::put_i64(out, drx);
        if h & H_FA_NZ != 0 {
            leb::put_u64(out, dfa);
        }
        if h & H_LSEQ_EXC != 0 {
            leb::put_u64(out, dls);
        }
        if h & H_SEQ_EXC != 0 {
            leb::put_u64(out, u64::from(p.pkt_seq));
        }
        self.apply_pkt(i, slot, p)
    }

    /// The state transition of one decoded or encoded PacketRecord.
    fn apply_pkt(&mut self, i: usize, slot: u16, p: &PacketRecord) -> Result<(), RepErr> {
        let next = p
            .first_lane_seq
            .0
            .checked_add(u64::from(p.count))
            .ok_or(RepErr::Range)?;
        let advance = p.flags & PacketFlags::ADVANCE != 0;
        let d = self.lanes.get(i).ok_or(RepErr::Half)?;
        if !advance {
            let after = p.pkt_seq.checked_add(1).ok_or(RepErr::Range)?;
            let t = self.tables.get_mut(d.table).ok_or(RepErr::Half)?;
            *t.next.get_mut(usize::from(slot)).ok_or(RepErr::Range)? = after;
        }
        let d = self.lanes.get_mut(i).ok_or(RepErr::Half)?;
        d.prev_rx_ts = p.rx_ts.0;
        d.prev_fa = p.fills_applied.0;
        d.next_lane_seq = next;
        if !advance {
            d.awaiting.push_back(p.first_lane_seq.0);
        }
        Ok(())
    }

    // ---- SessionBind ----

    fn decode_bind(&mut self, r: &mut Reader<'_>) -> Result<Section, RepErr> {
        let b = SessionBind {
            lane: LaneId(r.u8()?),
            slot: r.leb_u16()?,
            session: SessionId(r.u32()?),
            next_pkt_seq: r.leb_u32()?,
        };
        self.apply_bind(&b)?;
        Ok(Section::SessionBind(b))
    }

    fn encode_bind(&mut self, b: &SessionBind, out: &mut Vec<u8>) -> Result<(), RepErr> {
        self.apply_bind(b)?;
        out.push(tag::SESSION_BIND);
        out.push(b.lane.0);
        leb::put_u64(out, u64::from(b.slot));
        out.extend_from_slice(&b.session.0.to_le_bytes());
        leb::put_u64(out, u64::from(b.next_pkt_seq));
        Ok(())
    }

    fn apply_bind(&mut self, b: &SessionBind) -> Result<(), RepErr> {
        let i = self.lane_index(b.lane.0)?;
        if usize::from(b.slot) >= MAX_SESSIONS_PER_LANE {
            return Err(RepErr::Range);
        }
        let t = self.lanes.get(i).ok_or(RepErr::Half)?.table;
        self.tables
            .get_mut(t)
            .ok_or(RepErr::Half)?
            .bind(b.slot, b.session, b.next_pkt_seq)
    }

    // ---- HashRun ----

    fn decode_hash_run(&mut self, r: &mut Reader<'_>) -> Result<Section, RepErr> {
        let lane = r.u8()?;
        let i = self.lane_index(lane)?;
        let k = r.leb_u64()?;
        if k == 0 {
            return Err(RepErr::Count);
        }
        let mut entries = Vec::new();
        for _ in 0..k {
            let h = PktHash(r.u64()?);
            let d = self.lanes.get_mut(i).ok_or(RepErr::Half)?;
            let seq = d.awaiting.pop_front().ok_or(RepErr::Hash)?;
            entries.push((LaneSeq(seq), h));
        }
        Ok(Section::HashRun {
            lane: LaneId(lane),
            entries,
        })
    }

    fn encode_hash_run(
        &mut self,
        lane: LaneId,
        entries: &[(LaneSeq, PktHash)],
        out: &mut Vec<u8>,
    ) -> Result<(), RepErr> {
        let i = self.lane_index(lane.0)?;
        if entries.is_empty() {
            return Err(RepErr::Count);
        }
        out.push(tag::HASH_RUN);
        out.push(lane.0);
        leb::put_u64(out, entries.len() as u64);
        for (seq, h) in entries {
            let d = self.lanes.get_mut(i).ok_or(RepErr::Half)?;
            if d.awaiting.pop_front() != Some(seq.0) {
                return Err(RepErr::Hash);
            }
            out.extend_from_slice(&h.0.to_le_bytes());
        }
        Ok(())
    }

    // ---- StepRun ----

    fn decode_step_run(&mut self, r: &mut Reader<'_>) -> Result<Section, RepErr> {
        let m = r.leb_u64()?;
        if m == 0 {
            return Err(RepErr::Count);
        }
        let mut halves = Vec::new();
        for _ in 0..m {
            halves.push(self.decode_step(r)?);
        }
        Ok(Section::StepRun(halves))
    }

    fn encode_step_run(&mut self, halves: &[StepHalf], out: &mut Vec<u8>) -> Result<(), RepErr> {
        if halves.is_empty() {
            return Err(RepErr::Count);
        }
        out.push(tag::STEP_RUN);
        leb::put_u64(out, halves.len() as u64);
        for s in halves {
            self.encode_step(s, out)?;
        }
        Ok(())
    }

    /// Checks the kind, source and home rules of a half-record against this substream.
    fn check_step_shape(
        &self,
        kind: StepKind,
        home: Option<u8>,
        other: bool,
        mode: u8,
    ) -> Result<(), RepErr> {
        if other && self.layout.streams() == 1 {
            return Err(RepErr::Cut);
        }
        match home {
            None => {
                if mode == MODE_SAME || !other {
                    return Err(RepErr::Cut);
                }
            }
            Some(NO_SRC) => {
                if has_src(kind) {
                    return Err(RepErr::Kind);
                }
                if self.stream != 0 {
                    return Err(RepErr::Cut);
                }
            }
            Some(src) => {
                if !has_src(kind) {
                    return Err(RepErr::Kind);
                }
                self.lane_index(src).map_err(|_| RepErr::Cut)?;
            }
        }
        Ok(())
    }

    /// The step a record with `gap` names, which must be above the last mark.
    fn step_after(&self, gap: u64) -> Result<u64, RepErr> {
        let step = self
            .prev_step
            .checked_add(gap)
            .and_then(|s| s.checked_add(1))
            .ok_or(RepErr::Range)?;
        if step <= self.mark_step {
            return Err(RepErr::Mark);
        }
        Ok(step)
    }

    fn decode_step(&mut self, r: &mut Reader<'_>) -> Result<StepHalf, RepErr> {
        let b0 = r.u8()?;
        let kind = kind_from_wire(b0 & 0x0F).ok_or(RepErr::Kind)?;
        let is_home = b0 & S_HOME != 0;
        let mode = (b0 >> 5) & 0x03;
        let other = b0 & S_OTHER != 0;
        if mode > MODE_SPARSE {
            return Err(RepErr::Cut);
        }
        let step = self.step_after(r.leb_u64()?)?;
        let mut home = None;
        let mut src_delta = 0i64;
        if is_home {
            let src = r.u8()?;
            self.check_step_shape(kind, Some(src), other, mode)?;
            if src != NO_SRC {
                src_delta = r.leb_i64()?;
            }
            let payload = if has_payload(kind) {
                let plen = usize::try_from(r.leb_u64()?).map_err(|_| RepErr::Range)?;
                r.bytes(plen)?.to_vec()
            } else {
                Vec::new()
            };
            home = Some(Home {
                src_lane: LaneId(src),
                src_lane_seq: LaneSeq(0),
                payload,
            });
        } else {
            self.check_step_shape(kind, None, other, mode)?;
        }
        let n = self.lanes.len();
        let mut deltas = vec![0u64; n];
        match mode {
            MODE_DENSE => {
                for d in &mut deltas {
                    *d = r.leb_u64()?;
                }
            }
            MODE_SPARSE => {
                let map = r.bytes(self.bitmap_len())?.to_vec();
                check_bitmap_padding(&map, n)?;
                for (i, d) in deltas.iter_mut().enumerate() {
                    if bit(&map, i) {
                        *d = r.leb_u64()?;
                        if *d == 0 {
                            return Err(RepErr::Cut);
                        }
                    }
                }
            }
            _ => {}
        }
        if pick_mode(&deltas, self.bitmap_len()) != mode {
            return Err(RepErr::Cut);
        }
        let mut cut = Vec::with_capacity(n);
        for (p, d) in self.prev_cut.iter().zip(&deltas) {
            cut.push(p.checked_add(*d).ok_or(RepErr::Range)?);
        }
        if let Some(h) = &mut home
            && h.src_lane.0 != NO_SRC
        {
            let i = self.lane_index(h.src_lane.0)?;
            let base = cut.get(i).copied().ok_or(RepErr::Cut)?;
            let seq = base.checked_add_signed(src_delta).ok_or(RepErr::Range)?;
            if seq == 0 {
                return Err(RepErr::Range);
            }
            h.src_lane_seq = LaneSeq(seq);
        }
        self.prev_step = step;
        self.prev_cut.clone_from(&cut);
        Ok(StepHalf {
            step: StepId(step),
            kind,
            other,
            home,
            cut: cut.into_iter().map(LaneSeq).collect(),
        })
    }

    fn encode_step(&mut self, s: &StepHalf, out: &mut Vec<u8>) -> Result<(), RepErr> {
        let n = self.lanes.len();
        if s.cut.len() != n {
            return Err(RepErr::Cut);
        }
        let mut deltas = Vec::with_capacity(n);
        for (c, p) in s.cut.iter().zip(&self.prev_cut) {
            deltas.push(c.0.checked_sub(*p).ok_or(RepErr::Cut)?);
        }
        let mode = pick_mode(&deltas, self.bitmap_len());
        self.check_step_shape(s.kind, s.home.as_ref().map(|h| h.src_lane.0), s.other, mode)?;
        if s.step.0 <= self.prev_step {
            return Err(RepErr::Range);
        }
        let gap = s.step.0.wrapping_sub(self.prev_step).wrapping_sub(1);
        self.step_after(gap)?;
        let mut b0 = wire_kind(s.kind) | (mode << 5);
        if s.home.is_some() {
            b0 |= S_HOME;
        }
        if s.other {
            b0 |= S_OTHER;
        }
        out.push(b0);
        leb::put_u64(out, gap);
        if let Some(h) = &s.home {
            out.push(h.src_lane.0);
            if h.src_lane.0 == NO_SRC {
                if h.src_lane_seq.0 != 0 {
                    return Err(RepErr::Range);
                }
            } else {
                let i = self.lane_index(h.src_lane.0)?;
                let base = s.cut.get(i).ok_or(RepErr::Cut)?.0;
                if h.src_lane_seq.0 == 0 {
                    return Err(RepErr::Range);
                }
                let d = i128::from(h.src_lane_seq.0).wrapping_sub(i128::from(base));
                leb::put_i64(out, i64::try_from(d).map_err(|_| RepErr::Range)?);
            }
            if has_payload(s.kind) {
                leb::put_u64(out, h.payload.len() as u64);
                out.extend_from_slice(&h.payload);
            } else if !h.payload.is_empty() {
                return Err(RepErr::Kind);
            }
        }
        match mode {
            MODE_DENSE => deltas.iter().for_each(|&d| leb::put_u64(out, d)),
            MODE_SPARSE => {
                out.extend_from_slice(&bitmap(&deltas, self.bitmap_len()));
                deltas
                    .iter()
                    .filter(|&&d| d != 0)
                    .for_each(|&d| leb::put_u64(out, d));
            }
            _ => {}
        }
        self.prev_step = s.step.0;
        self.prev_cut = s.cut.iter().map(|c| c.0).collect();
        Ok(())
    }

    // ---- BlockMark ----

    fn decode_mark(&mut self, r: &mut Reader<'_>) -> Result<Section, RepErr> {
        let height = r.leb_u64()?;
        let dstep = r.leb_u64()?;
        let n = self.lanes.len();
        let map = r.bytes(self.bitmap_len())?.to_vec();
        check_bitmap_padding(&map, n).map_err(|_| RepErr::Mark)?;
        let mut bounds = Vec::with_capacity(n);
        for (i, p) in self.mark_bounds.iter().enumerate() {
            let d = if bit(&map, i) {
                let d = r.leb_u64()?;
                if d == 0 {
                    return Err(RepErr::Mark);
                }
                d
            } else {
                0
            };
            bounds.push(LaneSeq(p.checked_add(d).ok_or(RepErr::Range)?));
        }
        let m = BlockMark {
            height: Height(height),
            last_step: StepId(self.mark_step.checked_add(dstep).ok_or(RepErr::Range)?),
            lane_bounds: bounds,
        };
        self.apply_mark(&m)?;
        Ok(Section::BlockMark(m))
    }

    fn encode_mark(&mut self, m: &BlockMark, out: &mut Vec<u8>) -> Result<(), RepErr> {
        if m.lane_bounds.len() != self.lanes.len() {
            return Err(RepErr::Mark);
        }
        let dstep = m
            .last_step
            .0
            .checked_sub(self.mark_step)
            .ok_or(RepErr::Mark)?;
        let mut deltas = Vec::with_capacity(self.lanes.len());
        for (b, p) in m.lane_bounds.iter().zip(&self.mark_bounds) {
            deltas.push(b.0.checked_sub(*p).ok_or(RepErr::Mark)?);
        }
        let mut body = vec![tag::BLOCK_MARK];
        leb::put_u64(&mut body, m.height.0);
        leb::put_u64(&mut body, dstep);
        body.extend_from_slice(&bitmap(&deltas, self.bitmap_len()));
        deltas
            .iter()
            .filter(|&&d| d != 0)
            .for_each(|&d| leb::put_u64(&mut body, d));
        self.apply_mark(m)?;
        out.extend_from_slice(&body);
        Ok(())
    }

    fn apply_mark(&mut self, m: &BlockMark) -> Result<(), RepErr> {
        let bounds_ok = m
            .lane_bounds
            .iter()
            .zip(&self.lanes)
            .all(|(b, d)| b.0 == d.next_lane_seq.saturating_sub(1));
        if m.height.0 != self.next_height
            || m.last_step.0 < self.prev_step
            || m.last_step.0 < self.mark_step
            || m.lane_bounds.len() != self.lanes.len()
            || !bounds_ok
        {
            return Err(RepErr::Mark);
        }
        self.next_height = self.next_height.checked_add(1).ok_or(RepErr::Range)?;
        self.mark_step = m.last_step.0;
        self.mark_bounds = m.lane_bounds.iter().map(|b| b.0).collect();
        Ok(())
    }
}

fn nonzero(v: u64) -> Result<u64, RepErr> {
    if v == 0 { Err(RepErr::Canon) } else { Ok(v) }
}

fn bit(map: &[u8], i: usize) -> bool {
    map.get(i / 8).is_some_and(|b| b & (1u8 << (i % 8)) != 0)
}

fn bitmap(deltas: &[u64], len: usize) -> Vec<u8> {
    let mut map = vec![0u8; len];
    for (i, d) in deltas.iter().enumerate() {
        if *d != 0
            && let Some(b) = map.get_mut(i / 8)
        {
            *b |= 1u8 << (i % 8);
        }
    }
    map
}

/// Bits at positions ≥ `n` must be 0.
fn check_bitmap_padding(map: &[u8], n: usize) -> Result<(), RepErr> {
    let total = map.len().saturating_mul(8);
    if (n..total).any(|i| bit(map, i)) {
        return Err(RepErr::Cut);
    }
    Ok(())
}

/// SAME when nothing moved, else SPARSE when strictly shorter than DENSE, else DENSE.
fn pick_mode(deltas: &[u64], bitmap_len: usize) -> u8 {
    if deltas.iter().all(|&d| d == 0) {
        return MODE_SAME;
    }
    let dense: usize = deltas.iter().map(|&d| leb::len_u64(d)).sum();
    let sparse: usize = deltas
        .iter()
        .filter(|&&d| d != 0)
        .map(|&d| leb::len_u64(d))
        .sum::<usize>()
        .saturating_add(bitmap_len);
    if sparse < dense {
        MODE_SPARSE
    } else {
        MODE_DENSE
    }
}
