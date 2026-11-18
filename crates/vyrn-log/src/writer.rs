//! The sequencer's stream core for one substream (03 §4.1 core 4, 07 §3, §6.1): engine records
//! in, ORDER, HASH and HEADER frames out.
//!
//! # Contract
//!
//! **Input**, in the engine's output order (05 §6.2): [`SeqWriter::packet`] for each
//! `PacketRecord` (Advance records included) with the full BLAKE3 hash of every non-Advance
//! packet, [`SeqWriter::route`] for each `RouteRecord` after its packet, and [`SeqWriter::step`]
//! for each step with its absolute cut after the step.
//!
//! **Output.** [`SeqWriter::flush`] frames everything pushed since the last flush: frame 1 is an
//! ORDER frame holding only `TenureStart`; then ORDER frames with the pending sections (a
//! `SessionBind` before a session's first record on its lane; lane records grouped into
//! `LaneRun`s and steps into `StepRun`s, in input order); then HASH frames with a `HashRun` per
//! lane for every waiting packet, in FIFO order. [`SeqWriter::close_block`] flushes, frames a
//! `BlockMark` in its own ORDER frame, assembles the block's header ([`BlockAssembler`]), signs
//! it with the tenure's `seq_key` seed and frames it. Frames come out in the order a replica
//! must receive them on this substream (07 §3.12).
//!
//! **Frame size.** Every frame, its 24-byte header included, is at most the `max_frame` given to
//! [`SeqWriter::new`] (the transport's payload limit, such as `vyrn_nic::frame::MAX_PAYLOAD`).
//! Before a record is added, its worst-case encoded size (every LEB at 10 bytes) is reserved;
//! when it does not fit, the pending records are flushed first, and a `HashRun` is split across
//! HASH frames. A single record that cannot fit in an empty frame (a step payload that is too
//! long, or a `TenureStart` of a box too wide for the limit) is `RepErr::Range`.
//!
//! **Framed positions.** [`SeqWriter::framed_lane_seq`] and [`SeqWriter::framed_step`] name the
//! newest non-Advance `first_lane_seq` per lane, and the newest step, that frames already
//! returned carry. A caller that ships those frames first may then release the responses gated
//! on them (`INV-FRAME-FIRST`, 05 §8.10).
//!
//! **Limits of this version.** One substream (`Layout::streams() == 1`, the CONSUMER and AWS
//! layout, 07 §2.2): with two, a step's cut-only record and the second substream's header
//! inputs need the B side, which is a follow-up. Step payloads (Rescan, Control, Seal, Uncross)
//! are passed through as given. Session slots are bound in first-seen order and never reused.
//!
//! **Errors.** Every encoder error is returned and poisons the writer (the encoder fails
//! closed, [`StreamEncoder::encode`]); the sequencer fail-stops on it.

use vyrn_types::{BlockHeader, Hash, LaneId, LaneSeq, PacketFlags, PacketRecord, PktHash};
use vyrn_types::{RouteRecord, SessionId, StepId, StepKind};

use crate::block::sign_header;
use crate::frame::FRAME_HEADER_BYTES;
use crate::{
    BlockAssembler, BlockMark, Body, Home, Ident, LaneRec, Layout, RepErr, Section, SessionBind,
    StepHalf, StreamEncoder, TenureStart,
};

/// The longest canonical LEB128 of a u64.
const LEB: usize = 10;
/// A run's tag and its count.
const RUN: usize = 1 + LEB;
/// One lane record: `h`, slot (< 4098, 2 bytes), `rx_ts` ZZ, `fills_applied`, `first_lane_seq`
/// and `pkt_seq` (5 bytes).
const REC: usize = 1 + 2 + LEB + LEB + LEB + 5;
/// `SessionBind`: tag, lane, slot (2), session (4), `next_pkt_seq` (5).
const BIND: usize = 1 + 1 + 2 + 4 + 5;
/// A `HashRun`'s tag, lane and count, and one entry.
const HASH_RUN: usize = 1 + 1 + LEB;
const HASH_ENTRY: usize = 8;
/// The smallest `max_frame` [`SeqWriter::new`] accepts: the 190-byte header frame must fit.
pub const MIN_FRAME: usize = FRAME_HEADER_BYTES + 256;

/// One substream's stream core.
pub struct SeqWriter {
    enc: StreamEncoder,
    asm: BlockAssembler,
    seed: [u8; 32],
    tenure: Option<TenureStart>,
    sections: Vec<Section>,
    /// Worst-case encoded bytes of `sections`.
    bound: usize,
    max_body: usize,
    max_frame: usize,
    /// `|H|`.
    half: usize,
    /// Per lane: `(first_lane_seq, pkt_hash)` of packets whose hash is not framed yet.
    waiting: Vec<Vec<(LaneSeq, PktHash)>>,
    /// Per lane: bound sessions, slot = index.
    slots: Vec<Vec<SessionId>>,
    /// Full hashes of this block's non-Advance packets, in O-order.
    full: Vec<Hash>,
    last_step: StepId,
    /// Newest non-Advance `first_lane_seq` per lane in `sections`, and newest step.
    pend_lseq: Vec<Option<LaneSeq>>,
    pend_step: StepId,
    framed_lseq: Vec<Option<LaneSeq>>,
    framed_step: StepId,
}

/// The frames one call produced, in send order.
pub type Frames = Vec<Vec<u8>>;

impl SeqWriter {
    /// A writer for the tenure `ts` of `ident`, signing headers with `seed`; no frame exceeds
    /// `max_frame` bytes (at least [`MIN_FRAME`]).
    pub fn new(
        layout: Layout,
        ident: Ident,
        ts: TenureStart,
        seed: [u8; 32],
        max_frame: usize,
    ) -> Result<Self, RepErr> {
        if layout.streams() != 1 {
            return Err(RepErr::Layout);
        }
        if max_frame < MIN_FRAME || max_frame > usize::from(u16::MAX) {
            return Err(RepErr::Range);
        }
        let n = usize::from(layout.n_lanes());
        let first = StepId(ts.first_step.0.saturating_sub(1));
        Ok(Self {
            enc: StreamEncoder::new(layout, 0, ident)?,
            asm: BlockAssembler::from_tenure(ident.book, &ts),
            seed,
            last_step: first,
            tenure: Some(ts),
            sections: Vec::new(),
            bound: 0,
            max_body: max_frame.saturating_sub(FRAME_HEADER_BYTES),
            max_frame,
            half: n,
            waiting: vec![Vec::new(); n],
            slots: vec![Vec::new(); n],
            full: Vec::new(),
            pend_lseq: vec![None; n],
            pend_step: first,
            framed_lseq: vec![None; n],
            framed_step: first,
        })
    }

    /// The newest non-Advance `first_lane_seq` of `lane` in frames already returned.
    pub fn framed_lane_seq(&self, lane: LaneId) -> Option<LaneSeq> {
        self.framed_lseq.get(usize::from(lane.0)).copied().flatten()
    }

    /// The newest step in frames already returned.
    pub fn framed_step(&self) -> StepId {
        self.framed_step
    }

    /// Worst-case bytes of a cut or bounds list of this half.
    fn cut_bound(&self) -> usize {
        self.half
            .div_ceil(8)
            .saturating_add(self.half.saturating_mul(LEB))
    }

    /// Makes room for `need` more bytes, flushing first when they do not fit.
    fn reserve(&mut self, need: usize) -> Result<Frames, RepErr> {
        if need > self.max_body {
            return Err(RepErr::Range);
        }
        let out = if self.bound.saturating_add(need) > self.max_body {
            self.flush()?
        } else {
            Vec::new()
        };
        self.bound = self.bound.saturating_add(need);
        Ok(out)
    }

    /// One lane record. `full` is the packet's BLAKE3-256; `None` only for an Advance record. A
    /// `SHED` record's `full` is not in `data_root` (07 §6.1, 05 §18 Q17).
    pub fn packet(&mut self, p: PacketRecord, full: Option<Hash>) -> Result<Frames, RepErr> {
        let lane = usize::from(p.lane.0);
        let advance = p.flags & PacketFlags::ADVANCE != 0;
        let full = if advance {
            None
        } else {
            Some(full.ok_or(RepErr::Count)?)
        };
        let slots = self.slots.get(lane).ok_or(RepErr::Half)?;
        let new_bind = !advance && !slots.contains(&p.session);
        let new_run =
            !matches!(self.sections.last(), Some(Section::LaneRun { lane: l, .. }) if *l == p.lane);
        let bind = if new_bind { BIND + RUN } else { 0 };
        let run = if new_run { RUN } else { 0 };
        let need = REC.saturating_add(bind).saturating_add(run);
        let out = self.reserve(need)?;
        if let Some(full) = full {
            let slots = self.slots.get_mut(lane).ok_or(RepErr::Half)?;
            if !slots.contains(&p.session) {
                let slot = u16::try_from(slots.len()).map_err(|_| RepErr::Range)?;
                slots.push(p.session);
                self.sections.push(Section::SessionBind(SessionBind {
                    lane: p.lane,
                    slot,
                    session: p.session,
                    next_pkt_seq: p.pkt_seq,
                }));
            }
            self.waiting
                .get_mut(lane)
                .ok_or(RepErr::Half)?
                .push((p.first_lane_seq, p.pkt_hash));
            // A `SHED` record is outside `data_root` (07 §6.1, 05 §18 Q17).
            if p.flags & PacketFlags::SHED == 0 {
                self.full.push(full);
            }
            *self.pend_lseq.get_mut(lane).ok_or(RepErr::Half)? = Some(p.first_lane_seq);
        }
        let rec = LaneRec::Pkt(PacketRecord {
            pkt_hash: PktHash(0),
            ..p
        });
        match self.sections.last_mut() {
            Some(Section::LaneRun { lane: l, recs }) if *l == p.lane => recs.push(rec),
            _ => self.sections.push(Section::LaneRun {
                lane: p.lane,
                recs: vec![rec],
            }),
        }
        Ok(out)
    }

    /// One `RouteRecord` (07 §3.6): pushed after the `PacketRecord` holding its op, with no
    /// later non-Advance packet of its lane in between, as the lane logs it.
    pub fn route(&mut self, t: RouteRecord) -> Result<Frames, RepErr> {
        let new_run =
            !matches!(self.sections.last(), Some(Section::LaneRun { lane: l, .. }) if *l == t.lane);
        let out = self.reserve(if new_run { 3 + RUN } else { 3 })?;
        let rec = LaneRec::Route(t);
        match self.sections.last_mut() {
            Some(Section::LaneRun { lane: l, recs }) if *l == t.lane => recs.push(rec),
            _ => self.sections.push(Section::LaneRun {
                lane: t.lane,
                recs: vec![rec],
            }),
        }
        Ok(out)
    }

    /// One step: `src` is the source op for Cross, Improve and Shed, `flags` its
    /// `StepRecord.flags` (`StepFlags::CROSS` or 0; must be 0 without a source), `cut` the whole
    /// box's cut after the step.
    pub fn step(
        &mut self,
        step: StepId,
        kind: StepKind,
        src: Option<(LaneId, LaneSeq)>,
        flags: u8,
        payload: Vec<u8>,
        cut: &[LaneSeq],
    ) -> Result<Frames, RepErr> {
        let new_run = !matches!(self.sections.last(), Some(Section::StepRun(_)));
        let need = (1 + LEB + 1 + LEB + LEB)
            .saturating_add(payload.len())
            .saturating_add(self.cut_bound())
            .saturating_add(if new_run { RUN } else { 0 });
        let out = self.reserve(need)?;
        let half = StepHalf {
            step,
            kind,
            other: false,
            home: Some(Home {
                src_lane: src.map_or(LaneId(0xFF), |s| s.0),
                src_lane_seq: src.map_or(LaneSeq(0), |s| s.1),
                flags,
                payload,
            }),
            cut: cut.to_vec(),
        };
        match self.sections.last_mut() {
            Some(Section::StepRun(v)) => v.push(half),
            _ => self.sections.push(Section::StepRun(vec![half])),
        }
        self.last_step = step;
        self.pend_step = step;
        Ok(out)
    }

    fn encode(&mut self, body: &Body) -> Result<Vec<u8>, RepErr> {
        let f = self.enc.encode(body)?;
        if f.len() > self.max_frame {
            return Err(RepErr::Range);
        }
        Ok(f)
    }

    /// Frames everything pushed so far (see the module docs). Empty when nothing is pending.
    pub fn flush(&mut self) -> Result<Frames, RepErr> {
        let mut out = Vec::new();
        if let Some(ts) = self.tenure.take() {
            out.push(self.encode(&Body::Order {
                tenure_start: Some(ts),
                sections: Vec::new(),
            })?);
        }
        if !self.sections.is_empty() {
            let body = Body::Order {
                tenure_start: None,
                sections: core::mem::take(&mut self.sections),
            };
            out.push(self.encode(&body)?);
        }
        self.bound = 0;
        for (f, p) in self.framed_lseq.iter_mut().zip(&self.pend_lseq) {
            if p.is_some() {
                *f = *p;
            }
        }
        self.framed_step = self.pend_step;
        let n = self.waiting.len();
        let waiting = core::mem::replace(&mut self.waiting, vec![Vec::new(); n]);
        let mut runs = Vec::new();
        let mut used = 0usize;
        for (l, mut entries) in waiting.into_iter().enumerate() {
            let lane = LaneId(u8::try_from(l).map_err(|_| RepErr::Half)?);
            while !entries.is_empty() {
                let room = self
                    .max_body
                    .saturating_sub(used.saturating_add(HASH_RUN))
                    .checked_div(HASH_ENTRY)
                    .unwrap_or(0);
                if room == 0 {
                    out.push(self.encode(&Body::Hash(core::mem::take(&mut runs)))?);
                    used = 0;
                    continue;
                }
                let rest = entries.split_off(room.min(entries.len()));
                used = used
                    .saturating_add(HASH_RUN)
                    .saturating_add(entries.len().saturating_mul(HASH_ENTRY));
                runs.push(Section::HashRun { lane, entries });
                entries = rest;
            }
        }
        if !runs.is_empty() {
            out.push(self.encode(&Body::Hash(runs))?);
        }
        Ok(out)
    }

    /// Closes the current block: flush, `BlockMark`, then the signed HEADER frame. Returns the
    /// frames and the header.
    pub fn close_block(&mut self) -> Result<(Frames, BlockHeader), RepErr> {
        // The mark's bounds are the encoder's state, so pending records are framed first.
        let mut out = self.flush()?;
        if (1 + LEB + LEB).saturating_add(self.cut_bound()) > self.max_body {
            return Err(RepErr::Range);
        }
        let mark = BlockMark {
            height: self.enc.state().next_height(),
            last_step: self.last_step,
            lane_bounds: self.enc.state().lane_bounds(),
        };
        self.sections.push(Section::BlockMark(mark));
        out.extend(self.flush()?);
        let half = self.enc.take_closed().pop().ok_or(RepErr::Mark)?;
        let full = core::mem::take(&mut self.full);
        let h = self
            .asm
            .assemble(&half, None, &full, &[])
            .map_err(|_| RepErr::Header)?;
        let h = sign_header(&h, &self.seed);
        out.push(self.encode(&Body::Header(h))?);
        Ok((out, h))
    }

    /// The height the next [`close_block`](Self::close_block) closes.
    pub fn next_height(&self) -> vyrn_types::Height {
        self.enc.state().next_height()
    }

    /// The last step pushed.
    pub fn last_step(&self) -> StepId {
        self.last_step
    }
}
