//! The sequencer's stream core for one substream (03 §4.1 core 4, 07 §3, §6.1): engine records
//! in, ORDER, HASH and HEADER frames out.
//!
//! # Contract
//!
//! **Input**, in the engine's output order (05 §6.2): [`SeqWriter::packet`] for each
//! `PacketRecord` (Advance records included) with the full BLAKE3 hash of every non-Advance
//! packet, and [`SeqWriter::step`] for each step with its absolute cut after the step.
//!
//! **Output.** [`SeqWriter::flush`] frames everything pushed since the last flush: one ORDER
//! frame (`TenureStart` first in frame 1; a `SessionBind` before a session's first record on
//! its lane; lane records grouped into `LaneRun`s and steps into `StepRun`s, in input order),
//! then one HASH frame with a `HashRun` per lane for every waiting packet, in FIFO order.
//! [`SeqWriter::close_block`] flushes, frames a `BlockMark` in its own ORDER frame, assembles the block's header
//! ([`BlockAssembler`]), signs it with the tenure's `seq_key` seed and frames it. Frames come
//! out in the order a replica must receive them on this substream (07 §3.12).
//!
//! **Limits of this version.** One substream (`Layout::streams() == 1`, the CONSUMER and AWS
//! layout, 07 §2.2): with two, a step's cut-only record and the second substream's header
//! inputs need the B side, which is a follow-up. Step payloads (Rescan, Control, Seal, Uncross)
//! are passed through as given. Session slots are bound in first-seen order and never reused.
//!
//! **Errors.** Every encoder error is returned and poisons the writer (the encoder fails
//! closed, [`StreamEncoder::encode`]); the sequencer fail-stops on it.

use vyrn_types::{BlockHeader, Hash, LaneId, LaneSeq, PacketFlags, PacketRecord, PktHash};
use vyrn_types::{SessionId, StepId, StepKind};

use crate::block::sign_header;
use crate::{
    BlockAssembler, BlockMark, Body, Home, Ident, LaneRec, Layout, RepErr, Section, SessionBind,
    StepHalf, StreamEncoder, TenureStart,
};

/// Lane and step records per ORDER frame before [`SeqWriter::packet`] or [`SeqWriter::step`]
/// flushes on its own, so a frame body stays far below `u16::MAX` bytes.
pub const RECS_PER_FRAME: usize = 64;

/// One substream's stream core.
pub struct SeqWriter {
    enc: StreamEncoder,
    asm: BlockAssembler,
    seed: [u8; 32],
    tenure: Option<TenureStart>,
    sections: Vec<Section>,
    recs: usize,
    /// Per lane: `(first_lane_seq, pkt_hash)` of packets whose hash is not framed yet.
    waiting: Vec<Vec<(LaneSeq, PktHash)>>,
    /// Per lane: bound sessions, slot = index.
    slots: Vec<Vec<SessionId>>,
    /// Full hashes of this block's non-Advance packets, in O-order.
    full: Vec<Hash>,
    last_step: StepId,
}

/// The frames one call produced, in send order.
pub type Frames = Vec<Vec<u8>>;

impl SeqWriter {
    /// A writer for the tenure `ts` of `ident`, signing headers with `seed`.
    pub fn new(
        layout: Layout,
        ident: Ident,
        ts: TenureStart,
        seed: [u8; 32],
    ) -> Result<Self, RepErr> {
        if layout.streams() != 1 {
            return Err(RepErr::Layout);
        }
        let n = usize::from(layout.n_lanes());
        Ok(Self {
            enc: StreamEncoder::new(layout, 0, ident)?,
            asm: BlockAssembler::from_tenure(ident.book, &ts),
            seed,
            last_step: StepId(ts.first_step.0.saturating_sub(1)),
            tenure: Some(ts),
            sections: Vec::new(),
            recs: 0,
            waiting: vec![Vec::new(); n],
            slots: vec![Vec::new(); n],
            full: Vec::new(),
        })
    }

    /// One lane record. `full` is the packet's BLAKE3-256; `None` only for an Advance record.
    pub fn packet(&mut self, p: PacketRecord, full: Option<Hash>) -> Result<Frames, RepErr> {
        let lane = usize::from(p.lane.0);
        let advance = p.flags & PacketFlags::ADVANCE != 0;
        if !advance {
            let full = full.ok_or(RepErr::Count)?;
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
            self.full.push(full);
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
        self.counted()
    }

    /// One step: `src` is the source op for Cross, Improve and Shed, `cut` the whole box's cut
    /// after the step.
    pub fn step(
        &mut self,
        step: StepId,
        kind: StepKind,
        src: Option<(LaneId, LaneSeq)>,
        payload: Vec<u8>,
        cut: &[LaneSeq],
    ) -> Result<Frames, RepErr> {
        let half = StepHalf {
            step,
            kind,
            other: false,
            home: Some(Home {
                src_lane: src.map_or(LaneId(0xFF), |s| s.0),
                src_lane_seq: src.map_or(LaneSeq(0), |s| s.1),
                payload,
            }),
            cut: cut.to_vec(),
        };
        match self.sections.last_mut() {
            Some(Section::StepRun(v)) => v.push(half),
            _ => self.sections.push(Section::StepRun(vec![half])),
        }
        self.last_step = step;
        self.counted()
    }

    fn counted(&mut self) -> Result<Frames, RepErr> {
        self.recs = self.recs.saturating_add(1);
        if self.recs >= RECS_PER_FRAME {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }

    /// Frames everything pushed so far (see the module docs). Empty when nothing is pending.
    pub fn flush(&mut self) -> Result<Frames, RepErr> {
        let mut out = Vec::new();
        if !self.sections.is_empty() || self.tenure.is_some() {
            let body = Body::Order {
                tenure_start: self.tenure.take(),
                sections: core::mem::take(&mut self.sections),
            };
            out.push(self.enc.encode(&body)?);
        }
        self.recs = 0;
        let runs: Vec<Section> = self
            .waiting
            .iter_mut()
            .enumerate()
            .filter(|(_, w)| !w.is_empty())
            .map(|(l, w)| Section::HashRun {
                lane: LaneId(u8::try_from(l).unwrap_or(u8::MAX)),
                entries: core::mem::take(w),
            })
            .collect();
        if !runs.is_empty() {
            out.push(self.enc.encode(&Body::Hash(runs))?);
        }
        Ok(out)
    }

    /// Closes the current block: `BlockMark`, flush, then the signed HEADER frame. Returns the
    /// frames and the header.
    pub fn close_block(&mut self) -> Result<(Frames, BlockHeader), RepErr> {
        // The mark's bounds are the encoder's state, so pending records are framed first.
        let mut out = self.flush()?;
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
        out.push(self.enc.encode(&Body::Header(h))?);
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
