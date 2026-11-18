//! The order core (07 §3.12, §7.2 core 3): decodes both substreams, applies the lane-state and
//! step rules, checks headers, and hands out each block's replay inputs once it is complete.

use std::collections::{BTreeMap, VecDeque};

use vyrn_consensus::Verdict;
use vyrn_log::block::{header_hash, order_root, verify_seq_sig};
use vyrn_log::{
    Body, FrameHeader, HalfBlock, LaneRec, Layout, MergedStep, RepErr, Section, StepHalf,
    StepMerger, StreamDecoder, TenureStart,
};
use vyrn_types::{BlockHeader, Epoch, Hash, Height, LaneId, LaneSeq, PktHash, StepId};

use crate::check::{StepErr, check_step};
use crate::hashlag::{REP_HASHLAG_MAX_NS, check_hashlag};
use crate::lane::{LaneErr, LaneState};
use crate::ports::{BlockInputs, EpochView};

/// Why a header fails (07 §3.10, §6.4 item 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderErr {
    #[error("no seq_key for the sender, or seq_sig does not verify")]
    Sig,
    #[error("epoch or book differs from the epoch view")]
    Ident,
    #[error("a second header for one height")]
    Equivocation,
    #[error("height or prev does not chain")]
    Chain,
    #[error("first_step or last_step differs from the block's marks")]
    Steps,
    #[error("order_root differs from the ORDER bytes")]
    OrderRoot,
}

/// What a fault was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FaultKind {
    #[error("decoder: {0}")]
    Decode(RepErr),
    #[error("lane: {0}")]
    Lane(LaneErr),
    #[error("step: {0}")]
    Step(StepErr),
    #[error("REP_E_HASHLAG: lane {lane:?} record {lane_seq:?} waited {waited} ns")]
    HashLag {
        lane: LaneId,
        lane_seq: LaneSeq,
        waited: u64,
    },
    #[error("header: {0}")]
    Header(HeaderErr),
}

impl FaultKind {
    /// The `REP_E_*` code (07 §15) when the fault has one, else a short name.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Decode(e) => match e {
                RepErr::Tag => "REP_E_TAG",
                RepErr::Count => "REP_E_COUNT",
                RepErr::Ts => "REP_E_TS",
                RepErr::Kind => "REP_E_KIND",
                RepErr::Cut => "REP_E_CUT",
                RepErr::Tenure => "REP_E_TENURE",
                RepErr::HashLag => "REP_E_HASHLAG",
                _ => "DECODE",
            },
            Self::Lane(_) => "LANE",
            Self::Step(e) => e.code(),
            Self::HashLag { .. } => "REP_E_HASHLAG",
            Self::Header(_) => "HEADER",
        }
    }
}

/// A sequencer fault, recorded with the frame that showed it (07 §3.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "sequencer fault at epoch {epoch:?} tenure {tenure} stream {stream} frame {frame_seq}: {kind}"
)]
pub struct Fault {
    pub epoch: Epoch,
    pub tenure: u8,
    pub stream: u8,
    pub frame_seq: u64,
    /// The first height this replica no longer votes for.
    pub height: Height,
    pub kind: FaultKind,
}

/// Result of a rejected frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameErr {
    /// Not the substream's next `frame_seq`: the caller's ordering error; nothing changed.
    #[error("frame out of order")]
    OutOfOrder,
    /// A sequencer fault, this one or an earlier one.
    #[error(transparent)]
    Fault(Fault),
}

/// Where a frame came from, for fault records.
#[derive(Clone, Copy, Debug)]
struct FrameId {
    tenure: u8,
    stream: u8,
    frame_seq: u64,
}

/// One substream's share of a block that is not ready yet.
#[derive(Clone, Debug, Default)]
struct Part {
    recs: Vec<LaneRec>,
    missing: usize,
    half: Option<HalfBlock>,
}

#[derive(Clone, Debug)]
struct Sub {
    dec: StreamDecoder,
    first_lane: u8,
    lanes: Vec<LaneState>,
    cut: Vec<LaneSeq>,
    /// The half-cut its `TenureStart` set, which the step merger starts from.
    base_cut: Vec<LaneSeq>,
    mark_bounds: Vec<LaneSeq>,
    started: bool,
    tenure: u8,
    /// The height of the block the next lane record belongs to.
    open: u64,
    parts: BTreeMap<u64, Part>,
}

/// The tenure facts both `TenureStart`s must agree on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anchor {
    epoch: Epoch,
    first_step: StepId,
    first_height: Height,
    prev_header_hash: Hash,
}

/// The order core of one tenure. `N` is the box's lane count.
pub struct OrderCore<const N: usize, V> {
    layout: Layout,
    view: V,
    subs: Vec<Sub>,
    anchor: Option<Anchor>,
    merger: Option<StepMerger<N>>,
    pre_merge: Vec<(u8, StepHalf)>,
    merged: VecDeque<MergedStep<N>>,
    headers: BTreeMap<u64, (BlockHeader, FrameId)>,
    /// `header_hash` of the last ready block (or the anchor) and the next block's first step.
    tip: Option<(Hash, StepId)>,
    next_height: u64,
    ready: VecDeque<BlockInputs<N>>,
    fault: Option<Fault>,
    /// The `REP_E_HASHLAG` bound, in ns: [`REP_HASHLAG_MAX_NS`] unless set for DEV.
    hashlag_max: u64,
}

impl<const N: usize, V: EpochView> OrderCore<N, V> {
    pub fn new(layout: Layout, view: V) -> Result<Self, RepErr> {
        if usize::from(layout.n_lanes()) != N {
            return Err(RepErr::Layout);
        }
        let mut subs = Vec::new();
        for s in 0..layout.streams() {
            let half = layout.half(s);
            let n = usize::from(half.end.saturating_sub(half.start));
            subs.push(Sub {
                dec: StreamDecoder::new(layout, s)?,
                first_lane: half.start,
                lanes: vec![LaneState::default(); n],
                cut: vec![LaneSeq(0); n],
                base_cut: vec![LaneSeq(0); n],
                mark_bounds: vec![LaneSeq(0); n],
                started: false,
                tenure: 0,
                open: 0,
                parts: BTreeMap::new(),
            });
        }
        Ok(Self {
            layout,
            view,
            subs,
            anchor: None,
            merger: None,
            pre_merge: Vec::new(),
            merged: VecDeque::new(),
            headers: BTreeMap::new(),
            tip: None,
            next_height: 0,
            ready: VecDeque::new(),
            fault: None,
            hashlag_max: REP_HASHLAG_MAX_NS,
        })
    }

    /// The epoch view, to update in place: an epoch's own fence certifies after its order
    /// core has started (`ActiveEpoch::set_fence`), and the next `verdict` sees it.
    pub fn view_mut(&mut self) -> &mut V {
        &mut self.view
    }

    /// The fault that stopped this core, if any.
    pub const fn fault(&self) -> Option<&Fault> {
        self.fault.as_ref()
    }

    /// The next height [`take_ready`](Self::take_ready) will yield.
    pub const fn next_height(&self) -> Height {
        Height(self.next_height)
    }

    /// The next block's replay inputs, in height order.
    pub fn take_ready(&mut self) -> Option<BlockInputs<N>> {
        self.ready.pop_front()
    }

    /// 07 §6.4 items 2 and 5 for `first ..= last`: `Valid` when every block is ready (its ORDER
    /// bytes, steps and header passed) and no fence or fault covers it, `Invalid` when a fault or
    /// fence does, `Pending` otherwise.
    pub fn verdict(&self, first: Height, last: Height) -> Verdict {
        if first > last || self.view.fenced(last) || self.fault.is_some_and(|f| last >= f.height) {
            return Verdict::Invalid;
        }
        // Heights before this tenure's first block were never decoded here.
        let decoded = self.anchor.is_some_and(|a| first >= a.first_height);
        if last.0 < self.next_height && self.tip.is_some() && decoded {
            Verdict::Valid
        } else {
            Verdict::Pending
        }
    }

    /// Sets the `REP_E_HASHLAG` bound to `ns`. DEV only (07 §3.7): the spec's bound is
    /// [`REP_HASHLAG_MAX_NS`], and the validator refuses any other value outside DEV mode.
    pub fn set_hashlag_max(&mut self, ns: u64) {
        self.hashlag_max = ns;
    }

    /// Runs the `REP_E_HASHLAG` timer at `now` (ns, the receive clock).
    pub fn tick(&mut self, now: u64) -> Result<(), FrameErr> {
        if let Some(f) = self.fault {
            return Err(FrameErr::Fault(f));
        }
        for (s, sub) in (0u8..).zip(&self.subs) {
            if let Err(l) = check_hashlag(&sub.lanes, sub.first_lane, now, self.hashlag_max) {
                let id = FrameId {
                    tenure: sub.tenure,
                    stream: s,
                    frame_seq: l.rec.frame_seq,
                };
                let kind = FaultKind::HashLag {
                    lane: l.lane,
                    lane_seq: l.rec.lane_seq,
                    waited: l.waited,
                };
                return Err(self.raise(id, kind));
            }
        }
        Ok(())
    }

    /// Takes one frame of either substream, received at `now`.
    pub fn on_frame(&mut self, bytes: &[u8], now: u64) -> Result<(), FrameErr> {
        // Deadlines first: a HashRun that arrives late must not clear the record it is late for.
        self.tick(now)?;
        let id = match FrameHeader::parse(bytes) {
            Ok((h, _)) => FrameId {
                tenure: h.tenure,
                stream: h.stream,
                frame_seq: h.frame_seq,
            },
            Err(e) => return Err(self.raise(raw_id(bytes), FaultKind::Decode(e))),
        };
        let s = usize::from(id.stream);
        let Some(sub) = self.subs.get_mut(s) else {
            return Err(self.raise(id, FaultKind::Decode(RepErr::Header)));
        };
        let frame = match sub.dec.decode(bytes) {
            Ok(f) => f,
            Err(RepErr::Seq) => return Err(FrameErr::OutOfOrder),
            Err(e) => return Err(self.raise(id, FaultKind::Decode(e))),
        };
        let sender = frame.header.sender;
        if let Err(kind) = self.apply(id, sender, frame.body, now) {
            return Err(self.raise(id, kind));
        }
        let closed = self.subs.get_mut(s).map(|x| x.dec.take_closed());
        for hb in closed.into_iter().flatten() {
            if let Some(sub) = self.subs.get_mut(s) {
                let h = hb.height.0;
                sub.parts.entry(h).or_default().half = Some(hb);
            }
        }
        if let Err((fid, kind)) = self.advance() {
            return Err(self.raise(fid.unwrap_or(id), kind));
        }
        self.tick(now)
    }

    fn raise(&mut self, id: FrameId, kind: FaultKind) -> FrameErr {
        let f = Fault {
            epoch: self.view.epoch(),
            tenure: id.tenure,
            stream: id.stream,
            frame_seq: id.frame_seq,
            height: Height(self.next_height),
            kind,
        };
        self.fault = Some(f);
        FrameErr::Fault(f)
    }

    fn apply(&mut self, id: FrameId, sender: u8, body: Body, now: u64) -> Result<(), FaultKind> {
        match body {
            Body::Order {
                tenure_start,
                sections,
            } => {
                if let Some(ts) = tenure_start {
                    self.tenure_start(id, &ts)?;
                }
                for sec in sections {
                    self.order_section(id, sec, now)?;
                }
            }
            Body::Hash(sections) => {
                for sec in sections {
                    if let Section::HashRun { lane, entries } = sec {
                        self.hash_run(id.stream, lane, &entries)?;
                    }
                }
            }
            Body::Header(h) => self.header(id, sender, h)?,
            Body::Heartbeat(_) => {}
        }
        Ok(())
    }

    fn tenure_start(&mut self, id: FrameId, ts: &TenureStart) -> Result<(), FaultKind> {
        let tenure = FaultKind::Decode(RepErr::Tenure);
        let a = Anchor {
            epoch: ts.epoch,
            first_step: ts.first_step,
            first_height: ts.first_height,
            prev_header_hash: ts.prev_header_hash,
        };
        if ts.epoch != self.view.epoch() || self.anchor.is_some_and(|x| x != a) {
            return Err(tenure);
        }
        self.anchor = Some(a);
        let sub = self.subs.get_mut(usize::from(id.stream)).ok_or(tenure)?;
        if sub.started {
            return Err(tenure);
        }
        // A half-cut cannot start beyond its lanes' decoded prefixes (S2 at the tenure base).
        for ((l, c), base) in (sub.first_lane..).zip(&ts.prev_cut).zip(&ts.lanes) {
            let prefix = LaneSeq(base.next_lane_seq.0.saturating_sub(1));
            if *c > prefix {
                return Err(FaultKind::Step(StepErr::CutBeyondPrefix {
                    lane: LaneId(l),
                    cut: *c,
                    prefix,
                }));
            }
        }
        sub.lanes = ts.lanes.iter().map(LaneState::from_base).collect();
        sub.cut.clone_from(&ts.prev_cut);
        sub.base_cut.clone_from(&ts.prev_cut);
        sub.mark_bounds = sub.lanes.iter().map(LaneState::prefix).collect();
        sub.started = true;
        sub.tenure = id.tenure;
        sub.open = ts.first_height.0;
        if self.subs.iter().all(|s| s.started) {
            // From the TenureStart cuts, not `sub.cut`: a substream that started first may
            // already have moved its half-cut with steps queued in `pre_merge`.
            let mut cut = [LaneSeq(0); N];
            for sub in &self.subs {
                for (l, c) in (sub.first_lane..).zip(&sub.base_cut) {
                    if let Some(x) = cut.get_mut(usize::from(l)) {
                        *x = *c;
                    }
                }
            }
            let mut m =
                StepMerger::new(self.layout, a.first_step, cut).map_err(FaultKind::Decode)?;
            for (s, h) in self.pre_merge.drain(..) {
                m.push(s, h).map_err(FaultKind::Decode)?;
            }
            self.merger = Some(m);
            self.tip = Some((a.prev_header_hash, a.first_step));
            self.next_height = a.first_height.0;
        }
        Ok(())
    }

    fn order_section(&mut self, id: FrameId, sec: Section, now: u64) -> Result<(), FaultKind> {
        let layout = self.layout;
        let sub = self
            .subs
            .get_mut(usize::from(id.stream))
            .ok_or(FaultKind::Decode(RepErr::Layout))?;
        match sec {
            Section::LaneRun { lane, recs } => {
                let h = sub.open;
                let i = usize::from(lane.0.wrapping_sub(sub.first_lane));
                let part = sub.parts.entry(h).or_default();
                let st = sub
                    .lanes
                    .get_mut(i)
                    .ok_or(FaultKind::Decode(RepErr::Half))?;
                for r in recs {
                    match &r {
                        LaneRec::Pkt(p) => {
                            let at = (Height(h), part.recs.len());
                            st.on_packet(p, now, id.frame_seq, at)
                                .map_err(FaultKind::Lane)?;
                            if p.flags & vyrn_types::PacketFlags::ADVANCE == 0 {
                                part.missing = part.missing.saturating_add(1);
                            }
                        }
                        LaneRec::Take(t) => st.on_take(t).map_err(FaultKind::Lane)?,
                        // The decoder checked that it names an op of the preceding packet.
                        LaneRec::Route(_) => {}
                    }
                    part.recs.push(r);
                }
            }
            Section::StepRun(halves) => {
                for half in halves {
                    check_step(&layout, id.stream, &half, &sub.cut, &sub.lanes)
                        .map_err(FaultKind::Step)?;
                    sub.cut.clone_from(&half.cut);
                    match &mut self.merger {
                        Some(m) => m.push(id.stream, half).map_err(FaultKind::Decode)?,
                        None => self.pre_merge.push((id.stream, half)),
                    }
                }
            }
            Section::BlockMark(m) => {
                for (st, b) in sub.lanes.iter_mut().zip(&sub.mark_bounds) {
                    st.prune_shed(*b);
                }
                sub.mark_bounds = m.lane_bounds;
                // vyrn-log checked the mark against its own state; the two views must agree.
                if m.height.0 != sub.open {
                    return Err(FaultKind::Decode(RepErr::Mark));
                }
                sub.parts.entry(sub.open).or_default();
                sub.open = sub.open.saturating_add(1);
            }
            Section::SessionBind(_) | Section::HashRun { .. } | Section::Pad(_) => {}
        }
        Ok(())
    }

    fn hash_run(
        &mut self,
        stream: u8,
        lane: LaneId,
        entries: &[(LaneSeq, PktHash)],
    ) -> Result<(), FaultKind> {
        let sub = self
            .subs
            .get_mut(usize::from(stream))
            .ok_or(FaultKind::Decode(RepErr::Layout))?;
        let i = usize::from(lane.0.wrapping_sub(sub.first_lane));
        let st = sub
            .lanes
            .get_mut(i)
            .ok_or(FaultKind::Decode(RepErr::Half))?;
        for &(seq, hash) in entries {
            let a = st.on_hash(seq, hash).map_err(FaultKind::Lane)?;
            let part = sub
                .parts
                .get_mut(&a.height.0)
                .ok_or(FaultKind::Lane(LaneErr::Hash))?;
            if let Some(LaneRec::Pkt(p)) = part.recs.get_mut(a.index) {
                p.pkt_hash = hash;
            }
            part.missing = part.missing.saturating_sub(1);
        }
        Ok(())
    }

    fn header(&mut self, id: FrameId, sender: u8, h: BlockHeader) -> Result<(), FaultKind> {
        let key = self.view.seq_key(sender);
        if !key.is_some_and(|k| verify_seq_sig(&h, &k)) {
            return Err(FaultKind::Header(HeaderErr::Sig));
        }
        if h.epoch != self.view.epoch() || h.book != self.view.book() {
            return Err(FaultKind::Header(HeaderErr::Ident));
        }
        if h.height.0 < self.next_height || self.headers.contains_key(&h.height.0) {
            return Err(FaultKind::Header(HeaderErr::Equivocation));
        }
        self.headers.insert(h.height.0, (h, id));
        Ok(())
    }

    /// Merges steps and moves every complete block to `ready`, in height order.
    fn advance(&mut self) -> Result<(), (Option<FrameId>, FaultKind)> {
        if let Some(m) = &mut self.merger {
            while let Some(s) = m.pop().map_err(|e| (None, FaultKind::Decode(e)))? {
                self.merged.push_back(s);
            }
        }
        loop {
            let Some((tip_hash, first_step)) = self.tip else {
                return Ok(());
            };
            let h = self.next_height;
            let mut halves = Vec::new();
            let mut hashed = true;
            for sub in &self.subs {
                match sub.parts.get(&h) {
                    Some(Part {
                        half: Some(hb),
                        missing,
                        ..
                    }) => {
                        halves.push(hb);
                        hashed &= *missing == 0;
                    }
                    _ => return Ok(()),
                }
            }
            let last_step = halves.first().map_or(StepId(0), |b| b.last_step);
            if halves.iter().any(|b| b.last_step != last_step) {
                return Err((None, FaultKind::Decode(RepErr::Mark)));
            }
            // Both halves are closed, and vyrn-log refuses a step at or below a mark's
            // `last_step` after the mark, so a step the merger still lacks can never arrive.
            let merged_through = self
                .merger
                .as_ref()
                .map_or(0, |m| m.next_step().0.saturating_sub(1));
            if merged_through < last_step.0 {
                return Err((None, FaultKind::Decode(RepErr::Step)));
            }
            let Some(&(header, hid)) = self.headers.get(&h) else {
                return Ok(());
            };
            if !hashed {
                return Ok(());
            }
            let fail = |e| Err((Some(hid), FaultKind::Header(e)));
            if header.prev != tip_hash {
                return fail(HeaderErr::Chain);
            }
            if header.first_step != first_step || header.last_step != last_step {
                return fail(HeaderErr::Steps);
            }
            let empty: &[u8] = &[];
            let root = order_root(
                halves.first().map_or(empty, |b| &b.order_bytes),
                halves.get(1).map_or(empty, |b| &b.order_bytes),
            );
            if header.order_root != root {
                return fail(HeaderErr::OrderRoot);
            }
            let mut lanes = Vec::new();
            let mut split = 0;
            for (i, sub) in self.subs.iter_mut().enumerate() {
                if let Some(p) = sub.parts.remove(&h) {
                    lanes.extend(p.recs);
                }
                if i == 0 {
                    split = lanes.len();
                }
            }
            let mut steps = Vec::new();
            while self.merged.front().is_some_and(|s| s.rec.step <= last_step) {
                steps.extend(self.merged.pop_front());
            }
            self.headers.remove(&h);
            self.tip = Some((header_hash(&header), StepId(last_step.0.saturating_add(1))));
            self.next_height = h.saturating_add(1);
            self.ready.push_back(BlockInputs {
                header,
                lanes,
                split,
                steps,
            });
        }
    }
}

fn raw_id(bytes: &[u8]) -> FrameId {
    let seq = bytes
        .get(8..16)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_le_bytes);
    FrameId {
        tenure: bytes.get(17).copied().unwrap_or(0),
        stream: bytes.get(21).copied().unwrap_or(0xFF),
        frame_seq: seq,
    }
}
