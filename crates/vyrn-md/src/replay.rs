//! [`SinkStream`]: the observer replica's replay output as the [`ReplayStream`] contract, pushed
//! straight into an [`MboEncoder`] (10 §7.1). It is a `vyrn_engine::Sink`, so
//! `vyrn_replica::RustReplay` drives it, and a live engine can drive the same adapter.
//!
//! # Contract
//!
//! **Input.** The sink calls of one book and one epoch: order-stream records, lane responses
//! and fill TX packets, plus the request payloads ([`SinkStream::payload`], or
//! [`SinkStream::prepare`] once per replayed block). Each lane's records and responses arrive
//! in the lane's order and steps and TX packets in step order; how lanes interleave with each
//! other and with steps is not fixed (`REP_MERGE` fixes no more, 07 §7.1), and the output does
//! not depend on it.
//!
//! **Rebuild.** Events are rebuilt from 05's outputs only:
//!
//! - A lane op `(l, q)` takes effect before the first step `s` with `C_s[l] ≥ q`, so it is in
//!   interval `s − 1` (05 §5.1). Its effect comes from its response record, matched by
//!   `(session, echo_pkt, index)`, and its message: `Ack` of a `New` is `MD_ADD` (side and qty
//!   from the message); `CancelAck` of a `Cancel` is `MD_DELETE(cancel)`; `CancelAck(c)` of a
//!   `Reduce` is `MD_REDUCE` to `open − c`, or `MD_DELETE(cancel)` when `c` is all that was open.
//!   A reject or `Out` changes nothing. A forwarded op (a later step's source) is not a lane op.
//! - A step is `MD_STEP` (every StepRecord, Idle and Shed included, so step ids stay gapless as
//!   the encoder and `MD_SYNC` need). Its maker `Fill` records are its `MD_EXEC`s, in TX order;
//!   a maker `Out(STP)` is a step-op `MD_DELETE(STP)`; a taker `Ack` is a step-op `MD_ADD`
//!   (`via_bbo`) of what is left of the source after its taker fills, summed over the run of
//!   `CONT` steps of that source. `taker` is the source's handle as an oid, 0 without one.
//!
//! Step `s` is pushed to the encoder only once every op its cut covers has a resolution and
//! all `n_tx` of its TX packets arrived; the lane ops of its interval go first, sorted by
//! `(prio_ts, lane, LaneSeq)`. So the encoder sees one sequence whatever the call order.
//!
//! **Event time.** A lane op's `rx_ts` is its packet's priority `rx_ts` (the lane's running
//! maximum, as `vyrn-lane` sets it); a step's, its source's; a step without a source takes the
//! newest time so far; each is raised to the newest time so far, so `rx_ts` never decreases.
//!
//! **Readings** (recorded in 10 §7.9 with their labels): event time above; every step is an
//! `MD_STEP`; exec `ordinal` is the maker `Fill`'s position in the step's TX packets, not the
//! BBO's match ordinal, which no output carries; the lane-op tie order `(prio_ts, lane, seq)`.
//!
//! **Not covered yet** ([`SinkError::Unsupported`]): `Replace`, `CancelAll`, dependency TX
//! packets (`ROLE_DEPS`), unsolicited lane records (expiry, kills), steps without a source that
//! fill (Rescan, Uncross), STP causes other than STP, and the cases replay skips today (`MID`
//! Advance records, `SHED` resends).

use std::collections::{BTreeMap, VecDeque};

use vyrn_replica::BlockInputs;
use vyrn_replica::sink::{
    CutDelta, LaneRec, OUT_STP, Payloads, ROLE_DEPS, ROLE_MAKER, ROLE_TAKER, Rec, Record as Resp,
    RespPkt, Sink, StepEntry, TxEntry,
};
use vyrn_types::{
    BookId, Epoch, Handle, LaneId, LaneSeq, Nanos, PacketFlags, PacketRecord, Qty, RejectReason,
    SessionId, StepId, StepKind, Tick,
};
use vyrn_wire::{Msg, Request};

use crate::mbo::{MboEncoder, PacketSink, StreamError};
use crate::record::{DeleteCause, Side};
use crate::stream::{BookOp, Event, EventKind, oid};

/// Why the adapter stopped. After the first error it ignores every later call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// The encoder refused an event.
    Stream(StreamError),
    /// A packet record without a payload, or a step whose source op is unknown.
    NoPayload,
    /// A response or exec that does not fit the rebuilt book.
    Book,
    /// A case this version does not rebuild (module docs).
    Unsupported(&'static str),
    /// At the end, a step still waits for a resolution or a TX packet.
    Unresolved,
}

/// What a request's messages were, by `(session, pkt_seq)`.
type Msgs = Vec<Option<Msg>>;

/// One numbered lane op.
#[derive(Clone, Copy, Debug)]
struct Op {
    /// Its packet, and whether it is the packet's last numbered op.
    pkt: (SessionId, u32),
    last: bool,
    msg: Option<Msg>,
    prio_ts: u64,
    fwd: bool,
    res: Option<Resp>,
}

/// A packet's numbered ops: lane, first LaneSeq, and each index's offset (`None`: unnumbered).
#[derive(Clone, Debug)]
struct PktOps {
    lane: u8,
    first: u64,
    offset: Vec<Option<u8>>,
}

#[derive(Clone, Copy, Debug)]
struct Src {
    lane: LaneId,
    seq: LaneSeq,
    msg: Option<Msg>,
    prio_ts: u64,
}

#[derive(Clone, Debug)]
struct PendStep {
    step: StepId,
    kind: StepKind,
    src: Option<Src>,
    /// `(lane, C_s[l])` for every lane whose cut moved.
    covers: Vec<(u8, u64)>,
    tx_left: u8,
    taker: Vec<Resp>,
    maker: Vec<(LaneId, Resp)>,
}

#[derive(Clone, Copy, Debug)]
struct Resting {
    side: Side,
    tick: Tick,
    qty: Qty,
}

/// The `MBO` encoder behind a `Sink` (module docs).
pub struct SinkStream<K: PacketSink> {
    enc: MboEncoder,
    out: K,
    err: Option<SinkError>,
    msgs: BTreeMap<(SessionId, u32), Msgs>,
    pkts: BTreeMap<(SessionId, u32), PktOps>,
    /// Lane responses that came before their packet record (immediate rejects).
    early: Vec<(SessionId, u32, Resp)>,
    /// Per lane: the ops from LaneSeq `base[l]` on, and the lane's priority clock.
    ops: Vec<VecDeque<Op>>,
    base: Vec<u64>,
    prio: Vec<u64>,
    cut: Vec<u64>,
    steps: VecDeque<PendStep>,
    book: BTreeMap<u32, Resting>,
    newest: u64,
    /// The source of the last step and its taker fills so far (a `CONT` run).
    taker_acc: Option<((LaneId, LaneSeq), u32)>,
    /// The newest step source, for the `CONT` steps that follow it.
    last_src: Option<Src>,
    scratch: Vec<(u64, u8, u64, BookOp)>,
}

impl<K: PacketSink> SinkStream<K> {
    /// An adapter for a box of `n_lanes` lanes that starts at cut 0 (a tenure's first step 1).
    pub fn new(book: BookId, epoch: Epoch, n_lanes: usize, out: K) -> Self {
        Self {
            enc: MboEncoder::new(book, epoch),
            out,
            err: None,
            msgs: BTreeMap::new(),
            pkts: BTreeMap::new(),
            early: Vec::new(),
            ops: vec![VecDeque::new(); n_lanes],
            base: vec![1; n_lanes],
            prio: vec![0; n_lanes],
            cut: vec![0; n_lanes],
            steps: VecDeque::new(),
            book: BTreeMap::new(),
            newest: 0,
            taker_acc: None,
            last_src: None,
            scratch: Vec::new(),
        }
    }

    /// The first error, if any.
    pub fn error(&self) -> Option<SinkError> {
        self.err
    }

    /// One request payload (its signed bytes and tags), before its packet record arrives.
    pub fn payload(&mut self, bytes: &[u8]) {
        let Ok(req) = Request::parse(bytes) else {
            return; // V1 rejects it; the lane logs no op for it.
        };
        let h = req.header();
        let msgs = req.msgs().map(Result::ok).collect();
        self.msgs.insert((h.session(), h.pkt_seq.get()), msgs);
    }

    /// The payloads of one block's packet records, before `replay_block` runs it.
    pub fn prepare<const N: usize>(&mut self, blk: &BlockInputs<N>, p: &impl Payloads) {
        for r in &blk.lanes {
            if let LaneRec::Pkt(r) = r
                && r.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) == 0
                && let Some(b) = p.get(r)
            {
                self.payload(b);
            }
        }
    }

    /// Ends the epoch and hands back the packet sink.
    pub fn finish(mut self) -> Result<K, SinkError> {
        if let Some(e) = self.err {
            return Err(e);
        }
        if !self.steps.is_empty() {
            return Err(SinkError::Unresolved);
        }
        self.enc.finish(&mut self.out).map_err(SinkError::Stream)?;
        Ok(self.out)
    }

    fn fail(&mut self, e: SinkError) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }

    fn on_packet(&mut self, p: &PacketRecord) -> Result<(), SinkError> {
        if p.flags & PacketFlags::SHED != 0 {
            return Err(SinkError::Unsupported("SHED record"));
        }
        if p.flags & PacketFlags::MID != 0 {
            return Err(SinkError::Unsupported("MID Advance record"));
        }
        if p.flags & PacketFlags::ADVANCE != 0 || p.count == 0 {
            return Ok(());
        }
        let l = usize::from(p.lane.0);
        let key = (p.session, p.pkt_seq);
        let msgs = self.msgs.remove(&key).ok_or(SinkError::NoPayload)?;
        let all = msgs.len() == usize::from(p.count);
        let prio = p.rx_ts.0.max(*self.prio.get(l).ok_or(SinkError::Book)?);
        self.prio[l] = prio;
        let lane = &mut self.ops[l];
        if self.base[l] + lane.len() as u64 != p.first_lane_seq.0 {
            return Err(SinkError::Book);
        }
        let mut offset = Vec::with_capacity(msgs.len());
        let mut n = 0u8;
        for m in &msgs {
            let numbered = all || !matches!(m, Some(Msg::Heartbeat | Msg::ResendReq { .. }));
            offset.push(numbered.then_some(n));
            if numbered {
                n += 1;
                lane.push_back(Op {
                    pkt: key,
                    last: false,
                    msg: *m,
                    prio_ts: prio,
                    fwd: false,
                    res: None,
                });
            }
        }
        if let Some(o) = lane.back_mut().filter(|_| n > 0) {
            o.last = true;
        }
        self.pkts.insert(
            key,
            PktOps {
                lane: p.lane.0,
                first: p.first_lane_seq.0,
                offset,
            },
        );
        let early = std::mem::take(&mut self.early);
        for (s, q, r) in early {
            if (s, q) == key {
                self.resolve(s, q, r)?;
            } else {
                self.early.push((s, q, r));
            }
        }
        Ok(())
    }

    fn op_mut(&mut self, l: usize, seq: u64) -> Option<&mut Op> {
        let i = usize::try_from(seq.checked_sub(*self.base.get(l)?)?).ok()?;
        self.ops.get_mut(l)?.get_mut(i)
    }

    /// One response record of op `(session, pkt_seq, index)`.
    fn resolve(&mut self, s: SessionId, q: u32, r: Resp) -> Result<(), SinkError> {
        let ix = match r {
            Resp::Ack { index, .. }
            | Resp::Fill { index, .. }
            | Resp::Reject { index, .. }
            | Resp::CancelAck { index, .. }
            | Resp::Out { index, .. } => index,
        };
        let Some(pk) = self.pkts.get(&(s, q)) else {
            self.early.push((s, q, r));
            return Ok(());
        };
        let Some(off) = pk.offset.get(usize::from(ix)).copied().flatten() else {
            return Err(SinkError::Unsupported("response to an unnumbered message"));
        };
        let (l, seq) = (usize::from(pk.lane), pk.first + u64::from(off));
        let op = self.op_mut(l, seq).ok_or(SinkError::Book)?;
        if op.res.is_some() {
            return Err(SinkError::Unsupported("several records for one op"));
        }
        op.res = Some(r);
        Ok(())
    }

    fn on_lane_resp(&mut self, p: &RespPkt) -> Result<(), SinkError> {
        if p.resp_seq == 0 {
            return Ok(()); // out of stream (04 §3.2): no op behind it
        }
        if p.echo_pkt == 0 {
            return Err(SinkError::Unsupported("unsolicited lane record"));
        }
        for r in p.records() {
            if matches!(
                r,
                Resp::Reject {
                    reason: RejectReason::Busy,
                    ..
                }
            ) {
                return Err(SinkError::Unsupported("SHED answer"));
            }
            self.resolve(p.session, p.echo_pkt, *r)?;
        }
        Ok(())
    }

    fn on_step(&mut self, e: &StepEntry, ds: &[CutDelta]) -> Result<(), SinkError> {
        let kind = StepKind::from_code(e.kind).ok_or(SinkError::Book)?;
        let src = if e.src_lane_seq.0 == 0 {
            None
        } else if let Some(op) = self.op_mut(usize::from(e.src_lane.0), e.src_lane_seq.0) {
            op.fwd = true;
            let s = Src {
                lane: e.src_lane,
                seq: e.src_lane_seq,
                msg: op.msg,
                prio_ts: op.prio_ts,
            };
            self.last_src = Some(s);
            Some(s)
        } else {
            // A `CONT` step after the cut covered (and dropped) its source op.
            let s = self
                .last_src
                .filter(|s| (s.lane, s.seq) == (e.src_lane, e.src_lane_seq));
            Some(s.ok_or(SinkError::NoPayload)?)
        };
        let mut covers = Vec::new();
        for d in ds.get(..usize::from(e.n_delta)).unwrap_or(ds) {
            let l = usize::from(d.lane.0);
            let c = self.cut.get_mut(l).ok_or(SinkError::Book)?;
            if d.seq.0 < *c {
                return Err(SinkError::Book);
            }
            *c = d.seq.0;
            covers.push((d.lane.0, d.seq.0));
        }
        self.steps.push_back(PendStep {
            step: e.step,
            kind,
            src,
            covers,
            tx_left: e.n_tx,
            taker: Vec::new(),
            maker: Vec::new(),
        });
        Ok(())
    }

    fn on_tx(&mut self, h: &TxEntry, recs: &[Resp]) -> Result<(), SinkError> {
        let st = self
            .steps
            .iter_mut()
            .find(|s| s.step == h.step)
            .ok_or(SinkError::Book)?;
        st.tx_left = st.tx_left.checked_sub(1).ok_or(SinkError::Book)?;
        match h.role {
            ROLE_TAKER => st.taker.extend_from_slice(recs),
            ROLE_MAKER => st.maker.extend(recs.iter().map(|r| (h.lane, *r))),
            ROLE_DEPS => return Err(SinkError::Unsupported("dependency TX packet")),
            _ => return Err(SinkError::Book),
        }
        Ok(())
    }

    /// Pushes every step that is complete and whose covered ops are resolved, in step order.
    fn advance(&mut self) -> Result<(), SinkError> {
        while let Some(st) = self.steps.front() {
            if st.tx_left != 0 || !self.covered_ready(&st.covers) {
                return Ok(());
            }
            let st = self.steps.pop_front().ok_or(SinkError::Book)?;
            self.emit_interval(&st.covers)?;
            self.emit_step(&st)?;
        }
        Ok(())
    }

    fn covered_ready(&self, covers: &[(u8, u64)]) -> bool {
        covers.iter().all(|&(l, hi)| {
            let l = usize::from(l);
            let base = self.base[l];
            let q = &self.ops[l];
            base + q.len() as u64 > hi
                && q.iter()
                    .take((hi + 1 - base) as usize)
                    .all(|o| o.fwd || o.res.is_some())
        })
    }

    /// The lane ops a step's cut covers, popped and pushed in `(prio_ts, lane, seq)` order.
    fn emit_interval(&mut self, covers: &[(u8, u64)]) -> Result<(), SinkError> {
        let mut out = std::mem::take(&mut self.scratch);
        out.clear();
        for &(lc, hi) in covers {
            let l = usize::from(lc);
            while self.base[l] <= hi {
                let seq = self.base[l];
                let op = self.ops[l].pop_front().ok_or(SinkError::Book)?;
                self.base[l] += 1;
                if op.last {
                    self.pkts.remove(&op.pkt);
                }
                if op.fwd {
                    continue;
                }
                let Some(r) = op.res else {
                    return Err(SinkError::Book);
                };
                if let Some(b) = self.lane_op(lc, &op, &r)? {
                    out.push((op.prio_ts, lc, seq, b));
                }
            }
        }
        out.sort_unstable_by_key(|x| (x.0, x.1, x.2));
        let mut res = Ok(());
        for &(ts, _, _, b) in &out {
            res = self.push(ts, EventKind::LaneOp(b));
            if res.is_err() {
                break;
            }
        }
        self.scratch = out;
        res
    }

    /// The book change of one resolved lane op (module docs); the book is read as it was
    /// after the previous step, which is what the lane's B2 saw (05 §7.6).
    fn lane_op(&self, lane: u8, op: &Op, r: &Resp) -> Result<Option<BookOp>, SinkError> {
        let at = |h: Handle| oid(LaneId(lane), h.slot());
        Ok(match (op.msg, *r) {
            (Some(Msg::New { flags, qty, .. }), Resp::Ack { handle, tick, .. }) => {
                Some(BookOp::Add {
                    oid: at(handle),
                    side: side(flags.side),
                    tick,
                    qty,
                    prio_ts: Nanos(op.prio_ts),
                    via_bbo: false,
                    auction: false,
                })
            }
            (
                Some(Msg::Cancel { .. }),
                Resp::CancelAck {
                    handle, canceled, ..
                },
            ) => {
                let o = self.book.get(&at(handle)).ok_or(SinkError::Book)?;
                if o.qty != canceled {
                    return Err(SinkError::Book);
                }
                Some(BookOp::Delete {
                    oid: at(handle),
                    cause: DeleteCause::Cancel,
                    tick: o.tick,
                    qty: canceled,
                })
            }
            (
                Some(Msg::Reduce { .. }),
                Resp::CancelAck {
                    handle, canceled, ..
                },
            ) => {
                let o = self.book.get(&at(handle)).ok_or(SinkError::Book)?;
                let after = o.qty.0.checked_sub(canceled.0).ok_or(SinkError::Book)?;
                Some(if after == 0 {
                    BookOp::Delete {
                        oid: at(handle),
                        cause: DeleteCause::Cancel,
                        tick: o.tick,
                        qty: canceled,
                    }
                } else {
                    BookOp::Reduce {
                        oid: at(handle),
                        tick: o.tick,
                        qty_after: Qty(after),
                    }
                })
            }
            (Some(Msg::Replace { .. }), Resp::Ack { .. } | Resp::CancelAck { .. }) => {
                return Err(SinkError::Unsupported("Replace"));
            }
            (Some(Msg::CancelAll { .. }), Resp::CancelAck { .. }) => {
                return Err(SinkError::Unsupported("CancelAll"));
            }
            (_, Resp::Reject { .. } | Resp::Out { .. }) => None,
            _ => return Err(SinkError::Book),
        })
    }

    fn emit_step(&mut self, st: &PendStep) -> Result<(), SinkError> {
        let ts = st.src.map_or(self.newest, |s| s.prio_ts);
        let n_exec = st
            .maker
            .iter()
            .filter(|(_, r)| matches!(r, Resp::Fill { .. }))
            .count();
        if st.src.is_none() && !st.maker.is_empty() {
            return Err(SinkError::Unsupported("fills without a source step"));
        }
        let taker = st.src.and_then(|s| {
            st.taker.iter().find_map(|r| match *r {
                Resp::Ack { handle, .. } | Resp::Fill { handle, .. } => {
                    Some(oid(s.lane, handle.slot()))
                }
                _ => None,
            })
        });
        self.push(
            ts,
            EventKind::Step {
                step: st.step,
                kind: st.kind,
                n_exec: u16::try_from(n_exec).map_err(|_| SinkError::Book)?,
                taker: taker.unwrap_or(0),
            },
        )?;
        let mut ordinal = 0u16;
        for &(lane, r) in &st.maker {
            match r {
                Resp::Fill {
                    handle, tick, qty, ..
                } => {
                    let maker = oid(lane, handle.slot());
                    let o = self.book.get(&maker).ok_or(SinkError::Book)?;
                    let aggressor = opposite(o.side);
                    self.push(
                        ts,
                        EventKind::Exec {
                            aggressor,
                            ordinal,
                            maker,
                            tick,
                            qty,
                        },
                    )?;
                    ordinal += 1;
                }
                Resp::Out {
                    cause: OUT_STP,
                    handle,
                    qty,
                    ..
                } => {
                    let o = oid(lane, handle.slot());
                    let tick = self.book.get(&o).ok_or(SinkError::Book)?.tick;
                    self.push(
                        ts,
                        EventKind::StepOp(BookOp::Delete {
                            oid: o,
                            cause: DeleteCause::Stp,
                            tick,
                            qty,
                        }),
                    )?;
                }
                _ => return Err(SinkError::Unsupported("maker record")),
            }
        }
        let Some(s) = st.src else { return Ok(()) };
        let key = (s.lane, s.seq);
        let mut filled = match self.taker_acc {
            Some((k, q)) if k == key => q,
            _ => 0,
        };
        for r in &st.taker {
            match *r {
                Resp::Fill { qty, .. } => filled += qty.0,
                Resp::Ack { handle, tick, .. } => {
                    let Some(Msg::New { flags, qty, .. }) = s.msg else {
                        return Err(SinkError::Unsupported("source other than New"));
                    };
                    let left = qty.0.checked_sub(filled).ok_or(SinkError::Book)?;
                    self.push(
                        ts,
                        EventKind::StepOp(BookOp::Add {
                            oid: oid(s.lane, handle.slot()),
                            side: side(flags.side),
                            tick,
                            qty: Qty(left),
                            prio_ts: Nanos(s.prio_ts),
                            via_bbo: true,
                            auction: false,
                        }),
                    )?;
                }
                _ => {}
            }
        }
        self.taker_acc = Some((key, filled));
        Ok(())
    }

    /// Hands one event to the encoder and applies it to the rebuilt book.
    fn push(&mut self, ts: u64, kind: EventKind) -> Result<(), SinkError> {
        let ts = ts.max(self.newest);
        self.newest = ts;
        let ev = Event {
            rx_ts: Nanos(ts),
            kind,
        };
        self.enc
            .push(&ev, &mut self.out)
            .map_err(SinkError::Stream)?;
        match kind {
            EventKind::LaneOp(op) | EventKind::StepOp(op) => self.apply(&op),
            EventKind::Exec { maker, qty, .. } => {
                let o = self.book.get_mut(&maker).ok_or(SinkError::Book)?;
                o.qty = o.qty.checked_sub(qty).ok_or(SinkError::Book)?;
                if o.qty.0 == 0 {
                    self.book.remove(&maker);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn apply(&mut self, op: &BookOp) -> Result<(), SinkError> {
        match *op {
            BookOp::Add {
                oid,
                side,
                tick,
                qty,
                ..
            } => {
                if self.book.insert(oid, Resting { side, tick, qty }).is_some() {
                    return Err(SinkError::Book);
                }
            }
            BookOp::Delete { oid, .. } => {
                self.book.remove(&oid).ok_or(SinkError::Book)?;
            }
            BookOp::Reduce { oid, qty_after, .. } => {
                self.book.get_mut(&oid).ok_or(SinkError::Book)?.qty = qty_after;
            }
        }
        Ok(())
    }
}

const fn side(s: vyrn_wire::Side) -> Side {
    match s {
        vyrn_wire::Side::Buy => Side::Buy,
        vyrn_wire::Side::Sell => Side::Sell,
    }
}

const fn opposite(s: Side) -> Side {
    match s {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
    }
}

impl<K: PacketSink> Sink for SinkStream<K> {
    fn record(&mut self, r: &Rec<'_>) {
        if self.err.is_some() {
            return;
        }
        let res = match r {
            Rec::Packet(p) => self.on_packet(p),
            Rec::Step(e, ds) => self.on_step(e, ds),
            // The op's reject answers it; the route changes nothing in the book.
            Rec::Route(_) => Ok(()),
        };
        if let Err(e) = res.and_then(|()| self.advance()) {
            self.fail(e);
        }
    }

    fn lane_resp(&mut self, _: LaneId, p: &RespPkt) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.on_lane_resp(p).and_then(|()| self.advance()) {
            self.fail(e);
        }
    }

    fn tx(&mut self, h: &TxEntry, recs: &[Resp]) {
        if self.err.is_some() {
            return;
        }
        if let Err(e) = self.on_tx(h, recs).and_then(|()| self.advance()) {
            self.fail(e);
        }
    }

    fn take(&mut self, _: &vyrn_types::AcctTake) {
        self.fail(SinkError::Unsupported("pooled lane"));
    }
}
