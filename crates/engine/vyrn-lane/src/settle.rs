//! The boundary (05 §6.2): B1 applies fill events (§7.4, §7.5, 10 §4.4), B2 settles local ops
//! whose cut position is known (§7.6, `INV-ACK-AFTER-CUT`), B3 packs the records (§8.10 rule 4).

use vyrn_bbo::{
    DEP_ENDED, DEP_JOIN, FillEvent, FillKind, INDEX_MAKER, LIQ_AUCTION, LIQ_MAKER, LIQ_TAKER,
    OUT_FINISHED, Phase, RESTED_DONE, RESTED_IN_FLIGHT, Record,
};
use vyrn_cut::{LaneCutEntry, Visibility};
use vyrn_risk::{FillKind as RiskFill, Risk, Settle};
use vyrn_types::{
    Handle, LaneSeq, PacketFlags, PacketRecord, PktHash, Qty, RejectReason, StepId, Tick,
};
use vyrn_wire::PROTO_HANDLE_ALL;

use crate::lane::{Lane, PROTO_D_CANCELED, PROTO_D_FILLED, PROTO_D_OUT, PendE, PendK, SKind, uix};
use crate::out::{Gate, LogRec, RespPkt};

impl<V: Visibility, const NA: usize> Lane<'_, V, NA> {
    /// Moves every visible fill event into the lane buffer (05 §6.6 `drain_fill_ring_only`).
    pub(crate) fn buffer_events(&mut self, vis: &V) {
        while self.evbuf.len() < self.evbuf.capacity() {
            let Some(line) = self.io.fill.pop(vis) else {
                break;
            };
            self.evbuf.push_back(FillEvent::decode(&line));
        }
    }

    /// `boundary_due` (05 §6.1) with the frame and event gates of the contract (rule G): a
    /// newer `LaneCut`, `done_step ≥` its step (every event of steps ≤ it is in the ring), and
    /// work for B1 or B2.
    pub(crate) fn boundary_due(&mut self, vis: &V) -> Option<LaneCutEntry> {
        let lc = self.io.lane_cut.try_read(vis)?;
        if lc.step <= self.fills_applied {
            return None;
        }
        let snap = self.io.snapshot.try_read(vis)?;
        if snap.done_step < lc.step {
            return None;
        }
        self.buffer_events(vis);
        self.has_work(lc).then_some(lc)
    }

    /// A `LaneCut` newer than `fills_applied` whose step is visible (`done_step ≥` it), work or
    /// not: the catch-up boundary of [`Self::process_packet`].
    pub(crate) fn catch_up_due(&mut self, vis: &V) -> Option<LaneCutEntry> {
        let lc = self.io.lane_cut.try_read(vis)?;
        if lc.step <= self.fills_applied {
            return None;
        }
        let snap = self.io.snapshot.try_read(vis)?;
        (snap.done_step >= lc.step).then_some(lc)
    }

    fn has_work(&self, lc: LaneCutEntry) -> bool {
        let ev = self.evbuf.front().is_some_and(|e| e.step <= lc.step);
        let c = lc.cut.min(self.applied);
        let st = self
            .pend
            .front()
            .is_some_and(|p| p.seq <= c && !self.in_flight(p));
        ev || st
    }

    /// Runs a boundary between packets if one is due (05 §6.1 main loop; idle polls).
    pub fn poll<C: crate::admit::Clock>(&mut self, vis: &V, _clock: &C) -> bool {
        self.refresh_snapshot(vis);
        match self.boundary_due(vis) {
            Some(lc) => {
                self.boundary(vis, lc, None);
                true
            }
            None => false,
        }
    }

    /// A boundary at `(f, C_f[l]) = at`: inside a packet before pass `mid.0` of op `mid.1`, or
    /// between packets. Logged as an Advance record (05 §6.2).
    pub fn boundary(&mut self, vis: &V, at: LaneCutEntry, mid: Option<(u8, LaneSeq)>) {
        if at.step <= self.fills_applied {
            return;
        }
        // The base of later packets' `snap_lag` (05 §6.5). Inside a packet (a MID) the packet
        // keeps the snapshot it was accepted with.
        self.f_snap = at.snap;
        if mid.is_none() && at.snap.version > self.snap.version {
            self.snap = at.snap;
        }
        self.buffer_events(vis);
        // B1.
        let mut step = StepId(0);
        let mut taker: Option<u32> = None;
        loop {
            // Refill as B1 consumes: the ring may hold more events of steps ≤ `at.step` than
            // the buffer took at once (rule G makes them all visible).
            if self.evbuf.is_empty() {
                self.buffer_events(vis);
            }
            let Some(ev) = self.evbuf.front().copied() else {
                break;
            };
            if ev.step > at.step {
                break;
            }
            self.evbuf.pop_front();
            if ev.step != step {
                self.taker_end(taker.take());
                step = ev.step;
            }
            self.apply_event(&ev, &mut taker);
        }
        self.taker_end(taker.take());
        // B2.
        let c = at.cut.min(self.applied);
        while let Some(p) = self.pend.front().copied() {
            if p.seq > c || self.in_flight(&p) {
                break;
            }
            self.pend.pop_front();
            self.settle(&p);
        }
        // B3.
        self.flush_events(None);
        self.pack(at.step);
        self.fills_applied = at.step;
        let (flags, first) = match mid {
            Some((pass, next)) => (
                PacketFlags::ADVANCE
                    | PacketFlags::MID
                    | if pass == 2 { PacketFlags::PASS2 } else { 0 },
                next,
            ),
            None => (PacketFlags::ADVANCE, LaneSeq(self.seq.0.saturating_add(1))),
        };
        self.out.log(LogRec::Packet(PacketRecord {
            lane: self.cfg.lane,
            count: 0,
            flags,
            session: vyrn_types::SessionId(0),
            pkt_seq: 0,
            rx_ts: self.last_prio_ts,
            pkt_hash: PktHash(0),
            first_lane_seq: first,
            fills_applied: at.step,
            snap_lag: 0,
        }));
        self.publish_counter(vis);
    }

    /// An `Ack`/`ReplaceAck` waits while its version is a batch taker in flight (rule B).
    pub(crate) fn in_flight(&self, p: &PendE) -> bool {
        let v = match p.k {
            PendK::Ack => p.v,
            PendK::ReplaceAck => p.w,
            _ => return false,
        };
        self.slot(v).is_some_and(|s| s.in_flight)
    }

    // -----------------------------------------------------------------------------------------
    // B1 (05 §7.4)

    fn apply_event(&mut self, ev: &FillEvent, taker: &mut Option<u32>) {
        let Some(kind) = ev.fill_kind() else {
            self.fault = true;
            return;
        };
        match kind {
            FillKind::Phase => {
                if let Some(p) = u8::try_from(ev.cause).ok().and_then(Phase::from_code) {
                    self.phase = p;
                }
                return;
            }
            FillKind::Band => {
                self.band = (ev.tick, Tick(ev.qty));
                return;
            }
            FillKind::Uncross => {
                // The auction ends (05 §8.8); auction-only remainders and histograms are a
                // follow-up.
                self.phase = Phase::Continuous;
                return;
            }
            _ => {}
        }
        let v = ev.vslot;
        let Some(sp) = self.slot(v).copied() else {
            self.fault = true;
            return;
        };
        let root = sp.root;
        // A `Shed` step's `Dep(BUSY)` events carry the dependency slot and no handle (vyrn-bbo
        // `exec_shed`); every other event names its order.
        let shed_dep = kind == FillKind::Dep && ev.handle == Handle(0);
        if sp.kind == SKind::Free || (ev.handle != self.handle(root) && !shed_dep) {
            self.fault = true;
            return;
        }
        self.mark_executed(ev);
        match kind {
            FillKind::Fill => self.on_fill(ev, taker),
            FillKind::Rested => self.on_rested(ev),
            FillKind::Out | FillKind::Reject => self.on_end(ev, kind),
            FillKind::Dep => self.on_dep(ev),
            _ => {}
        }
    }

    /// Contract rule F: the front forwarded entry is executed once any event of its first step
    /// names its source version or is one of its `Dep` events.
    fn mark_executed(&mut self, ev: &FillEvent) {
        let Some(f) = self.fwd.front().copied() else {
            return;
        };
        let deps = f.dep_slots.get(..usize::from(f.n_dep)).unwrap_or(&[]);
        let hit = match ev.fill_kind() {
            Some(FillKind::Dep) => {
                deps.contains(&ev.vslot) || deps.iter().any(|d| self.same_leg(*d, ev.vslot))
            }
            Some(FillKind::Fill) => ev.vslot == f.vslot && ev.liq == LIQ_TAKER,
            Some(FillKind::Rested | FillKind::Out | FillKind::Reject) => {
                ev.vslot == f.vslot && ev.liq == LIQ_TAKER
            }
            _ => false,
        };
        if hit {
            self.fwd.pop_front();
        }
    }

    fn same_leg(&self, a: u32, b: u32) -> bool {
        let la = self.slot(a).map(|s| s.leg);
        la.is_some() && la == self.slot(b).map(|s| s.leg)
    }

    fn on_fill(&mut self, ev: &FillEvent, taker: &mut Option<u32>) {
        let v = ev.vslot;
        let Some(sp) = self.slot(v).copied() else {
            return;
        };
        let kind = match ev.liq {
            LIQ_MAKER => RiskFill::Maker,
            LIQ_TAKER => RiskFill::Taker,
            LIQ_AUCTION => RiskFill::Auction,
            _ => {
                self.fault = true;
                return;
            }
        };
        if kind == RiskFill::Taker {
            // An explicit Replace took effect at this step even if it never rests or goes out.
            self.end_replaced(sp.leg);
            if taker.is_some_and(|t| t != sp.leg) {
                self.taker_end(taker.take());
            }
            *taker = Some(sp.leg);
        }
        if !self.settle_with(sp.leg, |s, o| s.fill(o, kind, Qty(ev.qty), ev.tick)) {
            return;
        }
        if let Some(s) = self.slot_mut(v) {
            s.filled = s.filled.saturating_add(ev.qty);
            if kind == RiskFill::Taker {
                s.taker_filled = s.taker_filled.saturating_add(ev.qty);
            }
        }
        let filled = self
            .root(sp.root)
            .map_or(0, |r| r.filled)
            .saturating_add(ev.qty);
        // Completion against the version that traded, not a pending later one (`root.cur`).
        let cur_total = sp.total;
        if let Some(r) = self.root_mut(sp.root) {
            r.filled = filled;
            if filled >= cur_total {
                r.ended = true;
                r.end_detail = PROTO_D_FILLED;
            }
        }
        if filled >= cur_total
            && let Some(s) = self.slot_mut(v)
        {
            s.in_flight = false;
        }
        let head = self.slot(sp.leg).copied().unwrap_or_default();
        let h = self.handle(sp.root);
        match kind {
            // A `Rescan` batch join's taker fill: the lane's record (05 §8.10 rule 4).
            RiskFill::Taker if !head.explicit => self.emit(
                v,
                head.sess,
                head.pkt,
                Record::Fill {
                    index: head.ix,
                    liq: LIQ_TAKER,
                    handle: h,
                    tick: ev.tick,
                    qty: Qty(ev.qty),
                },
            ),
            // Auction fills are unsolicited and the lane's (05 §8.9).
            RiskFill::Auction => self.emit(
                v,
                head.sess,
                0,
                Record::Fill {
                    index: INDEX_MAKER,
                    liq: LIQ_AUCTION,
                    handle: h,
                    tick: ev.tick,
                    qty: Qty(ev.qty),
                },
            ),
            _ => {}
        }
    }

    fn on_rested(&mut self, ev: &FillEvent) {
        let v = ev.vslot;
        let Some(sp) = self.slot(v).copied() else {
            return;
        };
        if !sp.explicit {
            // A batch taker: in flight while capped, done otherwise (rule B).
            if let Some(s) = self.slot_mut(v) {
                s.in_flight = match ev.cause {
                    RESTED_IN_FLIGHT => true,
                    RESTED_DONE => false,
                    _ => s.in_flight,
                };
            }
            return;
        }
        self.write_position(v);
        self.end_replaced(v);
    }

    /// A forwarded or dependency new-priority `Replace` took effect at its step: the old
    /// version ends there (np_seq on the BBO side). Its tombstone carries the replace's
    /// `LaneSeq` unless a later cancel already wrote one; its leg's remainder is released.
    fn end_replaced(&mut self, w: u32) {
        let Some(sp) = self.slot(w).copied() else {
            return;
        };
        if sp.kind != SKind::NewPrio || !sp.pred_pending || sp.pred == 0 {
            return;
        }
        let prev = sp.pred;
        if let Some(s) = self.slot_mut(w) {
            s.pred_pending = false;
        }
        self.tombstone(prev, sp.ins_seq, sp.ts);
        self.end_position(prev);
        let old_leg = self.slot(prev).map_or(0, |s| s.leg);
        self.release(old_leg);
        self.true_up(w);
    }

    /// The new version of a `Replace` reserved its whole total, but the predecessor's fills,
    /// now final, are part of it: release them from the new leg (10 §4.4).
    pub(crate) fn true_up(&mut self, w: u32) {
        let Some(s) = self.slot(w).copied() else {
            return;
        };
        if s.kind != SKind::NewPrio || s.trued {
            return;
        }
        if let Some(x) = self.slot_mut(w) {
            x.trued = true;
        }
        let Some(o) = s.risk.filter(|o| !o.closed) else {
            return;
        };
        let filled = self.root(s.root).map_or(0, |r| r.filled);
        let filled_old = filled.saturating_sub(o.settled.0);
        if filled_old == 0 {
            return;
        }
        let rem = o.qty.0.saturating_sub(o.settled.0);
        if filled_old < rem {
            self.settle_with(w, |st, o| st.reduce(o, Qty(filled_old)));
        } else {
            self.release(w);
        }
    }

    /// The predecessor of pending `NewPrio` version `w`, or 0.
    fn pending_pred(&self, w: u32) -> u32 {
        self.slot(w)
            .filter(|s| s.kind == SKind::NewPrio && s.pred_pending)
            .map_or(0, |s| s.pred)
    }

    /// The version before a refused explicit `Replace` is current again.
    fn revert_replace(&mut self, w: u32) {
        let Some(sp) = self.slot(w).copied() else {
            return;
        };
        if sp.kind != SKind::NewPrio || !sp.pred_pending {
            return;
        }
        if let Some(s) = self.slot_mut(w) {
            s.pred_pending = false;
        }
        // Unlink `w` from the chain: its successor (or the root) points at its predecessor.
        let cur = self.root(sp.root).map_or(0, |r| r.cur);
        if cur == w {
            if let Some(r) = self.root_mut(sp.root) {
                r.cur = sp.pred;
            }
            return;
        }
        let mut x = cur;
        while x != 0 {
            let leg = self.slot(x).map_or(0, |s| s.leg);
            if self.slot(leg).is_some_and(|h| h.pred == w) {
                if let Some(h) = self.slot_mut(leg) {
                    h.pred = sp.pred;
                }
                return;
            }
            x = self.pending_pred(leg);
        }
    }

    fn end_root(&mut self, root: u32, detail: u32) {
        if let Some(r) = self.root_mut(root) {
            r.ended = true;
            r.end_detail = detail;
        }
    }

    fn on_end(&mut self, ev: &FillEvent, kind: FillKind) {
        let v = ev.vslot;
        let Some(sp) = self.slot(v).copied() else {
            return;
        };
        let busy = kind == FillKind::Reject && ev.cause == RejectReason::Busy.code();
        let keeps_old = kind == FillKind::Reject
            && sp.kind == SKind::NewPrio
            && [
                RejectReason::BookHalted.code(),
                RejectReason::AuctionPhase.code(),
                RejectReason::TooLate.code(),
                RejectReason::Busy.code(),
            ]
            .contains(&ev.cause);
        if busy {
            self.shed(sp.leg);
        } else {
            self.release(sp.leg);
        }
        if let Some(s) = self.slot_mut(sp.leg) {
            s.dead = true;
        }
        if let Some(s) = self.slot_mut(v) {
            s.in_flight = false;
            if ev.liq == LIQ_TAKER && !s.explicit {
                s.taker_end = true;
            }
        }
        if keeps_old {
            self.revert_replace(v);
            if ev.cause == RejectReason::TooLate.code() {
                self.end_root(sp.root, PROTO_D_FILLED);
            }
        } else {
            if kind == FillKind::Out && ev.cause == OUT_FINISHED {
                let prev = self.pending_pred(v);
                let old_leg = self.slot(prev).map_or(0, |s| s.leg);
                self.release(old_leg);
            }
            self.end_replaced(v);
            // `Reject STP` (04 §6.8) ends an order that was in the matching step, as an `Out`
            // does: later ops find it ended by the exchange, not canceled.
            let stp = kind == FillKind::Reject && ev.cause == RejectReason::Stp.code();
            let d = if (kind == FillKind::Out && ev.cause != OUT_FINISHED) || stp {
                PROTO_D_OUT
            } else {
                PROTO_D_CANCELED
            };
            // A shed `New` never existed (sequential: `BUSY`); later ops find it ended.
            self.end_root(sp.root, d);
        }
        // A batch taker's terminal record is the lane's (05 §8.10 rule 4); every other one was
        // sent by the fill TX core.
        let head = self.slot(sp.leg).copied().unwrap_or_default();
        if ev.liq == LIQ_TAKER && !head.explicit {
            let h = self.handle(sp.root);
            let tag = self.root(sp.root).map_or(0, |r| r.tag);
            let rec = if kind == FillKind::Out {
                Record::Out {
                    index: head.ix,
                    cause: ev.cause,
                    handle: h,
                    qty: Qty(ev.qty),
                    client_tag: tag,
                }
            } else {
                Record::Reject {
                    index: head.ix,
                    reason: RejectReason::from_code(ev.cause).unwrap_or(RejectReason::BadType),
                    detail: 0,
                    client_tag: tag,
                }
            };
            self.emit(v, head.sess, head.pkt, rec);
        }
    }

    fn on_dep(&mut self, ev: &FillEvent) {
        let v = ev.vslot;
        let Some(sp) = self.slot(v).copied() else {
            return;
        };
        let busy = ev.cause == RejectReason::Busy.code();
        if ev.liq == DEP_JOIN {
            match ev.cause {
                0 => {
                    self.write_position(v);
                    self.end_replaced(v);
                }
                DEP_ENDED => {
                    let prev = self.pending_pred(v);
                    let old_leg = self.slot(prev).map_or(0, |s| s.leg);
                    self.release(old_leg);
                    self.release(sp.leg);
                    self.end_replaced(v);
                    self.end_root(sp.root, PROTO_D_CANCELED);
                }
                c => {
                    if busy {
                        self.shed(sp.leg);
                    } else {
                        self.release(sp.leg);
                    }
                    if let Some(s) = self.slot_mut(sp.leg) {
                        s.dead = true;
                    }
                    if sp.kind == SKind::NewPrio {
                        self.revert_replace(v);
                        if c == RejectReason::TooLate.code() {
                            self.end_root(sp.root, PROTO_D_FILLED);
                        }
                    } else {
                        self.end_root(sp.root, PROTO_D_CANCELED);
                    }
                }
            }
        } else if ev.cause == 0 && ev.qty > 0 {
            // A dependency cancel took effect at its step.
            let seq = self.dep_seq_of_cancel(v);
            self.tombstone(v, seq.0, seq.1);
            self.end_position(v);
            self.release(sp.leg);
            if let Some(s) = self.slot_mut(sp.leg) {
                s.dead = true;
            }
            self.end_root(sp.root, PROTO_D_CANCELED);
        }
        // TOO_LATE (qty 0): the order had already ended. BUSY or AUCTION_PHASE: not applied.
    }

    /// `LaneSeq` and ts of the pending dependency cancel that names root of `v`.
    fn dep_seq_of_cancel(&self, v: u32) -> (LaneSeq, vyrn_types::Nanos) {
        let root = self.slot(v).map_or(0, |s| s.root);
        self.dep_cancels
            .iter()
            .find(|(r, _, _)| *r == root)
            .map_or((LaneSeq(0), vyrn_types::Nanos(0)), |(_, s, t)| (*s, *t))
    }

    // -----------------------------------------------------------------------------------------
    // Ledger (10 §4.4)

    /// Runs `f` on the leg's risk record in its account's settlement context. A `Fault` is an
    /// engine fault (05 §14.3).
    fn settle_with(
        &mut self,
        leg: u32,
        f: impl FnOnce(&mut Settle<'_>, &mut vyrn_risk::OrderRisk) -> Result<(), vyrn_risk::Fault>,
    ) -> bool {
        let Some(head) = self.slots.get(uix(leg)).copied() else {
            self.fault = true;
            return false;
        };
        let Some(mut o) = head.risk else {
            self.fault = true;
            return false;
        };
        let acct = self
            .root(head.root)
            .map_or(vyrn_risk::AcctSlot(0), |r| r.acct);
        let Ok((a, bal)) = self.accts.get_mut(acct) else {
            self.fault = true;
            return false;
        };
        let mut s = Settle {
            fees: &a.fees,
            bal,
            book: &mut self.bk,
            tick_size: self.cfg.spec.tick_size,
        };
        if f(&mut s, &mut o).is_err() {
            self.fault = true;
            return false;
        }
        if let Some(h) = self.slots.get_mut(uix(leg)) {
            h.risk = Some(o);
        }
        true
    }

    fn taker_end(&mut self, leg: Option<u32>) {
        if let Some(l) = leg {
            self.settle_with(l, |s, o| s.taker_end(o, true));
        }
    }

    /// Releases the leg's open remainder with `filled_final = settled` (10 §3.9), once.
    pub(crate) fn release(&mut self, leg: u32) {
        let open = self
            .slot(leg)
            .and_then(|s| s.risk)
            .is_some_and(|o| !o.closed);
        if open {
            self.settle_with(leg, |s, o| {
                let f = o.settled;
                s.release(o, f)
            });
        }
    }

    /// 10 §3.11: a shed op is as if it never arrived: reservation, message fee and tokens back.
    fn shed(&mut self, leg: u32) {
        let Some(head) = self.slot(leg).copied() else {
            return;
        };
        let Some(o) = head.risk.filter(|o| !o.closed) else {
            return;
        };
        if !self.settle_with(leg, |s, o| s.shed(o)) {
            return;
        }
        let snap = self.risk_snap();
        let spec = self.cfg.spec;
        let acct = self
            .root(head.root)
            .map_or(vyrn_risk::AcctSlot(0), |r| r.acct);
        let Some(sess) = self.sess.get_mut(head.sess) else {
            return;
        };
        let Ok((a, bal)) = self.accts.get_mut(acct) else {
            return;
        };
        Risk {
            acct: a,
            sess: &mut sess.buckets,
            bal,
            lane: &mut self.lane_bk,
            book: &mut self.bk,
            spec: &spec,
            snap: &snap,
            now: head.ts,
            slot_free: true,
        }
        .refund_shed_tokens(&o);
    }

    // -----------------------------------------------------------------------------------------
    // B2 (05 §7.6)

    fn open_of(&self, root: u32, v: u32) -> u32 {
        let Some(r) = self.root(root) else { return 0 };
        if r.ended {
            return 0;
        }
        self.slot(v).map_or(0, |s| s.total.saturating_sub(r.filled))
    }

    fn settle(&mut self, p: &PendE) {
        let h = self.handle(p.root);
        match p.k {
            PendK::Ack => {
                self.flush_events(Some(p.v));
                let s = self.slot(p.v).copied().unwrap_or_default();
                if !s.taker_end && s.taker_filled < s.total && !s.dead {
                    let tag = self.root(p.root).map_or(0, |r| r.tag);
                    self.stage(
                        p,
                        Record::Ack {
                            index: p.ix,
                            handle: h,
                            tick: s.tick,
                            client_tag: tag,
                        },
                    );
                }
            }
            PendK::CancelAck => {
                self.flush_events(Some(p.v));
                let cur = self.root(p.root).map_or(0, |r| r.cur);
                let open = self.open_of(p.root, cur);
                if open == 0 {
                    let d = self.root(p.root).map_or(PROTO_D_FILLED, |r| r.end_detail);
                    self.stage(
                        p,
                        Record::Reject {
                            index: p.ix,
                            reason: RejectReason::TooLate,
                            detail: d,
                            client_tag: p.tag,
                        },
                    );
                } else {
                    let leg = self.slot(cur).map_or(0, |s| s.leg);
                    self.release(leg);
                    self.end_root(p.root, PROTO_D_CANCELED);
                    self.stage(
                        p,
                        Record::CancelAck {
                            index: p.ix,
                            handle: h,
                            canceled: Qty(open),
                            client_tag: p.tag,
                        },
                    );
                }
            }
            PendK::ReduceAck => {
                self.flush_events(Some(p.v));
                // The open quantity at the reduce: fills on the versions before it (05 §2.3).
                // Fills on its successor `p.w` came later in L, even if they ended the order.
                let leg = self.slot(p.v).map_or(0, |s| s.leg);
                let dead = self.slot(leg).is_some_and(|h| h.dead);
                let r = self.root(p.root).copied().unwrap_or_default();
                let after = self.slot(p.w).map_or(0, |s| s.filled);
                let before = r.filled.saturating_sub(after);
                let ended_early = r.ended && r.end_detail != PROTO_D_FILLED;
                let open = if dead || ended_early {
                    0
                } else {
                    self.slot(p.v).map_or(0, |s| s.total.saturating_sub(before))
                };
                if open == 0 {
                    let d = self.root(p.root).map_or(PROTO_D_FILLED, |r| r.end_detail);
                    self.stage(
                        p,
                        Record::Reject {
                            index: p.ix,
                            reason: RejectReason::TooLate,
                            detail: d,
                            client_tag: p.tag,
                        },
                    );
                    return;
                }
                let canceled = p.r.min(open);
                let rem = self
                    .slot(leg)
                    .and_then(|h| h.risk)
                    .filter(|o| !o.closed)
                    .map_or(0, |o| o.qty.0.saturating_sub(o.settled.0));
                if canceled < rem {
                    self.settle_with(leg, |s, o| s.reduce(o, Qty(canceled)));
                } else {
                    // Nothing can trade after the reduce (its successor filled, or it was 0).
                    self.release(leg);
                }
                if p.r >= open {
                    self.end_root(p.root, PROTO_D_CANCELED);
                }
                self.stage(
                    p,
                    Record::CancelAck {
                        index: p.ix,
                        handle: h,
                        canceled: Qty(canceled),
                        client_tag: p.tag,
                    },
                );
            }
            PendK::ReplaceAck => self.settle_replace(p, h),
            PendK::CancelAllAck => self.settle_cancel_all(p),
        }
    }

    fn settle_replace(&mut self, p: &PendE, h: Handle) {
        self.flush_events(Some(p.v));
        self.flush_events(Some(p.w));
        let old = self.slot(p.v).copied().unwrap_or_default();
        let new = self.slot(p.w).copied().unwrap_or_default();
        let filled = self.root(p.root).map_or(0, |r| r.filled);
        let filled_new = new.risk.map_or(0, |o| o.settled.0);
        let filled_old = filled.saturating_sub(filled_new);
        let old_head = self.slot(old.leg).copied().unwrap_or_default();
        let old_open = if old_head.dead {
            0
        } else {
            old.total.saturating_sub(filled_old)
        };
        let tag = self.root(p.root).map_or(0, |r| r.tag);
        if old_open == 0 {
            // TOO_LATE: the order had ended; the new version never trades (replace_ok).
            self.release(p.w);
            if let Some(s) = self.slot_mut(p.w) {
                s.dead = true;
            }
            let d = self.root(p.root).map_or(PROTO_D_FILLED, |r| r.end_detail);
            self.end_root(p.root, if d == 0 { PROTO_D_FILLED } else { d });
            self.stage(
                p,
                Record::Reject {
                    index: p.ix,
                    reason: RejectReason::TooLate,
                    detail: d,
                    client_tag: tag,
                },
            );
            return;
        }
        self.release(old.leg);
        if new.total <= filled_old {
            // 05 §2.3: `qty' ≤ filled` finishes the order: CancelAck of the old open.
            self.release(p.w);
            self.end_root(p.root, PROTO_D_CANCELED);
            self.stage(
                p,
                Record::CancelAck {
                    index: p.ix,
                    handle: h,
                    canceled: Qty(old_open),
                    client_tag: tag,
                },
            );
            return;
        }
        self.true_up(p.w);
        if !new.taker_end && new.taker_filled < new.total.saturating_sub(filled_old) && !new.dead {
            self.stage(
                p,
                Record::Ack {
                    index: p.ix,
                    handle: h,
                    tick: new.tick,
                    client_tag: tag,
                },
            );
        }
    }

    /// 04 §6.6: one `CancelAck` per canceled order in ascending handle order, then the summary
    /// `CancelAck(PROTO_HANDLE_ALL, count)`.
    fn settle_cancel_all(&mut self, p: &PendE) {
        let Some(s) = self.sess.get(p.sess).copied() else {
            return;
        };
        let mut r = s.first;
        let mut count = 0u32;
        while r != 0 {
            let Some(rp) = self.root(r).copied() else {
                break;
            };
            let cur = self.slot(rp.cur).copied().unwrap_or_default();
            if rp.live && !rp.ended && cur.ins_seq < p.seq {
                let open = self.open_of(r, rp.cur);
                if open > 0 {
                    self.flush_events(Some(rp.cur));
                    self.release(cur.leg);
                    self.end_root(r, PROTO_D_CANCELED);
                    let h = self.handle(r);
                    self.stage(
                        p,
                        Record::CancelAck {
                            index: p.ix,
                            handle: h,
                            canceled: Qty(open),
                            client_tag: p.tag,
                        },
                    );
                    count = count.saturating_add(1);
                }
            }
            r = rp.next;
        }
        self.stage(
            p,
            Record::CancelAck {
                index: p.ix,
                handle: Handle(PROTO_HANDLE_ALL),
                canceled: Qty(count),
                client_tag: p.tag,
            },
        );
    }

    // -----------------------------------------------------------------------------------------
    // B3 (05 §8.10 rule 4)

    fn stage(&mut self, p: &PendE, r: Record) {
        self.b3.push((p.sess, p.pkt, r));
    }

    /// A record of an event that the lane, not the fill TX core, sends; held until the settle
    /// of the op that created or ended version `v`, or the end of B2.
    fn emit(&mut self, v: u32, sess: u16, pkt: u32, r: Record) {
        self.emitq.push((v, sess, pkt, r));
    }

    /// Moves held event records of version `v` (all of them for `None`) to B3, in event order.
    fn flush_events(&mut self, v: Option<u32>) {
        let mut i = 0;
        while i < self.emitq.len() {
            let take = self
                .emitq
                .get(i)
                .is_some_and(|e| v.is_none_or(|v| e.0 == v));
            if take {
                let (_, s, pkt, r) = self.emitq.remove(i);
                self.b3.push((s, pkt, r));
            } else {
                i = i.saturating_add(1);
            }
        }
    }

    /// Packs B3 records into response packets: consecutive records of one `(session, echo_pkt)`
    /// share a packet of ≤ 16; `resp_seq` follows emission order per session.
    fn pack(&mut self, f: StepId) {
        let recs = core::mem::take(&mut self.b3);
        let mut cur: Option<(u16, RespPkt)> = None;
        for (si, pkt, r) in recs.iter().copied() {
            let fits = cur
                .as_ref()
                .is_some_and(|(s, p)| *s == si && p.echo_pkt == pkt && !p.full());
            if !fits {
                if let Some((_, p)) = cur.take() {
                    self.out.resp(p);
                }
                let Some(s) = self.sess.get_mut(si) else {
                    continue;
                };
                let rs = s.next_resp;
                s.next_resp = s.next_resp.wrapping_add(1);
                cur = Some((si, RespPkt::new(s.id, rs, pkt, Gate::Step(f))));
            }
            if let Some((_, p)) = cur.as_mut() {
                p.push(r);
            }
        }
        if let Some((_, p)) = cur.take() {
            self.out.resp(p);
        }
        self.b3 = recs;
        self.b3.clear();
    }
}
