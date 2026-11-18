//! Live mode (05 §1.1, 11 §6.4): the shared lines and rings of one box, real lanes and a real BBO
//! core over them, and the roles the engine plays itself: both cut cores, the stream core's
//! `LaneCut` writes, the snapshot fan-out and the fill TX cores' ring reads.

use vyrn_bbo::admit::{Clock, NeverLate};
use vyrn_bbo::{
    Bbo, ControlCmd, ControlCons, ControlRing, Cut, CutDelta, Diverge, ENG_CONTROL_RING, FillProd,
    FwdCons, MAX_LANES, Poll, Record, StepEntry, StepLogProd, TxEntry, TxProd, decode_records,
};
use vyrn_cut::{
    BboFloor, Consumer, Counter, CounterLine, CutEntry, CutWriter, ENG_STEP_LOG, ENG_TX_RING,
    FillRing, Floor, FwdRing, HalfCut, HalfCutVal, LANES_PER_HALF, LaneCut, LaneCutEntry, Line64,
    PoolTok, Producer, STEP_LOG_READERS, Snapshot, SnapshotLine, StepLog, TxRing, Visibility,
};
use vyrn_lane::{
    Arena, ArenaConfig, ArenaView, ArenaWriter, Config as LaneConfig, Lane, LaneBook, LogRec, Mid,
    Ports, RespPkt, Rx, RxIn,
};
use vyrn_risk::Route;
use vyrn_types::{
    AccountId, AcctTake, LaneId, LaneSeq, PacketRecord, RouteRecord, SessionId, StepId,
};

/// Steps whose cut replay keeps for `MID` boundaries (`ENG_STEP_LOG`).
pub(crate) const STEP_HIST: usize = ENG_STEP_LOG;
/// Lane records 07 replay can carry from one block to the next (`ENG_FWD_RING` × 4).
pub(crate) const CARRY_CAP: usize = 4 * vyrn_cut::ENG_FWD_RING;
/// Records one fill TX packet can carry (`TxEntry.n_rec` is a `u8`).
const TX_RECS: usize = 256;
/// Polls per step before the engine reports no step (`Bbo::poll` may return `Idle` while it
/// consumes ring heads).
const POLLS_PER_STEP: usize = 4;

/// One element of the order stream (01 §6.6), as the engine emits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rec<'d> {
    /// A lane's `PacketRecord`, including `SHED` and Advance records.
    Packet(PacketRecord),
    /// A step with its changed cut entries (05 §4.15).
    Step(StepEntry, &'d [CutDelta]),
    /// The route of an op its lane classified `Cross` or `Improve`, forwarded or rejected by the
    /// lane itself (07 §3.6 `RouteRecord`, G12). The lane writes it in pass 1, so it comes
    /// before its packet's `PacketRecord` in the lane's output.
    Route(RouteRecord),
}

/// Where the engine's outputs go. Called on the engine's thread, in output order.
pub trait Sink {
    /// The order stream, in the order the engine produced it.
    fn record(&mut self, r: &Rec<'_>);
    /// A lane's response packet (05 §8.10 rules 3 and 4).
    fn lane_resp(&mut self, _lane: LaneId, _p: &RespPkt) {}
    /// A fill TX packet (05 §8.10 rules 1 and 2), after its step's [`Rec::Step`].
    fn tx(&mut self, _h: &TxEntry, _recs: &[Record]) {}
    /// A pooled lane's token take (01 §14.17.4, 05 §6.9): an order-stream element, called
    /// right before the [`Rec::Packet`] it covers.
    fn take(&mut self, _t: &AcctTake) {}
}

/// A fault (05 §14.3): the caller fail-stops the sequencer (live) or the replica (replay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Lane(LaneId),
    Bbo,
    /// A half-cut went back (`INV-CUT-MONO`).
    CutNotMonotone,
    /// A seqlocked line could not be read on the engine's own thread.
    Torn,
    /// No such lane.
    NoLane,
    /// A ring did not hold the lines its header announced.
    Ring,
    /// A pooled account's token was held, or its `ver` ran out (`INV-WRITER`, 05 §6.9).
    Pool(LaneId),
}

/// Every line and ring of one box (05 §4.1), owned in one place so the split handles can borrow
/// it. Built before `seal()`.
pub struct Shared<V: Visibility> {
    arenas: Vec<Arena>,
    fwd: Vec<FwdRing<V>>,
    fill: Vec<FillRing<V>>,
    counters: Vec<CounterLine<V>>,
    lane_cuts: Vec<LaneCut<V>>,
    lane_snaps: Vec<SnapshotLine<V>>,
    half_a: HalfCut<V>,
    half_b: HalfCut<V>,
    ctl: ControlRing<V>,
    log: StepLog<V>,
    tx: Vec<TxRing<V>>,
    snap: SnapshotLine<V>,
    floor: BboFloor<V>,
}

impl<V: Visibility> Shared<V> {
    /// `n` lanes (≤ [`MAX_LANES`], ≤ two halves), each arena `arena`, every snapshot line at
    /// `init` (the BBO core's `initial_snapshot`).
    pub fn new(vis: &V, n: usize, arena: ArenaConfig, init: &Snapshot) -> Option<Box<Self>> {
        if n == 0 || n > MAX_LANES || n > LANES_PER_HALF.saturating_mul(2) {
            return None;
        }
        let c0 = Counter {
            snap_ver: u32::try_from(init.version).ok()?,
            ..Counter::default()
        };
        Some(Box::new(Self {
            arenas: (0..n).map(|_| Arena::new(arena)).collect(),
            fwd: (0..n).map(|_| FwdRing::new(vis)).collect(),
            fill: (0..n).map(|_| FillRing::new(vis)).collect(),
            counters: (0..n).map(|_| CounterLine::new(vis, &c0)).collect(),
            lane_cuts: (0..n)
                .map(|_| LaneCut::new(vis, &LaneCutEntry::default()))
                .collect(),
            lane_snaps: (0..n).map(|_| SnapshotLine::new(vis, init)).collect(),
            half_a: HalfCut::new(vis, &HalfCutVal::default()),
            half_b: HalfCut::new(vis, &HalfCutVal::default()),
            ctl: ControlRing::new(vis),
            log: StepLog::new(vis),
            tx: (0..2).map(|_| TxRing::new(vis)).collect(),
            snap: SnapshotLine::new(vis, init),
            floor: BboFloor::new(vis, &Floor::default()),
        }))
    }
}

type StepLogCons<'a, V> = Consumer<'a, Line64, ENG_STEP_LOG, STEP_LOG_READERS, V>;

/// One box: `NA` lane-local accounts per lane (`vyrn_lane::Lane`'s parameter).
pub struct Engine<'a, V: Visibility, const NA: usize> {
    pub(crate) vis: &'a V,
    pub(crate) lanes: Vec<Lane<'a, V, NA>>,
    pub(crate) views: Vec<ArenaView<'a>>,
    fwd_c: Vec<FwdCons<'a, V>>,
    fill_p: Vec<FillProd<'a, V>>,
    ctl_p: Producer<'a, Line64, ENG_CONTROL_RING, 1, V>,
    ctl_c: ControlCons<'a, V>,
    log_p: StepLogProd<'a, V>,
    log_c: [StepLogCons<'a, V>; STEP_LOG_READERS],
    tx_p: Vec<TxProd<'a, V>>,
    tx_c: Vec<Consumer<'a, Line64, ENG_TX_RING, 1, V>>,
    counters: &'a [CounterLine<V>],
    lane_cuts: &'a [LaneCut<V>],
    lane_snaps: &'a [SnapshotLine<V>],
    half_a: &'a HalfCut<V>,
    half_b: &'a HalfCut<V>,
    snap: &'a SnapshotLine<V>,
    floor: &'a BboFloor<V>,
    cw: [CutWriter; 2],
    pub(crate) bbo: Bbo,
    /// `C_f[l]` of the newest step.
    pub(crate) cut: Cut,
    deltas: [CutDelta; MAX_LANES],
    /// `C_f` of the last [`STEP_HIST`] steps, `n` entries per step, keyed by `f mod STEP_HIST`;
    /// `hist_id` holds the step each slot is for (step 0, the epoch start, is all zeros).
    hist: Vec<LaneSeq>,
    hist_id: Vec<StepId>,
    recs: Vec<Record>,
    pub(crate) scratch: Vec<PacketRecord>,
    /// A step the BBO core published whose lines the stream role has not seen yet (a delayed
    /// `Visibility`, such as `Sim`): read before the BBO core is polled again.
    unread: Option<StepId>,
    /// Per lane: `(session, account, token)` of each pooled session ([`Engine::pool_session`]).
    pool: Vec<Vec<(SessionId, AccountId, &'a PoolTok)>>,
    /// 07 replay: lane records carried to the next block (07 §7.1 `REP_MERGE` item 3), and the
    /// buffer the next carry is built in. Both hold [`CARRY_CAP`] records.
    pub(crate) carry: Vec<PacketRecord>,
    pub(crate) carry_next: Vec<PacketRecord>,
    /// The route records of the carried packets, and the buffer the next one is built in.
    pub(crate) carry_routes: Vec<RouteRecord>,
    pub(crate) carry_routes_next: Vec<RouteRecord>,
}

impl<'a, V: Visibility, const NA: usize> Engine<'a, V, NA> {
    /// Splits `shared` and builds one lane per entry of `cfgs` with `mk` (which opens the
    /// lane's accounts: `vyrn_lane::Lane::new` needs a `vyrn_risk::AcctRisk`, a crate this one
    /// does not depend on, 11 §1.4). Allocates everything: call before `seal()`.
    pub fn new(
        vis: &'a V,
        shared: &'a mut Shared<V>,
        bbo: Bbo,
        cfgs: &[LaneConfig],
        mut mk: impl FnMut(LaneConfig, ArenaWriter<'a>, Ports<'a, V>) -> Lane<'a, V, NA>,
    ) -> Option<Self> {
        let Shared {
            arenas,
            fwd,
            fill,
            counters,
            lane_cuts,
            lane_snaps,
            half_a,
            half_b,
            ctl,
            log,
            tx,
            snap,
            floor,
        } = shared;
        let n = arenas.len();
        if cfgs.len() != n {
            return None;
        }
        let (mut lanes, mut views, mut fwd_c, mut fill_p) = (
            Vec::with_capacity(n),
            Vec::with_capacity(n),
            Vec::with_capacity(n),
            Vec::with_capacity(n),
        );
        let it = arenas
            .iter_mut()
            .zip(fwd.iter_mut())
            .zip(fill.iter_mut())
            .zip(counters.iter())
            .zip(lane_cuts.iter())
            .zip(lane_snaps.iter())
            .zip(cfgs);
        for ((((((a, fw), fi), counter), lane_cut), snapshot), cfg) in it {
            let (aw, av) = a.split()?;
            let (fp, [fc]) = fw.split()?;
            let (ip, [ic]) = fi.split()?;
            let ports = Ports {
                fwd: fp,
                fill: ic,
                counter,
                snapshot,
                lane_cut,
            };
            lanes.push(mk(*cfg, aw, ports));
            views.push(av);
            fwd_c.push(fc);
            fill_p.push(ip);
        }
        let (mut tx_p, mut tx_c) = (Vec::with_capacity(2), Vec::with_capacity(2));
        for r in tx.iter_mut() {
            let (p, [c]) = r.split()?;
            tx_p.push(p);
            tx_c.push(c);
        }
        let (ctl_p, [ctl_c]) = ctl.split()?;
        let (log_p, log_c) = log.split()?;
        Some(Self {
            vis,
            lanes,
            views,
            fwd_c,
            fill_p,
            ctl_p,
            ctl_c,
            log_p,
            log_c,
            tx_p,
            tx_c,
            counters,
            lane_cuts,
            lane_snaps,
            half_a,
            half_b,
            snap,
            floor,
            cw: [CutWriter::new(), CutWriter::new()],
            bbo,
            cut: [LaneSeq(0); MAX_LANES],
            deltas: [CutDelta::default(); MAX_LANES],
            hist: vec![LaneSeq(0); n.saturating_mul(STEP_HIST)],
            hist_id: vec![StepId(0); STEP_HIST],
            recs: Vec::with_capacity(TX_RECS),
            scratch: Vec::with_capacity(32),
            unread: None,
            pool: (0..n).map(|_| Vec::new()).collect(),
            carry: Vec::with_capacity(CARRY_CAP),
            carry_next: Vec::with_capacity(CARRY_CAP),
            carry_routes: Vec::with_capacity(CARRY_CAP),
            carry_routes_next: Vec::with_capacity(CARRY_CAP),
        })
    }

    /// Lanes in the box.
    pub fn n_lanes(&self) -> usize {
        self.lanes.len()
    }
    /// Lane `l` (control path before `seal()`: sessions, accounts; observers after).
    pub fn lane(&self, l: usize) -> Option<&Lane<'a, V, NA>> {
        self.lanes.get(l)
    }
    pub fn lane_mut(&mut self, l: usize) -> Option<&mut Lane<'a, V, NA>> {
        self.lanes.get_mut(l)
    }
    pub fn bbo(&self) -> &Bbo {
        &self.bbo
    }
    /// The control ring's producer end (control role, core 0: auction and `Control` steps).
    pub fn control(&mut self) -> &mut Producer<'a, Line64, ENG_CONTROL_RING, 1, V> {
        &mut self.ctl_p
    }
    /// The control role queues `c` for the BBO core, which executes it as the next step
    /// (`Control`, `Uncross` or `Seal`, 05 §8.8). `false` if the control ring is full.
    ///
    /// Replay: the order stream does not carry the command (05 §10 rows 4–5 take only the
    /// step's kind), so a replayer queues the same commands, in order, before
    /// [`Engine::replay`]; the BBO core holds each until the step that names it.
    pub fn command(&mut self, c: &ControlCmd) -> bool {
        self.ctl_p.push(self.vis, c.encode()).is_ok()
    }
    /// Lane `l` is pooled and `session` on it belongs to pooled `account`, whose token is
    /// `tok` (one `PoolTok` per account, shared by every pool lane). From then on each record
    /// of that session takes the token, logs [`AcctTake`] through [`Sink::take`] and releases
    /// it (05 §6.9). Pair with `Lane::set_pool_index` and `vyrn_bbo::Config::pool`, which make
    /// STP and kills compare the account across the pool. Configuration, before `seal()`.
    /// `false` if `l` is not a lane.
    pub fn pool_session(
        &mut self,
        l: usize,
        session: SessionId,
        account: AccountId,
        tok: &'a PoolTok,
    ) -> bool {
        match self.pool.get_mut(l) {
            Some(p) => {
                p.retain(|(s, _, _)| *s != session);
                p.push((session, account, tok));
                true
            }
            None => false,
        }
    }
    /// The BBO core's newest snapshot.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.snap.try_read(self.vis)
    }
    /// `C_f[l]` of the newest step.
    pub fn cut(&self) -> &[LaneSeq] {
        self.cut.get(..self.lanes.len()).unwrap_or(&[])
    }

    /// Live: lane `l` processes one received packet. `clock` is the lane's deadline clock.
    pub fn ingest<C: Clock, S: Sink>(
        &mut self,
        l: usize,
        p: RxIn<'_>,
        clock: &C,
        sink: &mut S,
    ) -> Result<Rx, Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        let r = lane.process_packet(self.vis, p, clock, &[]);
        self.drain(l, sink)?;
        Ok(r)
    }

    /// Replay: lane `l` replays one logged packet with its boundaries and forwarded ops given
    /// (`vyrn_lane::Lane::replay_packet`).
    pub(crate) fn replay_ingest<C: Clock, S: Sink>(
        &mut self,
        l: usize,
        p: RxIn<'_>,
        clock: &C,
        mids: &[Mid],
        routes: &[(LaneSeq, Route)],
        sink: &mut S,
    ) -> Result<Rx, Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        let r = lane.replay_packet(self.vis, p, clock, mids, routes);
        self.drain(l, sink)?;
        Ok(r)
    }

    /// Replay: lane `l` replays one logged `SHED` record without its payload
    /// (`vyrn_lane::Lane::replay_shed`, 05 §18 Q17).
    pub(crate) fn replay_shed<S: Sink>(
        &mut self,
        l: usize,
        rec: &PacketRecord,
        sink: &mut S,
    ) -> Result<Rx, Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        let r = lane.replay_shed(rec);
        self.drain(l, sink)?;
        Ok(r)
    }

    /// Both cut cores publish, then the BBO core decides at most one step; the stream core then
    /// writes every `LaneCut` and the fan-out copies the new snapshot to every lane.
    /// `clock` is the BBO core's deadline clock.
    pub fn step<C: Clock, S: Sink>(
        &mut self,
        clock: &C,
        sink: &mut S,
    ) -> Result<Option<StepId>, Fault> {
        self.drive(sink, |bbo, vis, ports, book| {
            Ok(bbo.poll(vis, ports, book, clock))
        })
        .map_err(|e| match e {
            StepErr::Fault(f) => f,
            StepErr::Diverge(_) => Fault::Bbo,
        })
    }

    /// Both cut cores publish, then `decide` runs the BBO core until it publishes a step (or
    /// [`POLLS_PER_STEP`] passes go by); then the stream and fan-out roles read the step. A
    /// step whose lines are not visible yet stays unread: the next call reads it instead of
    /// polling the BBO core, and returns its id then.
    pub(crate) fn drive<S: Sink>(
        &mut self,
        sink: &mut S,
        mut decide: impl FnMut(
            &mut Bbo,
            &V,
            &mut vyrn_bbo::Ports<'_, 'a, V>,
            &LaneBook<'_, 'a>,
        ) -> Result<Poll, Diverge>,
    ) -> Result<Option<StepId>, StepErr> {
        if let Some(s) = self.unread {
            return self.read_step(s, sink).map_err(StepErr::Fault);
        }
        self.publish_cut().map_err(StepErr::Fault)?;
        for _ in 0..POLLS_PER_STEP {
            let r = {
                let mut ports = vyrn_bbo::Ports {
                    half_a: self.half_a,
                    half_b: self.half_b,
                    fwd: &mut self.fwd_c,
                    control: &mut self.ctl_c,
                    fill: &mut self.fill_p,
                    step_log: &mut self.log_p,
                    tx: &mut self.tx_p,
                    snapshot: self.snap,
                    floor: self.floor,
                };
                let book = LaneBook::new(&self.views);
                decide(&mut self.bbo, self.vis, &mut ports, &book).map_err(StepErr::Diverge)?
            };
            match r {
                Poll::Step(s) => {
                    self.unread = Some(s);
                    return self.read_step(s, sink).map_err(StepErr::Fault);
                }
                Poll::Fault => return Err(StepErr::Fault(Fault::Bbo)),
                Poll::Idle | Poll::Stalled => {}
            }
        }
        Ok(None)
    }

    /// Every lane runs the boundary that is due, if any (05 §6.1 idle polls). Returns the
    /// number of boundaries run.
    pub fn poll_lanes<S: Sink>(&mut self, sink: &mut S) -> Result<usize, Fault> {
        let mut n = 0usize;
        for l in 0..self.lanes.len() {
            if self.poll_lane(l, sink)? {
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// Lane `l`'s idle poll: `true` if it ran a boundary.
    pub(crate) fn poll_lane<S: Sink>(&mut self, l: usize, sink: &mut S) -> Result<bool, Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        let ran = lane.poll(self.vis, &NeverLate);
        self.drain(l, sink)?;
        Ok(ran)
    }

    /// Replay of lane `l`'s non-`MID` Advance record: the boundary at `at = (f, C_f[l])` that
    /// the record names, not an idle poll on the newest `LaneCut`. Live, a poll may have read an
    /// older `LaneCut` (a delayed backend), and the record logs which one (F3a).
    pub(crate) fn replay_advance<S: Sink>(
        &mut self,
        l: usize,
        at: LaneCutEntry,
        sink: &mut S,
    ) -> Result<(), Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        lane.boundary(self.vis, at, None);
        self.drain(l, sink)
    }

    /// Steps and lane polls until neither has work, at most `rounds` rounds. `true` if quiet.
    pub fn run<C: Clock, S: Sink>(
        &mut self,
        clock: &C,
        sink: &mut S,
        rounds: usize,
    ) -> Result<bool, Fault> {
        for _ in 0..rounds {
            let stepped = self.step(clock, sink)?.is_some();
            let polled = self.poll_lanes(sink)?;
            if !stepped && polled == 0 && self.unread.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn drain<S: Sink>(&mut self, l: usize, sink: &mut S) -> Result<(), Fault> {
        let lane = self.lanes.get_mut(l).ok_or(Fault::NoLane)?;
        let id = lane_id(l);
        for p in lane.drain_responses() {
            sink.lane_resp(id, &p);
        }
        let pool = self.pool.get(l).map_or(&[][..], Vec::as_slice);
        for r in lane.drain_log() {
            let p = match r {
                LogRec::Packet(p) => p,
                // An op's route (07 §3.6) covers no account write, so it takes no token.
                LogRec::Route(x) => {
                    sink.record(&Rec::Route(x));
                    continue;
                }
            };
            if let Some((_, account, tok)) = pool.iter().find(|(s, _, _)| *s == p.session) {
                // Spec gap (PR body): the engine plays every pool core on one thread, so the
                // lane's work for this record is already done and no other core can have
                // written the account meanwhile. The take is logged before the record it
                // covers, which is the order 05 §6.9 requires.
                let ver = tok.try_take(id).map_err(|_| Fault::Pool(id))?;
                sink.take(&AcctTake {
                    lane: id,
                    account: *account,
                    ver,
                    lane_seq: p.first_lane_seq,
                });
                tok.release(id).map_err(|_| Fault::Pool(id))?;
            }
            sink.record(&Rec::Packet(p));
        }
        if lane.fault() {
            return Err(Fault::Lane(id));
        }
        Ok(())
    }

    /// The cut cores (05 §7.1): every `CounterLine` into its half, both halves published.
    fn publish_cut(&mut self) -> Result<(), Fault> {
        let mut h = [HalfCutVal::default(), HalfCutVal::default()];
        for (l, c) in self.counters.iter().enumerate() {
            let c = c.try_read(self.vis).ok_or(Fault::Torn)?;
            let (half, i) = if l < LANES_PER_HALF {
                (0, l)
            } else {
                (1, l.wrapping_sub(LANES_PER_HALF))
            };
            let e = h
                .get_mut(half)
                .and_then(|v| v.entries.get_mut(i))
                .ok_or(Fault::NoLane)?;
            *e = CutEntry {
                seq: c.seq,
                snap_ver: c.snap_ver,
                f_lo: c.f_lo,
            };
        }
        let [ha, hb] = &h;
        let [wa, wb] = &mut self.cw;
        wa.publish(self.half_a, self.vis, ha)
            .map_err(|_| Fault::CutNotMonotone)?;
        wb.publish(self.half_b, self.vis, hb)
            .map_err(|_| Fault::CutNotMonotone)?;
        Ok(())
    }

    /// One `StepLog` line, popped from every reader (the engine plays all of them).
    fn pop_log(&mut self) -> Option<Line64> {
        let mut out = None;
        for c in &mut self.log_c {
            let line = c.pop(self.vis);
            if out.is_none() {
                out = line;
            }
        }
        out
    }

    /// The stream and fill TX roles read step `s` (05 §4.15, §8.10) once it is visible:
    /// `Some(s)` if read, `None` if not yet. The BBO core publishes its snapshot (with
    /// `done_step = s`) after the step's log, fill and TX lines, so a snapshot at `s` means
    /// every line of the step is visible (each ring's lines go out in one `push_all`).
    fn read_step<S: Sink>(&mut self, s: StepId, sink: &mut S) -> Result<Option<StepId>, Fault> {
        let snap = match self.snap.try_read(self.vis) {
            Some(x) if x.done_step >= s => x,
            _ => return Ok(None),
        };
        self.unread = None;
        let entry = StepEntry::decode(&self.pop_log().ok_or(Fault::Ring)?);
        let n_delta = usize::from(entry.n_delta);
        let mut k = 0usize;
        while k < n_delta {
            let line = self.pop_log().ok_or(Fault::Ring)?;
            for d in CutDelta::decode_line(&line) {
                if k < n_delta {
                    if let Some(x) = self.deltas.get_mut(k) {
                        *x = d;
                    }
                    if let Some(c) = self.cut.get_mut(usize::from(d.lane.0)) {
                        *c = d.seq;
                    }
                    k = k.saturating_add(1);
                }
            }
        }
        self.remember_cut(entry.step);
        let deltas = self.deltas.get(..n_delta).ok_or(Fault::Ring)?;
        sink.record(&Rec::Step(entry, deltas));
        for c in &mut self.tx_c {
            while let Some(h) = c.pop(self.vis) {
                let h = TxEntry::decode(&h);
                self.recs.clear();
                let n_rec = usize::from(h.n_rec);
                while self.recs.len() < n_rec {
                    let line = c.pop(self.vis).ok_or(Fault::Ring)?;
                    for r in decode_records(&line).into_iter().flatten() {
                        if self.recs.len() < n_rec {
                            self.recs.push(r);
                        }
                    }
                }
                sink.tx(&h, &self.recs);
            }
        }
        // The stream core writes LaneCut after the frame; then the snapshot fan-out.
        for (lc, c) in self.lane_cuts.iter().zip(&self.cut) {
            lc.publish(
                self.vis,
                &LaneCutEntry {
                    step: entry.step,
                    cut: *c,
                },
            );
        }
        for line in self.lane_snaps {
            line.publish(self.vis, &snap);
        }
        Ok(Some(s))
    }
}

impl<V: Visibility, const NA: usize> Engine<'_, V, NA> {
    fn slot(f: StepId) -> usize {
        usize::try_from(f.0)
            .ok()
            .and_then(|x| x.checked_rem(STEP_HIST))
            .unwrap_or(0)
    }

    fn remember_cut(&mut self, f: StepId) {
        let n = self.lanes.len();
        let s = Self::slot(f);
        let base = s.saturating_mul(n);
        if let (Some(dst), Some(src)) = (
            self.hist.get_mut(base..base.saturating_add(n)),
            self.cut.get(..n),
        ) {
            dst.copy_from_slice(src);
        }
        if let Some(id) = self.hist_id.get_mut(s) {
            *id = f;
        }
    }

    /// `C_f[l]`, if step `f` is still in the history.
    pub(crate) fn cut_at(&self, f: StepId, l: usize) -> Option<LaneSeq> {
        let s = Self::slot(f);
        if *self.hist_id.get(s)? != f {
            return None;
        }
        self.hist
            .get(s.saturating_mul(self.lanes.len()).saturating_add(l))
            .copied()
    }
}

/// Why [`Engine::drive`] stopped.
pub(crate) enum StepErr {
    Fault(Fault),
    /// The BBO core refused a replayed step.
    Diverge(Diverge),
}

pub(crate) fn lane_id(l: usize) -> LaneId {
    LaneId(u8::try_from(l).unwrap_or(u8::MAX))
}
