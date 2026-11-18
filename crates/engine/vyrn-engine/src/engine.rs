//! Live mode (05 §1.1, 11 §6.4): the shared lines and rings of one box, real lanes and a real BBO
//! core over them, and the roles the engine plays itself: both cut cores, the stream core's
//! `LaneCut` writes, the snapshot fan-out and the fill TX cores' ring reads.

use vyrn_bbo::admit::{Clock, NeverLate};
use vyrn_bbo::{
    Bbo, ControlCons, ControlRing, CutDelta, ENG_CONTROL_RING, FillProd, FwdCons, MAX_LANES, Poll,
    Record, StepEntry, StepLogProd, TxEntry, TxProd, decode_records,
};
use vyrn_cut::{
    BboFloor, Consumer, Counter, CounterLine, CutEntry, CutWriter, ENG_STEP_LOG, ENG_TX_RING,
    FillRing, Floor, FwdRing, HalfCut, HalfCutVal, LANES_PER_HALF, LaneCut, LaneCutEntry, Line64,
    Producer, STEP_LOG_READERS, Snapshot, SnapshotLine, StepLog, TxRing, Visibility,
};
use vyrn_lane::{
    Arena, ArenaConfig, ArenaView, ArenaWriter, Config as LaneConfig, Lane, LaneBook, LogRec,
    Ports, RespPkt, Rx, RxIn,
};
use vyrn_types::{LaneId, LaneSeq, PacketRecord, StepId};

/// Packets per lane whose op range and `prio_ts` replay keeps (`ENG_FWD_RING`).
pub(crate) const PKT_HIST: usize = vyrn_cut::ENG_FWD_RING;
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
}

/// Where the engine's outputs go. Called on the engine's thread, in output order.
pub trait Sink {
    /// The order stream, in the order the engine produced it.
    fn record(&mut self, r: &Rec<'_>);
    /// A lane's response packet (05 §8.10 rules 3 and 4).
    fn lane_resp(&mut self, _lane: LaneId, _p: &RespPkt) {}
    /// A fill TX packet (05 §8.10 rules 1 and 2), after its step's [`Rec::Step`].
    fn tx(&mut self, _h: &TxEntry, _recs: &[Record]) {}
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
    pub(crate) cfgs: Vec<LaneConfig>,
    pub(crate) lanes: Vec<Lane<'a, V, NA>>,
    views: Vec<ArenaView<'a>>,
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
    cut: Vec<LaneSeq>,
    deltas: [CutDelta; MAX_LANES],
    recs: Vec<Record>,
    /// Replay: each lane's recent packets with ops, `(first LaneSeq, last LaneSeq, prio_ts)`,
    /// ring of [`PKT_HIST`] per lane (0 = empty).
    pub(crate) pkts: Vec<(u64, u64, u64)>,
    /// Replay: each lane's `prio_ts` (05 §6.3: `rx_ts` clamped to be non-decreasing).
    pub(crate) prio: Vec<u64>,
    pub(crate) pkt_next: Vec<usize>,
    pub(crate) scratch: Vec<PacketRecord>,
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
            cfgs: cfgs.to_vec(),
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
            cut: vec![LaneSeq(0); n],
            deltas: [CutDelta::default(); MAX_LANES],
            recs: Vec::with_capacity(TX_RECS),
            pkts: vec![(0, 0, 0); n.saturating_mul(PKT_HIST)],
            prio: vec![0; n],
            pkt_next: vec![0; n],
            scratch: Vec::with_capacity(32),
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
    /// The BBO core's newest snapshot.
    pub fn snapshot(&self) -> Option<Snapshot> {
        self.snap.try_read(self.vis)
    }
    /// `C_f[l]` of the newest step.
    pub fn cut(&self) -> &[LaneSeq] {
        &self.cut
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

    /// Both cut cores publish, then the BBO core decides at most one step; the stream core then
    /// writes every `LaneCut` and the fan-out copies the new snapshot to every lane.
    /// `clock` is the BBO core's deadline clock.
    pub fn step<C: Clock, S: Sink>(
        &mut self,
        clock: &C,
        sink: &mut S,
    ) -> Result<Option<StepId>, Fault> {
        self.publish_cut()?;
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
                self.bbo.poll(self.vis, &mut ports, &book, clock)
            };
            match r {
                Poll::Step(s) => {
                    self.read_step(sink)?;
                    return Ok(Some(s));
                }
                Poll::Fault => return Err(Fault::Bbo),
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
            if !stepped && polled == 0 {
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
        for r in lane.drain_log() {
            let LogRec::Packet(p) = r;
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

    /// The stream and fill TX roles read the step just published (05 §4.15, §8.10).
    fn read_step<S: Sink>(&mut self, sink: &mut S) -> Result<(), Fault> {
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
        let s = self.snap.try_read(self.vis).ok_or(Fault::Torn)?;
        for line in self.lane_snaps {
            line.publish(self.vis, &s);
        }
        Ok(())
    }
}

pub(crate) fn lane_id(l: usize) -> LaneId {
    LaneId(u8::try_from(l).unwrap_or(u8::MAX))
}
