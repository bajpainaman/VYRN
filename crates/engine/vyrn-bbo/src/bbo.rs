//! The BBO core's loop and its steps (05 §8). One [`Bbo::poll`] is one pass of 05 §8.2
//! `bbo_main`: it decides at most one step and publishes it.
//!
//! Choices this implementation makes inside the spec's freedom (all logged, so replay never
//! repeats them):
//!
//! - **Source-lane clamp.** The source lane's cut is clamped below the *smallest* dependency
//!   floor of its unexecuted entries, the source's own included (a partial cut, 05 §3.3). Then
//!   one cut is valid both for the source step and for a `Rescan` that preempts it, and no
//!   dependency of the source enters any batch (F2).
//! - **Partial `Rescan` cut.** When a band holds more than `ENG_RESCAN_MAX` = 1 in-band batch
//!   entry, the cut keeps only the one with the smallest key (05 §8.6).
//! - **Step cap.** STP removals count toward `ENG_STEP_FILLS` with fills (spec follow-up).

use vyrn_cut::{Floor, Line32, Line64, Snapshot, Visibility};
use vyrn_types::{Epoch, Handle, LaneId, LaneSeq, RejectReason, StepId, StepKind, Tick};

use crate::admit::{self, Clock};
use crate::book::{
    Ctx, Level, Maker, NO_DEP, PendEnt, State, away, lane_u8, lanes_mask, next_level,
};
use crate::codec::{
    ControlCmd, CutDelta, DEP_ENDED, DEP_JOIN, FillEvent, FillKind, FwdDep, FwdEntry, INDEX_MAKER,
    LIQ_AUCTION, LIQ_MAKER, LIQ_TAKER, MSG_NEW, OUT_AUCTION, OUT_FINISHED, OUT_IOC_REST, OUT_STP,
    Phase, RESTED_DONE, RESTED_IN_FLIGHT, Record, STEP_CONT, TxEntry, encode_records,
};
use crate::cut::{Cut, HalfPair, SrcRule, step_cut};
use crate::io::{Poll, Ports};
use crate::key::{PrioKey, Side, Stp, Tif, rank_e};
use crate::out::{MAX_EVENTS, StepOut, role_head};
use crate::view::{BookSource, JKind, OrderSlot, SlotKind};
use crate::{
    ENG_SNAP_HIST, ENG_STEP_FILLS, ENG_UNCROSS_CHUNK, MAX_DEPS, MAX_LANES, NO_ASK, NO_BID,
};

/// Book parameters fixed at epoch start (05 §13).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// `N_LANES` of the box, ≤ 50 (two half-cuts of 25).
    pub n_lanes: u8,
    pub epoch: Epoch,
    /// `ENG_SLOT_CAP`: slots per lane arena.
    pub slot_cap: usize,
    /// `ENG_SEG_CAP`: bounds a segment walk.
    pub seg_cap: u32,
    pub win_center: Tick,
    /// Phase at epoch start.
    pub phase: Phase,
    pub tick_min: Tick,
    pub tick_max: Tick,
    /// `ENG_BAND_HALF_TICKS`; 0 = the BBO core never moves the band (05 §13.2).
    pub band_half: u32,
    /// `ENG_BAND_HYST`.
    pub band_hyst: u32,
    /// The band reference at epoch start.
    pub band_ref: Tick,
}

/// A forwarded op with its dependency lines and its lane.
#[derive(Clone, Copy, Debug, Default)]
struct Fwd {
    lane: usize,
    e: FwdEntry,
    deps: [FwdDep; MAX_DEPS],
    n: usize,
}

impl Fwd {
    fn deps(&self) -> &[FwdDep] {
        self.deps.get(..self.n).unwrap_or(&[])
    }
    fn floor(&self) -> LaneSeq {
        self.e.floor(self.deps())
    }
}

/// Entries buffered per lane: one packet's forwarded ops at most (10 messages), so the smallest
/// floor of the head's packet is always in the buffer (spec follow-up F1).
const LANE_BUF: usize = 10;

#[derive(Clone, Copy, Debug, Default)]
struct LaneQ {
    buf: [Fwd; LANE_BUF],
    len: usize,
}

impl LaneQ {
    fn head(&self) -> Option<&Fwd> {
        self.buf.get(..self.len).and_then(|b| b.first())
    }
    fn pop(&mut self) {
        if self.len > 0 {
            self.buf.rotate_left(1);
            self.len = self.len.saturating_sub(1);
        }
    }
    fn push(&mut self, f: Fwd) {
        if let Some(s) = self.buf.get_mut(self.len) {
            *s = f;
            self.len = self.len.saturating_add(1);
        }
    }
    fn min_floor(&self) -> Option<LaneSeq> {
        self.buf.get(..self.len)?.iter().map(Fwd::floor).min()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Log,
    Fill(usize),
    Tx(usize),
    Snap,
}

#[derive(Clone, Copy, Debug)]
struct Unc {
    price: Tick,
    /// Remaining quantity to allocate: buys, sells.
    rem: [u64; 2],
    last_chunk: bool,
}

#[derive(Clone, Copy, Debug)]
struct Taker {
    lane: usize,
    side: Side,
    tick: Tick,
    total: u32,
    v: OrderSlot,
    vslot: u32,
    seq: LaneSeq,
}

impl Taker {
    fn handle(&self) -> Handle {
        Handle::new(self.v.root, self.v.gen_).unwrap_or(Handle(0))
    }
    fn open(&self, st: &State) -> u32 {
        let r = st.root(self.lane, self.v.root, self.v.gen_);
        if r.killed {
            0
        } else {
            self.total.saturating_sub(r.filled)
        }
    }
    fn tif(&self) -> Tif {
        self.v.flags.tif()
    }
    fn stp(&self) -> Stp {
        self.v.flags.stp()
    }
}

/// Who gets the taker's records: the fill TX core (a forwarded op), or the lane (a `Rescan`
/// batch join, whose records the lane emits at B3, 05 §8.10 rule 4).
#[derive(Clone, Copy, Debug)]
enum Role {
    Fwd { head: TxEntry, index: u8, tag: u32 },
    Batch,
}

/// A `Rescan` batch taker whose sweep hit the step cap (D14): it resumes in the next step at
/// the same cut, `C_{s−1}` and key, so its visibility is unchanged (05 §5.2).
#[derive(Clone, Copy, Debug)]
struct RCont {
    lane: usize,
    slot: u32,
    key: PrioKey,
    band: (Tick, Tick),
    cut: Cut,
    prev: Cut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sweep {
    /// The batch taker was not live at its key: nothing ran.
    Skipped,
    Open,
    Capped,
    Killed,
}

/// The BBO core of one book.
pub struct Bbo {
    cfg: Config,
    st: State,
    n: usize,
    cut: Cut,
    next: StepId,
    bid: Tick,
    ask: Tick,
    phase: Phase,
    version: u64,
    last_pub: (Tick, Tick, Phase),
    hist: Vec<(u64, Tick, Tick, bool)>,
    lowver: [u64; MAX_LANES],
    q: Vec<LaneQ>,
    ctl: Option<ControlCmd>,
    cont: Option<Fwd>,
    rcont: Option<RCont>,
    pair: HalfPair,
    out: StepOut,
    held: bool,
    stage: Stage,
    frozen: Option<Cut>,
    unc: Option<Unc>,
    band_ref: Tick,
    sealed: bool,
}

impl Bbo {
    /// Allocates every buffer: call before `seal()` (`INV-NOALLOC`).
    pub fn new(cfg: Config) -> Self {
        let n = usize::from(cfg.n_lanes).min(MAX_LANES);
        let rank = core::array::from_fn(|l| rank_e(cfg.epoch, LaneId(lane_u8(l)), cfg.n_lanes));
        let flag = cfg.phase != Phase::Continuous;
        let mut hist = vec![(u64::MAX, NO_BID, NO_ASK, false); ENG_SNAP_HIST];
        if let Some(h) = hist.first_mut() {
            *h = (0, NO_BID, NO_ASK, flag);
        }
        Self {
            cfg,
            st: State::new(n, cfg.slot_cap, cfg.seg_cap, rank),
            n,
            cut: [LaneSeq(0); MAX_LANES],
            next: StepId(1),
            bid: NO_BID,
            ask: NO_ASK,
            phase: cfg.phase,
            version: 0,
            last_pub: (NO_BID, NO_ASK, cfg.phase),
            hist,
            lowver: [0; MAX_LANES],
            q: vec![LaneQ::default(); n],
            ctl: None,
            cont: None,
            rcont: None,
            pair: HalfPair::default(),
            out: StepOut::default(),
            held: false,
            stage: Stage::Log,
            frozen: None,
            unc: None,
            band_ref: cfg.band_ref,
            sealed: false,
        }
    }

    /// The snapshot to initialize `SnapshotLine` with (version 0).
    pub fn initial_snapshot(&self) -> Snapshot {
        Snapshot {
            version: 0,
            bid: NO_BID,
            ask: NO_ASK,
            done_step: StepId(0),
            win_center: self.cfg.win_center,
            phase: self.phase.code(),
            flags: u8::from(self.phase != Phase::Continuous),
        }
    }

    /// Bounds `(B, A)` (05 §8.6, `INV-ENG-4`).
    pub fn bounds(&self) -> (Tick, Tick) {
        (self.bid, self.ask)
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// `C_{s−1}`: the cut of the last decided step.
    pub fn cut(&self) -> &Cut {
        &self.cut
    }
    /// The id the next step will take.
    pub fn next_step(&self) -> StepId {
        self.next
    }
    /// The outputs of the last decided step.
    pub fn last(&self) -> &StepOut {
        &self.out
    }

    /// One pass of 05 §8.2: decide at most one step and publish it.
    pub fn poll<V: Visibility, S: BookSource, C: Clock>(
        &mut self,
        vis: &V,
        p: &mut Ports<'_, '_, V>,
        src: &S,
        clock: &C,
    ) -> Poll {
        if self.st.fault {
            return Poll::Fault;
        }
        if self.held {
            return self.publish(vis, p);
        }
        if self.sealed {
            return Poll::Idle;
        }
        // 05 §8.3: both half-cuts, then the ring heads.
        if let Some(a) = p.half_a.try_read_newest(vis)
            && a.0 >= self.pair.a.0
        {
            self.pair.a = a;
        }
        if let Some(b) = p.half_b.try_read_newest(vis)
            && b.0 >= self.pair.b.0
        {
            self.pair.b = b;
        }
        self.poll_rings(vis, p);
        self.retire_pend();
        if self.ctl.is_none()
            && let Some(line) = p.control.pop(vis)
        {
            match ControlCmd::decode(&line) {
                Some(c) => self.ctl = Some(c),
                None => self.st.fault = true,
            }
        }
        if self.st.fault {
            return Poll::Fault;
        }
        self.decide(src, clock);
        if self.st.fault || self.out.overflow {
            self.st.fault = true;
            return Poll::Fault;
        }
        if self.held {
            self.publish(vis, p)
        } else {
            Poll::Idle
        }
    }

    fn poll_rings<V: Visibility>(&mut self, vis: &V, p: &mut Ports<'_, '_, V>) {
        for (l, (q, ring)) in self.q.iter_mut().zip(p.fwd.iter_mut()).enumerate() {
            while q.len < LANE_BUF {
                let Some(head) = ring.pop(vis) else { break };
                let e = FwdEntry::decode(&head);
                let n = usize::from(e.n_dep());
                if n > MAX_DEPS {
                    self.st.fault = true;
                    return;
                }
                let mut f = Fwd {
                    lane: l,
                    e,
                    deps: [FwdDep::default(); MAX_DEPS],
                    n,
                };
                for chunk in f.deps.chunks_mut(4).take(n.div_ceil(4)) {
                    let Some(line) = ring.pop(vis) else {
                        self.st.fault = true; // push_all publishes an entry with its lines
                        return;
                    };
                    for (d, x) in chunk.iter_mut().zip(FwdDep::decode_line(&line)) {
                        *d = x;
                    }
                }
                q.push(f);
            }
        }
    }

    /// 05 §8.5: drop `Pend` entries whose lane has applied their step (`f_lo ≥ step`).
    fn retire_pend(&mut self) {
        let pair = self.pair;
        self.st.pend.retain(|p| {
            let f_lo = pair.entry(p.lane).f_lo;
            let s_lo = u32::try_from(p.step.0 & 0xFFFF_FFFF).unwrap_or(0);
            f_lo.wrapping_sub(s_lo) >= 0x8000_0000
        });
    }

    fn ctx<'a, S: BookSource>(
        &'a self,
        src: &'a S,
        c: &'a Cut,
        prev: &'a Cut,
        key: Option<PrioKey>,
    ) -> Ctx<'a, S> {
        Ctx {
            src,
            st: &self.st,
            c,
            prev,
            key,
            auction: false,
            probe: self.probe(c),
        }
    }

    /// Wild lanes and lag lanes (`C[l] > K[l]`) are probed at every level (Lemma 7.1).
    fn probe(&self, c: &Cut) -> u64 {
        let mut m = self.pair.wild();
        for (l, x) in c.iter().enumerate().take(self.n) {
            if x.0 > self.pair.entry(l).seq.0 {
                m |= crate::book::bit(l);
            }
        }
        m & lanes_mask(self.n)
    }

    fn rank(&self, l: usize) -> u8 {
        self.st.rank.get(l).copied().unwrap_or(0)
    }

    fn decide<S: BookSource, C: Clock>(&mut self, src: &S, clock: &C) {
        if let Some(r) = self.rcont {
            self.out.reset(self.next);
            self.rescan_finish(src, r, true);
            return;
        }
        let k = self.pair.k();
        let prev = self.cut;
        let floors: [Option<LaneSeq>; MAX_LANES] =
            core::array::from_fn(|l| self.q.get(l).and_then(LaneQ::min_floor));
        let chosen = match self.cont {
            Some(f) => Some((f, true)),
            None if self.unc.is_some() || self.ctl.is_some() => None,
            None => self.pick().map(|f| (f, false)),
        };
        let rule = chosen.map(|(f, _)| SrcRule {
            lane: f.lane,
            q: f.e.lane_seq,
            a: LaneSeq(f.e.lane_seq.0.saturating_sub(u64::from(f.e.applied_back))),
            next_floor: floors.get(f.lane).copied().flatten(),
        });
        let c = step_cut(&prev, &k, &floors, rule);
        if self.phase == Phase::Continuous
            && let Some(band) = self.band_test(&c, &prev)
        {
            self.exec_rescan(src, c, band);
            return;
        }
        if let Some((f, cont)) = chosen {
            if !cont && admit::late(clock, f.e.deadline) {
                self.exec_shed(f, c);
            } else {
                self.exec_fwd(src, f, c, cont);
            }
            return;
        }
        if let Some(u) = self.unc {
            if c != prev && u.last_chunk {
                if let Some(x) = self.unc.as_mut() {
                    x.last_chunk = false;
                }
                self.exec_idle(src, c);
            } else {
                self.out.reset(self.next);
                self.uncross_chunk(src, &c);
                self.finish(c, StepKind::Uncross, None, false, None);
            }
            return;
        }
        if let Some(cmd) = self.ctl.take() {
            self.exec_control(src, cmd, c);
            return;
        }
        if c != prev {
            self.exec_idle(src, c);
        }
    }

    /// 05 §8.4: the ring head with the smallest key.
    fn pick(&self) -> Option<Fwd> {
        let mut best: Option<(PrioKey, Fwd)> = None;
        for (l, q) in self.q.iter().enumerate() {
            if let Some(f) = q.head() {
                let key = PrioKey {
                    ts: f.e.prio_ts,
                    rank: self.rank(l),
                    seq: f.e.lane_seq,
                };
                if best.is_none_or(|(b, _)| key < b) {
                    best = Some((key, *f));
                }
            }
        }
        best.map(|(_, f)| f)
    }

    // -----------------------------------------------------------------------------------------
    // Snapshot history and the band test (05 §8.6)

    fn expand(&self, v32: u32) -> u64 {
        let lo = u32::try_from(self.version & 0xFFFF_FFFF).unwrap_or(0);
        self.version.saturating_sub(u64::from(lo.wrapping_sub(v32)))
    }

    fn hist_ix(v: u64) -> usize {
        usize::try_from(
            v.checked_rem(u64::try_from(ENG_SNAP_HIST).unwrap_or(1))
                .unwrap_or(0),
        )
        .unwrap_or(0)
    }

    /// Max bid and min ask over versions `lo..=vcur`; `(TICK_MAX, 0)` when a version is gone or
    /// is an auction or halt version.
    fn envelope(&self, lo: u64) -> (Tick, Tick) {
        let suspect = (self.cfg.tick_max, Tick(0));
        let span = self.version.saturating_sub(lo);
        if span >= u64::try_from(ENG_SNAP_HIST).unwrap_or(0) {
            return suspect;
        }
        let (mut mb, mut ma) = (NO_BID, NO_ASK);
        for v in lo..=self.version {
            match self.hist.get(Self::hist_ix(v)) {
                Some((ver, b, a, flag)) if *ver == v && !flag => {
                    mb = mb.max(*b);
                    ma = ma.min(*a);
                }
                _ => return suspect,
            }
        }
        (mb, ma)
    }

    fn band_test(&mut self, c: &Cut, prev: &Cut) -> Option<(Tick, Tick)> {
        let (mut hi, mut lo) = (self.bid, self.ask);
        for l in 0..self.n {
            if c.get(l) > prev.get(l) {
                let (mb, ma) = self.envelope(self.lowver.get(l).copied().unwrap_or(0));
                hi = hi.max(mb);
                lo = lo.min(ma);
            }
        }
        if lo <= hi {
            Some((lo, hi))
        } else {
            self.bid = hi;
            self.ask = lo;
            None
        }
    }

    // -----------------------------------------------------------------------------------------
    // Finishing and publishing a step (05 §8.2 finish_step)

    fn finish(
        &mut self,
        c: Cut,
        kind: StepKind,
        src: Option<(usize, LaneSeq, u32)>,
        cont: bool,
        band: Option<(Tick, Tick)>,
    ) {
        self.maybe_band();
        self.out.drop_empty_tx();
        let s = self.next;
        let prev = self.cut;
        let e = &mut self.out.entry;
        e.step = s;
        e.kind = kind.code();
        if let Some((l, q, _)) = src {
            e.src_lane = LaneId(lane_u8(l));
            e.src_lane_seq = q;
        }
        e.flags = if cont { STEP_CONT } else { 0 };
        if let Some((lo, hi)) = band {
            e.band_lo = lo;
            e.band_hi = hi;
        }
        e.pub_a = u32::try_from(self.pair.a.0 & 0xFFFF_FFFF).unwrap_or(0);
        e.pub_b = u32::try_from(self.pair.b.0 & 0xFFFF_FFFF).unwrap_or(0);
        self.out.set_deltas(&prev, &c, self.n);
        for l in 0..self.n {
            let ent = self.pair.entry(l);
            if c.get(l) == Some(&ent.seq) {
                let v = self.expand(ent.snap_ver);
                if let Some(x) = self.lowver.get_mut(l) {
                    *x = v;
                }
            }
        }
        // 05 §8.6: the source lane's ops up to its cut were classified against ≥ the entry's
        // `snap_ver`.
        if let Some((l, _, sv)) = src {
            let v = self.expand(sv);
            if let Some(x) = self.lowver.get_mut(l) {
                *x = v;
            }
        }
        let cont_phase = self.phase == Phase::Continuous;
        let (b, a) = if cont_phase {
            (self.bid, self.ask)
        } else {
            (NO_BID, NO_ASK)
        };
        if (b, a, self.phase) != self.last_pub {
            self.version = self.version.saturating_add(1);
            self.last_pub = (b, a, self.phase);
            if let Some(h) = self.hist.get_mut(Self::hist_ix(self.version)) {
                *h = (self.version, b, a, !cont_phase);
            }
        }
        self.out.snapshot = Snapshot {
            version: self.version,
            bid: b,
            ask: a,
            done_step: s,
            win_center: self.cfg.win_center,
            phase: self.phase.code(),
            flags: u8::from(!cont_phase),
        };
        self.out.floor = Floor {
            done_a: self.pair.a.0,
            done_b: self.pair.b.0,
        };
        self.cut = c;
        self.next = StepId(s.0.saturating_add(1));
        self.held = true;
        self.stage = Stage::Log;
    }

    fn publish<V: Visibility>(&mut self, vis: &V, p: &mut Ports<'_, '_, V>) -> Poll {
        loop {
            match self.stage {
                Stage::Log => {
                    let mut lines = [[0u64; 8]; 1 + MAX_LANES / 4];
                    let ds = self.out.deltas();
                    let n = 1usize.saturating_add(ds.len().div_ceil(4));
                    for (line, x) in lines.iter_mut().zip(
                        core::iter::once(self.out.entry.encode())
                            .chain(ds.chunks(4).map(CutDelta::encode_line)),
                    ) {
                        *line = x;
                    }
                    if !p.step_log.push_all(vis, lines.get(..n).unwrap_or(&[])) {
                        return Poll::Stalled;
                    }
                    self.stage = Stage::Fill(0);
                }
                Stage::Fill(l) => {
                    if l >= self.n {
                        self.stage = Stage::Tx(0);
                        continue;
                    }
                    let mut buf: [Line32; MAX_EVENTS] = [[0; 4]; MAX_EVENTS];
                    let mut k = 0usize;
                    for (lane, ev) in self.out.events() {
                        if usize::from(lane.0) == l
                            && let Some(b) = buf.get_mut(k)
                        {
                            *b = ev.encode();
                            k = k.saturating_add(1);
                        }
                    }
                    if k > 0 {
                        let Some(ring) = p.fill.get_mut(l) else {
                            self.st.fault = true;
                            return Poll::Fault;
                        };
                        if !ring.push_all(vis, buf.get(..k).unwrap_or(&[])) {
                            return Poll::Stalled;
                        }
                    }
                    self.stage = Stage::Fill(l.saturating_add(1));
                }
                Stage::Tx(i) => {
                    let Some(pkt) = self.out.tx().get(i) else {
                        self.stage = Stage::Snap;
                        continue;
                    };
                    if pkt.head.n_rec > 0 {
                        let mut lines: [Line64; 5] = [[0; 8]; 5];
                        let recs = pkt.records();
                        let n = 1usize.saturating_add(recs.len().div_ceil(4));
                        for (line, x) in lines.iter_mut().zip(
                            core::iter::once(pkt.head.encode())
                                .chain(recs.chunks(4).map(encode_records)),
                        ) {
                            *line = x;
                        }
                        let ix = usize::from(pkt.head.lane.0 >= 25);
                        let Some(ring) = p.tx.get_mut(ix) else {
                            self.st.fault = true;
                            return Poll::Fault;
                        };
                        if !ring.push_all(vis, lines.get(..n).unwrap_or(&[])) {
                            return Poll::Stalled;
                        }
                    }
                    self.stage = Stage::Tx(i.saturating_add(1));
                }
                Stage::Snap => {
                    p.snapshot.publish(vis, &self.out.snapshot);
                    p.floor.publish(vis, &self.out.floor);
                    self.held = false;
                    return Poll::Step(self.out.entry.step);
                }
            }
        }
    }

    /// 05 §13.2: a step whose last trade is more than `ENG_BAND_HYST` from the reference moves
    /// the band and tells every lane.
    fn maybe_band(&mut self) {
        let Some(t) = self.out.last_trade else { return };
        if self.cfg.band_half == 0 || t.0.abs_diff(self.band_ref.0) <= self.cfg.band_hyst {
            return;
        }
        self.band_ref = t;
        let lo = t
            .checked_sub(self.cfg.band_half)
            .unwrap_or(Tick(0))
            .max(self.cfg.tick_min);
        let hi = t
            .checked_add(self.cfg.band_half)
            .unwrap_or(Tick(u32::MAX))
            .min(self.cfg.tick_max);
        self.band_events(lo, hi);
    }

    fn band_events(&mut self, lo: Tick, hi: Tick) {
        for l in 0..self.n {
            self.out.event(
                LaneId(lane_u8(l)),
                FillEvent {
                    tick: lo,
                    qty: hi.0,
                    kind: FillKind::Band.code(),
                    ..FillEvent::default()
                },
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // Bounds

    fn set_bound(&mut self, side: Side, t: Tick) {
        match side {
            Side::Buy => self.bid = t,
            Side::Sell => self.ask = t,
        }
    }

    fn bound(&self, side: Side) -> Tick {
        match side {
            Side::Buy => self.bid,
            Side::Sell => self.ask,
        }
    }

    /// A resting order at `t` on `side`: the bound moves toward the spread, never away.
    fn rest_bound(&mut self, side: Side, t: Tick) {
        match side {
            Side::Buy => self.bid = self.bid.max(t),
            Side::Sell => self.ask = self.ask.min(t),
        }
    }

    /// The far end of the ladder on `side`, as a `next_level` limit.
    fn far(side: Side) -> Tick {
        match side {
            Side::Buy => Tick(1),
            Side::Sell => Tick(u32::MAX.saturating_sub(1)),
        }
    }

    /// Exact bounds at cut `c` (after a `Rescan`, an uncross, or a return to Continuous).
    fn exact_bounds<S: BookSource>(&mut self, src: &S, c: &Cut, from_b: Tick, from_a: Tick) {
        let b = next_level(
            &self.ctx(src, c, c, None),
            Side::Buy,
            from_b,
            Self::far(Side::Buy),
        );
        let a = next_level(
            &self.ctx(src, c, c, None),
            Side::Sell,
            from_a,
            Self::far(Side::Sell),
        );
        self.bid = b.unwrap_or(NO_BID);
        self.ask = a.unwrap_or(NO_ASK);
    }

    /// 05 §8.5 `advance_bound` for a taker with limit `limit`: the best live opposite level it
    /// can trade with, and the bound made exact (or raised past the limit when there is none).
    fn touch<S: BookSource>(&mut self, src: &S, c: &Cut, side: Side, limit: Tick) -> Option<Tick> {
        let from = self.bound(side);
        if from == NO_BID && side == Side::Buy || from == NO_ASK && side == Side::Sell {
            return None;
        }
        let lvl = next_level(&self.ctx(src, c, c, None), side, from, limit);
        match lvl {
            Some(t) => self.set_bound(side, t),
            None => match side {
                Side::Sell => self.ask = self.ask.max(limit.checked_add(1).unwrap_or(NO_ASK)),
                Side::Buy => self.bid = self.bid.min(limit.checked_sub(1).unwrap_or(NO_BID)),
            },
        }
        lvl
    }

    // -----------------------------------------------------------------------------------------
    // Records and events

    fn maker_route(&self, m: &Maker, src_session: Option<TxEntry>) -> Option<u8> {
        let p = m.pend.and_then(|i| self.st.pend.get(i))?;
        (p.step == self.next && p.dep != NO_DEP && src_session.is_some()).then_some(p.dep)
    }

    fn maker_record<S: BookSource>(&mut self, src: &S, m: &Maker, r: Record) {
        let lane = LaneId(lane_u8(m.lane));
        match (self.maker_route(m, self.out.deps_head), self.out.deps_head) {
            // A full deps packet (9 Acks + 8 maker records > 16) spills the maker record to the
            // session's MakerSeq packet instead of faulting (spec follow-up F8).
            (Some(g), Some(h)) if self.out.has_room(h) => self.out.record(h, g, r),
            _ => {
                let h = StepOut::maker_head(self.next, lane, src.session(lane, m.v.root));
                self.out.record(h, 0, r);
            }
        }
    }

    fn fill_maker<S: BookSource>(
        &mut self,
        src: &S,
        m: &Maker,
        q: u32,
        price: Tick,
        liq: u8,
        record: bool,
    ) {
        if let Some(r) = self.st.root_mut(m.lane, m.v.root, m.v.gen_) {
            r.filled = r.filled.saturating_add(q);
        }
        let ord = self.out.next_ordinal();
        self.out.event(
            LaneId(lane_u8(m.lane)),
            FillEvent {
                handle: m.handle(),
                vslot: m.vslot,
                tick: price,
                qty: q,
                kind: FillKind::Fill.code(),
                liq,
                ordinal: ord,
                ..FillEvent::default()
            },
        );
        self.out.entry.n_fills = self.out.entry.n_fills.saturating_add(1);
        self.out.last_trade = Some(price);
        if record {
            let r = Record::Fill {
                index: INDEX_MAKER,
                liq,
                handle: m.handle(),
                tick: price,
                qty: vyrn_types::Qty(q),
            };
            self.maker_record(src, m, r);
        }
    }

    fn kill_maker<S: BookSource>(&mut self, src: &S, m: &Maker) {
        if let Some(r) = self.st.root_mut(m.lane, m.v.root, m.v.gen_) {
            r.killed = true;
        }
        let lane = LaneId(lane_u8(m.lane));
        let ord = self.out.ordinal;
        self.out.event(
            lane,
            FillEvent {
                handle: m.handle(),
                vslot: m.vslot,
                tick: m.v.tick,
                qty: m.open,
                kind: FillKind::Out.code(),
                liq: LIQ_MAKER,
                cause: OUT_STP,
                ordinal: ord,
                ..FillEvent::default()
            },
        );
        let r = Record::Out {
            index: INDEX_MAKER,
            cause: OUT_STP,
            handle: m.handle(),
            qty: vyrn_types::Qty(m.open),
            client_tag: src.client_tag(lane, m.v.root),
        };
        self.maker_record(src, m, r);
    }

    fn taker_level(&mut self, t: &Taker, role: Role, lvl: Tick, qty: u32) {
        let ord = self.out.ordinal.saturating_sub(1);
        self.out.event(
            LaneId(lane_u8(t.lane)),
            FillEvent {
                handle: t.handle(),
                vslot: t.vslot,
                tick: lvl,
                qty,
                kind: FillKind::Fill.code(),
                liq: LIQ_TAKER,
                ordinal: ord,
                ..FillEvent::default()
            },
        );
        if let Role::Fwd { head, index, .. } = role {
            let r = Record::Fill {
                index,
                liq: LIQ_TAKER,
                handle: t.handle(),
                tick: lvl,
                qty: vyrn_types::Qty(qty),
            };
            self.out.record(head, 0, r);
        }
    }

    /// Ends the taker with an event of `kind` and its record (nothing rests).
    fn end_taker(
        &mut self,
        t: &Taker,
        role: Role,
        kind: FillKind,
        cause: u16,
        rec: Option<Record>,
        kill: bool,
    ) {
        let open = t.open(&self.st);
        if kill && let Some(r) = self.st.root_mut(t.lane, t.v.root, t.v.gen_) {
            r.killed = true;
        }
        let ord = self.out.ordinal;
        self.out.event(
            LaneId(lane_u8(t.lane)),
            FillEvent {
                handle: t.handle(),
                vslot: t.vslot,
                tick: t.tick,
                qty: open,
                kind: kind.code(),
                cause,
                ordinal: ord,
                liq: LIQ_TAKER,
                ..FillEvent::default()
            },
        );
        if let (Role::Fwd { head, .. }, Some(r)) = (role, rec) {
            self.out.record(head, 0, r);
        }
    }

    fn reject_taker(&mut self, t: &Taker, role: Role, reason: RejectReason) {
        let rec = match role {
            Role::Fwd { index, tag, .. } => Some(Record::Reject {
                index,
                reason,
                detail: 0,
                client_tag: tag,
            }),
            Role::Batch => None,
        };
        // A rejected `Replace` leaves the order's current version in the book (05 §2.3, §13.3):
        // only the new version is refused. Post-only and FOK rejects end the order, since the
        // replace already removed the old version at its position in L.
        let keeps_old = t.v.kind == SlotKind::NewPrio
            && matches!(
                reason,
                RejectReason::BookHalted | RejectReason::AuctionPhase | RejectReason::TooLate
            );
        self.end_taker(t, role, FillKind::Reject, reason.code(), rec, !keeps_old);
    }

    fn out_taker(&mut self, t: &Taker, role: Role, cause: u16) {
        let rec = match role {
            Role::Fwd { index, tag, .. } => Some(Record::Out {
                index,
                cause,
                handle: t.handle(),
                qty: vyrn_types::Qty(t.open(&self.st)),
                client_tag: tag,
            }),
            Role::Batch => None,
        };
        self.end_taker(t, role, FillKind::Out, cause, rec, true);
    }

    fn rest_taker(&mut self, t: &Taker, role: Role) {
        let open = t.open(&self.st);
        self.st.pend_insert(PendEnt {
            lane: t.lane,
            slot: t.vslot,
            seq: t.seq,
            step: self.next,
            side: t.side,
            tick: t.tick,
            dep: NO_DEP,
        });
        self.rest_bound(t.side, t.tick);
        let ord = self.out.ordinal;
        self.out.event(
            LaneId(lane_u8(t.lane)),
            FillEvent {
                handle: t.handle(),
                vslot: t.vslot,
                tick: t.tick,
                qty: open,
                kind: FillKind::Rested.code(),
                ordinal: ord,
                liq: LIQ_TAKER,
                ..FillEvent::default()
            },
        );
        if let Role::Fwd { head, index, tag } = role {
            let r = Record::Ack {
                index,
                handle: t.handle(),
                tick: t.tick,
                client_tag: tag,
            };
            self.out.record(head, 0, r);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Matching (05 §2.4, §8.5)

    /// The sweep. `capped`: one level or `ENG_STEP_FILLS` per step (D14); a `Rescan` batch
    /// taker is uncapped. `key`: visibility at a batch key (05 §5.2), `None` at the cut.
    #[allow(clippy::too_many_arguments)]
    fn sweep<S: BookSource>(
        &mut self,
        src: &S,
        t: &Taker,
        role: Role,
        c: &Cut,
        prev: &Cut,
        key: Option<PrioKey>,
        from: Tick,
        capped: bool,
    ) -> Sweep {
        let side = t.side.opposite();
        let mut levels = 0u32;
        let mut work = 0u32;
        let mut from = from;
        loop {
            if t.open(&self.st) == 0 {
                return Sweep::Open;
            }
            if capped && (levels >= 1 || work >= ENG_STEP_FILLS) {
                return Sweep::Capped;
            }
            let lvl = if key.is_none() {
                self.touch(src, c, side, t.tick)
            } else {
                next_level(&self.ctx(src, c, prev, key), side, from, t.tick)
            };
            let Some(lvl) = lvl else { return Sweep::Open };
            let mut level = Level::new(&self.ctx(src, c, prev, key), side, lvl);
            let mut level_qty = 0u32;
            while !(capped && work >= ENG_STEP_FILLS) {
                let open = t.open(&self.st);
                if open == 0 {
                    break;
                }
                let Some(m) = level.next(&self.ctx(src, c, prev, key)) else {
                    break;
                };
                if m.lane == t.lane && t.stp() != Stp::None && m.v.acct_ix == t.v.acct_ix {
                    match t.stp() {
                        Stp::CancelOldest => {
                            self.kill_maker(src, &m);
                            work = work.saturating_add(1);
                            continue;
                        }
                        Stp::CancelBoth => self.kill_maker(src, &m),
                        _ => {}
                    }
                    if level_qty > 0 {
                        self.taker_level(t, role, lvl, level_qty);
                    }
                    self.out_taker(t, role, OUT_STP);
                    return Sweep::Killed;
                }
                let q = open.min(m.open);
                self.fill_maker(src, &m, q, lvl, LIQ_MAKER, true);
                if let Some(r) = self.st.root_mut(t.lane, t.v.root, t.v.gen_) {
                    r.filled = r.filled.saturating_add(q);
                }
                level_qty = level_qty.saturating_add(q);
                work = work.saturating_add(1);
            }
            if level_qty > 0 {
                self.taker_level(t, role, lvl, level_qty);
            }
            levels = levels.saturating_add(1);
            from = lvl;
        }
    }

    /// 05 §8.5 `dry_run_fillable`: what the sweep would fill, with the STP skip and stop rules,
    /// counted up to `need`. Writes nothing.
    fn fillable<S: BookSource>(&self, src: &S, t: &Taker, c: &Cut, need: u32) -> u32 {
        let side = t.side.opposite();
        let ctx = self.ctx(src, c, c, None);
        let mut sum = 0u32;
        let mut from = self.bound(side);
        while sum < need {
            let Some(lvl) = next_level(&ctx, side, from, t.tick) else {
                break;
            };
            let mut level = Level::new(&ctx, side, lvl);
            while let Some(m) = level.next(&ctx) {
                if m.lane == t.lane && t.stp() != Stp::None && m.v.acct_ix == t.v.acct_ix {
                    if t.stp() == Stp::CancelOldest {
                        continue;
                    }
                    return sum;
                }
                sum = sum.saturating_add(m.open);
                if sum >= need {
                    return sum;
                }
            }
            match away(side, lvl) {
                Some(x) => from = x,
                None => break,
            }
        }
        sum
    }

    // -----------------------------------------------------------------------------------------
    // Forwarded ops (05 §8.5)

    fn exec_fwd<S: BookSource>(&mut self, src: &S, f: Fwd, c: Cut, cont: bool) {
        let s = self.next;
        self.out.reset(s);
        let lane = f.lane;
        let lid = LaneId(lane_u8(lane));
        let e = f.e;
        if !cont && let Some(q) = self.q.get_mut(lane) {
            q.pop();
        }
        let Some(v) = src.slot(lid, e.vslot) else {
            self.st.fault = true;
            return;
        };
        let t = Taker {
            lane,
            side: e.flags().side(),
            tick: e.tick(),
            total: e.qty().0,
            v,
            vslot: e.vslot,
            seq: e.lane_seq,
        };
        let tag = if e.msg_type() == MSG_NEW {
            e.client_tag()
        } else {
            src.client_tag(lid, v.root)
        };
        let has_deps = f.n > 0;
        let src_head = if cont {
            role_head(s, lid, e.session, 0, e.pkt_seq, false)
        } else {
            let rs = if has_deps {
                e.resp_seq.wrapping_add(1)
            } else {
                e.resp_seq
            };
            role_head(s, lid, e.session, rs, e.pkt_seq, false)
        };
        if !cont && has_deps {
            let h = role_head(s, lid, e.session, e.resp_seq, e.pkt_seq, true);
            self.out.open(h);
            self.out.deps_head = Some(h);
        }
        self.out.open(src_head);
        let role = Role::Fwd {
            head: src_head,
            index: e.index(),
            tag,
        };
        let prev = self.cut;
        let mut done = false;
        if !cont {
            self.st.set_explicit(lane, e.vslot, e.lane_seq);
            for d in f.deps() {
                if d.kind == DEP_JOIN {
                    let seq = LaneSeq(e.lane_seq.0.saturating_sub(u64::from(d.back)));
                    self.st.set_explicit(lane, d.slot, seq);
                }
            }
            self.apply_deps(src, &f, &c, &prev);
            done = self.entry_checks(src, &t, role, &c);
        }
        let mut capped = false;
        if !done {
            match self.sweep(
                src,
                &t,
                role,
                &c,
                &prev,
                None,
                self.bound(t.side.opposite()),
                true,
            ) {
                Sweep::Capped => capped = true,
                Sweep::Killed | Sweep::Skipped => {}
                Sweep::Open => {
                    if t.open(&self.st) > 0 {
                        match t.tif() {
                            Tif::Ioc | Tif::Fok => self.out_taker(&t, role, OUT_IOC_REST),
                            _ => self.rest_taker(&t, role),
                        }
                    }
                }
            }
        }
        self.cont = capped.then_some(f);
        let kind = if cont || self.out.entry.n_fills > 0 {
            StepKind::Cross
        } else {
            StepKind::Improve
        };
        self.finish(c, kind, Some((lane, e.lane_seq, e.snap_ver)), cont, None);
    }

    /// 05 §2.5 P1, §2.3 `Replace`, the post-only test and the FOK dry run. `true` when the taker
    /// ended (or rested outside Continuous) without a sweep.
    fn entry_checks<S: BookSource>(&mut self, src: &S, t: &Taker, role: Role, c: &Cut) -> bool {
        let ioc = matches!(t.tif(), Tif::Ioc | Tif::Fok);
        match self.phase {
            Phase::Halted => {
                self.reject_taker(t, role, RejectReason::BookHalted);
                return true;
            }
            Phase::Frozen => {
                self.reject_taker(t, role, RejectReason::AuctionPhase);
                return true;
            }
            Phase::Auction if ioc => {
                self.out_taker(t, role, OUT_AUCTION);
                return true;
            }
            Phase::Continuous if t.tif() == Tif::AuctionOnly => {
                self.reject_taker(t, role, RejectReason::AuctionPhase);
                return true;
            }
            _ => {}
        }
        if t.v.kind == SlotKind::NewPrio {
            if !self.st.replace_ok(t.lane, t.vslot, &t.v) {
                self.reject_taker(t, role, RejectReason::TooLate);
                return true;
            }
            let r = self.st.root(t.lane, t.v.root, t.v.gen_);
            if let Some(rm) = self.st.root_mut(t.lane, t.v.root, t.v.gen_) {
                rm.np_seq = t.seq.0;
            }
            if t.total <= r.filled {
                let old = t.v.pred_total().saturating_sub(r.filled);
                let rec = match role {
                    Role::Fwd { index, tag, .. } => Some(Record::CancelAck {
                        index,
                        handle: t.handle(),
                        canceled: vyrn_types::Qty(old),
                        client_tag: tag,
                    }),
                    Role::Batch => None,
                };
                if let Some(rm) = self.st.root_mut(t.lane, t.v.root, t.v.gen_) {
                    rm.killed = true;
                }
                let ord = self.out.ordinal;
                self.out.event(
                    LaneId(lane_u8(t.lane)),
                    FillEvent {
                        handle: t.handle(),
                        vslot: t.vslot,
                        tick: t.tick,
                        qty: old,
                        kind: FillKind::Out.code(),
                        liq: LIQ_TAKER,
                        cause: OUT_FINISHED,
                        ordinal: ord,
                        ..FillEvent::default()
                    },
                );
                if let (Role::Fwd { head, .. }, Some(r)) = (role, rec) {
                    self.out.record(head, 0, r);
                }
                return true;
            }
        }
        if self.phase == Phase::Auction {
            self.rest_taker(t, role);
            return true;
        }
        let opp = t.side.opposite();
        if t.v.flags.post_only() && self.touch(src, c, opp, t.tick).is_some() {
            self.reject_taker(t, role, RejectReason::PostOnlyWouldCross);
            return true;
        }
        if t.tif() == Tif::Fok {
            let need = t.open(&self.st);
            if self.fillable(src, t, c, need) < need {
                self.reject_taker(t, role, RejectReason::FokUnfillable);
                return true;
            }
        }
        false
    }

    /// 05 §8.5 `apply_deps`, §3.7 (4): the dependencies in index order, before the source.
    fn apply_deps<S: BookSource>(&mut self, src: &S, f: &Fwd, c: &Cut, prev: &Cut) {
        let lane = f.lane;
        let lid = LaneId(lane_u8(lane));
        let Some(head) = self.out.deps_head else {
            return;
        };
        for (i, d) in f.deps().iter().enumerate() {
            let g = u8::try_from(i).unwrap_or(u8::MAX);
            let seq = LaneSeq(f.e.lane_seq.0.saturating_sub(u64::from(d.back)));
            // Spec follow-up F2: FwdDep carries no message index; this is exact only when no
            // session-only message sits between the dependency and the source.
            let index = f.e.index().saturating_sub(d.back);
            let found = match d.kind {
                DEP_JOIN => src.slot(lid, d.slot).map(|v| (d.slot, v, false)),
                _ => self.ctx(src, c, prev, None).current_version(lane, d.slot),
            };
            let Some((vslot, v, ended)) = found else {
                self.st.fault = true;
                return;
            };
            let handle = Handle::new(v.root, v.gen_).unwrap_or(Handle(0));
            let tag = src.client_tag(lid, v.root);
            let r = self.st.root(lane, v.root, v.gen_);
            let mut ev = FillEvent {
                handle,
                vslot,
                tick: d.tick,
                kind: FillKind::Dep.code(),
                liq: d.kind,
                ordinal: self.out.ordinal,
                ..FillEvent::default()
            };
            let reject = |reason: RejectReason| Record::Reject {
                index,
                reason,
                detail: 0,
                client_tag: tag,
            };
            let rec;
            if self.phase == Phase::Frozen || (self.phase == Phase::Halted && d.kind == DEP_JOIN) {
                let reason = if self.phase == Phase::Frozen {
                    RejectReason::AuctionPhase
                } else {
                    RejectReason::BookHalted
                };
                ev.cause = reason.code();
                rec = reject(reason);
            } else if d.kind == DEP_JOIN {
                if v.kind == SlotKind::NewPrio && !self.st.replace_ok(lane, d.slot, &v) {
                    ev.cause = RejectReason::TooLate.code();
                    rec = reject(RejectReason::TooLate);
                } else if v.kind == SlotKind::NewPrio && v.total <= r.filled {
                    if let Some(rm) = self.st.root_mut(lane, v.root, v.gen_) {
                        rm.np_seq = seq.0;
                        rm.killed = true;
                    }
                    let old = v.pred_total().saturating_sub(r.filled);
                    ev.cause = DEP_ENDED;
                    ev.qty = old;
                    rec = Record::CancelAck {
                        index,
                        handle,
                        canceled: vyrn_types::Qty(old),
                        client_tag: tag,
                    };
                } else {
                    if v.kind == SlotKind::NewPrio
                        && let Some(rm) = self.st.root_mut(lane, v.root, v.gen_)
                    {
                        rm.np_seq = seq.0;
                    }
                    let side = d.flags.side();
                    self.st.pend_insert(PendEnt {
                        lane,
                        slot: d.slot,
                        seq,
                        step: self.next,
                        side,
                        tick: d.tick,
                        dep: g,
                    });
                    // Spec follow-up F4: a dependency Join is not matched on entry (05 §8.5).
                    self.rest_bound(side, d.tick);
                    ev.qty = v.total.saturating_sub(r.filled);
                    rec = Record::Ack {
                        index,
                        handle,
                        tick: d.tick,
                        client_tag: tag,
                    };
                }
            } else {
                let open = if r.killed || ended {
                    0
                } else {
                    v.total.saturating_sub(r.filled)
                };
                if let Some(rm) = self.st.root_mut(lane, v.root, v.gen_) {
                    rm.killed = true;
                }
                ev.qty = open;
                if open == 0 {
                    ev.cause = RejectReason::TooLate.code();
                    rec = reject(RejectReason::TooLate);
                } else {
                    rec = Record::CancelAck {
                        index,
                        handle,
                        canceled: vyrn_types::Qty(open),
                        client_tag: tag,
                    };
                }
            }
            self.out.event(lid, ev);
            self.out.record(head, g, rec);
        }
    }

    /// 05 §8.1 `Shed`: the source and its dependencies get `Reject BUSY`; nothing is applied.
    fn exec_shed(&mut self, f: Fwd, c: Cut) {
        let s = self.next;
        self.out.reset(s);
        let lane = f.lane;
        let lid = LaneId(lane_u8(lane));
        let e = f.e;
        if let Some(q) = self.q.get_mut(lane) {
            q.pop();
        }
        let busy = RejectReason::Busy;
        let has_deps = f.n > 0;
        if has_deps {
            let h = role_head(s, lid, e.session, e.resp_seq, e.pkt_seq, true);
            self.out.open(h);
            for (i, d) in f.deps().iter().enumerate() {
                let g = u8::try_from(i).unwrap_or(u8::MAX);
                self.out.event(
                    lid,
                    FillEvent {
                        vslot: d.slot,
                        tick: d.tick,
                        qty: d.qty.0,
                        kind: FillKind::Dep.code(),
                        liq: d.kind,
                        cause: busy.code(),
                        ..FillEvent::default()
                    },
                );
                let r = Record::Reject {
                    index: e.index().saturating_sub(d.back),
                    reason: busy,
                    detail: 0,
                    client_tag: 0,
                };
                self.out.record(h, g, r);
            }
        }
        let rs = if has_deps {
            e.resp_seq.wrapping_add(1)
        } else {
            e.resp_seq
        };
        let h = role_head(s, lid, e.session, rs, e.pkt_seq, false);
        self.out.event(
            lid,
            FillEvent {
                handle: e.handle,
                vslot: e.vslot,
                tick: e.tick(),
                qty: e.qty().0,
                kind: FillKind::Reject.code(),
                cause: busy.code(),
                liq: LIQ_TAKER,
                ..FillEvent::default()
            },
        );
        let r = Record::Reject {
            index: e.index(),
            reason: busy,
            detail: 0,
            client_tag: e.client_tag(),
        };
        self.out.record(h, 0, r);
        self.finish(
            c,
            StepKind::Shed,
            Some((lane, e.lane_seq, e.snap_ver)),
            false,
            None,
        );
    }

    // -----------------------------------------------------------------------------------------
    // Rescan (05 §8.6)

    fn exec_rescan<S: BookSource>(&mut self, src: &S, c: Cut, band: (Tick, Tick)) {
        let s = self.next;
        self.out.reset(s);
        let prev = self.cut;
        let (lo, hi) = band;
        // Per lane: first in-band New/NewPrio entry (key, seq, slot) and the second one's seq.
        let mut first: [Option<(PrioKey, LaneSeq, u32)>; MAX_LANES] = [None; MAX_LANES];
        let mut second: [Option<LaneSeq>; MAX_LANES] = [None; MAX_LANES];
        let mut count = 0usize;
        for l in 0..self.n {
            let (Some(p), Some(x)) = (prev.get(l), c.get(l)) else {
                continue;
            };
            if x <= p {
                continue;
            }
            let lid = LaneId(lane_u8(l));
            let rank = self.rank(l);
            let (mut f, mut sc, mut n) = (None, None, 0usize);
            src.journal(lid, *p, *x, |j| {
                if !matches!(j.kind, JKind::New | JKind::NewPrio) || j.tick < lo || j.tick > hi {
                    return;
                }
                n = n.saturating_add(1);
                if f.is_none() {
                    let ts = src.slot(lid, j.slot).map(|v| v.prio_ts).unwrap_or_default();
                    f = Some((
                        PrioKey {
                            ts,
                            rank,
                            seq: j.seq,
                        },
                        j.seq,
                        j.slot,
                    ));
                } else if sc.is_none() {
                    sc = Some(j.seq);
                }
            });
            if let (Some(a), Some(b)) = (first.get_mut(l), second.get_mut(l)) {
                *a = f;
                *b = sc;
            }
            count = count.saturating_add(n);
        }
        let star = first
            .iter()
            .enumerate()
            .filter_map(|(l, x)| x.map(|(k, q, slot)| (k, l, q, slot)))
            .min_by_key(|x| x.0);
        let mut cr = c;
        if count > 1
            && let Some((_, sl, _, _)) = star
        {
            for l in 0..self.n {
                let keep = if l == sl {
                    second.get(l).copied().flatten()
                } else {
                    first.get(l).copied().flatten().map(|x| x.1)
                };
                if let (Some(k), Some(x)) = (keep, cr.get_mut(l)) {
                    *x = LaneSeq(k.0.saturating_sub(1));
                }
            }
        }
        // Ops after the taker's key stay out of this step's cut, so no lane settles one (05 §7.6)
        // while a capped sweep of the taker still runs in CONT steps. Any cut between C_{s−1}
        // and the rule is a valid partial cut (05 §3.3); the ops held back enter later steps.
        if let Some((key, _, _, _)) = star {
            self.clamp_after_key(src, &prev, &mut cr, key);
        }
        match star {
            Some((key, lane, _, slot)) => {
                let r = RCont {
                    lane,
                    slot,
                    key,
                    band,
                    cut: cr,
                    prev,
                };
                self.rescan_finish(src, r, false);
            }
            None => {
                self.exact_bounds(src, &cr, self.bid.max(hi), self.ask.min(lo));
                self.finish(cr, StepKind::Rescan, None, false, Some(band));
            }
        }
    }

    /// Lowers `cut[l]` to just below lane `l`'s first journal entry in `(prev[l], cut[l]]` whose
    /// key is greater than `key`. Within a lane, key order is `LaneSeq` order (05 §3.2).
    fn clamp_after_key<S: BookSource>(&self, src: &S, prev: &Cut, cut: &mut Cut, key: PrioKey) {
        for l in 0..self.n {
            let (Some(p), Some(x)) = (prev.get(l).copied(), cut.get(l).copied()) else {
                continue;
            };
            if x <= p {
                continue;
            }
            let lid = LaneId(lane_u8(l));
            let rank = self.rank(l);
            let mut stop: Option<LaneSeq> = None;
            src.journal(lid, p, x, |j| {
                if stop.is_some() {
                    return;
                }
                let ts = match j.kind {
                    JKind::Tomb => src.slot(lid, j.slot).map(|v| v.tomb_ts),
                    JKind::AcctKill => Some(src.acct_kill(lid, j.slot).kill_ts),
                    _ => src.slot(lid, j.slot).map(|v| v.ins_time()),
                }
                .unwrap_or_default();
                if (PrioKey {
                    ts,
                    rank,
                    seq: j.seq,
                }) > key
                {
                    stop = Some(j.seq);
                }
            });
            if let (Some(q), Some(c)) = (stop, cut.get_mut(l)) {
                *c = LaneSeq(q.0.saturating_sub(1).max(p.0));
            }
        }
    }

    /// Runs (or resumes) the batch taker of a `Rescan` and finishes the step. While the taker
    /// is in flight the bounds stay as they were: it is not resting (05 §2.3), and continuations
    /// run before any other step.
    fn rescan_finish<S: BookSource>(&mut self, src: &S, r: RCont, cont: bool) {
        let swept = self.rescan_taker(src, &r.cut, &r.prev, r.lane, r.slot, r.key, r.band, cont);
        self.rcont = (swept == Sweep::Capped).then_some(r);
        // One status event per Rescan step that ran a batch taker, so its lane can tell "in
        // flight" from "rests" at a boundary between CONT steps (spec follow-up F10).
        let status = match swept {
            Sweep::Capped => Some(RESTED_IN_FLIGHT),
            Sweep::Open => Some(RESTED_DONE),
            Sweep::Skipped | Sweep::Killed => None,
        };
        if let Some(cause) = status
            && let Some(v) = src.slot(LaneId(lane_u8(r.lane)), r.slot)
        {
            let r0 = self.st.root(r.lane, v.root, v.gen_);
            let open = if r0.killed {
                0
            } else {
                v.total.saturating_sub(r0.filled)
            };
            if open > 0 {
                let ord = self.out.ordinal;
                self.out.event(
                    LaneId(lane_u8(r.lane)),
                    FillEvent {
                        handle: Handle::new(v.root, v.gen_).unwrap_or(Handle(0)),
                        vslot: r.slot,
                        tick: v.tick,
                        qty: open,
                        kind: FillKind::Rested.code(),
                        liq: LIQ_TAKER,
                        cause,
                        ordinal: ord,
                        ..FillEvent::default()
                    },
                );
            }
        }
        if self.rcont.is_none() {
            let (b, a) = (self.bid.max(r.band.1), self.ask.min(r.band.0));
            self.exact_bounds(src, &r.cut, b, a);
        }
        self.finish(r.cut, StepKind::Rescan, None, cont, Some(r.band));
    }

    #[allow(clippy::too_many_arguments)]
    fn rescan_taker<S: BookSource>(
        &mut self,
        src: &S,
        c: &Cut,
        prev: &Cut,
        l: usize,
        slot: u32,
        key: PrioKey,
        band: (Tick, Tick),
        cont: bool,
    ) -> Sweep {
        let lid = LaneId(lane_u8(l));
        let Some(v) = src.slot(lid, slot) else {
            self.st.fault = true;
            return Sweep::Open;
        };
        let t = Taker {
            lane: l,
            side: v.flags.side(),
            tick: v.tick,
            total: v.total,
            v,
            vslot: slot,
            seq: v.ins_seq,
        };
        // Live just after its own key: (ts, rank, seq + 1) orders after it and before every
        // other op (05 §5.2).
        let after = PrioKey {
            seq: LaneSeq(key.seq.0.saturating_add(1)),
            ..key
        };
        if self
            .ctx(src, c, prev, Some(after))
            .live(l, slot, &v)
            .is_none()
        {
            return Sweep::Skipped;
        }
        let side = t.side.opposite();
        let from = match side {
            Side::Sell => self.ask.min(band.0),
            Side::Buy => self.bid.max(band.1),
        };
        if !cont
            && v.flags.post_only()
            && next_level(&self.ctx(src, c, prev, Some(key)), side, from, t.tick).is_some()
        {
            self.reject_taker(&t, Role::Batch, RejectReason::PostOnlyWouldCross);
            return Sweep::Killed;
        }
        // Capped like a forwarded sweep (D14): one level or ENG_STEP_FILLS per step.
        self.sweep(src, &t, Role::Batch, c, prev, Some(key), from, true)
    }

    // -----------------------------------------------------------------------------------------
    // Idle, Depletion, Control, Uncross (05 §8.7, §8.8)

    fn exec_idle<S: BookSource>(&mut self, src: &S, c: Cut) {
        self.out.reset(self.next);
        let mut kind = StepKind::Idle;
        if self.phase == Phase::Continuous {
            for side in [Side::Buy, Side::Sell] {
                let t = self.bound(side);
                if t == NO_BID || t == NO_ASK {
                    continue;
                }
                let live = {
                    let ctx = self.ctx(src, &c, &c, None);
                    Level::new(&ctx, side, t).next(&ctx).is_some()
                };
                if !live {
                    let nt = away(side, t).and_then(|f| {
                        next_level(&self.ctx(src, &c, &c, None), side, f, Self::far(side))
                    });
                    let empty = if side == Side::Buy { NO_BID } else { NO_ASK };
                    self.set_bound(side, nt.unwrap_or(empty));
                    kind = StepKind::Depletion;
                }
            }
        }
        self.finish(c, kind, None, false, None);
    }

    fn carry(seq: LaneSeq) -> (Handle, u32) {
        (
            Handle(u32::try_from(seq.0 & 0xFFFF_FFFF).unwrap_or(0)),
            u32::try_from(seq.0.wrapping_shr(32)).unwrap_or(0),
        )
    }

    fn exec_control<S: BookSource>(&mut self, src: &S, cmd: ControlCmd, c: Cut) {
        self.out.reset(self.next);
        let kind = match cmd {
            ControlCmd::Phase { phase, lo, hi } => {
                self.phase = phase;
                for l in 0..self.n {
                    let (handle, vslot) = if phase == Phase::Frozen {
                        Self::carry(c.get(l).copied().unwrap_or_default())
                    } else {
                        (Handle(0), 0)
                    };
                    self.out.event(
                        LaneId(lane_u8(l)),
                        FillEvent {
                            handle,
                            vslot,
                            tick: lo,
                            qty: hi.0,
                            kind: FillKind::Phase.code(),
                            cause: u16::from(phase.code()),
                            ..FillEvent::default()
                        },
                    );
                }
                if phase == Phase::Frozen {
                    self.frozen = Some(c);
                }
                if phase == Phase::Continuous {
                    self.exact_bounds(src, &c, Tick(u32::MAX.saturating_sub(1)), Tick(1));
                }
                StepKind::Control
            }
            ControlCmd::Band { lo, hi } => {
                self.band_events(lo, hi);
                StepKind::Control
            }
            ControlCmd::Uncross { price, qty } => {
                if self.phase != Phase::Frozen || self.frozen.is_none() {
                    self.st.fault = true;
                    return;
                }
                self.unc = Some(Unc {
                    price,
                    rem: [qty, qty],
                    last_chunk: false,
                });
                self.uncross_chunk(src, &c);
                StepKind::Uncross
            }
            ControlCmd::Seal => {
                self.sealed = true;
                StepKind::Seal
            }
        };
        self.finish(c, kind, None, false, None);
    }

    /// One `Uncross` chunk (05 §8.8 step 5): at most `ENG_UNCROSS_CHUNK` fills at `p*`, buys
    /// from the highest level down then sells from the lowest up, each level in merged-FIFO
    /// order, with visibility at `C*`. The last chunk ends the auction.
    fn uncross_chunk<S: BookSource>(&mut self, src: &S, c: &Cut) {
        let (Some(mut u), Some(cstar)) = (self.unc, self.frozen) else {
            self.st.fault = true;
            return;
        };
        let p = u.price;
        let mut fills = 0u32;
        for (i, side) in [Side::Buy, Side::Sell].into_iter().enumerate() {
            let mut from = match side {
                Side::Buy => Tick(u32::MAX.saturating_sub(1)),
                Side::Sell => Tick(1),
            };
            loop {
                let rem = u.rem.get(i).copied().unwrap_or(0);
                if rem == 0 || fills >= ENG_UNCROSS_CHUNK {
                    break;
                }
                let mut ctx = self.ctx(src, &cstar, &cstar, None);
                ctx.auction = true;
                ctx.probe = lanes_mask(self.n);
                let Some(lvl) = next_level(&ctx, side, from, p) else {
                    self.st.fault = true; // Q exceeds the book at C*: histograms disagree
                    return;
                };
                let mut level = Level::new(&ctx, side, lvl);
                let mut ms: [Option<Maker>; ENG_UNCROSS_CHUNK_USIZE] =
                    [None; ENG_UNCROSS_CHUNK_USIZE];
                let mut room = ENG_UNCROSS_CHUNK.saturating_sub(fills);
                let mut want = rem;
                for slot in ms.iter_mut() {
                    if room == 0 || want == 0 {
                        break;
                    }
                    let Some(m) = level.next(&ctx) else { break };
                    want = want.saturating_sub(u64::from(m.open));
                    room = room.saturating_sub(1);
                    *slot = Some(m);
                }
                for m in ms.iter().flatten() {
                    let rem = u.rem.get(i).copied().unwrap_or(0);
                    let q = u32::try_from(rem.min(u64::from(m.open))).unwrap_or(m.open);
                    self.fill_maker(src, m, q, p, LIQ_AUCTION, false);
                    if let Some(r) = u.rem.get_mut(i) {
                        *r = r.saturating_sub(u64::from(q));
                    }
                    fills = fills.saturating_add(1);
                }
                from = lvl;
            }
        }
        u.last_chunk = true;
        self.unc = Some(u);
        if u.rem == [0, 0] {
            for l in 0..self.n {
                let (handle, vslot) = Self::carry(cstar.get(l).copied().unwrap_or_default());
                self.out.event(
                    LaneId(lane_u8(l)),
                    FillEvent {
                        handle,
                        vslot,
                        tick: p,
                        kind: FillKind::Uncross.code(),
                        ..FillEvent::default()
                    },
                );
            }
            self.phase = Phase::Continuous;
            self.frozen = None;
            self.unc = None;
            self.exact_bounds(src, c, Tick(u32::MAX.saturating_sub(1)), Tick(1));
            self.out.last_trade = Some(p);
        }
    }
}

const ENG_UNCROSS_CHUNK_USIZE: usize = 6;
const _: () = assert!(ENG_UNCROSS_CHUNK_USIZE == 6 && ENG_UNCROSS_CHUNK == 6);
