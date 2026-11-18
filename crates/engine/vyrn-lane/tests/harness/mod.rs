//! A single-threaded box: `N` real [`vyrn_lane::Lane`]s and one real `vyrn_bbo::Bbo` over `Hw`
//! rings and lines, with the BBO reading the lanes' arenas through [`LaneBook`]. The harness
//! plays only the cores this crate does not implement, as 05 describes them:
//!
//! - the **cut cores** (05 §4.13): copy each lane's `CounterLine` (`seq`, `snap_ver`, `f_lo`)
//!   into its half-cut entry;
//! - the **stream core** (05 §4.15): after a step is in the `StepLog`, write every lane's
//!   `LaneCut = (f, C_f[l], snapshot of f)`, `C_f[l]` being the lane's last cut delta;
//! - the **snapshot fan-out**: copy the BBO's `SnapshotLine` into each lane's line. A test can
//!   *hold* a lane: its line keeps the snapshot it has and it runs no idle polls until its next
//!   packet, which it classifies against that older snapshot (05 §2.5). The hold ends after the
//!   packet.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_arguments,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use vyrn_bbo::admit::{Clock, FixedClock, NeverLate};
use vyrn_bbo::{
    Bbo, ControlCons, ControlRing, FillEvent, FillKind, FillProd, FwdCons, OrderFlags, Phase, Poll,
    Record, Side, StepEntry, StepLogProd, Stp, Tif, TxProd,
};
use vyrn_cut::{
    BboFloor, Consumer, Counter, CounterLine, CutEntry, CutWriter, ENG_STEP_LOG, ENG_TX_RING,
    FillRing, Floor, FwdRing, HalfCut, HalfCutVal, Hw, LANES_PER_HALF, LaneCut, LaneCutEntry,
    Line64, Producer, STEP_LOG_READERS, Snapshot, SnapshotLine, StepLog, TxRing,
};
use vyrn_lane::{
    Arena, ArenaConfig, ArenaView, Config, Lane, LaneBook, LogRec, Mid, PathTable, Ports, RespPkt,
    Rx, RxIn, SessionSpec, lane::FWD_DEADLINE_NS,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, Route, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, Handle, LaneId, LaneSeq, MAX_REQ_PAYLOAD, Nanos, PktHash, Qty,
    SessionId, StepId, Tick,
};
use vyrn_wire::{Msg, ReqHeader, encode_request};

pub const N: usize = 3;
pub const NA: usize = 16;
pub const BOOK: BookId = BookId(7);
pub const TICK_MAX: u32 = 512;

pub fn bbo_cfg_pool(pool: u64) -> vyrn_bbo::Config {
    vyrn_bbo::Config {
        n_lanes: u8::try_from(N).unwrap(),
        epoch: Epoch(0),
        slot_cap: 1024,
        seg_cap: 1024,
        win_center: Tick(100),
        phase: Phase::Continuous,
        tick_min: Tick(1),
        tick_max: Tick(TICK_MAX),
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(100),
        pool,
    }
}

pub fn bbo_cfg() -> vyrn_bbo::Config {
    bbo_cfg_pool(0)
}

/// Sessions per lane the harness can address (`sid(l, a)` with `a` below this).
pub const NS: usize = 64;

pub fn arena_cfg() -> ArenaConfig {
    ArenaConfig {
        slot_cap: 1024,
        seg_cap: 1024,
        tick_min: Tick(1),
        tick_max: Tick(TICK_MAX),
        accounts: u32::try_from(NA).unwrap(),
        journal: 1024,
    }
}

pub fn lane_cfg(l: usize) -> Config {
    Config {
        lane: lid(l),
        n_lanes: u8::try_from(N).unwrap(),
        epoch: Epoch(0),
        book: BOOK,
        spec: BookSpec::new(1, Tick(1), Tick(TICK_MAX), 10_000).unwrap(),
        path: PathTable::spec(),
        fwd_deadline_ns: FWD_DEADLINE_NS,
        phase: Phase::Continuous,
        out_cap: 4096,
    }
}

pub fn lid(l: usize) -> LaneId {
    LaneId(u8::try_from(l).unwrap())
}

/// Session `a` of lane `l` (`session_lane` = bits 12..20, generation 1).
pub fn sid(l: usize, a: u32) -> SessionId {
    SessionId((1 << 20) | (u32::try_from(l).unwrap() << 12) | a)
}

pub fn kseq(l: usize, a: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0] = u8::try_from(l).unwrap();
    k[1] = u8::try_from(a).unwrap();
    k[15] = 0x5A;
    k
}

pub fn day(side: Side) -> OrderFlags {
    OrderFlags::new(side, Tif::Day, false, Stp::None)
}

pub fn ioc(side: Side) -> OrderFlags {
    OrderFlags::new(side, Tif::Ioc, false, Stp::None)
}

pub fn wire_flags(f: OrderFlags) -> vyrn_wire::OrderFlags {
    vyrn_wire::OrderFlags::from_byte(f.0).unwrap()
}

pub fn new(f: OrderFlags, tick: u32, qty: u32, tag: u32) -> Msg {
    Msg::New {
        flags: wire_flags(f),
        tick: Tick(tick),
        qty: Qty(qty),
        client_tag: tag,
    }
}

pub fn cancel(h: Handle, tag: u32) -> Msg {
    Msg::Cancel {
        handle: h,
        client_tag: tag,
    }
}

/// Owned rings and lines; boxed so the split handles can borrow them in place.
pub struct World {
    arenas: Vec<Arena>,
    fwd: Vec<FwdRing<Hw>>,
    fill: Vec<FillRing<Hw>>,
    counters: Vec<CounterLine<Hw>>,
    lane_cuts: Vec<LaneCut<Hw>>,
    lane_snaps: Vec<SnapshotLine<Hw>>,
    half_a: HalfCut<Hw>,
    half_b: HalfCut<Hw>,
    ctl: ControlRing<Hw>,
    log: StepLog<Hw>,
    tx: Vec<TxRing<Hw>>,
    snap: SnapshotLine<Hw>,
    floor: BboFloor<Hw>,
}

impl World {
    pub fn new(init: &Snapshot) -> Box<Self> {
        let c0 = Counter {
            snap_ver: u32::try_from(init.version).unwrap(),
            ..Counter::default()
        };
        Box::new(Self {
            arenas: (0..N).map(|_| Arena::new(arena_cfg())).collect(),
            fwd: (0..N).map(|_| FwdRing::new(&Hw)).collect(),
            fill: (0..N).map(|_| FillRing::new(&Hw)).collect(),
            counters: (0..N).map(|_| CounterLine::new(&Hw, &c0)).collect(),
            lane_cuts: (0..N)
                .map(|_| LaneCut::new(&Hw, &LaneCutEntry::default()))
                .collect(),
            lane_snaps: (0..N).map(|_| SnapshotLine::new(&Hw, init)).collect(),
            half_a: HalfCut::new(&Hw, &HalfCutVal::default()),
            half_b: HalfCut::new(&Hw, &HalfCutVal::default()),
            ctl: ControlRing::new(&Hw),
            log: StepLog::new(&Hw),
            tx: (0..2).map(|_| TxRing::new(&Hw)).collect(),
            snap: SnapshotLine::new(&Hw, init),
            floor: BboFloor::new(&Hw, &Floor::default()),
        })
    }

    pub fn rig(&mut self) -> Rig<'_> {
        let mut lanes = Vec::new();
        let mut views = Vec::new();
        let mut fwd_c = Vec::new();
        let mut fill_p = Vec::new();
        let it = self
            .arenas
            .iter_mut()
            .zip(self.fwd.iter_mut())
            .zip(self.fill.iter_mut())
            .zip(self.counters.iter())
            .zip(self.lane_cuts.iter())
            .zip(self.lane_snaps.iter())
            .enumerate();
        for (l, (((((a, fw), fi), counter), lane_cut), snapshot)) in it {
            let (aw, av) = a.split().unwrap();
            let (fp, [fc]) = fw.split().unwrap();
            let (ip, [ic]) = fi.split().unwrap();
            let ports = Ports {
                fwd: fp,
                fill: ic,
                counter,
                snapshot,
                lane_cut,
            };
            let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
            acct.max_open_orders = 1000;
            let mut lane = Lane::<Hw, NA>::new(lane_cfg(l), aw, ports, acct);
            for a in 1..u32::try_from(NA).unwrap() {
                let (_, bal) = lane.account_mut(AcctSlot(a)).unwrap();
                bal.quote_free = 1 << 60;
                bal.base_free = 1 << 40;
                assert!(lane.open_session(&SessionSpec {
                    id: sid(l, a),
                    acct: AcctSlot(a),
                    k_seq: kseq(l, a),
                    book: BOOK,
                    buckets: SessionBuckets::default(),
                }));
            }
            lanes.push(lane);
            views.push(av);
            fwd_c.push(fc);
            fill_p.push(ip);
        }
        let (mut tx_p, mut tx_c) = (Vec::new(), Vec::new());
        for r in &mut self.tx {
            let (p, [c]) = r.split().unwrap();
            tx_p.push(p);
            tx_c.push(c);
        }
        let (ctl_p, [ctl_c]) = self.ctl.split().unwrap();
        let (log_p, [log_c, ..]) = self.log.split().unwrap();
        Rig {
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
            counters: &self.counters,
            lane_cuts: &self.lane_cuts,
            lane_snaps: &self.lane_snaps,
            half_a: &self.half_a,
            half_b: &self.half_b,
            snap: &self.snap,
            floor: &self.floor,
            cw: [CutWriter::new(), CutWriter::new()],
            hold: [false; N],
            cut: [LaneSeq(0); N],
            pkt: [[0; NS]; N],
            tr: None,
            seen: ([0; N], [0; N], 0),
            steps: Vec::new(),
            resp: (0..N).map(|_| Vec::new()).collect(),
            log: (0..N).map(|_| Vec::new()).collect(),
        }
    }
}

/// One step as the stream core reads it.
#[derive(Clone, Debug)]
pub struct Step {
    pub entry: StepEntry,
    pub events: Vec<(usize, FillEvent)>,
    /// Fill TX core packets: header and records.
    pub tx: Vec<(vyrn_bbo::TxEntry, Vec<Record>)>,
    /// `C_f[l]` after this step.
    pub cuts: [LaneSeq; N],
}

impl Step {
    pub fn of(&self, k: FillKind) -> Vec<(usize, FillEvent)> {
        self.events
            .iter()
            .filter(|(_, e)| e.fill_kind() == Some(k))
            .copied()
            .collect()
    }
}

pub struct Rig<'a> {
    pub lanes: Vec<Lane<'a, Hw, NA>>,
    pub views: Vec<ArenaView<'a>>,
    fwd_c: Vec<FwdCons<'a, Hw>>,
    fill_p: Vec<FillProd<'a, Hw>>,
    ctl_p: Producer<'a, Line64, { vyrn_bbo::ENG_CONTROL_RING }, 1, Hw>,
    ctl_c: ControlCons<'a, Hw>,
    log_p: StepLogProd<'a, Hw>,
    log_c: Consumer<'a, Line64, ENG_STEP_LOG, STEP_LOG_READERS, Hw>,
    tx_p: Vec<TxProd<'a, Hw>>,
    tx_c: Vec<Consumer<'a, Line64, ENG_TX_RING, 1, Hw>>,
    counters: &'a [CounterLine<Hw>],
    lane_cuts: &'a [LaneCut<Hw>],
    lane_snaps: &'a [SnapshotLine<Hw>],
    half_a: &'a HalfCut<Hw>,
    half_b: &'a HalfCut<Hw>,
    snap: &'a SnapshotLine<Hw>,
    floor: &'a BboFloor<Hw>,
    cw: [CutWriter; 2],
    /// Held lanes (see the module doc).
    pub hold: [bool; N],
    /// `C_f[l]` of the newest step.
    pub cut: [LaneSeq; N],
    /// Last `pkt_seq` sent per lane and session.
    pkt: [[u32; NS]; N],
    /// The language-neutral transcript (tests/golden/lane/README.md), when recording.
    pub tr: Option<Vec<String>>,
    /// Responses, log records and steps already written to `tr`.
    seen: ([usize; N], [usize; N], usize),
    pub steps: Vec<Step>,
    /// Everything each lane produced, in order.
    pub resp: Vec<Vec<RespPkt>>,
    pub log: Vec<Vec<LogRec>>,
}

impl Rig<'_> {
    /// Session `a` of lane `l` sends one packet at `rx_ts`, processed on time.
    pub fn send(&mut self, l: usize, a: u32, rx_ts: u64, msgs: &[Msg]) -> Rx {
        self.send_at(l, a, rx_ts, rx_ts, msgs, &[])
    }

    /// As [`Self::send`] with the lane's clock at `now` and caller-chosen boundaries.
    pub fn send_at(
        &mut self,
        l: usize,
        a: u32,
        rx_ts: u64,
        now: u64,
        msgs: &[Msg],
        mids: &[Mid],
    ) -> Rx {
        self.send_impl(l, a, rx_ts, now, msgs, mids, None)
    }

    /// Replay of one packet with forced routes (`Lane::replay_packet`, 05 §10).
    pub fn replay(
        &mut self,
        l: usize,
        a: u32,
        rx_ts: u64,
        msgs: &[Msg],
        mids: &[Mid],
        routes: &[(LaneSeq, Route)],
    ) -> Rx {
        self.send_impl(l, a, rx_ts, rx_ts, msgs, mids, Some(routes))
    }

    fn send_impl(
        &mut self,
        l: usize,
        a: u32,
        rx_ts: u64,
        now: u64,
        msgs: &[Msg],
        mids: &[Mid],
        routes: Option<&[(LaneSeq, Route)]>,
    ) -> Rx {
        let ai = usize::try_from(a).unwrap();
        self.pkt[l][ai] += 1;
        let hdr = ReqHeader::new(sid(l, a), self.pkt[l][ai], Epoch(0).low16(), BOOK, false);
        let mut buf = [0u8; MAX_REQ_PAYLOAD];
        let n = encode_request(&mut buf, hdr, msgs, &kseq(l, a), None).unwrap();
        let rx = RxIn {
            bytes: &buf[..n],
            rx_ts: Nanos(rx_ts),
            pkt_hash: PktHash(u64::from(self.pkt[l][ai])),
        };
        if self.tr.is_some() {
            let mut line = format!("pkt {l} {:#x} rx={rx_ts} now={now}", sid(l, a).0);
            for m in mids {
                line += &format!(
                    " mid={}:{}@{}/{}",
                    m.pass, m.next.0, m.at.step.0, m.at.cut.0
                );
            }
            line += &format!(" {}", hex(&buf[..n]));
            self.note(line);
        }
        let r = match routes {
            None => self.lanes[l].process_packet(&Hw, rx, &FixedClock(now), mids),
            Some(rt) => self.lanes[l].replay_packet(&Hw, rx, &FixedClock(now), mids, rt),
        };
        self.hold[l] = false;
        if r == Rx::Shed {
            self.pkt[l][ai] -= 1; // not accepted: the client resends this pkt_seq (05 §6.8)
        }
        self.collect(l);
        self.note_out();
        r
    }

    /// Lane `l` keeps its snapshot and runs no idle polls until its next packet.
    pub fn hold(&mut self, l: usize) {
        self.note(format!("hold {l}"));
        self.hold[l] = true;
    }

    /// Lane `l`'s snapshot is `s`, and its snapshot line holds `s` until its next packet (a
    /// held lane, 05 §2.5).
    pub fn pin_snapshot(&mut self, l: usize, s: &Snapshot) {
        self.lanes[l].restore_snapshot(*s);
        self.lane_snaps[l].publish(&Hw, s);
        self.hold[l] = true;
    }

    /// Opens another session `a` on lane `l` for lane-local account `acct`.
    pub fn open(&mut self, l: usize, a: u32, acct: u32, buckets: SessionBuckets) {
        assert!(self.lanes[l].open_session(&SessionSpec {
            id: sid(l, a),
            acct: AcctSlot(acct),
            k_seq: kseq(l, a),
            book: BOOK,
            buckets,
        }));
    }

    /// Takes lane `l`'s next forward-ring entry before the BBO core sees it (its header line;
    /// the dependency lines stay in the ring, so do not step the BBO after this).
    pub fn peek_fwd(&mut self, l: usize) -> vyrn_bbo::FwdEntry {
        vyrn_bbo::FwdEntry::decode(&self.fwd_c[l].pop(&Hw).unwrap())
    }

    fn note(&mut self, line: String) {
        if let Some(t) = &mut self.tr {
            t.push(line);
        }
    }

    /// Writes every output produced since the last call to the transcript.
    fn note_out(&mut self) {
        let Some(mut t) = self.tr.take() else { return };
        for st in &self.steps[self.seen.2..] {
            let e = &st.entry;
            let cuts: Vec<String> = st.cuts.iter().map(|c| c.0.to_string()).collect();
            t.push(format!(
                "  step {} kind={} src={}:{} flags={} cut={}",
                e.step.0,
                e.kind,
                e.src_lane.0,
                e.src_lane_seq.0,
                e.flags,
                cuts.join(",")
            ));
            for (l, v) in &st.events {
                t.push(format!(
                    "    ev {l} {} vslot={} h={:#x} tick={} qty={} liq={} cause={:#x}",
                    v.kind, v.vslot, v.handle.0, v.tick.0, v.qty, v.liq, v.cause
                ));
            }
            for (h, recs) in &st.tx {
                t.push(format!(
                    "    tx {:#x} resp={} echo={} role={}{}",
                    h.session.0,
                    h.resp_seq,
                    h.pkt_seq,
                    h.role,
                    recs_hex(recs)
                ));
            }
        }
        self.seen.2 = self.steps.len();
        for l in 0..N {
            for p in &self.resp[l][self.seen.0[l]..] {
                let gate = match p.gate {
                    vyrn_lane::Gate::None => "none".to_string(),
                    vyrn_lane::Gate::Packet(q) => format!("pkt:{}", q.0),
                    vyrn_lane::Gate::Step(f) => format!("step:{}", f.0),
                };
                t.push(format!(
                    "  resp {l} {:#x} resp={} echo={} gate={gate}{}",
                    p.session.0,
                    p.resp_seq,
                    p.echo_pkt,
                    recs_hex(p.records())
                ));
            }
            for rec in &self.log[l][self.seen.1[l]..] {
                t.push(match rec {
                    LogRec::Packet(r) => format!(
                        "  log {l} {:#x} pkt={} count={} flags={:#x} first={} fills_applied={} snap_lag={}",
                        r.session.0,
                        r.pkt_seq,
                        r.count,
                        r.flags,
                        r.first_lane_seq.0,
                        r.fills_applied.0,
                        r.snap_lag
                    ),
                    LogRec::Route(r) => {
                        format!("  route {l} seq={} cross={}", r.lane_seq.0, r.cross)
                    }
                });
            }
            self.seen.0[l] = self.resp[l].len();
            self.seen.1[l] = self.log[l].len();
        }
        self.tr = Some(t);
    }

    fn collect(&mut self, l: usize) {
        let lane = &mut self.lanes[l];
        self.resp[l].extend(lane.drain_responses());
        self.log[l].extend(lane.drain_log());
        assert!(!lane.fault(), "lane {l} fault");
    }

    /// The snapshot fan-out and both cut cores.
    pub fn publish(&mut self) {
        let s = self.snap.try_read(&Hw).unwrap();
        for l in 0..N {
            if !self.hold[l] {
                self.lane_snaps[l].publish(&Hw, &s);
            }
        }
        let mut a = HalfCutVal::default();
        for l in 0..N.min(LANES_PER_HALF) {
            let c = self.counters[l].try_read(&Hw).unwrap();
            a.entries[l] = CutEntry {
                seq: c.seq,
                snap_ver: c.snap_ver,
                f_lo: c.f_lo,
            };
        }
        self.cw[0].publish(self.half_a, &Hw, &a).unwrap();
        self.cw[1]
            .publish(self.half_b, &Hw, &HalfCutVal::default())
            .unwrap();
    }

    /// Publishes, then polls the BBO until one step is decided; the stream core then writes
    /// every lane's `LaneCut`. `None` if the BBO had nothing to do.
    pub fn bbo_step(&mut self, bbo: &mut Bbo) -> Option<Step> {
        self.note("step".into());
        let s = self.step_inner(bbo, &NeverLate);
        self.note_out();
        s
    }

    /// As [`Self::bbo_step`] with the BBO core's clock at `now` (its deadline test, 05 §6.8).
    pub fn bbo_step_at(&mut self, bbo: &mut Bbo, now: u64) -> Option<Step> {
        self.note(format!("step now={now}"));
        let s = self.step_inner(bbo, &FixedClock(now));
        self.note_out();
        s
    }

    fn step_inner<C: Clock>(&mut self, bbo: &mut Bbo, clock: &C) -> Option<Step> {
        self.publish();
        for _ in 0..4 {
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
                bbo.poll(&Hw, &mut ports, &book, clock)
            };
            match r {
                Poll::Step(_) => return Some(self.read_step(bbo)),
                Poll::Fault => panic!("BBO fault"),
                _ => {}
            }
        }
        None
    }

    fn read_step(&mut self, bbo: &Bbo) -> Step {
        let entry = StepEntry::decode(&self.log_c.pop(&Hw).unwrap());
        let mut deltas = Vec::new();
        for _ in 0..usize::from(entry.n_delta).div_ceil(4) {
            deltas.extend(vyrn_bbo::CutDelta::decode_line(
                &self.log_c.pop(&Hw).unwrap(),
            ));
        }
        deltas.truncate(usize::from(entry.n_delta));
        for d in &deltas {
            self.cut[usize::from(d.lane.0)] = d.seq;
        }
        let mut tx = Vec::new();
        for c in &mut self.tx_c {
            while let Some(h) = c.pop(&Hw) {
                let h = vyrn_bbo::TxEntry::decode(&h);
                let mut recs = Vec::new();
                for _ in 0..usize::from(h.n_rec).div_ceil(4) {
                    recs.extend(
                        vyrn_bbo::decode_records(&c.pop(&Hw).unwrap())
                            .into_iter()
                            .flatten(),
                    );
                }
                recs.truncate(usize::from(h.n_rec));
                tx.push((h, recs));
            }
        }
        // The step's snapshot (`done_step = entry.step`), which a lane takes at its boundary.
        let snap = self.snap.try_read(&Hw).unwrap();
        assert_eq!(snap.done_step, entry.step);
        for l in 0..N {
            self.lane_cuts[l].publish(
                &Hw,
                &LaneCutEntry {
                    step: entry.step,
                    cut: self.cut[l],
                    snap,
                },
            );
        }
        let events = bbo
            .last()
            .events()
            .iter()
            .map(|(l, e)| (usize::from(l.0), *e))
            .collect();
        let s = Step {
            entry,
            events,
            tx,
            cuts: self.cut,
        };
        self.steps.push(s.clone());
        s
    }

    /// Lane `l` runs every boundary that is due (05 §6.1 idle polls).
    pub fn lane_poll(&mut self, l: usize) -> usize {
        self.note(format!("poll {l}"));
        let n = self.poll_inner(l);
        self.note_out();
        n
    }

    fn poll_inner(&mut self, l: usize) -> usize {
        if self.hold[l] {
            return 0;
        }
        self.publish_snap(l);
        let mut n = 0;
        while self.lanes[l].poll(&Hw, &NeverLate) {
            n += 1;
        }
        self.collect(l);
        n
    }

    fn publish_snap(&mut self, l: usize) {
        let s = self.snap.try_read(&Hw).unwrap();
        self.lane_snaps[l].publish(&Hw, &s);
    }

    /// The BBO's newest snapshot.
    pub fn snapshot(&self) -> Snapshot {
        self.snap.try_read(&Hw).unwrap()
    }

    /// BBO steps and lane polls until nothing is left to do.
    pub fn settle(&mut self, bbo: &mut Bbo) {
        self.note("settle".into());
        for _ in 0..64 {
            let stepped = self.step_inner(bbo, &NeverLate).is_some();
            let mut polled = 0;
            for l in 0..N {
                polled += self.poll_inner(l);
            }
            if !stepped && polled == 0 {
                self.note_out();
                return;
            }
        }
        panic!("no quiescence");
    }

    pub fn lane_cut(&self, l: usize) -> LaneCutEntry {
        self.lane_cuts[l].try_read(&Hw).unwrap()
    }

    pub fn counter(&self, l: usize) -> Counter {
        self.counters[l].try_read(&Hw).unwrap()
    }

    /// Session `a` of lane `l`'s in-stream packets from both writers (the lane, and the fill
    /// TX core for forwarded sources, 05 §8.10), as `(resp_seq, records)` in `resp_seq` order.
    pub fn packets(&self, l: usize, a: u32) -> Vec<(u32, Vec<Record>)> {
        let s = sid(l, a);
        let mut v: Vec<(u32, Vec<Record>)> = self.resp[l]
            .iter()
            .filter(|p| p.session == s && p.resp_seq != 0)
            .map(|p| (p.resp_seq, p.records().to_vec()))
            .collect();
        for st in &self.steps {
            for (h, r) in &st.tx {
                if h.session == s && h.resp_seq != 0 {
                    v.push((h.resp_seq, r.clone()));
                }
            }
        }
        v.sort_by_key(|p| p.0);
        v
    }

    /// Every in-stream record session `a` of lane `l` received, in `resp_seq` order.
    pub fn records(&self, l: usize, a: u32) -> Vec<Record> {
        self.packets(l, a).into_iter().flat_map(|p| p.1).collect()
    }

    /// Maker-side records (`resp_seq` 0, `MakerSeq`, 05 §8.10 rule 2) of session `a`, in step
    /// order.
    pub fn maker_records(&self, l: usize, a: u32) -> Vec<Record> {
        let s = sid(l, a);
        self.steps
            .iter()
            .flat_map(|st| st.tx.iter())
            .filter(|(h, _)| h.session == s && h.resp_seq == 0)
            .flat_map(|(_, r)| r.iter().copied())
            .collect()
    }

    /// The handle of the newest `Ack` lane `l` sent to session `a`.
    pub fn last_ack(&self, l: usize, a: u32) -> Handle {
        self.records(l, a)
            .iter()
            .rev()
            .find_map(|r| match r {
                Record::Ack { handle, .. } => Some(*handle),
                _ => None,
            })
            .expect("an Ack")
    }

    pub fn fills_applied(&self, l: usize) -> StepId {
        self.lanes[l].fills_applied()
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn recs_hex(recs: &[Record]) -> String {
    recs.iter()
        .map(|r| format!(" {}", hex(&r.encode())))
        .collect()
}

pub fn setup() -> (Bbo, Box<World>) {
    setup_pool(0)
}

/// A box whose lanes in `pool` (bit `l`) are pooled (05 §6.9).
pub fn setup_pool(pool: u64) -> (Bbo, Box<World>) {
    let bbo = Bbo::new(bbo_cfg_pool(pool));
    let w = World::new(&bbo.initial_snapshot());
    (bbo, w)
}
