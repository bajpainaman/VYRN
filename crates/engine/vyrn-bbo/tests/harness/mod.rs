//! A single-threaded box around one BBO core: the lanes' ring ends, two cut writers and a
//! `MemBook`, all on `Hw` lines. Each helper does what 05 says a lane or cut core does, and no
//! more, so a test states its scenario as lane actions and BBO polls.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::too_many_arguments,
    clippy::needless_range_loop
)]

use vyrn_bbo::admit::Clock;
use vyrn_bbo::mem::{MEM_GEN, MemBook, MemOrder};
use vyrn_bbo::*;
use vyrn_cut::*;
use vyrn_types::*;

pub const N: usize = 3;
pub const BIG_DEADLINE: u32 = 0x4000_0000;

pub fn cfg() -> Config {
    Config {
        n_lanes: u8::try_from(N).unwrap(),
        epoch: Epoch(0),
        slot_cap: 1024,
        seg_cap: 1024,
        win_center: Tick(100),
        phase: Phase::Continuous,
        tick_min: Tick(1),
        tick_max: Tick(1 << 20),
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(100),
        pool: 0,
    }
}

/// Rings and lines, owned; `Box` keeps them in place while split handles borrow them.
pub struct World {
    pub half_a: HalfCut<Hw>,
    pub half_b: HalfCut<Hw>,
    pub fwd: Vec<FwdRing<Hw>>,
    pub fill: Vec<FillRing<Hw>>,
    pub ctl: ControlRing<Hw>,
    pub log: StepLog<Hw>,
    pub tx: Vec<TxRing<Hw>>,
    pub snap: SnapshotLine<Hw>,
    pub floor: BboFloor<Hw>,
}

impl World {
    pub fn new(init: &Snapshot) -> Box<Self> {
        Box::new(Self {
            half_a: HalfCut::new(&Hw, &HalfCutVal::default()),
            half_b: HalfCut::new(&Hw, &HalfCutVal::default()),
            fwd: (0..N).map(|_| FwdRing::new(&Hw)).collect(),
            fill: (0..N).map(|_| FillRing::new(&Hw)).collect(),
            ctl: ControlRing::new(&Hw),
            log: StepLog::new(&Hw),
            tx: (0..2).map(|_| TxRing::new(&Hw)).collect(),
            snap: SnapshotLine::new(&Hw, init),
            floor: BboFloor::new(&Hw, &Floor::default()),
        })
    }
}

/// One step as the stream and fill TX cores see it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub entry: StepEntry,
    pub deltas: Vec<CutDelta>,
    pub events: Vec<(usize, FillEvent)>,
    pub tx: Vec<(TxEntry, Vec<Record>)>,
}

impl Seen {
    pub fn kind(&self) -> StepKind {
        StepKind::from_code(self.entry.kind).unwrap()
    }
    pub fn fills(&self) -> Vec<(usize, u8, u32, u32)> {
        self.events
            .iter()
            .filter(|(_, e)| e.fill_kind() == Some(FillKind::Fill))
            .map(|(l, e)| (*l, e.liq, e.tick.0, e.qty))
            .collect()
    }
    pub fn of(&self, k: FillKind) -> Vec<(usize, FillEvent)> {
        self.events
            .iter()
            .filter(|(_, e)| e.fill_kind() == Some(k))
            .copied()
            .collect()
    }
    pub fn role(&self, role: u8) -> Vec<Vec<Record>> {
        self.tx
            .iter()
            .filter(|(h, _)| h.role == role)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

pub struct Lanes<'a> {
    pub fwd_p: Vec<Producer<'a, Line64, ENG_FWD_RING, 1, Hw>>,
    pub fwd_c: Vec<FwdCons<'a, Hw>>,
    pub fill_p: Vec<FillProd<'a, Hw>>,
    pub fill_c: Vec<Consumer<'a, Line32, ENG_FILL_RING, 1, Hw>>,
    pub ctl_p: Producer<'a, Line64, ENG_CONTROL_RING, 1, Hw>,
    pub ctl_c: ControlCons<'a, Hw>,
    pub log_p: StepLogProd<'a, Hw>,
    pub log_c: Consumer<'a, Line64, ENG_STEP_LOG, STEP_LOG_READERS, Hw>,
    pub tx_p: Vec<TxProd<'a, Hw>>,
    pub tx_c: Vec<Consumer<'a, Line64, ENG_TX_RING, 1, Hw>>,
    pub half_a: &'a HalfCut<Hw>,
    pub half_b: &'a HalfCut<Hw>,
    pub snap: &'a SnapshotLine<Hw>,
    pub floor: &'a BboFloor<Hw>,
    pub cw: [CutWriter; 2],
    pub book: MemBook,
    /// Per lane: last assigned `LaneSeq` and last applied step.
    pub seq: [u64; N],
    pub f: [u64; N],
    /// Snapshot version each lane reports (`CounterLine.snap_ver`); `None` = the newest.
    pub snap_ver: [Option<u32>; N],
    pub seen: Vec<Seen>,
}

impl World {
    pub fn lanes(&mut self) -> Lanes<'_> {
        let (mut fwd_p, mut fwd_c) = (Vec::new(), Vec::new());
        for r in &mut self.fwd {
            let (p, [c]) = r.split().unwrap();
            fwd_p.push(p);
            fwd_c.push(c);
        }
        let (mut fill_p, mut fill_c) = (Vec::new(), Vec::new());
        for r in &mut self.fill {
            let (p, [c]) = r.split().unwrap();
            fill_p.push(p);
            fill_c.push(c);
        }
        let (mut tx_p, mut tx_c) = (Vec::new(), Vec::new());
        for r in &mut self.tx {
            let (p, [c]) = r.split().unwrap();
            tx_p.push(p);
            tx_c.push(c);
        }
        let (ctl_p, [ctl_c]) = self.ctl.split().unwrap();
        let (log_p, [log_c, ..]) = self.log.split().unwrap();
        Lanes {
            fwd_p,
            fwd_c,
            fill_p,
            fill_c,
            ctl_p,
            ctl_c,
            log_p,
            log_c,
            tx_p,
            tx_c,
            half_a: &self.half_a,
            half_b: &self.half_b,
            snap: &self.snap,
            floor: &self.floor,
            cw: [CutWriter::new(), CutWriter::new()],
            book: MemBook::new(N),
            seq: [0; N],
            f: [0; N],
            snap_ver: [None; N],
            seen: Vec::new(),
        }
    }
}

pub fn lid(l: usize) -> LaneId {
    LaneId(u8::try_from(l).unwrap())
}

pub fn order(
    l: usize,
    seq: u64,
    ts: u64,
    flags: OrderFlags,
    tick: u32,
    qty: u32,
    acct: u32,
) -> MemOrder {
    MemOrder {
        flags,
        tick: Tick(tick),
        qty,
        seq: LaneSeq(seq),
        ts: Nanos(ts),
        acct_ix: acct,
        session: SessionId(u32::try_from(100 + l).unwrap() * 10 + acct),
        client_tag: u32::try_from(seq).unwrap() + 1000 * u32::try_from(l).unwrap(),
    }
}

pub fn day(side: Side) -> OrderFlags {
    OrderFlags::new(side, Tif::Day, false, Stp::None)
}

pub fn new_msg(flags: OrderFlags, index: u8, tick: u32, qty: u32, tag: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = MSG_NEW;
    m[1] = flags.0;
    m[2] = index;
    m[4..8].copy_from_slice(&tick.to_le_bytes());
    m[8..12].copy_from_slice(&qty.to_le_bytes());
    m[12..16].copy_from_slice(&tag.to_le_bytes());
    m
}

impl Lanes<'_> {
    pub fn snapshot(&self) -> Snapshot {
        self.snap.try_read(&Hw).unwrap()
    }

    /// The lane forwards a `New` (05 §6.6) with its dependency lines: it writes the source
    /// slot (and each Join dependency's slot, already written by the caller), then pushes.
    #[allow(clippy::too_many_arguments)]
    pub fn forward(
        &mut self,
        l: usize,
        ts: u64,
        flags: OrderFlags,
        tick: u32,
        qty: u32,
        acct: u32,
        index: u8,
        deps: &[FwdDep],
        deadline: u32,
    ) -> (u64, u32) {
        self.seq[l] += 1;
        let q = self.seq[l];
        let o = order(l, q, ts, flags, tick, qty, acct);
        let slot = self.book.new_slot(lid(l), &o);
        let e = FwdEntry {
            lane_seq: LaneSeq(q),
            prio_ts: Nanos(ts),
            snap_ver: self.snap_ver[l].unwrap_or(u32::try_from(self.snapshot().version).unwrap()),
            deadline,
            msg: new_msg(flags, index, tick, qty, o.client_tag),
            handle: Handle::new(slot, MEM_GEN).unwrap(),
            vslot: slot,
            session: o.session,
            resp_seq: 1,
            pkt_seq: 7,
            acct_ix: u16::try_from(acct).unwrap(),
            applied_back: u16::try_from(1 + deps.len()).unwrap(),
        };
        let mut lines = [[0u64; 8]; 4];
        let n = encode_fwd(&e, deps, &mut lines);
        assert!(self.fwd_p[l].push_all(&Hw, &lines[..n]));
        (q, slot)
    }

    /// A Join dependency's slot, written in pass 1 (05 §6.6): returns its `FwdDep`.
    pub fn dep_join(
        &mut self,
        l: usize,
        ts: u64,
        flags: OrderFlags,
        tick: u32,
        qty: u32,
        acct: u32,
        back: u8,
    ) -> FwdDep {
        self.seq[l] += 1;
        let o = order(l, self.seq[l], ts, flags, tick, qty, acct);
        let slot = self.book.new_slot(lid(l), &o);
        FwdDep {
            back,
            kind: DEP_JOIN,
            flags,
            pos: 0,
            tick: Tick(tick),
            qty: Qty(qty),
            slot,
        }
    }

    /// A local join applied in pass 2 (05 §6.4): slot, position, journal.
    pub fn join(
        &mut self,
        l: usize,
        ts: u64,
        flags: OrderFlags,
        tick: u32,
        qty: u32,
        acct: u32,
    ) -> u32 {
        self.seq[l] += 1;
        let o = order(l, self.seq[l], ts, flags, tick, qty, acct);
        self.book.rest(lid(l), &o)
    }

    /// A local cancel of version `slot` (05 §4.6).
    pub fn cancel(&mut self, l: usize, slot: u32, ts: u64) {
        self.seq[l] += 1;
        self.book
            .tombstone(lid(l), slot, LaneSeq(self.seq[l]), Nanos(ts));
    }

    /// B1 for every lane: drain fill events, write explicit positions (05 §7.4).
    pub fn apply_events(&mut self) {
        for l in 0..N {
            while let Some(line) = self.fill_c[l].pop(&Hw) {
                let ev = FillEvent::decode(&line);
                match ev.fill_kind() {
                    Some(FillKind::Rested) => self.book.place(lid(l), ev.vslot),
                    Some(FillKind::Dep) if ev.liq == DEP_JOIN && ev.cause == 0 => {
                        self.book.place(lid(l), ev.vslot)
                    }
                    _ => {}
                }
                self.f[l] = ev.step.0;
            }
        }
    }

    /// Both cut cores publish: every lane's last seq, its snapshot version, its `f_lo`.
    pub fn publish_cut(&mut self) {
        let v = u32::try_from(self.snapshot().version).unwrap();
        let entry = |s: &Self, l: usize| CutEntry {
            seq: LaneSeq(s.seq[l]),
            snap_ver: s.snap_ver[l].unwrap_or(v),
            f_lo: u32::try_from(s.f[l]).unwrap(),
        };
        let mut a = HalfCutVal::default();
        for l in 0..N.min(LANES_PER_HALF) {
            a.entries[l] = entry(self, l);
        }
        self.cw[0].publish(self.half_a, &Hw, &a).unwrap();
        self.cw[1]
            .publish(self.half_b, &Hw, &HalfCutVal::default())
            .unwrap();
    }

    pub fn control(&mut self, c: ControlCmd) {
        assert!(self.ctl_p.push(&Hw, c.encode()).is_ok());
    }

    /// One BBO pass; a decided step is read back from every ring.
    pub fn poll<C: Clock>(&mut self, bbo: &mut Bbo, clock: &C) -> Poll {
        let mut ports = Ports {
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
        let r = bbo.poll(&Hw, &mut ports, &self.book, clock);
        if let Poll::Step(_) = r {
            let seen = self.read_step(bbo);
            self.seen.push(seen);
        }
        r
    }

    fn read_step(&mut self, bbo: &Bbo) -> Seen {
        let entry = StepEntry::decode(&self.log_c.pop(&Hw).unwrap());
        let mut deltas = Vec::new();
        for _ in 0..usize::from(entry.n_delta).div_ceil(4) {
            deltas.extend(CutDelta::decode_line(&self.log_c.pop(&Hw).unwrap()));
        }
        deltas.truncate(usize::from(entry.n_delta));
        let mut tx = Vec::new();
        for c in &mut self.tx_c {
            while let Some(h) = c.pop(&Hw) {
                let h = TxEntry::decode(&h);
                let mut recs = Vec::new();
                for _ in 0..usize::from(h.n_rec).div_ceil(4) {
                    recs.extend(decode_records(&c.pop(&Hw).unwrap()).into_iter().flatten());
                }
                recs.truncate(usize::from(h.n_rec));
                tx.push((h, recs));
            }
        }
        // Events are read from the BBO's own copy so `apply_events` still finds them in the ring.
        let events = bbo
            .last()
            .events()
            .iter()
            .map(|(l, e)| (usize::from(l.0), *e))
            .collect();
        Seen {
            entry,
            deltas,
            events,
            tx,
        }
    }

    /// Poll until a step is published.
    pub fn step<C: Clock>(&mut self, bbo: &mut Bbo, clock: &C) -> Seen {
        for _ in 0..4 {
            match self.poll(bbo, clock) {
                Poll::Step(_) => return self.seen.last().unwrap().clone(),
                Poll::Fault => panic!("engine fault"),
                _ => {}
            }
        }
        panic!("no step")
    }
}
