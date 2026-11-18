//! The cluster run (crate docs, "Cluster"): one seeded event loop over the real engine.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;

use rand::RngExt;
use rand_chacha::ChaCha8Rng;
use vyrn_bbo::admit::FixedClock;
use vyrn_bbo::{Bbo, OrderFlags, Phase, Record, Side, Stp, Tif, TxEntry};
use vyrn_cut::Hw;
use vyrn_engine::{Engine, OwnedRec, Payloads, Rec, Shared, Sink};
use vyrn_lane::{
    ArenaConfig, Config as LaneConfig, Gate, Lane, PathTable, RespPkt, Rx, RxIn, SessionSpec,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, LaneId, MAX_REQ_PAYLOAD, Nanos, PacketFlags, PacketRecord, Qty,
    SessionId, Tick,
};
use vyrn_wire::{Msg, ReqHeader, encode_request};

use crate::check::{Checker, Obs, Violation};
use crate::rng::stream;

/// Lane-local account slots per lane; sessions use slots `1..NA`.
pub const NA: usize = 8;
/// Packets a client keeps unaccepted at once.
pub const WINDOW: usize = 4;
/// Every lane's idle-poll period.
pub const POLL_NS: u64 = 10_000;
/// A client resends its unaccepted packets this often.
pub const RESEND_NS: u64 = 25_000;
/// Virtual time after the workload and the last fault within which every client must finish
/// (`BLD_SIM_HEAL_MS`, compressed for the per-PR budget: spec gap, PR).
pub const HEAL_NS: u64 = 2_000_000;
/// Step-and-poll rounds after which a BBO run that still has work is a livelock: one packet
/// of at most 3 orders needs far fewer (`BBO-QUIESCE`).
pub const QUIESCE_ROUNDS: usize = 4096;
/// Virtual cost of one lane packet and of one BBO run.
const LANE_COST: u64 = 150;
const BBO_COST: u64 = 100;
const BOOK: BookId = BookId(7);
const TICK_MAX: u32 = 512;
/// Events kept for a failure report (11 §6.4: "the last 10,000 events").
pub const TAIL: usize = 10_000;

/// What one seed runs (11 §6.4 "Swarm testing").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub lanes: usize,
    /// Sessions per lane (slots `1..=sessions`).
    pub sessions: u32,
    pub replicas: usize,
    /// Packets each client sends.
    pub packets: u32,
    /// Mean gap between a client's sends, ns.
    pub gap_ns: u64,
    /// Fault classes the generated schedule may use: bit 0 network, 1 lane stall, 2 BBO stall.
    pub classes: u8,
}

impl Config {
    pub fn from_seed(seed: u64) -> Self {
        let mut r = stream(seed, "config");
        let lanes = r.random_range(1..=8usize);
        let sessions = r.random_range(1..=u32::try_from(NA - 1).unwrap_or(1));
        let clients = u32::try_from(lanes).unwrap_or(1).saturating_mul(sessions);
        // At most ~400 packets in total keeps a run in the per-PR budget.
        let packets = r.random_range(4..=(400 / clients).clamp(4, 40));
        Self {
            lanes,
            sessions,
            replicas: r.random_range(2..=4usize),
            packets,
            gap_ns: r.random_range(500..=20_000u64),
            classes: r.random_range(0..8u8),
        }
    }
    fn clients(&self) -> usize {
        self.lanes
            .saturating_mul(usize::try_from(self.sessions).unwrap_or(0))
    }
    /// Virtual time by which every client has had time to send everything.
    fn duration_ns(&self) -> u64 {
        u64::from(self.packets).saturating_mul(self.gap_ns.saturating_mul(2))
    }
}

/// One injected fault (11 §6.4 fault catalogue).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// SF-01: the `pkt`-th client transmission (0-based, resends included) is lost.
    Drop { pkt: u32 },
    /// SF-01: it arrives twice.
    Dup { pkt: u32 },
    /// SF-01: it arrives `ns` late (reordering).
    Delay { pkt: u32, ns: u64 },
    /// SF-11 / SF-27: lane `lane` takes no packet in `[at, at + ns)`.
    LaneStall { lane: u8, at: u64, ns: u64 },
    /// SF-12: the BBO core does not run in `[at, at + ns)`.
    BboStall { at: u64, ns: u64 },
    /// SF-24: replica `replica` gets record `rec` with one field changed.
    Diverge { replica: u8, rec: u32 },
}

impl Fault {
    fn end(&self) -> u64 {
        match *self {
            Self::LaneStall { at, ns, .. } | Self::BboStall { at, ns } => at.saturating_add(ns),
            _ => 0,
        }
    }
}

/// A fault schedule. Text form: faults separated by `;`, each one of `drop <pkt>`,
/// `dup <pkt>`, `delay <pkt> <ns>`, `lane-stall <lane> <at> <ns>`, `bbo-stall <at> <ns>`,
/// `diverge <replica> <rec>`. The empty string is the empty schedule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Schedule(pub Vec<Fault>);

impl Schedule {
    /// The schedule seed `seed` runs with: faults of `cfg.classes` only, never SF-24.
    pub fn generate(seed: u64, cfg: &Config) -> Self {
        let mut r = stream(seed, "faults");
        let mut v = Vec::new();
        let tx = u32::try_from(cfg.clients())
            .unwrap_or(1)
            .saturating_mul(cfg.packets)
            .max(1);
        let dur = cfg.duration_ns().max(1);
        for _ in 0..r.random_range(0..=12u32) {
            let class = r.random_range(0..3u8);
            if cfg.classes & (1 << class) == 0 {
                continue;
            }
            v.push(match class {
                0 => {
                    let pkt = r.random_range(0..tx);
                    match r.random_range(0..3u8) {
                        0 => Fault::Drop { pkt },
                        1 => Fault::Dup { pkt },
                        _ => Fault::Delay {
                            pkt,
                            ns: r.random_range(100..=50_000),
                        },
                    }
                }
                1 => Fault::LaneStall {
                    lane: r.random_range(0..u8::try_from(cfg.lanes).unwrap_or(1)),
                    at: r.random_range(0..dur),
                    ns: r.random_range(1_000..=1_000_000),
                },
                _ => Fault::BboStall {
                    at: r.random_range(0..dur),
                    ns: r.random_range(1_000..=100_000),
                },
            });
        }
        Self(v)
    }

    pub fn render(&self) -> String {
        let v: Vec<String> = self
            .0
            .iter()
            .map(|f| match *f {
                Fault::Drop { pkt } => format!("drop {pkt}"),
                Fault::Dup { pkt } => format!("dup {pkt}"),
                Fault::Delay { pkt, ns } => format!("delay {pkt} {ns}"),
                Fault::LaneStall { lane, at, ns } => format!("lane-stall {lane} {at} {ns}"),
                Fault::BboStall { at, ns } => format!("bbo-stall {at} {ns}"),
                Fault::Diverge { replica, rec } => format!("diverge {replica} {rec}"),
            })
            .collect();
        v.join("; ")
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        fn n<T: std::str::FromStr>(t: &[&str], i: usize) -> Result<T, String> {
            let x = t.get(i).ok_or("missing field")?;
            x.parse().map_err(|_| format!("bad number {x:?}"))
        }
        let mut v = Vec::new();
        for part in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let t: Vec<&str> = part.split_whitespace().collect();
            v.push(match t.first().copied() {
                Some("drop") => Fault::Drop { pkt: n(&t, 1)? },
                Some("dup") => Fault::Dup { pkt: n(&t, 1)? },
                Some("delay") => Fault::Delay {
                    pkt: n(&t, 1)?,
                    ns: n(&t, 2)?,
                },
                Some("lane-stall") => Fault::LaneStall {
                    lane: n(&t, 1)?,
                    at: n(&t, 2)?,
                    ns: n(&t, 3)?,
                },
                Some("bbo-stall") => Fault::BboStall {
                    at: n(&t, 1)?,
                    ns: n(&t, 2)?,
                },
                Some("diverge") => Fault::Diverge {
                    replica: n(&t, 1)?,
                    rec: n(&t, 2)?,
                },
                _ => return Err(format!("unknown fault {part:?}")),
            });
        }
        Ok(Self(v))
    }
}

/// Counts from one run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub events: u64,
    pub records: u64,
    pub steps: u64,
    pub fills: u64,
    pub accepted: u64,
    pub shed: u64,
    pub end_ns: u64,
}

/// The result of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub seed: u64,
    pub config: Config,
    pub schedule: Schedule,
    /// BLAKE3 over every event and every engine output, in order.
    pub trace: [u8; 32],
    pub stats: Stats,
    pub violation: Option<Violation>,
    /// The last [`TAIL`] events, one line each (only kept on failure).
    pub tail: Vec<String>,
}

impl Report {
    pub fn trace_hex(&self) -> String {
        self.trace.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }
}

#[derive(Clone, Debug)]
enum Ev {
    Send(usize),
    Resend(usize),
    Arrive {
        c: usize,
        bytes: Vec<u8>,
    },
    Process {
        c: usize,
        rx_ts: u64,
        bytes: Vec<u8>,
    },
    Verdict {
        c: usize,
        pkt_seq: u32,
        rx: Rx,
    },
    Bbo,
    Poll,
}

impl Ev {
    fn line(&self, t: u64) -> String {
        match self {
            Self::Send(c) => format!("{t} send c{c}"),
            Self::Resend(c) => format!("{t} resend c{c}"),
            Self::Arrive { c, bytes } => format!("{t} arrive c{c} {}", hex(bytes)),
            Self::Process { c, rx_ts, bytes } => {
                format!("{t} process c{c} rx_ts={rx_ts} {}", hex(bytes))
            }
            Self::Verdict { c, pkt_seq, rx } => format!("{t} verdict c{c} pkt {pkt_seq} {rx:?}"),
            Self::Bbo => format!("{t} bbo"),
            Self::Poll => format!("{t} poll"),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Everything an engine emitted, in order.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Out {
    pub recs: Vec<OwnedRec>,
    pub resp: Vec<(LaneId, RespPkt)>,
    pub tx: Vec<(TxEntry, Vec<Record>)>,
}

impl Sink for Out {
    fn record(&mut self, r: &Rec<'_>) {
        self.recs.push(OwnedRec::of(r));
    }
    fn lane_resp(&mut self, lane: LaneId, p: &RespPkt) {
        self.resp.push((lane, *p));
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        self.tx.push((*h, recs.to_vec()));
    }
}

/// Packet bytes by `(lane, session, pkt_seq, rx_ts)`: the data tier's role for replay.
#[derive(Default, Debug)]
pub struct Store(BTreeMap<(u8, u32, u32, u64), Vec<u8>>);

impl Payloads for Store {
    fn get(&self, r: &PacketRecord) -> Option<&[u8]> {
        self.0
            .get(&(r.lane.0, r.session.0, r.pkt_seq, r.rx_ts.0))
            .map(Vec::as_slice)
    }
}

fn sid(l: usize, a: u32) -> SessionId {
    SessionId((1 << 20) | (u32::try_from(l).unwrap_or(0) << 12) | a)
}

fn kseq(l: usize, a: u32) -> [u8; 16] {
    let mut k = [0x5Au8; 16];
    k[0] = u8::try_from(l).unwrap_or(0);
    k[1] = u8::try_from(a).unwrap_or(0);
    k
}

fn bbo_cfg(n: usize) -> vyrn_bbo::Config {
    vyrn_bbo::Config {
        n_lanes: u8::try_from(n).unwrap_or(1),
        epoch: Epoch(0),
        slot_cap: 4096,
        seg_cap: 4096,
        win_center: Tick(100),
        phase: Phase::Continuous,
        tick_min: Tick(1),
        tick_max: Tick(TICK_MAX),
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(100),
        pool: 0,
    }
}

fn arena_cfg() -> ArenaConfig {
    ArenaConfig {
        slot_cap: 4096,
        seg_cap: 4096,
        tick_min: Tick(1),
        tick_max: Tick(TICK_MAX),
        accounts: u32::try_from(NA).unwrap_or(1),
        journal: 4096,
    }
}

fn lane_cfgs(n: usize) -> Vec<LaneConfig> {
    (0..n)
        .map(|l| LaneConfig {
            lane: LaneId(u8::try_from(l).unwrap_or(0)),
            n_lanes: u8::try_from(n).unwrap_or(1),
            epoch: Epoch(0),
            book: BOOK,
            spec: BookSpec::new(1, Tick(1), Tick(TICK_MAX), 10_000).unwrap_or_else(|| {
                unreachable!("constant book spec");
            }),
            path: PathTable::spec(),
            fwd_deadline_ns: vyrn_lane::lane::FWD_DEADLINE_NS,
            phase: Phase::Continuous,
            out_cap: 4096,
        })
        .collect()
}

/// A box: `cfg.lanes` lanes, sessions `1..=cfg.sessions` on each, every account funded.
/// The sequencer and every replica build the same box (07: replicas start from the same state).
fn new_box(n: usize) -> (Bbo, Box<Shared<Hw>>) {
    let bbo = Bbo::new(bbo_cfg(n));
    let sh = Shared::new(&Hw, n, arena_cfg(), &bbo.initial_snapshot())
        .unwrap_or_else(|| unreachable!("lane count is 1..=8"));
    (bbo, sh)
}

fn engine<'a>(bbo: Bbo, sh: &'a mut Shared<Hw>, cfg: &Config) -> Engine<'a, Hw, NA> {
    let sessions = cfg.sessions;
    Engine::new(&Hw, sh, bbo, &lane_cfgs(cfg.lanes), |lc, aw, ports| {
        let l = usize::from(lc.lane.0);
        let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
        acct.max_open_orders = 4000;
        let mut lane = Lane::<Hw, NA>::new(lc, aw, ports, acct);
        for a in 1..=sessions {
            if let Some((_, bal)) = lane.account_mut(AcctSlot(a)) {
                bal.quote_free = 1 << 60;
                bal.base_free = 1 << 40;
            }
            lane.open_session(&SessionSpec {
                id: sid(l, a),
                acct: AcctSlot(a),
                k_seq: kseq(l, a),
                book: BOOK,
                buckets: SessionBuckets::default(),
            });
        }
        lane
    })
    .unwrap_or_else(|| unreachable!("lane configs match the box"))
}

struct Client {
    lane: usize,
    slot: u32,
    next_pkt: u32,
    to_send: u32,
    tag: u32,
    out: BTreeMap<u32, Vec<u8>>,
}

impl Client {
    fn done(&self) -> bool {
        self.to_send == 0 && self.out.is_empty()
    }
}

struct Queue {
    q: BTreeMap<(u64, u64, u64), Ev>,
    seq: u64,
    tie: ChaCha8Rng,
}

impl Queue {
    fn push(&mut self, t: u64, e: Ev) {
        self.seq = self.seq.saturating_add(1);
        let tie = self.tie.random_range(0..u64::MAX);
        self.q.insert((t, tie, self.seq), e);
    }
    fn pop(&mut self) -> Option<(u64, Ev)> {
        self.q.pop_first().map(|((t, _, _), e)| (t, e))
    }
}

/// Logical form for `INV-DET`: the physical publication ids are zeroed (`vyrn-engine`'s
/// `Why::Mismatch` contract).
fn logical(recs: &[OwnedRec]) -> Vec<OwnedRec> {
    recs.iter()
        .map(|r| match *r {
            OwnedRec::Step(e, d) => OwnedRec::Step(
                vyrn_bbo::StepEntry {
                    pub_a: 0,
                    pub_b: 0,
                    ..e
                },
                d,
            ),
            p => p,
        })
        .collect()
}

/// In-stream responses only: an out-of-stream one (`Gate::None`, 04 §3.2) answers a packet the
/// order stream does not hold, so replay cannot and need not reproduce it.
fn in_stream(r: &[(LaneId, RespPkt)]) -> Vec<(LaneId, RespPkt)> {
    r.iter()
        .filter(|(_, p)| p.gate != Gate::None)
        .copied()
        .collect()
}

/// The first position where a replica's outputs leave the live run's.
fn first_diff<T: PartialEq + std::fmt::Debug>(
    r: usize,
    what: &str,
    live: &[T],
    rep: &[T],
) -> String {
    let i = live
        .iter()
        .zip(rep)
        .position(|(a, b)| a != b)
        .unwrap_or(live.len().min(rep.len()));
    format!(
        "replica {r} {what} {i} of {}/{}: live {:?}, replay {:?}",
        live.len(),
        rep.len(),
        live.get(i),
        rep.get(i)
    )
}

/// The earliest end of a lane stall that covers `t`, if any lane is stalled at `t`. The engine
/// polls all lanes in one call (`Engine::poll_lanes`, `Engine::run`), so while any lane is
/// stalled no lane is polled: a stall pauses every lane's boundaries (spec gap, PR follow-up).
fn lane_stall_end(faults: &[Fault], t: u64) -> Option<u64> {
    faults
        .iter()
        .filter_map(|f| match *f {
            Fault::LaneStall { at, ns, .. } if t >= at && t < at.saturating_add(ns) => {
                Some(at.saturating_add(ns))
            }
            _ => None,
        })
        .min()
}

fn stalled(faults: &[Fault], lane: Option<u8>, t: u64) -> u64 {
    let mut t = t;
    // Stalls may overlap; repeat until `t` is outside every one.
    loop {
        let mut moved = false;
        for f in faults {
            let (at, ns) = match (*f, lane) {
                (Fault::LaneStall { lane: fl, at, ns }, Some(l)) if fl == l => (at, ns),
                (Fault::BboStall { at, ns }, None) => (at, ns),
                _ => continue,
            };
            if t >= at && t < at.saturating_add(ns) {
                t = at.saturating_add(ns);
                moved = true;
            }
        }
        if !moved {
            return t;
        }
    }
}

/// Runs `seed` with its generated schedule.
pub fn run_seed(seed: u64) -> Report {
    let cfg = Config::from_seed(seed);
    let s = Schedule::generate(seed, &cfg);
    run(seed, &s)
}

/// Runs `seed`'s configuration and workload under `schedule` (crate docs, "Run").
pub fn run(seed: u64, schedule: &Schedule) -> Report {
    let cfg = Config::from_seed(seed);
    let faults = &schedule.0;
    let mut wl = stream(seed, "workload");
    let mut net = stream(seed, "net");
    let mut q = Queue {
        q: BTreeMap::new(),
        seq: 0,
        tie: stream(seed, "sched"),
    };
    let mut trace = blake3::Hasher::new();
    let mut tail: VecDeque<String> = VecDeque::new();
    let mut stats = Stats::default();
    let mut checker = Checker::default();
    let mut violation: Option<Violation> = None;

    let mut clients: Vec<Client> = Vec::new();
    for l in 0..cfg.lanes {
        for a in 1..=cfg.sessions {
            clients.push(Client {
                lane: l,
                slot: a,
                next_pkt: 1,
                to_send: cfg.packets,
                tag: 0,
                out: BTreeMap::new(),
            });
        }
    }
    for c in 0..clients.len() {
        let t0 = wl.random_range(0..cfg.gap_ns.max(1));
        q.push(t0, Ev::Send(c));
        q.push(t0.saturating_add(RESEND_NS), Ev::Resend(c));
    }
    q.push(POLL_NS, Ev::Poll);
    let limit = faults
        .iter()
        .map(Fault::end)
        .max()
        .unwrap_or(0)
        .max(cfg.duration_ns())
        .saturating_add(HEAL_NS);

    let (bbo, mut sh) = new_box(cfg.lanes);
    let mut e = engine(bbo, &mut sh, &cfg);
    let mut out = Out::default();
    let mut store = Store::default();
    let mut lane_free = vec![0u64; cfg.lanes];
    let mut bbo_free = 0u64;
    let mut bbo_pending = false;
    let mut tx_n: u32 = 0;
    let (mut seen_rec, mut seen_resp) = (0usize, 0usize);
    let mut now = 0u64;

    // Sends every copy of one client transmission through the network (SF-01).
    let transmit =
        |q: &mut Queue, net: &mut ChaCha8Rng, now: u64, c: usize, bytes: &[u8], tx_n: &mut u32| {
            let k = *tx_n;
            *tx_n = tx_n.saturating_add(1);
            let lat = net.random_range(500..=3_000u64);
            let mut copies = 1u32;
            let mut extra = 0u64;
            for f in faults {
                match *f {
                    Fault::Drop { pkt } if pkt == k => copies = 0,
                    Fault::Dup { pkt } if pkt == k && copies > 0 => copies = 2,
                    Fault::Delay { pkt, ns } if pkt == k => extra = ns,
                    _ => {}
                }
            }
            for i in 0..copies {
                q.push(
                    now.saturating_add(lat)
                        .saturating_add(extra)
                        .saturating_add(u64::from(i).saturating_mul(200)),
                    Ev::Arrive {
                        c,
                        bytes: bytes.to_vec(),
                    },
                );
            }
        };

    while let Some((t, ev)) = q.pop() {
        if t > limit {
            break;
        }
        now = t;
        stats.events = stats.events.saturating_add(1);
        let line = ev.line(t);
        trace.update(line.as_bytes());
        trace.update(b"\n");
        if tail.len() == TAIL {
            tail.pop_front();
        }
        tail.push_back(line);

        let mut busy: Option<(u32, u32)> = None;
        let fault = match ev {
            Ev::Send(c) => {
                let cl = &mut clients[c];
                if cl.to_send > 0 && cl.out.len() < WINDOW {
                    let n = wl.random_range(1..=3usize);
                    let mut msgs = Vec::with_capacity(n);
                    for _ in 0..n {
                        let side = if wl.random_range(0..2u8) == 0 {
                            Side::Buy
                        } else {
                            Side::Sell
                        };
                        let tif = if wl.random_range(0..10u8) < 7 {
                            Tif::Day
                        } else {
                            Tif::Ioc
                        };
                        cl.tag = cl.tag.wrapping_add(1);
                        let flags = vyrn_wire::OrderFlags::from_byte(
                            OrderFlags::new(side, tif, false, Stp::None).0,
                        )
                        .unwrap_or_else(|_| unreachable!("valid flags"));
                        msgs.push(Msg::New {
                            flags,
                            tick: Tick(wl.random_range(95..=105u32)),
                            qty: Qty(wl.random_range(1..=20u32)),
                            client_tag: cl.tag,
                        });
                    }
                    let hdr = ReqHeader::new(
                        sid(cl.lane, cl.slot),
                        cl.next_pkt,
                        Epoch(0).low16(),
                        BOOK,
                        false,
                    );
                    let mut buf = [0u8; MAX_REQ_PAYLOAD];
                    let len = encode_request(&mut buf, hdr, &msgs, &kseq(cl.lane, cl.slot), None)
                        .unwrap_or_else(|| unreachable!("1..=3 messages fit"));
                    let bytes = buf[..len].to_vec();
                    cl.out.insert(cl.next_pkt, bytes.clone());
                    cl.next_pkt = cl.next_pkt.saturating_add(1);
                    cl.to_send = cl.to_send.saturating_sub(1);
                    transmit(&mut q, &mut net, t, c, &bytes, &mut tx_n);
                }
                if clients[c].to_send > 0 {
                    let g = cfg.gap_ns;
                    let d = wl.random_range(g / 2..=g.saturating_mul(3) / 2);
                    q.push(t.saturating_add(d.max(1)), Ev::Send(c));
                }
                None
            }
            Ev::Resend(c) => {
                let pkts: Vec<Vec<u8>> = clients[c].out.values().cloned().collect();
                for b in &pkts {
                    transmit(&mut q, &mut net, t, c, b, &mut tx_n);
                }
                if !clients[c].done() {
                    q.push(t.saturating_add(RESEND_NS), Ev::Resend(c));
                }
                None
            }
            Ev::Arrive { c, bytes } => {
                let l = clients[c].lane;
                let start = stalled(faults, u8::try_from(l).ok(), t.max(lane_free[l]));
                lane_free[l] = start.saturating_add(LANE_COST);
                q.push(start, Ev::Process { c, rx_ts: t, bytes });
                None
            }
            Ev::Process { c, rx_ts, bytes } => {
                let (l, slot) = (clients[c].lane, clients[c].slot);
                // The header's pkt_seq (bytes 4..8, 01 §6.1); the client knows what it sent.
                let pkt_seq = clients[c]
                    .out
                    .iter()
                    .find(|(_, b)| **b == bytes)
                    .map_or(0, |(p, _)| *p);
                let hdr_seq = bytes
                    .get(4..8)
                    .and_then(|b| b.try_into().ok())
                    .map_or(pkt_seq, u32::from_le_bytes);
                store
                    .0
                    .entry((u8::try_from(l).unwrap_or(0), sid(l, slot).0, hdr_seq, rx_ts))
                    .or_insert_with(|| bytes.clone());
                let n_msgs = bytes.len().saturating_sub(32) / 16;
                let rx = RxIn {
                    bytes: &bytes,
                    rx_ts: Nanos(rx_ts),
                    pkt_hash: vyrn_crypto::pkt_hash(
                        bytes.get(..16 + 16 * n_msgs).unwrap_or(&bytes),
                    ),
                };
                match e.ingest(l, rx, &FixedClock(t), &mut out) {
                    Ok(r) => {
                        if r == Rx::Shed {
                            stats.shed = stats.shed.saturating_add(1);
                            busy = Some((sid(l, slot).0, hdr_seq));
                        }
                        let lat = net.random_range(500..=3_000u64);
                        q.push(
                            t.saturating_add(lat),
                            Ev::Verdict {
                                c,
                                pkt_seq: hdr_seq,
                                rx: r,
                            },
                        );
                        if !bbo_pending {
                            bbo_pending = true;
                            q.push(stalled(faults, None, t.max(bbo_free)), Ev::Bbo);
                        }
                        None
                    }
                    Err(f) => Some(("ENGINE-FAULT", format!("lane {l} fault {f:?}"))),
                }
            }
            Ev::Verdict { c, pkt_seq, rx } => {
                if rx == Rx::Accepted && clients[c].out.remove(&pkt_seq).is_some() {
                    stats.accepted = stats.accepted.saturating_add(1);
                }
                None
            }
            Ev::Bbo => {
                bbo_pending = false;
                bbo_free = t.saturating_add(BBO_COST);
                match lane_stall_end(faults, t) {
                    // SF-11: a stalled lane core runs no boundary, so no lane polls. The BBO
                    // core steps alone; fills wait in the rings (back-pressure, SF-14), and a
                    // full run follows when the stall ends.
                    Some(end) => {
                        let mut r = Ok(());
                        for _ in 0..QUIESCE_ROUNDS {
                            match e.step(&FixedClock(t), &mut out) {
                                Ok(Some(_)) => {}
                                Ok(None) => break,
                                Err(f) => {
                                    r = Err(f);
                                    break;
                                }
                            }
                        }
                        bbo_pending = true;
                        q.push(stalled(faults, None, end.max(bbo_free)), Ev::Bbo);
                        r.err()
                            .map(|f| ("ENGINE-FAULT", format!("BBO fault {f:?}")))
                    }
                    None => match e.run(&FixedClock(t), &mut out, QUIESCE_ROUNDS) {
                        Ok(true) => None,
                        Ok(false) => Some((
                            "BBO-QUIESCE",
                            format!("no quiescence in {QUIESCE_ROUNDS} step and poll rounds"),
                        )),
                        Err(f) => Some(("ENGINE-FAULT", format!("BBO fault {f:?}"))),
                    },
                }
            }
            Ev::Poll if lane_stall_end(faults, t).is_some() => {
                // SF-11: skip every lane's idle poll while one is stalled (follow-up: per lane).
                q.push(t.saturating_add(POLL_NS), Ev::Poll);
                None
            }
            Ev::Poll => {
                let r = e.poll_lanes(&mut out);
                if !clients.iter().all(Client::done) {
                    q.push(t.saturating_add(POLL_NS), Ev::Poll);
                }
                match r {
                    Ok(n) => {
                        if n > 0 && !bbo_pending {
                            bbo_pending = true;
                            q.push(stalled(faults, None, t.max(bbo_free)), Ev::Bbo);
                        }
                        None
                    }
                    Err(f) => Some(("ENGINE-FAULT", format!("lane poll fault {f:?}"))),
                }
            }
        };
        let idx = stats.events.saturating_sub(1);
        if let Some((check, detail)) = fault {
            violation = Some(Violation {
                check,
                index: idx,
                detail,
            });
            break;
        }

        // Checks on everything the event produced (crate docs, "Checks").
        let mut obs = Vec::new();
        for r in &out.recs[seen_rec..] {
            match r {
                OwnedRec::Packet(p) => obs.push(Obs::Pkt {
                    session: p.session.0,
                    pkt_seq: p.pkt_seq,
                    shed: p.flags & PacketFlags::SHED != 0,
                }),
                OwnedRec::Step(s, d) => {
                    stats.steps = stats.steps.saturating_add(1);
                    stats.fills = stats.fills.saturating_add(u64::from(s.n_fills));
                    obs.push(Obs::Step {
                        step: s.step.0,
                        n_fills: s.n_fills,
                        cut: d
                            .get(..usize::from(s.n_delta))
                            .unwrap_or(&[])
                            .iter()
                            .map(|x| (x.lane.0, x.seq.0))
                            .collect(),
                    });
                }
            }
        }
        seen_rec = out.recs.len();
        for (_, p) in &out.resp[seen_resp..] {
            obs.push(Obs::Resp {
                session: p.session.0,
                resp_seq: p.resp_seq,
            });
        }
        seen_resp = out.resp.len();
        if let Some((session, pkt_seq)) = busy {
            obs.push(Obs::Busy { session, pkt_seq });
        }
        if let Some(s) = e.snapshot() {
            obs.push(Obs::Snap {
                bid: s.bid.0,
                ask: s.ask.0,
            });
        }
        if let Some((check, detail)) = obs.iter().find_map(|o| checker.observe(o).err()) {
            violation = Some(Violation {
                check,
                index: idx,
                detail,
            });
            break;
        }
    }
    stats.end_ns = now;
    stats.records = u64::try_from(out.recs.len()).unwrap_or(u64::MAX);

    // Liveness: every client finished once the faults healed.
    if violation.is_none()
        && let Some((i, c)) = clients.iter().enumerate().find(|(_, c)| !c.done())
    {
        violation = Some(Violation {
            check: "LIVENESS",
            index: stats.events,
            detail: format!(
                "client {i} (lane {} slot {}) has {} unsent and {} unaccepted packets at {} ns",
                c.lane,
                c.slot,
                c.to_send,
                c.out.len(),
                now
            ),
        });
    }

    // INV-DET: every replica replays the order stream to the same outputs.
    if violation.is_none() {
        let live = logical(&out.recs);
        let live_resp = in_stream(&out.resp);
        for r in 0..cfg.replicas {
            let mut recs = out.recs.clone();
            for f in faults {
                if let Fault::Diverge { replica, rec } = *f
                    && usize::from(replica) == r
                    && let Some(x) = recs.get_mut(usize::try_from(rec).unwrap_or(usize::MAX))
                {
                    match x {
                        OwnedRec::Packet(p) => {
                            p.fills_applied.0 = p.fills_applied.0.wrapping_add(1)
                        }
                        OwnedRec::Step(s, _) => s.n_fills = s.n_fills.wrapping_add(1),
                    }
                }
            }
            let (bbo, mut rsh) = new_box(cfg.lanes);
            let mut re = engine(bbo, &mut rsh, &cfg);
            let mut rout = Out::default();
            let res = re.replay(&recs, &store, &mut rout);
            let detail = match res {
                Err(d) => Some(format!(
                    "replica {r} diverged at record {}: {:?}",
                    d.index, d.why
                )),
                Ok(()) if logical(&rout.recs) != live => {
                    Some(format!("replica {r} order stream differs"))
                }
                Ok(()) if in_stream(&rout.resp) != live_resp => Some(first_diff(
                    r,
                    "response",
                    &live_resp,
                    &in_stream(&rout.resp),
                )),
                Ok(()) if rout.tx != out.tx => Some(first_diff(r, "fill TX", &out.tx, &rout.tx)),
                Ok(()) => None,
            };
            if let Some(detail) = detail {
                violation = Some(Violation {
                    check: "INV-DET",
                    index: stats.events,
                    detail,
                });
                break;
            }
        }
    }

    for r in &out.recs {
        trace.update(format!("{r:?}\n").as_bytes());
    }
    for r in &out.resp {
        trace.update(format!("{r:?}\n").as_bytes());
    }
    for r in &out.tx {
        trace.update(format!("{r:?}\n").as_bytes());
    }
    if let Some(v) = &violation {
        trace.update(format!("{v:?}\n").as_bytes());
    }
    Report {
        seed,
        config: cfg,
        schedule: schedule.clone(),
        trace: *trace.finalize().as_bytes(),
        stats,
        tail: if violation.is_some() {
            tail.into_iter().collect()
        } else {
            Vec::new()
        },
        violation,
    }
}

/// Delta debugging over the schedule (11 §6.4 `shrink`): drops faults one at a time while the
/// run still breaks the same check. Returns the smallest failing schedule found, or `None` if
/// `schedule` does not fail.
pub fn shrink(seed: u64, schedule: &Schedule) -> Option<Report> {
    let mut best = run(seed, schedule);
    let check = best.violation.as_ref()?.check;
    let mut i = 0;
    while i < best.schedule.0.len() {
        let mut s = best.schedule.clone();
        s.0.remove(i);
        let r = run(seed, &s);
        if r.violation.as_ref().is_some_and(|v| v.check == check) {
            best = r;
        } else {
            i = i.saturating_add(1);
        }
    }
    Some(best)
}
