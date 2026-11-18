//! A 3-lane box over `Hw` lines, a scripted driver, a journal sink and a payload store. A
//! script is data ([`Act`]), so the golden file can carry it for another implementation.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::type_complexity
)]

use std::fmt::Write as _;

use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{Bbo, OrderFlags, Phase, Record, Side, Stp, Tif, TxEntry};
use vyrn_cut::Hw;
use vyrn_engine::{
    Engine, NoResponses, OwnedRec, Payloads, Rec, Responses, Shared, Sink, WireStep,
};
use vyrn_lane::{ArenaConfig, Config, Lane, PathTable, RespPkt, Rx, RxIn, SessionSpec};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, Handle, LaneId, MAX_REQ_PAYLOAD, Nanos, PacketRecord, PktHash, Qty,
    SessionId, Tick,
};
use vyrn_wire::{Msg, ReqHeader, encode_request};

pub const N: usize = 3;
pub const NA: usize = 16;
pub const BOOK: BookId = BookId(7);
pub const TICK_MAX: u32 = 512;
/// Order slots and FIFO segments per lane, above `ENG_FWD_RING` + the BBO's lane buffer (as in vyrn-sim's 4096) so
/// a lane can have more forwarded ops in flight than the forward ring holds.
pub const SLOT_CAP: u32 = 2048;
/// `FwdEntry.deadline − rx_ts` used by every lane here.
pub const FWD_DL: u32 = vyrn_lane::lane::FWD_DEADLINE_NS;

pub fn bbo_cfg() -> vyrn_bbo::Config {
    vyrn_bbo::Config {
        n_lanes: N as u8,
        epoch: Epoch(0),
        slot_cap: SLOT_CAP as usize,
        seg_cap: SLOT_CAP,
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

pub fn arena_cfg() -> ArenaConfig {
    ArenaConfig {
        slot_cap: SLOT_CAP,
        seg_cap: SLOT_CAP,
        tick_min: Tick(1),
        tick_max: Tick(TICK_MAX),
        accounts: NA as u32,
        journal: 1024,
    }
}

pub fn lane_cfgs() -> Vec<Config> {
    (0..N)
        .map(|l| Config {
            lane: LaneId(l as u8),
            n_lanes: N as u8,
            epoch: Epoch(0),
            book: BOOK,
            spec: BookSpec::new(1, Tick(1), Tick(TICK_MAX), 10_000).unwrap(),
            path: PathTable::spec(),
            fwd_deadline_ns: FWD_DL,
            phase: Phase::Continuous,
            out_cap: 4096,
        })
        .collect()
}

/// Session `a` of lane `l` (`session_lane` = bits 12..20, generation 1).
pub fn sid(l: usize, a: u32) -> SessionId {
    SessionId((1 << 20) | ((l as u32) << 12) | a)
}

pub fn kseq(l: usize, a: u32) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0] = l as u8;
    k[1] = a as u8;
    k[15] = 0x5A;
    k
}

pub fn new_box() -> (Bbo, Box<Shared<Hw>>) {
    let bbo = Bbo::new(bbo_cfg());
    let sh = Shared::new(&Hw, N, arena_cfg(), &bbo.initial_snapshot()).unwrap();
    (bbo, sh)
}

/// Every lane with sessions 1..NA, each funded.
pub fn engine(bbo: Bbo, sh: &mut Shared<Hw>) -> Engine<'_, Hw, NA> {
    Engine::new(&Hw, sh, bbo, &lane_cfgs(), |cfg, aw, ports| {
        let l = usize::from(cfg.lane.0);
        let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
        acct.max_open_orders = 1000;
        let mut lane = Lane::<Hw, NA>::new(cfg, aw, ports, acct);
        for a in 1..NA as u32 {
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
        lane
    })
    .unwrap()
}

pub fn flags(side: Side, tif: Tif) -> vyrn_wire::OrderFlags {
    vyrn_wire::OrderFlags::from_byte(OrderFlags::new(side, tif, false, Stp::None).0).unwrap()
}

pub fn new(side: Side, tif: Tif, tick: u32, qty: u32, tag: u32) -> Msg {
    Msg::New {
        flags: flags(side, tif),
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

/// One driver action.
#[derive(Clone, Debug)]
pub enum Act {
    /// Session `a` of lane `l` sends `msgs` received at `rx_ts`; the lane's clock reads `now`.
    Pkt {
        l: usize,
        a: u32,
        rx_ts: u64,
        now: u64,
        msgs: Vec<Msg>,
    },
    /// One BBO step with its clock at `now` (`None`: on time).
    Step(Option<u64>),
    /// Every lane's idle poll.
    Poll,
    /// Steps and polls until quiet.
    Run,
}

/// Everything the engine emitted.
#[derive(Default, Debug)]
pub struct Journal {
    pub recs: Vec<OwnedRec>,
    pub resp: Vec<(LaneId, RespPkt)>,
    pub tx: Vec<(TxEntry, Vec<Record>)>,
}

impl Sink for Journal {
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

/// Packet bytes keyed by `(lane, session, pkt_seq, rx_ts)`.
#[derive(Default, Debug)]
pub struct Store(pub Vec<(Key, Vec<u8>)>);

/// `(lane, session, pkt_seq, rx_ts)`.
pub type Key = (LaneId, SessionId, u32, u64);

impl Payloads for Store {
    fn get(&self, r: &PacketRecord) -> Option<&[u8]> {
        let k = (r.lane, r.session, r.pkt_seq, r.rx_ts.0);
        self.0
            .iter()
            .find(|(x, _)| *x == k)
            .map(|(_, b)| b.as_slice())
    }
}

/// A deterministic stand-in for the RX path's BLAKE3 `PktHash` (01 §2).
pub fn fake_hash(b: &[u8]) -> PktHash {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h = (h ^ u64::from(*x)).wrapping_mul(0x100_0000_01b3);
    }
    PktHash(h)
}

/// Runs `script` live. Returns the journal, the payload store, the `Rx` of every packet, and the
/// input lines of the golden format.
pub fn live(script: &[Act]) -> (Journal, Store, Vec<Rx>, String) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    let mut store = Store::default();
    let mut rxs = Vec::new();
    let mut inputs = String::new();
    let mut pkt = [[0u32; NA]; N];
    for act in script {
        match act {
            Act::Pkt {
                l,
                a,
                rx_ts,
                now,
                msgs,
            } => {
                let ai = *a as usize;
                pkt[*l][ai] += 1;
                let hdr = ReqHeader::new(sid(*l, *a), pkt[*l][ai], Epoch(0).low16(), BOOK, false);
                let mut buf = [0u8; MAX_REQ_PAYLOAD];
                let n = encode_request(&mut buf, hdr, msgs, &kseq(*l, *a), None).unwrap();
                let bytes = buf[..n].to_vec();
                let rx = RxIn {
                    bytes: &bytes,
                    rx_ts: Nanos(*rx_ts),
                    pkt_hash: fake_hash(&bytes),
                };
                let r = e.ingest(*l, rx, &FixedClock(*now), &mut j).unwrap();
                if r == Rx::Shed {
                    pkt[*l][ai] -= 1; // the client resends this pkt_seq (05 §6.8)
                }
                writeln!(inputs, "I pkt {l} {rx_ts} {now} {}", hex(&bytes)).unwrap();
                store.0.push((
                    (
                        LaneId(*l as u8),
                        sid(*l, *a),
                        pkt[*l][ai] + u32::from(r == Rx::Shed),
                        *rx_ts,
                    ),
                    bytes,
                ));
                rxs.push(r);
            }
            Act::Step(now) => {
                match now {
                    Some(t) => e.step(&FixedClock(*t), &mut j).unwrap(),
                    None => e.step(&NeverLate, &mut j).unwrap(),
                };
                writeln!(
                    inputs,
                    "I step {}",
                    now.map_or("-".into(), |t| t.to_string())
                )
                .unwrap();
            }
            Act::Poll => {
                e.poll_lanes(&mut j).unwrap();
                writeln!(inputs, "I poll").unwrap();
            }
            Act::Run => {
                assert!(e.run(&NeverLate, &mut j, 64).unwrap(), "no quiescence");
                writeln!(inputs, "I run").unwrap();
            }
        }
    }
    (j, store, rxs, inputs)
}

/// Replays `recs` on a fresh box.
pub fn replay(recs: &[OwnedRec], store: &Store) -> (Result<(), vyrn_engine::Diverged>, Journal) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    let r = e.replay(recs, store, &mut NoResponses, &mut j);
    (r, j)
}

/// Replays `recs` on a fresh box, checking responses against `log`.
pub fn replay_checked(
    recs: &[OwnedRec],
    store: &Store,
    log: &Journal,
) -> (Result<(), vyrn_engine::Diverged>, Journal) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    let mut rl = RespLog::of(log);
    let r = e.replay(recs, store, &mut rl, &mut j);
    (r, j)
}

/// A response log built from a live journal: lane packets per lane in order, TX packets in
/// order.
pub struct RespLog {
    pub lane: Vec<std::collections::VecDeque<RespPkt>>,
    pub tx: std::collections::VecDeque<(TxEntry, Vec<Record>)>,
}

impl RespLog {
    pub fn of(j: &Journal) -> Self {
        let mut lane = vec![std::collections::VecDeque::new(); N];
        for (l, p) in &j.resp {
            lane[usize::from(l.0)].push_back(*p);
        }
        Self {
            lane,
            tx: j.tx.iter().cloned().collect(),
        }
    }
}

impl Responses for RespLog {
    fn lane(&mut self, lane: LaneId, p: &RespPkt) -> bool {
        self.lane[usize::from(lane.0)].pop_front().as_ref() == Some(p)
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) -> bool {
        self.tx
            .pop_front()
            .is_some_and(|(a, b)| a == *h && b == recs)
    }
    fn finished(&self) -> bool {
        self.tx.is_empty() && self.lane.iter().all(|q| q.is_empty())
    }
}

/// The 07 view of a journal (07 §7.1): packet records in journal order, the route records
/// (07 §3.6), and each step reduced to what 07's `StepRecord` carries (kind, source, `CROSS`
/// bit, full cut, Rescan band payload).
pub fn to_wire(recs: &[OwnedRec]) -> (Vec<PacketRecord>, Vec<vyrn_types::RouteRecord>, Vec<Wire>) {
    let mut lanes = Vec::new();
    let mut routes = Vec::new();
    let mut steps = Vec::new();
    let mut cut = vec![vyrn_types::LaneSeq(0); N];
    for r in recs {
        match r {
            OwnedRec::Packet(p) => lanes.push(*p),
            OwnedRec::Route(x) => routes.push(*x),
            OwnedRec::Step(e, d) => {
                for x in &d[..usize::from(e.n_delta)] {
                    cut[usize::from(x.lane.0)] = x.seq;
                }
                let kind = vyrn_types::StepKind::from_code(e.kind).unwrap();
                let mut payload = Vec::new();
                if kind == vyrn_types::StepKind::Rescan {
                    payload.extend_from_slice(&e.band_lo.0.to_le_bytes());
                    payload.extend_from_slice(&e.band_hi.0.to_le_bytes());
                }
                let src = (e.src_lane_seq.0 != 0).then_some((e.src_lane, e.src_lane_seq));
                let cross = e.flags & vyrn_bbo::STEP_CROSS != 0;
                steps.push((e.step, kind, src, cross, cut.clone(), payload));
            }
        }
    }
    (lanes, routes, steps)
}

/// One step as `to_wire` gives it: step, kind, source, `CROSS`, cut, payload.
pub type Wire = (
    vyrn_types::StepId,
    vyrn_types::StepKind,
    Option<(LaneId, vyrn_types::LaneSeq)>,
    bool,
    Vec<vyrn_types::LaneSeq>,
    Vec<u8>,
);

/// One block of 07 inputs: packet records, route records, steps.
pub type Block<'a> = (
    &'a [PacketRecord],
    &'a [vyrn_types::RouteRecord],
    &'a [Wire],
);

/// Replays 07-only inputs on a fresh box (`Engine::replay_wire`).
pub fn replay_wire(
    lanes: &[PacketRecord],
    routes: &[vyrn_types::RouteRecord],
    steps: &[Wire],
    store: &Store,
    log: Option<&Journal>,
) -> (Result<(), vyrn_engine::WireDiverged>, Journal) {
    let (r, j, _) = replay_blocks(&[(lanes, routes, steps)], store, log);
    (r, j)
}

/// Replays blocks of 07-only inputs, one `replay_wire` call each, on one fresh box. Returns the
/// first error (or `Ok`), the outputs, and how many records the last call carried.
pub fn replay_blocks(
    blocks: &[Block<'_>],
    store: &Store,
    log: Option<&Journal>,
) -> (Result<(), vyrn_engine::WireDiverged>, Journal, usize) {
    let (bbo, mut sh) = new_box();
    let mut e = engine(bbo, &mut sh);
    let mut j = Journal::default();
    let mut rl = log.map(RespLog::of);
    for (lanes, routes, steps) in blocks {
        let ws: Vec<WireStep<'_>> = steps
            .iter()
            .map(|(step, kind, src, cross, cut, payload)| WireStep {
                step: *step,
                kind: *kind,
                src: *src,
                cross: *cross,
                cut,
                payload,
            })
            .collect();
        let r = match &mut rl {
            Some(l) => e.replay_wire(lanes, routes, &ws, store, l, &mut j),
            None => e.replay_wire(lanes, routes, &ws, store, &mut NoResponses, &mut j),
        };
        if r.is_err() {
            return (r, j, e.carried().len());
        }
    }
    let n = e.carried().len();
    if rl.is_some_and(|l| !l.finished()) {
        let end = vyrn_engine::WireDiverged {
            at: vyrn_engine::WireAt::End,
            why: vyrn_engine::Why::Response,
        };
        return (Err(end), j, n);
    }
    (Ok(()), j, n)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The golden text form of one record.
pub fn rec_line(r: &OwnedRec) -> String {
    match r {
        OwnedRec::Packet(p) => format!(
            "P lane={} count={} flags={} session={} pkt_seq={} rx_ts={} pkt_hash={:016x} first={} fills_applied={}",
            p.lane.0,
            p.count,
            p.flags,
            p.session.0,
            p.pkt_seq,
            p.rx_ts.0,
            p.pkt_hash.0,
            p.first_lane_seq.0,
            p.fills_applied.0
        ),
        OwnedRec::Route(x) => format!(
            "R lane={} lane_seq={} cross={}",
            x.lane.0, x.lane_seq.0, x.cross as u8
        ),
        OwnedRec::Step(e, d) => {
            let ds: Vec<String> = d[..usize::from(e.n_delta)]
                .iter()
                .map(|d| format!("{}:{}", d.lane.0, d.seq.0))
                .collect();
            format!(
                "S step={} kind={} src={}:{} n_tx={} n_fills={} pub={}/{} band={}..{} fill_lanes={:x} flags={} cut=[{}]",
                e.step.0,
                e.kind,
                e.src_lane.0,
                e.src_lane_seq.0,
                e.n_tx,
                e.n_fills,
                e.pub_a,
                e.pub_b,
                e.band_lo.0,
                e.band_hi.0,
                e.fill_lanes,
                e.flags,
                ds.join(",")
            )
        }
    }
}
