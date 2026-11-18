//! One lane (05 §6): packet checks (04 §3.1 V1–V10), deadline admission (§6.8), the two passes
//! (§6.3, §6.4, 01 §14.2), classification (§6.5) and forwarding with the in-packet dependency
//! list (§6.6). The boundary (§6.2, §7.4–§7.6) is in `settle.rs`.

use vyrn_bbo::{
    DEP_CANCEL, DEP_JOIN, FWD_CROSS, FWD_INDEX, FwdDep, FwdEntry, JEnt, JKind, NO_ASK, OrderFlags,
    OrderSlot, Phase, Record, Side, SlotKind, Stp, Tif, encode_fwd,
};
use vyrn_cut::{
    Consumer, Counter, CounterLine, ENG_FILL_RING, ENG_FWD_RING, LaneCut, LaneCutEntry, Line32,
    Line64, OccEvent, Producer, Snapshot, SnapshotLine, Visibility,
};
use vyrn_risk::{
    Accounts, AcctRisk, AcctSlot, BookAcc, BookBal, BookSpec, CancelKind, LaneBuckets, NewOrder,
    OrderRisk, Reject as RiskReject, Risk, Route,
};
use vyrn_types::{
    BookId, Epoch, Handle, LaneId, LaneSeq, MSG_BYTES, Nanos, PacketFlags, PacketRecord, PktHash,
    Qty, RejectReason, RouteRecord, SessionId, StepId, Tick,
};
use vyrn_wire::{Msg, Request, session_lane};

use crate::admit::{self, Class, Clock, PathTable, Point};
use crate::arena::ArenaWriter;
use crate::fifo::{Fifo, Pos};
use crate::layout::join;
use crate::layout::{jent_to_words, slot_to_words};
use crate::out::{Gate, LogRec, Outbox, RespPkt};
use crate::session::{SessState, SessionSpec, Sessions};

/// `FwdEntry.deadline − rx_ts` (05 §6.8): `970 − 355` ns.
pub const FWD_DEADLINE_NS: u32 = 615;
/// Messages per packet (01 §6.1).
const MAX_OPS: usize = 10;
/// Generation of every root slot while slots are not reused (05 §4.2; reuse is a follow-up).
pub const ROOT_GEN: u8 = 1;
/// `TOO_LATE` details (04 §6.3).
pub const PROTO_D_FILLED: u32 = 1;
pub const PROTO_D_CANCELED: u32 = 2;
pub const PROTO_D_OUT: u32 = 3;
/// `SESSION_CLOSED` detail of a draining session (04 M4).
pub const PROTO_D_DRAINING: u32 = 1;

/// Book and lane parameters, fixed at epoch start (05 §13).
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub lane: LaneId,
    pub n_lanes: u8,
    pub epoch: Epoch,
    pub book: BookId,
    pub spec: BookSpec,
    pub path: PathTable,
    pub fwd_deadline_ns: u32,
    /// Phase at epoch start (lane order view, 05 §2.5).
    pub phase: Phase,
    /// Response packets and log records buffered per call.
    pub out_cap: usize,
}

/// The lane's ends of the rings and lines it touches (05 §4.1).
pub struct Ports<'a, V: Visibility> {
    pub fwd: Producer<'a, Line64, ENG_FWD_RING, 1, V>,
    pub fill: Consumer<'a, Line32, ENG_FILL_RING, 1, V>,
    pub counter: &'a CounterLine<V>,
    pub snapshot: &'a SnapshotLine<V>,
    pub lane_cut: &'a LaneCut<V>,
}

/// A received packet: its bytes, NIC `rx_ts` and `PktHash` (01 §2, BLAKE3 over bytes
/// `0 .. 16 + 16n`; computed by the RX path until `vyrn-wire` exposes it, PR follow-up).
#[derive(Clone, Copy, Debug)]
pub struct RxIn<'b> {
    pub bytes: &'b [u8],
    pub rx_ts: Nanos,
    pub pkt_hash: PktHash,
}

/// What happened to a packet (04 §3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rx {
    /// Accepted: logged, `pkt_seq` advanced, every message answered in stream.
    Accepted,
    /// Late (05 §6.8): `BUSY` for every message, `SHED` record, nothing applied.
    Shed,
    /// Dropped without a response (V1, V2, V5, a duplicate).
    Dropped,
    /// Answered out of stream (V4 `EPOCH_MISMATCH`, V7 `SESSION_CLOSED`, V8 `BAD_SEQ`).
    OutOfStream(RejectReason),
    /// V6 failed: the session is closed with `BAD_MAC`.
    Closed,
}

/// A boundary inside a packet chosen by the caller instead of the `LaneCut` poll: replay's `MID`
/// Advance records (05 §6.2, §10), and tests that pin boundary positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mid {
    /// 1 or 2.
    pub pass: u8,
    /// The op before whose step it runs.
    pub next: LaneSeq,
    /// `(f, C_f[l])`.
    pub at: LaneCutEntry,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum SKind {
    #[default]
    Free,
    Original,
    KeepPrio,
    NewPrio,
}

/// Lane-private per-slot state (05 §4.5 `SlotAux` plus the version fields the lane needs).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SlotP {
    pub kind: SKind,
    pub root: u32,
    /// Head slot of this version's priority leg (itself for `Original` and `NewPrio`).
    pub leg: u32,
    pub side: Option<Side>,
    pub flags: OrderFlags,
    pub tick: Tick,
    pub total: u32,
    pub ins_seq: LaneSeq,
    /// Key ts (`prio_ts`) of a leg head, op ts of a `KeepPrio`.
    pub ts: Nanos,
    pub tomb: bool,
    /// Leg heads: the queue position (assigned in pass 1).
    pub pos: Pos,
    pub has_pos: bool,
    /// Leg heads: created by an explicit op (forwarded source or Join dependency).
    pub explicit: bool,
    /// Leg heads: the risk record (10 §4.3).
    pub risk: Option<OrderRisk>,
    /// Leg heads: ended by a BBO decision (`Out`, `Reject`, dependency cancel).
    pub dead: bool,
    /// Fills on this version, and taker fills (a `Rescan` batch join, 05 §8.6).
    pub filled: u32,
    pub taker_filled: u32,
    /// A batch taker's terminal `Out`/`Reject` (its record is the lane's, 05 §8.10 rule 4).
    pub taker_end: bool,
    /// `NewPrio` versions: the version this one replaces, and whether the replace is still at
    /// the BBO core (explicit, not yet in effect). Per version, so a chain `v0 → v1 → v2` of
    /// pending replaces keeps every link (contract rule R).
    pub pred: u32,
    pub pred_pending: bool,
    /// `NewPrio` versions: the reservation was trued up for the predecessor's fills.
    pub trued: bool,
    /// A `Rescan` batch taker whose latest status event is `RESTED_IN_FLIGHT` (rule B).
    pub in_flight: bool,
    /// Index, session and `pkt_seq` of the op that created it (for lane-emitted records).
    pub ix: u8,
    pub sess: u16,
    pub pkt: u32,
}

/// Lane-private per-root state (05 §4.5 `RootAux`).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RootP {
    pub live: bool,
    pub sess: u16,
    pub acct: AcctSlot,
    pub tag: u32,
    /// Current version as pass 1 knows it (includes pending ops).
    pub cur: u32,
    pub filled: u32,
    /// The lane knows the order ended (`TOO_LATE` from now on), and how (04 §6.3).
    pub ended: bool,
    pub end_detail: u32,
    /// A local op that cannot be shed ends it (cancel, reduce to zero).
    pub local_end: bool,
    /// Next root of the session (creation order).
    pub next: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OpK {
    #[default]
    Reject,
    Join,
    Replace,
    Cancel,
    Reduce,
    CancelAll,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Op {
    pub seq: LaneSeq,
    pub ix: u8,
    pub k: OpK,
    pub explicit: bool,
    pub applied: bool,
    pub root: u32,
    /// Join: the new version. Replace, Cancel, Reduce: the version it ends.
    pub v: u32,
    /// Replace, Reduce: the new version.
    pub w: u32,
    pub side: Option<Side>,
    pub tick: Tick,
    pub r: u32,
    pub tag: u32,
}

/// What settles at the boundary that covers the op (05 §7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendK {
    Ack,
    CancelAck,
    ReduceAck,
    ReplaceAck,
    CancelAllAck,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PendE {
    pub seq: LaneSeq,
    pub k: PendK,
    pub root: u32,
    pub v: u32,
    pub w: u32,
    pub r: u32,
    pub ix: u8,
    pub sess: u16,
    pub pkt: u32,
    pub tag: u32,
}

/// A forwarded entry whose step the lane has not seen yet (`fwd_pend`, contract rule F).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FwdOut {
    pub floor: LaneSeq,
    pub vslot: u32,
    pub n_dep: u8,
    pub dep_slots: [u32; 9],
}

/// One lane. `NA` is the number of lane-local accounts (a power of two, `vyrn_types::Dense`).
pub struct Lane<'a, V: Visibility, const NA: usize> {
    pub(crate) cfg: Config,
    pub(crate) a: ArenaWriter<'a>,
    pub(crate) io: Ports<'a, V>,
    pub(crate) fifo: Fifo,
    pub(crate) accts: Accounts<NA>,
    pub(crate) acct_sessions: Vec<u16>,
    pub(crate) lane_bk: LaneBuckets,
    pub(crate) bk: BookAcc,
    pub(crate) sess: Sessions,
    pub(crate) slots: Vec<SlotP>,
    pub(crate) roots: Vec<RootP>,
    pub(crate) next_slot: u32,
    pub(crate) seq: LaneSeq,
    pub(crate) applied: LaneSeq,
    pub(crate) last_prio_ts: Nanos,
    pub(crate) fills_applied: StepId,
    pub(crate) phase: Phase,
    pub(crate) band: (Tick, Tick),
    pub(crate) snap: Snapshot,
    pub(crate) pend: std::collections::VecDeque<PendE>,
    pub(crate) evbuf: std::collections::VecDeque<vyrn_bbo::FillEvent>,
    pub(crate) fwd: std::collections::VecDeque<FwdOut>,
    pub(crate) out: Outbox,
    pub(crate) n_ev: u32,
    pub(crate) ev: [OccEvent; 3],
    pub(crate) jpos: u64,
    pub(crate) fault: bool,
    // Per-packet state.
    pub(crate) ops: [Op; MAX_OPS],
    pub(crate) n_ops: usize,
    pub(crate) cur_sess: u16,
    pub(crate) cur_pkt: u32,
    pub(crate) cur_ts: Nanos,
    pub(crate) imm: Option<RespPkt>,
    pub(crate) mids: [Option<Mid>; 20],
    /// The packet's boundaries are the caller's `mids` (replay): no `LaneCut` polls inside it.
    pub(crate) scripted: bool,
    /// The route `route_of` gave the op in pass 1, until the packet loop logs a `RouteRecord`
    /// for it on a reject (G9) or the next op starts.
    classified: Option<Route>,
    /// Replay routes (05 §10): `Some` while a [`Lane::replay_packet`] runs; the listed ops are
    /// forwarded with their route, every other op is local.
    pub(crate) forced: Option<[Option<(LaneSeq, Route)>; MAX_OPS]>,
    /// Account index handed to the BBO core per lane-local account: lane-local by default, the
    /// pool-wide index on a pooled lane (05 §6.9).
    pub(crate) acct_ix: Vec<u32>,
    pub(crate) b3: Vec<(u16, u32, Record)>,
    /// Pending explicit cancels forwarded as dependencies: root, op seq, op ts (rule R).
    pub(crate) dep_cancels: Vec<(u32, LaneSeq, Nanos)>,
    /// Lane-emitted batch-taker records awaiting B3: vslot, session, `pkt_seq`, record.
    pub(crate) emitq: Vec<(u32, u16, u32, Record)>,
}

fn rej(reason: RejectReason, detail: u32) -> RiskReject {
    RiskReject { reason, detail }
}

/// `client_tag` of a raw message (bytes 12..16, 01 §5).
fn tag_of(raw: &[u8]) -> u32 {
    raw.get(12..16)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes)
}

pub(crate) fn uix(x: u32) -> usize {
    usize::try_from(x).unwrap_or(usize::MAX)
}

fn lo32(x: u64) -> u32 {
    u32::try_from(x & 0xFFFF_FFFF).unwrap_or(0)
}

pub(crate) fn risk_side(s: Side) -> vyrn_risk::Side {
    match s {
        Side::Buy => vyrn_risk::Side::Buy,
        Side::Sell => vyrn_risk::Side::Sell,
    }
}

fn risk_tif(t: Tif) -> vyrn_risk::Tif {
    match t {
        Tif::Day => vyrn_risk::Tif::Day,
        Tif::Ioc => vyrn_risk::Tif::Ioc,
        Tif::Fok => vyrn_risk::Tif::Fok,
        Tif::AuctionOnly => vyrn_risk::Tif::AuctionOnly,
    }
}

/// Wire flags (vyrn-wire) → the flags byte vyrn-bbo reads.
fn bbo_flags(f: vyrn_wire::OrderFlags) -> OrderFlags {
    OrderFlags(f.to_byte())
}

/// `tick` is on `j`'s opposite side within `j`'s range (05 §6.6): `≤ j.tick` for a buy `j`,
/// `≥` for a sell.
fn in_range(j_side: Side, j_tick: Tick, side: Side, tick: Tick) -> bool {
    side == j_side.opposite()
        && match j_side {
            Side::Buy => tick <= j_tick,
            Side::Sell => tick >= j_tick,
        }
}

/// Where a `New` or a new-priority `Replace` goes (05 §6.5): `None` = local, else its route.
pub(crate) fn classify(snap: &Snapshot, side: Side, tif: Tif, tick: Tick) -> Option<Route> {
    if snap.phase != Phase::Continuous.code() {
        return None;
    }
    if matches!(tif, Tif::Ioc | Tif::Fok) {
        return Some(Route::Cross);
    }
    let (bid, ask) = (snap.bid, snap.ask);
    match side {
        Side::Buy if tick >= ask => Some(Route::Cross),
        Side::Buy if tick > bid => Some(Route::Improve),
        Side::Sell if tick <= bid => Some(Route::Cross),
        Side::Sell if tick < ask => Some(Route::Improve),
        _ => None,
    }
}

impl<'a, V: Visibility, const NA: usize> Lane<'a, V, NA> {
    /// Allocates every buffer: call before `seal()` (`INV-NOALLOC`).
    pub fn new(cfg: Config, a: ArenaWriter<'a>, io: Ports<'a, V>, fill: AcctRisk) -> Self {
        let ac = a.view().config();
        let n = uix(ac.slot_cap);
        Self {
            fifo: Fifo::new(ac.tick_min, ac.tick_max, ac.seg_cap),
            cfg,
            a,
            io,
            accts: Accounts::new(fill),
            acct_sessions: vec![0; NA],
            lane_bk: LaneBuckets::dedicated(),
            bk: BookAcc::default(),
            sess: Sessions::new(),
            slots: vec![SlotP::default(); n],
            roots: vec![RootP::default(); n],
            next_slot: 1,
            seq: LaneSeq(0),
            applied: LaneSeq(0),
            last_prio_ts: Nanos(0),
            fills_applied: StepId(0),
            phase: cfg.phase,
            band: (ac.tick_min, ac.tick_max),
            snap: Snapshot {
                ask: NO_ASK,
                ..Snapshot::default()
            },
            pend: std::collections::VecDeque::with_capacity(n),
            evbuf: std::collections::VecDeque::with_capacity(ENG_FILL_RING),
            fwd: std::collections::VecDeque::with_capacity(ENG_FWD_RING),
            out: Outbox::new(cfg.out_cap),
            n_ev: 0,
            ev: [OccEvent::default(); 3],
            jpos: 0,
            fault: false,
            ops: [Op::default(); MAX_OPS],
            n_ops: 0,
            cur_sess: 0,
            cur_pkt: 0,
            cur_ts: Nanos(0),
            imm: None,
            mids: [None; 20],
            scripted: false,
            forced: None,
            classified: None,
            acct_ix: (0..u32::try_from(NA).unwrap_or(0)).collect(),
            b3: Vec::with_capacity(4096),
            dep_cancels: Vec::with_capacity(64),
            emitq: Vec::with_capacity(64),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Control path and observers

    /// Opens a session (04 §4.4). `false` if the slot is in use or names another lane.
    pub fn open_session(&mut self, s: &SessionSpec) -> bool {
        if session_lane(s.id) != self.cfg.lane || !self.sess.open(s) {
            return false;
        }
        if let Some(n) = self.acct_sessions.get_mut(uix(s.acct.0)) {
            *n = n.saturating_add(1);
        }
        true
    }
    /// The account and its balance in this lane's book (control path: credits, limits).
    pub fn account_mut(&mut self, a: AcctSlot) -> Option<(&mut AcctRisk, &mut BookBal)> {
        self.accts.get_mut(a).ok()
    }
    pub fn book_acc(&self) -> BookAcc {
        self.bk
    }
    /// `LaneSeq` of the last op.
    pub fn seq(&self) -> LaneSeq {
        self.seq
    }
    /// Every op ≤ this is applied or explicit (`CounterLine.seq`).
    pub fn applied(&self) -> LaneSeq {
        self.applied
    }
    pub fn fills_applied(&self) -> StepId {
        self.fills_applied
    }
    /// `CounterLine.fwd_pend` as last published (contract rule F).
    pub fn fwd_pend(&self) -> LaneSeq {
        self.fwd.iter().map(|f| f.floor).min().unwrap_or(LaneSeq(0))
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn band(&self) -> (Tick, Tick) {
        self.band
    }
    /// Unsettled local ops.
    pub fn pending(&self) -> usize {
        self.pend.len()
    }
    /// An engine fault (05 §14.3): the caller fail-stops.
    pub fn fault(&self) -> bool {
        self.fault || self.out.overflow
    }
    /// Takes the response packets produced so far, in production order.
    pub fn drain_responses(&mut self) -> std::vec::Drain<'_, RespPkt> {
        self.out.resp.drain(..)
    }
    /// Takes the order-stream records produced so far.
    pub fn drain_log(&mut self) -> std::vec::Drain<'_, LogRec> {
        self.out.log.drain(..)
    }

    // -----------------------------------------------------------------------------------------
    // Counter, journal, snapshot

    pub(crate) fn publish_counter(&self, vis: &V) {
        let c = Counter {
            seq: self.applied,
            snap_ver: lo32(self.snap.version),
            f_lo: lo32(self.fills_applied.0),
            fwd_pend: self.fwd_pend(),
            n_ev: self.n_ev,
            dir_sel: 0,
            state: 0,
            ev: self.ev,
        };
        self.io.counter.publish(vis, &c);
    }

    fn occ_set_event(&mut self, side: Side, tick: Tick) {
        self.n_ev = self.n_ev.wrapping_add(1);
        self.ev.rotate_left(1);
        if let Some(e) = self.ev.last_mut() {
            *e = OccEvent {
                tick,
                back: 0,
                bits: u16::from(side.code()),
            };
        }
    }

    fn journal(&mut self, j: JEnt) {
        self.a.journal(self.jpos, jent_to_words(&j));
        self.jpos = self.jpos.wrapping_add(1);
    }

    /// Refreshes the lane's snapshot (05 §6.5: every later op uses this version or newer).
    pub(crate) fn refresh_snapshot(&mut self, vis: &V) {
        if let Some(s) = self.io.snapshot.try_read(vis)
            && s.version >= self.snap.version
        {
            self.snap = s;
        }
    }

    // -----------------------------------------------------------------------------------------
    // Slots

    pub(crate) fn slot(&self, s: u32) -> Option<&SlotP> {
        self.slots.get(uix(s))
    }
    pub(crate) fn slot_mut(&mut self, s: u32) -> Option<&mut SlotP> {
        self.slots.get_mut(uix(s))
    }
    pub(crate) fn root(&self, r: u32) -> Option<&RootP> {
        self.roots.get(uix(r))
    }
    pub(crate) fn root_mut(&mut self, r: u32) -> Option<&mut RootP> {
        self.roots.get_mut(uix(r))
    }
    fn slots_free(&self, n: u32) -> bool {
        self.next_slot
            .checked_add(n)
            .is_some_and(|e| uix(e) <= self.slots.len())
    }
    fn take_slot(&mut self) -> u32 {
        let s = self.next_slot;
        self.next_slot = s.saturating_add(1);
        s
    }
    pub(crate) fn handle(&self, root: u32) -> Handle {
        Handle::new(root, ROOT_GEN).unwrap_or(Handle(0))
    }
    /// The arena line of version `s`, from the lane's own copy of its fields.
    fn write_slot_line(&self, s: u32, root: u32, acct: AcctSlot) {
        let Some(p) = self.slot(s) else { return };
        let (kind, ins_ts) = match p.kind {
            SKind::KeepPrio => (SlotKind::KeepPrio, p.ts.0),
            SKind::NewPrio => {
                let pred = self.slot(p.pred).map_or(0, |v| v.total);
                (SlotKind::NewPrio, u64::from(pred))
            }
            _ => (SlotKind::Original, 0),
        };
        let prio_ts = self.slot(p.leg).map_or(p.ts, |h| h.ts);
        let line = OrderSlot {
            prio_ts,
            ins_seq: p.ins_seq,
            ins_ts,
            tomb_seq: LaneSeq(0),
            tomb_ts: Nanos(0),
            next_ver: 0,
            tick: p.tick,
            total: p.total,
            acct_ix: self.acct_index(acct),
            root,
            flags: p.flags,
            gen_: ROOT_GEN,
            kind,
            tomb_lane: self.cfg.lane,
        };
        self.a.slot_words(s, slot_to_words(&line));
    }

    /// Writes a tombstone on version `v` if it has none (write-once, `INV-ENG-2`).
    pub(crate) fn tombstone(&mut self, v: u32, seq: LaneSeq, ts: Nanos) {
        let Some(p) = self.slots.get_mut(uix(v)) else {
            return;
        };
        if p.tomb || p.kind == SKind::Free {
            return;
        }
        p.tomb = true;
        self.a.tombstone(v, seq, ts);
    }

    /// Ends the position of `v`'s leg (cancel or end): `active` cleared, `pend` set.
    pub(crate) fn end_position(&mut self, v: u32) {
        let leg = self.slot(v).map_or(0, |p| p.leg);
        if let Some(h) = self.slot(leg).copied()
            && h.has_pos
        {
            self.fifo.end(&self.a, h.pos);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Packet processing (05 §6.3)

    /// One received packet, with boundaries chosen by `LaneCut` polls (live) or by `mids`
    /// (replay `MID` records, tests). Every output goes to the outbox.
    pub fn process_packet<C: Clock>(
        &mut self,
        vis: &V,
        p: RxIn<'_>,
        clock: &C,
        mids: &[Mid],
    ) -> Rx {
        self.mids = [None; 20];
        for (d, m) in self.mids.iter_mut().zip(mids) {
            *d = Some(*m);
        }
        self.scripted = !mids.is_empty();
        let r = self.packet(vis, p, clock);
        self.mids = [None; 20];
        self.scripted = false;
        r
    }

    /// Replay of one logged packet (05 §10, "snapshot routing in `classify`" row): op `(l, q)`
    /// is forwarded iff a `StepRecord` has `src = (l, q)`. `routes` lists this packet's
    /// forwarded ops, each with the route the live lane classified it with (`Cross` or
    /// `Improve`), because risk charges by that route (10 M8). The step's kind does not give it:
    /// a `Cross` that STP leaves without fills is logged as an `Improve` step. Every other op is
    /// local, whatever the lane's snapshot says. Boundaries come from `mids` only, as in
    /// [`Self::process_packet`] with a nonempty list. The live path never calls this.
    pub fn replay_packet<C: Clock>(
        &mut self,
        vis: &V,
        p: RxIn<'_>,
        clock: &C,
        mids: &[Mid],
        routes: &[(LaneSeq, Route)],
    ) -> Rx {
        let mut f = [None; MAX_OPS];
        for (d, r) in f.iter_mut().zip(routes) {
            *d = Some(*r);
        }
        self.forced = Some(f);
        self.mids = [None; 20];
        for (d, m) in self.mids.iter_mut().zip(mids) {
            *d = Some(*m);
        }
        self.scripted = true;
        let r = self.packet(vis, p, clock);
        self.mids = [None; 20];
        self.scripted = false;
        self.forced = None;
        r
    }

    /// The account index lane-local account `a` hands the BBO core (`FwdEntry.acct_ix`,
    /// `OrderSlot.acct_ix`, `AcctKill` and its journal entry). On a pooled lane it is the
    /// pool-wide index, which STP and kills compare across the pool (05 §6.9). Configuration,
    /// before the first packet. `false` if `a` or `ix` is outside the lane's tables.
    pub fn set_pool_index(&mut self, a: AcctSlot, ix: u32) -> bool {
        if ix >= self.a.view().config().accounts {
            return false;
        }
        match self.acct_ix.get_mut(uix(a.0)) {
            Some(x) => {
                *x = ix;
                true
            }
            None => false,
        }
    }

    pub(crate) fn acct_index(&self, a: AcctSlot) -> u32 {
        self.acct_ix.get(uix(a.0)).copied().unwrap_or(a.0)
    }

    /// The route of op `seq` (05 §6.5), or the replay's forced route (05 §10).
    fn route_of(&self, seq: LaneSeq, side: Side, tif: Tif, tick: Tick) -> Option<Route> {
        match &self.forced {
            None => classify(&self.snap, side, tif, tick),
            Some(f) => f.iter().flatten().find(|(q, _)| *q == seq).map(|(_, r)| *r),
        }
    }

    fn packet<C: Clock>(&mut self, vis: &V, p: RxIn<'_>, clock: &C) -> Rx {
        // V1.
        let Ok(req) = Request::parse(p.bytes) else {
            return Rx::Dropped;
        };
        let h = req.header();
        let n = h.count;
        let cls = if req
            .raw_msgs()
            .iter()
            .any(|m| matches!(m.first(), Some(&Msg::NEW) | Some(&Msg::REPLACE)))
        {
            Class::Order
        } else {
            Class::Local
        };
        // V2 (the other-lane path of 04 §3.2 is the engine's: dropped here).
        let sid = h.session();
        if session_lane(sid) != self.cfg.lane {
            return Rx::Dropped;
        }
        let Some(si) = self.sess.find(sid) else {
            return Rx::Dropped;
        };
        let pkt_seq = h.pkt_seq.get();
        // V3 (bound source address) needs the RX source tuple: PR follow-up.
        // V4.
        if h.epoch16.get() != self.cfg.epoch.low16() {
            let d = self.cfg.epoch.0;
            self.oos(si, pkt_seq, RejectReason::EpochMismatch, d);
            return Rx::OutOfStream(RejectReason::EpochMismatch);
        }
        let Some(s) = self.sess.get(si).copied() else {
            return Rx::Dropped;
        };
        // V5: PROTO_SEQ_BACK/AHEAD window (04 §14).
        if pkt_seq < s.expected.saturating_sub(PROTO_SEQ_BACK)
            || pkt_seq > s.expected.saturating_add(PROTO_SEQ_AHEAD)
        {
            return Rx::Dropped;
        }
        // Test D at dequeue (05 §6.8): no MAC, nothing applied.
        if admit::late(clock, p.rx_ts, n, cls, Point::Dequeue, &self.cfg.path) {
            self.answer_busy(vis, si, &req, p);
            return Rx::Shed;
        }
        // V6.
        if !req.verify_seq(&s.k_seq) {
            self.sess.set_state(sid, SessState::Closed);
            let mut r = RespPkt::new(sid, s.next_resp, pkt_seq, Gate::None);
            r.push(Record::Reject {
                index: vyrn_wire::INDEX_NONE,
                reason: RejectReason::BadMac,
                detail: 0,
                client_tag: 0,
            });
            if let Some(x) = self.sess.get_mut(si) {
                x.next_resp = x.next_resp.wrapping_add(1);
            }
            self.out.resp(r);
            return Rx::Closed;
        }
        // V7.
        if s.state == SessState::Closed {
            self.oos(si, pkt_seq, RejectReason::SessionClosed, 0);
            return Rx::OutOfStream(RejectReason::SessionClosed);
        }
        // V8.
        if pkt_seq < s.expected {
            return Rx::Dropped; // duplicate; the resend path (04 §5.2) is a follow-up
        }
        if pkt_seq > s.expected {
            self.oos(si, pkt_seq, RejectReason::BadSeq, s.expected);
            return Rx::OutOfStream(RejectReason::BadSeq);
        }
        // Commit-point test: the pre-pass is done, nothing is applied yet.
        if admit::late(clock, p.rx_ts, n, cls, Point::Commit, &self.cfg.path) {
            self.answer_busy(vis, si, &req, p);
            return Rx::Shed;
        }
        // Accept (04 §3.1): from here every outcome is in stream.
        if let Some(x) = self.sess.get_mut(si) {
            x.expected = x.expected.wrapping_add(1);
        }
        let prio_ts = p.rx_ts.max(self.last_prio_ts);
        self.last_prio_ts = prio_ts;
        self.refresh_snapshot(vis);
        self.out.log(LogRec::Packet(PacketRecord {
            lane: self.cfg.lane,
            count: n,
            flags: 0,
            session: sid,
            pkt_seq,
            rx_ts: p.rx_ts,
            pkt_hash: p.pkt_hash,
            first_lane_seq: LaneSeq(self.seq.0.saturating_add(1)),
            fills_applied: self.fills_applied,
        }));
        self.n_ops = 0;
        self.cur_sess = si;
        self.cur_pkt = pkt_seq;
        self.cur_ts = prio_ts;
        self.imm = None;
        // V9 (header) and V10 (packet buckets): every message gets the reject.
        let hdr = req.check_header().err().map(|e| rej(e.reason, e.detail));
        let hdr = hdr.or_else(|| (s.book != h.book()).then(|| rej(RejectReason::BadBook, 0)));
        let hdr = match hdr {
            Some(r) => Some(r),
            None => self.risk_packet(si, prio_ts).err(),
        };
        // Pass 1, index order.
        for (ix, raw) in req.raw_msgs().iter().enumerate() {
            let ix = u8::try_from(ix).unwrap_or(u8::MAX);
            self.maybe_mid(vis, 1, LaneSeq(self.seq.0.saturating_add(1)));
            let m = Msg::decode(raw);
            if matches!(m, Ok(Msg::Heartbeat) | Ok(Msg::ResendReq { .. })) && hdr.is_none() {
                continue; // session-only: no LaneSeq (05 §3.1); 04 §6.7 is a follow-up
            }
            self.seq = LaneSeq(self.seq.0.saturating_add(1));
            let tag = tag_of(raw);
            let res = match (hdr, m) {
                (Some(r), _) => Err(r),
                (None, Err(e)) => Err(rej(e.reason, e.detail)),
                (None, Ok(m)) => {
                    self.classified = None;
                    self.pass1(vis, ix, raw, m, prio_ts)
                }
            };
            // G9: a Cross or Improve the lane rejects itself has no step; log its route, so
            // replay charges and rejects it the same way (01 §6.6, 10 M8).
            if let (Err(_), Some(r)) = (&res, self.classified.take()) {
                self.out.log(LogRec::Route(RouteRecord {
                    lane: self.cfg.lane,
                    lane_seq: self.seq,
                    cross: r == Route::Cross,
                }));
            }
            match res {
                Ok(op) => {
                    if let Some(slot) = self.ops.get_mut(self.n_ops) {
                        *slot = op;
                        self.n_ops = self.n_ops.saturating_add(1);
                    }
                }
                Err(r) => {
                    let client_tag = match m {
                        Ok(Msg::Replace { handle, .. }) => self.stored_tag(handle),
                        _ => tag,
                    };
                    self.stage_immediate(sid, ix, r, client_tag);
                    let op = Op {
                        seq: self.seq,
                        ix,
                        k: OpK::Reject,
                        ..Op::default()
                    };
                    if let Some(slot) = self.ops.get_mut(self.n_ops) {
                        *slot = op;
                        self.n_ops = self.n_ops.saturating_add(1);
                    }
                }
            }
        }
        // Pass 2, index order.
        self.pass2_through(vis, self.seq);
        if let Some(r) = self.imm.take() {
            self.out.resp(r);
        }
        Rx::Accepted
    }

    fn stored_tag(&self, h: Handle) -> u32 {
        self.root(h.slot()).filter(|r| r.live).map_or(0, |r| r.tag)
    }

    fn oos(&mut self, si: u16, pkt_seq: u32, reason: RejectReason, detail: u32) {
        let Some(s) = self.sess.get(si) else { return };
        let mut r = RespPkt::new(s.id, 0, pkt_seq, Gate::None);
        r.push(Record::Reject {
            index: vyrn_wire::INDEX_NONE,
            reason,
            detail,
            client_tag: 0,
        });
        self.out.resp(r);
    }

    /// 05 §6.8: `Reject BUSY` per message in one packet, a `SHED` record, `pkt_seq` unchanged.
    fn answer_busy(&mut self, vis: &V, si: u16, req: &Request<'_>, p: RxIn<'_>) {
        let _ = vis;
        let Some(s) = self.sess.get_mut(si) else {
            return;
        };
        let rs = s.next_resp;
        s.next_resp = s.next_resp.wrapping_add(1);
        let first = LaneSeq(self.seq.0.saturating_add(1));
        let mut r = RespPkt::new(s.id, rs, req.header().pkt_seq.get(), Gate::Packet(first));
        for (ix, raw) in req.raw_msgs().iter().enumerate() {
            let tag = tag_of(raw);
            r.push(Record::Reject {
                index: u8::try_from(ix).unwrap_or(u8::MAX),
                reason: RejectReason::Busy,
                detail: 0,
                client_tag: tag,
            });
        }
        let sid = s.id;
        self.out.resp(r);
        self.out.log(LogRec::Packet(PacketRecord {
            lane: self.cfg.lane,
            count: req.header().count,
            flags: PacketFlags::SHED,
            session: sid,
            pkt_seq: req.header().pkt_seq.get(),
            rx_ts: p.rx_ts,
            pkt_hash: PktHash(0),
            first_lane_seq: first,
            fills_applied: self.fills_applied,
        }));
    }

    /// 05 §8.10 rule 3: every immediate reject of the packet goes into one packet whose
    /// `resp_seq` is taken at the first one, after earlier forwarded reservations.
    fn stage_immediate(&mut self, sid: SessionId, ix: u8, r: RiskReject, tag: u32) {
        if self.imm.is_none() {
            let Some(s) = self.sess.get_mut(self.cur_sess) else {
                return;
            };
            let rs = s.next_resp;
            s.next_resp = s.next_resp.wrapping_add(1);
            let first = self.packet_first_seq();
            self.imm = Some(RespPkt::new(sid, rs, self.cur_pkt, Gate::Packet(first)));
        }
        if let Some(p) = self.imm.as_mut() {
            p.push(Record::Reject {
                index: ix,
                reason: r.reason,
                detail: r.detail,
                client_tag: tag,
            });
        }
    }

    fn packet_first_seq(&self) -> LaneSeq {
        match self.out.log.iter().rev().find_map(|r| match r {
            LogRec::Packet(p) if p.count != 0 => Some(p.first_lane_seq),
            _ => None,
        }) {
            Some(s) => s,
            None => LaneSeq(self.seq.0),
        }
    }

    fn risk_packet(&mut self, si: u16, now: Nanos) -> Result<(), RiskReject> {
        let snap = self.risk_snap();
        let spec = self.cfg.spec;
        let Some(s) = self.sess.get_mut(si) else {
            return Err(rej(RejectReason::SessionClosed, 0));
        };
        let (acct, bal) = self.accts.get_mut(s.acct)?;
        Risk {
            acct,
            sess: &mut s.buckets,
            bal,
            lane: &mut self.lane_bk,
            book: &mut self.bk,
            spec: &spec,
            snap: &snap,
            now,
            slot_free: true,
        }
        .check_packet()
    }

    /// The risk view: phase and halt in lane order (Phase events), bid and ask from the live
    /// snapshot for the band of 10 §3.5 (spec follow-up S1: not in the order stream).
    pub(crate) fn risk_snap(&self) -> vyrn_risk::Snapshot {
        vyrn_risk::Snapshot {
            halted: self.phase == Phase::Halted,
            phase: if self.phase == Phase::Continuous {
                vyrn_risk::Phase::Continuous
            } else {
                vyrn_risk::Phase::Auction
            },
            bid: self.snap.bid,
            ask: if self.snap.ask == NO_ASK {
                Tick(0)
            } else {
                self.snap.ask
            },
            ref_tick: Tick(0),
        }
    }

    /// The boundary before pass `pass` of op `next` (05 §6.3), if one is due.
    fn maybe_mid(&mut self, vis: &V, pass: u8, next: LaneSeq) {
        if self.scripted {
            let hit = self
                .mids
                .iter_mut()
                .find(|m| m.is_some_and(|m| m.pass == pass && m.next == next))
                .and_then(Option::take);
            if let Some(m) = hit {
                self.boundary(vis, m.at, Some((pass, next)));
            }
        } else if let Some(lc) = self.boundary_due(vis) {
            self.boundary(vis, lc, Some((pass, next)));
        }
    }

    /// Pass 2 through `upto` (05 §6.3 `pass2_through`): independent ops are applied, explicit ops
    /// skipped; the counter is published after each.
    pub(crate) fn pass2_through(&mut self, vis: &V, upto: LaneSeq) {
        for i in 0..self.n_ops {
            let Some(op) = self.ops.get(i).copied() else {
                continue;
            };
            if op.applied || op.seq > upto {
                continue;
            }
            self.maybe_mid(vis, 2, op.seq);
            if !op.explicit {
                self.pass2_apply(&op);
            }
            if let Some(o) = self.ops.get_mut(i) {
                o.applied = true;
            }
            self.applied = op.seq;
            self.publish_counter(vis);
        }
    }

    // -----------------------------------------------------------------------------------------
    // Pass 1 (05 §6.4)

    fn resolve(&self, h: Handle) -> Result<u32, RiskReject> {
        let unknown = rej(RejectReason::UnknownHandle, 0);
        let r = h.slot();
        let rp = self.root(r).ok_or(unknown)?;
        let s = self.sess.get(self.cur_sess).ok_or(unknown)?;
        if r == 0 || !rp.live || h.generation() != ROOT_GEN || rp.sess != self.cur_sess {
            return Err(unknown);
        }
        let cur = self.slot(rp.cur).ok_or(unknown)?;
        if rp.ended || rp.local_end || cur.ins_seq < s.cancel_all {
            let d = if rp.ended {
                rp.end_detail
            } else {
                PROTO_D_CANCELED
            };
            return Err(rej(RejectReason::TooLate, d));
        }
        Ok(r)
    }

    fn pass1(
        &mut self,
        vis: &V,
        ix: u8,
        raw: &[u8; MSG_BYTES],
        m: Msg,
        ts: Nanos,
    ) -> Result<Op, RiskReject> {
        let seq = self.seq;
        let si = self.cur_sess;
        let s = *self
            .sess
            .get(si)
            .ok_or(rej(RejectReason::SessionClosed, 0))?;
        let book_op = !matches!(m, Msg::Heartbeat | Msg::ResendReq { .. });
        if book_op && self.phase == Phase::Frozen {
            return Err(rej(RejectReason::AuctionPhase, 0)); // 05 §2.5 P4
        }
        let base = Op {
            seq,
            ix,
            ..Op::default()
        };
        match m {
            Msg::New {
                flags,
                tick,
                qty,
                client_tag,
            } => {
                if s.state == SessState::Draining {
                    return Err(rej(RejectReason::SessionClosed, PROTO_D_DRAINING));
                }
                let f = bbo_flags(flags);
                let side = f.side();
                let route = self.route_of(seq, side, f.tif(), tick);
                self.classified = route;
                let fit = self.slots_free(1) && self.fifo.can_assign(side, tick, ts);
                let risk = self.check_new(si, f, tick, qty, route, ts, fit)?;
                let v = self.take_slot();
                let pos = self.fifo.assign(&self.a, side, tick, ts).ok_or(rej(
                    RejectReason::RiskOrderCount,
                    vyrn_risk::consts::RSK_D_LANE_FULL,
                ))?;
                if pos.new_level {
                    self.occ_set_event(side, tick);
                }
                let cur_pkt = self.cur_pkt;
                if let Some(p) = self.slot_mut(v) {
                    *p = SlotP {
                        kind: SKind::Original,
                        root: v,
                        leg: v,
                        side: Some(side),
                        flags: f,
                        tick,
                        total: qty.0,
                        ins_seq: seq,
                        ts,
                        pos: pos.pos,
                        has_pos: true,
                        explicit: route.is_some(),
                        risk: Some(risk),
                        ix,
                        sess: si,
                        pkt: cur_pkt,
                        ..SlotP::default()
                    };
                }
                self.new_root(v, si, s.acct, client_tag);
                self.write_slot_line(v, v, s.acct);
                self.a.owner(v, join(s.id.0, client_tag));
                let mut op = Op {
                    k: OpK::Join,
                    root: v,
                    v,
                    side: Some(side),
                    tick,
                    tag: client_tag,
                    ..base
                };
                if let Some(r) = route {
                    op.explicit = true;
                    self.forward(vis, raw, &mut op, ts, r == Route::Cross)?;
                }
                Ok(op)
            }
            Msg::Cancel { handle, client_tag } => {
                self.check_cancel(si, CancelKind::Cancel, ts)?;
                let r = self.resolve(handle)?;
                Ok(self.cancel_op(base, r, client_tag))
            }
            Msg::Reduce {
                handle,
                by,
                client_tag,
            } => {
                self.check_cancel(si, CancelKind::Reduce, ts)?;
                if by.0 == 0 {
                    return Err(rej(RejectReason::BadQty, vyrn_risk::consts::RSK_D_QTY_ZERO));
                }
                let r = self.resolve(handle)?;
                self.reduce_op(base, r, by.0, client_tag, ts)
            }
            Msg::Replace {
                flags,
                handle,
                tick,
                qty,
            } => {
                let r = self.resolve(handle)?;
                if s.state == SessState::Draining {
                    return Err(rej(RejectReason::SessionClosed, PROTO_D_DRAINING));
                }
                let rp = *self.root(r).ok_or(rej(RejectReason::UnknownHandle, 0))?;
                let v = rp.cur;
                let vp = *self.slot(v).ok_or(rej(RejectReason::UnknownHandle, 0))?;
                let f = bbo_flags(flags);
                if Some(f.side()) != vp.side {
                    return Err(rej(RejectReason::SideMismatch, 0));
                }
                if tick == vp.tick && f == vp.flags && qty.0 < vp.total && qty.0 > 0 {
                    // A same-tick reduction is a Reduce (01 §6.2, 04 §6.5), with its buckets.
                    self.check_cancel(si, CancelKind::Reduce, ts)?;
                    let by = vp.total.saturating_sub(qty.0);
                    return self.reduce_op(base, r, by, rp.tag, ts);
                }
                let side = f.side();
                let route = self.route_of(seq, side, f.tif(), tick);
                self.classified = route;
                let fit = self.slots_free(1) && self.fifo.can_assign(side, tick, ts);
                let risk = self.check_new(si, f, tick, qty, route, ts, fit)?;
                let w = self.take_slot();
                let pos = self.fifo.assign(&self.a, side, tick, ts).ok_or(rej(
                    RejectReason::RiskOrderCount,
                    vyrn_risk::consts::RSK_D_LANE_FULL,
                ))?;
                if pos.new_level {
                    self.occ_set_event(side, tick);
                }
                let cur_pkt = self.cur_pkt;
                if let Some(p) = self.slot_mut(w) {
                    *p = SlotP {
                        kind: SKind::NewPrio,
                        root: r,
                        leg: w,
                        side: Some(side),
                        flags: f,
                        tick,
                        total: qty.0,
                        ins_seq: seq,
                        ts,
                        pos: pos.pos,
                        has_pos: true,
                        explicit: route.is_some(),
                        risk: Some(risk),
                        ix,
                        sess: si,
                        pkt: cur_pkt,
                        pred: v,
                        pred_pending: route.is_some(),
                        ..SlotP::default()
                    };
                }
                if let Some(x) = self.root_mut(r) {
                    x.cur = w;
                }
                self.write_slot_line(w, r, rp.acct);
                let mut op = Op {
                    k: OpK::Replace,
                    root: r,
                    v,
                    w,
                    side: Some(side),
                    tick,
                    tag: rp.tag,
                    ..base
                };
                if let Some(r) = route {
                    op.explicit = true;
                    self.forward(vis, raw, &mut op, ts, r == Route::Cross)?;
                }
                Ok(op)
            }
            Msg::CancelAll { client_tag } => {
                self.check_cancel(si, CancelKind::CancelAll, ts)?;
                if let Some(x) = self.sess.get_mut(si) {
                    x.cancel_all = seq;
                }
                Ok(Op {
                    k: OpK::CancelAll,
                    tag: client_tag,
                    ..base
                })
            }
            Msg::Heartbeat | Msg::ResendReq { .. } => Err(rej(RejectReason::BadType, 0)),
        }
    }

    fn new_root(&mut self, v: u32, si: u16, acct: AcctSlot, tag: u32) {
        if let Some(r) = self.root_mut(v) {
            *r = RootP {
                live: true,
                sess: si,
                acct,
                tag,
                cur: v,
                ..RootP::default()
            };
        }
        let Some(s) = self.sess.get_mut(si) else {
            return;
        };
        let last = s.last;
        s.last = v;
        if s.first == 0 {
            s.first = v;
        } else if let Some(p) = self.roots.get_mut(uix(last)) {
            p.next = v;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_new(
        &mut self,
        si: u16,
        f: OrderFlags,
        tick: Tick,
        qty: Qty,
        route: Option<Route>,
        now: Nanos,
        slot_free: bool,
    ) -> Result<OrderRisk, RiskReject> {
        let snap = self.risk_snap();
        let spec = self.cfg.spec;
        let s = self
            .sess
            .get_mut(si)
            .ok_or(rej(RejectReason::SessionClosed, 0))?;
        let (acct, bal) = self.accts.get_mut(s.acct)?;
        let m = NewOrder {
            side: risk_side(f.side()),
            tif: risk_tif(f.tif()),
            post_only: f.post_only(),
            tick,
            qty,
        };
        Risk {
            acct,
            sess: &mut s.buckets,
            bal,
            lane: &mut self.lane_bk,
            book: &mut self.bk,
            spec: &spec,
            snap: &snap,
            now,
            slot_free,
        }
        .check_new(&m, route.unwrap_or(Route::Join))
    }

    fn check_cancel(&mut self, si: u16, k: CancelKind, now: Nanos) -> Result<(), RiskReject> {
        let snap = self.risk_snap();
        let spec = self.cfg.spec;
        let s = self
            .sess
            .get_mut(si)
            .ok_or(rej(RejectReason::SessionClosed, 0))?;
        let (acct, bal) = self.accts.get_mut(s.acct)?;
        Risk {
            acct,
            sess: &mut s.buckets,
            bal,
            lane: &mut self.lane_bk,
            book: &mut self.bk,
            spec: &spec,
            snap: &snap,
            now,
            slot_free: true,
        }
        .check_cancel(k)
    }

    fn cancel_op(&mut self, base: Op, r: u32, tag: u32) -> Op {
        let v = self.root(r).map_or(0, |x| x.cur);
        let vp = self.slot(v).copied().unwrap_or_default();
        if let Some(x) = self.root_mut(r) {
            x.local_end = true;
        }
        Op {
            k: OpK::Cancel,
            root: r,
            v,
            side: vp.side,
            tick: vp.tick,
            tag,
            ..base
        }
    }

    fn reduce_op(
        &mut self,
        base: Op,
        r: u32,
        by: u32,
        tag: u32,
        ts: Nanos,
    ) -> Result<Op, RiskReject> {
        let rp = *self.root(r).ok_or(rej(RejectReason::UnknownHandle, 0))?;
        let v = rp.cur;
        let vp = *self.slot(v).ok_or(rej(RejectReason::UnknownHandle, 0))?;
        let known_open = vp.total.saturating_sub(rp.filled);
        if by >= known_open {
            // Reduce to 0 ends the order: a cancel (04 §6.4), answered with `canceled = open`.
            let mut op = self.cancel_op(base, r, tag);
            op.r = by;
            return Ok(op);
        }
        if !self.slots_free(1) {
            return Err(rej(
                RejectReason::RiskOrderCount,
                vyrn_risk::consts::RSK_D_LANE_FULL,
            ));
        }
        let w = self.take_slot();
        let (cur_sess, cur_pkt) = (self.cur_sess, self.cur_pkt);
        if let Some(p) = self.slot_mut(w) {
            *p = SlotP {
                kind: SKind::KeepPrio,
                root: r,
                leg: vp.leg,
                side: vp.side,
                flags: vp.flags,
                tick: vp.tick,
                total: vp.total.saturating_sub(by),
                ins_seq: base.seq,
                ts,
                ix: base.ix,
                sess: cur_sess,
                pkt: cur_pkt,
                ..SlotP::default()
            };
        }
        self.write_slot_line(w, r, rp.acct);
        if let Some(x) = self.root_mut(r) {
            x.cur = w;
        }
        Ok(Op {
            k: OpK::Reduce,
            root: r,
            v,
            w,
            side: vp.side,
            tick: vp.tick,
            r: by,
            tag,
            ..base
        })
    }

    // -----------------------------------------------------------------------------------------
    // Forwarding (05 §6.6)

    fn forward(
        &mut self,
        vis: &V,
        raw: &[u8; MSG_BYTES],
        op: &mut Op,
        ts: Nanos,
        cross: bool,
    ) -> Result<(), RiskReject> {
        let Some(j_side) = op.side else {
            return Ok(());
        };
        let j_tick = op.tick;
        // Pass barriers: a CancelAll, or a Reduce of an opposite-side order in range, is applied
        // and published before the push, so j sees it through the cut.
        let barrier = self
            .ops
            .iter()
            .take(self.n_ops)
            .filter(|o| !o.applied && !o.explicit)
            .filter(|o| match o.k {
                OpK::CancelAll => true,
                OpK::Reduce => o.side.is_some_and(|s| in_range(j_side, j_tick, s, o.tick)),
                // A local Replace that moves an order out of j's range: j must not see the old
                // version, so pass 2 applies and publishes it first (in range: a dependency).
                OpK::Replace => o.side.is_some_and(|s| {
                    let old = self.slot(o.v).map_or(o.tick, |p| p.tick);
                    in_range(j_side, j_tick, s, old) && !in_range(j_side, j_tick, s, o.tick)
                }),
                _ => false,
            })
            .map(|o| o.seq)
            .max();
        if let Some(b) = barrier {
            self.pass2_through(vis, b);
        }
        // Dependencies: earlier, unapplied, not explicit Joins and Cancels in range.
        let mut deps = [FwdDep::default(); 9];
        let mut dep_slots = [0u32; 9];
        let mut n = 0usize;
        for i in 0..self.n_ops {
            let Some(o) = self.ops.get(i).copied() else {
                continue;
            };
            let Some(side) = o.side else { continue };
            if o.applied || o.explicit || o.root == op.root {
                continue;
            }
            let is_join = matches!(o.k, OpK::Join | OpK::Replace);
            if !(is_join || o.k == OpK::Cancel) || !in_range(j_side, j_tick, side, o.tick) {
                continue;
            }
            let back = u8::try_from(op.seq.0.saturating_sub(o.seq.0)).unwrap_or(0);
            let d = if is_join {
                let w = if o.k == OpK::Join { o.v } else { o.w };
                let p = self.slot(w).copied().unwrap_or_default();
                FwdDep {
                    back,
                    kind: DEP_JOIN,
                    flags: p.flags,
                    pos: p.pos.i,
                    tick: p.tick,
                    qty: Qty(p.total),
                    slot: w,
                }
            } else {
                let leg = self.slot(o.v).map_or(0, |p| p.leg);
                let h = self.slot(leg).copied().unwrap_or_default();
                FwdDep {
                    back,
                    kind: DEP_CANCEL,
                    flags: h.flags,
                    pos: h.pos.i,
                    tick: h.tick,
                    qty: Qty(0),
                    slot: leg,
                }
            };
            if let (Some(x), Some(y)) = (deps.get_mut(n), dep_slots.get_mut(n)) {
                *x = d;
                *y = d.slot;
                n = n.saturating_add(1);
            }
            if let Some(o) = self.ops.get_mut(i) {
                o.explicit = true;
            }
            if is_join {
                let w = if o.k == OpK::Join { o.v } else { o.w };
                if let Some(p) = self.slot_mut(w) {
                    p.explicit = true;
                    // A Replace dependency is explicit: it can be shed or refused.
                    p.pred_pending = o.k == OpK::Replace;
                }
            } else {
                if let Some(x) = self.root_mut(o.root) {
                    x.local_end = false; // an explicit cancel can be shed (contract rule R)
                }
                self.dep_cancels.push((o.root, o.seq, self.cur_ts));
            }
        }
        let deps = deps.get(..n).unwrap_or(&[]);
        let si = self.cur_sess;
        let s = self
            .sess
            .get_mut(si)
            .ok_or(rej(RejectReason::SessionClosed, 0))?;
        let rs = s.next_resp;
        s.next_resp = s.next_resp.wrapping_add(if n == 0 { 1 } else { 2 });
        let (sid, acct) = (s.id, s.acct);
        let vslot = if op.k == OpK::Replace { op.w } else { op.v };
        let mut msg = *raw;
        if let Some(b) = msg.get_mut(2) {
            // 05 §4.12: the index, and the route risk charged (10 M8) for replay (05 §10).
            *b = (op.ix & FWD_INDEX) | if cross { FWD_CROSS } else { 0 };
        }
        let e = FwdEntry {
            lane_seq: op.seq,
            prio_ts: ts,
            snap_ver: lo32(self.snap.version),
            deadline: lo32(self.cur_rx_ts_deadline()),
            msg,
            handle: self.handle(op.root),
            vslot,
            session: sid,
            resp_seq: rs,
            pkt_seq: self.cur_pkt,
            acct_ix: u16::try_from(self.acct_index(acct)).unwrap_or(u16::MAX),
            applied_back: u16::try_from(op.seq.0.saturating_sub(self.applied.0))
                .unwrap_or(u16::MAX),
        };
        let mut lines = [[0u64; 8]; 4];
        let k = encode_fwd(&e, deps, &mut lines);
        // Back-pressure (05 §14.2): drain fill events into the lane buffer while the ring is
        // full; they are applied only at B1.
        let mut spins = 0u32;
        while !self.io.fwd.push_all(vis, lines.get(..k).unwrap_or(&[])) {
            self.buffer_events(vis);
            spins = spins.saturating_add(1);
            if spins > 1_000_000 {
                self.fault = true;
                return Err(rej(RejectReason::Busy, 0));
            }
        }
        let max_back = deps.iter().map(|d| d.back).max().unwrap_or(0);
        self.fwd.push_back(FwdOut {
            floor: LaneSeq(op.seq.0.saturating_sub(u64::from(max_back))),
            vslot,
            n_dep: u8::try_from(n).unwrap_or(0),
            dep_slots,
        });
        Ok(())
    }

    fn cur_rx_ts_deadline(&self) -> u64 {
        self.cur_ts
            .0
            .wrapping_add(u64::from(self.cfg.fwd_deadline_ns))
    }

    // -----------------------------------------------------------------------------------------
    // Pass 2 (05 §6.4 `pass2_apply`): independent ops only

    fn pass2_apply(&mut self, op: &Op) {
        let ts = self.cur_ts;
        match op.k {
            OpK::Reject => {}
            OpK::Join => {
                self.write_position(op.v);
                self.journal(JEnt {
                    seq: op.seq,
                    tick: op.tick,
                    slot: op.v,
                    kind: JKind::New,
                });
                self.pend_push(op, PendK::Ack);
            }
            OpK::Replace => {
                self.tombstone(op.v, op.seq, ts);
                self.end_position(op.v);
                self.write_position(op.w);
                self.journal(JEnt {
                    seq: op.seq,
                    tick: op.tick,
                    slot: op.w,
                    kind: JKind::NewPrio,
                });
                self.pend_push(op, PendK::ReplaceAck);
            }
            OpK::Cancel => {
                // Robust to earlier explicit Replaces still at the BBO core: end the current
                // version and every pending predecessor; the settle uses whichever is current
                // (contract rule R). One journal entry per op (05 §4.9).
                let mut v = op.v;
                while v != 0 {
                    self.tombstone(v, op.seq, ts);
                    self.end_position(v);
                    let leg = self.slot(v).map_or(0, |p| p.leg);
                    v = self
                        .slot(leg)
                        .filter(|h| h.kind == SKind::NewPrio && h.pred_pending)
                        .map_or(0, |h| h.pred);
                }
                self.journal(JEnt {
                    seq: op.seq,
                    tick: op.tick,
                    slot: op.v,
                    kind: JKind::Tomb,
                });
                self.pend_push(op, PendK::CancelAck);
            }
            OpK::Reduce => {
                let tick = self.slot(op.v).map_or(0, |p| p.tick.0);
                self.a.slot_next_ver(op.v, join(op.w, tick));
                self.tombstone(op.v, op.seq, ts);
                let leg = self.slot(op.v).map_or(0, |p| p.leg);
                if let Some(h) = self.slot(leg).copied()
                    && h.has_pos
                {
                    self.fifo.chain(&self.a, h.pos);
                }
                self.journal(JEnt {
                    seq: op.seq,
                    tick: op.tick,
                    slot: op.w,
                    kind: JKind::KeepPrio,
                });
                self.pend_push(op, PendK::ReduceAck);
            }
            OpK::CancelAll => {
                self.apply_cancel_all(op.seq, ts);
                self.pend_push(op, PendK::CancelAllAck);
            }
        }
    }

    /// Writes the position of leg head `v` (05 §4.6): independent ops in pass 2, explicit ops
    /// at B1. A version already tombstoned gets `pend` only.
    pub(crate) fn write_position(&mut self, v: u32) {
        let Some(p) = self.slot(v).copied() else {
            return;
        };
        if !p.has_pos {
            return;
        }
        self.fifo.write(
            &self.a,
            p.pos,
            v,
            p.total,
            p.ts,
            !p.tomb,
            p.kind == SKind::NewPrio,
        );
    }

    /// 05 §4.7: one `AcctKill` when the account has one session; per-order tombstones when it has
    /// more (`CancelAll` is per session, 04 §6.6). Before `kill_seq` is overwritten, the older
    /// `CancelAll`'s orders get their real tombstones.
    fn apply_cancel_all(&mut self, seq: LaneSeq, ts: Nanos) {
        let si = self.cur_sess;
        let Some(s) = self.sess.get(si).copied() else {
            return;
        };
        let single = self.acct_sessions.get(uix(s.acct.0)).copied() == Some(1);
        let kix = self.acct_index(s.acct);
        let prev = self.a.view().acct_kill(kix);
        let (upto, tseq, tts) = if single {
            (LaneSeq(prev.0), LaneSeq(prev.0), Nanos(prev.1))
        } else {
            (seq, seq, ts)
        };
        let mut r = s.first;
        while r != 0 {
            let Some(rp) = self.root(r).copied() else {
                break;
            };
            let cur = self.slot(rp.cur).copied().unwrap_or_default();
            // Single session: materialize the previous kill for every root it covered, ended
            // ones included (B2 already released them), before `AcctKill` is overwritten.
            if rp.live && (single || !rp.ended) && cur.ins_seq < upto && !cur.tomb {
                // The current version and every pending predecessor (contract rule R): a shed
                // replace makes its predecessor current again.
                let mut v = rp.cur;
                while v != 0 {
                    self.tombstone(v, tseq, tts);
                    if !single {
                        self.end_position(v);
                    }
                    let leg = self.slot(v).map_or(0, |p| p.leg);
                    v = self
                        .slot(leg)
                        .filter(|h| h.kind == SKind::NewPrio && h.pred_pending)
                        .map_or(0, |h| h.pred);
                }
            }
            r = rp.next;
        }
        if single {
            self.a.acct_kill(kix, seq, ts);
        }
        self.journal(JEnt {
            seq,
            tick: Tick(0),
            slot: kix,
            kind: JKind::AcctKill,
        });
    }

    fn pend_push(&mut self, op: &Op, k: PendK) {
        self.pend.push_back(PendE {
            seq: op.seq,
            k,
            root: op.root,
            v: op.v,
            w: op.w,
            r: op.r,
            ix: op.ix,
            sess: self.cur_sess,
            pkt: self.cur_pkt,
            tag: op.tag,
        });
    }

    #[allow(dead_code)]
    pub(crate) fn stp_none(f: OrderFlags) -> bool {
        f.stp() == Stp::None
    }
}

/// `PROTO_SEQ_BACK` and `PROTO_SEQ_AHEAD` (04 §14).
pub const PROTO_SEQ_BACK: u32 = 1024;
pub const PROTO_SEQ_AHEAD: u32 = 64;
