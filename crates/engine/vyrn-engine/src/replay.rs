//! Replay mode (05 §10, 01 §11.6): the same lanes and BBO core, driven by the order stream.
//!
//! Each record is replayed by the call that produced it live, and the call's output records
//! must equal the input records byte for byte:
//!
//! - a `Rec::Step`: [`vyrn_bbo::Bbo::replay_step`] with the step's cut (`C_{s−1}` plus its
//!   deltas), source, kind (incl. `Shed`, `CONT`) and `Rescan` band from the record (05 §10 rows
//!   4–5). No clock is read; the cut cores still publish, because `replay_step` reads the
//!   half-cuts for `Pend` retirement;
//! - a non-`MID` Advance record of lane `l`: lane `l`'s boundary at the `(f, C_f[l])` it logs
//!   (`f` = its `fills_applied`, `C_f` the replayed step `f`'s cut), as for a `MID` record;
//! - a packet record (with the `MID` Advance records the lane wrote while processing it): the
//!   packet, fetched from [`Payloads`], through `vyrn_lane::Lane::replay_packet` with an on-time
//!   clock, its `MID` records as `Mid` boundaries at `(f, C_f[l])` (05 §6.2, §10 row
//!   3), and its ops' routes taken from its `Route` records (one per op the lane classified,
//!   forwarded or rejected, 07 §3.6; §10 row 7);
//! - a `SHED` record: `vyrn_lane::Lane::replay_shed`, from the record alone. No payload is
//!   fetched: a shed packet's `BUSY` responses carry `client_tag` 0 (05 §6.8, §18 Q17).
//!   A `Route` record is part of its packet's lane call and is compared like the packet's.

use vyrn_bbo::admit::NeverLate;
use vyrn_bbo::{
    ControlCmd, Cut, CutDelta, Diverge, MAX_LANES, Phase, Record, ReplayStep, StepEntry, TxEntry,
};
use vyrn_cut::LaneCutEntry;
use vyrn_cut::Visibility;
use vyrn_lane::{Mid, RespPkt, RxIn};
use vyrn_risk::Route;
use vyrn_types::{
    AcctTake, LaneId, LaneSeq, PacketFlags, PacketRecord, RouteRecord, StepFlags, StepId, StepKind,
    StepRecord, Tick,
};

use crate::engine::{CARRY_CAP, Engine, Fault, Rec, Sink, StepErr};

/// One order-stream element, owned (for logs and journals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Inline deltas, not a `Box`: building one never allocates (`INV-NOALLOC`).
#[allow(clippy::large_enum_variant)]
pub enum OwnedRec {
    Packet(PacketRecord),
    Step(StepEntry, [CutDelta; MAX_LANES]),
    Route(RouteRecord),
    /// A pooled lane's account take (01 §14.17.4, 05 §6.9), logged right before the record it
    /// covers. [`Engine::replay`] checks it as part of that record's lane call.
    Take(AcctTake),
}

impl OwnedRec {
    pub fn of(r: &Rec<'_>) -> Self {
        match r {
            Rec::Packet(p) => Self::Packet(*p),
            Rec::Route(x) => Self::Route(*x),
            Rec::Step(e, d) => {
                let mut a = [CutDelta::default(); MAX_LANES];
                for (x, y) in a.iter_mut().zip(d.iter()) {
                    *x = *y;
                }
                Self::Step(*e, a)
            }
        }
    }
    /// The borrowed form; a step's deltas are its first `n_delta`. `None` for an `AcctTake`,
    /// which a [`Sink`] receives through [`Sink::take`], not [`Sink::record`].
    pub fn as_rec(&self) -> Option<Rec<'_>> {
        Some(match self {
            Self::Packet(p) => Rec::Packet(*p),
            Self::Route(x) => Rec::Route(*x),
            Self::Step(e, d) => Rec::Step(*e, d.get(..usize::from(e.n_delta)).unwrap_or(&[])),
            Self::Take(_) => return None,
        })
    }
}

/// Packet bytes by record (07's data tier keys them by `pkt_hash`, 07 §3.5). Replay never asks
/// for a `SHED` record's bytes (05 §18 Q17).
pub trait Payloads {
    fn get(&self, r: &PacketRecord) -> Option<&[u8]>;
}

/// A response log to check replay's responses against (07 §7.1: replay outputs every response
/// record). Each method returns `false` when the produced response is not the next one the log
/// holds for that stream. Lane responses are compared per lane, fill TX packets in step order;
/// the order across lanes is a schedule choice and is not compared.
pub trait Responses {
    fn lane(&mut self, lane: LaneId, p: &RespPkt) -> bool;
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) -> bool;
    /// `true` when every logged response was produced. Checked once, at the end.
    fn finished(&self) -> bool {
        true
    }
}

/// No response log: replay checks the order stream only.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResponses;

impl Responses for NoResponses {
    fn lane(&mut self, _: LaneId, _: &RespPkt) -> bool {
        true
    }
    fn tx(&mut self, _: &TxEntry, _: &[Record]) -> bool {
        true
    }
}

/// Why replay stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The replayed call produced a different record here (or none). Steps compare every
    /// field except the half-cut publication ids `pub_a`/`pub_b` (physical).
    Mismatch,
    /// No payload for this packet record.
    NoPayload,
    /// The BBO core took no step where the log has one.
    NoStep,
    /// A `MID` record names a step older than the cut history (`ENG_STEP_LOG` steps).
    StepTooOld,
    /// A step record does not decode (`StepKind`, delta count or lane out of range).
    BadStep,
    /// The BBO core refused the logged step: it cannot be this core's next step.
    Step(Diverge),
    /// A record names a lane the box does not have, or an Advance record with no lane work.
    BadRecord,
    /// A response differs from the response log, or the log holds responses replay did not
    /// produce.
    Response,
    /// The snapshot version a packet record's `snap_lag` names was never published, or replay
    /// no longer holds it ([`crate::REPLAY_SNAP_HIST`] versions, 07 §7.1).
    NoSnapshot,
    /// 07 §7.1 `REP_MERGE` cannot order the inputs (`REP_E_ORDER`): a step's cut covers an op its
    /// lane has not replayed, or a lane record is due at a step the input does not hold.
    Order,
    Fault(Fault),
}

/// Replay stopped at input record `index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diverged {
    pub index: usize,
    pub why: Why,
}

/// Collects one call's records and forwards everything to the caller's sink.
struct Tee<'s, S, R> {
    inner: &'s mut S,
    log: &'s mut R,
    pkts: &'s mut Vec<PacketRecord>,
    /// The call's route records, in output order.
    routes: [RouteRecord; MAX_ROUTES],
    n_routes: usize,
    /// The call's `AcctTake` records, in output order.
    takes: [Option<AcctTake>; MAX_TAKES],
    n_takes: usize,
    /// The kind of each record the call output, in output order: the compare checks the
    /// order across kinds, so a take must sit right before the record it covers.
    order: [Kind; MAX_OUT],
    n_order: usize,
    /// More than [`MAX_OUT`] records: the lane-call compare fails (other calls ignore it).
    order_full: bool,
    step: Option<OwnedRec>,
    bad_resp: bool,
}

impl<'s, S, R> Tee<'s, S, R> {
    fn new(inner: &'s mut S, log: &'s mut R, pkts: &'s mut Vec<PacketRecord>) -> Self {
        pkts.clear();
        Self {
            inner,
            log,
            pkts,
            routes: [NO_ROUTE; MAX_ROUTES],
            n_routes: 0,
            takes: [None; MAX_TAKES],
            n_takes: 0,
            order: [Kind::Packet; MAX_OUT],
            n_order: 0,
            order_full: false,
            step: None,
            bad_resp: false,
        }
    }
    fn routes(&self) -> &[RouteRecord] {
        self.routes.get(..self.n_routes).unwrap_or(&[])
    }
    fn order(&self) -> &[Kind] {
        self.order.get(..self.n_order).unwrap_or(&[])
    }
    /// Notes one output record's kind; more than a lane call can output fails its compare.
    fn note(&mut self, k: Kind) {
        match self.order.get_mut(self.n_order) {
            Some(d) => {
                *d = k;
                self.n_order = self.n_order.saturating_add(1);
            }
            None => self.order_full = true,
        }
    }
}

/// The kind of a lane call's output record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Packet,
    Route,
    Take,
}

const NO_ROUTE: RouteRecord = RouteRecord {
    lane: LaneId(0),
    lane_seq: LaneSeq(0),
    cross: false,
};

impl<S: Sink, R: Responses> Sink for Tee<'_, S, R> {
    fn record(&mut self, r: &Rec<'_>) {
        match r {
            Rec::Packet(p) => {
                if self.pkts.len() < self.pkts.capacity() {
                    self.pkts.push(*p);
                }
                self.note(Kind::Packet);
            }
            Rec::Route(x) => {
                self.note(Kind::Route);
                // More than one per op is a lane fault that the compare reports.
                match self.routes.get_mut(self.n_routes) {
                    Some(d) => {
                        *d = *x;
                        self.n_routes = self.n_routes.saturating_add(1);
                    }
                    None => self.bad_resp = true,
                }
            }
            Rec::Step(..) => self.step = Some(OwnedRec::of(r)),
        }
        self.inner.record(r);
    }
    fn lane_resp(&mut self, lane: LaneId, p: &RespPkt) {
        if !self.log.lane(lane, p) {
            self.bad_resp = true;
        }
        self.inner.lane_resp(lane, p);
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        if !self.log.tx(h, recs) {
            self.bad_resp = true;
        }
        self.inner.tx(h, recs);
    }
    fn take(&mut self, t: &AcctTake) {
        // More than one per packet record is a fault that the compare reports.
        match self.takes.get_mut(self.n_takes) {
            Some(d) => {
                *d = Some(*t);
                self.n_takes = self.n_takes.saturating_add(1);
            }
            None => self.bad_resp = true,
        }
        self.note(Kind::Take);
        self.inner.take(t);
    }
}

/// Equal as steps: every field but `pub_a`/`pub_b`, the half-cut publication ids. Those count
/// cut-core publications, a physical choice that replay does not repeat (05 §10: "replay needs
/// no cut core"); 01 §6.6's `StepRecord` does not carry them.
fn same_step(a: &OwnedRec, b: &OwnedRec) -> bool {
    let strip = |r: &OwnedRec| match *r {
        OwnedRec::Step(e, d) => Some((
            StepEntry {
                pub_a: 0,
                pub_b: 0,
                ..e
            },
            d,
        )),
        OwnedRec::Packet(_) | OwnedRec::Route(_) | OwnedRec::Take(_) => None,
    };
    let (x, y) = (strip(a), strip(b));
    x.is_some() && x == y
}

fn packet_of(r: &OwnedRec) -> Option<&PacketRecord> {
    match r {
        OwnedRec::Packet(p) => Some(p),
        OwnedRec::Step(..) | OwnedRec::Route(_) | OwnedRec::Take(_) => None,
    }
}

/// Boundaries one packet can hold: before pass 1 and pass 2 of each of its 10 ops.
const MAX_MIDS: usize = 20;
/// Forwarded ops one packet can hold.
const MAX_ROUTES: usize = 10;
/// `AcctTake` records one lane call can log: one for its packet record (05 §6.9); the rest of
/// the call's records are Advance records, which take no token.
const MAX_TAKES: usize = 2;
/// Records one lane call can output: its packet, its `MID` records and Advance records, routes
/// and takes.
const MAX_OUT: usize = 1 + MAX_MIDS + MAX_ROUTES + MAX_TAKES + 1;

/// The routes of packet `pk`'s classified ops (05 §10 row 7, 07 §3.6): one route record per op
/// the lane classified `Cross` or `Improve`, forwarded or rejected by the lane itself. Every
/// other op is `Join`.
fn routes_of(
    recs: impl Iterator<Item = RouteRecord>,
    pk: &PacketRecord,
    out: &mut [(LaneSeq, Route); MAX_ROUTES],
) -> usize {
    let mut n = 0usize;
    for x in recs.filter(|x| in_packet(pk, x)) {
        if out.iter().take(n).any(|(s, _)| *s == x.lane_seq) {
            continue;
        }
        let route = if x.cross {
            Route::Cross
        } else {
            Route::Improve
        };
        if let Some(d) = out.get_mut(n) {
            *d = (x.lane_seq, route);
            n = n.saturating_add(1);
        }
    }
    n
}

/// `x` names an op of packet `pk`.
fn in_packet(pk: &PacketRecord, x: &RouteRecord) -> bool {
    let lo = pk.first_lane_seq.0;
    x.lane == pk.lane
        && !is_advance(pk)
        && lo <= x.lane_seq.0
        && x.lane_seq.0 < lo.saturating_add(u64::from(pk.count))
}

fn is_advance(p: &PacketRecord) -> bool {
    p.flags & PacketFlags::ADVANCE != 0
}

fn is_mid(p: &PacketRecord) -> bool {
    p.flags & PacketFlags::MID != 0
}

/// Bytes of a `Control` step's payload (07 §3.8 "code, argument"): `code` u8 (1 Phase, 2
/// Band, as `ControlCmd`'s line), `phase` u8 (0 for Band), `lo` u32 LE, `hi` u32 LE
/// [Reading: 07 §3.8 names the fields, not their layout; PR body].
pub const CONTROL_PAYLOAD_LEN: usize = 10;

/// `c` as a `Control` step's payload; `None` for `Uncross` and `Seal`, which have their own step
/// kinds.
pub fn control_payload(c: &ControlCmd) -> Option<[u8; CONTROL_PAYLOAD_LEN]> {
    let (code, phase, lo, hi) = match *c {
        ControlCmd::Phase { phase, lo, hi } => (1, phase.code(), lo, hi),
        ControlCmd::Band { lo, hi } => (2, 0, lo, hi),
        ControlCmd::Uncross { .. } | ControlCmd::Seal => return None,
    };
    let ([l0, l1, l2, l3], [h0, h1, h2, h3]) = (lo.0.to_le_bytes(), hi.0.to_le_bytes());
    Some([code, phase, l0, l1, l2, l3, h0, h1, h2, h3])
}

/// The command a `Control` step's payload names ([`control_payload`]'s inverse).
pub fn control_of_payload(b: &[u8]) -> Option<ControlCmd> {
    let b: &[u8; CONTROL_PAYLOAD_LEN] = b.try_into().ok()?;
    let [code, phase, l0, l1, l2, l3, h0, h1, h2, h3] = *b;
    let (lo, hi) = (
        Tick(u32::from_le_bytes([l0, l1, l2, l3])),
        Tick(u32::from_le_bytes([h0, h1, h2, h3])),
    );
    match (code, phase) {
        (1, p) => Some(ControlCmd::Phase {
            phase: Phase::from_code(p)?,
            lo,
            hi,
        }),
        (2, 0) => Some(ControlCmd::Band { lo, hi }),
        _ => None,
    }
}

/// One whole step as 07 delivers it (§3.8, merged by StepId): kind, source, cut, kind payload.
/// Every other `StepEntry` field is an output of replay (07 §7.1 "Fields replay derives").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireStep<'p> {
    pub step: StepId,
    pub kind: StepKind,
    /// `None`: the kind has no source (07 `src_lane` 0xFF).
    pub src: Option<(LaneId, LaneSeq)>,
    /// `StepRecord.flags & StepFlags::CROSS` (07 §3.8 src byte bit 7): the route the source's
    /// lane classified, `Cross` when set, `Improve` when clear. Read only when `src` is set.
    pub cross: bool,
    /// `cut[l]` for every lane of the box.
    pub cut: &'p [LaneSeq],
    /// The kind payload; for `Rescan`, `band_lo` u32 LE then `band_hi` u32 LE, or empty for all
    /// ticks (07 §3.8, §7.1); for `Control`, [`control_payload`]'s bytes.
    pub payload: &'p [u8],
}

impl<'p> WireStep<'p> {
    /// From 01 §6.6's record (as `vyrn-log`'s `MergedStep` holds it) and its payload.
    pub fn of<const N: usize>(rec: &'p StepRecord<N>, payload: &'p [u8]) -> Self {
        Self {
            step: rec.step,
            kind: rec.kind,
            src: (rec.src_lane_seq.0 != 0).then_some((rec.src_lane, rec.src_lane_seq)),
            cross: rec.flags & StepFlags::CROSS != 0,
            cut: &rec.cut,
            payload,
        }
    }
}

/// Where [`Engine::replay_wire`] stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireAt {
    /// At this index of the lane records: the records carried from the previous block
    /// ([`Engine::carried`] before the call) come first, then this call's `lanes`.
    Lane(usize),
    /// At this step.
    Step(StepId),
    /// After the last input (the response log's final check).
    End,
}

/// [`Engine::replay_wire`] stopped at `at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireDiverged {
    pub at: WireAt,
    pub why: Why,
}

/// One lane call (07 §7.1 `REP_MERGE` item 1): a packet record with its `MID` records, or a
/// non-`MID` Advance record alone. `f` is the step it is due at.
#[derive(Clone, Copy)]
struct Call {
    rec: PacketRecord,
    f: StepId,
    mids: [PacketRecord; MAX_MIDS],
    n_mid: usize,
    /// Index of the last input record of the call, plus one.
    end: usize,
}

const NO_REC: PacketRecord = PacketRecord {
    lane: LaneId(0),
    count: 0,
    flags: 0,
    session: vyrn_types::SessionId(0),
    pkt_seq: 0,
    rx_ts: vyrn_types::Nanos(0),
    pkt_hash: vyrn_types::PktHash(0),
    first_lane_seq: LaneSeq(0),
    fills_applied: StepId(0),
    snap_lag: 0,
};

/// The carried records followed by one block's records, indexed as one sequence.
#[derive(Clone, Copy)]
struct Recs<'a> {
    a: &'a [PacketRecord],
    b: &'a [PacketRecord],
    /// The carried route records, then this block's.
    ra: &'a [RouteRecord],
    rb: &'a [RouteRecord],
}

impl Recs<'_> {
    fn len(&self) -> usize {
        self.a.len().saturating_add(self.b.len())
    }
    fn get(&self, i: usize) -> Option<&PacketRecord> {
        match i.checked_sub(self.a.len()) {
            None => self.a.get(i),
            Some(k) => self.b.get(k),
        }
    }
    fn routes(&self) -> impl Iterator<Item = RouteRecord> + '_ {
        self.ra.iter().chain(self.rb).copied()
    }
}

/// The next call of `lane` from index `from`: `(index of its first record, call)`.
fn next_call(recs: Recs<'_>, lane: LaneId, from: usize) -> Option<(usize, Result<Call, usize>)> {
    let i = (from..recs.len()).find(|&i| recs.get(i).is_some_and(|r| r.lane == lane))?;
    let r = *recs.get(i)?;
    if is_mid(&r) {
        return Some((i, Err(i)));
    }
    let mut c = Call {
        rec: r,
        f: r.fills_applied,
        mids: [NO_REC; MAX_MIDS],
        n_mid: 0,
        end: i.saturating_add(1),
    };
    if is_advance(&r) {
        return Some((i, Ok(c)));
    }
    for j in i.saturating_add(1)..recs.len() {
        let Some(m) = recs.get(j) else { break };
        if m.lane != lane {
            continue;
        }
        if !is_mid(m) {
            break;
        }
        let Some(d) = c.mids.get_mut(c.n_mid) else {
            return Some((i, Err(j)));
        };
        *d = *m;
        c.n_mid = c.n_mid.saturating_add(1);
        c.f = c.f.max(m.fills_applied);
        c.end = j.saturating_add(1);
    }
    Some((i, Ok(c)))
}

impl<V: Visibility, const NA: usize> Engine<'_, V, NA> {
    /// The lane records [`Engine::replay_wire`] carried to the next block, in input order.
    pub fn carried(&self) -> &[PacketRecord] {
        &self.carry
    }

    /// Replays the engine's own journal `recs` from its initial state, forwarding every output to
    /// `sink` and checking responses against `log` ([`NoResponses`] for none).
    pub fn replay<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        recs: &[OwnedRec],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
    ) -> Result<(), Diverged> {
        self.track_snapshots();
        let mut buf = core::mem::take(&mut self.scratch);
        let r = self.replay_in(recs, payloads, log, sink, &mut buf);
        buf.clear();
        self.scratch = buf;
        r?;
        if log.finished() {
            Ok(())
        } else {
            Err(Diverged {
                index: recs.len(),
                why: Why::Response,
            })
        }
    }

    /// Replays one block's 07 inputs (07 §7.1): `lanes` holds every lane's records, each lane in
    /// O-order (other lanes' records may sit between them, as in a decoded block), `routes` the
    /// block's route records (07 §3.6, any order: each joins the lane call of the packet that
    /// holds its `(lane, lane_seq)`, and must equal the route record that call emits), and
    /// `steps` the merged steps in StepId order. The two are merged by `REP_MERGE`. Steps
    /// compare only what 07 carries (kind, source, `CROSS`, cut, checked by `Bbo::replay_step`);
    /// packet records compare byte for byte; responses compare against `log`. A route record
    /// no packet of the inputs holds is [`Why::BadRecord`] at [`WireAt::End`].
    ///
    /// Blocks are replayed by calling this once per block, in height order, on the same engine.
    /// A lane record not yet due at the block's last step is carried, with its route records,
    /// into the next call
    /// ([`Engine::carried`]), ahead of that call's `lanes` (07 §7.1 `REP_MERGE` item 3). A response
    /// log spans blocks, so the caller checks [`Responses::finished`] after its last block.
    pub fn replay_wire<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        lanes: &[PacketRecord],
        routes: &[RouteRecord],
        steps: &[WireStep<'_>],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
    ) -> Result<(), WireDiverged> {
        self.track_snapshots();
        let mut buf = core::mem::take(&mut self.scratch);
        let carry = core::mem::take(&mut self.carry);
        let mut next = core::mem::take(&mut self.carry_next);
        let carry_r = core::mem::take(&mut self.carry_routes);
        let mut next_r = core::mem::take(&mut self.carry_routes_next);
        next.clear();
        next_r.clear();
        // Reserved on the first call only; a no-op once the buffers have the room.
        next.reserve(CARRY_CAP);
        next_r.reserve(CARRY_CAP);
        let recs = Recs {
            a: &carry,
            b: lanes,
            ra: &carry_r,
            rb: routes,
        };
        let r = self.wire_in(
            recs,
            steps,
            payloads,
            log,
            sink,
            &mut buf,
            (&mut next, &mut next_r),
        );
        buf.clear();
        self.scratch = buf;
        // On success `next` is the new carry; on an error replay stops anyway.
        self.carry = next;
        self.carry_next = carry;
        self.carry_routes = next_r;
        self.carry_routes_next = carry_r;
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn wire_in<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        lanes: Recs<'_>,
        steps: &[WireStep<'_>],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
        buf: &mut Vec<PacketRecord>,
        (carry, carry_r): (&mut Vec<PacketRecord>, &mut Vec<RouteRecord>),
    ) -> Result<(), WireDiverged> {
        let n = self.lanes.len();
        if (0..lanes.len()).any(|i| lanes.get(i).is_some_and(|r| usize::from(r.lane.0) >= n)) {
            return Err(WireDiverged {
                at: WireAt::End,
                why: Why::BadRecord,
            });
        }
        // cur[l]: index of lane l's next record.
        let mut cur = [0usize; MAX_LANES];
        let (lo, hi) = self.tick_range().ok_or(WireDiverged {
            at: WireAt::End,
            why: Why::BadStep,
        })?;
        for w in steps {
            self.wire_lanes(lanes, w.step, &mut cur, payloads, log, sink, buf)?;
            let at = |why| WireDiverged {
                at: WireAt::Step(w.step),
                why,
            };
            // REP_MERGE: every op the cut covers is replayed (else REP_E_ORDER, 07 §7.1).
            let covered = (0..n).all(|l| {
                let lane = self.lanes.get(l).map_or(LaneSeq(0), |x| x.applied());
                w.cut.get(l).is_some_and(|c| *c <= lane)
            });
            if w.cut.len() != n || w.cut.len() > MAX_LANES {
                return Err(at(Why::BadStep));
            }
            if !covered {
                return Err(at(Why::Order));
            }
            // The live control role queued the command before this step (05 §8.8); replay
            // queues the one the step's payload names.
            if w.kind == StepKind::Control {
                let c = control_of_payload(w.payload).ok_or(at(Why::BadStep))?;
                if !self.command(&c) {
                    return Err(at(Why::BadStep));
                }
            }
            let mut cut: Cut = [LaneSeq(0); MAX_LANES];
            for (d, c) in cut.iter_mut().zip(w.cut) {
                *d = *c;
            }
            let band = if w.kind == StepKind::Rescan {
                match w.payload {
                    [] => (lo, hi),
                    [a, b, c, d, e, f, g, h] => (
                        Tick(u32::from_le_bytes([*a, *b, *c, *d])),
                        Tick(u32::from_le_bytes([*e, *f, *g, *h])),
                    ),
                    _ => return Err(at(Why::BadStep)),
                }
            } else {
                (Tick(0), Tick(0))
            };
            let rs = ReplayStep {
                kind: w.kind,
                src: w.src,
                cross: w.cross,
                // 07 has no CONT bit: a pending continuation must be the next step (07 §7.1).
                cont: self.bbo.continuing(),
                band,
                cut,
            };
            let mut tee = Tee::new(sink, log, buf);
            self.step_call(&rs, &mut tee).map_err(at)?;
            if tee.bad_resp {
                return Err(at(Why::Response));
            }
            if !tee
                .step
                .as_ref()
                .is_some_and(|g| matches!(g, OwnedRec::Step(e, _) if e.step == w.step))
            {
                return Err(at(Why::Mismatch));
            }
        }
        let last = steps
            .last()
            .map_or(self.bbo.next_step().0.saturating_sub(1), |w| w.step.0);
        self.wire_lanes(
            lanes,
            StepId(last.saturating_add(1)),
            &mut cur,
            payloads,
            log,
            sink,
            buf,
        )?;
        // Item 3: what is left (not yet due) carries to the next block, per lane in
        // O-order.
        for i in 0..lanes.len() {
            let Some(r) = lanes.get(i) else { continue };
            if i >= cur
                .get(usize::from(r.lane.0))
                .copied()
                .unwrap_or(usize::MAX)
            {
                if carry.len() >= CARRY_CAP {
                    return Err(WireDiverged {
                        at: WireAt::Lane(i),
                        why: Why::Order,
                    });
                }
                carry.push(*r);
            }
        }
        // A route record belongs to a packet of its lane in these inputs (07 §3.6): replayed
        // (and compared in that lane call) or carried with it. Its owner is the last packet
        // whose range holds it, as in the lane call's rule: an earlier one (a `SHED` record
        // before its resend, a heartbeat-only packet) shares the range but took no op there.
        for x in lanes.routes() {
            let lane_cur = cur.get(usize::from(x.lane.0)).copied().unwrap_or(0);
            let Some(i) = (0..lanes.len())
                .rev()
                .find(|&i| lanes.get(i).is_some_and(|p| in_packet(p, &x)))
            else {
                return Err(WireDiverged {
                    at: WireAt::End,
                    why: Why::BadRecord,
                });
            };
            if i >= lane_cur {
                if carry_r.len() >= CARRY_CAP {
                    return Err(WireDiverged {
                        at: WireAt::End,
                        why: Why::Order,
                    });
                }
                carry_r.push(x);
            }
        }
        Ok(())
    }

    /// `REP_MERGE` item 2: every lane, in lane id order, replays its records due before step `s`.
    #[allow(clippy::too_many_arguments)]
    fn wire_lanes<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        lanes: Recs<'_>,
        s: StepId,
        cur: &mut [usize; MAX_LANES],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
        buf: &mut Vec<PacketRecord>,
    ) -> Result<(), WireDiverged> {
        for l in 0..self.lanes.len() {
            let lane = crate::engine::lane_id(l);
            loop {
                let from = cur.get(l).copied().unwrap_or(0);
                let (i, c) = match next_call(lanes, lane, from) {
                    None => {
                        // Nothing left: later passes skip this lane in O(1).
                        if let Some(x) = cur.get_mut(l) {
                            *x = lanes.len();
                        }
                        break;
                    }
                    Some((_, Err(j))) => {
                        return Err(WireDiverged {
                            at: WireAt::Lane(j),
                            why: Why::BadRecord,
                        });
                    }
                    Some((i, Ok(c))) => (i, c),
                };
                // Park the cursor on the found record so the next pass starts there.
                if let Some(x) = cur.get_mut(l) {
                    *x = i;
                }
                // Due once its step's fills are in, and once the replayed BBO has published the
                // snapshot it was classified against (its `snap_lag`, 07 §7.1).
                // A version the ring already evicted is not waited for: `lane_call` rejects it
                // with `Why::NoSnapshot`.
                if c.f >= s || self.snap_want(l, &c.rec).is_some_and(|v| v > self.snap_now) {
                    break;
                }
                let at = |why| WireDiverged {
                    at: WireAt::Lane(i),
                    why,
                };
                let mut tee = Tee::new(sink, log, buf);
                let mids = c.mids.get(..c.n_mid).unwrap_or(&[]);
                // A route record belongs to this packet only if the lane's next packet starts
                // above it: a session-only packet (heartbeat) counts its messages but takes no
                // LaneSeq, so its range overlaps the next packet's.
                let next_first = (c.end..lanes.len())
                    .filter_map(|j| lanes.get(j))
                    .find(|p| p.lane == c.rec.lane && !is_advance(p))
                    .map(|p| p.first_lane_seq.0);
                let owns = |x: &RouteRecord| {
                    in_packet(&c.rec, x) && next_first.is_none_or(|f| x.lane_seq.0 < f)
                };
                let rejected = lanes.routes().filter(|x| owns(x));
                self.lane_call(l, &c.rec, mids, rejected, payloads, &mut tee)
                    .map_err(at)?;
                if tee.bad_resp {
                    return Err(at(Why::Response));
                }
                // The call's route records must be the packet's input route records, matched by
                // op in any order (07 §3.6): none missing, extra, repeated or conflicting.
                let want_r = || lanes.routes().filter(|x| owns(x));
                let got = tee.routes();
                let same_r = want_r().count() == got.len()
                    && want_r().all(|x| got.contains(&x))
                    && got.iter().all(|g| want_r().any(|x| x == *g));
                if !same_r {
                    return Err(at(Why::Mismatch));
                }
                let want = core::iter::once(&c.rec).chain(mids.iter());
                if buf.len() != c.n_mid.saturating_add(1)
                    || !want.zip(buf.iter()).all(|(w, g)| w == g)
                {
                    return Err(at(Why::Mismatch));
                }
                if let Some(x) = cur.get_mut(l) {
                    *x = c.end;
                }
            }
        }
        Ok(())
    }

    /// The snapshot version packet record `rec` of lane `l` names, `snap_base + snap_lag`;
    /// `None` for an Advance or `SHED` record, which classifies nothing.
    fn snap_want(&self, l: usize, rec: &PacketRecord) -> Option<u64> {
        let lane = self.lanes.get(l)?;
        if is_advance(rec) || rec.flags & PacketFlags::SHED != 0 {
            return None;
        }
        Some(lane.snap_base().saturating_add(u64::from(rec.snap_lag)))
    }

    /// The arena's tick range: a `Rescan` with no band covers all of it (05 §10).
    fn tick_range(&self) -> Option<(Tick, Tick)> {
        let c = self.views.first()?.config();
        Some((c.tick_min, c.tick_max))
    }

    /// One replayed step: `replay_step` until it publishes.
    fn step_call<S: Sink>(&mut self, rs: &ReplayStep, sink: &mut S) -> Result<(), Why> {
        let got = self
            .drive(sink, |bbo, vis, ports, book| {
                bbo.replay_step(vis, ports, book, rs)
            })
            .map_err(|x| match x {
                StepErr::Fault(f) => Why::Fault(f),
                StepErr::Diverge(v) => Why::Step(v),
            })?;
        if got.is_none() {
            return Err(Why::NoStep);
        }
        Ok(())
    }

    /// One replayed lane call: a non-`MID` Advance record is the lane's boundary at its logged
    /// `(f, C_f[l])`; a packet goes
    /// through `Lane::replay_packet` with `mids` as its boundaries and the routes its route
    /// records `routes` give.
    fn lane_call<P: Payloads, S: Sink>(
        &mut self,
        l: usize,
        rec: &PacketRecord,
        mids: &[PacketRecord],
        routes_in: impl Iterator<Item = RouteRecord>,
        payloads: &P,
        sink: &mut S,
    ) -> Result<(), Why> {
        if is_advance(rec) {
            // A boundary at the logged `(f, C_f[l])`, like a `MID` record (05 §6.2, F3a). One
            // that is not after the lane's `fills_applied` logs nothing: the compare reports it.
            let f = rec.fills_applied;
            let at = self.cut_at(f, l).ok_or(Why::StepTooOld)?;
            return self.replay_advance(l, at, sink).map_err(Why::Fault);
        }
        if rec.flags & PacketFlags::SHED != 0 {
            // A shed packet's responses and record come from the record alone (05 §6.8,
            // §18 Q17): no payload is read, and the data tier need not hold it.
            return self
                .replay_shed(l, rec, sink)
                .map(|_| ())
                .map_err(Why::Fault);
        }
        let mut ms = [Mid {
            pass: 0,
            next: LaneSeq(0),
            at: LaneCutEntry::default(),
        }; MAX_MIDS];
        for (d, m) in ms.iter_mut().zip(mids) {
            let at = self.cut_at(m.fills_applied, l).ok_or(Why::StepTooOld)?;
            *d = Mid {
                pass: if m.flags & PacketFlags::PASS2 != 0 {
                    2
                } else {
                    1
                },
                next: m.first_lane_seq,
                at,
            };
        }
        // The snapshot the live lane classified this packet against (05 §6.5, 07 §7.1).
        if let Some(v) = self.snap_want(l, rec) {
            let snap = self.snap_of(v).ok_or(Why::NoSnapshot)?;
            if let Some(x) = self.lanes.get_mut(l) {
                x.restore_snapshot(snap);
            }
        }
        let mut routes = [(LaneSeq(0), Route::Join); MAX_ROUTES];
        let n_route = routes_of(routes_in, rec, &mut routes);
        let bytes = payloads.get(rec).ok_or(Why::NoPayload)?;
        let rx = RxIn {
            bytes,
            rx_ts: rec.rx_ts,
            pkt_hash: rec.pkt_hash,
        };
        let ms = ms.get(..mids.len()).unwrap_or(&[]);
        let routes = routes.get(..n_route).unwrap_or(&[]);
        self.replay_ingest(l, rx, &NeverLate, ms, routes, sink)
            .map(|_| ())
            .map_err(Why::Fault)
    }

    fn replay_in<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        recs: &[OwnedRec],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
        buf: &mut Vec<PacketRecord>,
    ) -> Result<(), Diverged> {
        let mut i = 0usize;
        while let Some(r) = recs.get(i) {
            let at = |why| Diverged { index: i, why };
            let mut tee = Tee::new(sink, log, buf);
            let used = match r {
                OwnedRec::Step(e, d) => {
                    let deltas = d.get(..usize::from(e.n_delta)).unwrap_or(&[]);
                    let rs = ReplayStep::from_log(&self.cut, e, deltas).ok_or(at(Why::BadStep))?;
                    self.step_call(&rs, &mut tee).map_err(at)?;
                    if tee.bad_resp {
                        return Err(at(Why::Response));
                    }
                    if !tee.step.as_ref().is_some_and(|g| same_step(g, r)) {
                        return Err(at(Why::Mismatch));
                    }
                    1
                }
                OwnedRec::Packet(_) | OwnedRec::Route(_) | OwnedRec::Take(_) => {
                    let lane = match r {
                        OwnedRec::Packet(p) => p.lane,
                        OwnedRec::Route(x) => x.lane,
                        OwnedRec::Take(t) => t.lane,
                        OwnedRec::Step(..) => LaneId(0),
                    };
                    let l = usize::from(lane.0);
                    let run = recs.get(i..).unwrap_or(&[]);
                    // A packet's lane call: the lane's MID and route records right before it in
                    // the run and its MID records right after it, up to the lane's next other
                    // record (05 §6.2; the lane writes route records in pass 1).
                    let lane_run = run.iter().map_while(|x| match x {
                        OwnedRec::Packet(q) if q.lane == lane => Some(Some(q)),
                        OwnedRec::Route(q) if q.lane == lane => Some(None),
                        OwnedRec::Take(q) if q.lane == lane => Some(None),
                        _ => None,
                    });
                    let (k, pk) = match r {
                        OwnedRec::Packet(p) if is_advance(p) && !is_mid(p) => (0, p),
                        _ => lane_run
                            .enumerate()
                            .find_map(|(k, q)| q.filter(|q| !is_advance(q)).map(|q| (k, q)))
                            // A take whose packet's group does not follow it is misplaced
                            // (05 §6.9, #135 ruling); a route with no packet is malformed.
                            .ok_or(at(if matches!(r, OwnedRec::Take(_)) {
                                Why::Mismatch
                            } else {
                                Why::BadRecord
                            }))?,
                    };
                    let before = run.get(..k).unwrap_or(&[]);
                    // The lane's records from `i` on, through its MID and route records after
                    // the packet: the call's input route records sit anywhere in it.
                    let span = run.iter().take_while(|x| match x {
                        OwnedRec::Packet(q) => q.lane == lane && (is_mid(q) || !is_advance(q)),
                        OwnedRec::Route(q) => q.lane == lane,
                        OwnedRec::Take(q) => q.lane == lane,
                        OwnedRec::Step(..) => false,
                    });
                    let mut mids = [NO_REC; MAX_MIDS];
                    let mut n_mid = 0usize;
                    if !is_advance(pk) {
                        let after = run
                            .iter()
                            .skip(k.saturating_add(1))
                            .map_while(|x| match x {
                                OwnedRec::Packet(q) if q.lane == lane && is_mid(q) => Some(Some(q)),
                                OwnedRec::Route(q) if q.lane == lane => Some(None),
                                OwnedRec::Take(q) if q.lane == lane => Some(None),
                                _ => None,
                            })
                            .flatten();
                        for m in before
                            .iter()
                            .filter_map(packet_of)
                            .filter(|q| is_mid(q))
                            .chain(after)
                        {
                            *mids.get_mut(n_mid).ok_or(at(Why::BadRecord))? = *m;
                            n_mid = n_mid.saturating_add(1);
                        }
                    }
                    let mids = mids.get(..n_mid).unwrap_or(&[]);
                    let rejected = span.filter_map(|x| match x {
                        OwnedRec::Route(q) => Some(*q),
                        _ => None,
                    });
                    self.lane_call(l, pk, mids, rejected, payloads, &mut tee)
                        .map_err(at)?;
                    if tee.bad_resp {
                        return Err(at(Why::Response));
                    }
                    // The call's output, packets, route and `AcctTake` records in output order,
                    // must be the next records of the input: a take sits right before the
                    // record it covers, and its `ver` is the pool's next (05 §6.9).
                    let (n_pk, n_rt, n_tk) = (tee.pkts.len(), tee.n_routes, tee.n_takes);
                    let used = n_pk.saturating_add(n_rt).saturating_add(n_tk);
                    let want = recs.get(i..i.saturating_add(used)).unwrap_or(&[]);
                    let mut gp = tee.pkts.iter();
                    let mut gr = tee.routes().iter();
                    let mut gt = tee.takes.iter().flatten();
                    let mut kinds = tee.order().iter();
                    let same = n_pk > 0
                        && want.len() == used
                        && !tee.order_full
                        && tee.order().len() == used
                        && want.iter().all(|w| match w {
                            OwnedRec::Packet(p) => {
                                kinds.next() == Some(&Kind::Packet) && gp.next() == Some(p)
                            }
                            OwnedRec::Route(x) => {
                                kinds.next() == Some(&Kind::Route) && gr.next() == Some(x)
                            }
                            OwnedRec::Take(t) => {
                                kinds.next() == Some(&Kind::Take) && gt.next() == Some(t)
                            }
                            OwnedRec::Step(..) => false,
                        });
                    if !same {
                        return Err(at(Why::Mismatch));
                    }
                    used
                }
            };
            i = i.saturating_add(used);
        }
        Ok(())
    }
}
