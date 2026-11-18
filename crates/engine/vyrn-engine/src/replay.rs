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
//!   packet, fetched from [`Payloads`], through `vyrn_lane::Lane::replay_packet` with a late
//!   clock iff `SHED`, its `MID` records as `Mid` boundaries at `(f, C_f[l])` (05 §6.2, §10 row
//!   3), and its ops' routes taken from the later `StepRecord`s that name them (their
//!   `STEP_CROSS` bit, §10 row 7) and from its `Route` records (ops the lane rejected itself).
//!   A `Route` record is part of its packet's lane call and is compared like the packet's.

use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{
    Cut, CutDelta, Diverge, MAX_LANES, Record, ReplayStep, STEP_CONT, STEP_CROSS, StepEntry,
    TxEntry,
};
use vyrn_cut::LaneCutEntry;
use vyrn_cut::Visibility;
use vyrn_lane::{Mid, RespPkt, RxIn};
use vyrn_risk::Route;
use vyrn_types::{
    LaneId, LaneSeq, PacketFlags, PacketRecord, RouteRecord, StepFlags, StepId, StepKind,
    StepRecord, Tick,
};

use crate::engine::{Engine, Fault, Rec, Sink, StepErr};

/// One order-stream element, owned (for logs and journals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Inline deltas, not a `Box`: building one never allocates (`INV-NOALLOC`).
#[allow(clippy::large_enum_variant)]
pub enum OwnedRec {
    Packet(PacketRecord),
    Step(StepEntry, [CutDelta; MAX_LANES]),
    Route(RouteRecord),
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
    /// The borrowed form; a step's deltas are its first `n_delta`.
    pub fn as_rec(&self) -> Rec<'_> {
        match self {
            Self::Packet(p) => Rec::Packet(*p),
            Self::Route(x) => Rec::Route(*x),
            Self::Step(e, d) => Rec::Step(*e, d.get(..usize::from(e.n_delta)).unwrap_or(&[])),
        }
    }
}

/// Packet bytes by record (07's data tier keys them by `pkt_hash`; a `SHED` record has
/// `pkt_hash` 0, so the store may key on the whole record: spec gap, PR body).
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
            step: None,
            bad_resp: false,
        }
    }
    fn routes(&self) -> &[RouteRecord] {
        self.routes.get(..self.n_routes).unwrap_or(&[])
    }
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
            }
            Rec::Route(x) => {
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
    fn take(&mut self, t: &vyrn_types::AcctTake) {
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
        OwnedRec::Packet(_) | OwnedRec::Route(_) => None,
    };
    let (x, y) = (strip(a), strip(b));
    x.is_some() && x == y
}

fn packet_of(r: &OwnedRec) -> Option<&PacketRecord> {
    match r {
        OwnedRec::Packet(p) => Some(p),
        OwnedRec::Step(..) | OwnedRec::Route(_) => None,
    }
}

/// Boundaries one packet can hold: before pass 1 and pass 2 of each of its 10 ops.
const MAX_MIDS: usize = 20;
/// Forwarded ops one packet can hold.
const MAX_ROUTES: usize = 10;

/// The routes of packet `pk`'s classified ops (05 §10 row 7, 07 §3.6): each op a later step
/// names as its source, with that step's `CROSS` bit, and each op of `rejected` (the packet's
/// route records: ops the lane classified and then rejected itself). Every other op is `Join`.
/// A lane's sources come in `LaneSeq` order (its `FwdRing` is FIFO), so the scan of `srcs`
/// stops at the first later one.
fn routes_of(
    srcs: impl Iterator<Item = (LaneId, LaneSeq, bool)>,
    rejected: impl Iterator<Item = RouteRecord>,
    pk: &PacketRecord,
    out: &mut [(LaneSeq, Route); MAX_ROUTES],
) -> usize {
    let lo = pk.first_lane_seq.0;
    let hi = lo.saturating_add(u64::from(pk.count));
    let route = |cross: bool| if cross { Route::Cross } else { Route::Improve };
    let mut n = 0usize;
    let mut put = |seq: LaneSeq, r: Route, n: &mut usize| {
        if out.iter().take(*n).any(|(s, _)| *s == seq) {
            return;
        }
        if let Some(d) = out.get_mut(*n) {
            *d = (seq, r);
            *n = n.saturating_add(1);
        }
    };
    for x in rejected.filter(|x| in_packet(pk, x)) {
        put(x.lane_seq, route(x.cross), &mut n);
    }
    for (lane, seq, cross) in srcs {
        if lane != pk.lane {
            continue;
        }
        if seq.0 >= hi {
            break;
        }
        if seq.0 >= lo {
            put(seq, route(cross), &mut n);
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

/// `routes_of` sources over journal records (`CONT` steps name an op already routed).
fn journal_sources(recs: &[OwnedRec]) -> impl Iterator<Item = (LaneId, LaneSeq, bool)> + '_ {
    recs.iter().filter_map(|r| match r {
        OwnedRec::Step(e, _) if e.src_lane_seq.0 != 0 && e.flags & STEP_CONT == 0 => {
            Some((e.src_lane, e.src_lane_seq, e.flags & STEP_CROSS != 0))
        }
        _ => None,
    })
}

/// `routes_of` sources over 07 steps. A `CONT` step repeats its source, which the dedup drops.
fn wire_sources<'a>(
    steps: &'a [WireStep<'a>],
) -> impl Iterator<Item = (LaneId, LaneSeq, bool)> + 'a {
    steps
        .iter()
        .filter_map(|w| w.src.map(|(l, q)| (l, q, w.cross)))
}

fn is_advance(p: &PacketRecord) -> bool {
    p.flags & PacketFlags::ADVANCE != 0
}

fn is_mid(p: &PacketRecord) -> bool {
    p.flags & PacketFlags::MID != 0
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
    /// ticks (07 §3.8, §7.1).
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

/// A packet whose ops are not all decided by this block (07 §7.1 item 3): one of them is above
/// the block's last cut, so a step of a later block may still name it as a source. It is
/// carried unless a step left in this block names one of its ops, which must be replayed now.
fn undecided(c: &Call, final_cut: LaneSeq, later: &[WireStep<'_>]) -> bool {
    let r = &c.rec;
    if is_advance(r) || r.count == 0 || r.flags & PacketFlags::SHED != 0 {
        return false;
    }
    let lo = r.first_lane_seq.0;
    let hi = lo.saturating_add(u64::from(r.count));
    let named = later
        .iter()
        .filter_map(|w| w.src)
        .any(|(l, q)| l == r.lane && lo <= q.0 && q.0 < hi);
    hi.saturating_sub(1) > final_cut.0 && !named
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
    /// A lane record that is not settled by the block (not yet due, or a packet with an op above
    /// the block's last cut that no step of the block names) is carried into the next call
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
        let mut buf = core::mem::take(&mut self.scratch);
        let carry = core::mem::take(&mut self.carry);
        let mut next = core::mem::take(&mut self.carry_next);
        let carry_r = core::mem::take(&mut self.carry_routes);
        let mut next_r = core::mem::take(&mut self.carry_routes_next);
        next.clear();
        next_r.clear();
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
        // The block's last cut decides which ops are settled in this block (item 3).
        let mut final_cut = self.cut;
        if let Some(w) = steps.last() {
            for (d, c) in final_cut.iter_mut().zip(w.cut) {
                *d = *c;
            }
        }
        // cur[l]: index of lane l's next record; held[l]: lane l carries from cur[l] on.
        let mut cur = [0usize; MAX_LANES];
        let mut held = [false; MAX_LANES];
        let (lo, hi) = self.tick_range().ok_or(WireDiverged {
            at: WireAt::End,
            why: Why::BadStep,
        })?;
        for (k, w) in steps.iter().enumerate() {
            self.wire_lanes(
                lanes,
                steps.get(k..).unwrap_or(&[]),
                w.step,
                &final_cut,
                &mut cur,
                &mut held,
                payloads,
                log,
                sink,
                buf,
            )?;
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
            &[],
            StepId(last.saturating_add(1)),
            &final_cut,
            &mut cur,
            &mut held,
            payloads,
            log,
            sink,
            buf,
        )?;
        // Item 3: what is left (not yet due, or undecided) carries to the next block, per lane in
        // O-order.
        for i in 0..lanes.len() {
            let Some(r) = lanes.get(i) else { continue };
            if i >= cur
                .get(usize::from(r.lane.0))
                .copied()
                .unwrap_or(usize::MAX)
            {
                if carry.len() >= carry.capacity() {
                    return Err(WireDiverged {
                        at: WireAt::Lane(i),
                        why: Why::Order,
                    });
                }
                carry.push(*r);
            }
        }
        // A route record belongs to a packet of its lane in these inputs (07 §3.6): replayed
        // (and compared in that lane call) or carried with it.
        for x in lanes.routes() {
            let lane_cur = cur.get(usize::from(x.lane.0)).copied().unwrap_or(0);
            let Some(i) =
                (0..lanes.len()).find(|&i| lanes.get(i).is_some_and(|p| in_packet(p, &x)))
            else {
                return Err(WireDiverged {
                    at: WireAt::End,
                    why: Why::BadRecord,
                });
            };
            if i >= lane_cur {
                if carry_r.len() >= carry_r.capacity() {
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
    /// `later` is the steps from `s` on, for the forwarded-op routes.
    #[allow(clippy::too_many_arguments)]
    fn wire_lanes<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        lanes: Recs<'_>,
        later: &[WireStep<'_>],
        s: StepId,
        final_cut: &Cut,
        cur: &mut [usize; MAX_LANES],
        held: &mut [bool; MAX_LANES],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
        buf: &mut Vec<PacketRecord>,
    ) -> Result<(), WireDiverged> {
        for l in 0..self.lanes.len() {
            if held.get(l).copied().unwrap_or(true) {
                continue;
            }
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
                if c.f >= s {
                    break;
                }
                if undecided(&c, final_cut.get(l).copied().unwrap_or(LaneSeq(0)), later) {
                    if let Some(h) = held.get_mut(l) {
                        *h = true;
                    }
                    break;
                }
                let at = |why| WireDiverged {
                    at: WireAt::Lane(i),
                    why,
                };
                let mut tee = Tee::new(sink, log, buf);
                let mids = c.mids.get(..c.n_mid).unwrap_or(&[]);
                let rejected = lanes.routes().filter(|x| in_packet(&c.rec, x));
                self.lane_call(
                    l,
                    &c.rec,
                    mids,
                    wire_sources(later),
                    rejected,
                    payloads,
                    &mut tee,
                )
                .map_err(at)?;
                if tee.bad_resp {
                    return Err(at(Why::Response));
                }
                // The call's route records must be the packet's input route records, in order.
                let mut want_r = lanes.routes().filter(|x| in_packet(&c.rec, x));
                let same_r = tee.routes().iter().all(|g| want_r.next() == Some(*g));
                if !same_r || want_r.next().is_some() {
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
    /// through `Lane::replay_packet` with `mids` as its boundaries and the routes that `srcs`
    /// (later steps) and `rejected` (its route records) give.
    #[allow(clippy::too_many_arguments)]
    fn lane_call<P: Payloads, S: Sink>(
        &mut self,
        l: usize,
        rec: &PacketRecord,
        mids: &[PacketRecord],
        srcs: impl Iterator<Item = (LaneId, LaneSeq, bool)>,
        rejected: impl Iterator<Item = RouteRecord>,
        payloads: &P,
        sink: &mut S,
    ) -> Result<(), Why> {
        if is_advance(rec) {
            // A boundary at the logged `(f, C_f[l])`, like a `MID` record (05 §6.2, F3a). One
            // that is not after the lane's `fills_applied` logs nothing: the compare reports it.
            let f = rec.fills_applied;
            let cut = self.cut_at(f, l).ok_or(Why::StepTooOld)?;
            let at = LaneCutEntry { step: f, cut };
            return self.replay_advance(l, at, sink).map_err(Why::Fault);
        }
        let mut ms = [Mid {
            pass: 0,
            next: LaneSeq(0),
            at: LaneCutEntry::default(),
        }; MAX_MIDS];
        for (d, m) in ms.iter_mut().zip(mids) {
            let cut = self.cut_at(m.fills_applied, l).ok_or(Why::StepTooOld)?;
            *d = Mid {
                pass: if m.flags & PacketFlags::PASS2 != 0 {
                    2
                } else {
                    1
                },
                next: m.first_lane_seq,
                at: LaneCutEntry {
                    step: m.fills_applied,
                    cut,
                },
            };
        }
        let mut routes = [(LaneSeq(0), Route::Join); MAX_ROUTES];
        let n_route = routes_of(srcs, rejected, rec, &mut routes);
        let bytes = payloads.get(rec).ok_or(Why::NoPayload)?;
        let rx = RxIn {
            bytes,
            rx_ts: rec.rx_ts,
            pkt_hash: rec.pkt_hash,
        };
        let ms = ms.get(..mids.len()).unwrap_or(&[]);
        let routes = routes.get(..n_route).unwrap_or(&[]);
        let res = if rec.flags & PacketFlags::SHED != 0 {
            self.replay_ingest(l, rx, &FixedClock(u64::MAX), ms, routes, sink)
        } else {
            self.replay_ingest(l, rx, &NeverLate, ms, routes, sink)
        };
        res.map(|_| ()).map_err(Why::Fault)
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
                OwnedRec::Packet(_) | OwnedRec::Route(_) => {
                    let lane = match r {
                        OwnedRec::Packet(p) => p.lane,
                        OwnedRec::Route(x) => x.lane,
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
                        _ => None,
                    });
                    let (k, pk) = match r {
                        OwnedRec::Packet(p) if is_advance(p) && !is_mid(p) => (0, p),
                        _ => lane_run
                            .enumerate()
                            .find_map(|(k, q)| q.filter(|q| !is_advance(q)).map(|q| (k, q)))
                            .ok_or(at(Why::BadRecord))?,
                    };
                    let before = run.get(..k).unwrap_or(&[]);
                    // The lane's records from `i` on, through its MID and route records after
                    // the packet: the call's input route records sit anywhere in it.
                    let span = run.iter().take_while(|x| match x {
                        OwnedRec::Packet(q) => q.lane == lane && (is_mid(q) || !is_advance(q)),
                        OwnedRec::Route(q) => q.lane == lane,
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
                    self.lane_call(
                        l,
                        pk,
                        mids,
                        journal_sources(run),
                        rejected,
                        payloads,
                        &mut tee,
                    )
                    .map_err(at)?;
                    if tee.bad_resp {
                        return Err(at(Why::Response));
                    }
                    // The call's output, packets and route records in output order, must be
                    // the next records of the input.
                    let (n_pk, n_rt) = (tee.pkts.len(), tee.n_routes);
                    let used = n_pk.saturating_add(n_rt);
                    let want = recs.get(i..i.saturating_add(used)).unwrap_or(&[]);
                    let mut gp = tee.pkts.iter();
                    let mut gr = tee.routes().iter();
                    let same = n_pk > 0
                        && want.len() == used
                        && want.iter().all(|w| match w {
                            OwnedRec::Packet(p) => gp.next() == Some(p),
                            OwnedRec::Route(x) => gr.next() == Some(x),
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
