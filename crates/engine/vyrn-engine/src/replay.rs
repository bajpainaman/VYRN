//! Replay mode (05 §10, 01 §11.6): the same lanes and BBO core, driven by the order stream.
//!
//! Each record is replayed by the call that produced it live, and the call's output records
//! must equal the input records byte for byte:
//!
//! - a `Rec::Step`: [`vyrn_bbo::Bbo::replay_step`] with the step's cut (`C_{s−1}` plus its
//!   deltas), source, kind (incl. `Shed`, `CONT`) and `Rescan` band from the record (05 §10 rows
//!   4–5). No clock is read; the cut cores still publish, because `replay_step` reads the
//!   half-cuts for `Pend` retirement;
//! - a non-`MID` Advance record of lane `l`: lane `l`'s idle poll, which reads the `LaneCut`
//!   that the replayed steps wrote;
//! - a packet record (with the `MID` Advance records the lane wrote while processing it): the
//!   packet, fetched from [`Payloads`], through `vyrn_lane::Lane::replay_packet` with a late
//!   clock iff `SHED`, its `MID` records as `Mid` boundaries at `(f, C_f[l])` (05 §6.2, §10 row
//!   3), and its forwarded ops taken from the later `StepRecord`s that name them (§10 row 7).

use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{
    Cut, CutDelta, Diverge, MAX_LANES, Record, ReplayStep, STEP_CONT, StepEntry, TxEntry,
};
use vyrn_cut::LaneCutEntry;
use vyrn_cut::Visibility;
use vyrn_lane::{Mid, RespPkt, RxIn};
use vyrn_risk::Route;
use vyrn_types::{LaneId, LaneSeq, PacketFlags, PacketRecord, StepId, StepKind, StepRecord, Tick};

use crate::engine::{Engine, Fault, Rec, Sink, StepErr};

/// One order-stream element, owned (for logs and journals).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Inline deltas, not a `Box`: building one never allocates (`INV-NOALLOC`).
#[allow(clippy::large_enum_variant)]
pub enum OwnedRec {
    Packet(PacketRecord),
    Step(StepEntry, [CutDelta; MAX_LANES]),
}

impl OwnedRec {
    pub fn of(r: &Rec<'_>) -> Self {
        match r {
            Rec::Packet(p) => Self::Packet(*p),
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
    step: Option<OwnedRec>,
    bad_resp: bool,
}

impl<S: Sink, R: Responses> Sink for Tee<'_, S, R> {
    fn record(&mut self, r: &Rec<'_>) {
        match r {
            Rec::Packet(p) => {
                if self.pkts.len() < self.pkts.capacity() {
                    self.pkts.push(*p);
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
        OwnedRec::Packet(_) => None,
    };
    let (x, y) = (strip(a), strip(b));
    x.is_some() && x == y
}

fn packet_of(r: &OwnedRec) -> Option<&PacketRecord> {
    match r {
        OwnedRec::Packet(p) => Some(p),
        OwnedRec::Step(..) => None,
    }
}

/// Boundaries one packet can hold: before pass 1 and pass 2 of each of its 10 ops.
const MAX_MIDS: usize = 20;
/// Forwarded ops one packet can hold.
const MAX_ROUTES: usize = 10;

/// The forwarded ops of packet `pk` and their routes (05 §10: op `(l, q)` is forwarded iff a
/// `StepRecord` has `src = (l, q)`), from the steps after it in `recs`. A lane's sources come
/// in `LaneSeq` order (its `FwdRing` is FIFO), so the scan stops at the first later one.
///
/// TEMPORARY (lane follow-up 18): the route comes from [`route_of_kind`] until the log carries
/// the route the live lane classified (a `FwdEntry` route bit copied into a `StepRecord` flag,
/// in progress). Switching is a change to that one function.
/// TEMPORARY: the route of a step's source, from the step's kind (`Improve` → `Improve`,
/// `Cross` and `Shed` → `Cross`); `None` for kinds that have no forwarded source. A `Cross`
/// that STP stops before any fill is logged as `Improve`, and a shed `Improve` as `Shed`, so
/// both replay with the other route's risk bucket: a known divergence (PR gap G7).
fn route_of_kind(kind: StepKind) -> Option<Route> {
    match kind {
        StepKind::Improve => Some(Route::Improve),
        StepKind::Cross | StepKind::Shed => Some(Route::Cross),
        _ => None,
    }
}

/// `routes_of` over journal records (`CONT` steps name an op already routed).
fn journal_sources(recs: &[OwnedRec]) -> impl Iterator<Item = (LaneId, LaneSeq, StepKind)> + '_ {
    recs.iter().filter_map(|r| match r {
        OwnedRec::Step(e, _) if e.src_lane_seq.0 != 0 && e.flags & STEP_CONT == 0 => {
            Some((e.src_lane, e.src_lane_seq, StepKind::from_code(e.kind)?))
        }
        _ => None,
    })
}

/// `routes_of` over 07 steps. A `CONT` step repeats its source, which the dedup below drops.
fn wire_sources<'a>(
    steps: &'a [WireStep<'a>],
) -> impl Iterator<Item = (LaneId, LaneSeq, StepKind)> + 'a {
    steps
        .iter()
        .filter_map(|w| w.src.map(|(l, q)| (l, q, w.kind)))
}

fn routes_of(
    srcs: impl Iterator<Item = (LaneId, LaneSeq, StepKind)>,
    pk: &PacketRecord,
    out: &mut [(LaneSeq, Route); MAX_ROUTES],
) -> usize {
    let lo = pk.first_lane_seq.0;
    let hi = lo.saturating_add(u64::from(pk.count));
    let mut n = 0usize;
    for (lane, seq, kind) in srcs {
        if lane != pk.lane {
            continue;
        }
        let Some(route) = route_of_kind(kind) else {
            continue;
        };
        let q = seq.0;
        if q >= hi {
            break;
        }
        if q < lo || out.iter().take(n).any(|(s, _)| s.0 == q) {
            continue;
        }
        if let Some(d) = out.get_mut(n) {
            *d = (seq, route);
            n = n.saturating_add(1);
        }
    }
    n
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
    /// O-order (other lanes' records may sit between them, as in a decoded block), and `steps`
    /// the merged steps in StepId order. The two are merged by `REP_MERGE`. Steps compare only
    /// what 07 carries (kind, source, cut, checked by `Bbo::replay_step`); packet records compare
    /// byte for byte; responses compare against `log`.
    ///
    /// Blocks are replayed by calling this once per block, in height order, on the same engine.
    /// A lane record that is not settled by the block (not yet due, or a packet with an op above
    /// the block's last cut that no step of the block names) is carried into the next call
    /// ([`Engine::carried`]), ahead of that call's `lanes` (07 §7.1 `REP_MERGE` item 3). A response
    /// log spans blocks, so the caller checks [`Responses::finished`] after its last block.
    pub fn replay_wire<P: Payloads, S: Sink, R: Responses>(
        &mut self,
        lanes: &[PacketRecord],
        steps: &[WireStep<'_>],
        payloads: &P,
        log: &mut R,
        sink: &mut S,
    ) -> Result<(), WireDiverged> {
        let mut buf = core::mem::take(&mut self.scratch);
        let carry = core::mem::take(&mut self.carry);
        let mut next = core::mem::take(&mut self.carry_next);
        next.clear();
        let recs = Recs {
            a: &carry,
            b: lanes,
        };
        let r = self.wire_in(recs, steps, payloads, log, sink, &mut buf, &mut next);
        buf.clear();
        self.scratch = buf;
        // On success `next` is the new carry; on an error replay stops anyway.
        self.carry = next;
        self.carry_next = carry;
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
        carry: &mut Vec<PacketRecord>,
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
                // 07 has no CONT bit: a pending continuation must be the next step (07 §7.1).
                cont: self.bbo.continuing(),
                band,
                cut,
            };
            buf.clear();
            let mut tee = Tee {
                inner: sink,
                log,
                pkts: buf,
                step: None,
                bad_resp: false,
            };
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
                buf.clear();
                let mut tee = Tee {
                    inner: sink,
                    log,
                    pkts: buf,
                    step: None,
                    bad_resp: false,
                };
                let mids = c.mids.get(..c.n_mid).unwrap_or(&[]);
                self.lane_call(l, &c.rec, mids, wire_sources(later), payloads, &mut tee)
                    .map_err(at)?;
                if tee.bad_resp {
                    return Err(at(Why::Response));
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

    /// One replayed lane call: a non-`MID` Advance record is the lane's idle poll; a packet goes
    /// through `Lane::replay_packet` with `mids` as its boundaries and the routes `srcs` give.
    fn lane_call<P: Payloads, S: Sink>(
        &mut self,
        l: usize,
        rec: &PacketRecord,
        mids: &[PacketRecord],
        srcs: impl Iterator<Item = (LaneId, LaneSeq, StepKind)>,
        payloads: &P,
        sink: &mut S,
    ) -> Result<(), Why> {
        if is_advance(rec) {
            return if self.poll_lane(l, sink).map_err(Why::Fault)? {
                Ok(())
            } else {
                Err(Why::BadRecord)
            };
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
        let n_route = routes_of(srcs, rec, &mut routes);
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
            buf.clear();
            let mut tee = Tee {
                inner: sink,
                log,
                pkts: buf,
                step: None,
                bad_resp: false,
            };
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
                OwnedRec::Packet(p) => {
                    let l = usize::from(p.lane.0);
                    let run = recs.get(i..).unwrap_or(&[]);
                    // A packet's MID records: the lane's MID records right before it in the
                    // run and right after it, up to the lane's next other record (05 §6.2).
                    let lane_run = run.iter().map_while(|x| match x {
                        OwnedRec::Packet(q) if q.lane == p.lane => Some(q),
                        _ => None,
                    });
                    let (k, pk) = if is_advance(p) && !is_mid(p) {
                        (0, p)
                    } else {
                        lane_run
                            .enumerate()
                            .find(|(_, q)| !is_advance(q))
                            .ok_or(at(Why::BadRecord))?
                    };
                    let mut mids = [NO_REC; MAX_MIDS];
                    let mut n_mid = 0usize;
                    if !is_advance(pk) {
                        let after = run.iter().skip(k.saturating_add(1)).map_while(|x| match x {
                            OwnedRec::Packet(q) if q.lane == p.lane && is_mid(q) => Some(q),
                            _ => None,
                        });
                        for m in run
                            .iter()
                            .take(k)
                            .filter_map(packet_of)
                            .filter(|q| is_mid(q))
                            .chain(after)
                        {
                            *mids.get_mut(n_mid).ok_or(at(Why::BadRecord))? = *m;
                            n_mid = n_mid.saturating_add(1);
                        }
                    }
                    let mids = mids.get(..n_mid).unwrap_or(&[]);
                    self.lane_call(l, pk, mids, journal_sources(run), payloads, &mut tee)
                        .map_err(at)?;
                    if tee.bad_resp {
                        return Err(at(Why::Response));
                    }
                    tee.pkts.len()
                }
            };
            if let OwnedRec::Packet(_) = r {
                let want = recs.get(i..i.saturating_add(used)).unwrap_or(&[]);
                let same = used > 0
                    && want.len() == used
                    && want
                        .iter()
                        .zip(buf.iter())
                        .all(|(w, g)| *w == OwnedRec::Packet(*g));
                if !same {
                    return Err(at(Why::Mismatch));
                }
            }
            i = i.saturating_add(used);
        }
        Ok(())
    }
}
