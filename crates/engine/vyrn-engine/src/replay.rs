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
use vyrn_bbo::{CutDelta, Diverge, MAX_LANES, ReplayStep, STEP_CONT, StepEntry};
use vyrn_cut::LaneCutEntry;
use vyrn_cut::Visibility;
use vyrn_lane::Mid;
use vyrn_lane::RxIn;
use vyrn_risk::Route;
use vyrn_types::{LaneSeq, PacketFlags, PacketRecord, StepKind};

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
    Fault(Fault),
}

/// Replay stopped at input record `index`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Diverged {
    pub index: usize,
    pub why: Why,
}

/// Collects one call's records and forwards everything to the caller's sink.
struct Tee<'s, S> {
    inner: &'s mut S,
    pkts: &'s mut Vec<PacketRecord>,
    step: Option<OwnedRec>,
}

impl<S: Sink> Sink for Tee<'_, S> {
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
    fn lane_resp(&mut self, lane: vyrn_types::LaneId, p: &vyrn_lane::RespPkt) {
        self.inner.lane_resp(lane, p);
    }
    fn tx(&mut self, h: &vyrn_bbo::TxEntry, recs: &[vyrn_bbo::Record]) {
        self.inner.tx(h, recs);
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
fn route_of_kind(e: &StepEntry) -> Option<Route> {
    match StepKind::from_code(e.kind)? {
        StepKind::Improve => Some(Route::Improve),
        StepKind::Cross | StepKind::Shed => Some(Route::Cross),
        _ => None,
    }
}

fn routes_of(
    recs: &[OwnedRec],
    pk: &PacketRecord,
    out: &mut [(LaneSeq, Route); MAX_ROUTES],
) -> usize {
    let lo = pk.first_lane_seq.0;
    let hi = lo.saturating_add(u64::from(pk.count));
    let mut n = 0usize;
    for r in recs {
        let OwnedRec::Step(e, _) = r else { continue };
        if e.src_lane != pk.lane || e.src_lane_seq.0 == 0 || e.flags & STEP_CONT != 0 {
            continue;
        }
        let Some(route) = route_of_kind(e) else {
            continue;
        };
        let q = e.src_lane_seq.0;
        if q >= hi {
            break;
        }
        if q < lo || out.iter().take(n).any(|(s, _)| s.0 == q) {
            continue;
        }
        if let Some(d) = out.get_mut(n) {
            *d = (e.src_lane_seq, route);
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

impl<V: Visibility, const NA: usize> Engine<'_, V, NA> {
    /// Replays `recs` from the engine's initial state, forwarding every output to `sink`.
    pub fn replay<P: Payloads, S: Sink>(
        &mut self,
        recs: &[OwnedRec],
        payloads: &P,
        sink: &mut S,
    ) -> Result<(), Diverged> {
        let mut buf = core::mem::take(&mut self.scratch);
        let r = self.replay_in(recs, payloads, sink, &mut buf);
        buf.clear();
        self.scratch = buf;
        r
    }

    fn replay_in<P: Payloads, S: Sink>(
        &mut self,
        recs: &[OwnedRec],
        payloads: &P,
        sink: &mut S,
        buf: &mut Vec<PacketRecord>,
    ) -> Result<(), Diverged> {
        let mut i = 0usize;
        while let Some(r) = recs.get(i) {
            let at = |why| Diverged { index: i, why };
            buf.clear();
            let mut tee = Tee {
                inner: sink,
                pkts: buf,
                step: None,
            };
            let used = match r {
                OwnedRec::Step(e, d) => {
                    let deltas = d.get(..usize::from(e.n_delta)).unwrap_or(&[]);
                    let rs = ReplayStep::from_log(&self.cut, e, deltas).ok_or(at(Why::BadStep))?;
                    let got = self
                        .drive(&mut tee, |bbo, vis, ports, book| {
                            bbo.replay_step(vis, ports, book, &rs)
                        })
                        .map_err(|x| {
                            at(match x {
                                StepErr::Fault(f) => Why::Fault(f),
                                StepErr::Diverge(v) => Why::Step(v),
                            })
                        })?;
                    if got.is_none() {
                        return Err(at(Why::NoStep));
                    }
                    if !tee.step.as_ref().is_some_and(|g| same_step(g, r)) {
                        return Err(at(Why::Mismatch));
                    }
                    1
                }
                OwnedRec::Packet(p) if is_advance(p) && !is_mid(p) => {
                    let l = usize::from(p.lane.0);
                    if !self.poll_lane(l, &mut tee).map_err(|f| at(Why::Fault(f)))? {
                        return Err(at(Why::BadRecord));
                    }
                    tee.pkts.len()
                }
                OwnedRec::Packet(p) => {
                    let l = usize::from(p.lane.0);
                    let run = recs.get(i..).unwrap_or(&[]);
                    let (k, pk) = run
                        .iter()
                        .map_while(|x| match x {
                            OwnedRec::Packet(q) if q.lane == p.lane => Some(q),
                            _ => None,
                        })
                        .enumerate()
                        .find(|(_, q)| !is_advance(q))
                        .ok_or(at(Why::BadRecord))?;
                    // The packet's MID boundaries: the MID records of this lane before it in the
                    // run and right after it, up to the lane's next other record (05 §6.2).
                    let mut mids = [Mid {
                        pass: 0,
                        next: LaneSeq(0),
                        at: LaneCutEntry::default(),
                    }; MAX_MIDS];
                    let mut n_mid = 0usize;
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
                        let cut = self.cut_at(m.fills_applied, l).ok_or(at(Why::StepTooOld))?;
                        let d = mids.get_mut(n_mid).ok_or(at(Why::BadRecord))?;
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
                        n_mid = n_mid.saturating_add(1);
                    }
                    let mut routes = [(LaneSeq(0), Route::Join); MAX_ROUTES];
                    let n_route = routes_of(recs.get(i..).unwrap_or(&[]), pk, &mut routes);
                    let bytes = payloads.get(pk).ok_or(at(Why::NoPayload))?;
                    let rx = RxIn {
                        bytes,
                        rx_ts: pk.rx_ts,
                        pkt_hash: pk.pkt_hash,
                    };
                    let mids = mids.get(..n_mid).unwrap_or(&[]);
                    let routes = routes.get(..n_route).unwrap_or(&[]);
                    let res = if pk.flags & PacketFlags::SHED != 0 {
                        self.replay_ingest(l, rx, &FixedClock(u64::MAX), mids, routes, &mut tee)
                    } else {
                        self.replay_ingest(l, rx, &NeverLate, mids, routes, &mut tee)
                    };
                    res.map_err(|f| at(Why::Fault(f)))?;
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
