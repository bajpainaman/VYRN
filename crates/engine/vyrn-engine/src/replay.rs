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
//!   packet, fetched from [`Payloads`], with a late clock iff `SHED`.

use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{CutDelta, Diverge, MAX_LANES, ReplayStep, StepEntry};
use vyrn_cut::Visibility;
use vyrn_lane::RxIn;
use vyrn_types::{PacketFlags, PacketRecord};

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
                    let pk = recs
                        .get(i..)
                        .unwrap_or(&[])
                        .iter()
                        .map_while(|x| match x {
                            OwnedRec::Packet(q) if q.lane == p.lane => Some(q),
                            _ => None,
                        })
                        .find(|q| !is_advance(q))
                        .ok_or(at(Why::BadRecord))?;
                    let bytes = payloads.get(pk).ok_or(at(Why::NoPayload))?;
                    let rx = RxIn {
                        bytes,
                        rx_ts: pk.rx_ts,
                        pkt_hash: pk.pkt_hash,
                    };
                    let shed = pk.flags & PacketFlags::SHED != 0;
                    let res = if shed {
                        self.ingest(l, rx, &FixedClock(u64::MAX), &mut tee)
                    } else {
                        self.ingest(l, rx, &NeverLate, &mut tee)
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
