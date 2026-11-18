//! Replay mode (05 §10, 01 §11.6): the same lanes and BBO core, driven by the order stream.
//!
//! Each record is replayed by the call that produced it live, and the call's output records
//! must equal the input records byte for byte:
//!
//! - a `Rec::Step`: one BBO step ([`Engine::step`]), its clock set so the source's deadline test
//!   gives the logged kind (`Shed` iff late);
//! - a non-`MID` Advance record of lane `l`: lane `l`'s idle poll, which reads the `LaneCut`
//!   that the replayed steps wrote;
//! - a packet record (with the `MID` Advance records the lane wrote while processing it): the
//!   packet, fetched from [`Payloads`], with a late clock iff `SHED`.

use vyrn_bbo::admit::{FixedClock, NeverLate};
use vyrn_bbo::{CutDelta, MAX_LANES, StepEntry};
use vyrn_cut::Visibility;
use vyrn_lane::RxIn;
use vyrn_types::{LaneSeq, PacketFlags, PacketRecord, StepKind};

use crate::engine::{Engine, Fault, PKT_HIST, Rec, Sink};

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
    /// A step's source op is not in the packet history (`ENG_FWD_RING` packets per lane).
    SourceTooOld,
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
                OwnedRec::Step(e, _) => {
                    let late = e.kind == StepKind::Shed.code();
                    let got = match self.src_deadline(e) {
                        Some(None) => self.step(&NeverLate, &mut tee),
                        Some(Some(d)) => {
                            let now = if late { d.wrapping_add(1) } else { d };
                            self.step(&FixedClock(u64::from(now)), &mut tee)
                        }
                        None => return Err(at(Why::SourceTooOld)),
                    };
                    if got.map_err(|f| at(Why::Fault(f)))?.is_none() {
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
                    let before = self.lanes.get(l).map_or(LaneSeq(0), |x| x.seq());
                    let res = if shed {
                        self.ingest(l, rx, &FixedClock(u64::MAX), &mut tee)
                    } else {
                        self.ingest(l, rx, &NeverLate, &mut tee)
                    };
                    res.map_err(|f| at(Why::Fault(f)))?;
                    if !shed {
                        let after = self.lanes.get(l).map_or(LaneSeq(0), |x| x.seq());
                        self.remember(l, before, after, pk.rx_ts.0);
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

    /// Lane `l` accepted a packet received at `rx_ts` and gave its ops the `LaneSeq`s
    /// `before + 1 ..= after` (Heartbeat and ResendReq take none, so the message count is not
    /// the range). The lane keys the packet at `prio_ts = max(rx_ts, previous prio_ts)` (05
    /// §6.3), and its forwarded ops' deadlines are built from that, so that is what is kept.
    fn remember(&mut self, l: usize, before: LaneSeq, after: LaneSeq, rx_ts: u64) {
        let Some(prio) = self.prio.get_mut(l) else {
            return;
        };
        *prio = rx_ts.max(*prio);
        let ts = *prio;
        if after <= before {
            return;
        }
        let Some(n) = self.pkt_next.get_mut(l) else {
            return;
        };
        let slot = l.saturating_mul(PKT_HIST).saturating_add(*n);
        if let Some(x) = self.pkts.get_mut(slot) {
            *x = (before.0.saturating_add(1), after.0, ts);
        }
        *n = n.saturating_add(1).checked_rem(PKT_HIST).unwrap_or(0);
    }

    /// The deadline (`FwdEntry.deadline`, low 32 bits of `rx_ts + fwd_deadline_ns`, 05 §6.8) of
    /// step `e`'s source: `Some(None)` if the step has no source, `None` if it is unknown.
    fn src_deadline(&self, e: &StepEntry) -> Option<Option<u32>> {
        if e.src_lane_seq.0 == 0 {
            return Some(None);
        }
        let l = usize::from(e.src_lane.0);
        let cfg = self.cfgs.get(l)?;
        let ring = self
            .pkts
            .get(l.saturating_mul(PKT_HIST)..l.saturating_add(1).saturating_mul(PKT_HIST))?;
        let q = e.src_lane_seq.0;
        let rx = ring
            .iter()
            .find_map(|(lo, hi, ts)| (*lo != 0 && *lo <= q && q <= *hi).then_some(*ts))?;
        let [a, b, c, d, ..] = rx
            .wrapping_add(u64::from(cfg.fwd_deadline_ns))
            .to_le_bytes();
        Some(Some(u32::from_le_bytes([a, b, c, d])))
    }
}
