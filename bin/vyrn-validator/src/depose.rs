//! Sequencer failover, the voter's side of 07 §9.1–9.4: silence, freeze, `Silence`, deposition and
//! the seal candidate. Promotion of a standby (07 §9.5) is not here: with no promotable box the
//! seal names `next_seq = 0xFF` and the book stays halted (07 §9.5 "No promotable box").
//!
//! | Step | Who | What |
//! |---|---|---|
//! | Suspect (07 §9.1) | order thread | no frame for `[failover] silence_us` after the first: it **freezes** (stops polling the ORDER queues; the socket buffers what still arrives) and snapshots its TailReport from [`OrderCore::tail`] |
//! | `Silence` (07 §9.1) | consensus thread | signs it with the vote key and sends it on the p2p tail channel ([`vyrn_consensus::net`]) |
//! | Abort (07 §9.1) | consensus thread | fewer than Q voters' `Silence` `abort_us` after its own: unfreeze, drop the reports |
//! | Depose (07 §9.2) | consensus thread | Q voters' `Silence`: INV-REP-5, the ORDER queues are drained unread from then on |
//! | Prefix (07 §9.3) | consensus thread | from every report held once all `n` arrived or at `T* + REP_TAIL_WAIT_MS` |
//! | Seal (07 §9.4) | order thread | its own candidate from its tail and the prefix ([`seal`]), into the `BlockSource` |
//!
//! *Readings* (each labelled in the PR):
//! - **DEV timers.** `silence_us` (default 2000 = `FAILOVER_SILENCE_MS`) and `abort_us` (default
//!   5000 = `REP_SUSPECT_ABORT_MS`) differ from the spec only with `dev = true`.
//! - **Freeze buffers in the socket.** A frozen voter stops polling its ORDER queues and runs no
//!   `REP_E_HASHLAG` deadline; an abort resumes both. Frames buffered past the bound then trip
//!   `REP_E_HASHLAG`, which the spec's 5 ms abort window against a 1 ms bound implies too.
//! - **`H_i`** is the last block the order core made ready (header, ORDER frames and HashRuns),
//!   and **`F_i`** the last frame it decoded: it decodes in `frame_seq` order, so it holds
//!   `1..=F_i`. No `extra` ranges (frames `Paths` holds behind a gap are not reported), and every
//!   `direct` bit is 1 (the source of a repaired frame is not tracked).
//! - **No tail fetch yet** (07 §9.3 item 2, a gap). A voter whose `H_i` is below `H*` or whose
//!   `F_i` is below `F*` on a substream holds no seal candidate: as leader it proposes nothing
//!   and the view nullifies; it never seals a shorter prefix.
//! - **Data** (07 §9.3 item 4): a tail packet is resolved from the `DataJoin` (by `pkt_hash`,
//!   or for an unhashed record by `(session, pkt_seq)` alone, its first variant); one it cannot
//!   resolve, or every one without `[data]`, is unavailable, with 32 zero bytes in `data_root`.
//!   No fetch at seal time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use serde::Deserialize;
use vyrn_consensus::silence::{Deposition, Reason};
use vyrn_consensus::tail::{next_seq, prefix, seal_header, tail_deadline};
use vyrn_consensus::{Committee, Prefix, Reporter, Seal, SealExt, Silence, Tail, TailReport};
use vyrn_log::LaneRec;
use vyrn_log::block::{data_root, order_root};
use vyrn_replica::{DataJoin, TailState, full_hash};
use vyrn_types::{BlockHeader, Epoch, Hash, PacketFlags, PubKey};

/// `[failover]`: turns on 07 §9.1–9.4 at this voter.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    /// `FAILOVER_SILENCE_MS` in µs; another value is DEV only.
    #[serde(default = "d_silence")]
    pub silence_us: u64,
    /// `REP_SUSPECT_ABORT_MS` in µs; another value is DEV only.
    #[serde(default = "d_abort")]
    pub abort_us: u64,
}

pub const fn d_silence() -> u64 {
    vyrn_types::FAILOVER_SILENCE_MS * 1000
}

pub const fn d_abort() -> u64 {
    5_000
}

/// Where this voter is in a failover.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Live,
    /// Suspected: the ORDER queues are not polled.
    Frozen,
    /// Deposed (INV-REP-5): the ORDER queues are drained unread.
    Deposed,
}

#[derive(Default)]
struct St {
    phase: Phase,
    /// This voter's report, from the order thread, until the consensus thread signs it.
    own: Option<TailReport>,
    decided: Option<(Prefix, u8)>,
}

/// What the order and consensus threads share about a failover.
#[derive(Clone, Default)]
pub struct Shared(Arc<Mutex<St>>);

impl Shared {
    fn st(&self) -> std::sync::MutexGuard<'_, St> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn phase(&self) -> Phase {
        self.st().phase
    }

    /// The order thread suspects: freeze, with its report.
    pub fn freeze(&self, report: TailReport) {
        let mut s = self.st();
        if s.phase == Phase::Live {
            s.phase = Phase::Frozen;
            s.own = Some(report);
        }
    }

    /// The prefix and `next_seq`, once, after deposition.
    pub fn take_decision(&self) -> Option<(Prefix, u8)> {
        self.st().decided.take()
    }
}

/// The order thread's part of a failover.
pub struct OrderSide {
    pub shared: Shared,
    pub silence_ns: u64,
    pub epoch: Epoch,
    pub me: u8,
    /// It left `Live` and has not come back (an abort resets the silence clock).
    pub was_frozen: bool,
    pub sealed: bool,
    /// ORDER datagrams drained unread since deposition (INV-REP-5).
    pub dropped: u64,
}

/// This voter's TailReport from its order core's tail.
pub fn report(t: &TailState, epoch: Epoch, tenure: u8, me: u8, t_last_rx: u64) -> TailReport {
    let tail = |s: Option<&vyrn_replica::SubTail>| {
        s.map_or_else(Tail::default, |s| {
            let frames = s.last.saturating_sub(s.mark);
            Tail {
                mark: s.mark,
                contiguous: s.last,
                extra: Vec::new(),
                direct: vec![0xFF; usize::try_from(frames.div_ceil(8)).unwrap_or(0)],
            }
        })
    };
    TailReport {
        epoch,
        tenure,
        reporter: me,
        held_height: t.height,
        tails: [tail(t.subs.first()), tail(t.subs.get(1))],
        t_last_rx,
        replay_lag_us: 0,
        promotable: false,
    }
}

/// This voter's seal candidate on top of `star`, the header at `H*` (07 §9.4), or why it holds
/// none: its tail must end exactly at the prefix (no tail fetch yet, module docs).
pub fn seal(
    t: &TailState,
    p: &Prefix,
    next: u8,
    tenure: u8,
    star: Option<BlockHeader>,
    join: Option<&DataJoin>,
) -> Result<Seal, String> {
    if t.height != p.height {
        return Err(format!(
            "held height {} below H* {}",
            t.height.0, p.height.0
        ));
    }
    let star = star.ok_or("no header at H*")?;
    for (s, (sub, end)) in t.subs.iter().zip(p.end).enumerate() {
        if sub.last != end {
            return Err(format!(
                "substream {s} holds through {} of F* {end}",
                sub.last
            ));
        }
    }
    let mut full: [Vec<Hash>; 2] = [Vec::new(), Vec::new()];
    let mut unavail = Vec::new();
    for (sub, out) in t.subs.iter().zip(&mut full) {
        for r in &sub.recs {
            let LaneRec::Pkt(pkt) = r else { continue };
            if pkt.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) != 0 {
                continue;
            }
            let held = join.and_then(|j| {
                if pkt.pkt_hash.0 == 0 {
                    j.variants(pkt.session, pkt.pkt_seq).next().map(full_hash)
                } else {
                    j.resolve(pkt).ok().map(|(_, h)| h)
                }
            });
            out.push(held.unwrap_or_else(|| {
                unavail.push((pkt.session, pkt.pkt_seq));
                Hash([0; 32])
            }));
        }
    }
    unavail.sort_unstable();
    unavail.dedup();
    let empty: &[u8] = &[];
    let order = order_root(
        t.subs.first().map_or(empty, |s| &s.order_bytes),
        t.subs.get(1).map_or(empty, |s| &s.order_bytes),
    );
    let [a, b] = &full;
    Ok(Seal {
        header: seal_header(&star, t.last_step, order, data_root(a, b)),
        ext: SealExt {
            end_frame_seq: p.end,
            next_seq: next,
            next_tenure: tenure.wrapping_add(1),
            unavail,
        },
    })
}

/// The consensus thread's count of one failover.
pub struct Tally {
    committee: Committee,
    seq_order: Vec<PubKey>,
    epoch: Epoch,
    me: u8,
    abort: std::time::Duration,
    reports: BTreeMap<u8, TailReport>,
    dep: Deposition,
    sent_at: Option<Instant>,
    deposed: bool,
    decided: bool,
}

impl Tally {
    pub fn new(
        committee: Committee,
        seq_order: Vec<PubKey>,
        epoch: Epoch,
        me: u8,
        abort_us: u64,
    ) -> Self {
        let dep = Deposition::new(&committee);
        Self {
            committee,
            seq_order,
            epoch,
            me,
            abort: std::time::Duration::from_micros(abort_us),
            reports: BTreeMap::new(),
            dep,
            sent_at: None,
            deposed: false,
            decided: false,
        }
    }

    /// This voter's own `Silence`, signed, when the order thread has frozen and it was not sent.
    pub fn own(&mut self, shared: &Shared, vote_seed: &[u8; 32]) -> Option<Vec<u8>> {
        let report = shared.st().own.take()?;
        let s = Silence::sign(0, Reason::Silence, report.clone(), vote_seed);
        self.sent_at = Some(Instant::now());
        self.reports.insert(self.me, report);
        self.dep.add(self.me);
        Some(s.encode())
    }

    /// A peer's `Silence` from the tail channel. Only this epoch's and the first tenure seen
    /// count; a standby's report counts toward the prefix, never toward Q (07 §9.1).
    pub fn on_silence(&mut self, bytes: &[u8]) -> Result<(), String> {
        let s = Silence::decode(bytes).map_err(|e| e.to_string())?;
        let who = s
            .verify(&self.committee, &self.seq_order)
            .map_err(|e| e.to_string())?;
        let tenure = self.reports.values().next().map(|r| r.tenure);
        if s.report.epoch != self.epoch || tenure.is_some_and(|t| t != s.report.tenure) {
            return Err("another epoch or tenure".into());
        }
        if self.decided {
            return Ok(());
        }
        if let Reporter::Voter(v) = who {
            self.dep.add(v);
        }
        self.reports.insert(s.report.reporter, s.report);
        Ok(())
    }

    /// Advances the failover; returns a line to print when it moves.
    pub fn poll(&mut self, shared: &Shared, now_real_ns: u64) -> Option<String> {
        if !self.deposed && self.dep.deposed() {
            self.deposed = true;
            shared.st().phase = Phase::Deposed;
            return Some(format!(
                "DEPOSED epoch={} reports={}",
                self.epoch.0,
                self.reports.len()
            ));
        }
        if self.deposed && !self.decided {
            let reports: Vec<TailReport> = self.reports.values().cloned().collect();
            let all = reports.len() >= self.committee.n();
            if all || tail_deadline(&reports).is_some_and(|d| now_real_ns >= d) {
                let p = prefix(&reports)?;
                // seq_order[0] is the deposed one; no standby report yet, so none is promotable.
                let next = next_seq(&self.committee, self.seq_order.len(), 0, &[0], &reports);
                self.decided = true;
                shared.st().decided = Some((p, next));
                return Some(format!(
                    "PREFIX height={} end_a={} end_b={} reports={} next_seq={next}",
                    p.height.0,
                    p.end[0],
                    p.end[1],
                    reports.len()
                ));
            }
        }
        if !self.deposed && self.sent_at.is_some_and(|t| t.elapsed() >= self.abort) {
            self.sent_at = None;
            self.reports.clear();
            self.dep = Deposition::new(&self.committee);
            let mut s = shared.st();
            s.phase = Phase::Live;
            s.own = None;
            return Some("UNFREEZE (fewer than Q Silence within abort_us)".into());
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use vyrn_consensus::tail::NO_NEXT_SEQ;
    use vyrn_replica::SubTail;
    use vyrn_types::{Height, LaneId, LaneSeq, Nanos, PacketRecord, PktHash, SessionId, StepId};

    fn pkt(seq: u32) -> LaneRec {
        LaneRec::Pkt(PacketRecord {
            lane: LaneId(0),
            count: 1,
            flags: 0,
            session: SessionId(9),
            pkt_seq: seq,
            rx_ts: Nanos(0),
            pkt_hash: PktHash(0),
            first_lane_seq: LaneSeq(u64::from(seq)),
            fills_applied: StepId(0),
            snap_lag: 0,
        })
    }

    fn tail(last: u64) -> TailState {
        TailState {
            height: Height(5),
            last_step: StepId(9),
            subs: vec![SubTail {
                mark: 10,
                last,
                order_bytes: vec![1, 2, 3],
                recs: vec![pkt(3), pkt(2)],
            }],
        }
    }

    fn star() -> BlockHeader {
        BlockHeader {
            height: Height(5),
            epoch: Epoch(0),
            book: vyrn_types::BookId(7),
            first_step: StepId(1),
            last_step: StepId(7),
            prev: Hash([0; 32]),
            order_root: Hash([0; 32]),
            data_root: Hash([0; 32]),
            seq_sig: [0; 64],
        }
    }

    /// 07 §9.3, no tail fetch: a voter missing the prefix's last frame holds no candidate,
    /// rather than a seal one frame short.
    #[test]
    fn a_voter_short_of_the_prefix_holds_no_seal() {
        let p = Prefix {
            height: Height(5),
            end: [12, 0],
        };
        assert!(seal(&tail(11), &p, NO_NEXT_SEQ, 0, Some(star()), None).is_err());
        let high = Prefix {
            height: Height(6),
            end: [12, 0],
        };
        assert!(seal(&tail(12), &high, NO_NEXT_SEQ, 0, Some(star()), None).is_err());
        let s = seal(&tail(12), &p, NO_NEXT_SEQ, 0, Some(star()), None).unwrap();
        assert_eq!(s.ext.end_frame_seq, [12, 0]);
        assert_eq!(s.ext.next_seq, 0xFF);
        assert_eq!(s.ext.next_tenure, 1);
        // Without [data] every tail packet is unavailable, ascending.
        assert_eq!(s.ext.unavail, vec![(SessionId(9), 2), (SessionId(9), 3)]);
        assert_eq!(s.header.height, Height(6));
        assert_eq!(s.header.first_step, StepId(8));
        assert_eq!(s.header.last_step, StepId(9));
        assert_eq!(s.header.order_root, order_root(&[1, 2, 3], &[]));
        assert_eq!(s.header.data_root, data_root(&[Hash([0; 32]); 2], &[]));
    }
}
