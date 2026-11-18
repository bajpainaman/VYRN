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
use vyrn_consensus::{Committee, Prefix, Seal, SealExt, Silence, Tail, TailReport};
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
    /// The order thread had no report to give (no block ready yet).
    own_none: bool,
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

    /// The order thread suspects: freeze, with its report. Already deposed by the others in
    /// the meantime, the report still goes in: the prefix waits for it.
    pub fn freeze(&self, report: TailReport) {
        let mut s = self.st();
        if s.phase == Phase::Live {
            s.phase = Phase::Frozen;
        }
        s.own = Some(report);
    }

    /// Deposed by the others' `Silence` before this voter suspected (Codex r4618501027): its
    /// tail still goes into the prefix, which waits for it (07 §9.2). `None`: no block ready.
    pub fn publish(&self, report: Option<TailReport>) {
        let mut s = self.st();
        match report {
            Some(r) => s.own = Some(r),
            None => s.own_none = true,
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
    /// Its TailReport went to the consensus thread in this failover.
    pub reported: bool,
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
    /// The tenure this voter follows: a report of another counts nowhere.
    tenure: u8,
    me: u8,
    abort: std::time::Duration,
    /// Each reporter's newest report and when it last arrived.
    reports: BTreeMap<u8, (Instant, TailReport)>,
    /// This voter's own report is in `reports`, or it has none to give.
    own_in: bool,
    sent_at: Option<Instant>,
    deposed: bool,
    decided: bool,
}

impl Tally {
    pub fn new(
        committee: Committee,
        seq_order: Vec<PubKey>,
        epoch: Epoch,
        tenure: u8,
        me: u8,
        abort_us: u64,
    ) -> Self {
        Self {
            committee,
            seq_order,
            epoch,
            tenure,
            me,
            abort: std::time::Duration::from_micros(abort_us),
            reports: BTreeMap::new(),
            own_in: false,
            sent_at: None,
            deposed: false,
            decided: false,
        }
    }

    /// This voter's own `Silence`, signed, when the order thread has frozen and it was not sent.
    pub fn own(&mut self, shared: &Shared, vote_seed: &[u8; 32]) -> Option<Vec<u8>> {
        let report = {
            let mut st = shared.st();
            if std::mem::take(&mut st.own_none) {
                self.own_in = true;
            }
            st.own.take()?
        };
        let s = Silence::sign(0, Reason::Silence, report.clone(), vote_seed);
        // The check every peer runs (Codex r4618501052): a report they would refuse counts
        // nowhere, here included.
        if let Err(e) = Silence::decode(&s.encode())
            .map_err(|e| e.to_string())
            .and_then(|d| {
                d.verify(&self.committee, &self.seq_order)
                    .map_err(|e| e.to_string())
            })
        {
            println!("SILENCE_UNREPORTABLE {e}");
            self.own_in = true;
            return None;
        }
        self.own_in = true;
        if !self.deposed {
            self.sent_at = Some(Instant::now());
        }
        self.reports.insert(self.me, (Instant::now(), report));
        Some(s.encode())
    }

    /// A peer's `Silence` from the tail channel. Only this voter's epoch and tenure count (a
    /// signed report of another tenure is refused, never adopted); a standby's report counts
    /// toward the prefix, never toward Q (07 §9.1). A repeat refreshes its arrival time.
    /// `from` is the reporter index (voter, or `n + j` for `seq_order[j]`) whose p2p key
    /// authenticated the connection the report arrived on (Codex r4618710697): a report counts
    /// only from its own signer, so a peer cannot replay another's old Silence as fresh.
    pub fn on_silence(&mut self, from: u8, bytes: &[u8]) -> Result<(), String> {
        let s = Silence::decode(bytes).map_err(|e| e.to_string())?;
        s.verify(&self.committee, &self.seq_order)
            .map_err(|e| e.to_string())?;
        if s.report.reporter != from {
            return Err(format!(
                "reporter {} forwarded by peer {from}",
                s.report.reporter
            ));
        }
        if s.report.epoch != self.epoch || s.report.tenure != self.tenure {
            return Err("another epoch or tenure".into());
        }
        if s.report.reporter == self.me {
            return Err("this voter's own index".into());
        }
        if !self.decided {
            self.reports
                .insert(s.report.reporter, (Instant::now(), s.report));
        }
        Ok(())
    }

    /// 07 §9.1–9.2: Silence from Q distinct voters, each of them held within the abort window
    /// (a frozen voter repeats its own every 2 ms, an aborted one stops), this voter's own
    /// while it is frozen.
    fn quorum(&self) -> bool {
        let mut dep = Deposition::new(&self.committee);
        let n = self.committee.n();
        for (&who, (at, _)) in &self.reports {
            let fresh = if who == self.me {
                self.sent_at.is_some()
            } else {
                at.elapsed() < self.abort
            };
            if fresh && usize::from(who) < n {
                dep.add(who);
            }
        }
        dep.deposed()
    }

    /// Advances the failover; returns a line to print when it moves.
    pub fn poll(&mut self, shared: &Shared, now_real_ns: u64) -> Option<String> {
        if !self.deposed && self.quorum() {
            self.deposed = true;
            shared.st().phase = Phase::Deposed;
            return Some(format!(
                "DEPOSED epoch={} reports={}",
                self.epoch.0,
                self.reports.len()
            ));
        }
        if self.deposed && !self.decided {
            let reports: Vec<TailReport> = self.reports.values().map(|(_, r)| r.clone()).collect();
            let all = reports.len() >= self.committee.n();
            // Never without this voter's own tail (07 §9.2 waits for every report).
            let due = all || tail_deadline(&reports).is_some_and(|d| now_real_ns >= d);
            if due && self.own_in {
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
            self.own_in = false;
            self.reports.remove(&self.me);
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

    fn seed(i: u8) -> [u8; 32] {
        [i + 1; 32]
    }

    /// A committee of 4 (seeds `[i + 1; 32]`) and this voter's tally at index 0.
    fn tally(abort_us: u64) -> (Tally, Shared) {
        let keys = (0..4)
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .collect();
        let seq = vyrn_crypto::ed25519::public_key(&[0x99; 32]);
        let c = Committee::new(vyrn_types::Mode::Base, keys, &[seq]).unwrap();
        (
            Tally::new(c, vec![seq], Epoch(0), 0, 0, abort_us),
            Shared::default(),
        )
    }

    fn silence(from: u8, tenure: u8) -> Vec<u8> {
        let r = report(&tail(12), Epoch(0), tenure, from, 1);
        Silence::sign(0, Reason::Silence, r, &seed(from)).encode()
    }

    /// 07 §9.1 "within REP_SUSPECT_ABORT_MS" (Vercel r4618491834): Silence a peer sent before
    /// it aborted does not add up with later ones into a quorum.
    #[test]
    // The abort window is wall-clock (`Instant`): the test waits it out.
    #[allow(clippy::disallowed_methods)]
    fn stale_silence_does_not_add_up_to_a_quorum() {
        let (mut t, sh) = tally(20_000);
        t.on_silence(1, &silence(1, 0)).unwrap();
        t.on_silence(2, &silence(2, 0)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(40));
        t.on_silence(3, &silence(3, 0)).unwrap();
        assert_eq!(t.poll(&sh, 0), None);
        assert_eq!(sh.phase(), Phase::Live);
        // The two repeat theirs (a frozen voter does every 2 ms): now Q are fresh.
        t.on_silence(1, &silence(1, 0)).unwrap();
        t.on_silence(2, &silence(2, 0)).unwrap();
        assert!(t.poll(&sh, 0).unwrap().starts_with("DEPOSED"));
    }

    /// Codex r4618710697: a voter's valid signed Silence that another peer forwards (a replay)
    /// is refused and does not count toward Q.
    #[test]
    fn a_forwarded_silence_does_not_count() {
        let (mut t, sh) = tally(1_000_000);
        t.on_silence(1, &silence(1, 0)).unwrap();
        assert!(t.on_silence(1, &silence(2, 0)).is_err());
        assert!(t.on_silence(1, &silence(3, 0)).is_err());
        assert_eq!(t.poll(&sh, 0), None);
        assert_eq!(sh.phase(), Phase::Live);
        t.on_silence(2, &silence(2, 0)).unwrap();
        t.on_silence(3, &silence(3, 0)).unwrap();
        assert!(t.poll(&sh, 0).unwrap().starts_with("DEPOSED"));
    }

    /// Vercel r4618491826: a signed report of another tenure is refused and does not pin the
    /// tally to that tenure.
    #[test]
    fn a_report_of_another_tenure_pins_nothing() {
        let (mut t, sh) = tally(1_000_000);
        assert!(t.on_silence(1, &silence(1, 5)).is_err());
        for v in 1..=3 {
            t.on_silence(v, &silence(v, 0)).unwrap();
        }
        assert!(t.poll(&sh, 0).unwrap().starts_with("DEPOSED"));
    }

    /// Codex r4618501027: deposed by its peers before it suspected, a voter decides the prefix
    /// only with its own tail in it (07 §9.2), however late the deadline.
    #[test]
    fn a_voter_deposed_by_its_peers_waits_for_its_own_tail() {
        let (mut t, sh) = tally(1_000_000);
        for v in 1..=3 {
            t.on_silence(v, &silence(v, 0)).unwrap();
        }
        assert!(t.poll(&sh, u64::MAX).unwrap().starts_with("DEPOSED"));
        assert_eq!(t.poll(&sh, u64::MAX), None);
        assert_eq!(sh.take_decision(), None);
        // Its own tail holds two more frames than the others'.
        sh.publish(Some(report(&tail(14), Epoch(0), 0, 0, 2)));
        assert!(t.own(&sh, &seed(0)).is_some());
        let line = t.poll(&sh, u64::MAX).unwrap();
        assert!(
            line.contains("end_a=14 ") && line.contains("reports=4"),
            "{line}"
        );
    }
}
