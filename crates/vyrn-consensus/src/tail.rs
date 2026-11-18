//! Signed `Silence` and its TailReport, the prefix rule, and the seal proposal
//! (spec/07-replication.md §9.1–9.5).
//!
//! | Contract | Type | Spec |
//! |---|---|---|
//! | What a reporter claims to hold, signed | [`Silence`], [`TailReport`], [`Tail`] | 07 §9.1, §9.3 |
//! | Which reporters count toward deposition | [`Silence::verify`] → [`Reporter`] | 07 §9.1–9.2 |
//! | The prefix the leader seals | [`prefix`] → [`Prefix`], [`holder`], [`tail_deadline`] | 07 §9.2–9.3 |
//! | Who sequences next | [`next_seq`] | 07 §9.5 |
//! | What a seal commits to | [`SealExt`], [`seal_header`], [`seal_proposal`], [`seal_digest`] | 07 §9.4 |
//!
//! Everything here is a pure function of signed or locally held data, so any voter recomputes the
//! leader's prefix and `next_seq` and refuses a seal that differs (07 §9.4–9.5). Frames, payloads
//! and fetching stay with the caller: this module names who holds a frame, never fetches it.
//!
//! Spec gaps, each with the reading taken (search for `Spec gap`):
//! 1. 07 §9.3 lists TailReport fields without byte widths for `extra` and `direct`, and the
//!    `direct` bitmap starts at "H_i's mark", which the report does not carry. Reading: each
//!    substream's [`Tail`] carries `mark`, the `frame_seq` of `BlockMark(H_i)` on it. **Wire
//!    addition: 8 bytes per substream.**
//! 2. 07 §9.1 signs `Silence` and 07 §9.3 signs the TailReport inside it. Reading: one Ed25519
//!    signature over `"vyrn      v1 silence" ‖ seq ‖ reason ‖ report`; the report's epoch and tenure
//!    are the Silence's. One signature, and it covers the report.
//! 3. The standby's `reporter` value is not defined. Reading: `reporter = n + j` names
//!    `REP_Membership.seq_order[j]`, signing under that box's `seq_key`.
//! 4. 07 §9.4 writes the seal digest as `BLAKE3(proposal ‖ seal ext)` without the §6.3 domain
//!    string. Reading: `BLAKE3("vyrn      v1 proposal" ‖ REP_Proposal ‖ REP_SealExt)`, the §6.3
//!    rule extended. **Semantics:** a kind-1 Simplex payload is not `Proposal::digest`, so a
//!    `REP_FinalityCert` of a seal cannot be checked from its 85-byte proposal alone (see the PR).
//! 5. `t_last_rx` is "PTP time" with no unit. Reading: nanoseconds.
//! 6. `next_seq` takes "the first entry after the deposed one". Reading: no wrap-around; with none
//!    left it is `0xFF` (07 §9.5 "No promotable box").

use crate::membership::Committee;
use crate::proposal::{PROPOSAL_CONTEXT, Proposal, ProposalErr, ProposalKind};
use crate::silence::Reason;
use thiserror::Error;
use vyrn_log::block::header_hash;
use vyrn_types::{BlockHeader, Ed25519Sig, Epoch, Hash, Height, PubKey, SessionId, StepId};

/// Domain string of the `Silence` signature, in the width of [`PROPOSAL_CONTEXT`].
pub const SILENCE_CONTEXT: &[u8] = b"vyrn      v1 silence";
/// At most 64 ranges of frames held above `F_i`, per substream (07 §9.3).
pub const MAX_EXTRA_RANGES: usize = 64;
/// Decode cap on the frames one [`Tail`] may describe (its `direct` bitmap). Not in 07; it bounds
/// what a malformed report can make a decoder allocate (128 KiB of bitmap).
pub const MAX_TAIL_FRAMES: u64 = 1 << 20;
/// `REP_TAIL_WAIT_MS` = 4.05 ms (07 §9.2), in nanoseconds.
pub const TAIL_WAIT_NS: u64 = 4_050_000;
/// `REP_PROMOTE_LAG_US`: the `replay_lag_us` bound of a promotable box (07 §9.5).
pub const PROMOTE_LAG_US: u32 = 2_000;
/// `REP_SealExt.next_seq` when no box is promotable (07 §9.5).
pub const NO_NEXT_SEQ: u8 = 0xFF;

/// One substream's part of a TailReport (07 §9.3). Index 0 of a pair is substream A, 1 is B.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tail {
    /// `frame_seq` of `BlockMark(H_i)` on this substream (spec gap 1).
    pub mark: u64,
    /// `F_i`: every frame `1..=contiguous` of the tenure is held.
    pub contiguous: u64,
    /// Ranges `[a, b]` held above `F_i`: ascending, disjoint, the first not adjacent to `F_i`.
    pub extra: Vec<(u64, u64)>,
    /// One bit per frame of `(mark, F_i]`, then of each `extra` range in order, LSB first:
    /// 1 = received from a sequencer path, 0 = repaired from a peer.
    pub direct: Vec<u8>,
}

impl Tail {
    /// Frames the `direct` bitmap covers, or `None` when the ranges are malformed.
    fn frames(&self) -> Option<u64> {
        let mut total = self.contiguous.checked_sub(self.mark)?;
        // The first range leaves a gap above `F_i` (frame `F_i + 1` is missing, or `F_i` would
        // be higher); later ranges only have to be ascending and disjoint, adjacent allowed.
        let mut floor = self.contiguous.checked_add(1)?;
        for &(a, b) in &self.extra {
            if a <= floor || b < a {
                return None;
            }
            total = total.checked_add(b - a + 1)?;
            floor = b;
        }
        (total <= MAX_TAIL_FRAMES).then_some(total)
    }

    fn check(&self) -> Result<(), TailErr> {
        if self.extra.len() > MAX_EXTRA_RANGES {
            return Err(TailErr::Ranges);
        }
        let frames = self.frames().ok_or(TailErr::Ranges)?;
        if self.direct.len() as u64 != frames.div_ceil(8) {
            return Err(TailErr::Direct);
        }
        Ok(())
    }

    /// Whether this tail holds frame `k`.
    pub fn holds(&self, k: u64) -> bool {
        (1..=self.contiguous).contains(&k) || self.extra.iter().any(|&(a, b)| (a..=b).contains(&k))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mark.to_le_bytes());
        out.extend_from_slice(&self.contiguous.to_le_bytes());
        out.push(u8::try_from(self.extra.len()).unwrap_or(u8::MAX));
        for (a, b) in &self.extra {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        out.extend_from_slice(&self.direct);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, TailErr> {
        let mark = r.u64()?;
        let contiguous = r.u64()?;
        let count = usize::from(r.u8()?);
        if count > MAX_EXTRA_RANGES {
            return Err(TailErr::Ranges);
        }
        let mut extra = Vec::with_capacity(count);
        for _ in 0..count {
            extra.push((r.u64()?, r.u64()?));
        }
        let mut tail = Self {
            mark,
            contiguous,
            extra,
            direct: Vec::new(),
        };
        let frames = tail.frames().ok_or(TailErr::Ranges)?;
        let len = usize::try_from(frames.div_ceil(8)).map_err(|_| TailErr::Ranges)?;
        tail.direct = r.take(len)?.to_vec();
        Ok(tail)
    }
}

/// `TailReport` (07 §9.3), carried inside a [`Silence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailReport {
    pub epoch: Epoch,
    pub tenure: u8,
    /// A voter index, or `n + j` for `seq_order[j]` (spec gap 3).
    pub reporter: u8,
    /// `H_i`: the highest height held with a valid `seq_sig` and every ORDER frame through its
    /// `BlockMark`.
    pub held_height: Height,
    /// Substreams A and B.
    pub tails: [Tail; 2],
    /// When the reporter received its newest frame of the tenure, PTP nanoseconds (spec gap 5).
    pub t_last_rx: u64,
    pub replay_lag_us: u32,
    pub promotable: bool,
}

/// A signed `Silence{epoch, tenure, seq, reason, report}` (07 §9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Silence {
    /// Index in `seq_order` of the suspected sequencer.
    pub seq: u8,
    pub reason: Reason,
    pub report: TailReport,
    /// The reporter's Ed25519 signature over [`Silence::message`] (spec gap 2).
    pub sig: Ed25519Sig,
}

/// Who signed a verified [`Silence`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reporter {
    /// A voter: its Silence counts toward deposition (07 §9.2).
    Voter(u8),
    /// A `seq_order` box (the standby): its report counts toward the prefix, never toward Q.
    Standby(u8),
}

/// Why bytes are not a valid, correctly signed `Silence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum TailErr {
    #[error("message is truncated or has trailing bytes")]
    Length,
    #[error("unknown suspicion reason {0}")]
    Reason(u8),
    #[error("frame ranges are malformed, unordered or over the cap")]
    Ranges,
    #[error("direct bitmap does not match the frame ranges")]
    Direct,
    #[error("reporter {0} is neither a voter nor a seq_order box")]
    Unknown(u8),
    #[error("reporter {0} is the suspected sequencer; it never reports on its own tenure")]
    Suspected(u8),
    #[error("signature of reporter {0} is invalid")]
    BadSig(u8),
}

fn reason_code(r: Reason) -> u8 {
    match r {
        Reason::Silence => 0,
        Reason::Equivocation => 1,
        Reason::RootMismatch => 2,
    }
}

impl Silence {
    /// The body: everything but the signature, little-endian.
    fn body(&self) -> Vec<u8> {
        let r = &self.report;
        let mut out = Vec::with_capacity(64);
        out.push(self.seq);
        out.push(reason_code(self.reason));
        out.extend_from_slice(&r.epoch.0.to_le_bytes());
        out.push(r.tenure);
        out.push(r.reporter);
        out.extend_from_slice(&r.held_height.0.to_le_bytes());
        for t in &r.tails {
            t.encode(&mut out);
        }
        out.extend_from_slice(&r.t_last_rx.to_le_bytes());
        out.extend_from_slice(&r.replay_lag_us.to_le_bytes());
        out.push(u8::from(r.promotable));
        out
    }

    /// The bytes the reporter signs: `SILENCE_CONTEXT ‖ body`.
    pub fn message(&self) -> Vec<u8> {
        let mut m = Vec::from(SILENCE_CONTEXT);
        m.extend_from_slice(&self.body());
        m
    }

    /// Signs `report` as `reporter`'s Silence with the 32-byte `seed` of its key.
    pub fn sign(seq: u8, reason: Reason, report: TailReport, seed: &[u8; 32]) -> Self {
        let mut s = Self {
            seq,
            reason,
            report,
            sig: [0; 64],
        };
        s.sig = vyrn_crypto::ed25519::sign(seed, &s.message());
        s
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.sig);
        out
    }

    /// Parses bytes; structure only. [`Silence::verify`] checks the signer.
    pub fn decode(bytes: &[u8]) -> Result<Self, TailErr> {
        let mut r = Reader(bytes);
        let seq = r.u8()?;
        let reason = match r.u8()? {
            0 => Reason::Silence,
            1 => Reason::Equivocation,
            2 => Reason::RootMismatch,
            k => return Err(TailErr::Reason(k)),
        };
        let epoch = Epoch(r.u32()?);
        let tenure = r.u8()?;
        let reporter = r.u8()?;
        let held_height = Height(r.u64()?);
        let tails = [Tail::decode(&mut r)?, Tail::decode(&mut r)?];
        let t_last_rx = r.u64()?;
        let replay_lag_us = r.u32()?;
        let promotable = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(TailErr::Length),
        };
        let sig = r.take(64)?.try_into().map_err(|_| TailErr::Length)?;
        if !r.0.is_empty() {
            return Err(TailErr::Length);
        }
        Ok(Self {
            seq,
            reason,
            report: TailReport {
                epoch,
                tenure,
                reporter,
                held_height,
                tails,
                t_last_rx,
                replay_lag_us,
                promotable,
            },
            sig,
        })
    }

    /// Checks the ranges and the signature. Voters sign with their `vote_key`; `seq_order[j]`
    /// signs as reporter `n + j` with its `seq_key`, except `j = seq`, the suspected sequencer:
    /// 07 §9.3's safety argument needs every reporter honest when the sequencer is the fault.
    pub fn verify(&self, committee: &Committee, seq_order: &[PubKey]) -> Result<Reporter, TailErr> {
        for t in &self.report.tails {
            t.check()?;
        }
        let who = self.report.reporter;
        let n = committee.n();
        let (key, reporter) = match committee.voter(who) {
            Some(k) => (k, Reporter::Voter(who)),
            None => {
                let j = usize::from(who)
                    .checked_sub(n)
                    .ok_or(TailErr::Unknown(who))?;
                if j == usize::from(self.seq) {
                    return Err(TailErr::Suspected(who));
                }
                let k = seq_order.get(j).ok_or(TailErr::Unknown(who))?;
                (k, Reporter::Standby(u8::try_from(j).unwrap_or(u8::MAX)))
            }
        };
        if !vyrn_crypto::ed25519::verify(key, &self.message(), &self.sig) {
            return Err(TailErr::BadSig(who));
        }
        Ok(reporter)
    }
}

/// What the leader seals (07 §9.3 items 1–2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    /// `H* = max H_i`: one reporter suffices, because `seq_sig` is verifiable.
    pub height: Height,
    /// `F*` per substream: the largest `k` with every frame `1..=k` held by some reporter.
    pub end: [u64; 2],
}

impl Prefix {
    /// 07 §9.3 item 3: after a `TailConflict` at `frame_seq` on `substream`, the next proposal
    /// ends below it.
    pub fn truncate(&mut self, substream: usize, frame_seq: u64) {
        if let Some(end) = self.end.get_mut(substream) {
            *end = (*end).min(frame_seq.saturating_sub(1));
        }
    }
}

/// The prefix of the verified `reports` (≥ Q of them once the wait of 07 §9.2 ends), or `None`
/// with no reports.
pub fn prefix(reports: &[TailReport]) -> Option<Prefix> {
    let height = reports.iter().map(|r| r.held_height).max()?;
    let end = [0, 1].map(|s| {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for r in reports {
            let t = &r.tails[s];
            if t.contiguous > 0 {
                runs.push((1, t.contiguous));
            }
            runs.extend_from_slice(&t.extra);
        }
        runs.sort_unstable();
        // Sweep: extend `k` while the next run starts at or below `k + 1`.
        let mut k = 0u64;
        for (a, b) in runs {
            if a > k.saturating_add(1) {
                break;
            }
            k = k.max(b);
        }
        k
    });
    Some(Prefix { height, end })
}

/// The reporter that holds frame `k` of `substream`, preferring one that received it directly
/// from the sequencer: where the leader fetches it from (07 §9.3 item 2).
pub fn holder(reports: &[TailReport], substream: usize, k: u64) -> Option<u8> {
    let holders = || {
        reports
            .iter()
            .filter(move |r| r.tails.get(substream).is_some_and(|t| t.holds(k)))
    };
    holders()
        .find(|r| r.tails.get(substream).is_some_and(|t| direct_bit(t, k)))
        .or_else(|| holders().next())
        .map(|r| r.reporter)
}

/// The `direct` bit of frame `k`, false outside the bitmap.
fn direct_bit(t: &Tail, k: u64) -> bool {
    let ranges =
        std::iter::once((t.mark.saturating_add(1), t.contiguous)).chain(t.extra.iter().copied());
    let mut base = 0u64;
    for (a, b) in ranges {
        if (a..=b).contains(&k) {
            let at = base + (k - a);
            return usize::try_from(at / 8)
                .ok()
                .and_then(|i| t.direct.get(i))
                .is_some_and(|byte| byte >> (at % 8) & 1 == 1);
        }
        base = base.saturating_add(b.saturating_add(1).saturating_sub(a));
    }
    false
}

/// When the leader stops waiting for reports: `T* + REP_TAIL_WAIT_MS`, with `T*` the newest
/// `t_last_rx` it holds (07 §9.2). `None` with no reports.
pub fn tail_deadline(reports: &[TailReport]) -> Option<u64> {
    let newest = reports.iter().map(|r| r.t_last_rx).max()?;
    Some(newest.saturating_add(TAIL_WAIT_NS))
}

/// `REP_SealExt.next_seq` (07 §9.5): the first `seq_order` index after `deposed_now` that was not
/// deposed this epoch, sent a report, and is promotable; [`NO_NEXT_SEQ`] when none is (gap 6).
/// `reports` are the verified reports, so a `seq_order[j]` report has reporter `n + j`.
pub fn next_seq(
    committee: &Committee,
    seq_order_len: usize,
    deposed_now: u8,
    deposed: &[u8],
    reports: &[TailReport],
) -> u8 {
    let n = committee.n();
    (usize::from(deposed_now) + 1..seq_order_len)
        .filter_map(|j| u8::try_from(j).ok())
        .find(|&j| {
            !deposed.contains(&j)
                && reports.iter().any(|r| {
                    usize::from(r.reporter) == n + usize::from(j)
                        && r.promotable
                        && r.replay_lag_us <= PROMOTE_LAG_US
                })
        })
        .unwrap_or(NO_NEXT_SEQ)
}

/// `REP_SealExt` (07 §9.4), encoded little-endian.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SealExt {
    /// `F*` of substreams A and B.
    pub end_frame_seq: [u64; 2],
    pub next_seq: u8,
    pub next_tenure: u8,
    /// Unavailable packets `(session, pkt_seq)`, ascending and distinct.
    pub unavail: Vec<(SessionId, u32)>,
}

impl SealExt {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(22 + 8 * self.unavail.len());
        for f in self.end_frame_seq {
            out.extend_from_slice(&f.to_le_bytes());
        }
        out.push(self.next_seq);
        out.push(self.next_tenure);
        out.extend_from_slice(
            &u32::try_from(self.unavail.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for (s, p) in &self.unavail {
            out.extend_from_slice(&s.0.to_le_bytes());
            out.extend_from_slice(&p.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TailErr> {
        let mut r = Reader(bytes);
        let end_frame_seq = [r.u64()?, r.u64()?];
        let next_seq = r.u8()?;
        let next_tenure = r.u8()?;
        let count = usize::try_from(r.u32()?).map_err(|_| TailErr::Length)?;
        if r.0.len() != count.checked_mul(8).ok_or(TailErr::Length)? {
            return Err(TailErr::Length);
        }
        let mut unavail = Vec::with_capacity(count);
        for _ in 0..count {
            unavail.push((SessionId(r.u32()?), r.u32()?));
        }
        if unavail.windows(2).any(|w| w[0] >= w[1]) {
            return Err(TailErr::Ranges);
        }
        Ok(Self {
            end_frame_seq,
            next_seq,
            next_tenure,
            unavail,
        })
    }
}

/// The seal header of 07 §9.4 on top of `last`, the header at `H*`. The caller supplies the
/// roots over the tail (`order_root` over each substream's ORDER bytes after `BlockMark(H*)`
/// through its `F*`; `data_root` with zeros for unavailable packets) and the last step in frames
/// `≤ F*`. Its `seq_sig` is zero: the seal's finality certificate stands in for it.
pub fn seal_header(
    last: &BlockHeader,
    last_step: StepId,
    order_root: Hash,
    data_root: Hash,
) -> BlockHeader {
    BlockHeader {
        height: Height(last.height.0.saturating_add(1)),
        epoch: last.epoch,
        book: last.book,
        first_step: StepId(last.last_step.0.saturating_add(1)),
        last_step,
        prev: header_hash(last),
        order_root,
        data_root,
        seq_sig: [0; 64],
    }
}

/// The kind-1 proposal `first_height ..= seal.height` (07 §9.4): the signed headers above the
/// parent plus the seal header, at most `REP_MAX_SEAL_RANGE` = 64 heights.
pub fn seal_proposal(
    epoch: Epoch,
    first_height: Height,
    seal: &BlockHeader,
    excl_root: Hash,
) -> Result<Proposal, ProposalErr> {
    let p = Proposal {
        kind: ProposalKind::Seal,
        epoch,
        first_height,
        last_height: seal.height,
        last_hash: header_hash(seal),
        excl_root,
    };
    p.check_range()?;
    Ok(p)
}

/// The Simplex payload of a seal: `BLAKE3(PROPOSAL_CONTEXT ‖ REP_Proposal ‖ REP_SealExt)`
/// (07 §9.4, spec gap 4).
pub fn seal_digest(proposal: &Proposal, ext: &SealExt) -> Hash {
    let mut msg = Vec::from(PROPOSAL_CONTEXT);
    msg.extend_from_slice(&proposal.encode());
    msg.extend_from_slice(&ext.encode());
    vyrn_crypto::hash::hash(&msg)
}

/// A little-endian cursor that fails on truncation.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TailErr> {
        if self.0.len() < n {
            return Err(TailErr::Length);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, TailErr> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, TailErr> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| TailErr::Length)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, TailErr> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| TailErr::Length)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyrn_types::{BookId, Mode};

    /// Voter `i` has seed `[i + 1; 32]`; `seq_order[j]` has seed `[0x90 + j; 32]`.
    fn seed(i: u8) -> [u8; 32] {
        [i + 1; 32]
    }
    fn seq_seed(j: u8) -> [u8; 32] {
        [0x90 + j; 32]
    }
    fn committee() -> (Committee, Vec<PubKey>) {
        let voters = (0..4)
            .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
            .collect();
        let seq: Vec<_> = (0..3)
            .map(|j| vyrn_crypto::ed25519::public_key(&seq_seed(j)))
            .collect();
        let c = Committee::new(Mode::Base, voters, &seq).unwrap_or_else(|e| panic!("{e}"));
        (c, seq)
    }

    fn tail(contiguous: u64, extra: &[(u64, u64)]) -> Tail {
        let mut t = Tail {
            mark: 0,
            contiguous,
            extra: extra.to_vec(),
            direct: Vec::new(),
        };
        let frames = t.frames().unwrap_or(0);
        t.direct = vec![0xFF; usize::try_from(frames.div_ceil(8)).unwrap_or(0)];
        t
    }

    fn report(reporter: u8, held: u64, a: Tail, b: Tail) -> TailReport {
        TailReport {
            epoch: Epoch(7),
            tenure: 2,
            reporter,
            held_height: Height(held),
            tails: [a, b],
            t_last_rx: 1_000_000 + u64::from(reporter),
            replay_lag_us: 0,
            promotable: false,
        }
    }

    #[test]
    fn silence_round_trips_and_verifies_its_signer() {
        let (c, seq) = committee();
        let mut a = tail(10, &[(12, 14), (20, 20)]);
        a.mark = 4;
        a.direct = vec![0b1010_1010, 0b01];
        let r = report(2, 99, a, tail(3, &[]));
        let s = Silence::sign(0, Reason::Silence, r, &seed(2));
        let bytes = s.encode();
        let back = Silence::decode(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back, s);
        assert_eq!(back.verify(&c, &seq), Ok(Reporter::Voter(2)));
        // The standby signs as n + 1 under its seq_key; it never counts as a voter.
        let r = report(5, 99, tail(3, &[]), tail(3, &[]));
        let s = Silence::sign(0, Reason::Equivocation, r, &seq_seed(1));
        assert_eq!(s.verify(&c, &seq), Ok(Reporter::Standby(1)));
        // Every byte is signed: a changed field or reporter fails.
        let mut forged = back.clone();
        forged.report.held_height.0 += 1;
        assert_eq!(forged.verify(&c, &seq), Err(TailErr::BadSig(2)));
        let mut other = back.clone();
        other.report.reporter = 1;
        assert_eq!(other.verify(&c, &seq), Err(TailErr::BadSig(1)));
        other.report.reporter = 9;
        assert_eq!(other.verify(&c, &seq), Err(TailErr::Unknown(9)));
        // The suspected sequencer (seq_order[0], reporter n + 0) cannot report on itself, even
        // correctly signed.
        let r = report(4, 99, tail(3, &[]), tail(3, &[]));
        let s = Silence::sign(0, Reason::Silence, r, &seq_seed(0));
        assert_eq!(s.verify(&c, &seq), Err(TailErr::Suspected(4)));
        // Truncated, trailing and malformed bytes are refused.
        assert_eq!(
            Silence::decode(&bytes[..bytes.len() - 1]),
            Err(TailErr::Length)
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Silence::decode(&long), Err(TailErr::Length));
        let mut bad = bytes;
        bad[1] = 3;
        assert_eq!(Silence::decode(&bad), Err(TailErr::Reason(3)));
    }

    #[test]
    fn malformed_ranges_are_refused() {
        let (c, seq) = committee();
        // Adjacent ranges after the first gap are well formed: 12..=13 then 14..=15.
        let r = report(0, 1, tail(10, &[(12, 13), (14, 15)]), tail(1, &[]));
        let s = Silence::sign(0, Reason::Silence, r, &seed(0));
        assert_eq!(s.verify(&c, &seq), Ok(Reporter::Voter(0)));
        assert_eq!(Silence::decode(&s.encode()), Ok(s));
        for extra in [
            &[(11, 12)][..],
            &[(14, 13)],
            &[(15, 16), (16, 18)],
            &[(20, 22), (13, 14)],
        ] {
            let r = report(0, 1, tail(10, &[]), tail(1, &[]));
            let mut s = Silence::sign(0, Reason::Silence, r, &seed(0));
            s.report.tails[0].extra = extra.to_vec();
            assert_eq!(s.verify(&c, &seq), Err(TailErr::Ranges), "{extra:?}");
        }
        let mut s = Silence::sign(
            0,
            Reason::Silence,
            report(0, 1, tail(10, &[]), tail(1, &[])),
            &seed(0),
        );
        s.report.tails[1].direct.push(0);
        assert_eq!(s.verify(&c, &seq), Err(TailErr::Direct));
    }

    #[test]
    fn prefix_is_the_union_of_reports_up_to_the_first_hole() {
        // A holds 1..=5; B 1..=3 and 6..=8; C 1..=2 and 10..=12. Frame 9 is held by nobody.
        let reports = vec![
            report(0, 40, tail(5, &[]), tail(7, &[])),
            report(1, 42, tail(3, &[(6, 8)]), tail(2, &[(4, 4)])),
            report(2, 41, tail(2, &[(10, 12)]), tail(0, &[(3, 3)])),
        ];
        let p = prefix(&reports).unwrap_or_else(|| panic!("no prefix"));
        assert_eq!(p.height, Height(42));
        assert_eq!(p.end, [8, 7]);
        assert_eq!(holder(&reports, 0, 7), Some(1));
        assert_eq!(holder(&reports, 0, 9), None);
        assert_eq!(holder(&reports, 0, 11), Some(2));
        // A conflict at frame 6 cuts substream A to 5 and leaves B.
        let mut q = p;
        q.truncate(0, 6);
        assert_eq!(q.end, [5, 7]);
        assert_eq!(prefix(&[]), None);
        assert_eq!(tail_deadline(&reports), Some(1_000_002 + TAIL_WAIT_NS));
    }

    #[test]
    fn holder_prefers_a_direct_copy() {
        // Both hold frame 3 of substream A above mark 0; only reporter 1 received it directly.
        let mut repaired = tail(4, &[]);
        repaired.direct = vec![0b1111_1011];
        let mut direct = tail(4, &[]);
        direct.direct = vec![0b0000_0100];
        let reports = vec![
            report(0, 1, repaired, tail(0, &[])),
            report(1, 1, direct, tail(0, &[])),
        ];
        assert_eq!(holder(&reports, 0, 3), Some(1));
        assert_eq!(holder(&reports, 0, 4), Some(0));
    }

    #[test]
    fn next_seq_is_the_first_promotable_reporter_after_the_deposed() {
        let (c, _) = committee();
        let mut warm = report(4 + 2, 1, tail(0, &[]), tail(0, &[]));
        warm.promotable = true;
        let mut lagging = report(4 + 1, 1, tail(0, &[]), tail(0, &[]));
        lagging.promotable = true;
        lagging.replay_lag_us = PROMOTE_LAG_US + 1;
        // seq_order[1] lags, so seq_order[2] is chosen.
        assert_eq!(
            next_seq(&c, 3, 0, &[0], &[lagging.clone(), warm.clone()]),
            2
        );
        lagging.replay_lag_us = PROMOTE_LAG_US;
        assert_eq!(
            next_seq(&c, 3, 0, &[0], &[lagging.clone(), warm.clone()]),
            1
        );
        // Already deposed this epoch, or no report: skipped. None left: 0xFF.
        assert_eq!(
            next_seq(&c, 3, 0, &[0, 1], &[lagging.clone(), warm.clone()]),
            2
        );
        assert_eq!(next_seq(&c, 3, 0, &[0], &[]), NO_NEXT_SEQ);
        assert_eq!(next_seq(&c, 3, 2, &[0, 2], &[lagging, warm]), NO_NEXT_SEQ);
    }

    #[test]
    fn seal_commits_to_the_header_chain_and_the_extension() {
        let last = BlockHeader {
            height: Height(100),
            epoch: Epoch(7),
            book: BookId(1),
            first_step: StepId(90),
            last_step: StepId(99),
            prev: Hash([1; 32]),
            order_root: Hash([2; 32]),
            data_root: Hash([3; 32]),
            seq_sig: [4; 64],
        };
        let seal = seal_header(&last, StepId(104), Hash([5; 32]), Hash([6; 32]));
        assert_eq!(seal.height, Height(101));
        assert_eq!(seal.first_step, StepId(100));
        assert_eq!(seal.prev, header_hash(&last));
        assert_eq!(seal.seq_sig, [0; 64]);
        let p = seal_proposal(Epoch(7), Height(38), &seal, Hash([0; 32]));
        assert_eq!(p.map(|p| p.heights()), Ok(Some(64)));
        assert_eq!(
            seal_proposal(Epoch(7), Height(37), &seal, Hash([0; 32])),
            Err(ProposalErr::TooLong(65))
        );
        let p = seal_proposal(Epoch(7), Height(98), &seal, Hash([0; 32]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(p.kind, ProposalKind::Seal);
        assert_eq!(p.last_hash, header_hash(&seal));
        let ext = SealExt {
            end_frame_seq: [0x0102, 0x0304],
            next_seq: 1,
            next_tenure: 3,
            unavail: vec![(SessionId(5), 9), (SessionId(5), 10), (SessionId(6), 1)],
        };
        let bytes = ext.encode();
        assert_eq!(bytes.len(), 16 + 1 + 1 + 4 + 3 * 8);
        assert_eq!(&bytes[0..2], &[0x02, 0x01]);
        assert_eq!(SealExt::decode(&bytes), Ok(ext.clone()));
        assert_eq!(
            SealExt::decode(&bytes[..bytes.len() - 1]),
            Err(TailErr::Length)
        );
        let mut unsorted = ext.clone();
        unsorted.unavail.swap(0, 1);
        assert_eq!(SealExt::decode(&unsorted.encode()), Err(TailErr::Ranges));
        // The digest covers the extension and is not the kind-0 digest of the same proposal.
        let mut other = ext.clone();
        other.next_seq = NO_NEXT_SEQ;
        assert_ne!(seal_digest(&p, &ext), seal_digest(&p, &other));
        assert_ne!(seal_digest(&p, &ext), p.digest());
        let mut plain = Vec::from(PROPOSAL_CONTEXT);
        plain.extend_from_slice(&p.encode());
        plain.extend_from_slice(&bytes);
        assert_eq!(seal_digest(&p, &ext), vyrn_crypto::hash::hash(&plain));
    }
}
