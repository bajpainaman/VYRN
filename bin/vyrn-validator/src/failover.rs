//! Data box failure, the replica side (07 §5.7 steps 1–3).
//!
//! **Step 1.** A replica marks data box `d` down when its feed has heard from it once and then
//! nothing for `REP_DATA_SILENCE_MS` (1 ms; `[data] silence_us`, DEV only, for unpinned hosts),
//! and gossips `DataDown{d}` to its `[[data.peer]]`s, again every [`GOSSIP_EVERY_NS`] while `d`
//! is not effective (UDP). `d` is effective once [`Failover::quorum`] distinct voters, this one
//! included, sent it. A vote is kept for the run (reading: 07 names no withdrawal), and one tagged
//! `e - 1`, `e` or `e + 1` counts (reading: peers cross an epoch boundary one at a time).
//!
//! **Step 2.** The sessions homed on `d` move to `backup_home(d, live)`. *Reading (DEV):* until a
//! session's `KeyBundle` reaches the replica, every session's `KeyBundle.data` list is
//! `[data] boxes` in order and its home is entry 0, so positions are box indices, and an
//! effective `d` that is the current home moves every session the replica knows.
//!
//! **Step 3.** For each such session the replica sends every live box one REDIRECT fetch
//! (`vyrn-data` kind 4) with its `resend_from`, sealed under that box's `K_fetch` like any fetch,
//! [`REDIRECT_ROUNDS`] times [`GOSSIP_EVERY_NS`] apart (UDP; boxes act on each, clients drop the
//! repeats by DR2). *Reading:* `resend_from` is the session's lowest `pkt_seq` in a block this
//! replica holds that is not final yet, resolved here or not, else one past the highest in a
//! final block. A replica sees only its own joins: a final block's payloads were resolved by Q
//! replicas (vote-rule item 3), so the rest fetch them from peers, but one this replica got by
//! repair before finality may be held by no other. The first redirect to reach the client wins
//! (07 §5.7), and the data tier dedupes what it resends.
//!
//! **`DataDown` bytes** (*reading*, wire; 07 names none), 24 bytes little-endian, sent to a peer's
//! `[nic] data_port` like a peer fetch:
//!
//! ```text
//! off size field
//!   0   2  magic 0x4444 ("DD")   2 1 version 1   3 1 d   4 1 voter   5 3 zero
//!   8   4  epoch               12 4 zero
//!  16   8  tag = SipHash-2-4(K, bytes 0..16), K = the sender's peer K_fetch toward this voter;
//!          0 from an unkeyed (DEV) sender
//! ```
//!
//! A keyed replica takes it only under a key of a requester at the source IPv4 (as a peer fetch,
//! `fetch::PeerServer`); an unkeyed one only from a configured peer IP with a zero tag.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vyrn_types::SessionId;

pub const MAGIC: u16 = 0x4444;
const VERSION: u8 = 1;
pub const BYTES: usize = 24;
/// Gossip and redirect resend period (reading).
pub const GOSSIP_EVERY_NS: u64 = 10_000_000;
/// How many times each redirect round goes out (reading).
pub const REDIRECT_ROUNDS: u8 = 3;

/// `DataDown{d}` from voter `voter` in `epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataDown {
    pub d: u8,
    pub voter: u8,
    pub epoch: u32,
}

impl DataDown {
    fn body(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        b[2] = VERSION;
        b[3] = self.d;
        b[4] = self.voter;
        b[8..12].copy_from_slice(&self.epoch.to_le_bytes());
        b
    }

    /// The 24 bytes, tagged under `key` (`None`: a zero tag, DEV).
    pub fn encode(&self, key: Option<&[u8; 16]>) -> [u8; BYTES] {
        let body = self.body();
        let tag = key.map_or(0, |k| vyrn_crypto::siphash24(k, &body).0);
        let mut b = [0u8; BYTES];
        b[..16].copy_from_slice(&body);
        b[16..].copy_from_slice(&tag.to_le_bytes());
        b
    }

    /// Parses the fields and returns them with the body and tag for the caller to check; `None`
    /// if the bytes are not a `DataDown`.
    pub fn parse(b: &[u8]) -> Option<(Self, [u8; 16], u64)> {
        let b: &[u8; BYTES] = b.try_into().ok()?;
        let mut body = [0u8; 16];
        body.copy_from_slice(&b[..16]);
        let mut t = [0u8; 8];
        t.copy_from_slice(&b[16..]);
        let m = Self {
            d: b[3],
            voter: b[4],
            epoch: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        };
        (u16::from_le_bytes([b[0], b[1]]) == MAGIC
            && b[2] == VERSION
            && b[5..8] == [0; 3]
            && b[12..16] == [0; 4]
            && body == m.body())
        .then_some((m, body, u64::from_le_bytes(t)))
    }
}

/// Counters printed at exit (`FAILOVER ...`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub down_sent: u64,
    pub down_heard: u64,
    pub down_bad: u64,
    pub effective: u64,
    pub redirects: u64,
}

/// [`Failover::step`]'s result: boxes newly effective with their vote counts, and redirect
/// rounds due as `(down, to)`.
pub type Step = (Vec<(u8, usize)>, Vec<(u8, u8)>);

/// Each session's lowest and highest `pkt_seq` in one block.
type SeqSpan = BTreeMap<SessionId, (u32, u32)>;

/// One replica's view of the data boxes' failures.
pub struct Failover {
    me: u8,
    quorum: usize,
    pub epoch: u32,
    pub silence_ns: u64,
    votes: Vec<BTreeSet<u8>>,
    effective: Vec<bool>,
    gossiped: Vec<Option<u64>>,
    /// Every session's current home position (step 2 reading).
    home: u8,
    /// Redirect rounds still to send: `(down, to, rounds left, next at)`.
    rounds: Vec<(u8, u8, u8, u64)>,
    /// The highest `pkt_seq` per session in a final block.
    final_max: BTreeMap<SessionId, u32>,
    /// Released blocks not final yet: height and each session's lowest and highest `pkt_seq`.
    unfinal: VecDeque<(u64, SeqSpan)>,
    pub counts: Counts,
}

impl Failover {
    pub fn new(n_boxes: u8, me: u8, quorum: usize, epoch: u32, silence_ns: u64) -> Self {
        let n = usize::from(n_boxes);
        Self {
            me,
            quorum,
            epoch,
            silence_ns,
            votes: vec![BTreeSet::new(); n],
            effective: vec![false; n],
            gossiped: vec![None; n],
            home: 0,
            rounds: Vec::new(),
            final_max: BTreeMap::new(),
            unfinal: VecDeque::new(),
            counts: Counts::default(),
        }
    }

    pub fn quorum(&self) -> usize {
        self.quorum
    }

    /// Whether box `d` is live (not effectively down).
    pub fn live(&self, d: usize) -> bool {
        !self.effective.get(d).copied().unwrap_or(true)
    }

    /// The boxes this replica finds `silent` at `now`: its own vote, and the `DataDown`s to
    /// gossip now.
    pub fn silent(&mut self, silent: &[u8], now: u64) -> Vec<DataDown> {
        let mut out = Vec::new();
        for &d in silent {
            let i = usize::from(d);
            if self.effective.get(i).copied().unwrap_or(true) {
                continue;
            }
            if let Some(v) = self.votes.get_mut(i) {
                v.insert(self.me);
            }
            let due = self
                .gossiped
                .get(i)
                .copied()
                .flatten()
                .is_none_or(|t| now.saturating_sub(t) >= GOSSIP_EVERY_NS);
            if due {
                if let Some(g) = self.gossiped.get_mut(i) {
                    *g = Some(now);
                }
                out.push(DataDown {
                    d,
                    voter: self.me,
                    epoch: self.epoch,
                });
            }
        }
        out
    }

    /// A peer's authenticated `DataDown`. *Reading:* one of epoch `e - 1`, `e` or `e + 1` counts,
    /// as peers cross a boundary one at a time (the peer-key window, 07 §5.5 (l)); one of
    /// another epoch or an unknown box counts as bad.
    pub fn heard(&mut self, m: DataDown) {
        match self.votes.get_mut(usize::from(m.d)) {
            Some(v) if m.epoch.abs_diff(self.epoch) <= 1 => {
                v.insert(m.voter);
                self.counts.down_heard = self.counts.down_heard.saturating_add(1);
            }
            _ => self.counts.down_bad = self.counts.down_bad.saturating_add(1),
        }
    }

    /// Boxes that just became effective (each once), and the redirect rounds due at `now` as
    /// `(down, to)`. An effective box that is the sessions' home starts [`REDIRECT_ROUNDS`].
    pub fn step(&mut self, now: u64) -> Step {
        let mut newly = Vec::new();
        for (i, v) in self.votes.iter().enumerate() {
            if v.len() >= self.quorum && !self.effective.get(i).copied().unwrap_or(true) {
                newly.push((u8::try_from(i).unwrap_or(u8::MAX), v.len()));
            }
        }
        for &(d, _) in &newly {
            if let Some(e) = self.effective.get_mut(usize::from(d)) {
                *e = true;
            }
            self.counts.effective = self.counts.effective.saturating_add(1);
            if d == self.home {
                let live: Vec<bool> = self.effective.iter().map(|e| !e).collect();
                if let Some(to) = vyrn_data::redirect::backup_home(d, &live) {
                    self.home = to;
                    self.rounds.push((d, to, REDIRECT_ROUNDS, now));
                }
            }
        }
        let mut due = Vec::new();
        for r in &mut self.rounds {
            if r.2 > 0 && now >= r.3 {
                due.push((r.0, r.1));
                r.2 -= 1;
                r.3 = now.saturating_add(GOSSIP_EVERY_NS);
            }
        }
        self.rounds.retain(|r| r.2 > 0);
        (newly, due)
    }

    /// A released block at `height` with these client records' `(session, pkt_seq)`.
    pub fn released(&mut self, height: u64, recs: impl IntoIterator<Item = (SessionId, u32)>) {
        let mut m = SeqSpan::new();
        for (s, p) in recs {
            let e = m.entry(s).or_insert((p, p));
            *e = (e.0.min(p), e.1.max(p));
        }
        self.unfinal.push_back((height, m));
    }

    /// Finality reached `height`: the released blocks up to it are final.
    pub fn finalized(&mut self, height: u64) {
        while self.unfinal.front().is_some_and(|(h, _)| *h <= height) {
            let Some((_, m)) = self.unfinal.pop_front() else {
                break;
            };
            for (s, (_, hi)) in m {
                let e = self.final_max.entry(s).or_insert(hi);
                *e = (*e).max(hi);
            }
        }
    }

    /// Each known session's `resend_from`: its lowest `pkt_seq` in `unresolved` (the pending
    /// blocks) or a released block not final yet, else one past the highest in a final block.
    pub fn resend_from(&self, unresolved: &BTreeMap<SessionId, u32>) -> Vec<(SessionId, u32)> {
        let mut out: BTreeMap<SessionId, u32> = self
            .final_max
            .iter()
            .map(|(s, p)| (*s, p.saturating_add(1)))
            .collect();
        let mut low: BTreeMap<SessionId, u32> = unresolved.clone();
        for (s, (lo, _)) in self.unfinal.iter().flat_map(|(_, m)| m) {
            let e = low.entry(*s).or_insert(*lo);
            *e = (*e).min(*lo);
        }
        out.extend(low);
        out.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn data_down_round_trips_and_tags() {
        let m = DataDown {
            d: 1,
            voter: 3,
            epoch: 7,
        };
        let k = [9u8; 16];
        let b = m.encode(Some(&k));
        let (p, body, tag) = DataDown::parse(&b).unwrap();
        assert_eq!(p, m);
        assert!(vyrn_crypto::siphash::verify(
            &k,
            &body,
            vyrn_types::Tag(tag)
        ));
        assert_eq!(DataDown::parse(&m.encode(None)).unwrap().2, 0);
        let mut bad = b;
        bad[5] = 1;
        assert!(DataDown::parse(&bad).is_none(), "reserved bytes");
        assert!(DataDown::parse(&b[..23]).is_none());
    }

    /// Q votes make a box effective once; a home box starts the redirect rounds to the next
    /// live box, and a non-home box moves nobody.
    #[test]
    fn quorum_makes_down_effective_and_moves_the_home() {
        let mut f = Failover::new(3, 0, 3, 0, 1);
        let dd = |d, voter| DataDown { d, voter, epoch: 0 };
        assert_eq!(f.silent(&[0], 0).len(), 1);
        assert!(f.silent(&[0], 1).is_empty(), "gossip waits a period");
        f.heard(dd(0, 1));
        assert_eq!(f.step(2), (vec![], vec![]), "two of three");
        f.heard(dd(0, 1));
        f.heard(DataDown {
            epoch: 2,
            ..dd(0, 2)
        });
        assert_eq!(
            f.step(3).0,
            vec![],
            "a repeat and a non-adjacent epoch do not count"
        );
        // A peer one epoch ahead (it crossed the boundary first) counts.
        f.heard(DataDown {
            epoch: 1,
            ..dd(0, 2)
        });
        assert_eq!(f.step(4), (vec![(0, 3)], vec![(0, 1)]));
        assert!(!f.live(0) && f.live(1));
        assert_eq!(f.step(5), (vec![], vec![]), "next round waits a period");
        assert_eq!(f.step(4 + GOSSIP_EVERY_NS).1, vec![(0, 1)]);
        // Box 2 is not the home: effective, but no redirects.
        for v in 0..3 {
            f.heard(dd(2, v));
        }
        let (newly, due) = f.step(5 + GOSSIP_EVERY_NS);
        assert_eq!(newly, vec![(2, 3)]);
        assert!(due.is_empty());
        assert_eq!(f.counts.down_bad, 1);
    }

    /// Session 5 is final through 9, so past it; 6 has a released block not final yet below
    /// its unresolved record, which wins; 7 only an unresolved one; 8 only a final block.
    #[test]
    fn resend_from_is_the_lowest_not_final_else_past_the_final() {
        let mut f = Failover::new(2, 0, 1, 0, 1);
        let (s5, s6, s7, s8) = (SessionId(5), SessionId(6), SessionId(7), SessionId(8));
        f.released(1, [(s5, 9), (s5, 4), (s8, 2)]);
        f.released(2, [(s6, 2), (s6, 5)]);
        f.released(3, [(s5, 11)]);
        f.finalized(1);
        let unresolved = BTreeMap::from([(s6, 7), (s7, 1)]);
        assert_eq!(
            f.resend_from(&unresolved),
            vec![(s5, 11), (s6, 2), (s7, 1), (s8, 3)]
        );
        f.finalized(3);
        assert_eq!(
            f.resend_from(&BTreeMap::new()),
            vec![(s5, 12), (s6, 6), (s8, 3)]
        );
    }
}
