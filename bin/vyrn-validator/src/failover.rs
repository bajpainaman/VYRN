//! Data box failure, the replica side (07 §5.7 steps 1–3).
//!
//! **Step 1.** A replica marks data box `d` down when its feed has heard from it once and then
//! nothing for `REP_DATA_SILENCE_MS` (1 ms; `[data] silence_us`, DEV only, for unpinned hosts),
//! and gossips `DataDown{d}` to its `[[data.peer]]`s, again every [`GOSSIP_EVERY_NS`] while `d`
//! stays silent, effective or not (UDP: a peer that lost one must still reach Q). `d` is effective once [`Failover::quorum`] distinct voters, this one
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
//! repeats by DR2). The rounds queue up and leave [`REDIRECT_BATCH`] per [`GOSSIP_EVERY_NS`],
//! oldest first, under a box's fetch bucket (`vyrn-data` defaults: burst 256, 20 000/s), so no
//! session is starved by a long list. *Reading:* `resend_from` is the session's lowest `pkt_seq` in a block this
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
//! It counts only as the vote of the voter it names ([`DownAuth`]): keyed, the tag must verify
//! under that voter's peer key, from its `repl_addr` IPv4; unkeyed (DEV), the voter must be a
//! `[[data.peer]]` at the source IPv4 and the tag 0. A keyed DEV replica also takes tag 0 from a
//! configured peer whose roster key is unusable, as it sends that peer unsealed fetches.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;

use vyrn_types::SessionId;

pub const MAGIC: u16 = 0x4444;
const VERSION: u8 = 1;
pub const BYTES: usize = 24;
/// Gossip and redirect resend period (reading).
pub const GOSSIP_EVERY_NS: u64 = 10_000_000;
/// How many times each redirect round goes out (reading).
pub const REDIRECT_ROUNDS: u8 = 3;
/// Every session's home before any move: entry 0 of its `KeyBundle.data` (reading s).
const FIRST_HOME: u8 = 0;
/// REDIRECTs sent per [`GOSSIP_EVERY_NS`] to each live box (reading): 12 800/s with bursts of
/// 128, under `vyrn-data`'s default fetch bucket.
/// Limit (07 §5.7, open): the first round of `n` sessions takes `n / 12 800` s, so above about
/// 1 200 sessions per home box it can outlast the clients' 100 ms retention (04 DR4).
pub const REDIRECT_BATCH: usize = 128;

/// Who a peer's `DataDown` may come from (module docs).
pub struct DownAuth {
    /// `[[data.peer]]`: voter index and IPv4.
    peers: Vec<(u8, Ipv4Addr)>,
    /// Keyed: every peer key of the window, by voter index and IPv4; `None` unkeyed (DEV).
    keys: Option<Vec<(u8, Ipv4Addr, [u8; 16])>>,
    /// Keyed DEV: the configured peers with no usable roster key.
    open: Vec<u8>,
}

impl DownAuth {
    pub fn new(peers: Vec<(u8, Ipv4Addr)>) -> Self {
        Self {
            peers,
            keys: None,
            open: Vec::new(),
        }
    }

    /// A keyed replica's keys; `sealed[i]` is the key it seals to `peers[i]` with, `None` for a
    /// peer whose roster key is unusable.
    pub fn set_keys(&mut self, keys: Vec<(u8, Ipv4Addr, [u8; 16])>, sealed: &[Option<[u8; 16]>]) {
        self.open = self
            .peers
            .iter()
            .zip(sealed)
            .filter(|(_, k)| k.is_none())
            .map(|((v, _), _)| *v)
            .collect();
        self.keys = Some(keys);
    }

    /// Whether `voter` sent this `body` and `tag` from `from`. The voter must be a configured
    /// peer: the roster's peer keys also cover its `vyrn-seq` boxes (requester indices after the
    /// voters), which cast no vote (Vercel r4612778821).
    pub fn authentic(&self, from: Ipv4Addr, voter: u8, body: &[u8], tag: u64) -> bool {
        let configured = self.peers.contains(&(voter, from));
        match &self.keys {
            None => configured && tag == 0,
            Some(_) if !self.peers.iter().any(|(v, _)| *v == voter) => false,
            Some(keys) => {
                (configured && tag == 0 && self.open.contains(&voter))
                    || keys.iter().any(|(v, ip, k)| {
                        *v == voter
                            && *ip == from
                            && vyrn_crypto::siphash::verify(k, body, vyrn_types::Tag(tag))
                    })
            }
        }
    }
}

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
    /// Queued REDIRECTs `(session, resend_from, down, to)`, and when the next batch may leave.
    outbox: VecDeque<(SessionId, u32, u8, u8)>,
    next_batch: u64,
    /// Whether the home moved, and the sessions queued a REDIRECT for its last move: a session
    /// first released after the rounds is queued then (Codex r4612821618), from the home every
    /// session starts on to the current one, since it has followed no move (Codex r4612923593).
    moved: bool,
    redirected: BTreeSet<SessionId>,
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
            home: FIRST_HOME,
            rounds: Vec::new(),
            outbox: VecDeque::new(),
            next_batch: 0,
            moved: false,
            redirected: BTreeSet::new(),
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
            if i >= self.effective.len() {
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

    /// A peer's authenticated `DataDown` ([`DownAuth`]); the caller checked `m.voter`. *Reading:* one of epoch `e - 1`, `e` or `e + 1` counts,
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
                    self.moved = true;
                    self.redirected.clear();
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

    /// Queues one round of REDIRECTs for `list`.
    pub fn queue(&mut self, down: u8, to: u8, list: &[(SessionId, u32)]) {
        self.redirected.extend(list.iter().map(|&(s, _)| s));
        self.outbox
            .extend(list.iter().map(|&(s, r)| (s, r, down, to)));
    }

    /// The REDIRECTs to send now: at most [`REDIRECT_BATCH`] per [`GOSSIP_EVERY_NS`].
    pub fn batch(&mut self, now: u64) -> Vec<(SessionId, u32, u8, u8)> {
        if self.outbox.is_empty() || now < self.next_batch {
            return Vec::new();
        }
        self.next_batch = now.saturating_add(GOSSIP_EVERY_NS);
        let n = self.outbox.len().min(REDIRECT_BATCH);
        self.outbox.drain(..n).collect()
    }

    /// A released block at `height` with these client records' `(session, pkt_seq)`.
    pub fn released(&mut self, height: u64, recs: impl IntoIterator<Item = (SessionId, u32)>) {
        let mut m = SeqSpan::new();
        for (s, p) in recs {
            let e = m.entry(s).or_insert((p, p));
            *e = (e.0.min(p), e.1.max(p));
        }
        // After a home move, a session not redirected yet gets its rounds now, from its lowest
        // `pkt_seq` in this block, which is not final yet (reading t).
        if self.moved {
            for (s, (lo, _)) in &m {
                if self.redirected.insert(*s) {
                    for _ in 0..REDIRECT_ROUNDS {
                        self.outbox.push_back((*s, *lo, FIRST_HOME, self.home));
                    }
                }
            }
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
        // Codex r4612686942: gossip goes on after the box is effective, for peers short of Q.
        let mut g = Failover::new(1, 0, 1, 0, 1);
        assert_eq!(g.silent(&[0], 0).len(), 1);
        assert_eq!(g.step(0).0, vec![(0, 1)]);
        assert_eq!(
            g.silent(&[0], GOSSIP_EVERY_NS).len(),
            1,
            "still gossiped when effective"
        );
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

    /// Codex r4612686917: a DataDown counts only as the voter whose key, IP and peer entry match.
    #[test]
    fn data_down_is_bound_to_its_voter() {
        let (a, b) = (Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        let (ka, kb) = ([1u8; 16], [2u8; 16]);
        let m = |voter| DataDown {
            d: 0,
            voter,
            epoch: 0,
        };
        let tagged = |voter, k: &[u8; 16]| {
            let (_, body, tag) = DataDown::parse(&m(voter).encode(Some(k))).unwrap();
            (body, tag)
        };
        let mut auth = DownAuth::new(vec![(1, a), (2, b), (3, a)]);
        // Unkeyed (DEV): a configured (voter, IP) with tag 0 only.
        let (body, _) = tagged(1, &ka);
        assert!(auth.authentic(a, 1, &body, 0));
        assert!(!auth.authentic(b, 1, &body, 0), "voter 1 is not at b");
        assert!(!auth.authentic(a, 4, &body, 0), "voter 4 is not a peer");
        // Keyed: voter 1's key at a; voter 3 has no usable key (DEV open).
        auth.set_keys(vec![(1, a, ka), (2, b, kb)], &[Some(ka), Some(kb), None]);
        let (body, tag) = tagged(1, &ka);
        assert!(auth.authentic(a, 1, &body, tag));
        let (body2, tag2) = tagged(2, &ka);
        assert!(
            !auth.authentic(a, 2, &body2, tag2),
            "voter 1 claiming voter 2"
        );
        assert!(!auth.authentic(a, 1, &body, 0), "a keyed peer's tag 0");
        let (body3, _) = tagged(3, &ka);
        assert!(
            auth.authentic(a, 3, &body3, 0),
            "an unusable-key peer in DEV"
        );
        // Vercel r4612778821: a keyed seq box (requester 4, after the voters) is not a voter.
        let ks = [4u8; 16];
        auth.set_keys(
            vec![(1, a, ka), (2, b, kb), (4, b, ks)],
            &[Some(ka), Some(kb), None],
        );
        let (body4, tag4) = tagged(4, &ks);
        assert!(!auth.authentic(b, 4, &body4, tag4), "a seq box's DataDown");
    }

    /// Codex r4612686954: rounds queue; each period sends at most a batch, oldest first, so a
    /// later round never restarts ahead of sessions not yet sent.
    #[test]
    fn redirects_leave_in_paced_batches() {
        let mut f = Failover::new(2, 0, 1, 0, 1);
        let list: Vec<(SessionId, u32)> = (0..300).map(|i| (SessionId(i), 1)).collect();
        f.queue(0, 1, &list);
        f.queue(0, 1, &list);
        let b1 = f.batch(5);
        assert_eq!(b1.len(), REDIRECT_BATCH);
        assert!(f.batch(6).is_empty(), "the next batch waits a period");
        let b2 = f.batch(5 + GOSSIP_EVERY_NS);
        let b3 = f.batch(5 + 2 * GOSSIP_EVERY_NS);
        assert_eq!(b2.first().map(|r| r.0), Some(SessionId(128)));
        assert_eq!(b3.first().map(|r| r.0), Some(SessionId(256)));
        assert_eq!(
            b3.get(44).map(|r| r.0),
            Some(SessionId(0)),
            "round 2 after round 1"
        );
    }

    /// Codex r4612821618: a session first released after the home moved is queued then, once.
    #[test]
    fn a_late_session_is_redirected() {
        let mut f = Failover::new(2, 0, 1, 0, 1);
        f.released(1, [(SessionId(5), 3)]);
        f.silent(&[0], 0);
        assert_eq!(f.step(0).1, vec![(0, 1)]);
        f.queue(0, 1, &f.resend_from(&BTreeMap::new()));
        f.released(2, [(SessionId(9), 7), (SessionId(9), 6), (SessionId(5), 4)]);
        let sent = f.batch(0);
        let late: Vec<_> = sent.iter().filter(|r| r.0 == SessionId(9)).collect();
        assert_eq!(late.len(), usize::from(REDIRECT_ROUNDS));
        assert!(late.iter().all(|r| (r.1, r.2, r.3) == (6, 0, 1)));
        assert_eq!(
            sent.len(),
            1 + usize::from(REDIRECT_ROUNDS),
            "session 5 not again"
        );
        f.released(3, [(SessionId(9), 8)]);
        assert!(f.batch(GOSSIP_EVERY_NS).is_empty(), "queued once");
    }

    /// Codex r4612923593: after 0 → 1 and 1 → 2, a late session still sends to box 0, so its
    /// redirect is 0 → 2 (DR2 drops a 1 → 2 one).
    #[test]
    fn a_late_session_moves_from_its_first_home() {
        let mut f = Failover::new(3, 0, 1, 0, 1);
        f.silent(&[0], 0);
        assert_eq!(f.step(0).1, vec![(0, 1)]);
        f.silent(&[1], 1);
        assert_eq!(f.step(1).1, vec![(1, 2)]);
        f.released(1, [(SessionId(9), 4)]);
        let sent = f.batch(0);
        assert!(!sent.is_empty());
        assert!(sent.iter().all(|r| (r.1, r.2, r.3) == (4, 0, 2)));
    }

    /// The bound 07 §5.7 records (open; the batched REDIRECT lifts it): 2 000 sessions of one
    /// home queued at once, 2 ms after the failure. Clients keep sent packets for 100 ms (04
    /// DR4), so a session's first REDIRECT must leave by 98 ms; at [`REDIRECT_BATCH`] per
    /// [`GOSSIP_EVERY_NS`] only 10 batches do. The batch PR flips the last assertion.
    #[test]
    fn first_round_outlasts_dr4_above_the_bound() {
        const RETAIN_NS: u64 = 100_000_000;
        const DETECT_NS: u64 = 2_000_000;
        let mut f = Failover::new(2, 0, 1, 0, 1);
        let list: Vec<(SessionId, u32)> = (0..2000).map(|i| (SessionId(i), 1)).collect();
        f.queue(0, 1, &list);
        let mut in_time = 0usize;
        let mut t = 0;
        while t + DETECT_NS <= RETAIN_NS {
            in_time += f.batch(t).len();
            t += GOSSIP_EVERY_NS;
        }
        assert_eq!(
            in_time,
            10 * REDIRECT_BATCH,
            "about 1 200 sessions fit DR4's window"
        );
        assert!(
            in_time < list.len(),
            "2 000 sessions do not (07 §5.7 limit)"
        );
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
