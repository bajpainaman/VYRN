//! Fetching a missing payload from its three sources (07 §5.5), and serving peers' fetches.
//!
//! **Escalation** ([`Sources`], reading (b), accepted). A payload a pending block still misses
//! `REP_DATA_WAIT_US` = 300 µs after it was first seen missing is fetched by key from source 1,
//! every configured data box (no session-to-data-home map yet). Each further `REP_DATA_WAIT_US`
//! without it moves to the next source: 2, one peer replica in round-robin order
//! (`PeerDataFetch`), then 3, the sequencer's repair port (`SeqDataReq`), then back to 1. A
//! source that is not configured is skipped. Every missing key has its own escalation. The
//! front block's first missing key escalates alone until it is [`Sources::stuck`] (a data
//! box answered its KEY fetch with a miss: it was lost at its box); then every key the pending blocks miss
//! escalates at once, so a burst of lost packets reaches source 3 within one escalation, not
//! one after another: the sequencer retains a packet only `REP_SEQ_PKT_RETAIN_MS` = 50 ms
//! (07 §5.5, reading (j)). A replica catching up, whose data is still arriving by RANGE, keeps
//! asking for one key.
//! A round ([`Sources::begin_round`]) runs at most every [`ROUND_NS`], examines at most
//! [`FETCH_SCAN_MAX`] pending records and asks at most [`FETCH_KEYS_MAX`] keys, starting where
//! the last round stopped ([`Sources::scan_start`], [`Sources::scanned`]), so every missing key
//! gets its turn however long the backlog; a key is forgotten after two full cycles of the scan
//! that do not name it.
//!
//! **`PeerDataFetch`** (reading (a), accepted). The request is the same KEY fetch as `DataFetch`
//! and `SeqDataReq`. A replica answers on its data port, so `[[data.peer]]` lists the peers'
//! `[nic] data_port` addresses. The answer is `FETCH_RESP` data frames with `src` [`PEER_SRC`],
//! `data_seq = session << 32 | pkt_seq`, the first variant's `book` and `epoch16`: every variant
//! the replica holds of the key, as many frames as they need (reading (g)); a miss is one frame
//! with no packets and `book`, `epoch16` 0. These are the sequencer's bytes, so the requester's
//! `DataFeed` takes them as it takes any `FETCH_RESP`, and the join checks them by `pkt_hash`.
//!
//! **Held for peers** (reading (f)). A replica releases a block's payloads once it is checked
//! and replayed (07 §5.4), possibly before a slower peer asks. [`PeerServer::keep`] copies each
//! released payload into a FIFO of the last [`PEER_KEEP`] payloads, which serving reads with the
//! live join.
//!
//! **Sealed** (reading (c), accepted; 08 §9.6). With `[data] xchg` every KEY fetch [`send_key`]
//! sends is the 40-byte form under its target's `K_fetch`: `d` a data box, `SEQ_TARGET + j` for
//! `vyrn-seq` box `j`, `VOTER_TARGET + j` for peer voter `j` under the context
//! `"vyrn      v1 peerfetch"`. A keyed [`PeerServer`] serves only fetches that open under the
//! key of a requester at the source's IPv4 (it tries each: DEV hosts share 127.0.0.1); an
//! unkeyed one serves the 32-byte form from configured peer IPs only.
//!
//! **Refused** with no answer, counted `bad`: a requester that fails the above, and a RANGE or
//! BLOCK fetch (only data boxes serve those). **Rate** (reading (d)): one bucket per replica of
//! `REP_SEQ_DATA_MAX_PPS` = 50k packets/s, 10 ms of tokens; an answer takes one token per packet
//! and a miss one. A request with no token is counted `limited` and not answered; one with
//! fewer tokens than variants gets what they buy, and the next resumes after it (reading (i)).

use std::collections::{BTreeMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use vyrn_data::frame::{DataHdr, Fetch, FrameBuf, Kind, key_seq, seal_fetch};
use vyrn_log::LaneRec;
use vyrn_replica::DataJoin;
use vyrn_types::{BookId, PacketFlags, SessionId};

/// `REP_DATA_WAIT_US` (07 §5.5): how long each source gets before the next is asked.
pub const REP_DATA_WAIT_NS: u64 = 300_000;
/// The `src` of a replica's `FETCH_RESP` to a peer: no data box index takes it, nor the
/// sequencer's 0xFF.
pub const PEER_SRC: u8 = 0xFE;
/// Released payloads a replica holds for its peers (reading (f)).
pub const PEER_KEEP: usize = 16_384;
/// `REP_SEQ_DATA_MAX_PPS`, reused as each replica's peer-serving rate (reading (d)).
const PEER_MAX_PPS: u64 = 50_000;
const BURST_NS: u64 = 10_000_000;
/// Missing keys one round of [`Sources`] asks for at most (reading (j)). Rounds are
/// [`ROUND_NS`] apart and a key is asked every `REP_DATA_WAIT_US`, so 3 rounds ask 96 keys: an
/// 89-packet burst reaches source 3 in one escalation.
pub const FETCH_KEYS_MAX: usize = 32;
/// Pending records one round examines at most; the next round goes on from there (Codex
/// r4618145217). Small, so the scan stays a few µs of the order thread's time: 4,096 every
/// 100 µs stopped a restarted voter at `REP_E_HASHLAG` while it caught up.
pub const FETCH_SCAN_MAX: usize = 256;
/// The least time between two rounds, so a replica far behind (catching up from a restart) does
/// not rescan its pending blocks on every poll.
pub const ROUND_NS: u64 = 100_000;
const SEC: u64 = 1_000_000_000;

/// Fetches sent and served, printed at exit as `FETCH box=<n> peer=<n> seq=<n>
/// served=<n> missed=<n> limited=<n> bad=<n>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub boxes: u64,
    pub peer: u64,
    pub seq: u64,
    pub served: u64,
    pub missed: u64,
    pub limited: u64,
    pub bad: u64,
}

/// Where a KEY fetch goes, and the `K_fetch` it is sealed under (`None`: the 32-byte form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddrV4,
    pub key: Option<[u8; 16]>,
}

/// One of 07 §5.5's sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Boxes,
    Peer,
    Seq,
}

/// One missing key's escalation.
#[derive(Clone, Copy, Debug)]
struct Esc {
    /// The stage asked last (`None`: not asked yet), and since when.
    last: Option<Stage>,
    at: u64,
    /// The scan cycle that last named it.
    round: u64,
    /// Its own peer cursor, so each key turns through every peer whatever the other keys do
    /// (Vercel r4617946666).
    peer: usize,
    /// A data box answered its KEY fetch with a miss (an empty `FETCH_RESP`).
    box_missed: bool,
}

/// The fetch sources and the escalation of each missing key the pending blocks wait for.
pub struct Sources {
    boxes: Vec<Target>,
    peers: Vec<Target>,
    seq: Option<Target>,
    next_peer: usize,
    /// Per missing key, its escalation.
    missing: BTreeMap<(SessionId, u32), Esc>,
    /// Scan cycles: one ends each time the scan passes the last pending record.
    round: u64,
    /// Where the next scan starts: a pending block's height and a record index in it.
    scan_at: (u64, usize),
    /// When the last round began (`None`: none yet).
    round_at: Option<u64>,
    pub counts: Counts,
}

impl Sources {
    pub fn new(boxes: Vec<Target>, peers: Vec<Target>, seq: Option<Target>) -> Self {
        Self {
            boxes,
            peers,
            seq,
            next_peer: 0,
            missing: BTreeMap::new(),
            round: 0,
            scan_at: (0, 0),
            round_at: None,
            counts: Counts::default(),
        }
    }

    /// The peer targets, with the keys this replica seals to them under.
    pub fn peers(&self) -> &[Target] {
        &self.peers
    }

    /// A new epoch's keys (`EPOCH <e>`), by the same index as the targets they seal for.
    pub fn set_keys(
        &mut self,
        boxes: &[[u8; 16]],
        peers: &[Option<[u8; 16]>],
        seq: Option<[u8; 16]>,
    ) {
        for (t, k) in self.boxes.iter_mut().zip(boxes) {
            t.key = Some(*k);
        }
        for (t, k) in self.peers.iter_mut().zip(peers) {
            t.key = *k;
        }
        if let Some(t) = self.seq.as_mut() {
            t.key = seq;
        }
    }

    fn configured(&self, s: Stage) -> bool {
        match s {
            Stage::Boxes => !self.boxes.is_empty(),
            Stage::Peer => !self.peers.is_empty(),
            Stage::Seq => self.seq.is_some(),
        }
    }

    /// Starts a round of [`Sources::due`] calls at `now`, unless one began less than
    /// [`ROUND_NS`] ago: then `false`, and the caller skips this round.
    pub fn begin_round(&mut self, now: u64) -> bool {
        if self
            .round_at
            .is_some_and(|t| now.saturating_sub(t) < ROUND_NS)
        {
            return false;
        }
        self.round_at = Some(now);
        true
    }

    /// A data box answered `(session, pkt_seq)`'s KEY fetch with a miss: it never stored it.
    pub fn box_missed(&mut self, session: SessionId, pkt_seq: u32) {
        if let Some(x) = self.missing.get_mut(&(session, pkt_seq)) {
            x.box_missed = true;
        }
    }

    /// Whether a data box said it lacks `(session, pkt_seq)`: then it was lost at its box, and
    /// so may the packets after it be, so every missing key is escalated at once (reading (j)).
    /// A replica catching up, whose data is in flight, never gets a box's miss, so it keeps
    /// asking for one key: a timer here (2 × `REP_DATA_WAIT_US`) fired for a restarted voter
    /// catching up and stopped it at `REP_E_HASHLAG` in 8 of 40 loaded runs.
    pub fn stuck(&self, session: SessionId, pkt_seq: u32) -> bool {
        self.missing
            .get(&(session, pkt_seq))
            .is_some_and(|x| x.box_missed)
    }

    /// Where this round's scan starts: the height and record index where the last one stopped,
    /// so every record gets its turn (Codex r4618145217, CodeRabbit r4618053807). The caller
    /// finds that block from the front block's height, so a round costs no walk of the backlog
    /// (Codex r4618501668); a height no longer pending starts at the front.
    pub fn scan_start(&self) -> (u64, usize) {
        self.scan_at
    }

    /// The round stopped before `next` (height, record index); `ended` when it passed the last
    /// pending record, ending a cycle: the next round starts at the front, and keys neither
    /// this cycle nor the one before named (joined, or released) are forgotten, so a key the
    /// scan reaches is named in any two cycles in a row (Vercel r4618223901). Nothing is cut
    /// mid-cycle, so a key the scan has not reached keeps its escalation (Codex r4618241007).
    pub fn scanned(&mut self, next: (u64, usize), ended: bool) {
        self.scan_at = if ended { (0, 0) } else { next };
        let r = self.round;
        if ended {
            self.round = r.wrapping_add(1);
        }
        if ended {
            self.missing
                .retain(|_, x| x.round == r || x.round.wrapping_add(1) == r);
        }
    }

    /// A block was released: its keys need no more fetching, so their escalations go, whether
    /// or not a scan ever ran (Codex r4618328951). The map holds only pending blocks' keys.
    pub fn released(&mut self, keys: impl IntoIterator<Item = (SessionId, u32)>) {
        for k in keys {
            self.missing.remove(&k);
        }
    }

    /// A pending block misses `(session, pkt_seq)` at `now`: the targets to KEY-fetch it from
    /// now, empty while the current source still has time.
    pub fn due(&mut self, session: SessionId, pkt_seq: u32, now: u64) -> Vec<Target> {
        let key = (session, pkt_seq);
        let round = self.round;
        let Some(x) = self.missing.get_mut(&key) else {
            // A new key's peer turns start where the last new key's left off.
            let peer = self.next_peer;
            self.next_peer = self.next_peer.wrapping_add(1);
            self.missing.insert(
                key,
                Esc {
                    last: None,
                    at: now,
                    round,
                    peer,
                    box_missed: false,
                },
            );
            return Vec::new();
        };
        x.round = round;
        let (last, at) = (x.last, x.at);
        if now.saturating_sub(at) < REP_DATA_WAIT_NS {
            return Vec::new();
        }
        let order = [Stage::Boxes, Stage::Peer, Stage::Seq];
        let from = last.map_or(0, |l| {
            order
                .iter()
                .position(|s| *s == l)
                .map_or(0, |i| i.saturating_add(1))
        });
        let Some(stage) = (0..order.len())
            .filter_map(|d| order.get(from.saturating_add(d) % order.len()).copied())
            .find(|s| self.configured(*s))
        else {
            return Vec::new();
        };
        let Some(x) = self.missing.get_mut(&key) else {
            return Vec::new();
        };
        x.last = Some(stage);
        x.at = now;
        match stage {
            Stage::Boxes => {
                self.counts.boxes = self.counts.boxes.saturating_add(1);
                self.boxes.clone()
            }
            Stage::Peer => {
                self.counts.peer = self.counts.peer.saturating_add(1);
                let i = x.peer % self.peers.len().max(1);
                x.peer = i.saturating_add(1);
                self.peers.get(i).copied().into_iter().collect()
            }
            Stage::Seq => {
                self.counts.seq = self.counts.seq.saturating_add(1);
                self.seq.into_iter().collect()
            }
        }
    }
}

/// Sends a KEY fetch for `(session, pkt_seq)` to each target, sealed under its key when it has
/// one. UDP: a lost one is asked again by [`Sources::due`].
pub fn send_key(sock: &UdpSocket, session: SessionId, pkt_seq: u32, to: &[Target]) {
    let q = Fetch::Key { session, pkt_seq };
    for t in to {
        let _ = match &t.key {
            Some(k) => sock.send_to(&seal_fetch(k, &q), t.addr),
            None => sock.send_to(&q.encode(), t.addr),
        };
    }
}

/// Answers peers' KEY fetches from this replica's join and its released payloads
/// (`PeerDataFetch`).
pub struct PeerServer {
    /// Unkeyed: the peers' IPs, the only requesters served.
    peers: Vec<Ipv4Addr>,
    /// Keyed (`Some`, even empty: then nothing is served): each requester's
    /// `K_fetch(e, i, VOTER_TARGET + me)` by its IPv4. `None`: unkeyed (DEV).
    keys: Option<Vec<(Ipv4Addr, [u8; 16])>>,
    level: u64,
    at: u64,
    kept: BTreeMap<(SessionId, u32), Vec<Vec<u8>>>,
    order: VecDeque<(SessionId, u32)>,
    buf: FrameBuf,
    /// Per requester source address and key whose variants outnumber the tokens one answer got:
    /// where its next answer starts, so requesters interleaving fetches of one key each progress,
    /// even when they share an IPv4.
    resume: BTreeMap<(SocketAddrV4, SessionId, u32), usize>,
}

impl PeerServer {
    pub fn new(peers: &[SocketAddrV4], keys: Option<Vec<(Ipv4Addr, [u8; 16])>>) -> Self {
        Self {
            peers: peers.iter().map(|p| *p.ip()).collect(),
            keys,
            level: cap(),
            at: 0,
            kept: BTreeMap::new(),
            order: VecDeque::new(),
            buf: FrameBuf::default(),
            resume: BTreeMap::new(),
        }
    }

    /// A keyed server's new epoch's keys (`EPOCH <e>`): it then serves only fetches sealed
    /// under them. An unkeyed server stays unkeyed.
    pub fn set_keys(&mut self, keys: Vec<(Ipv4Addr, [u8; 16])>) {
        if self.keys.is_some() {
            self.keys = Some(keys);
        }
    }

    /// Before `join.release(recs)`: copies the payloads those records name, so peers can still
    /// fetch them. Keeps the last [`PEER_KEEP`].
    pub fn keep(&mut self, join: &DataJoin, recs: &[LaneRec]) {
        for r in recs {
            let LaneRec::Pkt(p) = r else { continue };
            if p.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) != 0 {
                continue;
            }
            let Ok((b, _)) = join.resolve(p) else {
                continue;
            };
            let key = (p.session, p.pkt_seq);
            let v = self.kept.entry(key).or_default();
            if v.iter().any(|x| x == b) {
                continue;
            }
            v.push(b.to_vec());
            self.order.push_back(key);
            while self.order.len() > PEER_KEEP {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                if let Some(v) = self.kept.get_mut(&old) {
                    if !v.is_empty() {
                        v.remove(0);
                    }
                    if v.is_empty() {
                        self.kept.remove(&old);
                    }
                }
            }
        }
    }

    fn open(&self, from: Ipv4Addr, req: &[u8]) -> Option<(SessionId, u32)> {
        let q = match &self.keys {
            None => self
                .peers
                .contains(&from)
                .then(|| Fetch::decode(req).ok())
                .flatten(),
            Some(keys) => keys
                .iter()
                .filter(|(ip, _)| *ip == from)
                .find_map(|(_, k)| Fetch::open(req, k).ok()),
        };
        match q? {
            Fetch::Key { session, pkt_seq } => Some((session, pkt_seq)),
            _ => None,
        }
    }

    /// The `FETCH_RESP` frames answering request `req` from `from` at `now`; empty: no answer.
    pub fn serve(
        &mut self,
        join: &DataJoin,
        from: SocketAddrV4,
        req: &[u8],
        now: u64,
        counts: &mut Counts,
    ) -> Vec<Vec<u8>> {
        let Some((session, pkt_seq)) = self.open(*from.ip(), req) else {
            counts.bad = counts.bad.saturating_add(1);
            return Vec::new();
        };
        let mut vars: Vec<&[u8]> = join.variants(session, pkt_seq).collect();
        for b in self.kept.get(&(session, pkt_seq)).into_iter().flatten() {
            if !vars.contains(&b.as_slice()) {
                vars.push(b);
            }
        }
        let n = u64::try_from(vars.len()).unwrap_or(u64::MAX);
        self.level = self
            .level
            .saturating_add(now.saturating_sub(self.at).saturating_mul(PEER_MAX_PPS))
            .min(cap());
        self.at = now;
        // One token per payload sent (at least one per answer). An answer that the tokens on hand
        // cannot cover sends what they buy and the next one resumes after it (reading (i)), so a
        // key with more variants than a full bucket still gets every one served.
        let take = usize::try_from((self.level / SEC).min(n.max(1))).unwrap_or(usize::MAX);
        if take == 0 {
            counts.limited = counts.limited.saturating_add(1);
            return Vec::new();
        }
        let key = (from, session, pkt_seq);
        if take < vars.len() {
            let total = vars.len();
            let start = self.resume.get(&key).copied().unwrap_or(0) % total;
            vars.rotate_left(start);
            vars.truncate(take);
            if self.resume.len() >= PEER_KEEP {
                self.resume.clear();
            }
            self.resume.insert(key, start.saturating_add(take) % total);
        } else {
            self.resume.remove(&key);
        }
        let n = u64::try_from(vars.len()).unwrap_or(u64::MAX);
        let used = n.max(1).saturating_mul(SEC);
        self.level = self.level.saturating_sub(used);
        let mut hdr = DataHdr {
            kind: Kind::FetchResp,
            book: BookId(0),
            epoch16: 0,
            data_seq: key_seq(session, pkt_seq),
            src: PEER_SRC,
        };
        if let Some(b) = vars.first() {
            let u16_at = |a: usize| {
                b.get(a..a.saturating_add(2))
                    .and_then(|x| x.try_into().ok())
                    .map_or(0, u16::from_le_bytes)
            };
            (hdr.epoch16, hdr.book) = (u16_at(10), BookId(u16_at(12)));
        }
        let mut out = Vec::new();
        for b in &vars {
            if !self.buf.push(b) {
                out.push(self.buf.finish(&hdr).to_vec());
                // A payload no frame can hold is skipped, never sent alone over the cap.
                let _ = self.buf.push(b);
            }
        }
        if !self.buf.is_empty() || out.is_empty() {
            out.push(self.buf.finish(&hdr).to_vec());
        }
        if n == 0 {
            counts.missed = counts.missed.saturating_add(1);
        } else {
            counts.served = counts.served.saturating_add(n);
        }
        out
    }
}

/// A full bucket: 10 ms of tokens, in token-nanoseconds.
fn cap() -> u64 {
    PEER_MAX_PPS.saturating_mul(BURST_NS)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use vyrn_data::frame::decode;
    use vyrn_types::{LaneId, LaneSeq, Nanos, PacketRecord, PktHash, StepId};

    fn a(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
    }

    fn t(port: u16) -> Target {
        Target {
            addr: a(port),
            key: None,
        }
    }

    #[test]
    fn escalates_box_peer_seq_each_wait_and_round_robins_peers() {
        let mut s = Sources::new(vec![t(1), t(2)], vec![t(11), t(12)], Some(t(21)));
        let (k, w) = (SessionId(5), REP_DATA_WAIT_NS);
        assert!(
            s.due(k, 1, 0).is_empty(),
            "first seen: RANGE may still fill it"
        );
        assert!(s.due(k, 1, w - 1).is_empty());
        assert_eq!(s.due(k, 1, w), vec![t(1), t(2)]);
        assert!(
            s.due(k, 1, 2 * w - 1).is_empty(),
            "the boxes get their wait"
        );
        assert_eq!(s.due(k, 1, 2 * w), vec![t(11)]);
        assert_eq!(s.due(k, 1, 3 * w), vec![t(21)]);
        assert_eq!(
            s.due(k, 1, 4 * w),
            vec![t(1), t(2)],
            "then back to the boxes"
        );
        assert_eq!(s.due(k, 1, 5 * w), vec![t(12)], "the next peer");
        // Another key starts over, its peer turns one past the last new key's.
        assert!(s.due(k, 2, 5 * w).is_empty());
        assert_eq!(s.due(k, 2, 6 * w), vec![t(1), t(2)]);
        assert_eq!(s.due(k, 2, 7 * w), vec![t(12)]);
        assert_eq!((s.counts.boxes, s.counts.peer, s.counts.seq), (3, 3, 1));
        // Unconfigured sources are skipped.
        let mut s = Sources::new(Vec::new(), Vec::new(), Some(t(21)));
        assert!(s.due(k, 1, 0).is_empty());
        assert_eq!(s.due(k, 1, w), vec![t(21)]);
        assert_eq!(s.due(k, 1, 2 * w), vec![t(21)]);
        let mut s = Sources::new(Vec::new(), Vec::new(), None);
        assert!(s.due(k, 1, 0).is_empty());
        assert!(s.due(k, 1, w).is_empty());
    }

    /// Missing keys escalate side by side, so a burst reaches the sequencer within one
    /// escalation (reading (j)); a round forgets the keys it no longer names.
    #[test]
    fn missing_keys_escalate_together_and_rounds_forget_joined_ones() {
        let mut s = Sources::new(vec![t(1)], vec![t(11)], Some(t(21)));
        let (k, w) = (SessionId(5), REP_DATA_WAIT_NS);
        // One round that scans every key of `keys`, a full cycle.
        let round = |s: &mut Sources, keys: &[u32], now: u64| {
            assert!(s.begin_round(now));
            let out: Vec<Vec<Target>> = keys.iter().map(|&q| s.due(k, q, now)).collect();
            s.scanned((0, 0), true);
            out
        };
        assert_eq!(round(&mut s, &[1, 2, 3], 0), vec![vec![]; 3]);
        assert_eq!(round(&mut s, &[1, 2, 3], w), vec![vec![t(1)]; 3]);
        assert_eq!(round(&mut s, &[1, 2, 3], 2 * w), vec![vec![t(11)]; 3]);
        // Key 2 joined: 1 and 3 reach the sequencer at the same time; two cycles without key 2
        // forget it.
        assert_eq!(round(&mut s, &[1, 3], 3 * w), vec![vec![t(21)]; 2]);
        assert_eq!(round(&mut s, &[1, 3], 4 * w), vec![vec![t(1)]; 2]);
        assert_eq!(s.missing.len(), 2);
        // Key 2 missing again starts over.
        assert_eq!(round(&mut s, &[2], 5 * w), vec![vec![]]);
        // Two keys with two peers: each still turns through both peers (Vercel r4617946666).
        let mut s = Sources::new(Vec::new(), vec![t(11), t(12)], None);
        let mut got: [Vec<Target>; 2] = [Vec::new(), Vec::new()];
        for c in 0..5u64 {
            assert!(s.begin_round(c * w));
            for (q, g) in (1u32..).zip(got.iter_mut()) {
                g.extend(s.due(k, q, c * w));
            }
            s.scanned((0, 0), true);
        }
        for g in &got {
            assert!(g.contains(&t(11)) && g.contains(&t(12)), "{g:?}");
        }
        // A key is stuck once a box said it lacks it, however long it has waited.
        let mut s = Sources::new(vec![t(1)], vec![t(11)], Some(t(21)));
        assert!(s.begin_round(5 * w));
        assert!(s.due(k, 9, 5 * w).is_empty());
        assert_eq!(s.due(k, 9, 6 * w), vec![t(1)]);
        assert_eq!(s.due(k, 9, 7 * w), vec![t(11)]);
        assert!(!s.stuck(k, 9));
        s.box_missed(k, 8);
        assert!(!s.stuck(k, 9));
        s.box_missed(k, 9);
        assert!(s.stuck(k, 9));
        // Rounds are at least ROUND_NS apart.
        assert!(!s.begin_round(5 * w + ROUND_NS - 1));
        assert!(s.begin_round(5 * w + ROUND_NS));
        // Single-key rounds never end a cycle: releasing the block forgets its keys, and only
        // its keys (Codex r4618328951).
        for q in 10..1000u32 {
            let _ = s.due(k, q, 8 * w);
        }
        s.released((10..1000u32).map(|q| (k, q)));
        assert_eq!(s.missing.keys().copied().collect::<Vec<_>>(), vec![(k, 9)]);
    }

    /// The scan goes on where the last round stopped and wraps, so a key past one round's budget
    /// gets its turn, and a key named in the last cycle keeps its timer (Codex r4618145217,
    /// CodeRabbit r4618053807).
    #[test]
    fn the_scan_resumes_where_it_stopped_and_keeps_timers_across_rounds() {
        let mut s = Sources::new(vec![t(1)], Vec::new(), None);
        assert_eq!(s.scan_start(), (0, 0));
        s.scanned((7, 4), false);
        assert_eq!(s.scan_start(), (7, 4));
        // Key 7 named in cycle 0, which then ends: it stays, and its timer keeps running.
        let k = SessionId(5);
        assert!(s.due(k, 7, 0).is_empty());
        s.scanned((9, 0), true);
        assert_eq!(
            s.scan_start(),
            (0, 0),
            "a cycle's end starts the next at the front"
        );
        assert_eq!(s.missing.len(), 1);
        assert_eq!(
            s.due(k, 7, REP_DATA_WAIT_NS),
            vec![t(1)],
            "its timer kept running"
        );
        s.scanned((0, 0), true); // cycle 1 named it: stays
        assert_eq!(s.missing.len(), 1);
        s.scanned((3, 1), false); // mid-cycle: nothing is cut (Codex r4618241007)
        s.scanned((0, 0), true); // cycle 2 did not, cycle 1 did: stays (Vercel r4618223901)
        assert_eq!(s.missing.len(), 1);
        s.scanned((0, 0), true); // neither cycle 3 nor 2: forgotten
        assert!(s.missing.is_empty());
    }

    /// A keyed target gets the 40-byte form that opens under its key; an unkeyed one the 32.
    #[test]
    fn send_key_seals_under_the_target_key() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let std::net::SocketAddr::V4(to) = rx.local_addr().unwrap() else {
            panic!("v4")
        };
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let k = [0x42; 16];
        send_key(
            &tx,
            sid(),
            3,
            &[
                Target {
                    addr: to,
                    key: Some(k),
                },
                Target {
                    addr: to,
                    key: None,
                },
            ],
        );
        let mut b = [0u8; 64];
        let n = rx.recv(&mut b).unwrap();
        let want = Fetch::Key {
            session: sid(),
            pkt_seq: 3,
        };
        assert_eq!(Fetch::open(&b[..n], &k).unwrap(), want);
        assert!(Fetch::open(&b[..n], &[0x43; 16]).is_err());
        let n = rx.recv(&mut b).unwrap();
        assert_eq!(Fetch::decode(&b[..n]).unwrap(), want);
    }

    fn sid() -> SessionId {
        vyrn_wire::session_id(1, vyrn_types::LaneId(0), 1).unwrap()
    }

    /// A signed packet of `pkt_seq` 1, book 7: `n` heartbeats under `epoch16` `e`, which makes
    /// its variant.
    fn pkt_e(n: u8, e: u16) -> Vec<u8> {
        let hdr = vyrn_wire::ReqHeader::new(sid(), 1, e, BookId(7), false);
        let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
        let n = vyrn_wire::encode_request(
            &mut buf,
            hdr,
            &vec![vyrn_wire::Msg::Heartbeat; usize::from(n)],
            &[0x11; 16],
            None,
        )
        .unwrap();
        buf[..n].to_vec()
    }

    fn pkt(n: u8) -> Vec<u8> {
        pkt_e(n, 9)
    }

    fn fetch(q: u32) -> [u8; 32] {
        Fetch::Key {
            session: sid(),
            pkt_seq: q,
        }
        .encode()
    }

    fn packets(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = frames
            .iter()
            .flat_map(|f| {
                decode(f)
                    .unwrap()
                    .packets()
                    .map(<[u8]>::to_vec)
                    .collect::<Vec<_>>()
            })
            .collect();
        v.sort_unstable();
        v
    }

    const PEER: Ipv4Addr = Ipv4Addr::LOCALHOST;

    #[test]
    fn serves_peers_every_variant_and_refuses_strangers() {
        let mut j = DataJoin::default();
        j.put(sid(), 1, pkt(1));
        j.put(sid(), 1, pkt(2));
        let mut srv = PeerServer::new(&[a(11)], None);
        let mut c = Counts::default();
        let hit = srv.serve(&j, SocketAddrV4::new(PEER, 9), &fetch(1), 0, &mut c);
        assert_eq!(hit.len(), 1);
        let f = decode(&hit[0]).unwrap();
        assert_eq!(
            (
                f.hdr.kind,
                f.hdr.src,
                f.hdr.book,
                f.hdr.epoch16,
                f.hdr.data_seq
            ),
            (Kind::FetchResp, PEER_SRC, BookId(7), 9, key_seq(sid(), 1))
        );
        let mut want = vec![pkt(1), pkt(2)];
        want.sort_unstable();
        assert_eq!(packets(&hit), want, "every variant, byte for byte");
        // The requester's feed stores the answer like any FETCH_RESP.
        let mut feed = vyrn_replica::DataFeed::new(BookId(7), 1, 0);
        let mut mine = DataJoin::default();
        assert_eq!(feed.on_frame(&mut mine, &hit[0], 0).unwrap().stored, 2);
        let miss = srv.serve(&j, SocketAddrV4::new(PEER, 9), &fetch(2), 0, &mut c);
        assert_eq!(miss.len(), 1);
        assert_eq!(decode(&miss[0]).unwrap().n_pkts, 0);
        assert!(
            srv.serve(
                &j,
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 9),
                &fetch(1),
                0,
                &mut c
            )
            .is_empty()
        );
        let range = Fetch::Range {
            dst: 0,
            from: 1,
            to: 1,
        }
        .encode();
        assert!(
            srv.serve(&j, SocketAddrV4::new(PEER, 9), &range, 0, &mut c)
                .is_empty()
        );
        assert_eq!((c.served, c.missed, c.bad, c.limited), (2, 1, 2, 0));
        // 10 ms of 50k/s is 500 tokens: the 251st two-variant answer at one instant is refused.
        let mut srv = PeerServer::new(&[a(11)], None);
        let mut c = Counts::default();
        for _ in 0..250 {
            assert!(
                !srv.serve(&j, SocketAddrV4::new(PEER, 9), &fetch(1), 0, &mut c)
                    .is_empty()
            );
        }
        assert!(
            srv.serve(&j, SocketAddrV4::new(PEER, 9), &fetch(1), 0, &mut c)
                .is_empty()
        );
        assert_eq!(c.limited, 1);
        assert!(
            !srv.serve(&j, SocketAddrV4::new(PEER, 9), &fetch(1), 40_000, &mut c)
                .is_empty(),
            "40 µs refills 2"
        );
    }

    /// More variants than a full bucket: each answer sends what its tokens buy and the next
    /// resumes after it, so two answers cover all of them, for each requester.
    #[test]
    fn variants_past_the_bucket_are_served_over_answers() {
        let mut j = DataJoin::default();
        let mut all = Vec::new();
        // 1,000 variants, two full buckets: a cursor shared by both requesters would give each
        // the same half every time.
        for e in 0..250 {
            for n in 1..=4 {
                j.put(sid(), 1, pkt_e(n, e));
                all.push(pkt_e(n, e));
            }
        }
        all.sort_unstable();
        // Two requesters on one IPv4 interleave: each one's answers still cover every variant.
        let mut srv = PeerServer::new(&[a(11)], None);
        let mut c = Counts::default();
        let mut got = [Vec::new(), Vec::new()];
        for (t, (who, port)) in [(0, 9), (1, 10), (0, 9), (1, 10)].into_iter().enumerate() {
            let now = u64::try_from(t).unwrap() * BURST_NS;
            let ans =
                packets(&srv.serve(&j, SocketAddrV4::new(PEER, port), &fetch(1), now, &mut c));
            assert_eq!(ans.len(), 500, "a full bucket");
            got[who].extend(ans);
        }
        for mut g in got {
            g.sort_unstable();
            g.dedup();
            assert_eq!(g, all);
        }
        assert_eq!(c.limited, 0);
    }

    /// More variants than one data frame holds go out in several frames, none dropped.
    #[test]
    fn variants_past_one_frame_are_split_not_dropped() {
        let mut j = DataJoin::default();
        let vars: Vec<Vec<u8>> = (0..9).map(|e| pkt_e(10, e)).collect();
        for v in &vars {
            j.put(sid(), 1, v.clone());
        }
        let total: usize = vars
            .iter()
            .map(|v| vyrn_data::frame::entry_len(v.len()))
            .sum();
        assert!(
            total > vyrn_data::frame::MAX_FRAME,
            "the test needs more than one frame"
        );
        let mut srv = PeerServer::new(&[a(11)], None);
        let frames = srv.serve(
            &j,
            SocketAddrV4::new(PEER, 9),
            &fetch(1),
            0,
            &mut Counts::default(),
        );
        assert!(frames.len() >= 2, "{} frames", frames.len());
        let mut want = vars.clone();
        want.sort_unstable();
        assert_eq!(packets(&frames), want);
    }

    /// A payload this replica already released is still served to a peer that asks later.
    #[test]
    fn released_payloads_stay_servable() {
        let p = pkt(1);
        let h = vyrn_replica::full_hash(&p);
        let rec = PacketRecord {
            lane: LaneId(0),
            count: 1,
            flags: 0,
            session: sid(),
            pkt_seq: 1,
            rx_ts: Nanos(1),
            pkt_hash: PktHash(u64::from_le_bytes(h.0[..8].try_into().unwrap())),
            first_lane_seq: LaneSeq(1),
            fills_applied: StepId(0),
            snap_lag: 0,
        };
        let recs = [LaneRec::Pkt(rec)];
        let mut j = DataJoin::default();
        j.put(sid(), 1, p.clone());
        let mut srv = PeerServer::new(&[a(11)], None);
        srv.keep(&j, &recs);
        j.release(vyrn_types::Height(1), &recs);
        assert!(j.resolve(&rec).is_err(), "the join no longer holds it");
        let frames = srv.serve(
            &j,
            SocketAddrV4::new(PEER, 9),
            &fetch(1),
            0,
            &mut Counts::default(),
        );
        assert_eq!(packets(&frames), vec![p]);
    }

    /// Keyed: only fetches sealed under the source IP's key are served.
    #[test]
    fn a_keyed_server_serves_only_sealed_fetches() {
        let mut j = DataJoin::default();
        j.put(sid(), 1, pkt(1));
        let k = [0x42; 16];
        let mut srv = PeerServer::new(&[], Some(vec![(PEER, [0x41; 16]), (PEER, k)]));
        let mut c = Counts::default();
        let q = Fetch::Key {
            session: sid(),
            pkt_seq: 1,
        };
        assert_eq!(
            packets(&srv.serve(
                &j,
                SocketAddrV4::new(PEER, 9),
                &seal_fetch(&k, &q),
                0,
                &mut c
            )),
            vec![pkt(1)]
        );
        assert!(
            srv.serve(&j, SocketAddrV4::new(PEER, 9), &q.encode(), 0, &mut c)
                .is_empty(),
            "unsealed"
        );
        assert!(
            srv.serve(
                &j,
                SocketAddrV4::new(PEER, 9),
                &seal_fetch(&[0x43; 16], &q),
                0,
                &mut c
            )
            .is_empty()
        );
        let other = Ipv4Addr::new(10, 0, 0, 9);
        assert!(
            srv.serve(
                &j,
                SocketAddrV4::new(other, 9),
                &seal_fetch(&k, &q),
                0,
                &mut c
            )
            .is_empty(),
            "wrong IP"
        );
        assert_eq!((c.served, c.bad), (1, 3));
    }

    /// Keyed with no usable requester key: fails closed, even for a configured peer's IP.
    #[test]
    fn a_keyed_server_without_keys_serves_nothing() {
        let mut j = DataJoin::default();
        j.put(sid(), 1, pkt(1));
        let mut srv = PeerServer::new(&[a(11)], Some(Vec::new()));
        let mut c = Counts::default();
        let q = Fetch::Key {
            session: sid(),
            pkt_seq: 1,
        };
        assert!(
            srv.serve(&j, SocketAddrV4::new(PEER, 9), &q.encode(), 0, &mut c)
                .is_empty()
        );
        assert_eq!(c.served, 0);
    }
}
