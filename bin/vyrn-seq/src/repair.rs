//! `SeqDataReq` (07 §5.5 source 3) on the repair thread: retained packets out to replicas.
//!
//! The engine thread hands a [`Kept`] for each `Accepted` or `Shed` packet through the
//! [`RetainRing`]. It never waits: a full ring loses that copy and counts `retain_dropped`. This
//! thread puts each copy into a [`Retain`] and answers fetches from the replicas.
//!
//! **Wire** (07 §5.5): the request is `vyrn-data`'s 32-byte KEY fetch (`Fetch::Key{session,
//! pkt_seq}`), sent to the box's repair port. The answer is one `FETCH_RESP` data frame with
//! `src` [`SEQ_SRC`], `data_seq = session << 32 | pkt_seq`, the first variant's `book` and
//! `epoch16`, and every retained variant in arrival order. A miss is the same frame with no
//! packets and `book`, `epoch16` 0. These are the bytes a data box uses, so a replica's
//! `DataFeed` takes the answer as it takes a data box's.
//!
//! **Refused**, counted in `repair_bad` with no answer: a requester whose IP is not one of
//! `[replication] order`, a frame that is not a fast-path frame, a fetch that does not decode, and
//! a RANGE or BLOCK fetch (only data boxes serve those).
//!
//! **Sealed** (07 §5.5, 08 §9.6, *reading*): with [`Server::set_keys`] the box serves only the
//! 40-byte form under the requester's `K_fetch(e, i, SEQ_TARGET + j)`, keyed by its source IPv4,
//! like a keyed data box; `j` is this box's place in `home.seq`. A plain or wrongly tagged
//! fetch counts in `repair_bad`. Like a data box it holds the keys of epochs `e` and `e + 1`
//! ([`window_keys`]); `EPOCH <e>` on stdin moves both, and the repair thread prints
//! `FETCH_EPOCHS <e>,<e+1>` once it has installed them (07 §5.5 Epoch boundary).
//!
//! **Rate** (07 §5.5, 13 §2, DAV-2): each answer takes one token per packet it carries, and a miss
//! takes one, from a box bucket of `REP_SEQ_DATA_MAX_PPS` = 50k/s. Each packet also takes one
//! token from its session's bucket of `DAV_SESSION_REPAIR_PPS` = 2,000/s. Each bucket holds 10 ms
//! of tokens, and at least `MAX_VARIANTS` (4). A request either bucket cannot cover gets no answer
//! and counts `repair_limited`;
//! the replica asks again or moves on (07 §5.5).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use vyrn_cut::{Consumer, Hw, Ring};
use vyrn_data::frame::{DataHdr, Fetch, FrameBuf, Kind, key_seq};
use vyrn_engine::retain::{Kept, Retain};
use vyrn_nic::frame::{self, Endpoint, FrameHdr};
use vyrn_types::{BookId, SessionId};

/// Copies in flight between the engine and repair threads (a power of two).
pub const RETAIN_HANDOFF: usize = 8192;
pub type RetainRing = Ring<Kept, RETAIN_HANDOFF, 1, Hw>;
/// The `src` of a sequencer's `FETCH_RESP`: no data box index reaches it.
pub const SEQ_SRC: u8 = 0xFF;
/// `REP_SEQ_DATA_MAX_PPS`.
pub const REP_SEQ_DATA_MAX_PPS: u64 = 50_000;
/// `DAV_SESSION_REPAIR_PPS`.
pub const DAV_SESSION_REPAIR_PPS: u64 = 2_000;
/// A bucket holds this much time's worth of tokens.
const BURST_NS: u64 = 10_000_000;
const SEC: u64 = 1_000_000_000;
/// Retention copies the repair thread stores before it polls requests again.
const DRAIN_BATCH: usize = 1024;

/// A token bucket in token-nanoseconds, so refills need no division.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    level: u64,
    at: u64,
}

impl Bucket {
    fn full(rate: u64, now: u64) -> Self {
        Self {
            level: cap(rate),
            at: now,
        }
    }

    fn refill(&mut self, rate: u64, now: u64) {
        let dt = now.saturating_sub(self.at).min(SEC);
        self.level = self
            .level
            .saturating_add(dt.saturating_mul(rate))
            .min(cap(rate));
        self.at = now;
    }
}

fn cap(rate: u64) -> u64 {
    // At least the largest answer's tokens, so a low rate still serves every key.
    let most = u64::try_from(vyrn_engine::retain::MAX_VARIANTS).unwrap_or(u64::MAX);
    BURST_NS.saturating_mul(rate).max(most.saturating_mul(SEC))
}

/// `K_fetch(e, i, SEQ_TARGET + j)` of every requester of `home`, by its `repl_addr` IPv4, for
/// the `vyrn-seq` box `j` whose X25519 secret is `secret` (08 §9.6). An error if `secret` is no
/// seq box's key, or no requester gets a key (an empty map would mean plain fetches).
pub fn fetch_keys(
    roster: &vyrn_epoch::Roster,
    domain: &vyrn_epoch::Domain,
    epoch: vyrn_types::Epoch,
    home: vyrn_types::HomeCode,
    secret: &[u8; 32],
) -> Result<BTreeMap<Ipv4Addr, [u8; 16]>, String> {
    let n = u8::try_from(roster.home(home).seq.len()).unwrap_or(0);
    let keys = (0..n)
        .find_map(|j| {
            roster.box_fetch_keys(
                vyrn_epoch::FETCH_CONTEXT,
                domain,
                epoch,
                home,
                vyrn_epoch::SEQ_TARGET + j,
                secret,
            )
        })
        .ok_or("repair.xchg is not the X25519 key of a vyrn-seq box of home")?;
    let mut out = BTreeMap::new();
    for (i, addr, k) in keys {
        let ip = addr
            .ipv4()
            .ok_or(format!("roster: requester {i} has no IPv4 repl_addr"))?;
        if out.insert(ip, k).is_some() {
            return Err(format!("roster: two requesters share {ip}"));
        }
    }
    if out.is_empty() {
        return Err("roster: no requester has a usable K_fetch".into());
    }
    Ok(out)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RepairStats {
    pub served: u64,
    pub missed: u64,
    pub limited: u64,
    pub bad: u64,
}

/// `K_fetch` per requester address, under every epoch the box holds.
pub type Keys = BTreeMap<Ipv4Addr, Vec<[u8; 16]>>;

/// [`fetch_keys`] of epochs `e` and `e + 1` (when it exists), merged by requester address: the
/// window a box serves under, so a requester that moved to `e + 1` first is still served.
pub fn window_keys(
    roster: &vyrn_epoch::Roster,
    domain: &vyrn_epoch::Domain,
    e: u32,
    home: vyrn_types::HomeCode,
    secret: &[u8; 32],
) -> Result<Keys, String> {
    let mut out = Keys::new();
    for ep in [Some(e), e.checked_add(1)].into_iter().flatten() {
        for (ip, k) in fetch_keys(roster, domain, vyrn_types::Epoch(ep), home, secret)? {
            out.entry(ip).or_default().push(k);
        }
    }
    Ok(out)
}

/// The repair service of one box.
pub struct Server {
    retain: Retain,
    replicas: Vec<Ipv4Addr>,
    /// `K_fetch` per requester address; empty: plain 32-byte fetches (DEV).
    keys: Keys,
    box_pps: u64,
    session_pps: u64,
    total: Bucket,
    sessions: BTreeMap<SessionId, Bucket>,
    buf: FrameBuf,
    pub stats: RepairStats,
}

impl Server {
    pub fn new(slots: usize, replicas: Vec<Ipv4Addr>, box_pps: u64, session_pps: u64) -> Self {
        Self {
            retain: Retain::new(slots),
            replicas,
            keys: Keys::new(),
            box_pps,
            session_pps,
            total: Bucket::full(box_pps, 0),
            sessions: BTreeMap::new(),
            buf: FrameBuf::default(),
            stats: RepairStats::default(),
        }
    }

    /// Serve only fetches sealed under one of these keys, by source address.
    pub fn set_keys(&mut self, keys: Keys) {
        self.keys = keys;
    }

    pub fn put(&mut self, k: Kept) {
        self.retain.put(k);
    }

    /// Answers one request from `from` at `now_ns`: the `FETCH_RESP` payload, or `None`.
    pub fn serve(&mut self, from: Ipv4Addr, req: &[u8], now_ns: u64) -> Option<&[u8]> {
        let q = if self.keys.is_empty() {
            Fetch::decode(req).ok()
        } else {
            self.keys
                .get(&from)
                .and_then(|ks| ks.iter().find_map(|k| Fetch::open(req, k).ok()))
        };
        let key = match q {
            Some(Fetch::Key { session, pkt_seq }) if self.replicas.contains(&from) => {
                (session, pkt_seq)
            }
            _ => {
                self.stats.bad = self.stats.bad.saturating_add(1);
                return None;
            }
        };
        let (session, pkt_seq) = key;
        let n = u64::try_from(self.retain.find(session, pkt_seq).count()).unwrap_or(u64::MAX);
        self.total.refill(self.box_pps, now_ns);
        let need_box = n.max(1).saturating_mul(SEC);
        if self.total.level < need_box {
            self.stats.limited = self.stats.limited.saturating_add(1);
            return None;
        }
        // Only a hit takes a session token, so only a session the lanes authenticated (one with
        // a retained packet) ever gets a bucket: a miss for a made-up session stores nothing.
        if n > 0 {
            let rate = self.session_pps;
            // A live hit session has a retained packet, so at most `capacity` are live. Past that,
            // buckets that refilled to full (idle ≥ 10 ms) carry no state and are dropped.
            if !self.sessions.contains_key(&session)
                && self.sessions.len() >= self.retain.capacity()
            {
                self.sessions.retain(|_, b| {
                    b.refill(rate, now_ns);
                    b.level < cap(rate)
                });
            }
            let s = self
                .sessions
                .entry(session)
                .or_insert_with(|| Bucket::full(rate, now_ns));
            s.refill(rate, now_ns);
            let need_session = n.saturating_mul(SEC);
            if s.level < need_session {
                self.stats.limited = self.stats.limited.saturating_add(1);
                return None;
            }
            s.level = s.level.saturating_sub(need_session);
        }
        self.total.level = self.total.level.saturating_sub(need_box);
        let mut hdr = DataHdr {
            kind: Kind::FetchResp,
            book: BookId(0),
            epoch16: 0,
            data_seq: key_seq(session, pkt_seq),
            src: SEQ_SRC,
        };
        for (i, k) in self.retain.find(session, pkt_seq).enumerate() {
            let b = k.bytes();
            if i == 0 {
                let u16_at = |a: usize| {
                    b.get(a..a.saturating_add(2))
                        .map_or(0, |x| u16::from_le_bytes([x[0], x[1]]))
                };
                (hdr.epoch16, hdr.book) = (u16_at(10), BookId(u16_at(12)));
            }
            self.buf.push(b);
        }
        if n == 0 {
            self.stats.missed = self.stats.missed.saturating_add(1);
        } else {
            self.stats.served = self.stats.served.saturating_add(n);
        }
        Some(self.buf.finish(&hdr))
    }
}

/// The repair thread's loop: copies from the engine into retention, requests answered, and
/// `EPOCH` key sets from `rekey` installed (acked `FETCH_EPOCHS <e>,<e+1>` once in place), until
/// `stop`. Allocates freely: it is not the sealed engine thread.
pub fn run<R: vyrn_wire::RxRing, T: vyrn_wire::TxRing>(
    mut server: Server,
    rekey: Option<std::sync::mpsc::Receiver<(u32, Keys)>>,
    mut copies: Consumer<'_, Kept, RETAIN_HANDOFF, 1, Hw>,
    mut rx: R,
    mut tx: T,
    me: Endpoint,
    stop: &std::sync::atomic::AtomicBool,
) -> RepairStats {
    let t0 = std::time::Instant::now();
    let mut burst = [vyrn_wire::RxPkt::empty(); vyrn_wire::RX_BURST];
    let mut wire = [0u8; frame::MAX_FRAME_BYTES];
    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        for (e, keys) in rekey.iter().flat_map(|r| r.try_iter()) {
            server.set_keys(keys);
            match e.checked_add(1) {
                Some(n) => println!("FETCH_EPOCHS {e},{n}"),
                None => println!("FETCH_EPOCHS {e}"),
            }
        }
        // A bounded batch, so requests and `stop` are served under sustained ingest.
        let mut work = 0usize;
        while work < DRAIN_BATCH {
            let Some(k) = copies.pop(&Hw) else { break };
            server.put(k);
            work = work.saturating_add(1);
        }
        tx.reap();
        let k = rx.poll(&mut burst);
        let now = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        for p in burst.iter().take(k) {
            let Ok(f) = frame::parse(rx.bytes(p)) else {
                server.stats.bad = server.stats.bad.saturating_add(1);
                continue;
            };
            let to = f.hdr.src;
            if let Some(reply) = server.serve(to.ip, f.payload, now) {
                let hdr = FrameHdr { src: me, dst: to };
                if let Ok(len) = frame::build(&hdr, reply, &mut wire) {
                    // A refused send is a lost answer; the replica asks again.
                    let _ = tx.send(wire.get(..len).unwrap_or(&[]));
                }
            }
        }
        rx.release(k);
        if work == 0 && k == 0 {
            std::thread::yield_now();
        }
    }
    while let Some(k) = copies.pop(&Hw) {
        server.put(k);
    }
    server.stats
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use vyrn_data::frame::decode;
    use vyrn_types::{Nanos, PktHash};

    fn kept(session: u32, pkt_seq: u32, tag: u8) -> Kept {
        let mut b = [tag; 48];
        b[..4].copy_from_slice(&session.to_le_bytes());
        b[4..8].copy_from_slice(&pkt_seq.to_le_bytes());
        b[8] = 1;
        b[10..12].copy_from_slice(&9u16.to_le_bytes());
        b[12..14].copy_from_slice(&7u16.to_le_bytes());
        Kept::new(&b, Nanos(1), PktHash(u64::from(tag))).unwrap()
    }

    const R: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    fn key(session: u32, pkt_seq: u32) -> [u8; 32] {
        Fetch::Key {
            session: SessionId(session),
            pkt_seq,
        }
        .encode()
    }

    #[test]
    fn a_keyed_box_serves_only_sealed_fetches_under_the_sources_key() {
        let mut s = Server::new(64, vec![R], 50_000, 2_000);
        let k = [0x42; 16];
        s.set_keys(Keys::from([(R, vec![[0x41; 16], k])]));
        s.put(kept(5, 1, 0xA));
        let q = Fetch::Key {
            session: SessionId(5),
            pkt_seq: 1,
        };
        assert!(s.serve(R, &q.encode(), 0).is_none());
        assert!(
            s.serve(R, &vyrn_data::frame::seal_fetch(&[0x43; 16], &q), 0)
                .is_none()
        );
        let other = Ipv4Addr::new(10, 0, 0, 3);
        assert!(
            s.serve(other, &vyrn_data::frame::seal_fetch(&k, &q), 0)
                .is_none()
        );
        let reply = s
            .serve(R, &vyrn_data::frame::seal_fetch(&k, &q), 0)
            .unwrap();
        assert_eq!(decode(reply).unwrap().n_pkts, 1);
        assert_eq!((s.stats.served, s.stats.bad), (1, 3));
    }

    #[test]
    fn answers_hits_and_misses_in_data_frame_bytes_and_refuses_strangers() {
        let mut s = Server::new(64, vec![R], 50_000, 2_000);
        s.put(kept(5, 1, 0xA));
        s.put(kept(5, 1, 0xB));
        let reply = s.serve(R, &key(5, 1), 0).unwrap().to_vec();
        let f = decode(&reply).unwrap();
        assert_eq!(
            (
                f.hdr.kind,
                f.hdr.book,
                f.hdr.epoch16,
                f.hdr.data_seq,
                f.hdr.src
            ),
            (Kind::FetchResp, BookId(7), 9, (5u64 << 32) | 1, SEQ_SRC)
        );
        assert_eq!(
            f.packets().map(|p| p[16]).collect::<Vec<_>>(),
            vec![0xA, 0xB]
        );
        let miss = s.serve(R, &key(5, 2), 0).unwrap().to_vec();
        let m = decode(&miss).unwrap();
        assert_eq!(
            (m.n_pkts, m.hdr.book, m.hdr.data_seq),
            (0, BookId(0), (5u64 << 32) | 2)
        );
        assert!(s.serve(Ipv4Addr::new(10, 0, 0, 9), &key(5, 1), 0).is_none());
        let range = Fetch::Range {
            dst: 0,
            from: 1,
            to: 1,
        }
        .encode();
        assert!(s.serve(R, &range, 0).is_none());
        assert!(s.serve(R, b"short", 0).is_none());
        assert_eq!(
            s.stats,
            RepairStats {
                served: 2,
                missed: 1,
                limited: 0,
                bad: 3
            }
        );
    }

    #[test]
    fn the_box_and_session_caps_hold() {
        // Session cap 2,000/s holds 20 packets per 10 ms; the box cap 50k/s holds 500.
        let mut s = Server::new(4096, vec![R], 50_000, 2_000);
        for q in 1..=40 {
            s.put(kept(5, q, 1));
            s.put(kept(6, q, 1));
        }
        let ok = (1..=40)
            .filter(|&q| s.serve(R, &key(5, q), 0).is_some())
            .count();
        assert_eq!(ok, 20, "one session's burst");
        assert!(
            s.serve(R, &key(6, 1), 0).is_some(),
            "another session is not starved"
        );
        // 1 ms later the session has 2 more tokens.
        let later = (21..=40)
            .filter(|&q| s.serve(R, &key(5, q), 1_000_000).is_some())
            .count();
        assert_eq!(later, 2);
        // The box cap: misses cost one token each, 500 per burst.
        let mut b = Server::new(16, vec![R], 50_000, 2_000);
        let ok = (1..=600)
            .filter(|&q| b.serve(R, &key(9, q), 0).is_some())
            .count();
        assert_eq!(ok, 500);
        assert_eq!(b.stats.limited, 100);
        assert!(b.sessions.is_empty(), "misses create no session bucket");
        // A rate below MAX_VARIANTS per 10 ms still answers a key with several variants.
        let mut lo = Server::new(16, vec![R], 100, 100);
        for t in 0..4 {
            lo.put(kept(7, 1, 0xA + t));
        }
        let reply = lo.serve(R, &key(7, 1), 0).unwrap().to_vec();
        assert_eq!(decode(&reply).unwrap().n_pkts, 4);
        // Many distinct hit sessions: idle buckets are pruned at the retention's capacity.
        let mut c = Server::new(16, vec![R], 50_000, 2_000);
        for q in 0..200u32 {
            c.put(kept(100 + q, 1, 1));
            assert!(
                c.serve(R, &key(100 + q, 1), u64::from(q) * 20_000_000)
                    .is_some()
            );
            assert!(c.sessions.len() <= 16, "{}", c.sessions.len());
        }
    }
}
