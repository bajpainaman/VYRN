//! RSS spread across ingest cores (07 §5.2: "RX queue (RSS by session)", ~12 cores at peak).
//!
//! *Reading (recorded in 07 §5.2, "RSS by session"):* a data box runs `n` ingest shards, and each session belongs
//! to exactly one, [`shard_of`]. A shard is a whole [`DataHome`] (MAC keys, dedupe windows, ring)
//! holding only its sessions, so steps 1–5 need no state shared between cores, and dedupe and
//! `CopyConflict` stay exact: every copy of a `(session, pkt_seq)` meets the same window and ring.
//! The NIC cannot hash a UDP payload, so the steering is in software: [`session_of`] reads the
//! session from header bytes 0..4 without parsing the rest, and [`Spread::ingest_from`] hands the
//! packet to its shard. Each shard is `Send`, so the owner can move it to its core
//! ([`Spread::into_shards`]) and feed it from a per-core queue.
//!
//! The ring is split evenly: a shard gets `ring_slots / n` slots (at least 1), so the box keeps
//! about the same packets in RAM in total.

use std::collections::BTreeMap;

use vyrn_nic::frame::Endpoint;
use vyrn_types::{Nanos, SessionId};

use crate::ingest::{DataHome, Event, HomeConfig, Ingested, Reject};

/// The shard that owns `session` among `n` (≥ 1). Fibonacci hashing of the 32-bit `SessionId`,
/// so consecutive slots and lanes spread evenly; every core and every restart agree on it.
pub fn shard_of(session: SessionId, n: usize) -> usize {
    let h = u64::from(session.0.wrapping_mul(0x9E37_79B9));
    // (h × n) >> 32 maps [0, 2^32) onto [0, n) without a division.
    usize::try_from((h * n.max(1) as u64) >> 32).unwrap_or(0)
}

/// The session of a request packet: bytes 0..4 LE (01 §6.1). `None` if the packet is shorter.
pub fn session_of(pkt: &[u8]) -> Option<SessionId> {
    let b: [u8; 4] = pkt.get(..4)?.try_into().ok()?;
    Some(SessionId(u32::from_le_bytes(b)))
}

impl HomeConfig {
    /// Shard `i` of `n`: the same home with only the sessions [`shard_of`] gives to `i`, and
    /// `ring_slots / n` slots.
    pub fn shard(&self, i: usize, n: usize) -> HomeConfig {
        HomeConfig {
            mode: self.mode,
            books: self.books.clone(),
            keys: self
                .keys
                .iter()
                .filter(|(s, _)| shard_of(**s, n) == i)
                .map(|(s, k)| (*s, *k))
                .collect::<BTreeMap<_, _>>(),
            ring_slots: (self.ring_slots / n.max(1)).max(1),
            index_key: self.index_key,
        }
    }
}

/// A data home split into `n` shards by session.
#[derive(Debug)]
pub struct Spread {
    shards: Vec<DataHome>,
}

impl Spread {
    /// `n` shards (≥ 1) of `cfg`.
    pub fn new(cfg: &HomeConfig, n: usize) -> Self {
        let n = n.max(1);
        Self {
            shards: (0..n).map(|i| DataHome::new(cfg.shard(i, n))).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.shards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// The shard a packet goes to, or `None` for one too short to name a session.
    pub fn route(&self, pkt: &[u8]) -> Option<usize> {
        session_of(pkt).map(|s| shard_of(s, self.shards.len()))
    }

    pub fn shard(&self, i: usize) -> Option<&DataHome> {
        self.shards.get(i)
    }

    /// [`DataHome::ingest_from`] on the packet's shard. A packet too short to route is
    /// [`Reject::Header`], as the shard's own parse would find.
    pub fn ingest_from(
        &mut self,
        pkt: &[u8],
        src: Option<Endpoint>,
        rx_ts: Nanos,
        event: &mut Option<Event>,
    ) -> Result<Ingested, Reject> {
        let i = self.route(pkt).ok_or(Reject::Header)?;
        self.shards
            .get_mut(i)
            .ok_or(Reject::Header)?
            .ingest_from(pkt, src, rx_ts, event)
    }

    /// The shards, in index order, for the owner to move one to each core.
    pub fn into_shards(self) -> Vec<DataHome> {
        self.shards
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn shard_of_is_in_range_and_spreads_slots_evenly() {
        for n in [1usize, 2, 3, 12] {
            let mut count = vec![0u32; n];
            // 4096 sessions: slot 1..=1024 on lanes 0..4, generation 1 (04 §4.1 layout).
            for lane in 0..4u32 {
                for slot in 1..=1024u32 {
                    let s = SessionId(slot | lane << 12 | 1 << 20);
                    count[shard_of(s, n)] += 1;
                }
            }
            let (lo, hi) = (*count.iter().min().unwrap(), *count.iter().max().unwrap());
            let mean = 4096 / n as u32;
            assert!(
                lo * 10 >= mean * 9 && hi * 10 <= mean * 11,
                "n={n} {count:?}"
            );
        }
        assert_eq!(shard_of(SessionId(7), 0), 0);
    }

    /// Sharding by session changes no verdict: the same mixed stream (new packets, resends,
    /// byte-identical duplicates, an equivocating copy, a bad MAC, an unknown session, late
    /// copies, a runt) gets the same result and event per packet from 3 shards as from one home.
    #[test]
    fn three_shards_give_the_same_verdicts_and_events_as_one_home() {
        use vyrn_types::{BookId, MAX_REQ_PAYLOAD};
        use vyrn_wire::{Msg, ReqHeader, encode_request};
        let book = BookId(1);
        let key = |s: u32| [s as u8; 16];
        let pkt = |s: u32, q: u32, resend: bool, tag: u32, k: [u8; 16]| {
            let mut out = [0u8; MAX_REQ_PAYLOAD];
            let h = ReqHeader::new(SessionId(s), q, 9, book, resend);
            let m = [Msg::Cancel {
                handle: vyrn_types::Handle(tag),
                client_tag: tag,
            }];
            let n = encode_request(&mut out, h, &m, &k, None).unwrap();
            out[..n].to_vec()
        };
        let cfg = HomeConfig {
            mode: crate::ingest::Mode::Base,
            books: vec![book],
            keys: (1..=9u32).map(|s| (SessionId(s), key(s))).collect(),
            ring_slots: 3 * 64,
            index_key: [3; 16],
        };
        let mut stream = Vec::new();
        for q in 1..=300u32 {
            for s in 1..=9u32 {
                stream.push(pkt(s, q, false, q, key(s)));
            }
        }
        stream.push(pkt(4, 300, false, 300, key(4))); // byte-identical: duplicate
        stream.push(pkt(4, 300, true, 300, key(4))); // resend variant
        stream.push(pkt(5, 300, false, 99, key(5))); // equivocation
        stream.push(pkt(6, 301, false, 1, [0; 16])); // bad MAC
        stream.push(pkt(77, 1, false, 1, key(7))); // unknown session
        stream.push(pkt(2, 1, false, 1, key(2))); // far below the window: late
        stream.push(vec![1, 0]); // runt
        let mut one = DataHome::new(cfg.clone());
        let mut spread = Spread::new(&cfg, 3);
        assert!((0..3).all(|i| spread.shard(i).is_some()));
        let mut seen = Vec::new();
        for (i, p) in stream.iter().enumerate() {
            let (mut e1, mut e2) = (None, None);
            let a = one.ingest_from(p, None, Nanos(i as u64), &mut e1);
            let b = spread.ingest_from(p, None, Nanos(i as u64), &mut e2);
            assert_eq!(a, b, "packet {i}");
            assert_eq!(e1, e2, "event of packet {i}");
            if let Err(r) = a {
                seen.push(format!("{r:?}"));
            }
            if let Some(Event::CopyConflict { .. }) = e1 {
                seen.push("Conflict".into());
            }
        }
        // The stream exercised every path it was built for (the resend variant is stored).
        for want in [
            "Duplicate",
            "Conflict",
            "BadMac",
            "UnknownSession",
            "Late",
            "Header",
        ] {
            assert!(seen.iter().any(|s| s == want), "{want} not hit: {seen:?}");
        }
    }
}
