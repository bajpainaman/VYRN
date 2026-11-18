//! The ingest pipeline of one data home (07 §5.2 steps 1–5), with no NIC: bytes in, a verdict
//! out. Fan-out (step 6) is the node's.

use std::collections::BTreeMap;

use vyrn_crypto::hash::hash;
use vyrn_types::{BookId, Hash, MAX_REQ_PAYLOAD, Nanos, PktHash, SessionId};
use vyrn_wire::Request;

use crate::dedupe::{Dedupe, Seen};
use crate::ring::Ring;

/// Which tag the home checks (07 §5.2 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `tag_seq` under `K_seq`.
    Base,
    /// `tag_com` under `K_com`.
    Chain,
}

#[derive(Clone, Debug)]
pub struct HomeConfig {
    pub mode: Mode,
    /// The books this home serves.
    pub books: Vec<BookId>,
    /// The MAC key of each session, `K_seq` (BASE) or `K_com` (CHAIN).
    pub keys: BTreeMap<SessionId, [u8; 16]>,
    /// RAM ring slots.
    pub ring_slots: usize,
}

/// Why a packet was dropped (crate docs, § Ingest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("malformed header")]
    Header,
    #[error("book not served by this home")]
    Book,
    #[error("no key for the session")]
    UnknownSession,
    #[error("bad MAC")]
    BadMac,
    #[error("duplicate")]
    Duplicate,
    #[error("below the dedupe window")]
    Late,
}

/// A packet that was stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ingested {
    pub session: SessionId,
    pub pkt_seq: u32,
    pub book: BookId,
    pub epoch16: u16,
    pub hash: Hash,
    pub pkt_hash: PktHash,
    /// False for a conflicting second copy, which is stored but not forwarded.
    pub forward: bool,
}

/// A copy of one request packet, for evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    len: u8,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Packet {
    pub fn new(b: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_REQ_PAYLOAD];
        let n = b.len().min(MAX_REQ_PAYLOAD);
        if let (Some(d), Some(s)) = (bytes.get_mut(..n), b.get(..n)) {
            d.copy_from_slice(s);
        }
        Self {
            len: u8::try_from(n).unwrap_or(0),
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// What the control core is told (07 §5.2 steps 2 and 3).
// The evidence is inline so that raising an event never allocates; events are rare.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `DataBadMac{session, pkt_seq}`, for the sequencer's control core.
    BadMac { session: SessionId, pkt_seq: u32 },
    /// `CopyConflict{session, pkt_seq, h1, h2}` with both packets as evidence.
    CopyConflict {
        session: SessionId,
        pkt_seq: u32,
        h1: Hash,
        h2: Hash,
        first: Packet,
        second: Packet,
    },
}

#[derive(Debug)]
pub struct DataHome {
    mode: Mode,
    books: Vec<BookId>,
    keys: BTreeMap<SessionId, [u8; 16]>,
    dedupe: Dedupe,
    ring: Ring,
}

impl DataHome {
    pub fn new(cfg: HomeConfig) -> Self {
        Self {
            mode: cfg.mode,
            books: cfg.books,
            keys: cfg.keys,
            dedupe: Dedupe::default(),
            ring: Ring::new(cfg.ring_slots),
        }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    /// Runs 07 §5.2 steps 1–5 on one UDP payload. An event, if any, is written to `event`.
    pub fn ingest(
        &mut self,
        pkt: &[u8],
        rx_ts: Nanos,
        event: &mut Option<Event>,
    ) -> Result<Ingested, Reject> {
        let req = Request::parse(pkt).map_err(|_| Reject::Header)?;
        req.check_header().map_err(|_| Reject::Header)?;
        let h = req.header();
        let (session, pkt_seq) = (h.session(), h.pkt_seq.get());
        if pkt_seq == 0 {
            return Err(Reject::Header);
        }
        let book = h.book();
        if !self.books.contains(&book) {
            return Err(Reject::Book);
        }
        let key = self.keys.get(&session).ok_or(Reject::UnknownSession)?;
        let ok = match self.mode {
            Mode::Base => req.verify_seq(key),
            Mode::Chain => req.verify_com(key),
        };
        if !ok {
            *event = Some(Event::BadMac { session, pkt_seq });
            return Err(Reject::BadMac);
        }
        let full = hash(req.signed_bytes());
        let mut forward = true;
        match self.dedupe.mark(session, pkt_seq) {
            Seen::New => {}
            Seen::Late => return Err(Reject::Late),
            Seen::Repeat => match self.ring.get(session, pkt_seq) {
                Some(first) if first.hash != full => {
                    *event = Some(Event::CopyConflict {
                        session,
                        pkt_seq,
                        h1: first.hash,
                        h2: full,
                        first: Packet::new(first.bytes()),
                        second: Packet::new(pkt),
                    });
                    forward = false;
                }
                // Equal, or the first copy has left the ring and cannot be compared.
                _ => return Err(Reject::Duplicate),
            },
        }
        self.ring.put(session, pkt_seq, full, rx_ts, pkt, forward);
        Ok(Ingested {
            session,
            pkt_seq,
            book,
            epoch16: h.epoch16.get(),
            hash: full,
            pkt_hash: pkt_hash_of(&full),
            forward,
        })
    }
}

/// `PktHash`: the first 8 bytes of the full hash, little-endian (01 §3).
pub fn pkt_hash_of(full: &Hash) -> PktHash {
    let mut b = [0u8; 8];
    b.copy_from_slice(full.0.get(..8).unwrap_or(&[0; 8]));
    PktHash(u64::from_le_bytes(b))
}
