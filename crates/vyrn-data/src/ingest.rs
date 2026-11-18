//! The ingest pipeline of one data home (07 §5.2 steps 1–5), with no NIC: bytes in, a verdict
//! out. Fan-out (step 6) is the node's.

use std::collections::BTreeMap;

use vyrn_crypto::hash::hash;
use vyrn_nic::frame::Endpoint;
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
    /// The secret of the ring index's bucket hash (`ring` module docs). Draw it at random per
    /// box; it never leaves the box.
    pub index_key: [u8; 16],
}

/// Variants with the same logical content kept per `pkt_seq` (04 D3 allows `flags` bit 0 and
/// `epoch16` to differ). More are duplicates. *Gap:* 04 sets no bound.
pub const MAX_VARIANTS: usize = 4;

/// Why a packet was dropped (crate docs, § Ingest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reject {
    #[error("malformed header")]
    Header,
    #[error("book not served by this home")]
    Book,
    #[error("no key for the session")]
    UnknownSession,
    #[error("epoch16 is not one this home serves")]
    Epoch,
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

/// One epoch's MAC keys. `epoch16` `None` takes every `epoch16`.
#[derive(Debug)]
struct Keys {
    epoch16: Option<u16>,
    map: BTreeMap<SessionId, [u8; 16]>,
}

impl Keys {
    fn serves(&self, epoch16: u16) -> bool {
        self.epoch16.is_none_or(|e| e == epoch16)
    }
}

/// The two-epoch boundary (08 §4.6). A home holds one key table, for every `epoch16`, as 07 §5.4
/// filters none. From T the new home also holds epoch e + 1's keys ([`DataHome::add_epoch`]);
/// `epoch16` then picks the table, and a copy of neither epoch is dropped as [`Reject::Epoch`]
/// before its MAC is checked, so it raises no `DataBadMac` (08 §8.2 F5, P8). After activation,
/// and at the old home after `EPO_REDIRECT_HOLD_S`, the owner retires epoch e
/// ([`DataHome::retire_epoch`]). Dedupe windows and the ring span both epochs: sessions and
/// `pkt_seq` carry over the boundary (04 H8), so a resend under e + 1 of a packet first sent
/// under e is a D3 variant.
#[derive(Debug)]
pub struct DataHome {
    mode: Mode,
    books: Vec<BookId>,
    /// `None` once its last epoch is retired: then no copy is taken.
    keys: Option<Keys>,
    /// Epoch e + 1 during the boundary.
    next: Option<Keys>,
    dedupe: Dedupe,
    ring: Ring,
}

impl DataHome {
    pub fn new(cfg: HomeConfig) -> Self {
        Self {
            mode: cfg.mode,
            books: cfg.books,
            // Every keyed session gets its window now, so ingest never inserts one.
            dedupe: Dedupe::with_sessions(cfg.keys.keys().copied()),
            keys: Some(Keys {
                epoch16: None,
                map: cfg.keys,
            }),
            next: None,
            ring: Ring::new(cfg.ring_slots, cfg.index_key),
        }
    }

    /// From T (08 §4.6): also accept copies with the low 16 bits of `epoch` under `keys`, its
    /// `K_seq(e+1, ·)` or `K_com(e+1, ·)`. The table held now becomes epoch − 1's alone, and a
    /// table already added is replaced. Cold path: new sessions get their dedupe windows here.
    pub fn add_epoch(&mut self, epoch: u32, keys: BTreeMap<SessionId, [u8; 16]>) {
        let e16 = epoch16_of(epoch);
        if let Some(k) = &mut self.keys {
            k.epoch16 = Some(e16.wrapping_sub(1));
        }
        self.dedupe.add_sessions(keys.keys().copied());
        self.next = Some(Keys {
            epoch16: Some(e16),
            map: keys,
        });
    }

    /// Stops accepting copies of `epoch`: after activation at the new home, after
    /// `EPO_REDIRECT_HOLD_S` at the old one (08 §4.6). Retiring the older table makes the added one
    /// the only one; retiring the only table leaves the home serving no epoch. Already stored
    /// copies stay in the ring and age out.
    pub fn retire_epoch(&mut self, epoch: u32) {
        let e16 = epoch16_of(epoch);
        if self.next.as_ref().is_some_and(|k| k.epoch16 == Some(e16)) {
            self.next = None;
        } else if self.keys.as_ref().is_some_and(|k| k.serves(e16)) {
            self.keys = self.next.take();
        }
    }

    /// Whether a copy with this `epoch16` reaches the MAC check.
    pub fn serves(&self, epoch16: u16) -> bool {
        self.keys_for(epoch16).is_some()
    }

    fn keys_for(&self, epoch16: u16) -> Option<&BTreeMap<SessionId, [u8; 16]>> {
        match (&self.next, &self.keys) {
            (Some(n), _) if n.serves(epoch16) => Some(&n.map),
            (_, Some(k)) if k.serves(epoch16) => Some(&k.map),
            _ => None,
        }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    /// The address of `session`'s newest copy whose MAC passed (07 §5.7 step 3).
    pub fn source(&self, session: SessionId) -> Option<Endpoint> {
        self.dedupe.source(session)
    }

    /// `session`'s MAC key (`K_seq` or `K_com`), which also tags its `DataRedirect`: the newest
    /// epoch's during the boundary, as the client sends under e + 1 from T (04 H2).
    pub fn key(&self, session: SessionId) -> Option<&[u8; 16]> {
        self.next
            .as_ref()
            .and_then(|n| n.map.get(&session))
            .or_else(|| self.keys.as_ref().and_then(|k| k.map.get(&session)))
    }

    /// Runs 07 §5.2 steps 1–5 on one UDP payload. An event, if any, is written to `event`.
    pub fn ingest(
        &mut self,
        pkt: &[u8],
        rx_ts: Nanos,
        event: &mut Option<Event>,
    ) -> Result<Ingested, Reject> {
        self.ingest_from(pkt, None, rx_ts, event)
    }

    /// [`DataHome::ingest`] of a copy from `src`. Once the MAC passes, `src` becomes the
    /// session's address ([`DataHome::source`]), where a `DataRedirect` goes (07 §5.7).
    pub fn ingest_from(
        &mut self,
        pkt: &[u8],
        src: Option<Endpoint>,
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
        let key = self
            .keys_for(h.epoch16.get())
            .ok_or(Reject::Epoch)?
            .get(&session)
            .ok_or(Reject::UnknownSession)?;
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
        let seen = match src {
            Some(a) => self.dedupe.mark_from(session, pkt_seq, a),
            None => self.dedupe.mark(session, pkt_seq),
        };
        match seen {
            Seen::New => {}
            Seen::Late => return Err(Reject::Late),
            Seen::Repeat => {
                let mut vars = self.ring.variants(session, pkt_seq);
                let Some(first) = vars.next() else {
                    // The first copy has left the ring and cannot be compared.
                    return Err(Reject::Duplicate);
                };
                if !same_logical(first.bytes(), pkt) {
                    *event = Some(Event::CopyConflict {
                        session,
                        pkt_seq,
                        h1: first.hash,
                        h2: full,
                        first: Packet::new(first.bytes()),
                        second: Packet::new(pkt),
                    });
                    forward = false;
                } else {
                    // A resend (04 D3). A byte-identical copy, or one past MAX_VARIANTS, is a
                    // duplicate; a new variant is stored and forwarded, because the sequencer
                    // may have accepted these exact bytes.
                    let n = 1usize.saturating_add(vars.count());
                    let dup = self
                        .ring
                        .find(session, pkt_seq, pkt_hash_of(&full).0)
                        .is_some_and(|v| v.hash == full);
                    if dup || n >= MAX_VARIANTS {
                        return Err(Reject::Duplicate);
                    }
                }
            }
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

/// 04 D3: two transmissions of one `pkt_seq` carry the same logical content, `(session,
/// pkt_seq, count, book, message bytes)`. Only `flags` bit 0, `epoch16` and the tags may differ,
/// so those bytes (9..12 and the tags) are not compared. Both packets parsed, so `count` fixes
/// their lengths.
pub fn same_logical(a: &[u8], b: &[u8]) -> bool {
    fn signed(p: &[u8]) -> &[u8] {
        let n = usize::from(p.get(8).copied().unwrap_or(0));
        p.get(..n.saturating_mul(16).saturating_add(16))
            .unwrap_or(&[])
    }
    let (a, b) = (signed(a), signed(b));
    a.len() == b.len() && a.get(..9) == b.get(..9) && a.get(12..) == b.get(12..)
}

/// The low 16 bits of an epoch, as packets carry it (01 §6.1).
pub fn epoch16_of(epoch: u32) -> u16 {
    (epoch & 0xFFFF) as u16
}

/// `PktHash`: the first 8 bytes of the full hash, little-endian (01 §3).
pub fn pkt_hash_of(full: &Hash) -> PktHash {
    let mut b = [0u8; 8];
    b.copy_from_slice(full.0.get(..8).unwrap_or(&[0; 8]));
    PktHash(u64::from_le_bytes(b))
}
