//! The data join (07 §5.4, §6.4 item 3): client packets from the data tier, joined to the
//! PacketRecords of a block by `(session, pkt_seq)` and checked by `pkt_hash` and `data_root`.
//!
//! **Writer.** The data RX cores put each payload they receive from the session's data home
//! ([`DataJoin::put`]). A resend of one `pkt_seq` may differ in its unsigned bytes (04 D3), so a
//! key holds every variant, and a record picks the variant whose `pkt_hash` it names.
//!
//! **Readers.** The vote reads [`DataJoin::check`] for a ready block: `Pending` while a payload
//! is missing, an error when its own `data_root` differs from the header's. Replay reads payloads
//! through [`vyrn_engine::Payloads`].
//!
//! **Hashes.** A packet's full hash is BLAKE3 of its signed bytes, `0 .. 16 + 16·count`, the
//! tags excluded (01 §3, as `vyrn-data` hashes them); `pkt_hash` is its first 8 bytes,
//! little-endian. `data_root` is `vyrn_log::block::data_root` over the full hashes of each
//! substream's packets in O-order, Advance records excluded (07 §6.1).

use std::collections::BTreeMap;

use vyrn_log::LaneRec;
use vyrn_log::block::data_root;
use vyrn_types::{Hash, PacketFlags, PacketRecord, PktHash, SessionId};

use crate::ports::BlockInputs;

/// One payload variant.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Variant {
    full: Hash,
    bytes: Vec<u8>,
}

/// Why a block's data does not check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DataErr {
    /// A PacketRecord has no payload with its `pkt_hash` yet: ask again (07 §5.5 fetches it).
    #[error("payload missing for session {session:?} pkt_seq {pkt_seq}")]
    Missing { session: SessionId, pkt_seq: u32 },
    /// Every payload is joined, and the block's `data_root` is not the header's.
    #[error("data_root differs from the header")]
    Root,
}

/// Payloads by `(session, pkt_seq)`.
#[derive(Clone, Debug, Default)]
pub struct DataJoin {
    by_key: BTreeMap<(SessionId, u32), Vec<Variant>>,
}

/// The signed bytes of a request packet: its 16-byte header and `count` 16-byte messages.
fn signed(bytes: &[u8]) -> &[u8] {
    let n = usize::from(bytes.get(8).copied().unwrap_or(0));
    bytes
        .get(..n.saturating_mul(16).saturating_add(16))
        .unwrap_or(bytes)
}

/// The full hash of a packet (01 §3).
pub fn full_hash(bytes: &[u8]) -> Hash {
    vyrn_crypto::hash::hash(signed(bytes))
}

fn prefix(h: &Hash) -> PktHash {
    let mut b = [0u8; 8];
    b.iter_mut().zip(h.0.iter()).for_each(|(d, s)| *d = *s);
    PktHash(u64::from_le_bytes(b))
}

impl DataJoin {
    /// Stores one payload; a byte-identical copy is stored once. Returns its full hash.
    pub fn put(&mut self, session: SessionId, pkt_seq: u32, bytes: Vec<u8>) -> Hash {
        let full = full_hash(&bytes);
        let vars = self.by_key.entry((session, pkt_seq)).or_default();
        if !vars.iter().any(|v| v.full == full) {
            vars.push(Variant { full, bytes });
        }
        full
    }

    fn variant(&self, r: &PacketRecord) -> Option<&Variant> {
        self.by_key
            .get(&(r.session, r.pkt_seq))?
            .iter()
            .find(|v| prefix(&v.full) == r.pkt_hash)
    }

    /// The payload and full hash a record names, if held.
    pub fn resolve(&self, r: &PacketRecord) -> Option<(&[u8], Hash)> {
        self.variant(r).map(|v| (v.bytes.as_slice(), v.full))
    }

    /// Vote-rule item 3 for one ready block: every packet is joined and `data_root` matches.
    pub fn check<const N: usize>(&self, b: &BlockInputs<N>) -> Result<(), DataErr> {
        let mut halves: [Vec<Hash>; 2] = [Vec::new(), Vec::new()];
        for (i, r) in b.lanes.iter().enumerate() {
            let LaneRec::Pkt(p) = r else { continue };
            if p.flags & PacketFlags::ADVANCE != 0 {
                continue;
            }
            let (_, full) = self.resolve(p).ok_or(DataErr::Missing {
                session: p.session,
                pkt_seq: p.pkt_seq,
            })?;
            let half = usize::from(i >= b.split);
            if let Some(h) = halves.get_mut(half) {
                h.push(full);
            }
        }
        let [a, bb] = &halves;
        if data_root(a, bb) == b.header.data_root {
            Ok(())
        } else {
            Err(DataErr::Root)
        }
    }

    /// Forgets every payload of the given records, once their block is replayed and stored.
    pub fn release<'a>(&mut self, recs: impl IntoIterator<Item = &'a LaneRec>) {
        for r in recs {
            if let LaneRec::Pkt(p) = r {
                self.by_key.remove(&(p.session, p.pkt_seq));
            }
        }
    }
}

impl vyrn_engine::Payloads for DataJoin {
    fn get(&self, r: &PacketRecord) -> Option<&[u8]> {
        self.resolve(r).map(|(b, _)| b)
    }
}
