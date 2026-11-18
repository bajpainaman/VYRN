//! The data join (07 §5.4, §6.4 item 3): client packets from the data tier, joined to the
//! PacketRecords of a block by `(session, pkt_seq)` and checked by `pkt_hash` and `data_root`.
//!
//! **Writer.** The data RX cores put each payload they receive from the session's data home
//! ([`DataJoin::put`]). A resend of one `pkt_seq` may differ in its unsigned bytes (04 D3), so a
//! key holds every variant, and a record picks the variant whose `pkt_hash` it names.
//!
//! **Retention** (07 §5.4). A payload no ORDER record has referenced yet ([`DataJoin::reference`],
//! at block readiness) expires once [`REP_SHED_KEEP_BLOCKS`] blocks have become final after it
//! arrived ([`DataJoin::finalized`]); at most [`REP_DATA_UNREF_MAX`] such payloads are held, and
//! a put above that evicts the oldest first. [`DataJoin::evictions`] counts both. Referenced
//! payloads leave only by [`DataJoin::release`].
//!
//! **Readers.** The vote reads [`DataJoin::check`] for a ready block: `Missing` (ask again)
//! while a payload is absent, `Count` when a payload with the record's hash has another number of
//! numbered messages, `Root` when its own `data_root` differs from the header's. Replay reads payloads
//! through [`vyrn_engine::Payloads`].
//!
//! **Hashes.** A packet's full hash is BLAKE3 of its signed bytes, `0 .. 16 + 16·count`, the
//! tags excluded (01 §3, as `vyrn-data` hashes them); `pkt_hash` is its first 8 bytes,
//! little-endian. `data_root` is `vyrn_log::block::data_root` over the full hashes of each
//! substream's packets in O-order, Advance and `SHED` records excluded (07 §6.1). A `SHED`
//! record is not joined: its responses come from the record alone (05 §18 Q17).

use std::collections::{BTreeMap, VecDeque};

use vyrn_log::LaneRec;
use vyrn_log::block::data_root;
use vyrn_types::{Hash, Height, PacketFlags, PacketRecord, PktHash, SessionId};

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
    /// A payload with the record's `pkt_hash` whose numbered messages do not match the
    /// record's `count` (07 §5.4).
    #[error("count of session {session:?} pkt_seq {pkt_seq} differs from its payload")]
    Count { session: SessionId, pkt_seq: u32 },
    /// Every payload is joined, and the block's `data_root` is not the header's.
    #[error("data_root differs from the header")]
    Root,
}

/// Payloads by `(session, pkt_seq)`.
#[derive(Clone, Debug)]
pub struct DataJoin {
    by_key: BTreeMap<(SessionId, u32), Vec<Variant>>,
    /// Variants kept for a bounded window after a release, `(height released, key, hash)`: a
    /// `SHED` record's variant (for its retry), and the unused variants of an accepted packet.
    shed: VecDeque<(Height, (SessionId, u32), PktHash)>,
    /// Records of ready blocks naming each key, not released yet: a SHED record and its retry
    /// share a key, so one release must not end the other's reference.
    refs: BTreeMap<(SessionId, u32), u32>,
    /// Unreferenced variants by arrival order: `(final height at arrival, key, hash)`.
    unref: BTreeMap<u64, (u64, (SessionId, u32), PktHash)>,
    /// The arrival numbers of each key's unreferenced variants, to drop them on reference.
    unref_keys: BTreeMap<(SessionId, u32), Vec<u64>>,
    next_arrival: u64,
    /// The highest final height reported to [`DataJoin::finalized`].
    final_height: u64,
    cap: usize,
    evicted: Evictions,
}

impl Default for DataJoin {
    fn default() -> Self {
        Self::with_cap(REP_DATA_UNREF_MAX)
    }
}

/// Unreferenced payloads [`DataJoin`] dropped (07 §5.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Evictions {
    /// [`REP_SHED_KEEP_BLOCKS`] blocks became final after it arrived.
    pub expired: u64,
    /// Over [`REP_DATA_UNREF_MAX`], oldest first.
    pub capped: u64,
}

/// Unreferenced payloads a replica holds at most (07 §5.4): the `vyrn-data` RAM ring's
/// 65,536 slots, so the box can still serve any payload the replica dropped
/// [Reading: the coordinator's ruling names a cap, not its size; PR body].
pub const REP_DATA_UNREF_MAX: usize = 65_536;

/// Blocks a released `SHED` record's payload is kept for its retry, which reuses the packet's
/// `pkt_seq` (05 §6.8, `vyrn-lane` `answer_busy`) and may have the same bytes. 128 blocks
/// (≈ 128 ms) covers `REP_CLIENT_RETAIN_MS` = 100 (07 §5.6) [Guessing: spec gap, PR body].
pub const REP_SHED_KEEP_BLOCKS: u64 = 128;

/// The signed bytes of a request packet: its 16-byte header and `count` 16-byte messages.
fn signed(bytes: &[u8]) -> &[u8] {
    let n = usize::from(bytes.get(8).copied().unwrap_or(0));
    bytes
        .get(..n.saturating_mul(16).saturating_add(16))
        .unwrap_or(bytes)
}

/// Whether a record's `count` fits its payload (07 §5.4, 05 §3.1). As the lane assigns them
/// (`vyrn-lane` pass 1), every message takes a LaneSeq except one that decodes as a Heartbeat or
/// ResendReq, in a packet with no packet-level reject; a malformed one is answered with a reject
/// and takes a LaneSeq. A packet-level reject numbers every message. The replica cannot see that
/// reject, so either count is accepted [Likely: spec gap, PR body].
pub fn count_fits(count: u8, bytes: &[u8]) -> bool {
    let n = bytes.get(8).copied().unwrap_or(0);
    let unnumbered = (0..usize::from(n))
        .filter_map(|i| {
            let at = i.saturating_mul(16).saturating_add(16);
            bytes.get(at..at.saturating_add(16))?.try_into().ok()
        })
        .filter(|m: &&[u8; 16]| {
            matches!(
                vyrn_wire::Msg::decode(m),
                Ok(vyrn_wire::Msg::Heartbeat) | Ok(vyrn_wire::Msg::ResendReq { .. })
            )
        })
        .count();
    let numbered = usize::from(n).saturating_sub(unnumbered);
    usize::from(count) == numbered || count == n
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
    /// A join that holds at most `cap` unreferenced payloads.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            by_key: BTreeMap::new(),
            shed: VecDeque::new(),
            refs: BTreeMap::new(),
            unref: BTreeMap::new(),
            unref_keys: BTreeMap::new(),
            next_arrival: 0,
            final_height: 0,
            cap,
            evicted: Evictions::default(),
        }
    }

    /// Stores one payload; a byte-identical copy is stored once. Returns its full hash. A
    /// payload of a key no ready block names yet is unreferenced (module docs, retention).
    pub fn put(&mut self, session: SessionId, pkt_seq: u32, bytes: Vec<u8>) -> Hash {
        let full = full_hash(&bytes);
        let key = (session, pkt_seq);
        let vars = self.by_key.entry(key).or_default();
        if !vars.iter().any(|v| v.full == full) {
            vars.push(Variant { full, bytes });
            if !self.refs.contains_key(&key) {
                let n = self.next_arrival;
                self.next_arrival = n.wrapping_add(1);
                self.unref
                    .insert(n, (self.final_height, key, prefix(&full)));
                self.unref_keys.entry(key).or_default().push(n);
                while self.unref.len() > self.cap {
                    if let Some((_, (_, k, h))) = self.unref.pop_first() {
                        self.drop_unref(k, h);
                        self.evicted.capped = self.evicted.capped.saturating_add(1);
                    }
                }
            }
        }
        full
    }

    /// A ready block's records name their keys: their payloads, held or to come, are referenced
    /// and leave only by [`DataJoin::release`].
    pub fn reference<const N: usize>(&mut self, b: &BlockInputs<N>) {
        for r in &b.lanes {
            let LaneRec::Pkt(p) = r else { continue };
            let key = (p.session, p.pkt_seq);
            let n = self.refs.entry(key).or_default();
            *n = n.saturating_add(1);
            self.unlist(key);
        }
    }

    /// Takes `key`'s payloads out of the unreferenced set: a record names them.
    fn unlist(&mut self, key: (SessionId, u32)) {
        for n in self.unref_keys.remove(&key).unwrap_or_default() {
            self.unref.remove(&n);
        }
    }

    /// `height` is final: unreferenced payloads that arrived [`REP_SHED_KEEP_BLOCKS`] or more
    /// final blocks ago expire.
    pub fn finalized(&mut self, height: Height) {
        self.final_height = self.final_height.max(height.0);
        while let Some((&n, &(at, k, h))) = self.unref.first_key_value() {
            if at.saturating_add(REP_SHED_KEEP_BLOCKS) > self.final_height {
                break;
            }
            self.unref.remove(&n);
            self.drop_unref(k, h);
            self.evicted.expired = self.evicted.expired.saturating_add(1);
        }
    }

    /// The unreferenced payloads dropped so far.
    pub fn evictions(&self) -> Evictions {
        self.evicted
    }

    /// Drops an unreferenced variant whose `unref` entry is already gone.
    fn drop_unref(&mut self, key: (SessionId, u32), hash: PktHash) {
        if let Some(ns) = self.unref_keys.get_mut(&key) {
            ns.retain(|n| self.unref.contains_key(n));
            if ns.is_empty() {
                self.unref_keys.remove(&key);
            }
        }
        self.evict(key, hash);
    }

    fn variant(&self, r: &PacketRecord) -> Option<&Variant> {
        self.by_key
            .get(&(r.session, r.pkt_seq))?
            .iter()
            .find(|v| prefix(&v.full) == r.pkt_hash)
    }

    /// The payload and full hash a record names, if held and its `count` fits (07 §5.4).
    pub fn resolve(&self, r: &PacketRecord) -> Result<(&[u8], Hash), DataErr> {
        let v = self.variant(r).ok_or(DataErr::Missing {
            session: r.session,
            pkt_seq: r.pkt_seq,
        })?;
        if !count_fits(r.count, &v.bytes) {
            return Err(DataErr::Count {
                session: r.session,
                pkt_seq: r.pkt_seq,
            });
        }
        Ok((v.bytes.as_slice(), v.full))
    }

    /// Vote-rule item 3 for one ready block: every packet is joined and `data_root` matches.
    pub fn check<const N: usize>(&self, b: &BlockInputs<N>) -> Result<(), DataErr> {
        let mut halves: [Vec<Hash>; 2] = [Vec::new(), Vec::new()];
        for (i, r) in b.lanes.iter().enumerate() {
            let LaneRec::Pkt(p) = r else { continue };
            // Advance and `SHED` records are outside the join and `data_root` (07 §6.1,
            // 05 §18 Q17): replay never reads a shed packet's bytes.
            if p.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) != 0 {
                continue;
            }
            let (_, full) = self.resolve(p)?;
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

    /// Releases the payloads of block `height`'s records once that block is replayed and
    /// stored. Only the variant each record names (by `pkt_hash`) goes, so other variants of its
    /// `(session, pkt_seq)` stay. A `SHED` record's variant stays [`REP_SHED_KEEP_BLOCKS`] more
    /// blocks, for the retry that reuses its `pkt_seq`; a retry released in a later block frees
    /// it at once, and a later `SHED` record of the same variant extends the window. The other
    /// variants of an accepted packet expire after the same window. Calls come in non-decreasing
    /// `height`.
    pub fn release<'a>(&mut self, height: Height, recs: impl IntoIterator<Item = &'a LaneRec>) {
        for r in recs {
            let LaneRec::Pkt(p) = r else { continue };
            if p.flags & PacketFlags::ADVANCE != 0 {
                continue;
            }
            let key = (p.session, p.pkt_seq);
            // A released record named its key, referenced or not (a caller may release without
            // `reference`): its payloads now follow the release rules below, not the cap.
            self.unlist(key);
            if let Some(n) = self.refs.get_mut(&key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.refs.remove(&key);
                }
            }
            if p.flags & PacketFlags::SHED != 0 {
                self.shed.push_back((height, key, p.pkt_hash));
            } else {
                self.evict(key, p.pkt_hash);
                // Other variants of an accepted packet (resends the sequencer did not take) have
                // no record left to release them: they expire after the same window.
                let rest: Vec<PktHash> = self
                    .by_key
                    .get(&key)
                    .map(|vs| vs.iter().map(|v| prefix(&v.full)).collect())
                    .unwrap_or_default();
                for h in rest {
                    if !self.shed.iter().any(|&(_, k, x)| k == key && x == h) {
                        self.shed.push_back((height, key, h));
                    }
                }
            }
        }
        while let Some(&(h, key, hash)) = self.shed.front() {
            if h.0.saturating_add(REP_SHED_KEEP_BLOCKS) > height.0 {
                break;
            }
            self.shed.pop_front();
            // A later SHED record of the same variant (the retry was shed again) keeps it.
            if !self.shed.iter().any(|&(_, k, x)| k == key && x == hash) {
                self.evict(key, hash);
            }
        }
    }

    fn evict(&mut self, key: (SessionId, u32), hash: PktHash) {
        if let Some(vars) = self.by_key.get_mut(&key) {
            vars.retain(|v| prefix(&v.full) != hash);
            if vars.is_empty() {
                self.by_key.remove(&key);
            }
        }
    }
}

impl vyrn_engine::Payloads for DataJoin {
    fn get(&self, r: &PacketRecord) -> Option<&[u8]> {
        self.resolve(r).ok().map(|(b, _)| b)
    }
}
