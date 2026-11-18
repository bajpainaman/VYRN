//! The RAM ring (07 §5.2 step 5): fixed slots of `MAX_REQ_PAYLOAD` bytes, overwritten oldest
//! first, and a fixed open-addressed index from `(session, pkt_seq)` to slots holding
//! `(session, pkt_seq, pkt_hash, slot)`.
//!
//! Both are sized at construction and never grow: [`Ring::put`] and every lookup allocate
//! nothing. The index has at least twice as many buckets as the ring has slots (load ≤ 0.5),
//! uses linear probing, and deletes by backward shift, so it never holds tombstones.
//!
//! *Gap (07 §5.2 step 5):* 07 keys the table by `pkt_hash`. The data box is looked up by
//! `(session, pkt_seq)` (dedupe, the KEY fetch), which a `pkt_hash` key cannot answer, so the
//! bucket is SipHash-2-4 of `(session, pkt_seq)` under a per-box secret `index_key`, and each
//! entry also carries `pkt_hash`. The secret keeps a client from steering its packets into one
//! probe chain: the hashed bytes are its own.
//!
//! One `pkt_seq` may have several indexed variants: transmissions with the same logical content
//! whose `flags` bit 0 or `epoch16` differ (04 D3), so their hashes differ too. The sequencer may
//! accept any of them, so each is kept. A conflicting copy (07 §5.2 step 3) takes a slot but is
//! not indexed.

use vyrn_crypto::siphash24;
use vyrn_types::{Hash, MAX_REQ_PAYLOAD, Nanos, SessionId};

#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub session: SessionId,
    pub pkt_seq: u32,
    pub hash: Hash,
    pub rx_ts: Nanos,
    indexed: bool,
    len: u16,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Slot {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// One bucket. `slot == EMPTY` marks a free bucket.
#[derive(Clone, Copy, Debug)]
struct Entry {
    session: u32,
    pkt_seq: u32,
    slot: u32,
    /// The bucket the key hashes to, kept so a backward shift needs no rehash.
    home: u32,
    pkt_hash: u64,
}

const EMPTY: u32 = u32::MAX;
const FREE: Entry = Entry {
    session: 0,
    pkt_seq: 0,
    slot: EMPTY,
    home: 0,
    pkt_hash: 0,
};

#[derive(Debug)]
pub struct Ring {
    slots: Vec<Option<Slot>>,
    next: usize,
    table: Vec<Entry>,
    mask: usize,
    key: [u8; 16],
}

impl Ring {
    /// `slots` packets of retention, 1 ..= 2^30; `index_key` is the bucket hash's secret.
    pub fn new(slots: usize, index_key: [u8; 16]) -> Self {
        let slots = slots.clamp(1, 1 << 30);
        let buckets = slots.saturating_mul(2).next_power_of_two();
        Self {
            slots: vec![None; slots],
            next: 0,
            table: vec![FREE; buckets],
            mask: buckets - 1,
            key: index_key,
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn bucket(&self, session: SessionId, pkt_seq: u32) -> usize {
        let mut b = [0u8; 8];
        let (lo, hi) = b.split_at_mut(4);
        lo.copy_from_slice(&session.0.to_le_bytes());
        hi.copy_from_slice(&pkt_seq.to_le_bytes());
        // Truncation is the point: the low bits pick the bucket.
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let h = siphash24(&self.key, &b).0 as usize;
        h & self.mask
    }

    fn at(&self, i: usize) -> Entry {
        self.table.get(i).copied().unwrap_or(FREE)
    }

    /// Stores `pkt` (at most `MAX_REQ_PAYLOAD` bytes), evicting the oldest slot. `indexed` is
    /// false for a conflicting second copy.
    pub fn put(
        &mut self,
        session: SessionId,
        pkt_seq: u32,
        hash: Hash,
        rx_ts: Nanos,
        pkt: &[u8],
        indexed: bool,
    ) {
        let at = self.next;
        self.next = (at + 1) % self.slots.len();
        if let Some(old) = self.slots.get(at).copied().flatten()
            && old.indexed
        {
            self.unindex(old.session, old.pkt_seq, at);
        }
        let Some(slot) = self.slots.get_mut(at) else {
            return;
        };
        let mut bytes = [0u8; MAX_REQ_PAYLOAD];
        let n = pkt.len().min(MAX_REQ_PAYLOAD);
        if let (Some(d), Some(s)) = (bytes.get_mut(..n), pkt.get(..n)) {
            d.copy_from_slice(s);
        }
        *slot = Some(Slot {
            session,
            pkt_seq,
            hash,
            rx_ts,
            indexed,
            len: u16::try_from(n).unwrap_or(0),
            bytes,
        });
        if indexed {
            self.index(session, pkt_seq, crate::ingest::pkt_hash_of(&hash).0, at);
        }
    }

    fn index(&mut self, session: SessionId, pkt_seq: u32, pkt_hash: u64, slot: usize) {
        let home = self.bucket(session, pkt_seq);
        let mut i = home;
        // Load ≤ 0.5, so a free bucket exists and the loop ends.
        while self.at(i).slot != EMPTY {
            i = (i + 1) & self.mask;
        }
        if let Some(e) = self.table.get_mut(i) {
            *e = Entry {
                session: session.0,
                pkt_seq,
                slot: u32::try_from(slot).unwrap_or(EMPTY),
                home: u32::try_from(home).unwrap_or(0),
                pkt_hash,
            };
        }
    }

    fn unindex(&mut self, session: SessionId, pkt_seq: u32, slot: usize) {
        let mut i = self.bucket(session, pkt_seq);
        let slot = u32::try_from(slot).unwrap_or(EMPTY);
        loop {
            let e = self.at(i);
            if e.slot == EMPTY {
                return;
            }
            if e.slot == slot {
                break;
            }
            i = (i + 1) & self.mask;
        }
        // Backward shift: pull each later entry of the run into the hole unless its home lies
        // cyclically in (hole, j].
        let mut hole = i;
        let mut j = i;
        loop {
            j = (j + 1) & self.mask;
            let e = self.at(j);
            if e.slot == EMPTY {
                break;
            }
            let h = usize::try_from(e.home).unwrap_or(0);
            let stays = if hole <= j {
                hole < h && h <= j
            } else {
                hole < h || h <= j
            };
            if !stays {
                if let Some(d) = self.table.get_mut(hole) {
                    *d = e;
                }
                hole = j;
            }
        }
        if let Some(d) = self.table.get_mut(hole) {
            *d = FREE;
        }
    }

    /// Every indexed variant of `(session, pkt_seq)` still in the ring, in the order stored.
    pub fn variants(&self, session: SessionId, pkt_seq: u32) -> impl Iterator<Item = &Slot> {
        let mut i = self.bucket(session, pkt_seq);
        let mut done = false;
        core::iter::from_fn(move || {
            while !done {
                let e = self.at(i);
                i = (i + 1) & self.mask;
                if e.slot == EMPTY {
                    done = true;
                } else if (e.session, e.pkt_seq) == (session.0, pkt_seq) {
                    let s = usize::try_from(e.slot).ok()?;
                    return self.slots.get(s)?.as_ref();
                }
            }
            None
        })
    }

    /// The indexed variant of `(session, pkt_seq)` whose `pkt_hash` is `pkt_hash`. The key is
    /// matched too, because 8-byte hashes collide (07 §5.2 step 5).
    pub fn find(&self, session: SessionId, pkt_seq: u32, pkt_hash: u64) -> Option<&Slot> {
        let mut i = self.bucket(session, pkt_seq);
        loop {
            let e = self.at(i);
            if e.slot == EMPTY {
                return None;
            }
            if (e.session, e.pkt_seq, e.pkt_hash) == (session.0, pkt_seq, pkt_hash) {
                return self.slots.get(usize::try_from(e.slot).ok()?)?.as_ref();
            }
            i = (i + 1) & self.mask;
        }
    }

    /// One indexed variant of `(session, pkt_seq)`, if any is still in the ring.
    pub fn get(&self, session: SessionId, pkt_seq: u32) -> Option<&Slot> {
        self.variants(session, pkt_seq).next()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn evicts_oldest_and_keeps_the_first_copy_indexed() {
        let mut r = Ring::new(3, [9; 16]);
        let s = SessionId(1);
        r.put(s, 1, Hash([1; 32]), Nanos(0), b"a", true);
        r.put(s, 1, Hash([2; 32]), Nanos(0), b"b", false);
        assert_eq!(r.get(s, 1).map(|x| x.bytes()), Some(&b"a"[..]));
        r.put(s, 2, Hash([3; 32]), Nanos(0), b"c", true);
        // Slot 0 (pkt 1's first copy) is overwritten; the unindexed second copy does not stand
        // in for it.
        r.put(s, 3, Hash([4; 32]), Nanos(0), b"d", true);
        assert!(r.get(s, 1).is_none());
        assert_eq!(r.get(s, 3).map(|x| x.bytes()), Some(&b"d"[..]));
        // Overwriting the unindexed slot leaves pkt 2's entry alone.
        r.put(s, 4, Hash([5; 32]), Nanos(0), b"e", true);
        assert_eq!(r.get(s, 2).map(|x| x.bytes()), Some(&b"c"[..]));
        let ph = crate::ingest::pkt_hash_of(&Hash([3; 32])).0;
        assert!(r.find(s, 2, ph).is_some());
        assert!(r.find(s, 2, ph ^ 1).is_none(), "same key, other hash");
        assert!(
            r.find(SessionId(2), 2, ph).is_none(),
            "same hash, other key"
        );
    }

    /// Against a model of what the ring must hold: the last `slots` puts. A tiny table (8 slots,
    /// 16 buckets) and few keys make long probe runs that wrap, so every backward-shift case runs.
    #[test]
    fn matches_a_model_under_wrapping_probe_runs() {
        const N: usize = 8;
        let mut r = Ring::new(N, [3; 16]);
        let mut live: Vec<(u32, u32, u8, bool)> = Vec::new();
        let mut x = 0x9e37_79b9_u32;
        for step in 0..20_000u32 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let (s, q, indexed) = (x % 3, (x >> 8) % 5 + 1, x >> 30 != 0);
            let tag = (step % 251) as u8;
            r.put(SessionId(s), q, Hash([tag; 32]), Nanos(0), &[tag], indexed);
            live.push((s, q, tag, indexed));
            if live.len() > N {
                live.remove(0);
            }
            let mut want: BTreeMap<(u32, u32), Vec<u8>> = BTreeMap::new();
            for &(s, q, t, i) in &live {
                if i {
                    want.entry((s, q)).or_default().push(t);
                }
            }
            for s in 0..3 {
                for q in 1..=5 {
                    let got: Vec<u8> = r.variants(SessionId(s), q).map(|v| v.bytes()[0]).collect();
                    let w = want.get(&(s, q)).cloned().unwrap_or_default();
                    assert_eq!(got, w, "step {step} key ({s}, {q})");
                }
            }
        }
    }
}
