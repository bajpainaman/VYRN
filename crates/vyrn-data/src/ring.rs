//! The RAM ring (07 §5.2 step 5): fixed slots of `MAX_REQ_PAYLOAD` bytes, overwritten oldest
//! first, and an index from `(session, pkt_seq)` to the slot of the first copy stored.
//!
//! A conflicting second copy (07 §5.2 step 3) takes a slot but is not indexed: lookups return the
//! first copy, which is the one forwarded.

use std::collections::BTreeMap;

use vyrn_types::{Hash, MAX_REQ_PAYLOAD, Nanos, SessionId};

#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub session: SessionId,
    pub pkt_seq: u32,
    pub hash: Hash,
    pub rx_ts: Nanos,
    len: u16,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Slot {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

#[derive(Debug)]
pub struct Ring {
    slots: Vec<Option<Slot>>,
    next: usize,
    index: BTreeMap<(SessionId, u32), usize>,
}

impl Ring {
    /// `slots` ≥ 1 packets of retention.
    pub fn new(slots: usize) -> Self {
        let slots = slots.max(1);
        Self {
            slots: vec![None; slots],
            next: 0,
            index: BTreeMap::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
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
        let Some(slot) = self.slots.get_mut(at) else {
            return;
        };
        if let Some(old) = slot.take() {
            let k = (old.session, old.pkt_seq);
            if self.index.get(&k) == Some(&at) {
                self.index.remove(&k);
            }
        }
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
            len: u16::try_from(n).unwrap_or(0),
            bytes,
        });
        if indexed {
            self.index.insert((session, pkt_seq), at);
        }
    }

    /// The first stored copy of `(session, pkt_seq)`, if it is still in the ring.
    pub fn get(&self, session: SessionId, pkt_seq: u32) -> Option<&Slot> {
        let at = *self.index.get(&(session, pkt_seq))?;
        self.slots.get(at)?.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_and_keeps_the_first_copy_indexed() {
        let mut r = Ring::new(3);
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
    }
}
