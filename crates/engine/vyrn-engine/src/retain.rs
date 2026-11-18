//! Sequencer packet retention (05 §6.10, `REP_SEQ_PKT_RETAIN_MS`): the bytes of every packet the
//! lanes logged, kept so the sequencer can answer `SeqDataReq` (07 §5.5 source 3). It is the only
//! copy of the exact bytes the sequencer matched, so it settles a mismatch between a client's two
//! copies (07 §5.6).
//!
//! **Writer.** One thread, the sequencer's repair thread ([`Retain::put`]), fed from the RX path
//! with a [`Kept`] for each packet whose lane verdict is `Accepted` or `Shed`: exactly the packets
//! that have a PacketRecord. The live engine thread hands a [`Kept`] (a `Copy` value) through a
//! `vyrn_cut::Ring` and never waits: a full ring loses that copy, which a replica then fetches from
//! another source (07 §5.5).
//!
//! **Reader.** The same thread ([`Retain::find`]).
//!
//! **Memory.** Every slot and index bucket is allocated in [`Retain::new`]; `put` and `find`
//! never allocate. The slots are a FIFO overwritten oldest first. The index is 4-way set
//! associative over `(session, pkt_seq)` with at least eight ways per slot. It is never cleaned:
//! a way is reused when it is empty, when its slot no longer holds that bucket's key, or else when
//! it is the oldest of the four, and a lookup checks the slot's key. A packet can lose its index
//! entry only when a bucket holds more than 4 live packets: at a mean of ≤ 0.5 per bucket that is
//! under 0.1% of them (`a_full_ring_finds_almost_every_live_packet`). Such a packet is a miss,
//! which the other sources cover. The bucket hash is not keyed. A packet shed at dequeue (05 §6.8
//! test D) is retained without a MAC check, because its `SHED` record is logged and the sequencer
//! is the only source of its bytes. Such a packet still names an open session and a `pkt_seq` in
//! its V5 window, so a sender picks among a few thousand keys against ≥ 2 × slots buckets and
//! cannot aim several at one bucket. Repeating one key fills its bucket, but an unchecked packet
//! never takes a way from an accepted (MAC-checked) one. A shed copy displaced this way is lost,
//! which costs nothing: replay and `data_root` do not use a `SHED` record's bytes (05 §18 Q17). A record joins only the variant its `pkt_hash` names (07
//! §5.4), so foreign bytes never enter a block.
//!
//! **Window.** A packet is served while its `rx_ts` is within [`REP_SEQ_PKT_RETAIN_NS`] of the
//! newest `rx_ts` put. Size the slots as peak packet rate × window; fewer slots shorten the
//! window.

use vyrn_types::{MAX_REQ_PAYLOAD, Nanos, PktHash, SessionId};

/// `REP_SEQ_PKT_RETAIN_MS` = 50 (07 §5.5, 13 §2), in nanoseconds.
pub const REP_SEQ_PKT_RETAIN_NS: u64 = 50_000_000;

const WAYS: usize = 4;
/// The most variants one [`Retain::find`] returns: one bucket's ways.
pub const MAX_VARIANTS: usize = WAYS;

/// One retained packet: its exact UDP payload and the fields the lane already computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kept {
    pub session: SessionId,
    pub pkt_seq: u32,
    pub pkt_hash: PktHash,
    pub rx_ts: Nanos,
    /// The lane checked its MAC (verdict `Accepted`). A packet shed at dequeue (05 §6.8 test D)
    /// was never checked, and never takes an index way from one that was.
    pub verified: bool,
    len: u8,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Kept {
    /// A copy of request packet `bytes` (at least its 8-byte `(session, pkt_seq)` prefix, at
    /// most `MAX_REQ_PAYLOAD`), or `None` if it does not fit.
    pub fn new(bytes: &[u8], rx_ts: Nanos, pkt_hash: PktHash) -> Option<Self> {
        let len = u8::try_from(bytes.len()).ok()?;
        let mut b = [0u8; MAX_REQ_PAYLOAD];
        b.get_mut(..bytes.len())?.copy_from_slice(bytes);
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
            ))
        };
        Some(Self {
            session: SessionId(word(0)?),
            pkt_seq: word(4)?,
            pkt_hash,
            rx_ts,
            verified: false,
            len,
            bytes: b,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

#[derive(Clone, Copy)]
struct Slot {
    /// Puts before this one, plus one; 0 is an empty slot.
    seq: u64,
    kept: Kept,
}

/// The retention of one sequencer box (module docs).
pub struct Retain {
    slots: Box<[Slot]>,
    /// Slot index + 1 per way; 0 is empty.
    index: Box<[[u32; WAYS]]>,
    puts: u64,
    newest: Nanos,
}

fn bucket_of(session: SessionId, pkt_seq: u32, mask: u64) -> usize {
    let k = (u64::from(session.0) << 32) | u64::from(pkt_seq);
    // murmur3's fmix64: every input bit reaches every low bit, so sequential `pkt_seq`s of one
    // session spread evenly (a bare multiply leaves them on a lattice of buckets).
    let mut h = k ^ (k >> 33);
    h = h.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    h ^= h >> 33;
    h = h.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    h ^= h >> 33;
    usize::try_from(h & mask).unwrap_or(0)
}

impl Retain {
    /// `slots` packets (at least 1, at most `u32::MAX - 1`). Allocates everything.
    pub fn new(slots: usize) -> Self {
        let n = slots.clamp(1, usize::try_from(u32::MAX - 1).unwrap_or(usize::MAX));
        let empty = Slot {
            seq: 0,
            kept: Kept {
                session: SessionId(0),
                pkt_seq: 0,
                pkt_hash: PktHash(0),
                rx_ts: Nanos(0),
                verified: false,
                len: 0,
                bytes: [0; MAX_REQ_PAYLOAD],
            },
        };
        // ≥ 8 ways per slot: buckets = 2 × the next power of two ≥ n, a mean ≤ 0.5 live packets
        // per 4-way bucket (32 B of index per 216 B slot).
        let buckets = n.next_power_of_two().saturating_mul(2);
        Self {
            slots: vec![empty; n].into_boxed_slice(),
            index: vec![[0; WAYS]; buckets].into_boxed_slice(),
            puts: 0,
            newest: Nanos(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn mask(&self) -> u64 {
        u64::try_from(self.index.len()).unwrap_or(1).wrapping_sub(1)
    }

    /// The slot behind way value `w` if it holds `(session, pkt_seq)`.
    fn live(&self, w: u32, session: SessionId, pkt_seq: u32) -> Option<&Slot> {
        let at = usize::try_from(w.checked_sub(1)?).ok()?;
        let s = self.slots.get(at)?;
        (s.seq != 0 && s.kept.session == session && s.kept.pkt_seq == pkt_seq).then_some(s)
    }

    /// Stores `k`, overwriting the oldest slot.
    pub fn put(&mut self, k: Kept) {
        let n = u64::try_from(self.slots.len()).unwrap_or(1);
        let at = usize::try_from(self.puts.checked_rem(n).unwrap_or(0)).unwrap_or(0);
        self.puts = self.puts.wrapping_add(1);
        self.newest = self.newest.max(k.rx_ts);
        let Some(slot) = self.slots.get_mut(at) else {
            return;
        };
        *slot = Slot {
            seq: self.puts,
            kept: k,
        };
        let b = bucket_of(k.session, k.pkt_seq, self.mask());
        let Some(ways) = self.index.get(b).copied() else {
            return;
        };
        let mine = u32::try_from(at.wrapping_add(1)).unwrap_or(0);
        // A way that already names this slot is reused, so no two ways name one slot. Else a way
        // is free when empty or when its slot left this bucket. Else the oldest unverified way
        // goes, then the oldest verified one, but only for a verified packet: an unchecked shed
        // packet is left unindexed before it displaces an accepted one.
        let mut free = None;
        let mut victim: Option<(bool, u64, usize)> = None;
        let reuse = ways.iter().position(|&w| w == mine);
        for (i, &w) in ways.iter().enumerate() {
            if reuse.is_some() {
                break;
            }
            let held = usize::try_from(w.wrapping_sub(1))
                .ok()
                .and_then(|a| self.slots.get(a))
                .filter(|s| w != 0 && w != mine && s.seq != 0)
                .filter(|s| bucket_of(s.kept.session, s.kept.pkt_seq, self.mask()) == b);
            match held {
                None => {
                    free = Some(i);
                    break;
                }
                Some(s) => {
                    let rank = (s.kept.verified, s.seq, i);
                    if victim.is_none_or(|v| rank < v) {
                        victim = Some(rank);
                    }
                }
            }
        }
        let pick = match (reuse.or(free), victim) {
            (Some(i), _) => i,
            (None, Some((false, _, i))) => i,
            (None, Some((true, _, i))) if k.verified => i,
            _ => return,
        };
        if let Some(w) = self.index.get_mut(b).and_then(|ws| ws.get_mut(pick)) {
            *w = mine;
        }
    }

    /// Every retained variant of `(session, pkt_seq)` inside the window, oldest first.
    pub fn find(&self, session: SessionId, pkt_seq: u32) -> impl Iterator<Item = &Kept> + '_ {
        let b = bucket_of(session, pkt_seq, self.mask());
        let ways = self.index.get(b).copied().unwrap_or([0; WAYS]);
        let mut hits: [Option<&Slot>; WAYS] = [None; WAYS];
        for (h, w) in hits.iter_mut().zip(ways) {
            *h = self
                .live(w, session, pkt_seq)
                .filter(|s| self.newest.0.saturating_sub(s.kept.rx_ts.0) <= REP_SEQ_PKT_RETAIN_NS);
        }
        hits.sort_by_key(|h| h.map_or(u64::MAX, |s| s.seq));
        hits.into_iter().flatten().map(|s| &s.kept)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn pkt(session: u32, pkt_seq: u32, tag: u8, ts: u64) -> Kept {
        let mut b = [tag; 48];
        b[..4].copy_from_slice(&session.to_le_bytes());
        b[4..8].copy_from_slice(&pkt_seq.to_le_bytes());
        Kept::new(&b, Nanos(ts), PktHash(u64::from(tag))).unwrap()
    }

    #[test]
    fn keeps_variants_evicts_oldest_and_honours_the_window() {
        let mut r = Retain::new(4);
        r.put(pkt(1, 1, 0xA, 0));
        r.put(pkt(1, 1, 0xB, 1)); // a resend variant of the same pkt_seq
        r.put(pkt(1, 2, 0xC, 2));
        let v: Vec<_> = r.find(SessionId(1), 1).map(|k| k.pkt_hash.0).collect();
        assert_eq!(v, vec![0xA, 0xB], "both variants, oldest first");
        assert_eq!(r.find(SessionId(1), 1).next().unwrap().bytes()[8], 0xA);
        assert_eq!(r.find(SessionId(2), 1).count(), 0);
        // The fifth put overwrites slot 0 (variant A) only: B stays findable.
        r.put(pkt(1, 3, 0xD, 3));
        r.put(pkt(1, 4, 0xE, 4));
        let v: Vec<_> = r.find(SessionId(1), 1).map(|k| k.pkt_hash.0).collect();
        assert_eq!(v, vec![0xB], "an overwritten slot is no hit");
        assert_eq!(r.find(SessionId(1), 2).count(), 1);
        // A put REP_SEQ_PKT_RETAIN_NS + 1 after pkt 2's rx_ts closes its window.
        r.put(pkt(1, 5, 0xF, 2 + REP_SEQ_PKT_RETAIN_NS + 1));
        assert_eq!(r.find(SessionId(1), 2).count(), 0, "outside the window");
        assert_eq!(r.find(SessionId(1), 5).count(), 1);
    }

    /// Unchecked shed packets of one key never evict its accepted packet from the index.
    #[test]
    fn shed_floods_never_displace_an_accepted_packet() {
        let mut r = Retain::new(64);
        r.put(Kept {
            verified: true,
            ..pkt(1, 1, 0xA, 0)
        });
        for t in 0..20u8 {
            r.put(pkt(1, 1, 0x10 + t, 1));
        }
        let v: Vec<_> = r.find(SessionId(1), 1).map(|k| k.pkt_hash.0).collect();
        assert_eq!(v.len(), WAYS);
        assert_eq!(v[0], 0xA, "the accepted copy stays: {v:x?}");
        // Unverified ways still rotate oldest first among themselves.
        assert_eq!(v[WAYS - 1], 0x10 + 19);
    }

    /// A wrapped FIFO that overwrites a slot with another key of the same bucket names it once.
    #[test]
    fn an_overwritten_slot_is_indexed_once() {
        // Capacity 4: 2 × 4 = 8 buckets, so one session's keys share buckets often.
        for seqs in [[4u32, 7, 1, 2, 3, 9], [1, 9, 17, 25, 33, 41]] {
            let mut r = Retain::new(4);
            for (t, &q) in seqs.iter().enumerate() {
                r.put(pkt(1, q, 1, u64::try_from(t).unwrap()));
            }
            for &q in &seqs[2..] {
                assert_eq!(r.find(SessionId(1), q).count(), 1, "{seqs:?} pkt {q}");
            }
        }
        // Exhaustive over small sequences: every live key is found at most once.
        for m in 0..4096u32 {
            let mut r = Retain::new(4);
            let seqs: Vec<u32> = (0..6).map(|i| 1 + ((m >> (2 * i)) & 3) * 8 + i).collect();
            for (t, &q) in seqs.iter().enumerate() {
                r.put(pkt(1, q, 1, u64::try_from(t).unwrap()));
            }
            for &q in &seqs {
                assert!(r.find(SessionId(1), q).count() <= 1, "{seqs:?} pkt {q}");
            }
        }
    }

    /// At the design load every live packet but a sliver keeps its index entry, with many
    /// sessions or with one session's sequential `pkt_seq`s (the case a weak hash clusters).
    #[test]
    fn a_full_ring_finds_almost_every_live_packet() {
        for sessions in [977, 1] {
            let n: u32 = 1 << 14;
            let mut r = Retain::new(usize::try_from(n).unwrap());
            let sid = |i: u32| 0x0010_0000 | (i % sessions);
            for i in 0..(3 * n) {
                r.put(pkt(sid(i), i, 1, 0));
            }
            let live = (2 * n)..(3 * n);
            let hits = live
                .clone()
                .filter(|&i| r.find(SessionId(sid(i)), i).count() == 1)
                .count();
            assert!(
                hits * 1000 >= live.len() * 999,
                "{sessions}: {hits} of {}",
                live.len()
            );
        }
    }
}
