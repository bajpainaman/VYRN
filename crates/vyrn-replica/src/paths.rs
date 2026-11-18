//! Two-path ORDER receive (07 §4.9) and the observer's durability gate (10 §8.2).
//!
//! Every substream `(epoch16, tenure, sender, stream)` has its own `next` frame. A frame is
//! handed on once, in `frame_seq` order: the first copy at `next` goes out at once, a copy
//! ahead of `next` waits in a bounded hold, and a copy below `next` (the other path's) is
//! counted as a duplicate. Separately, each substream keeps `both`: every frame ≤ `both` has
//! arrived on both paths. A block's [`Mark`] is what was handed on when it became ready, and
//! [`Paths::durable`] holds once every substream's `both` reaches it, so the observer replays
//! (and the drop copy sends, `flags.bit2`) only what it holds from both paths.
//!
//! Repair (07 §4.10) is not here: a frame one path lost stays missing from `both`, and an
//! observer then waits, as the spec has it (it cannot attest durability).

use std::collections::BTreeMap;

use vyrn_log::frame::FrameHeader;
use vyrn_types::BookId;

/// Path A or B: the port a datagram arrived on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A,
    B,
}

impl Path {
    const fn bit(self) -> u8 {
        match self {
            Self::A => 1,
            Self::B => 2,
        }
    }
}

/// Frames held ahead of `next`, per substream; past it a copy is dropped (DEV: no repair).
const HOLD_MAX: usize = 1 << 14;
/// Frames tracked above `both`, per substream, each with its first copy's bytes; past it
/// `both` stops (a path is down).
const SEEN_MAX: usize = 1 << 16;
/// `flags`, the only header byte the two copies may differ in (07 §3.2, INV-REP-3).
const FLAGS_AT: usize = 16;

/// `(epoch16, tenure, sender, stream)`.
pub type Key = (u16, u8, u8, u8);

#[derive(Debug)]
struct Sub {
    next: u64,
    hold: BTreeMap<u64, Vec<u8>>,
    both: u64,
    /// Paths each frame above `both` arrived on (bit A = 1, B = 2), and the bytes of its first
    /// copy, which is the one handed on: another copy counts for its path only if it is the
    /// same frame.
    seen: BTreeMap<u64, (u8, Vec<u8>)>,
}

impl Default for Sub {
    fn default() -> Self {
        Self {
            next: 1,
            hold: BTreeMap::new(),
            both: 0,
            seen: BTreeMap::new(),
        }
    }
}

/// A frame's substream and `frame_seq`, if its header parses.
pub fn frame_key(frame: &[u8]) -> Option<(Key, u64)> {
    let (h, _) = FrameHeader::parse(frame).ok()?;
    Some(((h.epoch16, h.tenure, h.sender, h.stream), h.frame_seq))
}

/// What a block needs on both paths: each substream's last frame handed on when it was ready.
pub type Mark = Vec<(Key, u64)>;

/// Substreams tracked at once: two per tenure and sender; past it a new one is refused.
const SUBS_MAX: usize = 64;

#[derive(Debug)]
pub struct Paths {
    /// The receive context: frames of another book or epoch, of a sender index at or past
    /// `senders`, or of a stream past B are refused before any state is kept for them.
    book: BookId,
    epoch16: u16,
    senders: u8,
    subs: BTreeMap<Key, Sub>,
    /// Datagrams refused by the receive context or [`SUBS_MAX`].
    pub refused: u64,
    /// Copies of frames already handed on, per path.
    pub dups: [u64; 2],
    /// Copies whose bytes (`flags` aside) differ from the first copy of their frame, per path.
    /// They count for no path, so a block that needs them stays held.
    pub mismatched: [u64; 2],
}

/// Whether two copies are the same frame: equal bytes except `flags`.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .enumerate()
            .all(|(i, (x, y))| i == FLAGS_AT || x == y)
}

impl Paths {
    pub fn new(book: BookId, epoch16: u16, senders: u8) -> Self {
        Self {
            book,
            epoch16,
            senders,
            subs: BTreeMap::new(),
            refused: 0,
            dups: [0; 2],
            mismatched: [0; 2],
        }
    }

    /// One datagram from `path`; `deliver` gets every frame now due, in `frame_seq` order. A
    /// datagram whose header does not parse goes through as is, for the order core to refuse.
    pub fn rx(&mut self, path: Path, frame: &[u8], deliver: &mut impl FnMut(&[u8])) {
        let Ok((h, _)) = FrameHeader::parse(frame) else {
            return deliver(frame);
        };
        let key = (h.epoch16, h.tenure, h.sender, h.stream);
        let known = self.subs.contains_key(&key);
        if h.book != self.book
            || h.epoch16 != self.epoch16
            || h.sender >= self.senders
            || h.stream > 1
            || (!known && self.subs.len() >= SUBS_MAX)
        {
            self.refused = self.refused.saturating_add(1);
            return;
        }
        let s = self.subs.entry(key).or_default();
        let q = h.frame_seq;
        if q > s.both {
            let fresh = s.seen.len() < SEEN_MAX;
            match s.seen.get_mut(&q) {
                Some((bits, first)) if same(first, frame) => *bits |= path.bit(),
                Some(_) => {
                    // Not the frame first seen under this `frame_seq`: it counts for no path
                    // and is never handed on, so what is delivered is what `both` tracks.
                    if let Some(m) = self.mismatched.get_mut(usize::from(path == Path::B)) {
                        *m = m.saturating_add(1);
                    }
                    return;
                }
                None if fresh => {
                    s.seen.insert(q, (path.bit(), frame.to_vec()));
                }
                None => {}
            }
        }
        if q < s.next || s.hold.contains_key(&q) {
            if let Some(d) = self.dups.get_mut(usize::from(path == Path::B)) {
                *d = d.saturating_add(1);
            }
        } else if q > s.next {
            if s.hold.len() < HOLD_MAX {
                s.hold.insert(q, frame.to_vec());
            }
        } else {
            deliver(frame);
            s.next = s.next.saturating_add(1);
            while let Some(f) = s.hold.remove(&s.next) {
                deliver(&f);
                s.next = s.next.saturating_add(1);
            }
        }
        // `both` passes only frames already handed on: until then their first copy's bytes
        // stay in `seen`, so the copy that is handed on is compared with them, even one that
        // arrives after both paths' copies were dropped by a full hold.
        while s
            .seen
            .first_key_value()
            .is_some_and(|(k, v)| *k == s.both.saturating_add(1) && *k < s.next && v.0 == 3)
        {
            s.seen.pop_first();
            s.both = s.both.saturating_add(1);
        }
    }

    /// Every substream's last frame handed on.
    pub fn mark(&self) -> Mark {
        self.subs
            .iter()
            .map(|(k, s)| (*k, s.next.saturating_sub(1)))
            .collect()
    }

    /// Whether every frame up to `m` arrived on both paths.
    pub fn durable(&self, m: &Mark) -> bool {
        m.iter()
            .all(|(k, q)| self.subs.get(k).is_some_and(|s| s.both >= *q))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use vyrn_log::frame::{FrameFlags, FrameKind, with_flags};

    fn frame(stream: u8, q: u64) -> Vec<u8> {
        let h = FrameHeader {
            kind: FrameKind::Heartbeat,
            book: BookId(1),
            epoch16: 0,
            frame_seq: q,
            flags: 0,
            tenure: 0,
            body_len: 1,
            sender: 0,
            stream,
        };
        let mut v = h.encode().to_vec();
        v.push(u8::try_from(q % 256).unwrap());
        v
    }

    fn seqs(out: &[Vec<u8>]) -> Vec<u64> {
        out.iter()
            .map(|f| FrameHeader::parse(f).unwrap().0.frame_seq)
            .collect()
    }

    #[test]
    fn each_frame_once_in_order_whichever_path_leads() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let mut out = Vec::new();
        let mut d = |f: &[u8]| out.push(f.to_vec());
        // A loses 2; B lags by one and then catches up past A.
        p.rx(Path::A, &frame(0, 1), &mut d);
        p.rx(Path::A, &frame(0, 3), &mut d);
        p.rx(
            Path::B,
            &with_flags(&frame(0, 1), FrameFlags::PATH_B),
            &mut d,
        );
        p.rx(
            Path::B,
            &with_flags(&frame(0, 2), FrameFlags::PATH_B),
            &mut d,
        );
        p.rx(
            Path::B,
            &with_flags(&frame(0, 3), FrameFlags::PATH_B),
            &mut d,
        );
        p.rx(
            Path::B,
            &with_flags(&frame(0, 4), FrameFlags::PATH_B),
            &mut d,
        );
        p.rx(Path::A, &frame(0, 4), &mut d);
        assert_eq!(seqs(&out), vec![1, 2, 3, 4]);
        assert_eq!(p.dups, [1, 2]);
    }

    /// Codex #167: past the hold buffer, a frame is kept only in `seen`; a conflicting copy at
    /// `next` is never handed on, and the matching one is.
    #[test]
    fn a_conflicting_copy_is_never_handed_on() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let out = std::cell::RefCell::new(Vec::new());
        let mut d = |f: &[u8]| out.borrow_mut().push(f.to_vec());
        let last = HOLD_MAX as u64 + 2;
        for q in 2..=last {
            p.rx(Path::A, &frame(0, q), &mut d);
        }
        p.rx(Path::A, &frame(0, 1), &mut d);
        assert_eq!(out.borrow().len(), HOLD_MAX + 1, "1 and the held frames");
        let mut forged = with_flags(&frame(0, last), FrameFlags::PATH_B);
        *forged.last_mut().unwrap() ^= 0xff;
        p.rx(Path::B, &forged, &mut d);
        assert_eq!(
            out.borrow().len(),
            HOLD_MAX + 1,
            "the conflicting copy is not handed on"
        );
        assert_eq!(p.mismatched, [0, 1]);
        p.rx(
            Path::B,
            &with_flags(&frame(0, last), FrameFlags::PATH_B),
            &mut d,
        );
        assert_eq!(out.borrow().last().unwrap()[24..], frame(0, last)[24..]);
    }

    /// CodeRabbit #167: both paths' copies of a frame past a full hold leave it in `seen` only;
    /// once the gap closes, `both` must not pass it before it is handed on, or a third copy
    /// with other bytes would go out uncompared.
    #[test]
    fn both_never_passes_a_frame_not_yet_handed_on() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let out = std::cell::RefCell::new(Vec::new());
        let mut d = |f: &[u8]| out.borrow_mut().push(f.to_vec());
        let last = HOLD_MAX as u64 + 2;
        for q in 2..=last {
            p.rx(Path::A, &frame(0, q), &mut d);
            p.rx(
                Path::B,
                &with_flags(&frame(0, q), FrameFlags::PATH_B),
                &mut d,
            );
        }
        p.rx(Path::A, &frame(0, 1), &mut d);
        p.rx(
            Path::B,
            &with_flags(&frame(0, 1), FrameFlags::PATH_B),
            &mut d,
        );
        assert_eq!(out.borrow().len(), HOLD_MAX + 1);
        assert!(
            !p.durable(&vec![((0, 0, 0, 0), last)]),
            "`last` not handed on"
        );
        let mut forged = frame(0, last);
        *forged.last_mut().unwrap() ^= 0xff;
        p.rx(Path::A, &forged, &mut d);
        assert_eq!(
            out.borrow().len(),
            HOLD_MAX + 1,
            "forged copy not handed on"
        );
        assert_eq!(p.mismatched, [1, 0]);
        p.rx(Path::A, &frame(0, last), &mut d);
        assert_eq!(out.borrow().last().unwrap(), &frame(0, last));
        assert!(p.durable(&p.mark()));
    }

    #[test]
    fn foreign_substreams_keep_no_state() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let mut d = |_: &[u8]| {};
        let mut f = frame(0, 2);
        f[20] = 1; // sender 1: this box has one sequencer
        p.rx(Path::A, &f, &mut d);
        assert_eq!((p.refused, p.subs.len()), (1, 0));
        for t in 0..=255u8 {
            let mut f = frame(0, 2);
            f[17] = t; // tenure
            p.rx(Path::A, &f, &mut d);
        }
        assert_eq!(p.subs.len(), SUBS_MAX);
        assert_eq!(p.refused, 1 + 256 - SUBS_MAX as u64);
    }

    #[test]
    fn durable_waits_for_both_paths_of_every_marked_frame() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let mut d = |_: &[u8]| {};
        for q in 1..=3 {
            p.rx(Path::A, &frame(0, q), &mut d);
            p.rx(Path::A, &frame(1, q), &mut d);
        }
        let m = p.mark();
        assert_eq!(m.iter().map(|x| x.1).collect::<Vec<_>>(), vec![3, 3]);
        assert!(!p.durable(&m), "path B has nothing");
        for q in 1..=3 {
            p.rx(Path::B, &frame(0, q), &mut d);
        }
        p.rx(Path::B, &frame(1, 1), &mut d);
        p.rx(Path::B, &frame(1, 3), &mut d);
        assert!(!p.durable(&m), "stream 1 frame 2 only on path A");
        p.rx(Path::B, &frame(1, 2), &mut d);
        assert!(p.durable(&m));
        // A copy with other bytes is not the frame: it counts for no path.
        let m2 = {
            let mut forged = frame(0, 4);
            *forged.last_mut().unwrap() ^= 0xff;
            p.rx(Path::A, &frame(0, 4), &mut d);
            p.rx(Path::B, &with_flags(&forged, FrameFlags::PATH_B), &mut d);
            p.mark()
        };
        assert!(!p.durable(&m2), "path B's frame 4 has other bytes");
        assert_eq!(p.mismatched, [0, 1]);
        p.rx(
            Path::B,
            &with_flags(&frame(0, 4), FrameFlags::PATH_B),
            &mut d,
        );
        assert!(p.durable(&m2));
        // A substream the mark does not name is not waited for; one it names but never saw is.
        p.rx(Path::A, &frame(2, 1), &mut d);
        assert_eq!(p.refused, 1, "stream 2 is outside the receive context");
        assert!(p.durable(&m));
        assert!(!p.durable(&vec![((0, 0, 0, 3), 1)]));
    }
}
