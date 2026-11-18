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
//! **Repair** (07 §4.10, sequencer retransmit). [`Paths::poll`] names the holes to ask for:
//! a delivery gap (frames below a held one, which no path delivered) on every path, and, for a
//! gated observer, a copy one path has not brought (a frame in `(both, next)` without that
//! path's bit) on that path. A hole is asked for after `hole_wait`, again every `retry`, and
//! after `tries` asks, or a [`NackTooOld`](vyrn_log::nack::NackTooOld) for it, given up
//! ([`Ask::Gap`], `ORDER_GAP`): an observer then waits as before (it cannot attest durability).
//! A frame dropped at [`SEEN_MAX`] is never tracked again, so its block stays held; repair
//! keeps `seen` from filling while a path is only lossy.

use std::collections::BTreeMap;

use vyrn_log::frame::FrameHeader;
use vyrn_types::BookId;

use vyrn_log::nack::NACK_SPAN_MAX;

pub use vyrn_log::nack::Path;

/// A path's bit in `seen` (A = 1, B = 2).
const fn bit(p: Path) -> u8 {
    match p {
        Path::A => 1,
        Path::B => 2,
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

/// A hole being repaired: frames `from..=to`.
#[derive(Clone, Copy, Debug)]
struct Hole {
    from: u64,
    to: u64,
    since: u64,
    last: u64,
    tries: u32,
    done: bool,
    /// The sequencer answered `NackTooOld`: give up at the next poll.
    old: bool,
}

/// Repair timers (07 §4.9, §4.10), in ns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Repair {
    /// `REP_HOLE_WAIT_US`: a hole is first asked for this long after it opens.
    pub hole_wait_ns: u64,
    /// `REP_NACK_RETRY_US`: and again this often.
    pub retry_ns: u64,
    /// Asks before the hole is given up.
    pub tries: u32,
}

/// What [`Paths::poll`] wants done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// Ask for frames `from..=to` of `key` on `path`.
    Nack {
        path: Path,
        key: Key,
        from: u64,
        to: u64,
    },
    /// Repair gave up on `from..=to` of `key`: on `path` for a copy, on every path (`None`)
    /// for a delivery gap.
    Gap {
        path: Option<Path>,
        key: Key,
        from: u64,
        to: u64,
    },
}

/// Advances `h` towards `want` (`None`: no hole); `Some((from, to, gave_up))` when it is due.
fn due(
    h: &mut Option<Hole>,
    want: Option<(u64, u64)>,
    now: u64,
    r: &Repair,
) -> Option<(u64, u64, bool)> {
    let Some((from, to)) = want else {
        *h = None;
        return None;
    };
    if h.is_none_or(|x| x.from != from) {
        *h = Some(Hole {
            from,
            to,
            since: now,
            last: now,
            tries: 0,
            done: false,
            old: false,
        });
    }
    let x = h.as_mut()?;
    let wait = if x.tries == 0 {
        now.saturating_sub(x.since) >= r.hole_wait_ns
    } else {
        now.saturating_sub(x.last) >= r.retry_ns
    };
    if x.done || !(wait || x.old) {
        return None;
    }
    if x.old || x.tries >= r.tries {
        x.done = true;
        return Some((x.from, x.to, true));
    }
    x.tries = x.tries.saturating_add(1);
    x.last = now;
    Some((x.from, x.to, false))
}

#[derive(Debug)]
struct Sub {
    next: u64,
    /// Each held frame's bytes and receive time.
    hold: BTreeMap<u64, (Vec<u8>, u64)>,
    both: u64,
    /// Paths each frame above `both` arrived on (bit A = 1, B = 2), and the bytes of its first
    /// copy, which is the one handed on: another copy counts for its path only if it is the
    /// same frame.
    seen: BTreeMap<u64, (u8, Vec<u8>)>,
    /// The delivery gap being repaired, and each path's missing copy.
    gap: Option<Hole>,
    copy: [Option<Hole>; 2],
}

impl Default for Sub {
    fn default() -> Self {
        Self {
            next: 1,
            hold: BTreeMap::new(),
            both: 0,
            seen: BTreeMap::new(),
            gap: None,
            copy: [None; 2],
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
    /// Two paths: `seen` and `both` are kept. One path ([`Paths::one_path`]): reorder and
    /// delivery-gap repair only.
    two: bool,
    subs: BTreeMap<Key, Sub>,
    /// The receive times of every held frame, with their counts (for [`Paths::held_min`]).
    held_at: BTreeMap<u64, u32>,
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
            two: true,
            subs: BTreeMap::new(),
            held_at: BTreeMap::new(),
            refused: 0,
            dups: [0; 2],
            mismatched: [0; 2],
        }
    }

    /// A box with path A only: frames are reordered and gaps repaired; no copy is tracked.
    pub fn one_path(mut self) -> Self {
        self.two = false;
        self
    }

    /// The receive time of the oldest frame held behind a gap (`u64::MAX`: none). Deadlines
    /// that run on receive time must not pass it: the frame may be a timely HashRun (07 §3.7).
    pub fn held_min(&self) -> u64 {
        self.held_at.first_key_value().map_or(u64::MAX, |(t, _)| *t)
    }

    /// One datagram from `path`; `deliver` gets every frame now due, in `frame_seq` order. A
    /// datagram whose header does not parse goes through as is, for the order core to refuse.
    pub fn rx(&mut self, path: Path, frame: &[u8], deliver: &mut impl FnMut(&[u8])) {
        self.rx_at(path, frame, 0, &mut |f: &[u8], _| deliver(f));
    }

    /// [`Paths::rx`] for a datagram received at `at`; `deliver` gets each due frame with its
    /// receive time. A frame that fills a gap counts as received no later than any frame held
    /// behind it (07 §3.7): it was sent before them, so the time its first copy was lost for
    /// is not counted against the sequencer, and each held frame keeps its own time.
    pub fn rx_at(
        &mut self,
        path: Path,
        frame: &[u8],
        at: u64,
        deliver: &mut impl FnMut(&[u8], u64),
    ) {
        let Ok((h, _)) = FrameHeader::parse(frame) else {
            return deliver(frame, at);
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
        if self.two && q > s.both {
            let fresh = s.seen.len() < SEEN_MAX;
            match s.seen.get_mut(&q) {
                Some((bits, first)) if same(first, frame) => *bits |= bit(path),
                Some(_) => {
                    // Not the frame first seen under this `frame_seq`: it counts for no path
                    // and is never handed on, so what is delivered is what `both` tracks.
                    if let Some(m) = self.mismatched.get_mut(usize::from(path == Path::B)) {
                        *m = m.saturating_add(1);
                    }
                    return;
                }
                None if fresh => {
                    s.seen.insert(q, (bit(path), frame.to_vec()));
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
                s.hold.insert(q, (frame.to_vec(), at));
                let c = self.held_at.entry(at).or_default();
                *c = c.saturating_add(1);
            }
        } else {
            s.next = s.next.saturating_add(1);
            let mut run = Vec::new();
            while let Some(f) = s.hold.remove(&s.next) {
                if let Some(c) = self.held_at.get_mut(&f.1) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        self.held_at.remove(&f.1);
                    }
                }
                run.push(f);
                s.next = s.next.saturating_add(1);
            }
            // Each frame's time is the earliest of its own and those after it in the run.
            let mut t = u64::MAX;
            for f in run.iter_mut().rev() {
                t = t.min(f.1);
                f.1 = t;
            }
            deliver(frame, at.min(t));
            for (f, t) in &run {
                deliver(f, *t);
            }
        }
        // `both` passes only frames already handed on: until then their first copy's bytes
        // stay in `seen`, so the copy that is handed on is compared with them, even one that
        // arrives after both paths' copies were dropped by a full hold.
        while self.two
            && s.seen
                .first_key_value()
                .is_some_and(|(k, v)| *k == s.both.saturating_add(1) && *k < s.next && v.0 == 3)
        {
            s.seen.pop_first();
            s.both = s.both.saturating_add(1);
        }
    }

    /// The holes due at `now` (see the module doc), into `out`. `copies`: also each path's
    /// missing copies (a gated observer).
    pub fn poll(&mut self, now: u64, r: &Repair, copies: bool, out: &mut Vec<Ask>) {
        let paths: &[Path] = if self.two {
            &[Path::A, Path::B]
        } else {
            &[Path::A]
        };
        for (key, s) in &mut self.subs {
            let key = *key;
            let want = s.hold.first_key_value().map(|(q, _)| {
                let to = q
                    .saturating_sub(1)
                    .min(s.next.saturating_add(NACK_SPAN_MAX - 1));
                (s.next, to)
            });
            match due(&mut s.gap, want, now, r) {
                Some((from, to, true)) => out.push(Ask::Gap {
                    path: None,
                    key,
                    from,
                    to,
                }),
                Some((from, to, false)) => {
                    for &path in paths {
                        out.push(Ask::Nack {
                            path,
                            key,
                            from,
                            to,
                        });
                    }
                }
                None => {}
            }
            if !(copies && self.two) {
                continue;
            }
            let q0 = s.both.saturating_add(1);
            for (i, path) in [Path::A, Path::B].into_iter().enumerate() {
                let lacks = |q: u64| s.seen.get(&q).is_none_or(|v| v.0 & bit(path) == 0);
                let Some(slot) = s.copy.get_mut(i) else {
                    continue;
                };
                let want = (q0 < s.next && lacks(q0)).then(|| match slot {
                    // The same hole: its end was found when it opened.
                    Some(h) if h.from == q0 => (q0, h.to),
                    _ => {
                        let mut to = q0;
                        while to.saturating_add(1) < s.next
                            && to.saturating_sub(q0) < NACK_SPAN_MAX - 1
                            && lacks(to.saturating_add(1))
                        {
                            to = to.saturating_add(1);
                        }
                        (q0, to)
                    }
                });
                match due(slot, want, now, r) {
                    Some((from, to, true)) => out.push(Ask::Gap {
                        path: Some(path),
                        key,
                        from,
                        to,
                    }),
                    Some((from, to, false)) => out.push(Ask::Nack {
                        path,
                        key,
                        from,
                        to,
                    }),
                    None => {}
                }
            }
        }
    }

    /// The sequencer no longer holds frames below `oldest` of `(tenure, stream)` (07 §4.10
    /// `NackTooOld`): a hole of `path` below it is given up at the next [`Paths::poll`]. A
    /// reply for another epoch is ignored, as [`Paths::rx`] ignores its frames: a delayed one
    /// reaching a reused port must not give up a hole the current sequencer still holds.
    pub fn too_old(&mut self, path: Path, epoch16: u16, tenure: u8, stream: u8, oldest: u64) {
        if epoch16 != self.epoch16 {
            return;
        }
        let i = usize::from(path == Path::B);
        for (_, s) in self
            .subs
            .iter_mut()
            .filter(|(k, _)| k.0 == epoch16 && k.1 == tenure && k.3 == stream)
        {
            let copy = s.copy.get_mut(i).and_then(Option::as_mut);
            for h in s.gap.as_mut().into_iter().chain(copy) {
                if h.from < oldest {
                    h.old = true;
                }
            }
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

    /// Vercel #213: frames held behind a gap keep their own receive times, and the frame that
    /// fills the gap counts as received no later than the earliest frame held behind it.
    #[test]
    fn a_gap_fill_keeps_each_held_frames_receive_time() {
        let mut p = Paths::new(BookId(1), 0, 1).one_path();
        let mut out = Vec::new();
        let mut d = |f: &[u8], at: u64| out.push((FrameHeader::parse(f).unwrap().0.frame_seq, at));
        p.rx_at(Path::A, &frame(0, 1), 10, &mut d);
        p.rx_at(Path::A, &frame(0, 4), 40, &mut d);
        p.rx_at(Path::A, &frame(0, 3), 30, &mut d);
        assert_eq!(p.held_min(), 30, "3 and 4 are held");
        p.rx_at(Path::A, &frame(0, 2), 900, &mut d);
        assert_eq!(p.held_min(), u64::MAX, "nothing is held");
        p.rx_at(Path::A, &frame(0, 5), 950, &mut d);
        assert_eq!(out, [(1, 10), (2, 30), (3, 30), (4, 40), (5, 950)]);
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

    const R: Repair = Repair {
        hole_wait_ns: 10,
        retry_ns: 100,
        tries: 2,
    };

    fn asks(p: &mut Paths, now: u64, copies: bool) -> Vec<Ask> {
        let mut v = Vec::new();
        p.poll(now, &R, copies, &mut v);
        v
    }

    const K: Key = (0, 0, 0, 0);

    /// A delivery gap is asked for on both paths after `hole_wait`, again every `retry`, and
    /// given up after `tries`; filling it ends it.
    #[test]
    fn a_delivery_gap_is_nacked_retried_and_given_up() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let mut d = |_: &[u8]| {};
        p.rx(Path::A, &frame(0, 1), &mut d);
        p.rx(Path::A, &frame(0, 4), &mut d);
        assert!(asks(&mut p, 0, false).is_empty(), "the hole opens at 0");
        assert!(asks(&mut p, 9, false).is_empty(), "before hole_wait");
        let n = |path| Ask::Nack {
            path,
            key: K,
            from: 2,
            to: 3,
        };
        assert_eq!(asks(&mut p, 10, false), vec![n(Path::A), n(Path::B)]);
        assert!(asks(&mut p, 50, false).is_empty(), "before retry");
        assert_eq!(asks(&mut p, 110, false), vec![n(Path::A), n(Path::B)]);
        let gap = Ask::Gap {
            path: None,
            key: K,
            from: 2,
            to: 3,
        };
        assert_eq!(asks(&mut p, 210, false), vec![gap]);
        assert!(asks(&mut p, 999, false).is_empty(), "reported once");
        // A one-path box asks on A only, and a filled hole asks for nothing.
        let mut q = Paths::new(BookId(1), 0, 1).one_path();
        q.rx(Path::A, &frame(0, 3), &mut d);
        asks(&mut q, 0, false);
        assert_eq!(
            asks(&mut q, 10, false),
            vec![Ask::Nack {
                path: Path::A,
                key: K,
                from: 1,
                to: 2
            }]
        );
        q.rx(Path::A, &frame(0, 1), &mut d);
        q.rx(Path::A, &frame(0, 2), &mut d);
        assert!(asks(&mut q, 500, false).is_empty());
    }

    /// A gated observer asks each path for the copies it lacks, from `both + 1`, and a
    /// `NackTooOld` below the hole gives it up at once.
    #[test]
    fn a_missing_copy_is_nacked_on_its_path() {
        let mut p = Paths::new(BookId(1), 0, 1);
        let mut d = |_: &[u8]| {};
        for q in 1..=4 {
            p.rx(Path::A, &frame(0, q), &mut d);
        }
        for q in [1, 4] {
            p.rx(
                Path::B,
                &with_flags(&frame(0, q), FrameFlags::PATH_B),
                &mut d,
            );
        }
        assert!(
            asks(&mut p, 0, false).is_empty(),
            "voters do not ask for copies"
        );
        asks(&mut p, 0, true);
        // Another epoch's NackTooOld is ignored: the hole is still Nacked, not given up.
        p.too_old(Path::B, 1, 0, 0, 5);
        assert_eq!(
            asks(&mut p, 10, true),
            vec![Ask::Nack {
                path: Path::B,
                key: K,
                from: 2,
                to: 3
            }]
        );
        p.too_old(Path::B, 0, 0, 0, 5);
        assert_eq!(
            asks(&mut p, 11, true),
            vec![Ask::Gap {
                path: Some(Path::B),
                key: K,
                from: 2,
                to: 3
            }]
        );
        // The retransmits arrive: durable again, nothing to ask.
        for q in [2, 3] {
            let rt = with_flags(&frame(0, q), FrameFlags::PATH_B | FrameFlags::RETRANSMIT);
            p.rx(Path::B, &rt, &mut d);
        }
        assert!(p.durable(&p.mark()));
        assert!(asks(&mut p, 900, true).is_empty());
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
