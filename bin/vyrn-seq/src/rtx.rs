//! Sequencer retransmit (07 §4.10, first choice): the stream core's frame ring and its answer to
//! a `Nack`.
//!
//! **Ring.** Every frame the stream core ships on path A is kept, per substream, in `frame_seq`
//! order, until the ring holds more than `[replication] rtx_ring_bytes` (default
//! `REP_RTX_RING_BYTES` = 64 MiB); then the oldest frames go. The ring counts each buffer's
//! capacity, not its frame's length, and keeps at most [`SPARE_MAX`] evicted buffers for reuse,
//! so its retained storage stays within the cap plus `SPARE_MAX` frames whatever the frame sizes
//! (Codex r4613789579). Buffers are reused, so a full ring of steady frames allocates nothing
//! per frame.
//!
//! **Nacks** come from the finality listener on `REP_UDP_CTRL` (`finality.rs`) through a bounded
//! queue ([`NACK_QUEUE`]; a full queue drops the Nack and counts it), and the stream core serves
//! at most [`NACKS_PER_TURN`] of them between batches. A Nack is served only if its source IPv4 and `port` name one of the
//! configured replicas on its path (`[replication] order` for A, `order_b` for B), and every
//! frame goes to that configured address, never to the datagram's source: a forged Nack cannot
//! reflect frames to a third party (07 §4.10, reading). Each copy has `flags` = the Nack's path
//! bit plus `RETRANSMIT`. A Nack for another epoch or tenure is refused; one whose `from_seq`
//! has left the ring gets `NackTooOld { oldest_seq }` at the same address. Frames past
//! `REP_RTX_MAX_FPS` = 200k/s (a token bucket of 10 ms) are not sent and are counted.

use std::collections::VecDeque;
use std::net::SocketAddrV4;

use vyrn_log::frame::FrameFlags;
use vyrn_log::nack::{Nack, NackTooOld, Path};

/// `REP_RTX_RING_BYTES`.
pub const REP_RTX_RING_BYTES: usize = 64 << 20;
/// `REP_RTX_MAX_FPS`.
pub const REP_RTX_MAX_FPS: u64 = 200_000;
/// Nacks in flight from the listener to the stream core.
pub const NACK_QUEUE: usize = 1024;
/// Nacks the stream core serves per turn of its loop.
pub const NACKS_PER_TURN: usize = 16;
/// Evicted buffers kept for reuse; the rest are freed.
pub const SPARE_MAX: usize = 64;
const FLAGS_AT: usize = 16;
const BURST_NS: u64 = 10_000_000;
const SEC: u64 = 1_000_000_000;

/// A Nack as the listener received it.
pub type Req = (std::net::Ipv4Addr, Nack);

/// What the stream core sends for one Nack: `(to, bytes)` pairs.
pub type Out<'a> = &'a mut Vec<(SocketAddrV4, Vec<u8>)>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RtxStats {
    pub nacks: u64,
    pub sent: u64,
    pub too_old: u64,
    pub refused: u64,
    pub limited: u64,
}

#[derive(Debug)]
pub struct Ring {
    epoch16: u16,
    tenure: u8,
    /// Per substream: its frames from `first[s]` on.
    frames: [VecDeque<Vec<u8>>; 2],
    first: [u64; 2],
    bytes: usize,
    cap: usize,
    spare: Vec<Vec<u8>>,
    tokens: u64,
    at: u64,
    pub stats: RtxStats,
}

fn seq_of(f: &[u8]) -> Option<(usize, u64)> {
    let stream = usize::from(*f.get(21)?);
    let seq = u64::from_le_bytes(f.get(8..16)?.try_into().ok()?);
    (stream < 2).then_some((stream, seq))
}

impl Ring {
    pub fn new(epoch16: u16, tenure: u8, cap: usize) -> Self {
        Self {
            epoch16,
            tenure,
            frames: [VecDeque::new(), VecDeque::new()],
            first: [1, 1],
            bytes: 0,
            cap,
            spare: Vec::new(),
            tokens: REP_RTX_MAX_FPS * BURST_NS,
            at: 0,
            stats: RtxStats::default(),
        }
    }

    /// Keeps a shipped path A frame.
    pub fn push(&mut self, f: &[u8]) {
        let Some((s, seq)) = seq_of(f) else { return };
        let (Some(q), Some(first)) = (self.frames.get_mut(s), self.first.get_mut(s)) else {
            return;
        };
        if q.is_empty() {
            *first = seq;
        } else if first.saturating_add(q.len() as u64) != seq {
            return; // not the next frame of the substream: the writer never does this
        }
        let mut b = self.spare.pop().unwrap_or_default();
        b.clear();
        b.extend_from_slice(f);
        self.bytes = self.bytes.saturating_add(b.capacity());
        q.push_back(b);
        while self.bytes > self.cap {
            let Some(i) = (0..2).max_by_key(|&i| self.frames[i].len()) else {
                break;
            };
            let Some(old) = self.frames[i].pop_front() else {
                break;
            };
            self.first[i] = self.first[i].saturating_add(1);
            self.bytes = self.bytes.saturating_sub(old.capacity());
            if self.spare.len() < SPARE_MAX {
                self.spare.push(old);
            }
        }
    }

    /// Answers `n` from `src` at `now` (ns): the frames (or a `NackTooOld`) to send, and where.
    /// `a` and `b` are the configured replicas of each path.
    pub fn serve(
        &mut self,
        src: std::net::Ipv4Addr,
        n: &Nack,
        a: &[SocketAddrV4],
        b: &[SocketAddrV4],
        now: u64,
        out: Out<'_>,
    ) {
        self.stats.nacks = self.stats.nacks.saturating_add(1);
        let (list, bit) = match n.path {
            Path::A => (a, 0),
            Path::B => (b, FrameFlags::PATH_B),
        };
        let to = list.iter().find(|r| *r.ip() == src && r.port() == n.port);
        let s = usize::from(n.stream);
        let (Some(&to), true, true, Some(q)) = (
            to,
            n.epoch16 == self.epoch16,
            n.tenure == self.tenure,
            self.frames.get(s),
        ) else {
            self.stats.refused = self.stats.refused.saturating_add(1);
            return;
        };
        let first = self.first[s];
        if n.from_seq < first {
            self.stats.too_old = self.stats.too_old.saturating_add(1);
            let t = NackTooOld {
                path: n.path,
                epoch16: n.epoch16,
                tenure: n.tenure,
                stream: n.stream,
                oldest_seq: first,
            };
            out.push((to, t.encode().to_vec()));
            return;
        }
        self.tokens = self
            .tokens
            .saturating_add(now.saturating_sub(self.at).min(SEC) * REP_RTX_MAX_FPS)
            .min(REP_RTX_MAX_FPS * BURST_NS);
        self.at = now;
        for seq in n.from_seq..=n.to_seq {
            let Some(f) = usize::try_from(seq - first).ok().and_then(|i| q.get(i)) else {
                break; // not framed yet
            };
            if self.tokens < SEC {
                self.stats.limited = self.stats.limited.saturating_add(1);
                continue;
            }
            self.tokens -= SEC;
            let mut c = f.clone();
            if let Some(x) = c.get_mut(FLAGS_AT) {
                *x = bit | FrameFlags::RETRANSMIT;
            }
            self.stats.sent = self.stats.sent.saturating_add(1);
            out.push((to, c));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use vyrn_log::frame::{FrameHeader, FrameKind};
    use vyrn_types::BookId;

    fn frame(stream: u8, q: u64) -> Vec<u8> {
        let h = FrameHeader {
            kind: FrameKind::Heartbeat,
            book: BookId(1),
            epoch16: 3,
            frame_seq: q,
            flags: 0,
            tenure: 0,
            body_len: 8,
            sender: 0,
            stream,
        };
        let mut v = h.encode().to_vec();
        v.extend_from_slice(&q.to_le_bytes());
        v
    }

    fn nack(path: Path, port: u16, from: u64, to: u64) -> Nack {
        Nack {
            path,
            epoch16: 3,
            tenure: 0,
            stream: 1,
            port,
            from_seq: from,
            to_seq: to,
        }
    }

    const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

    #[test]
    fn retained_storage_stays_within_the_cap_for_mixed_frame_sizes() {
        // Codex's probe: batches of 32 B and 250 B frames under a 64 KiB cap. Counting frame
        // lengths kept 180,236 B of buffers; capacity is what the ring holds.
        let cap = 65_536;
        let mut r = Ring::new(3, 0, cap);
        let mut q = 0;
        // Large frames fill the ring, then small ones replace them: a small frame in a reused
        // large buffer holds 250 B of storage for 32 B of frame.
        for round in 0..4 {
            let pad = if round % 2 == 0 { 218 } else { 0 };
            for _ in 0..4096 {
                q += 1;
                let mut f = frame(0, q);
                f.resize(f.len() + pad, 0);
                r.push(&f);
            }
        }
        let held: usize = r.frames.iter().flatten().map(Vec::capacity).sum();
        let spare: usize = r.spare.iter().map(Vec::capacity).sum();
        assert!(held <= cap, "ring holds {held} B");
        assert!(
            r.spare.len() <= SPARE_MAX && spare <= SPARE_MAX * 256,
            "spare {spare} B"
        );
        assert_eq!(r.bytes, held);
    }

    #[test]
    fn serves_from_the_configured_address_with_flags_and_wraps() {
        let a = [SocketAddrV4::new(LO, 9000)];
        let b = [SocketAddrV4::new(LO, 9001), SocketAddrV4::new(LO, 9002)];
        // Room for 3 frames of 32 B.
        let mut r = Ring::new(3, 0, 96);
        for q in 1..=5 {
            r.push(&frame(1, q));
        }
        r.push(&frame(0, 1));
        let mut out = Vec::new();
        r.serve(LO, &nack(Path::B, 9002, 4, 6), &a, &b, 0, &mut out);
        assert_eq!(out.len(), 2, "5 is the last framed; 6 is not yet");
        assert_eq!(out[0].0, b[1], "to the configured replica the Nack named");
        assert_eq!(out[0].1[16], FrameFlags::PATH_B | FrameFlags::RETRANSMIT);
        assert_eq!(out[0].1[24..], frame(1, 4)[24..]);
        out.clear();
        // Stream 1 lost its oldest frames to the cap: 1..=3 of it are gone.
        r.serve(LO, &nack(Path::A, 9000, 2, 4), &a, &b, 0, &mut out);
        let t = NackTooOld::decode(&out[0].1).unwrap();
        assert_eq!((out[0].0, t.oldest_seq, t.path), (a[0], 4, Path::A));
        assert_eq!(r.stats.too_old, 1);
        // A source or port that names no configured replica of that path gets nothing.
        out.clear();
        r.serve(
            Ipv4Addr::new(10, 0, 0, 9),
            &nack(Path::A, 9000, 4, 4),
            &a,
            &b,
            0,
            &mut out,
        );
        r.serve(LO, &nack(Path::A, 9001, 4, 4), &a, &b, 0, &mut out);
        assert!(out.is_empty());
        assert_eq!(r.stats.refused, 2);
    }

    #[test]
    fn the_rate_cap_holds() {
        let a = [SocketAddrV4::new(LO, 9000)];
        let mut r = Ring::new(3, 0, 64 << 20);
        for q in 1..=3000 {
            r.push(&frame(1, q));
        }
        let mut out = Vec::new();
        for k in 0..3 {
            r.serve(
                LO,
                &nack(Path::A, 9000, 1 + 1000 * k, 1000 + 1000 * k),
                &a,
                &[],
                0,
                &mut out,
            );
        }
        // A full bucket is 10 ms at 200k/s: 2000 frames.
        assert_eq!(out.len(), 2000);
        assert_eq!(r.stats.limited, 1000);
    }
}
