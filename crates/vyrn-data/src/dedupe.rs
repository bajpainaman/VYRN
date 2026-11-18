//! Per-session dedupe window (07 §5.2 step 3): `hi`, the highest `pkt_seq` seen, and a 256-bit
//! window of the `pkt_seq`s `hi − 255 ..= hi`, bit `d` standing for `hi − d`.

use std::collections::BTreeMap;

use vyrn_types::SessionId;

pub const WINDOW: u32 = 256;

/// What the window says about one `(session, pkt_seq)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// Not seen before; now marked.
    New,
    /// Already marked.
    Repeat,
    /// At or below `hi − 256`: outside the window.
    Late,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Win {
    hi: u32,
    bits: [u64; 4],
}

fn shift_up(bits: &mut [u64; 4], k: u32) {
    if k >= WINDOW {
        *bits = [0; 4];
        return;
    }
    let w = (k / 64) as usize;
    let b = k % 64;
    let mut out = [0u64; 4];
    for (i, o) in out.iter_mut().enumerate().skip(w) {
        let src = i - w;
        let mut v = bits[src] << b;
        if b > 0 && src > 0 {
            v |= bits[src - 1] >> (64 - b);
        }
        *o = v;
    }
    *bits = out;
}

impl Win {
    fn mark(&mut self, pkt_seq: u32) -> Seen {
        if pkt_seq > self.hi {
            shift_up(&mut self.bits, pkt_seq - self.hi);
            self.hi = pkt_seq;
            self.bits[0] |= 1;
            return Seen::New;
        }
        let d = self.hi - pkt_seq;
        if d >= WINDOW {
            return Seen::Late;
        }
        let (w, b) = ((d / 64) as usize, d % 64);
        let m = 1u64 << b;
        if self.bits[w] & m != 0 {
            Seen::Repeat
        } else {
            self.bits[w] |= m;
            Seen::New
        }
    }
}

/// The windows of every session this home has seen.
#[derive(Clone, Debug, Default)]
pub struct Dedupe {
    wins: BTreeMap<SessionId, Win>,
}

impl Dedupe {
    /// A window for each of `sessions`. [`Dedupe::mark`] on one of them never allocates.
    pub fn with_sessions(sessions: impl IntoIterator<Item = SessionId>) -> Self {
        Self {
            wins: sessions.into_iter().map(|s| (s, Win::default())).collect(),
        }
    }

    /// Marks `pkt_seq` (≥ 1) of `session`. A session without a window gets one, which
    /// allocates.
    pub fn mark(&mut self, session: SessionId, pkt_seq: u32) -> Seen {
        self.wins.entry(session).or_default().mark(pkt_seq)
    }

    /// The highest `pkt_seq` seen of `session`.
    pub fn hi(&self, session: SessionId) -> Option<u32> {
        self.wins.get(&session).map(|w| w.hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain set model: what the window must answer, independently of the bit layout.
    #[test]
    fn matches_a_set_model() {
        let mut d = Dedupe::default();
        let s = SessionId(7);
        let mut seen = std::collections::BTreeSet::new();
        let mut hi = 0u32;
        // Asymmetric jumps across word and window boundaries, repeats, and late arrivals.
        let seqs = [
            1, 2, 2, 64, 65, 63, 1, 300, 45, 44, 299, 64, 557, 301, 302, 556, 302, 1000, 745, 744,
            1000, 999,
        ];
        for q in seqs {
            let want = if hi >= WINDOW && q <= hi - WINDOW {
                Seen::Late
            } else if seen.contains(&q) {
                Seen::Repeat
            } else {
                Seen::New
            };
            if want == Seen::New {
                seen.insert(q);
                hi = hi.max(q);
            }
            assert_eq!(d.mark(s, q), want, "pkt_seq {q}");
        }
        assert_eq!(d.hi(s), Some(1000));
        assert_eq!(d.mark(SessionId(8), 1000), Seen::New, "sessions are apart");
    }
}
