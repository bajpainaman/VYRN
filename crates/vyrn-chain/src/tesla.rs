//! Session keys and TESLA (09 §5.3, §5.4, §5.10): `K_seq`, `K_out`, the `K_com` hash chain, its
//! anchor, the validator's key window and self-certifying disclosures.
//!
//! ```text
//! K_seq(e, s)    = derive_key("vyrn v1 session", P_seq ‖ x25519_pub ‖ le32(e) ‖ [s] ‖ "seq")[0..16]
//! K_out(e, s)    = derive_key("vyrn v1 session", P_seq ‖ x25519_pub ‖ le32(e) ‖ [s] ‖ "out")[0..16]
//! head(e, s)     = derive_key("vyrn v1 kcom head", P_com ‖ x25519_pub ‖ le32(e) ‖ [s])
//! c(N) = head;  c(k − 1) = BLAKE3(c(k));  A(e, s) = c(0)
//! K_com(e, s, i) = derive_key("vyrn v1 kcom", c(i))[0..16]          i = 1 ..= N
//! ```
//!
//! **Spec gap (contexts).** 09 §5.3 prints the contexts with a run of spaces after `vyrn`
//! (`"vyrn      v1 kcom"`); 09 §17.3 and 01 §4 print one space. This crate reads one space, as
//! `vyrn_crypto::SESSION_CONTEXT` and the SMT contexts (whose vectors are on main) already do.
//!
//! **Spec gap (traversal).** 09 §5.4 names Jakobsson's fractal traversal (15 pebbles, ≤ 15 hashes
//! per step). [`Traversal`] is the simpler binary-split traversal: ≤ 16 stored values, the same
//! outputs, and ~7.5 hashes per step on average over an epoch (the B-CHN-1 budget is an average:
//! the window has a full interval of slack). One step can cost up to ~N/2 hashes, once per epoch,
//! off the voting path. The worst-case bound of Jakobsson's layout is a follow-up.

use vyrn_crypto::hash::hash;
use vyrn_crypto::{SESSION_CONTEXT, derive_key, siphash24, tag_eq, x25519};
use vyrn_types::{Epoch, Hash, Height, SessionId, Tag};

/// `CHN_TESLA_N`: intervals per epoch and the hash-chain length (09 §17.1).
pub const TESLA_N: u32 = 28_800;
/// `CHN_TESLA_BLOCKS`: book blocks per TESLA interval (09 §17.1).
pub const TESLA_BLOCKS: u64 = 1_000;
/// The `derive_key` context of the chain head (09 §17.3).
pub const KCOM_HEAD_CONTEXT: &str = "vyrn v1 kcom head";
/// The `derive_key` context of `K_com` (09 §17.3).
pub const KCOM_CONTEXT: &str = "vyrn v1 kcom";

/// A 128-bit SipHash key (01 §4).
pub type Key = [u8; 16];

/// An operator index (09 §2.1; 09 §18 request 8 asks 01 for the type).
pub type OpIdx = u8;

/// The material `P ‖ x25519_pub ‖ le32(e) ‖ [s] ‖ suffix`.
fn material(p: &[u8; 32], x25519_pub: &[u8; 32], e: Epoch, s: OpIdx, suffix: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(72);
    m.extend_from_slice(p);
    m.extend_from_slice(x25519_pub);
    m.extend_from_slice(&e.0.to_le_bytes());
    m.push(s);
    m.extend_from_slice(suffix);
    m
}

fn key16(k: [u8; 32]) -> Key {
    let mut out = [0u8; 16];
    out.copy_from_slice(k.first_chunk::<16>().map_or(&[0u8; 16][..], |c| &c[..]));
    out
}

/// `K_seq(e, s)` from `P_seq = X25519(x, XK(s, home(e)))`.
pub fn k_seq(p_seq: &[u8; 32], x25519_pub: &[u8; 32], e: Epoch, s: OpIdx) -> Key {
    key16(derive_key(
        SESSION_CONTEXT,
        &material(p_seq, x25519_pub, e, s, b"seq"),
    ))
}

/// `K_out(e, s)`, which tags responses (01 §6.3).
pub fn k_out(p_seq: &[u8; 32], x25519_pub: &[u8; 32], e: Epoch, s: OpIdx) -> Key {
    key16(derive_key(
        SESSION_CONTEXT,
        &material(p_seq, x25519_pub, e, s, b"out"),
    ))
}

/// `head(e, s) = c(e, s, N)` from `P_com = X25519(x, G(e, s).pub)`.
pub fn kcom_head(p_com: &[u8; 32], x25519_pub: &[u8; 32], e: Epoch, s: OpIdx) -> [u8; 32] {
    derive_key(KCOM_HEAD_CONTEXT, &material(p_com, x25519_pub, e, s, b""))
}

/// One step down the chain: `c(k − 1) = BLAKE3(c(k))`.
#[inline]
pub fn step(c: &[u8; 32]) -> [u8; 32] {
    hash(c).0
}

/// `c` hashed `n` times.
pub fn hash_n(c: &[u8; 32], n: u32) -> [u8; 32] {
    let mut v = *c;
    for _ in 0..n {
        v = step(&v);
    }
    v
}

/// `A(e, s) = c(e, s, 0)`, the anchor a `SessionOpen` carries.
pub fn anchor(head: &[u8; 32]) -> Hash {
    Hash(hash_n(head, TESLA_N))
}

/// `K_com(e, s, i)` from `c(e, s, i)`.
pub fn k_com(c_i: &[u8; 32]) -> Key {
    key16(derive_key(KCOM_CONTEXT, c_i))
}

/// `interval(e, b, h) = min(N, 1 + (h − h0(e, b)) / CHN_TESLA_BLOCKS)`; `None` when `h < h0`.
pub fn interval(h: Height, h0: Height) -> Option<u32> {
    let blocks = h.0.checked_sub(h0.0)?;
    let i = (blocks / TESLA_BLOCKS).saturating_add(1);
    Some(u32::try_from(i).unwrap_or(u32::MAX).min(TESLA_N))
}

/// The acceptance window of interval `i` in the order the validator tries it: `i`, `i − 1`,
/// `i + 1`, each kept only when it is in `[1, N]` (09 §5.4).
pub fn window(i: u32) -> impl Iterator<Item = u32> {
    [Some(i), i.checked_sub(1), i.checked_add(1)]
        .into_iter()
        .flatten()
        .filter(|j| (1..=TESLA_N).contains(j))
}

/// What the client derives for one (session, e, s) (09 §5.3, table "Party").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientKeys {
    /// `K_seq(e, s)`.
    pub k_seq: Key,
    /// `K_out(e, s)`.
    pub k_out: Key,
    /// `head(e, s) = c(e, s, N)`.
    pub head: [u8; 32],
}

impl ClientKeys {
    /// Keys for epoch `e` and sequencer `s` from the session's X25519 secret `x`, the exchange key
    /// `xk_pub` of s's node in `home(e)`, and the committee key `g_pub = G(e, s).pub`. `None` if
    /// either public key is a low-order point.
    pub fn derive(
        x: &[u8; 32],
        xk_pub: &[u8; 32],
        g_pub: &[u8; 32],
        e: Epoch,
        s: OpIdx,
    ) -> Option<Self> {
        let me = x25519::public_key(x);
        let p_seq = x25519::shared_secret(x, xk_pub)?;
        let p_com = x25519::shared_secret(x, g_pub)?;
        Some(Self {
            k_seq: k_seq(&p_seq, &me, e, s),
            k_out: k_out(&p_seq, &me, e, s),
            head: kcom_head(&p_com, &me, e, s),
        })
    }

    /// The anchor `A(e, s)`.
    pub fn anchor(&self) -> Hash {
        anchor(&self.head)
    }
}

/// `(K_seq, K_out)` on the sequencer node of s, from its `XK` private half.
pub fn sequencer_keys(
    xk: &[u8; 32],
    x25519_pub: &[u8; 32],
    e: Epoch,
    s: OpIdx,
) -> Option<(Key, Key)> {
    let p = x25519::shared_secret(xk, x25519_pub)?;
    Some((k_seq(&p, x25519_pub, e, s), k_out(&p, x25519_pub, e, s)))
}

/// `head(e, s)` on a committee member i ≠ s, from the `G(e, s)` private half.
pub fn member_head(g: &[u8; 32], x25519_pub: &[u8; 32], e: Epoch, s: OpIdx) -> Option<[u8; 32]> {
    let p = x25519::shared_secret(g, x25519_pub)?;
    Some(kcom_head(&p, x25519_pub, e, s))
}

/// The anchor check failed: `head` hashed N times is not the on-chain anchor (09 §5.4). The
/// member submits `AnchorFault`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the chain head does not hash to the session's anchor")]
pub struct AnchorMismatch;

/// Outputs `c(1), c(2), …, c(N)` in order from `head = c(N)`, storing ≤ 16 values.
///
/// The stack holds `(index, c(index))` with indices decreasing toward the top, all ≥ the next
/// output. To reach index t it splits the gap to the top entry in half until the top is t.
#[derive(Clone, Debug)]
pub struct Traversal {
    stack: Vec<(u32, [u8; 32])>,
    next: u32,
    hashes: u64,
}

impl Traversal {
    /// Walks `head` down to the anchor once, checks it (the anchor check of 09 §5.4), and keeps
    /// the values the first output needs, so seeding costs exactly N hashes.
    pub fn seed(head: &[u8; 32], anchor: &Hash) -> Result<Self, AnchorMismatch> {
        // The indices that splitting from (N, head) toward t = 1 would produce.
        let mut marks = vec![TESLA_N];
        let mut p = TESLA_N;
        while p > 1 {
            p = split(1, p);
            marks.push(p);
        }
        let mut stack = Vec::with_capacity(17);
        let mut v = *head;
        let mut want = marks.iter().copied().peekable();
        for idx in (0..=TESLA_N).rev() {
            if want.peek() == Some(&idx) {
                stack.push((idx, v));
                want.next();
            }
            if idx > 0 {
                v = step(&v);
            }
        }
        if v != anchor.0 {
            return Err(AnchorMismatch);
        }
        Ok(Self {
            stack,
            next: 1,
            hashes: u64::from(TESLA_N),
        })
    }

    /// The next `(i, c(i))`, or `None` after `c(N)`.
    pub fn next_value(&mut self) -> Option<(u32, [u8; 32])> {
        let t = self.next;
        loop {
            let &(p, v) = self.stack.last()?;
            if p == t {
                break;
            }
            // p > t: every stacked index is at least the next output.
            let mid = split(t, p);
            let n = p.saturating_sub(mid);
            self.stack.push((mid, hash_n(&v, n)));
            self.hashes = self.hashes.saturating_add(u64::from(n));
        }
        let out = self.stack.pop()?;
        self.next = t.saturating_add(1);
        Some(out)
    }

    /// BLAKE3 calls so far, seeding included (for B-CHN-1 accounting).
    pub fn hashes(&self) -> u64 {
        self.hashes
    }
}

/// The index between target `t` and stacked index `p > t` that the traversal stores next.
fn split(t: u32, p: u32) -> u32 {
    let gap = p.saturating_sub(t);
    if gap <= 1 {
        t
    } else {
        t.saturating_add(gap / 2)
    }
}

/// The validator's `K_com` keys for one (session, e, s): during interval i it holds the keys of
/// `i − 1 ..= i + 2`, so the whole acceptance window is ready when a packet arrives (09 §5.4).
#[derive(Clone, Debug)]
pub struct KcomWindow {
    trav: Traversal,
    ring: [(u32, Key); 4],
}

impl KcomWindow {
    /// A window at interval 1, from a seeded traversal.
    pub fn new(trav: Traversal) -> Self {
        let mut w = Self {
            trav,
            ring: [(0, [0; 16]); 4],
        };
        w.advance(1);
        w
    }

    /// Derives keys up to `min(N, i + 2)`. Intervals only move forward; a jump derives every key
    /// in between.
    pub fn advance(&mut self, i: u32) {
        let target = i.saturating_add(2).min(TESLA_N);
        while self.trav.next <= target {
            let Some((j, c)) = self.trav.next_value() else {
                return;
            };
            if let Some(slot) = self.ring.get_mut(slot_of(j)) {
                *slot = (j, k_com(&c));
            }
        }
    }

    /// `K_com(e, s, j)` if it is in the window.
    pub fn key(&self, j: u32) -> Option<Key> {
        self.ring
            .get(slot_of(j))
            .filter(|(at, _)| *at == j && j != 0)
            .map(|(_, k)| *k)
    }

    /// The `tag_com` check of a packet in a block of interval `i` (09 §5.5): tries `i`, `i − 1`,
    /// `i + 1`. Call [`Self::advance`] for the interval first.
    pub fn check(&self, i: u32, body: &[u8], tag: Tag) -> bool {
        window(i).any(|j| {
            self.key(j)
                .is_some_and(|k| tag_eq(siphash24(&k, body), tag))
        })
    }

    /// BLAKE3 calls so far.
    pub fn hashes(&self) -> u64 {
        self.trav.hashes()
    }
}

fn slot_of(j: u32) -> usize {
    usize::try_from(j % 4).unwrap_or(0)
}

/// `KeyDisclosure` (09 §5.10): self-certifying, no signature. 45 bytes on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDisclosure {
    /// The session.
    pub session: SessionId,
    /// The epoch of the chain.
    pub epoch: Epoch,
    /// The sequencer s of the chain.
    pub seq_op: OpIdx,
    /// i, with `value = c(e, s, i)`.
    pub index: u32,
    /// `c(e, s, i)`.
    pub value: [u8; 32],
}

/// The encoded length of a [`KeyDisclosure`].
pub const DISCLOSURE_LEN: usize = 45;

impl KeyDisclosure {
    /// `le32(session) ‖ le32(epoch) ‖ [seq_op] ‖ le32(index) ‖ value`.
    ///
    /// **Spec gap:** 09 §5.10 gives the fields, not the encoding; this is field order, little-endian
    /// (01 §3), which matches its "45 bytes" cost figure.
    pub fn encode(&self) -> [u8; DISCLOSURE_LEN] {
        let mut w = crate::codec::Writer::with_capacity(DISCLOSURE_LEN);
        w.u32(self.session.0);
        w.u32(self.epoch.0);
        w.u8(self.seq_op);
        w.u32(self.index);
        w.bytes(&self.value);
        w.finish().try_into().unwrap_or([0; DISCLOSURE_LEN])
    }

    /// The inverse of [`Self::encode`].
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = crate::codec::Reader::new(b);
        let d = Self {
            session: SessionId(r.u32()?),
            epoch: Epoch(r.u32()?),
            seq_op: r.u8()?,
            index: r.u32()?,
            value: r.array()?,
        };
        r.finish()?;
        Some(d)
    }

    /// Whether `value` hashed `index` times is `anchor` and `index` is in `[1, N]`.
    pub fn verify(&self, anchor: &Hash) -> bool {
        (1..=TESLA_N).contains(&self.index) && hash_n(&self.value, self.index) == anchor.0
    }

    /// `K_com(e, s, j)` for `1 ≤ j ≤ index`: `c(j) = H^(index − j)(value)`. Verify first.
    pub fn k_com(&self, j: u32) -> Option<Key> {
        if j == 0 || j > self.index {
            return None;
        }
        Some(k_com(&hash_n(&self.value, self.index.saturating_sub(j))))
    }
}

/// The newest index that may be disclosed once a block of interval `final_interval` is final:
/// every block of interval ≤ i + 1 must be final, so `i ≤ final_interval − 2` (09 §5.10). 0 means
/// none yet. At the epoch's end, when every block is final, `c(N)` may be disclosed.
pub fn disclosable(final_interval: u32) -> u32 {
    final_interval.saturating_sub(2)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// All of `c(0..=N)` by one walk, index = position.
    fn chain(head: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut c = vec![[0u8; 32]; TESLA_N as usize + 1];
        let mut v = *head;
        for i in (0..=TESLA_N as usize).rev() {
            c[i] = v;
            v = step(&v);
        }
        c
    }

    #[test]
    fn traversal_outputs_the_whole_chain_in_order_with_small_state() {
        let head = [7u8; 32];
        let c = chain(&head);
        let mut t = Traversal::seed(&head, &Hash(c[0])).unwrap();
        let mut max_stack = 0;
        for i in 1..=TESLA_N {
            max_stack = max_stack.max(t.stack.len());
            assert_eq!(t.next_value(), Some((i, c[i as usize])), "index {i}");
        }
        assert_eq!(t.next_value(), None);
        assert!(max_stack <= 16, "stack {max_stack}");
        // Amortized cost: ~log2(N)/2 per step after seeding; well under 15.
        let per_step = (t.hashes() - u64::from(TESLA_N)) / u64::from(TESLA_N);
        assert!(per_step <= 8, "per step {per_step}");
    }

    #[test]
    fn seed_rejects_a_wrong_anchor() {
        let head = [7u8; 32];
        let bad = Hash(hash_n(&head, TESLA_N - 1));
        assert_eq!(Traversal::seed(&head, &bad).unwrap_err(), AnchorMismatch);
    }

    #[test]
    fn client_member_and_sequencer_agree_and_the_window_checks_tags() {
        let x = [1u8; 32];
        let xk = [2u8; 32];
        let g = [3u8; 32];
        let (e, s) = (Epoch(9), 2);
        let me = x25519::public_key(&x);
        let ck = ClientKeys::derive(&x, &x25519::public_key(&xk), &x25519::public_key(&g), e, s)
            .unwrap();
        assert_eq!(sequencer_keys(&xk, &me, e, s), Some((ck.k_seq, ck.k_out)));
        assert_eq!(member_head(&g, &me, e, s), Some(ck.head));
        assert_ne!(ck.k_seq, ck.k_out);
        // Another sequencer or epoch gives other keys.
        assert_ne!(
            sequencer_keys(&xk, &me, e, 3).unwrap().0,
            ck.k_seq,
            "s is in the material"
        );
        assert_ne!(member_head(&g, &me, Epoch(10), s), Some(ck.head));

        let c = chain(&ck.head);
        let mut w = KcomWindow::new(Traversal::seed(&ck.head, &ck.anchor()).unwrap());
        let body = b"packet body without tags";
        let tag_at = |j: u32| siphash24(&k_com(&c[j as usize]), body);
        w.advance(5);
        // Window of 5 is {5, 4, 6}; 3 and 7 are outside even though 7 is already derived.
        for (j, ok) in [(3, false), (4, true), (5, true), (6, true), (7, false)] {
            assert_eq!(w.check(5, body, tag_at(j)), ok, "j = {j}");
        }
        assert_eq!(w.key(7), Some(k_com(&c[7])));
        assert_eq!(w.key(3), None, "evicted");
        // Interval 1 has no i − 1; the last interval has no i + 1.
        assert_eq!(window(1).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(window(TESLA_N).collect::<Vec<_>>(), [TESLA_N, TESLA_N - 1]);
        w.advance(TESLA_N);
        assert!(w.check(TESLA_N, body, tag_at(TESLA_N)));
        assert!(w.check(TESLA_N, body, tag_at(TESLA_N - 1)));
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    /// Computed with `b3sum --derive-key <context>` (BLAKE3 1.8.7 CLI) over the material bytes.
    #[test]
    fn derivations_match_b3sum() {
        let (p, me, e, s) = ([0x11; 32], [0x22; 32], Epoch(9), 2);
        let seq: [u8; 32] =
            unhex("3bdfe6d7f8c48cfeb801ba49239ce4da808f5a7f6a4d7060ca314b810a61b2b6");
        assert_eq!(k_seq(&p, &me, e, s), seq[..16]);
        assert_eq!(
            kcom_head(&p, &me, e, s),
            unhex::<32>("ac92253e94cc0a4401706bf8e057afec11f974501920b75186879aa2cc252ec6")
        );
        let kc: [u8; 32] =
            unhex("faf91cb4df5a9d6aeefbc3568640056f090114eb896d34dc9a0ac3c0d8bdf129");
        assert_eq!(k_com(&[0x33; 32]), kc[..16]);
    }

    #[test]
    fn low_order_keys_are_refused() {
        // u = 0 and u = 1 are low-order Montgomery points.
        let mut one = [0u8; 32];
        one[0] = 1;
        for bad in [[0u8; 32], one] {
            assert_eq!(
                ClientKeys::derive(&[1; 32], &bad, &[9; 32], Epoch(1), 0),
                None
            );
            assert_eq!(member_head(&[3; 32], &bad, Epoch(1), 0), None);
        }
    }

    #[test]
    fn interval_counts_book_blocks_and_caps_at_n() {
        let h0 = Height(5_000);
        assert_eq!(interval(Height(4_999), h0), None);
        assert_eq!(interval(h0, h0), Some(1));
        assert_eq!(interval(Height(5_999), h0), Some(1));
        assert_eq!(interval(Height(6_000), h0), Some(2));
        assert_eq!(interval(Height(u64::MAX), h0), Some(TESLA_N));
    }

    #[test]
    fn disclosures_self_certify_and_give_earlier_keys_only() {
        let head = [5u8; 32];
        let c = chain(&head);
        let a = Hash(c[0]);
        let d = KeyDisclosure {
            session: SessionId(77),
            epoch: Epoch(3),
            seq_op: 4,
            index: 100,
            value: c[100],
        };
        assert!(d.verify(&a));
        assert_eq!(KeyDisclosure::decode(&d.encode()), Some(d));
        assert_eq!(KeyDisclosure::decode(&d.encode()[..44]), None);
        assert_eq!(d.k_com(99), Some(k_com(&c[99])));
        assert_eq!(d.k_com(100), Some(k_com(&c[100])));
        assert_eq!(d.k_com(101), None);
        assert_eq!(d.k_com(0), None);
        // A value from another index, or index 0 (the anchor itself), does not verify.
        assert!(!KeyDisclosure { value: c[101], ..d }.verify(&a));
        assert!(
            !KeyDisclosure {
                index: 0,
                value: c[0],
                ..d
            }
            .verify(&a)
        );
        assert_eq!(disclosable(1), 0);
        assert_eq!(disclosable(12), 10);
    }
}
