//! The opening auction (08 §7): what a window message gets in its 1 µs answer, the reference
//! price and band, the uncross rule and the per-order fill.
//!
//! Everything here is a pure integer function, so the Rust engine, the Vx client, every replica
//! and an oracle compute the same clearing tick and the same fills (`INV-DET`). The engine (05
//! §8.8, `vyrn-engine`) owns the histograms, the lane FIFOs and the distributed marginal search;
//! this module owns the rule they implement and a reference implementation to test them against.
//!
//! | Function | Spec | Input | Output |
//! |---|---|---|---|
//! | [`window_answer`] | §7.2, §7.11, 04 §6.9 | one request message, halted or not | queued `Ack`, `EpochNotice` or a reject |
//! | [`at_uncross`] | §7.2 "At U" | a window order's TIF | rests or ends `Out` cause auction |
//! | [`reference`], [`Band::around`] | §7.5 | last trade, bid(S), ask(S), book ref | `ref`, the 8,193-tick band |
//! | [`uncross`], [`uncross_price`] | §7.6, §7.7, 05 §8.8 step 4 | per-tick buy and sell totals over the band | [`Clearing`] or none |
//! | [`marginal`] | §7.7 `select_marginal` | the orders at `p_m` in key order | the marginal key and its fill |
//! | [`auction_fill`] | §7.7 | one order and the [`UncrossRecord`] | its fill |
//! | [`prio_key`] | §7.4 | `rx_ts`, entry rank, entry `LaneSeq` | the u128 key |
//!
//! # Spec gap: IOC in the window [Likely]
//!
//! 08 §7.2 queues a window `New` IOC (it joins the auction, its rest is `Out` cause auction).
//! 04 §6.9 and 05 §8.8 step 1 reject IOC in the auction phase with `AUCTION_PHASE`, and 08 §7.11
//! does not list IOC among the messages that cannot be queued. This crate follows **04 §6.9**:
//! two chapters agree, the engine already rejects it, and §7.9 says the same calls serve every
//! auction (a reopening after `BOOK_HALTED` too), so one rule for every auction keeps the answer a
//! function of the phase alone. [`IOC_IN_WINDOW`] is the single switch. 08 §7.2 should be amended.

use vyrn_types::{Qty, RejectReason, Tick};
use vyrn_wire::{Msg, Side, Tif};

/// Band half-width in ticks (08 Local definitions): the band is `2 × 4,096 + 1` = 8,193 ticks.
pub const EPO_HIST_HALF: u32 = 4_096;
/// Width of the band and of every histogram.
pub const EPO_HIST_TICKS: usize = 2 * EPO_HIST_HALF as usize + 1;
/// `EPO_ACK_QUEUED` in `Ack` bytes 2–3 (08 Requests to 01 item 8).
///
/// Spec gap: 08 names the flag without a value. This crate uses 1 [Guessing].
pub const EPO_ACK_QUEUED: u16 = 1;
/// `PROTO_PHASE_AUCTION`, the `AUCTION_PHASE` detail in the window (04 §6.9).
pub const PROTO_PHASE_AUCTION: u16 = 2;

/// What a window IOC gets: the reading this crate chose (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IocRule {
    /// 04 §6.9: `Reject AUCTION_PHASE`.
    Reject,
    /// 08 §7.2: queued, joins, the rest ends `Out` cause auction.
    Queue,
}

/// The chosen reading: 04 §6.9.
pub const IOC_IN_WINDOW: IocRule = IocRule::Reject;

/// The 1 µs answer to one window message (§7.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowAnswer {
    /// `Ack` with `EPO_ACK_QUEUED`: in the log of e+1, resolved at U.
    Queued,
    /// `EpochNotice` in the window stream (`Heartbeat`, 04 §4.8).
    Notice,
    /// `Reject` in the window stream with this reason and detail.
    Reject(RejectReason, u16),
}

/// What happens to a window order's remainder at U (§7.2 column "At U").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtUncross {
    /// The remainder rests (Day).
    Rest,
    /// The remainder ends `Out` cause auction (auction-only, and IOC under [`IocRule::Queue`]).
    OutAuction,
}

fn tif_answer(tif: Tif, post_only: bool) -> WindowAnswer {
    let phase = WindowAnswer::Reject(RejectReason::AuctionPhase, PROTO_PHASE_AUCTION);
    match (tif, post_only) {
        (_, true) | (Tif::Fok, _) => phase,
        (Tif::Ioc, _) if IOC_IN_WINDOW == IocRule::Reject => phase,
        _ => WindowAnswer::Queued,
    }
}

/// §7.2 and §7.11 for one decoded message. `halted` is true from the cut after `EpoHalt`
/// (§10.3): `New` and `Replace` are then `BOOK_HALTED`, and risk-reducing messages still queue.
///
/// The gates every message passes first (deadline admission, `rx_ts`, `epoch16`, session,
/// duplicate `pkt_seq`, buffer full) are the lane's and come before this call.
pub fn window_answer(m: &Msg, halted: bool) -> WindowAnswer {
    match m {
        Msg::New { .. } | Msg::Replace { .. } if halted => {
            WindowAnswer::Reject(RejectReason::BookHalted, 0)
        }
        Msg::New { flags, .. } | Msg::Replace { flags, .. } => {
            tif_answer(flags.tif, flags.post_only)
        }
        Msg::Cancel { .. } | Msg::Reduce { .. } | Msg::CancelAll { .. } | Msg::ResendReq { .. } => {
            WindowAnswer::Queued
        }
        Msg::Heartbeat => WindowAnswer::Notice,
    }
}

/// §7.2 "At U" for a window order that [`window_answer`] queued.
pub fn at_uncross(tif: Tif) -> AtUncross {
    match tif {
        Tif::Day => AtUncross::Rest,
        Tif::Ioc | Tif::Fok | Tif::AuctionOnly => AtUncross::OutAuction,
    }
}

/// `PrioKey = rx_ts ‖ entry_rank (8 bits) ‖ entry_lane_seq (56 bits)` as one u128 (§7.4).
/// `entry_lane_seq` above `2^56 − 1` is truncated; §7.4 shows it cannot occur.
pub fn prio_key(rx_ts: u64, entry_rank: u8, entry_lane_seq: u64) -> u128 {
    (u128::from(rx_ts) << 64)
        | (u128::from(entry_rank) << 56)
        | u128::from(entry_lane_seq & ((1 << 56) - 1))
}

/// §7.5: the last trade of epoch e, else bid(S), else ask(S), else `BookSpec.ref_tick`, clamped
/// into `[bid(S), ask(S)]`.
pub fn reference(
    last_trade: Option<Tick>,
    bid: Option<Tick>,
    ask: Option<Tick>,
    book_ref: Tick,
) -> Tick {
    let mut r = last_trade.or(bid).or(ask).unwrap_or(book_ref);
    if let Some(b) = bid {
        r = r.max(b);
    }
    if let Some(a) = ask {
        r = r.min(a);
    }
    r
}

/// The auction band (§7.5), inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band {
    pub lo: Tick,
    pub hi: Tick,
}

impl Band {
    /// `[max(min_tick, ref − EPO_HIST_HALF), min(max_tick, ref + EPO_HIST_HALF)]`.
    pub fn around(reference: Tick, min_tick: Tick, max_tick: Tick) -> Self {
        Self {
            lo: Tick(reference.0.saturating_sub(EPO_HIST_HALF).max(min_tick.0)),
            hi: Tick(reference.0.saturating_add(EPO_HIST_HALF).min(max_tick.0)),
        }
    }

    pub fn contains(&self, t: Tick) -> bool {
        self.lo <= t && t <= self.hi
    }

    /// The histogram bucket of `t`, if `t` is in the band.
    pub fn index(&self, t: Tick) -> Option<usize> {
        self.contains(t).then(|| (t.0 - self.lo.0) as usize)
    }
}

/// A window `New` outside the band is `BAD_TICK` (§7.5); a carried order outside it rests and
/// stays out of the histogram.
pub fn band_check(band: &Band, t: Tick) -> Result<(), RejectReason> {
    if band.contains(t) {
        Ok(())
    } else {
        Err(RejectReason::BadTick)
    }
}

/// The result of the uncross rule over the band (§7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clearing {
    /// p*.
    pub p: Tick,
    /// V(p*) > 0.
    pub v: u64,
    /// I(p*) = D(p*) − S(p*).
    pub imb: i128,
    /// The marginal tick on the rationed side (= p when `imb` = 0).
    pub p_m: Tick,
    /// Quantity the orders at `p_m` share in key order (0 when `imb` = 0).
    pub q_rem: u64,
}

impl Clearing {
    /// The rationed side, if any.
    pub fn rationed(&self) -> Option<Side> {
        match self.imb.signum() {
            1 => Some(Side::Buy),
            -1 => Some(Side::Sell),
            _ => None,
        }
    }
}

/// §7.6–7.7 over per-tick totals `buy[i]`, `sell[i]` at tick `lo + i`, carried and window orders
/// together. `None` when nothing crosses (`max V = 0`), or the slices differ in length or are
/// empty. O(B).
pub fn uncross(buy: &[u64], sell: &[u64], lo: Tick, reference: Tick) -> Option<Clearing> {
    let n = buy.len();
    if n == 0 || sell.len() != n {
        return None;
    }
    // D(t) = Σ_{u ≥ t} b[u], S(t) = Σ_{u ≤ t} s[u].
    let mut d = vec![0u64; n];
    let mut acc = 0u64;
    for i in (0..n).rev() {
        acc = acc.saturating_add(buy[i]);
        d[i] = acc;
    }
    let mut sp = vec![0u64; n];
    acc = 0;
    for i in 0..n {
        acc = acc.saturating_add(sell[i]);
        sp[i] = acc;
    }
    let (i, v) = best(&d, &sp, lo, reference)?;
    let tick = |i: usize| Tick(lo.0.saturating_add(u32::try_from(i).unwrap_or(u32::MAX)));
    let imb = i128::from(d[i]) - i128::from(sp[i]);
    let (m, q_rem) = match imb.signum() {
        0 => (i, 0),
        // Highest m with D(m) ≥ V; q_rem = V − D(m + 1).
        1 => {
            let m = (i..n).rev().find(|&u| d[u] >= v).unwrap_or(i);
            (m, v - d.get(m + 1).copied().unwrap_or(0))
        }
        // Lowest m with S(m) ≥ V; q_rem = V − S(m − 1).
        _ => {
            let m = (0..=i).find(|&u| sp[u] >= v).unwrap_or(i);
            (m, v - if m > 0 { sp[m - 1] } else { 0 })
        }
    };
    Some(Clearing {
        p: tick(i),
        v,
        imb,
        p_m: tick(m),
        q_rem,
    })
}

/// Rules 1–4 of §7.6 as one lexicographic key over cumulative `d` and `s`. Returns the index of
/// p* and V(p*), or `None` when `max V = 0`.
fn best(d: &[u64], s: &[u64], lo: Tick, reference: Tick) -> Option<(usize, u64)> {
    type Key = (
        u64,
        core::cmp::Reverse<u128>,
        core::cmp::Reverse<u32>,
        core::cmp::Reverse<u32>,
    );
    let mut top: Option<(Key, usize)> = None;
    for (i, (&di, &si)) in d.iter().zip(s).enumerate() {
        let t = lo.0.saturating_add(u32::try_from(i).unwrap_or(u32::MAX));
        let imb = i128::from(di) - i128::from(si);
        let k: Key = (
            di.min(si),
            core::cmp::Reverse(imb.unsigned_abs()),
            core::cmp::Reverse(t.abs_diff(reference.0)),
            core::cmp::Reverse(t),
        );
        if top.as_ref().is_none_or(|(bk, _)| k > *bk) {
            top = Some((k, i));
        }
    }
    let ((v, ..), i) = top?;
    (v > 0).then_some((i, v))
}

/// 05 §8.8 step 4's signature: cumulative demand `d[i] = D(lo + i)` and supply `s[i] = S(lo + i)`
/// in, `(p*, V)` out, or `None` if nothing crosses.
pub fn uncross_price(d: &[u64], s: &[u64], lo: Tick, reference: Tick) -> Option<(Tick, u64)> {
    if d.len() != s.len() {
        return None;
    }
    let (i, v) = best(d, s, lo, reference)?;
    Some((Tick(lo.0.saturating_add(u32::try_from(i).ok()?)), v))
}

/// §7.7 `select_marginal`, as a sequential reference: `orders` are `(PrioKey, remaining)` at
/// `p_m` on the rationed side, in ascending key order. Returns the first key at which the
/// cumulative quantity reaches `q_rem` and that order's fill, or `None` when `q_rem` is 0 or the
/// orders hold less than `q_rem` (an input the engine cannot produce).
///
/// The engine's parallel weighted-median search over the lanes must return the same pair.
pub fn marginal(orders: impl IntoIterator<Item = (u128, Qty)>, q_rem: u64) -> Option<(u128, Qty)> {
    if q_rem == 0 {
        return None;
    }
    let mut below = 0u64;
    for (key, q) in orders {
        let q64 = u64::from(q.0);
        if below + q64 >= q_rem {
            return Some((key, Qty(u32::try_from(q_rem - below).ok()?)));
        }
        below += q64;
    }
    None
}

/// What the BBO core publishes at U and every lane reads (§7.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UncrossRecord {
    pub p: Tick,
    pub v: u64,
    pub imb: i128,
    pub p_m: Tick,
    /// The marginal order's key (0 if `imb` = 0).
    pub marg: u128,
    /// The marginal order's fill (0 if `imb` = 0).
    pub marg_qty: Qty,
    pub ref_tick: Tick,
    pub band_lo: Tick,
}

impl UncrossRecord {
    /// The record for `c`, with the marginal pair from [`marginal`] (ignored when `imb` = 0).
    pub fn new(c: &Clearing, marg: Option<(u128, Qty)>, reference: Tick, band: &Band) -> Self {
        let (marg, marg_qty) = match (c.imb, marg) {
            (0, _) | (_, None) => (0, Qty(0)),
            (_, Some(m)) => m,
        };
        Self {
            p: c.p,
            v: c.v,
            imb: c.imb,
            p_m: c.p_m,
            marg,
            marg_qty,
            ref_tick: reference,
            band_lo: band.lo,
        }
    }
}

/// One order as `auction_fill` sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuctionOrder {
    pub side: Side,
    pub tick: Tick,
    pub key: u128,
    pub remaining: Qty,
}

/// §7.7 `auction_fill`: the fill of one order, a pure function of the record. Every execution is
/// at `u.p`.
pub fn auction_fill(o: &AuctionOrder, u: &UncrossRecord) -> Qty {
    let buy = o.side == Side::Buy;
    let at_or_better = if buy { o.tick >= u.p } else { o.tick <= u.p };
    if !at_or_better {
        return Qty(0);
    }
    let rationed = (u.imb > 0 && buy) || (u.imb < 0 && !buy);
    if !rationed {
        return o.remaining;
    }
    let beyond = if buy { o.tick > u.p_m } else { o.tick < u.p_m };
    if beyond {
        o.remaining
    } else if o.tick != u.p_m {
        Qty(0)
    } else if o.key < u.marg {
        o.remaining
    } else if o.key == u.marg {
        u.marg_qty
    } else {
        Qty(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyrn_types::Handle;
    use vyrn_wire::{OrderFlags, Stp};

    fn new(tif: Tif, post_only: bool) -> Msg {
        Msg::New {
            flags: OrderFlags {
                side: Side::Buy,
                tif,
                post_only,
                stp: Stp::None,
            },
            tick: Tick(100),
            qty: Qty(1),
            client_tag: 0,
        }
    }

    #[test]
    fn window_table_follows_04_for_ioc() {
        let phase = WindowAnswer::Reject(RejectReason::AuctionPhase, PROTO_PHASE_AUCTION);
        assert_eq!(
            window_answer(&new(Tif::Day, false), false),
            WindowAnswer::Queued
        );
        assert_eq!(
            window_answer(&new(Tif::AuctionOnly, false), false),
            WindowAnswer::Queued
        );
        assert_eq!(window_answer(&new(Tif::Ioc, false), false), phase);
        assert_eq!(window_answer(&new(Tif::Fok, false), false), phase);
        assert_eq!(window_answer(&new(Tif::Day, true), false), phase);
        let rep = Msg::Replace {
            flags: OrderFlags {
                side: Side::Sell,
                tif: Tif::Day,
                post_only: true,
                stp: Stp::None,
            },
            handle: Handle(1),
            tick: Tick(1),
            qty: Qty(1),
        };
        assert_eq!(window_answer(&rep, false), phase);
        assert_eq!(window_answer(&Msg::Heartbeat, false), WindowAnswer::Notice);
        let cancel = Msg::Cancel {
            handle: Handle(3),
            client_tag: 0,
        };
        // After EpoHalt: New and Replace are BOOK_HALTED, a cancel still queues.
        assert_eq!(
            window_answer(&new(Tif::Day, false), true),
            WindowAnswer::Reject(RejectReason::BookHalted, 0)
        );
        assert_eq!(
            window_answer(&rep, true),
            WindowAnswer::Reject(RejectReason::BookHalted, 0)
        );
        assert_eq!(window_answer(&cancel, true), WindowAnswer::Queued);
        assert_eq!(
            window_answer(&Msg::CancelAll { client_tag: 0 }, true),
            WindowAnswer::Queued
        );
        assert_eq!(at_uncross(Tif::Day), AtUncross::Rest);
        assert_eq!(at_uncross(Tif::AuctionOnly), AtUncross::OutAuction);
    }

    #[test]
    fn reference_is_clamped_into_the_carried_spread() {
        let r = Tick(1_000);
        assert_eq!(
            reference(Some(Tick(90)), Some(Tick(100)), Some(Tick(110)), r),
            Tick(100)
        );
        assert_eq!(
            reference(Some(Tick(120)), Some(Tick(100)), Some(Tick(110)), r),
            Tick(110)
        );
        assert_eq!(
            reference(Some(Tick(105)), Some(Tick(100)), Some(Tick(110)), r),
            Tick(105)
        );
        assert_eq!(reference(None, None, Some(Tick(110)), r), Tick(110));
        assert_eq!(reference(None, None, None, r), r);
        let b = Band::around(Tick(100), Tick(1), Tick(u32::MAX));
        assert_eq!((b.lo, b.hi), (Tick(1), Tick(4_196)));
        let b = Band::around(Tick(10_000), Tick(1), Tick(12_000));
        assert_eq!((b.lo, b.hi), (Tick(5_904), Tick(12_000)));
        assert_eq!(b.index(Tick(5_904)), Some(0));
        assert_eq!(band_check(&b, Tick(5_903)), Err(RejectReason::BadTick));
        assert_eq!(prio_key(1, 2, 3), (1u128 << 64) | (2 << 56) | 3);
    }

    #[test]
    fn hand_cases() {
        // Buys 5@12, 5@10; sells 4@9, 4@11. At 10: D = 10, S = 4, V = 4. At 11: D = 5, S = 8,
        // V = 5, |I| = 3. At 12: D = 5, S = 8. Max V = 5 at 11 and 12; |I| ties; 11 is nearer
        // ref 10. Sells rationed? I(11) = 5 − 8 < 0, so sells are rationed: lowest m with S ≥ 5
        // is 11; q_rem = 5 − S(10) = 1.
        let lo = Tick(9);
        let buy = [0, 5, 0, 5];
        let sell = [4, 0, 4, 0];
        let c = uncross(&buy, &sell, lo, Tick(10)).unwrap_or_else(|| panic!("crosses"));
        assert_eq!(
            c,
            Clearing {
                p: Tick(11),
                v: 5,
                imb: -3,
                p_m: Tick(11),
                q_rem: 1
            }
        );
        // Nothing crosses.
        assert_eq!(uncross(&[1, 0], &[0, 1], Tick(1), Tick(1)), None);
        // Rule 3: V and |I| tie on [10, 12]; ref 15 picks 12, ref 2 picks 9.
        let (buy, sell) = ([0, 0, 0, 3], [3, 0, 0, 0]);
        assert_eq!(
            uncross(&buy, &sell, Tick(9), Tick(15)).map(|c| c.p),
            Some(Tick(12))
        );
        assert_eq!(
            uncross(&buy, &sell, Tick(9), Tick(2)).map(|c| c.p),
            Some(Tick(9))
        );
        assert_eq!(
            uncross_price(&[3, 3, 3, 3], &[3, 3, 3, 3], Tick(9), Tick(11)),
            Some((Tick(11), 3))
        );
    }

    /// A tiny deterministic generator, so the test needs no dependency.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, m: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % m
        }
    }

    /// The rule from first principles: brute force over every tick, then price-time allocation by
    /// sorting. Compared with `uncross` + `marginal` + `auction_fill`.
    #[test]
    fn matches_a_brute_force_oracle() {
        let mut g = Lcg(7);
        for _ in 0..3_000 {
            let width = 1 + g.next(12) as u32;
            let lo = Tick(50);
            let reference = Tick(lo.0 + g.next(u64::from(width) + 4) as u32).max(lo);
            let orders: Vec<AuctionOrder> = (0..g.next(14))
                .map(|k| AuctionOrder {
                    side: if g.next(2) == 0 {
                        Side::Buy
                    } else {
                        Side::Sell
                    },
                    tick: Tick(lo.0 + g.next(u64::from(width)) as u32),
                    key: u128::from(g.next(1_000)) << 8 | k as u128,
                    remaining: Qty(1 + g.next(6) as u32),
                })
                .collect();
            let w = width as usize;
            let (mut buy, mut sell) = (vec![0u64; w], vec![0u64; w]);
            for o in &orders {
                let i = (o.tick.0 - lo.0) as usize;
                match o.side {
                    Side::Buy => buy[i] += u64::from(o.remaining.0),
                    Side::Sell => sell[i] += u64::from(o.remaining.0),
                }
            }
            // Oracle p*.
            let dem = |t: u32| {
                orders
                    .iter()
                    .filter(|o| o.side == Side::Buy && o.tick.0 >= t)
                    .map(|o| u64::from(o.remaining.0))
                    .sum::<u64>()
            };
            let sup = |t: u32| {
                orders
                    .iter()
                    .filter(|o| o.side == Side::Sell && o.tick.0 <= t)
                    .map(|o| u64::from(o.remaining.0))
                    .sum::<u64>()
            };
            let mut cands: Vec<u32> = (lo.0..lo.0 + width).collect();
            let vmax = cands.iter().map(|&t| dem(t).min(sup(t))).max().unwrap_or(0);
            let got = uncross(&buy, &sell, lo, reference);
            if vmax == 0 {
                assert_eq!(got, None);
                continue;
            }
            cands.retain(|&t| dem(t).min(sup(t)) == vmax);
            let imin = cands
                .iter()
                .map(|&t| (i128::from(dem(t)) - i128::from(sup(t))).unsigned_abs())
                .min()
                .unwrap_or(0);
            cands.retain(|&t| (i128::from(dem(t)) - i128::from(sup(t))).unsigned_abs() == imin);
            let rmin = cands
                .iter()
                .map(|&t| t.abs_diff(reference.0))
                .min()
                .unwrap_or(0);
            cands.retain(|&t| t.abs_diff(reference.0) == rmin);
            let p = cands[0];
            let c = got.unwrap_or_else(|| panic!("oracle crosses at {p}"));
            assert_eq!((c.p, c.v), (Tick(p), vmax));
            // Oracle allocation: each side in price-then-key order until V.
            let mut want = vec![0u32; orders.len()];
            for side in [Side::Buy, Side::Sell] {
                let mut idx: Vec<usize> = (0..orders.len())
                    .filter(|&k| {
                        orders[k].side == side
                            && if side == Side::Buy {
                                orders[k].tick.0 >= p
                            } else {
                                orders[k].tick.0 <= p
                            }
                    })
                    .collect();
                idx.sort_by_key(|&k| {
                    let t = orders[k].tick.0;
                    (
                        if side == Side::Buy { u32::MAX - t } else { t },
                        orders[k].key,
                    )
                });
                let mut left = vmax;
                for k in idx {
                    let q = u64::from(orders[k].remaining.0).min(left);
                    want[k] = q as u32;
                    left -= q;
                }
            }
            let side = c.rationed();
            let at_pm: Vec<(u128, Qty)> = {
                let mut v: Vec<_> = orders
                    .iter()
                    .filter(|o| Some(o.side) == side && o.tick == c.p_m)
                    .map(|o| (o.key, o.remaining))
                    .collect();
                v.sort();
                v
            };
            let u = UncrossRecord::new(
                &c,
                marginal(at_pm, c.q_rem),
                reference,
                &Band {
                    lo,
                    hi: Tick(lo.0 + width - 1),
                },
            );
            let (mut fb, mut fs) = (0u64, 0u64);
            for (k, o) in orders.iter().enumerate() {
                let f = auction_fill(o, &u);
                assert_eq!(f.0, want[k], "order {k} {o:?} {c:?}");
                match o.side {
                    Side::Buy => fb += u64::from(f.0),
                    Side::Sell => fs += u64::from(f.0),
                }
            }
            assert_eq!((fb, fs), (vmax, vmax));
            // Lemma 3: the residual book is uncrossed.
            let rest = |s: Side| {
                orders
                    .iter()
                    .zip(&want)
                    .filter(move |(o, f)| o.side == s && o.remaining.0 > **f)
                    .map(|(o, _)| o.tick)
            };
            if let (Some(bb), Some(ba)) = (rest(Side::Buy).max(), rest(Side::Sell).min()) {
                assert!(bb < ba, "residual crossed: {bb:?} ≥ {ba:?}");
            }
        }
    }
}
