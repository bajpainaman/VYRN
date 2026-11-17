//! The deterministic workload generator (02 §6, 11 §7.1 rule 4).
//!
//! `Generator::new(config, seed)` is a pure function of its inputs: it yields the same packets,
//! byte for byte, on every build and target (B4). It uses integer arithmetic only (see
//! [`crate::fixed`] and [`crate::rng`]); no clock, no environment, no hash-ordered container.
//!
//! What it does not do: it has no `vyrn-md` feed and no sequencer counters, so the model book is
//! the fixed BBO of [`crate::config::BookModel`], and the mix controller of 02 §6.10 and the lane
//! pacer of 02 §6.9 belong to the rig that sends the packets. Handles are placeholders (see
//! [`Generator`]).
#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss
)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::fmt;

use vyrn_crypto::hash::derive_key;
use vyrn_types::{BookId, Handle, LaneId, MAX_REQ_PAYLOAD, Qty, SessionId, Tick};
use vyrn_wire::{Msg, OrderFlags, ReqHeader, Side, Stp, Tif, encode_request, session_id};

use crate::config::{
    Auction, Class, ClassKind, Config, ConfigError, Cross, Dist, LifetimeRow,
    MAX_SESSIONS_PER_LANE, Mode, PPM, Packets, Placement, Skew, Sweep, invalid,
};
use crate::fixed::{exp2_q32, log_uniform, log2_q32, neg_ln_q32};
use crate::rng::Xoshiro256;

const PS_PER_NS: u64 = 1_000;
/// Caps a Geometric draw so that a tiny `p` cannot loop for long.
const GEOM_MAX: u64 = 4_096;
/// `derive_key` contexts of the bench MAC keys. These keys exist only for generated traffic.
const CTX_K_SEQ: &str = "vyrn-bench v1 gen k_seq";
const CTX_K_COM: &str = "vyrn-bench v1 gen k_com";

/// What a message was meant to be. A `Reduce` of a one-lot order is sent, and counted, as `Cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgKind {
    Join,
    Replace,
    Cancel,
    Reduce,
    Improve,
    Cross,
}

impl MsgKind {
    pub const ALL: [Self; 6] = [
        Self::Join,
        Self::Replace,
        Self::Cancel,
        Self::Reduce,
        Self::Improve,
        Self::Cross,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Replace => "replace",
            Self::Cancel => "cancel",
            Self::Reduce => "reduce",
            Self::Improve => "improve",
            Self::Cross => "cross",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Join => 0,
            Self::Replace => 1,
            Self::Cancel => 2,
            Self::Reduce => 3,
            Self::Improve => 4,
            Self::Cross => 5,
        }
    }
}

/// Counts over a run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    pub msgs: u64,
    pub bytes: u64,
    pub by_kind: [u64; 6],
    pub by_class: [u64; 3],
    pub last_send_ns: u64,
}

impl Stats {
    pub fn kind(&self, k: MsgKind) -> u64 {
        self.by_kind.get(k.index()).copied().unwrap_or(0)
    }

    /// Share of all messages in ppm (integer, truncated).
    pub fn share_ppm(&self, n: u64) -> u64 {
        if self.msgs == 0 {
            return 0;
        }
        u64::try_from(u128::from(n) * u128::from(PPM) / u128::from(self.msgs)).unwrap_or(0)
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "packets {} msgs {} bytes {} last_send_ns {}",
            self.packets, self.msgs, self.bytes, self.last_send_ns
        )?;
        for k in MsgKind::ALL {
            writeln!(
                f,
                "  {:<8} {:>12} {:>7} ppm",
                k.name(),
                self.kind(k),
                self.share_ppm(self.kind(k))
            )?;
        }
        for (name, n) in ["mm", "tk", "rt"].iter().zip(self.by_class) {
            writeln!(f, "  class {name} {n} msgs {} ppm", self.share_ppm(n))?;
        }
        Ok(())
    }
}

/// Options that are not part of the config.
#[derive(Clone, Copy, Debug)]
pub struct GenOptions {
    /// `run_seed` (02 §6.2).
    pub seed: u64,
    /// Replaces `rate_msgs_per_s`.
    pub rate_override: Option<u64>,
}

/// One request packet and when to send it.
#[derive(Clone, Debug)]
pub struct Packet {
    pub send_ns: u64,
    pub lane: LaneId,
    pub class: ClassKind,
    len: usize,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Packet {
    /// The wire bytes: header, messages and both tags.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

// ----- integer distributions -----

fn geometric(rng: &mut Xoshiro256, p_ppm: u32, cap: u64) -> u64 {
    let mut g = 0;
    while g < cap && !rng.chance_ppm(p_ppm) {
        g += 1;
    }
    g
}

/// ps between events of a Poisson process of `uhz` µHz, from an Exp(1) draw `e` in Q32.
fn gap_ps(e: u64, uhz: u64) -> u64 {
    let den = u128::from(uhz.max(1)) << 32;
    u64::try_from(u128::from(e) * 1_000_000_000_000_000_000 / den).unwrap_or(u64::MAX)
}

// ----- the model of 02 §6.4–§6.7 -----

struct Tables {
    bid: u32,
    ask: u32,
    mid: u32,
    depth: u64,
    spread: u32,
    join: Vec<Dist>,
    join_w: Vec<u64>,
    sweeps: Vec<Sweep>,
    sweep_w: Vec<u64>,
    life: Vec<LifetimeRow>,
    life_w: Vec<u64>,
    replace_ppm: u32,
    cross: Cross,
    auction: Option<Auction>,
}

fn pick(rng: &mut Xoshiro256, weights: &[u64]) -> usize {
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return 0;
    }
    let mut r = rng.below(total);
    for (i, &w) in weights.iter().enumerate() {
        if r < w {
            return i;
        }
        r -= w;
    }
    weights.len().saturating_sub(1)
}

fn tick32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl Tables {
    fn new(cfg: &Config) -> Self {
        let b = cfg.book_model;
        let bid = b.mid_tick - b.spread_ticks / 2;
        Self {
            bid,
            ask: bid + b.spread_ticks,
            mid: b.mid_tick,
            depth: u64::from(b.depth_lots),
            spread: b.spread_ticks,
            join_w: cfg
                .join_distance
                .iter()
                .map(|d| u64::from(d.ppm()))
                .collect(),
            join: cfg.join_distance.clone(),
            sweep_w: cfg.cross_levels.iter().map(|s| u64::from(s.ppm)).collect(),
            sweeps: cfg.cross_levels.clone(),
            life_w: cfg.lifetimes.row.iter().map(|r| u64::from(r.ppm)).collect(),
            life: cfg.lifetimes.row.clone(),
            replace_ppm: cfg.lifetimes.replace_ppm,
            cross: cfg.cross,
            auction: cfg.auction,
        }
    }

    /// Ticks behind the own side's best (02 §6.5).
    fn distance(&self, rng: &mut Xoshiro256) -> u64 {
        let i = pick(rng, &self.join_w);
        match self.join.get(i).copied() {
            Some(Dist::Fixed { d, .. }) => d,
            Some(Dist::Geometric {
                base, cap, p_ppm, ..
            }) => base.saturating_add(geometric(rng, p_ppm, cap)),
            Some(Dist::LogUniform { lo, hi, .. }) => log_uniform(lo, hi, rng.next_u64()),
            Some(Dist::Uniform { base, span, .. }) => base.saturating_add(rng.below(span)),
            None => 0,
        }
    }

    fn join_tick(&self, side: Side, d: u64) -> u32 {
        match side {
            Side::Buy => self.bid.saturating_sub(tick32(d)).max(1),
            Side::Sell => self.ask.saturating_add(tick32(d)),
        }
    }

    /// An auction order: behind the reference by `d`, or through it (02 §6.1 `WL-AUCTION`).
    fn auction_tick(&self, side: Side, d: u64, through: bool) -> u32 {
        let up = (side == Side::Buy) == through;
        if up {
            self.mid.saturating_add(tick32(d))
        } else {
            self.mid.saturating_sub(tick32(d)).max(1)
        }
    }

    fn lifetime_ps(&self, rng: &mut Xoshiro256) -> u64 {
        let i = pick(rng, &self.life_w);
        let ns = self
            .life
            .get(i)
            .map_or(0, |r| log_uniform(r.lo_ns, r.hi_ns, rng.next_u64()));
        ns.saturating_mul(PS_PER_NS)
    }
}

fn random_side(rng: &mut Xoshiro256) -> Side {
    if rng.below(2) == 0 {
        Side::Buy
    } else {
        Side::Sell
    }
}

// ----- sessions and their live orders -----

struct Order {
    side: Side,
    qty: u32,
    end_ps: u64,
    near_pos: Option<usize>,
}

/// The orders a session believes are live: by handle slot, by drawn end time, and the ones within
/// 3 ticks of the touch (`Reduce` picks among those, 02 §6.6).
#[derive(Default)]
struct Orders {
    by_slot: BTreeMap<u32, Order>,
    by_end: BTreeSet<(u64, u32)>,
    near: Vec<u32>,
}

impl Orders {
    fn len(&self) -> usize {
        self.by_slot.len()
    }

    fn insert(&mut self, slot: u32, mut o: Order, d: u64) {
        if d <= 3 {
            o.near_pos = Some(self.near.len());
            self.near.push(slot);
        }
        self.by_end.insert((o.end_ps, slot));
        self.by_slot.insert(slot, o);
    }

    fn remove(&mut self, slot: u32) -> Option<Order> {
        let o = self.by_slot.remove(&slot)?;
        self.by_end.remove(&(o.end_ps, slot));
        if let Some(pos) = o.near_pos {
            self.near.swap_remove(pos);
            if let Some(moved) = self.near.get(pos).copied()
                && let Some(m) = self.by_slot.get_mut(&moved)
            {
                m.near_pos = Some(pos);
            }
        }
        Some(o)
    }

    /// The order whose drawn lifetime ends first.
    fn oldest(&self) -> Option<u32> {
        self.by_end.first().map(|&(_, slot)| slot)
    }
}

struct Session {
    id: SessionId,
    lane: LaneId,
    class: usize,
    rng: Xoshiro256,
    pkt_seq: u32,
    next_serial: u32,
    next_tag: u32,
    k_seq: [u8; 16],
    k_com: Option<[u8; 16]>,
    /// Packets per second ×10⁶ of each stream: 0 bundles or all messages, 1 urgent packets.
    rate_uhz: [u64; 2],
    orders: Orders,
}

impl Session {
    /// A handle slot: 1 … 0xFF_FFFE (slot 0xFF_FFFF is never a real handle, 04 §6.1), skipping
    /// slots of live orders.
    fn serial(&mut self) -> u32 {
        loop {
            let s = self.next_serial;
            self.next_serial = if s >= 0xFF_FFFE { 1 } else { s + 1 };
            if !self.orders.by_slot.contains_key(&s) {
                return s;
            }
        }
    }

    fn tag(&mut self) -> u32 {
        let t = self.next_tag;
        self.next_tag = t.wrapping_add(1);
        t
    }
}

fn handle(slot: u32) -> Handle {
    Handle::new(slot, 0).unwrap_or_default()
}

/// Per-class constants derived from the config.
struct ClassRt {
    kind: ClassKind,
    packets: Packets,
    qty_p_ppm: u32,
    stp: Stp,
    bursty: bool,
    max_live: usize,
    /// Weights over [Join, Cancel, Reduce, Improve, Cross] per stream.
    weights: [[u64; 5]; 2],
}

impl ClassRt {
    fn new(c: &Class) -> Self {
        let m = c.mix;
        let [j, ca, r, i, x] = [m.join, m.cancel, m.reduce, m.improve, m.cross].map(u64::from);
        let weights = match c.packets {
            Packets::Bundled {
                urgent_cancel_ppm, ..
            } => {
                let cancel_b = ca * (PPM - u64::from(urgent_cancel_ppm)) / PPM;
                [[j, cancel_b, r, 0, 0], [0, ca - cancel_b, 0, i, x]]
            }
            Packets::Single { .. } => [[j, ca, r, i, x], [0; 5]],
        };
        Self {
            kind: c.kind,
            packets: c.packets,
            qty_p_ppm: c.qty_p_ppm,
            stp: if c.stp_cancel_newest {
                Stp::CancelNewest
            } else {
                Stp::None
            },
            bursty: c.bursty,
            max_live: usize::try_from(c.max_live_orders).unwrap_or(usize::MAX),
            weights,
        }
    }
}

fn draw_kind(rng: &mut Xoshiro256, mut w: [u64; 5], cross_scale_ppm: u64) -> MsgKind {
    w[4] = w[4] * cross_scale_ppm / PPM;
    match pick(rng, &w) {
        1 => MsgKind::Cancel,
        2 => MsgKind::Reduce,
        3 => MsgKind::Improve,
        4 => MsgKind::Cross,
        _ => MsgKind::Join,
    }
}

fn flags(side: Side, tif: Tif, post_only: bool, stp: Stp) -> OrderFlags {
    OrderFlags {
        side,
        tif,
        post_only,
        stp,
    }
}

fn quantity(rng: &mut Xoshiro256, p_ppm: u32) -> u32 {
    tick32(1 + geometric(rng, p_ppm, GEOM_MAX))
}

fn cancel_oldest(s: &mut Session) -> Option<Msg> {
    let slot = s.orders.oldest()?;
    s.orders.remove(slot)?;
    Some(Msg::Cancel {
        handle: handle(slot),
        client_tag: s.tag(),
    })
}

/// Builds one message of `kind`, falling back to a join when the session has nothing live to act
/// on (the controller of 02 §6.10 compensates in a real run), and to a cancel at the live cap.
fn make_msg(
    t: &Tables,
    cl: &ClassRt,
    s: &mut Session,
    kind: MsgKind,
    now_ps: u64,
) -> (Msg, MsgKind) {
    let mut kind = kind;
    if matches!(kind, MsgKind::Join | MsgKind::Improve) && s.orders.len() >= cl.max_live {
        kind = MsgKind::Cancel;
    }
    if kind == MsgKind::Cancel && s.orders.by_slot.is_empty() {
        kind = MsgKind::Join;
    }
    if kind == MsgKind::Reduce && s.orders.near.is_empty() {
        kind = MsgKind::Join;
    }
    if kind == MsgKind::Join
        && t.auction.is_none()
        && !s.orders.by_slot.is_empty()
        && s.rng.chance_ppm(t.replace_ppm)
    {
        kind = MsgKind::Replace;
    }
    match kind {
        MsgKind::Cancel => {
            if let Some(m) = cancel_oldest(s) {
                return (m, MsgKind::Cancel);
            }
        }
        MsgKind::Reduce => {
            let pick = tick32(s.rng.below(u64::try_from(s.orders.near.len()).unwrap_or(1)));
            let slot = s
                .orders
                .near
                .get(usize::try_from(pick).unwrap_or(0))
                .copied();
            if let Some(slot) = slot
                && let Some(o) = s.orders.by_slot.get_mut(&slot)
            {
                if o.qty < 2 {
                    s.orders.remove(slot);
                    return (
                        Msg::Cancel {
                            handle: handle(slot),
                            client_tag: s.tag(),
                        },
                        MsgKind::Cancel,
                    );
                }
                let by = o.qty / 2;
                o.qty -= by;
                return (
                    Msg::Reduce {
                        handle: handle(slot),
                        by: Qty(by),
                        client_tag: s.tag(),
                    },
                    MsgKind::Reduce,
                );
            }
        }
        MsgKind::Replace => {
            if let Some(old) = s.orders.oldest()
                && let Some(o) = s.orders.remove(old)
            {
                let d = t.distance(&mut s.rng);
                let tick = t.join_tick(o.side, d);
                let qty = quantity(&mut s.rng, cl.qty_p_ppm);
                let end = now_ps.saturating_add(t.lifetime_ps(&mut s.rng));
                let slot = s.serial();
                s.orders.insert(
                    slot,
                    Order {
                        side: o.side,
                        qty,
                        end_ps: end,
                        near_pos: None,
                    },
                    d,
                );
                return (
                    Msg::Replace {
                        flags: flags(o.side, Tif::Day, false, cl.stp),
                        handle: handle(old),
                        tick: Tick(tick),
                        qty: Qty(qty),
                    },
                    MsgKind::Replace,
                );
            }
        }
        MsgKind::Improve => {
            let side = random_side(&mut s.rng);
            // With a spread under 2 ticks there is nothing to improve: join at d = 0.
            let tick = if t.spread >= 2 {
                match side {
                    Side::Buy => t.bid + 1,
                    Side::Sell => t.ask - 1,
                }
            } else {
                t.join_tick(side, 0)
            };
            let qty = quantity(&mut s.rng, cl.qty_p_ppm);
            let end = now_ps.saturating_add(t.lifetime_ps(&mut s.rng));
            let slot = s.serial();
            s.orders.insert(
                slot,
                Order {
                    side,
                    qty,
                    end_ps: end,
                    near_pos: None,
                },
                0,
            );
            return (
                Msg::New {
                    flags: flags(side, Tif::Day, true, cl.stp),
                    tick: Tick(tick),
                    qty: Qty(qty),
                    client_tag: s.tag(),
                },
                MsgKind::Improve,
            );
        }
        MsgKind::Cross => return (make_cross(t, cl, s), MsgKind::Cross),
        MsgKind::Join => {}
    }
    (make_join(t, cl, s, now_ps), MsgKind::Join)
}

fn make_join(t: &Tables, cl: &ClassRt, s: &mut Session, now_ps: u64) -> Msg {
    let side = random_side(&mut s.rng);
    let d = t.distance(&mut s.rng);
    let (tick, tif) = match t.auction {
        Some(a) => {
            let through = s.rng.chance_ppm(a.through_ppm);
            (t.auction_tick(side, d, through), Tif::AuctionOnly)
        }
        None => (t.join_tick(side, d), Tif::Day),
    };
    let qty = quantity(&mut s.rng, cl.qty_p_ppm);
    let end = now_ps.saturating_add(t.lifetime_ps(&mut s.rng));
    let slot = s.serial();
    s.orders.insert(
        slot,
        Order {
            side,
            qty,
            end_ps: end,
            near_pos: None,
        },
        d,
    );
    Msg::New {
        flags: flags(side, tif, false, cl.stp),
        tick: Tick(tick),
        qty: Qty(qty),
        client_tag: s.tag(),
    }
}

/// A taker order sweeping `k` levels of the model book (02 §6.5). It is not tracked as live: a
/// day residual rests, but the generator cannot see whether it did.
fn make_cross(t: &Tables, cl: &ClassRt, s: &mut Session) -> Msg {
    let side = random_side(&mut s.rng);
    let k = {
        let i = pick(&mut s.rng, &t.sweep_w);
        t.sweeps
            .get(i)
            .map_or(1, |sw| s.rng.range(u64::from(sw.lo), u64::from(sw.hi)))
    };
    let reach = tick32(k - 1);
    let tick = match side {
        Side::Buy => t.ask.saturating_add(reach),
        Side::Sell => t.bid.saturating_sub(reach).max(1),
    };
    let depth = u128::from(t.depth) * u128::from(k);
    let frac = 500_000 + u128::from(s.rng.below(500_001));
    let mut qty = (depth * frac / u128::from(PPM)).max(1);
    let tif_w = [
        u64::from(t.cross.ioc_ppm),
        u64::from(t.cross.day_ppm),
        u64::from(t.cross.fok_ppm),
    ];
    let tif = match pick(&mut s.rng, &tif_w) {
        0 => Tif::Ioc,
        1 => Tif::Day,
        _ => Tif::Fok,
    };
    if tif == Tif::Day && s.rng.chance_ppm(t.cross.through_ppm) {
        qty = depth * u128::from(t.cross.through_qty_pct) / 100;
    }
    Msg::New {
        flags: flags(side, tif, false, cl.stp),
        tick: Tick(tick),
        qty: Qty(u32::try_from(qty.max(1)).unwrap_or(u32::MAX)),
        client_tag: s.tag(),
    }
}

// ----- time: phases and bursts -----

/// Global burst windows, generated lazily from their own stream so that no session's draws depend
/// on how far ahead they were generated.
struct Bursts {
    rng: Xoshiro256,
    rate_uhz: u64,
    window_ps: u64,
    cursor: u64,
    wins: VecDeque<(u64, u64)>,
}

impl Bursts {
    /// Generates windows until one starts after `t`.
    fn extend(&mut self, t: u64) {
        while self.wins.back().is_none_or(|w| w.0 <= t) {
            let e = neg_ln_q32(self.rng.next_u64());
            let start = self.cursor.saturating_add(gap_ps(e, self.rate_uhz));
            let end = start.saturating_add(self.window_ps);
            self.cursor = start;
            match self.wins.back_mut() {
                Some(b) if start <= b.1 => b.1 = b.1.max(end),
                _ => self.wins.push_back((start, end)),
            }
        }
    }

    /// Whether `t` is in a burst, and when that changes.
    fn at(&self, t: u64) -> (bool, u64) {
        for &(s, e) in &self.wins {
            if e > t {
                return if s <= t { (true, e) } else { (false, s) };
            }
        }
        (false, u64::MAX)
    }

    fn prune(&mut self, floor: u64) {
        while self.wins.front().is_some_and(|w| w.1 <= floor) {
            self.wins.pop_front();
        }
    }
}

struct Timeline {
    ends_ps: Vec<u64>,
    rate_ppm: Vec<u64>,
    cross_ppm: Vec<u64>,
    end_ps: u64,
    bursts: Option<Bursts>,
    burst_mult_ppm: u64,
    base_scale_ppm: u64,
}

impl Timeline {
    fn new(cfg: &Config, seed: u64) -> Self {
        let mut acc = 0u64;
        let mut ends_ps = Vec::new();
        for p in &cfg.phase {
            acc = acc.saturating_add(p.duration_ns.saturating_mul(PS_PER_NS));
            ends_ps.push(acc);
        }
        let b = cfg.burst;
        Self {
            ends_ps,
            rate_ppm: cfg.phase.iter().map(|p| u64::from(p.rate_ppm)).collect(),
            cross_ppm: cfg
                .phase
                .iter()
                .map(|p| u64::from(p.cross_scale_ppm))
                .collect(),
            end_ps: acc,
            bursts: (b.rate_per_s > 0).then(|| Bursts {
                rng: Xoshiro256::for_global(seed),
                rate_uhz: u64::from(b.rate_per_s) * 1_000_000,
                window_ps: b.window_ns.saturating_mul(PS_PER_NS),
                cursor: 0,
                wins: VecDeque::new(),
            }),
            burst_mult_ppm: u64::from(b.mult_ppm),
            base_scale_ppm: u64::from(b.base_scale_ppm),
        }
    }

    fn phase_at(&self, t: u64) -> usize {
        self.ends_ps.partition_point(|&e| e <= t)
    }

    /// The next event of a Poisson process of `uhz` after `t`, whose rate changes at phase and
    /// burst edges. Memorylessness lets a draw that crosses an edge restart there. `None` at the
    /// end of the run.
    fn next_arrival(
        &mut self,
        mut t: u64,
        uhz: u64,
        bursty: bool,
        rng: &mut Xoshiro256,
    ) -> Option<u64> {
        loop {
            if t >= self.end_ps {
                return None;
            }
            let ph = self.phase_at(t);
            let mut bound = self.ends_ps.get(ph).copied().unwrap_or(self.end_ps);
            let mut rate =
                u128::from(uhz) * u128::from(self.rate_ppm.get(ph).copied().unwrap_or(0));
            let mut div = u128::from(PPM);
            if bursty {
                rate *= u128::from(self.base_scale_ppm);
                div *= u128::from(PPM);
                if let Some(b) = self.bursts.as_mut() {
                    b.extend(t);
                    let (inside, edge) = b.at(t);
                    if inside {
                        rate *= u128::from(self.burst_mult_ppm);
                        div *= u128::from(PPM);
                    }
                    bound = bound.min(edge);
                }
            }
            let rate = u64::try_from(rate / div).unwrap_or(u64::MAX);
            if rate > 0 {
                let e = neg_ln_q32(rng.next_u64());
                let next = t.saturating_add(gap_ps(e, rate));
                if next < bound {
                    return Some(next);
                }
            }
            t = bound;
        }
    }
}

// ----- the population -----

struct Planned {
    class: usize,
    lane: u8,
    slot: u16,
    rate_uhz: u64,
}

/// Rank weights of a skew: 2^40 for rank 1 under Zipf, so that integer division keeps ~30 bits.
fn weights(skew: Skew, n: usize) -> Vec<u64> {
    (1..=n)
        .map(|r| match skew {
            Skew::Equal => 1,
            Skew::Zipf { s_milli } => {
                let e = (40u64 << 32).saturating_sub(
                    u64::from(s_milli) * log2_q32(u64::try_from(r).unwrap_or(1)) / 1000,
                );
                u64::try_from(exp2_q32(e) >> 32).unwrap_or(u64::MAX)
            }
        })
        .collect()
}

/// Splits a class's rate over `n` sessions by `skew`; units are µHz of messages.
fn session_rates(class_uhz: u128, skew: Skew, n: usize) -> Vec<u64> {
    let w = weights(skew, n);
    let total: u128 = w.iter().map(|&x| u128::from(x)).sum::<u128>().max(1);
    w.iter()
        .map(|&x| u64::try_from(class_uhz * u128::from(x) / total).unwrap_or(u64::MAX))
        .collect()
}

fn plan_population(cfg: &Config, rate_msgs_per_s: u64) -> Result<Vec<Planned>, ConfigError> {
    let mut out = Vec::new();
    let mut pooled: Vec<(usize, u128, u64, usize)> = Vec::new(); // (class, cross µHz, msg µHz, rank)
    for (ci, c) in cfg.class.iter().enumerate() {
        let class_uhz = u128::from(rate_msgs_per_s) * u128::from(c.mix.total());
        match c.placement {
            Placement::Dedicated {
                lane_first,
                lane_count,
                sessions_per_lane,
            } => {
                let spl = usize::try_from(sessions_per_lane).unwrap_or(0);
                let n = spl * usize::from(lane_count);
                let rates = session_rates(class_uhz, c.skew, n);
                for (i, rate_uhz) in rates.into_iter().enumerate() {
                    out.push(Planned {
                        class: ci,
                        lane: lane_first + u8::try_from(i / spl).unwrap_or(0),
                        slot: u16::try_from(i % spl).unwrap_or(0),
                        rate_uhz,
                    });
                }
            }
            Placement::Pooled { sessions } => {
                let n = usize::try_from(sessions).unwrap_or(0);
                for (rank, rate_uhz) in session_rates(class_uhz, c.skew, n).into_iter().enumerate()
                {
                    let cross =
                        u128::from(rate_uhz) * u128::from(c.mix.cross) / u128::from(c.mix.total());
                    pooled.push((ci, cross, rate_uhz, rank));
                }
            }
        }
    }
    if let Some(pool) = cfg.pool.filter(|_| !pooled.is_empty()) {
        // 02 §6.10: sort by expected cross rate, descending; give each session to the pool lane
        // with the smallest cross rate so far (ties: smaller message rate, then lower lane).
        pooled.sort_by_key(|&(ci, cross, _, rank)| (Reverse(cross), ci, rank));
        let n = usize::from(pool.lanes);
        let mut load = vec![(0u128, 0u128, 0u32); n]; // (cross, rate, sessions)
        for (ci, cross, rate_uhz, _) in pooled {
            // A lane at its slot limit is skipped (WL-SESS fills the pool exactly).
            let Some((lane, _)) = load
                .iter()
                .enumerate()
                .filter(|&(_, &(_, _, n))| n < MAX_SESSIONS_PER_LANE)
                .min_by_key(|&(i, &(c, r, _))| (c, r, i))
            else {
                return invalid("the pool holds more sessions than its lanes have slots");
            };
            let Some(l) = load.get_mut(lane) else { break };
            out.push(Planned {
                class: ci,
                lane: pool.first_lane + u8::try_from(lane).unwrap_or(0),
                slot: u16::try_from(l.2).unwrap_or(0),
                rate_uhz,
            });
            l.0 += cross;
            l.1 += u128::from(rate_uhz);
            l.2 += 1;
        }
    }
    Ok(out)
}

/// Packets per second ×10⁶ of a session's two streams (02 §6.8).
fn stream_rates(c: &Class, msg_uhz: u64) -> [u64; 2] {
    let total = c.mix.total();
    let part = |n: u64| {
        u64::try_from(u128::from(msg_uhz) * u128::from(n) / u128::from(total)).unwrap_or(0)
    };
    let per_packet = |uhz: u64, two_ppm: u32| {
        u64::try_from(u128::from(uhz) * u128::from(PPM) / (u128::from(PPM) + u128::from(two_ppm)))
            .unwrap_or(0)
    };
    match c.packets {
        Packets::Single { two_ppm } => [per_packet(msg_uhz, two_ppm), 0],
        Packets::Bundled {
            bundle_size,
            urgent_cancel_ppm,
            urgent_two_ppm,
        } => {
            let cancel_b = u64::from(c.mix.cancel) * (PPM - u64::from(urgent_cancel_ppm)) / PPM;
            let bundle_msgs = part(u64::from(c.mix.join) + cancel_b + u64::from(c.mix.reduce));
            let urgent_msgs = msg_uhz.saturating_sub(bundle_msgs);
            [
                bundle_msgs / u64::from(bundle_size),
                per_packet(urgent_msgs, urgent_two_ppm),
            ]
        }
    }
}

/// MAC keys of a generated session. Test keys: anyone with the seed can derive them.
pub fn session_keys(seed: u64, session: SessionId, mode: Mode) -> ([u8; 16], Option<[u8; 16]>) {
    let mut material = [0u8; 12];
    let (a, b) = material.split_at_mut(8);
    a.copy_from_slice(&seed.to_le_bytes());
    b.copy_from_slice(&session.0.to_le_bytes());
    let k = |ctx: &str| {
        derive_key(ctx, &material)
            .first_chunk::<16>()
            .copied()
            .unwrap_or_default()
    };
    (k(CTX_K_SEQ), (mode == Mode::Chain).then(|| k(CTX_K_COM)))
}

// ----- the generator -----

/// An iterator of request packets in send order.
///
/// **Handles are placeholders.** The lane assigns the real `Handle` of an order when it accepts the
/// `New`, and a client learns it from the `Ack`. The generator has no responses, so it numbers a
/// session's orders 1, 2, 3 … in the handle's slot bits (generation 0). A rig that sends these
/// packets against a live sequencer must map them to the real handles and re-MAC the packets.
pub struct Generator {
    tables: Tables,
    classes: Vec<ClassRt>,
    sessions: Vec<Session>,
    timeline: Timeline,
    heap: BinaryHeap<Reverse<(u64, u32, u8, usize)>>,
    msgs: Vec<Msg>,
    book: BookId,
    epoch16: u16,
    stats: Stats,
}

impl Generator {
    pub fn new(cfg: &Config, opts: &GenOptions) -> Result<Self, ConfigError> {
        cfg.validate()?;
        let rate = opts.rate_override.unwrap_or(cfg.rate_msgs_per_s);
        if rate == 0 {
            return invalid("rate is 0");
        }
        let classes: Vec<ClassRt> = cfg.class.iter().map(ClassRt::new).collect();
        let mut plan = plan_population(cfg, rate)?;
        plan.retain(|p| {
            cfg.class.get(p.class).is_some_and(|c| c.enabled)
                && cfg.lane.is_none_or(|l| l == p.lane)
        });
        let mut timeline = Timeline::new(cfg, opts.seed);
        let mut sessions = Vec::with_capacity(plan.len());
        let mut heap = BinaryHeap::new();
        for p in plan {
            let Some(c) = cfg.class.get(p.class) else {
                continue;
            };
            let Some(id) = session_id(p.slot, LaneId(p.lane), 0) else {
                return invalid("a session slot does not fit in 12 bits");
            };
            let (k_seq, k_com) = session_keys(opts.seed, id, cfg.mode);
            let mut s = Session {
                id,
                lane: LaneId(p.lane),
                class: p.class,
                rng: Xoshiro256::for_session(opts.seed, id.0),
                pkt_seq: 1,
                next_serial: 1,
                next_tag: 1,
                k_seq,
                k_com,
                rate_uhz: stream_rates(c, p.rate_uhz),
                orders: Orders::default(),
            };
            let idx = sessions.len();
            for (stream, uhz) in s.rate_uhz.into_iter().enumerate() {
                if uhz == 0 {
                    continue;
                }
                if let Some(t) = timeline.next_arrival(0, uhz, c.bursty, &mut s.rng) {
                    heap.push(Reverse((t, id.0, u8::try_from(stream).unwrap_or(0), idx)));
                }
            }
            sessions.push(s);
        }
        Ok(Self {
            tables: Tables::new(cfg),
            classes,
            sessions,
            timeline,
            heap,
            msgs: Vec::with_capacity(16),
            book: BookId(cfg.book),
            epoch16: cfg.epoch16,
            stats: Stats::default(),
        })
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Iterator for Generator {
    type Item = Packet;

    fn next(&mut self) -> Option<Packet> {
        let Reverse((t_ps, _, stream, idx)) = self.heap.pop()?;
        if let Some(b) = self.timeline.bursts.as_mut() {
            b.prune(t_ps);
        }
        let ph = self.timeline.phase_at(t_ps);
        let cross_scale = self.timeline.cross_ppm.get(ph).copied().unwrap_or(PPM);
        let s = self.sessions.get_mut(idx)?;
        let cl = self.classes.get(s.class)?;
        let w = cl
            .weights
            .get(usize::from(stream))
            .copied()
            .unwrap_or([0; 5]);
        let n = match (cl.packets, stream) {
            (Packets::Bundled { bundle_size, .. }, 0) => u32::from(bundle_size),
            (
                Packets::Bundled {
                    urgent_two_ppm: two,
                    ..
                }
                | Packets::Single { two_ppm: two },
                _,
            ) => 1 + u32::from(s.rng.chance_ppm(two)),
        };
        self.msgs.clear();
        for _ in 0..n {
            let k = draw_kind(&mut s.rng, w, cross_scale);
            let (m, kind) = make_msg(&self.tables, cl, s, k, t_ps);
            self.stats.by_kind[kind.index()] += 1;
            self.stats.by_class[usize::from(cl.kind.code())] += 1;
            self.msgs.push(m);
        }
        let header = ReqHeader::new(s.id, s.pkt_seq, self.epoch16, self.book, false);
        s.pkt_seq = s.pkt_seq.wrapping_add(1);
        let mut bytes = [0u8; MAX_REQ_PAYLOAD];
        // None only for a message count outside 1..=10, which validation rules out.
        let len = encode_request(&mut bytes, header, &self.msgs, &s.k_seq, s.k_com.as_ref())?;
        let send_ns = t_ps / PS_PER_NS;
        self.stats.packets += 1;
        self.stats.msgs += u64::from(n);
        self.stats.bytes += u64::try_from(len).unwrap_or(0);
        self.stats.last_send_ns = send_ns;
        let uhz = s.rate_uhz.get(usize::from(stream)).copied().unwrap_or(0);
        if let Some(next) = self.timeline.next_arrival(t_ps, uhz, cl.bursty, &mut s.rng) {
            self.heap.push(Reverse((next, s.id.0, stream, idx)));
        }
        Some(Packet {
            send_ns,
            lane: s.lane,
            class: cl.kind,
            len,
            bytes,
        })
    }
}
