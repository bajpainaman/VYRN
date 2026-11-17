//! Workload configs: `bench/workloads/*.toml` (02 §6, 11 §2).
//!
//! A config is data, not code: every number of 02 §6.3–§6.9 that a workload can change is a field
//! here, in integers (probabilities in parts per million, times in ns, rates in msgs/s). Unknown
//! keys are rejected so that a typo cannot silently fall back to a default; `extensions` is the
//! one table a v1 reader ignores. A reader rejects any `version` it does not know.

use serde::Deserialize;
use thiserror::Error;
use vyrn_crypto::hash::hash;
use vyrn_types::MAX_MSGS_PER_PKT;

/// The only config version this crate reads.
pub const CONFIG_VERSION: u32 = 1;
/// Probabilities are integers in parts per million.
pub const PPM: u64 = 1_000_000;
/// Most sessions one lane holds (`MAX_SESSIONS_PER_LANE`, the slot is 12 bits).
pub const MAX_SESSIONS_PER_LANE: u32 = 4_096;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config does not parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config is invalid: {0}")]
    Invalid(String),
}

pub(crate) fn invalid<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Invalid(msg.into()))
}

/// BASE sends one MAC tag; CHAIN also fills `tag_com` (01 §14.19 B).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Base,
    Chain,
}

/// The classes of 02 §6.3. The kind decides nothing by itself; it labels the output.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClassKind {
    Mm,
    Tk,
    Rt,
}

impl ClassKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Mm => 0,
            Self::Tk => 1,
            Self::Rt => 2,
        }
    }
}

/// The offline model book (02 §6.2). Without a `vyrn-md` feed the generator keeps the BBO fixed:
/// best bid = `mid_tick` − `spread_ticks` / 2, best ask = best bid + `spread_ticks`, and every
/// level holds `depth_lots`.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookModel {
    pub mid_tick: u32,
    pub spread_ticks: u32,
    pub depth_lots: u32,
}

/// Global bursts (02 §6.9): Poisson at `rate_per_s`; during `window_ns` the bursty classes send at
/// `mult_ppm` / 10⁶ of their rate. Base rates are scaled by `base_scale_ppm` / 10⁶.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Burst {
    pub rate_per_s: u32,
    pub window_ns: u64,
    pub mult_ppm: u32,
    pub base_scale_ppm: u32,
}

/// One row of 02 §6.7: the lifetime is log-uniform on [`lo_ns`, `hi_ns`].
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifetimeRow {
    pub ppm: u32,
    pub lo_ns: u64,
    pub hi_ns: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifetimes {
    /// Share of join-class messages that are a `Replace` (02 §6.4: 11.5%).
    pub replace_ppm: u32,
    pub row: Vec<LifetimeRow>,
}

/// One row of the join-distance table (02 §6.5).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Dist {
    /// `d` = `d`.
    Fixed { ppm: u32, d: u64 },
    /// `d` = `base` + min(G, `cap`), G ~ Geometric(`p_ppm`) on {0, 1, …}.
    Geometric {
        ppm: u32,
        base: u64,
        cap: u64,
        p_ppm: u32,
    },
    /// `d` log-uniform on [`lo`, `hi` − 1].
    LogUniform { ppm: u32, lo: u64, hi: u64 },
    /// `d` = `base` + uniform on [0, `span`).
    Uniform { ppm: u32, base: u64, span: u64 },
}

impl Dist {
    pub const fn ppm(&self) -> u32 {
        match *self {
            Self::Fixed { ppm, .. }
            | Self::Geometric { ppm, .. }
            | Self::LogUniform { ppm, .. }
            | Self::Uniform { ppm, .. } => ppm,
        }
    }
}

/// A cross sweeps k levels, uniform on [`lo`, `hi`] (02 §6.5).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sweep {
    pub ppm: u32,
    pub lo: u32,
    pub hi: u32,
}

/// Cross time in force and the residual-through-the-touch case (02 §6.5).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cross {
    pub ioc_ppm: u32,
    pub day_ppm: u32,
    pub fok_ppm: u32,
    /// Share of day crosses whose quantity exceeds the swept depth.
    pub through_ppm: u32,
    /// That quantity, in percent of the swept depth (120).
    pub through_qty_pct: u32,
}

/// `WL-AUCTION`: every order is `AUCTION_ONLY`, priced around the model mid (the last trade), and
/// `through_ppm` of them go through it.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auction {
    pub through_ppm: u32,
}

/// Pooled lanes (02 §6.3: lanes 42–48 on `REF`).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub first_lane: u8,
    pub lanes: u8,
}

/// A stretch of the run. `rate_ppm` scales every session's rate; `cross_scale_ppm` scales the
/// weight of `Cross` in every draw (`WL-XSWEEP`; the realized share is in the run's stats).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub duration_ns: u64,
    pub rate_ppm: u32,
    #[serde(default = "full")]
    pub cross_scale_ppm: u32,
}

fn full() -> u32 {
    1_000_000
}

fn yes() -> bool {
    true
}

fn live_cap() -> u32 {
    8_192
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Placement {
    /// `lane_count` lanes from `lane_first`, `sessions_per_lane` sessions on each.
    Dedicated {
        lane_first: u8,
        lane_count: u8,
        sessions_per_lane: u32,
    },
    /// `sessions` sessions spread over the pool (02 §6.10).
    Pooled { sessions: u32 },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Skew {
    /// Every session sends the same rate (MM, and RT).
    Equal,
    /// Session of rank r (from 1) sends in proportion to r^(−`s_milli` / 1000).
    Zipf { s_milli: u32 },
}

/// Share of all messages, in ppm, per type (02 §6.4). A `Replace` counts as a join.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mix {
    pub join: u32,
    pub cancel: u32,
    pub reduce: u32,
    pub improve: u32,
    pub cross: u32,
}

impl Mix {
    pub fn total(&self) -> u64 {
        [
            self.join,
            self.cancel,
            self.reduce,
            self.improve,
            self.cross,
        ]
        .iter()
        .map(|&v| u64::from(v))
        .sum()
    }
}

/// How messages become packets (02 §6.8).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Packets {
    /// Quote bundles of `bundle_size` joins, replaces, reduces and cancels, plus urgent packets
    /// (crosses, improves, and `urgent_cancel_ppm` of cancels) of one message, or two with
    /// probability `urgent_two_ppm`.
    Bundled {
        bundle_size: u8,
        urgent_cancel_ppm: u32,
        urgent_two_ppm: u32,
    },
    /// Every message in a packet of one message, or two with probability `two_ppm`.
    Single { two_ppm: u32 },
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Class {
    pub kind: ClassKind,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub placement: Placement,
    pub skew: Skew,
    pub mix: Mix,
    /// Quantity is 1 + Geometric(`qty_p_ppm`) lots (02 §6.6).
    pub qty_p_ppm: u32,
    /// STP "cancel newest" on every order (02 §6.4: MM).
    #[serde(default)]
    pub stp_cancel_newest: bool,
    /// Takes part in bursts (02 §6.9: MM and TK).
    #[serde(default)]
    pub bursty: bool,
    /// A session at this many live orders sends a cancel in place of a join or improve.
    #[serde(default = "live_cap")]
    pub max_live_orders: u32,
    pub packets: Packets,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub book: u16,
    #[serde(default)]
    pub epoch16: u16,
    /// Full-rate target over all classes (02 §6.1: `WL-REF` states a rate, default 10⁹).
    pub rate_msgs_per_s: u64,
    /// Keep only the sessions of this lane (`WL-LANE`). Rates stay those of the full population.
    pub lane: Option<u8>,
    pub book_model: BookModel,
    pub burst: Burst,
    pub lifetimes: Lifetimes,
    pub join_distance: Vec<Dist>,
    pub cross_levels: Vec<Sweep>,
    pub cross: Cross,
    pub pool: Option<Pool>,
    pub auction: Option<Auction>,
    pub phase: Vec<Phase>,
    pub class: Vec<Class>,
    /// Ignored by v1 readers.
    pub extensions: Option<toml::Table>,
    /// BLAKE3 of the config file's bytes; the stream header carries it.
    #[serde(skip)]
    pub digest: [u8; 32],
}

fn sum_ppm(what: &str, parts: impl Iterator<Item = u32>) -> Result<(), ConfigError> {
    let sum: u64 = parts.map(u64::from).sum();
    if sum != PPM {
        return invalid(format!("{what} must sum to {PPM} ppm, not {sum}"));
    }
    Ok(())
}

fn at_most_ppm(what: &str, v: u32) -> Result<(), ConfigError> {
    if u64::from(v) > PPM {
        return invalid(format!("{what} is {v} ppm, above {PPM}"));
    }
    Ok(())
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut cfg: Self = toml::from_str(text)?;
        cfg.digest = hash(text.as_bytes()).0;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Total length of the run.
    pub fn duration_ns(&self) -> u64 {
        self.phase
            .iter()
            .fold(0u64, |a, p| a.saturating_add(p.duration_ns))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return invalid(format!(
                "version {} is not supported (this reader: {CONFIG_VERSION})",
                self.version
            ));
        }
        if self.rate_msgs_per_s == 0 {
            return invalid("rate_msgs_per_s is 0");
        }
        let b = &self.book_model;
        if b.spread_ticks == 0 || b.mid_tick <= b.spread_ticks || b.depth_lots == 0 {
            return invalid(
                "book_model needs spread_ticks ≥ 1, mid_tick > spread_ticks, depth_lots ≥ 1",
            );
        }
        if b.mid_tick.checked_add(b.spread_ticks).is_none() {
            return invalid("book_model overflows a tick");
        }
        let bu = &self.burst;
        if bu.rate_per_s > 0 && (bu.window_ns == 0 || bu.mult_ppm == 0) {
            return invalid("burst needs window_ns ≥ 1 and mult_ppm ≥ 1");
        }
        if bu.base_scale_ppm == 0 {
            return invalid("burst.base_scale_ppm is 0");
        }
        if self.lifetimes.row.is_empty() {
            return invalid("lifetimes.row is empty");
        }
        sum_ppm(
            "lifetimes.row ppm",
            self.lifetimes.row.iter().map(|r| r.ppm),
        )?;
        at_most_ppm("lifetimes.replace_ppm", self.lifetimes.replace_ppm)?;
        for r in &self.lifetimes.row {
            if r.lo_ns == 0 || r.lo_ns >= r.hi_ns {
                return invalid("a lifetime row needs 0 < lo_ns < hi_ns");
            }
        }
        sum_ppm(
            "join_distance ppm",
            self.join_distance.iter().map(Dist::ppm),
        )?;
        for d in &self.join_distance {
            match *d {
                Dist::Geometric { p_ppm, .. } if p_ppm == 0 || u64::from(p_ppm) > PPM => {
                    return invalid("Geometric p_ppm must be in 1..=10^6");
                }
                Dist::LogUniform { lo, hi, .. } if lo == 0 || lo >= hi => {
                    return invalid("LogUniform needs 0 < lo < hi");
                }
                Dist::Uniform { span: 0, .. } => return invalid("Uniform span is 0"),
                _ => {}
            }
        }
        sum_ppm("cross_levels ppm", self.cross_levels.iter().map(|s| s.ppm))?;
        if self.cross_levels.iter().any(|s| s.lo == 0 || s.lo > s.hi) {
            return invalid("a cross level needs 1 ≤ lo ≤ hi");
        }
        let c = &self.cross;
        sum_ppm(
            "cross tif ppm",
            [c.ioc_ppm, c.day_ppm, c.fok_ppm].into_iter(),
        )?;
        at_most_ppm("cross.through_ppm", c.through_ppm)?;
        if c.through_qty_pct < 100 {
            return invalid("cross.through_qty_pct is below 100");
        }
        if let Some(a) = &self.auction {
            at_most_ppm("auction.through_ppm", a.through_ppm)?;
        }
        if self
            .phase
            .iter()
            .any(|p| p.rate_ppm > 1_000_000_000 || p.cross_scale_ppm > 1_000_000_000)
        {
            return invalid("phase rate_ppm and cross_scale_ppm are capped at 1000x (10^9 ppm)");
        }
        if self.cross_levels.iter().any(|s| s.hi > 1_000_000) {
            return invalid("a cross level is capped at 10^6");
        }
        if self.phase.is_empty() || self.phase.iter().any(|p| p.duration_ns == 0) {
            return invalid("phase needs at least one entry, each with duration_ns ≥ 1");
        }
        // Times run in picoseconds in a u64: about 213 days.
        if self.duration_ns() > u64::MAX / 1_000 {
            return invalid("total phase duration exceeds 213 days");
        }
        if !self.class.iter().any(|c| c.enabled) {
            return invalid("no class is enabled");
        }
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for (i, c) in self.class.iter().enumerate() {
            let tag = format!("class[{i}]");
            if [
                c.mix.join,
                c.mix.cancel,
                c.mix.reduce,
                c.mix.improve,
                c.mix.cross,
            ]
            .iter()
            .any(|&v| u64::from(v) > PPM)
            {
                return invalid(format!("{tag}.mix has a share above {PPM} ppm"));
            }
            if c.mix.total() == 0 {
                return invalid(format!("{tag}.mix is all zero"));
            }
            if c.qty_p_ppm == 0 || u64::from(c.qty_p_ppm) > PPM || c.max_live_orders == 0 {
                return invalid(format!(
                    "{tag}: qty_p_ppm in 1..=10^6 and max_live_orders ≥ 1"
                ));
            }
            if let Skew::Zipf { s_milli } = c.skew
                && s_milli > 2_000
            {
                return invalid(format!("{tag}: zipf s_milli above 2000"));
            }
            match c.packets {
                Packets::Bundled {
                    bundle_size,
                    urgent_cancel_ppm,
                    urgent_two_ppm,
                } => {
                    if !(1..=MAX_MSGS_PER_PKT).contains(&bundle_size) {
                        return invalid(format!(
                            "{tag}: bundle_size not in 1..={MAX_MSGS_PER_PKT}"
                        ));
                    }
                    at_most_ppm("urgent_cancel_ppm", urgent_cancel_ppm)?;
                    at_most_ppm("urgent_two_ppm", urgent_two_ppm)?;
                }
                Packets::Single { two_ppm } => at_most_ppm("two_ppm", two_ppm)?,
            }
            match c.placement {
                Placement::Dedicated {
                    lane_first,
                    lane_count,
                    sessions_per_lane,
                } => {
                    if lane_count == 0
                        || sessions_per_lane == 0
                        || sessions_per_lane > MAX_SESSIONS_PER_LANE
                    {
                        return invalid(format!(
                            "{tag}: dedicated needs lane_count ≥ 1 and 1 ≤ sessions_per_lane ≤ {MAX_SESSIONS_PER_LANE}"
                        ));
                    }
                    let end = u32::from(lane_first) + u32::from(lane_count);
                    if end > 256 {
                        return invalid(format!("{tag}: lanes run past 255"));
                    }
                    ranges.push((u32::from(lane_first), end));
                }
                Placement::Pooled { sessions } => {
                    let Some(pool) = self.pool else {
                        return invalid(format!("{tag} is pooled but there is no [pool]"));
                    };
                    if sessions == 0 || pool.lanes == 0 {
                        return invalid(format!(
                            "{tag}: pooled needs sessions ≥ 1 and pool.lanes ≥ 1"
                        ));
                    }
                }
            }
        }
        if let Some(p) = self.pool {
            ranges.push((
                u32::from(p.first_lane),
                u32::from(p.first_lane) + u32::from(p.lanes),
            ));
        }
        for (i, a) in ranges.iter().enumerate() {
            if a.1 > 256 {
                return invalid("pool lanes run past 255");
            }
            for b in ranges.iter().skip(i + 1) {
                if a.0 < b.1 && b.0 < a.1 {
                    return invalid("lane ranges of dedicated classes and the pool overlap");
                }
            }
        }
        Ok(())
    }
}
