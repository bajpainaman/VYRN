//! The box config of the `vyrn-data` binary: a MINIMAL schema (`schema = 1`), a labelled subset
//! of 11 §10.1, in the shape of `vyrn-seq`'s. `main.rs` has the field table. Unknown fields are
//! refused.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vyrn_types::{BookId, SessionId};

use crate::{HomeConfig, Mode};

pub const SCHEMA: u32 = 1;
pub const PROTOCOL: u32 = 1;
/// `BLD_METRICS_PORT` (11 §8.4).
pub const METRICS_PORT: u16 = 9464;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub protocol: u32,
    pub role: String,
    pub mode: String,
    pub home: String,
    /// A DEV box: open-mode fetches and hex keys in this file are allowed only here.
    #[serde(default)]
    pub dev: bool,
    /// This box's index, the `src` of its frames.
    pub src: u8,
    pub books: Vec<u16>,
    pub nic: Nic,
    pub ring: RingCfg,
    /// Every voter and the warm standby, in data-frame `dst` order (07 §5.1).
    pub dests: Vec<SocketAddrV4>,
    #[serde(default)]
    pub session: Vec<Session>,
    /// Where `K_fetch` comes from (08 §9.6). Omitted: open-mode fetches, DEV only.
    #[serde(default)]
    pub roster: Option<RosterCfg>,
    #[serde(default)]
    pub fetch: FetchCfg,
    #[serde(default)]
    pub store: Store,
    #[serde(default)]
    pub metrics: Metrics,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nic {
    /// `kernel_udp` only: the binary has no injector for `sim`.
    pub backend: String,
    pub ip: Ipv4Addr,
    /// 0 asks for an ephemeral port (tests).
    pub ingest_port: u16,
    pub fetch_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingCfg {
    pub slots: usize,
    /// The index secret's handle; omitted, 16 bytes are read from `/dev/urandom`.
    #[serde(default)]
    pub index_key: Option<String>,
}

/// A session's MAC key (`K_seq` in BASE, `K_com` in CHAIN). The session gateway (04, 09 §5)
/// is not wired, so sessions are listed here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: u32,
    pub key: String,
}

/// `[roster]`: the roster this box derives every requester's `K_fetch(e, i, d)` from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterCfg {
    /// The roster bytes (08 §9.6), raw or as hex text.
    pub file: PathBuf,
    /// `EpoConfig.roster_hash`, hex; the bytes must hash to it (R1).
    pub roster_hash: String,
    /// `Domain.genesis_hash`, hex.
    pub genesis_hash: String,
    /// The epoch the keys are for.
    pub epoch: u32,
    /// This box's position `d` in `home(e).data`.
    #[serde(rename = "box")]
    pub data_box: u8,
    /// This box's X25519 private key handle: the secret of its roster `xchg_key`.
    pub xchg_secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchCfg {
    #[serde(default = "d_rate")]
    pub rate: u64,
    #[serde(default = "d_burst")]
    pub burst: u64,
}

fn d_rate() -> u64 {
    20_000
}
fn d_burst() -> u64 {
    256
}

impl Default for FetchCfg {
    fn default() -> Self {
        Self {
            rate: d_rate(),
            burst: d_burst(),
        }
    }
}

/// The log source the node reads (crate docs, § Roles). No `dirs`: an empty in-memory store.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    #[serde(default)]
    pub dirs: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// The management address (11 §8.4); port 0 asks for an ephemeral one.
    #[serde(default = "d_listen")]
    pub listen: SocketAddrV4,
}

fn d_listen() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, METRICS_PORT)
}

impl Default for Metrics {
    fn default() -> Self {
        Self { listen: d_listen() }
    }
}

pub fn hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let b = s.as_bytes();
    if b.len() != 2 * N {
        return Err(format!("expected {} hex digits, got {}", 2 * N, b.len()));
    }
    let mut out = [0u8; N];
    for (o, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        let s = std::str::from_utf8(pair.as_slice()).map_err(|e| e.to_string())?;
        *o = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        c.check()?;
        Ok(c)
    }

    fn check(&self) -> Result<(), String> {
        let bad = |f: &str, why: &str| Err(format!("config {f} {why}"));
        if self.schema != SCHEMA {
            return bad("schema", &format!("must be {SCHEMA}"));
        }
        if self.protocol != PROTOCOL {
            return bad("protocol", &format!("must be {PROTOCOL}"));
        }
        if self.role != "data" {
            return bad("role", "must be \"data\" for vyrn-data");
        }
        if !matches!(self.mode.as_str(), "BASE" | "CHAIN") {
            return bad("mode", "must be BASE or CHAIN");
        }
        if self.nic.backend != "kernel_udp" {
            return bad("nic.backend", "must be kernel_udp in this release");
        }
        if self.books.is_empty() || self.dests.is_empty() || self.ring.slots == 0 {
            return bad("books/dests/ring.slots", "must not be empty or 0");
        }
        if self.roster.is_none() && !self.dev {
            return bad(
                "roster",
                "is empty: open-mode fetches are DEV only (set dev = true on a DEV box)",
            );
        }
        if self.fetch.rate == 0 || self.fetch.burst == 0 {
            return bad("fetch", "rate and burst must be ≥ 1");
        }
        Ok(())
    }

    /// Resolves a key handle: `env:NAME` (hex in that variable) anywhere, `hex:…` on DEV only.
    /// Key bytes outside DEV never sit in the file.
    pub fn resolve<const N: usize>(&self, handle: &str) -> Result<[u8; N], String> {
        if let Some(var) = handle.strip_prefix("env:") {
            let v = std::env::var(var).map_err(|_| format!("key {handle:?}: {var} is not set"))?;
            return hex(v.trim());
        }
        // The handle itself is never echoed: outside `env:` it may be the secret.
        match handle.strip_prefix("hex:") {
            Some(h) if self.dev => hex(h),
            Some(_) => Err("a hex: key handle is DEV only".into()),
            None => Err("a key handle must be env:NAME or hex:…".into()),
        }
    }

    pub fn home(&self) -> Result<HomeConfig, String> {
        let keys = self
            .session
            .iter()
            .map(|s| Ok((SessionId(s.id), self.resolve::<16>(&s.key)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let index_key = match &self.ring.index_key {
            Some(h) => self.resolve::<16>(h)?,
            None => urandom()?,
        };
        Ok(HomeConfig {
            mode: if self.mode == "CHAIN" {
                Mode::Chain
            } else {
                Mode::Base
            },
            books: self.books.iter().map(|&b| BookId(b)).collect(),
            keys,
            ring_slots: self.ring.slots,
            index_key,
        })
    }
}

fn urandom() -> Result<[u8; 16], String> {
    use std::io::Read as _;
    let mut k = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut k))
        .map_err(|e| format!("ring.index_key from /dev/urandom: {e}"))?;
    Ok(k)
}
