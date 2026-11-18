//! The box config of `vyrn-seq`: a MINIMAL schema (`schema = 1`), a labelled subset of 11 §10.1.
//! See `main.rs` for the field table. Unknown fields are refused.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

use serde::Deserialize;

/// The schema this release reads. 11 §10.1's example says 3; no schema is defined in
/// `deploy/schema/` yet, so this minimal one is 1 (spec gap, PR body).
pub const SCHEMA: u32 = 1;
/// The protocol version (`vyrn_wire::PROTO_VERSION` is the source of truth, 11 §10.2).
pub const PROTOCOL: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub protocol: u32,
    pub role: String,
    pub mode: String,
    pub home: String,
    pub book: u16,
    #[serde(default)]
    pub epoch: u32,
    pub engine: Engine,
    pub nic: Nic,
    #[serde(default)]
    pub cores: Cores,
    pub replication: Replication,
    pub keys: Keys,
    #[serde(default)]
    pub epoch_boundary: Option<EpochBoundary>,
    #[serde(default)]
    pub dev_session: Vec<DevSession>,
    #[serde(default)]
    pub repair: Option<Repair>,
    /// Optional: the finality listener (`finality.rs`).
    #[serde(default)]
    pub consensus: Option<Consensus>,
}

/// `SeqDataReq` service (07 §5.5 source 3, `repair.rs`). Omitted: the box retains nothing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repair {
    /// The UDP port replicas send KEY fetches to; 0 asks for an ephemeral one (tests).
    pub port: u16,
    /// Retained packets: size as peak packet rate × `REP_SEQ_PKT_RETAIN_MS`.
    #[serde(default = "d_slots")]
    pub slots: usize,
    /// `REP_SEQ_DATA_MAX_PPS`.
    #[serde(default = "d_pps")]
    pub max_pps: u64,
    /// `DAV_SESSION_REPAIR_PPS`.
    #[serde(default = "d_session_pps")]
    pub session_pps: u64,
}

fn d_slots() -> usize {
    1 << 16
}

fn d_pps() -> u64 {
    crate::repair::REP_SEQ_DATA_MAX_PPS
}

fn d_session_pps() -> u64 {
    crate::repair::DAV_SESSION_REPAIR_PPS
}

/// `[consensus]`: the finality listener; its committee comes from the roster (08 §9.6).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consensus {
    /// This box's `REP_UDP_CTRL` (07 §3.1: port 7401); port 0 asks for an ephemeral one.
    pub ctrl: SocketAddrV4,
    /// The roster bytes (08 §9.6), raw or as hex text.
    pub roster: std::path::PathBuf,
    /// `EpoConfig.roster_hash`, hex.
    pub roster_hash: String,
    /// `Domain.genesis_hash`, hex.
    pub genesis_hash: String,
    /// `EpoConfig.seq_order`; default the home's first two `vyrn-seq` boxes, `[n, n + 1]`.
    #[serde(default)]
    pub seq_order: Option<[u8; 2]>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engine {
    /// Dedicated lanes; the pool is not wired yet (`pooled` must be 0).
    pub dedicated: u8,
    #[serde(default)]
    pub pooled: u8,
    pub tick_min: u32,
    pub tick_max: u32,
    pub win_center: u32,
    #[serde(default = "d_cap")]
    pub slot_cap: u32,
}

fn d_cap() -> u32 {
    1024
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nic {
    /// `kernel_udp` or `sim` (efvi and dpdk need the C shim: refused).
    pub backend: String,
    pub ip: Ipv4Addr,
    /// Lane `l` listens on `port_base + l`; 0 asks for ephemeral ports (tests).
    pub port_base: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cores {
    /// Pin threads to `engine` and `stream`. Refused today: `vyrn-nic::sys` has no affinity call.
    #[serde(default)]
    pub pin: bool,
    pub engine: Option<u16>,
    pub stream: Option<u16>,
    /// `abort` (`seal()`), `count` (`seal_counting()`, reports violations at exit) or `off`.
    #[serde(default = "d_seal")]
    pub seal: String,
}

fn d_seal() -> String {
    "count".into()
}

/// An omitted `[cores]` table means the same as an empty one.
impl Default for Cores {
    fn default() -> Self {
        Self {
            pin: false,
            engine: None,
            stream: None,
            seal: d_seal(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replication {
    /// Every replica's ORDER port (F4–F6 share it in this version).
    pub order: Vec<SocketAddrV4>,
    /// A block closes this often while steps are pending.
    pub block_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// `seq_key` handle. Only `env:NAME` (32-byte Ed25519 seed, hex, in that variable) resolves
    /// here; `hsm:` handles are a follow-up. Key bytes never sit in this file.
    pub seq: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochBoundary {
    pub next: u32,
    /// T, TAI ns.
    pub t_ns: u64,
    pub to_home: String,
    #[serde(default)]
    pub seq_index: u8,
}

/// A session opened at start. DEV backends only: in BASE and CHAIN, sessions open through the
/// session gateway (04, 09 §5), which is not wired yet.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevSession {
    pub lane: u8,
    pub slot: u16,
    /// Lane-local account slot (≥ 1).
    pub account: u32,
    /// Hex, 16 bytes each.
    pub k_seq: String,
    pub k_out: String,
    pub quote: u64,
    pub base: u64,
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

/// Resolves a key handle to its secret bytes.
pub fn resolve<const N: usize>(handle: &str) -> Result<[u8; N], String> {
    let Some(var) = handle.strip_prefix("env:") else {
        return Err(format!(
            "key handle {handle:?}: only env:NAME resolves in this release"
        ));
    };
    let v = std::env::var(var).map_err(|_| format!("key handle {handle:?}: {var} is not set"))?;
    hex(v.trim())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        c.check()?;
        Ok(c)
    }

    /// The start-time checks of 11 §10.1 this release can make.
    fn check(&self) -> Result<(), String> {
        let bad = |f: &str, why: &str| Err(format!("config {f} {why}"));
        if self.schema != SCHEMA {
            return bad("schema", &format!("must be {SCHEMA}"));
        }
        if self.protocol != PROTOCOL {
            return bad("protocol", &format!("must be {PROTOCOL}"));
        }
        if self.role != "seq" {
            return bad("role", "must be \"seq\" for vyrn-seq");
        }
        if self.mode != "BASE" {
            return bad("mode", "must be BASE (CHAIN session open is not wired)");
        }
        let n = self.engine.dedicated;
        if n == 0 || usize::from(n) > crate::MAX_LANES {
            return bad("engine.dedicated", "must be 1 ..= MAX_LANES");
        }
        if self.engine.pooled != 0 {
            return bad("engine.pooled", "must be 0 (pooled lanes are not wired)");
        }
        if !matches!(self.nic.backend.as_str(), "kernel_udp" | "sim") {
            return bad("nic.backend", "must be kernel_udp or sim in this release");
        }
        if self.cores.pin {
            return bad(
                "cores.pin",
                "is not supported yet (no affinity call in vyrn-nic::sys)",
            );
        }
        if !matches!(self.cores.seal.as_str(), "abort" | "count" | "off") {
            return bad("cores.seal", "must be abort, count or off");
        }
        if self.replication.order.is_empty() || self.replication.block_ms == 0 {
            return bad("replication", "needs an order address and block_ms ≥ 1");
        }
        for s in &self.dev_session {
            if s.lane >= n
                || s.account == 0
                || usize::try_from(s.account).is_ok_and(|a| a >= crate::NA)
            {
                return bad(
                    "dev_session",
                    "names a lane or account slot that does not exist",
                );
            }
            hex::<16>(&s.k_seq)?;
            hex::<16>(&s.k_out)?;
        }
        Ok(())
    }
}
