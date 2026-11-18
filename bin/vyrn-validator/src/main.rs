//! `vyrn-validator` (03 §1.3, 07, 09; 11 §1.3): everything in `vyrn-replica` plus `vyrn-chain`.
//! main.rs and config wiring only: the order core's checks live in `vyrn-replica`, the bridge
//! and guardian rules in `vyrn-chain`.
//!
//! # Contract
//!
//! **Invocation.** `vyrn-validator --config FILE [--stop-on-stdin-eof]`. `VYRN_LOG=warn` (or
//! `info`, `debug`) prints Commonware's and the voter's logs on stderr.
//!
//! **Config**: MINIMAL schema 1, a labelled subset of 11 §10.1. Unknown fields are refused.
//!
//! | Field | Meaning |
//! |---|---|
//! | `schema = 1`, `protocol = 1` | must match this release |
//! | `role = "validator"` or `"observer"`, `mode = "BASE"`, `book`, `epoch` | the book and epoch served (`EpochView`); an observer is described below |
//! | `lanes` | the sequencer box's lane count, one substream (07 §2.2); 1–4, 8, 11 or 49 |
//! | `[nic] backend = "kernel_udp", ip, order_port, order_port_b` | where ORDER, HASH and HEADER frames arrive on path A and (optional, required for an observer) path B (0: ephemeral). With both, each frame is handed to the order core once, in `frame_seq` order (07 §4.9, `vyrn_replica::Paths`) |
//! | `[cores] order` | REF core of the order core (07 §7.2 core 3); reported, not pinned |
//! | `[membership] seq_keys = ["<hex>"]` | `REP_Membership`'s `seq_key` per sequencer index (07 §13.1); public keys, so they may sit in the file |
//! | `[keys] vote, node` | vote key handle; `node` (the p2p identity) defaults to `vote`. Only `env:NAME` (seed hex) resolves, and only with `[consensus]` |
//! | `[nic] data_port`, `[data] boxes = ["ip:port"], me, max_range, xchg, seq_repair = "ip:port", seq_box = 0, silence_us = 1000, [[data.peer]] voter, addr` | optional: the data RX queue (07 §5.4); `boxes[i]` is data box `src = i`, `me` this replica's index in their destination lists; with `xchg` (needs `[consensus]`) every fetch to `boxes[d]` is sealed under `K_fetch(e, me, d)` (08 §9.6). `[[data.peer]]` are the other replicas (roster voter index, `[nic] data_port`) and `seq_repair` is `vyrn-seq` box `seq_box`'s `[repair]` port: 07 §5.5 sources 2 and 3 (`fetch.rs`), sealed too with `xchg`. Without `[data]` vote-rule item 3 is not checked (DEV) |
//! | `dev = false` | `true` marks a DEV validator: only then may `[replay] hashlag_us` differ from 1000 |
//! | `[replay] tick_min, tick_max, win_center, slot_cap, hashlag_us, [[replay.session]] lane, slot, account, k_seq, quote, base` | optional, needs `[data]`: replay of every block that passes item 3 on `vyrn-engine` (`replay.rs`), built from the sequencer's `[engine]` and `[[dev_session]]` (no state snapshot encoding yet). `hashlag_us` (DEV only, default 1000 = the spec's 1 ms, 07 §3.7) is the `REP_E_HASHLAG` bound, for unpinned DEV hosts |
//! | `[repair] nack, hole_wait_us, retry_us, tries, order_as, order_b_as` | optional: sequencer retransmit (07 §4.10). Holes are Nacked to `nack`, the box's `[consensus] ctrl`, after `hole_wait_us` (5), again every `retry_us` (50), and given up after `tries` (8) or a `NackTooOld`, printing `ORDER_GAP tenure= stream= from= to= path=`. Other timers are DEV only. `order_as`/`order_b_as`: the port the box has for this replica when a relay stands in front of it. Prints `REPAIR nacks= gaps= too_old=` at exit |
//! | `[consensus] roster, roster_hash, genesis_hash, home, seq_order, observers, delta_ms, storage` | optional: the Simplex voter (`consensus.rs`); `storage` (the Simplex journal's directory, kept across restarts) is required for a voter, and an empty journal for the epoch starts only with `--fresh`, a flag and not a config key (07 §6.3 Journal, prints `FRESH_JOURNAL epoch= voter=`); committee and peers from the roster file (08 §9.6), checked against `roster_hash`; `membership.seq_keys[0]` must be the roster's primary `seq_key` |
//!
//! **Start sequence** (11 §10.1): load and check config → resolve keys → build the order core
//! (`vyrn_replica::OrderCore`) over the config's `EpochView` → open the NIC queues → start the
//! order thread and, with `[consensus]`, the voter thread → print `DATA rx=<ip:port>` (with
//! `[data]`), `CONSENSUS voter=<i> repl=<ip:port>` (with `[consensus]`) and
//! `ORDER_B order=<ip:port>` (with `order_port_b`) and `READY vyrn-validator order=<ip:port>` on
//! stdout.
//!
//! **Threads.** `order` (07 §7.2 core 3): polls the queue, runs `OrderCore::on_frame` and the
//! `REP_E_HASHLAG` timer, and for each ready block prints
//! `BLOCK height=<h> first_step=<s> last_step=<s> lanes=<k> steps=<k> verdict=<Valid|Invalid|Pending>`
//! (07 §6.4 items 2 and 5, the precondition for a vote). A sequencer fault prints
//! `FAULT <code> height=<h>` once; the core then refuses every later frame. A frame that is not
//! its substream's next prints `OUT_OF_ORDER next_height=<h>` once per stall (without `[repair]`). With `[data]` it also
//! polls the data RX queue: one `DataFeed::on_frame` per payload into the `DataJoin`, a
//! `DataFetch` RANGE to the box for every gap, and item 3 (`DataJoin::check`) for each ready
//! block before the voter may vote for it; a block whose data contradicts its header prints
//! `DATA_FAULT height=<h>`. With `[replay]` such a block's `BLOCK` line is printed after it
//! replays and ends in ` out=<hex>`, its `RustReplay` output hash; the first divergence prints
//! `REPLAY_FAULT height=<h> <why>` and replay stops (so does a `DATA_FAULT`). `voter` (`consensus.rs`): Simplex, `FINAL ...` per certificate.
//! main: start, readiness, stop, `STATS frames=<n> blocks=<n> faults=<n>` and, with `[data]`,
//! `DATA_EVICT expired=<n> capped=<n>`: unreferenced payloads the join dropped (07 §5.4; expiry
//! runs only with `[consensus]`, which reports finality). The order thread prints, at exit with
//! `[data]`, `FETCH box=<n> peer=<n> seq=<n> served=<n> missed=<n> limited=<n> bad=<n>`: KEY
//! fetches it sent to each 07 §5.5 source, and peers' fetches it served (`fetch.rs`).
//!
//! **Observer** (`role = "observer"`, 03 §4.5: the same binary, without c3's votes). It needs
//! `[replay]`, `[consensus]`, `[observer] ring, ring_cap, ctrl` and `[nic] order_port_b`, and
//! refuses `[keys]`. It replays a block only once every frame handed on through it arrived on
//! both paths (10 §8.2: the drop copy's durability bit); a block held `REP_PATH_DOWN_MS` (100 ms)
//! for a frame one path lost prints `DURABLE_WAIT height=<h>` once.
//! Replay's sink is `vyrn_md::SinkStream` tapped into the output ring at `ring` (10 §8.6,
//! `ring_cap` data bytes, default 64 MiB), which `vyrn-dropcopy` reads. `[consensus]` gives the
//! roster only (no voter starts): it binds `ctrl`, where the validators send their finalize votes and certificates
//! (their `[consensus] observers`), and prints `OBSERVER ctrl=<ip:port>` and `FINAL height=<h>
//! from=<votes|cert>` as finality moves. Each block that is both replayed and final gets one
//! `DC_FINAL` frame on the ring, in height order, once the certificate's `last_hash` equals the
//! header hash of the replayed block at its `last_height`; a different hash prints
//! `FINALITY_FAULT height=<h> ...` and replay stops. A ring or adapter error prints
//! `REPLAY_FAULT height=<h> output ring: <why>` and replay stops. Not wired here: the epoch's
//! end (`DC_EOD`; this build serves one epoch), settlement, and `MBO` publication.
//! **Data box failure** (07 §5.7 steps 1–3, `failover.rs`, with `[data]` and `[consensus]`): a
//! box silent for `[data] silence_us` (1000; other values DEV only) is gossiped as `DataDown` to
//! the `[[data.peer]]`s; at Q votes it prints `DATA_DOWN box=<d> votes=<n> quorum=<q>`, and if it
//! is the sessions' home every live box gets a sealed REDIRECT per session
//! (`REDIRECT_SENT down=<d> to=<d'> sessions=<n> boxes=<n>`). Exit prints `FAILOVER down_sent=
//! down_heard= down_bad= effective= redirects= redirect_msgs=` (sessions and messages sent, summed
//! over the boxes).
//! **Control** (stdin, one line each; *reading*: 07 and 08 name no transport for it yet).
//! `EPOCH <e>` re-derives every `K_fetch` of a keyed `[data]` for epoch `e` (07 §5.5 Epoch
//! boundary); once the order thread has installed the keys it prints `FETCH_EPOCH <e>`. A
//! refused or unknown line prints `CONTROL_ERR <why>` on stderr and changes nothing. With
//! `--stop-on-stdin-eof`, EOF stops the validator.
//!
//! **Not wired yet** (PR follow-ups): seals in the voter's source (tail reports, Silence), the chain guardian
//! (`vyrn_chain::bridge::Guardian` needs a `vyrn_chain::Replica` over finalized `StateCommit`s,
//! which `vyrn-replica` does not produce yet), path B dedupe and repair, CHAIN mode.
#![forbid(unsafe_code)]

use std::collections::VecDeque;

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use clap::Parser;
use serde::Deserialize;
use vyrn_chain as _;
use vyrn_data::frame::Fetch;
use vyrn_replica::feed::Gap;
use vyrn_replica::{
    BlockInputs, DataErr, DataFeed, DataJoin, Evictions, Mark, Path as RepPath, Paths,
};

mod consensus;
mod failover;
mod fetch;
mod replay;
use vyrn_consensus::Verdict;
use vyrn_log::{LaneRec, Layout};
use vyrn_nic::frame;
use vyrn_nic::{BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, RxBind};
use vyrn_replica::paths::{Ask, Repair};
use vyrn_replica::{EpochView, FrameErr, Nack, NackTooOld, OrderCore};
use vyrn_types::{BookId, Epoch, Hash, Height, LaneId, PacketFlags, PubKey, StepId};
use vyrn_wire::{RX_BURST, RxPkt, RxRing};

#[derive(Parser)]
#[command(version, about = "The VYRN validator box")]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[arg(long)]
    stop_on_stdin_eof: bool,
    /// Acknowledge, for this start only, an empty Simplex journal for this epoch (07 §6.3).
    #[arg(long)]
    fresh: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    protocol: u32,
    role: String,
    mode: String,
    book: u16,
    #[serde(default)]
    epoch: u32,
    lanes: u8,
    #[serde(default)]
    dev: bool,
    nic: Nic,
    #[serde(default)]
    cores: Cores,
    membership: Membership,
    #[serde(default)]
    keys: Option<Keys>,
    #[serde(default)]
    observer: Option<ObserverCfg>,
    #[serde(default)]
    data: Option<Data>,
    #[serde(default)]
    consensus: Option<consensus::Section>,
    #[serde(default)]
    replay: Option<replay::Section>,
    #[serde(default)]
    repair: Option<RepairCfg>,
}

/// `[repair]` (module docs): sequencer retransmit (07 §4.10).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairCfg {
    /// The sequencer's `REP_UDP_CTRL` (`vyrn-seq`'s `[consensus] ctrl`).
    nack: SocketAddrV4,
    #[serde(default = "d_hole_wait_us")]
    hole_wait_us: u64,
    #[serde(default = "d_retry_us")]
    retry_us: u64,
    #[serde(default = "d_tries")]
    tries: u32,
    /// The ORDER port the sequencer has for this box on path A and on path B, when it is not
    /// the one bound here (a relay or NAT in front of it). A Nack names it, and the sequencer
    /// serves only a port it has configured.
    #[serde(default)]
    order_as: Option<u16>,
    #[serde(default)]
    order_b_as: Option<u16>,
}

/// `REP_HOLE_WAIT_US`, `REP_NACK_RETRY_US` (07 §4.9).
const fn d_hole_wait_us() -> u64 {
    5
}
const fn d_retry_us() -> u64 {
    50
}
/// Asks before a hole is given up (`ORDER_GAP`).
const fn d_tries() -> u32 {
    8
}

/// `[observer]` (module docs).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverCfg {
    ring: PathBuf,
    #[serde(default = "d_ring_cap")]
    ring_cap: u64,
    ctrl: std::net::SocketAddr,
}

fn d_ring_cap() -> u64 {
    64 << 20
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    boxes: Vec<std::net::SocketAddrV4>,
    me: u8,
    /// Peer replicas: 07 §5.5 source 2 (`fetch.rs`).
    #[serde(default)]
    peer: Vec<Peer>,
    /// `vyrn-seq` box `seq_box`'s `[repair]` port: 07 §5.5 source 3, `SeqDataReq`.
    #[serde(default)]
    seq_repair: Option<std::net::SocketAddrV4>,
    /// The roster index of the box at `seq_repair` among its home's `vyrn-seq` boxes.
    #[serde(default)]
    seq_box: u8,
    /// The largest RANGE fetch a data box accepts, in frames.
    #[serde(default = "d_range")]
    max_range: u64,
    /// `REP_DATA_SILENCE_MS` in µs (07 §5.7 step 1, `failover.rs`): other than 1000 only with
    /// `dev = true`, for unpinned DEV hosts.
    #[serde(default = "d_silence_us")]
    silence_us: u64,
    /// This voter's X25519 secret (`env:NAME`), the private half of its roster `xchg_key`:
    /// with it every fetch to `boxes[d]` is sealed under `K_fetch(e, me, d)` (07 §5.5, 08
    /// §9.6). Needs `[consensus]`. Without it fetches go unsealed, which only an open-mode
    /// (DEV) box serves.
    #[serde(default)]
    xchg: Option<String>,
}

/// A peer replica: its roster voter index (for its key, `VOTER_TARGET + voter`) and its
/// `[nic] data_port` address.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    voter: u8,
    addr: std::net::SocketAddrV4,
}

fn d_silence_us() -> u64 {
    1000
}

fn d_range() -> u64 {
    64
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nic {
    backend: String,
    ip: Ipv4Addr,
    order_port: u16,
    #[serde(default)]
    order_port_b: Option<u16>,
    #[serde(default)]
    data_port: u16,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cores {
    order: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    seq_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Keys {
    vote: String,
    #[serde(default)]
    node: Option<String>,
}

fn hex32(s: &str) -> Result<PubKey, String> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err("a seq_key must be 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (o, p) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        let p = std::str::from_utf8(p.as_slice()).map_err(|e| e.to_string())?;
        *o = u8::from_str_radix(p, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

impl Config {
    fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let bad = |f: &str, why: &str| Err(format!("config {f} {why}"));
        if c.schema != 1 || c.protocol != 1 {
            return bad("schema/protocol", "must be 1 and 1 in this release");
        }
        if !matches!(c.role.as_str(), "validator" | "observer") || c.mode != "BASE" {
            return bad(
                "role/mode",
                "must be validator or observer, and BASE (CHAIN needs the guardian)",
            );
        }
        if c.observer() {
            if c.keys.is_some() {
                return bad(
                    "keys",
                    "is refused for an observer: it does not vote (03 §4.5)",
                );
            }
            if c.observer.is_none() || c.replay.is_none() || c.consensus.is_none() {
                return bad(
                    "role",
                    "observer needs [observer], [replay] and [consensus] (its finality)",
                );
            }
            if c.nic.order_port_b.is_none() {
                return bad(
                    "nic.order_port_b",
                    "is required for an observer: it replays only frames held from both paths (10 §8.2)",
                );
            }
        } else if c.observer.is_some() {
            return bad("observer", "needs role = \"observer\"");
        }
        if c.nic.backend != "kernel_udp" {
            return bad("nic.backend", "must be kernel_udp in this release");
        }
        if c.membership.seq_keys.is_empty() {
            return bad("membership.seq_keys", "is empty");
        }
        if !c.observer() && c.keys.as_ref().is_none_or(|k| k.vote.is_empty()) {
            return bad("keys.vote", "is missing or empty");
        }
        if c.replay.is_some() && c.data.is_none() {
            return bad("replay", "needs [data]: replay reads the blocks' payloads");
        }
        match c.data.as_ref().map(|d| d.silence_us) {
            Some(0) => return bad("data.silence_us", "must be at least 1"),
            Some(us) if us != 1000 && !c.dev => {
                return bad(
                    "data.silence_us",
                    "other than 1000 (07 §5.7) is DEV only: set dev = true on a DEV validator",
                );
            }
            _ => {}
        }
        if let Some(r) = &c.repair {
            if r.hole_wait_us == 0 || r.retry_us == 0 || r.tries == 0 {
                return bad(
                    "repair",
                    "hole_wait_us, retry_us and tries must be at least 1",
                );
            }
            if !c.dev && (r.hole_wait_us != d_hole_wait_us() || r.retry_us != d_retry_us()) {
                return bad(
                    "repair.hole_wait_us/retry_us",
                    "other than 5 and 50 (07 §4.9) are DEV only: set dev = true",
                );
            }
        }
        match c.replay.as_ref().and_then(|r| r.hashlag_us) {
            Some(0) => return bad("replay.hashlag_us", "must be at least 1"),
            Some(us) if us != 1000 && !c.dev => {
                return bad(
                    "replay.hashlag_us",
                    "other than 1000 (07 §3.7) is DEV only: set dev = true on a DEV validator",
                );
            }
            _ => {}
        }
        Ok(c)
    }

    fn observer(&self) -> bool {
        self.role == "observer"
    }
}

/// The epoch facts of this config (08; `vyrn-epoch`'s `Membership` replaces it once wired).
struct View {
    epoch: Epoch,
    book: BookId,
    seq_keys: Vec<PubKey>,
}

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
    fn book(&self) -> BookId {
        self.book
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        self.seq_keys.get(usize::from(sender)).copied()
    }
    fn fenced(&self, _height: Height) -> bool {
        false
    }
}

#[derive(Default)]
struct Stats {
    frames: AtomicU64,
    blocks: AtomicU64,
    faults: AtomicU64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // `VYRN_LOG=warn|info|debug`: Commonware's and the voter's logs on stderr (off by default).
    if let Some(level) = std::env::var("VYRN_LOG")
        .ok()
        .and_then(|l| l.parse::<tracing::Level>().ok())
    {
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_writer(std::io::stderr)
            .init();
    }
    let r = Config::load(&cli.config).and_then(|mut c| {
        if let Some(s) = c.consensus.as_mut() {
            s.fresh |= cli.fresh;
        }
        start(&c, cli.stop_on_stdin_eof)
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vyrn-validator: {e}");
            ExitCode::from(2)
        }
    }
}

fn start(cfg: &Config, stdin_stop: bool) -> Result<(), String> {
    // `OrderCore` takes the lane count as a type parameter.
    match cfg.lanes {
        1 => run::<1>(cfg, stdin_stop),
        2 => run::<2>(cfg, stdin_stop),
        3 => run::<3>(cfg, stdin_stop),
        4 => run::<4>(cfg, stdin_stop),
        8 => run::<8>(cfg, stdin_stop),
        11 => run::<11>(cfg, stdin_stop),
        49 => run::<49>(cfg, stdin_stop),
        _ => Err("config lanes must be 1-4, 8, 11 or 49".into()),
    }
}

fn run<const N: usize>(cfg: &Config, stdin_stop: bool) -> Result<(), String> {
    let seq_keys = cfg
        .membership
        .seq_keys
        .iter()
        .map(|k| hex32(k))
        .collect::<Result<_, _>>()?;
    let view = View {
        epoch: Epoch(cfg.epoch),
        book: BookId(cfg.book),
        seq_keys,
    };
    let plan = match (&cfg.consensus, &cfg.keys) {
        (Some(s), Some(k)) => Some(consensus::Plan::new(
            s,
            view.epoch,
            &k.vote,
            k.node.as_deref(),
        )?),
        _ => None,
    };
    // An observer's finality: the roster's committee, heard on `[observer] ctrl` (module docs).
    let (cert_tx, cert_rx) = std::sync::mpsc::channel();
    let mut cert_rx = cfg.observer.is_some().then_some(cert_rx);
    let observe = match (&cfg.consensus, &cfg.observer) {
        (Some(s), Some(o)) => {
            let sock = UdpSocket::bind(o.ctrl).map_err(|e| format!("observer.ctrl: {e}"))?;
            sock.set_read_timeout(Some(std::time::Duration::from_millis(20)))
                .map_err(|e| e.to_string())?;
            Some((consensus::committee(s, view.epoch)?, sock, cert_tx))
        }
        _ => None,
    };
    if plan
        .as_ref()
        .is_some_and(|p| view.seq_keys.first() != Some(&p.seq_key))
    {
        return Err("config membership.seq_keys[0] is not the roster's primary seq_key".into());
    }
    let layout = Layout::new(cfg.lanes, 1, 0).map_err(|e| e.to_string())?;
    let mut core: OrderCore<N, View> = OrderCore::new(layout, view).map_err(|e| e.to_string())?;
    if let Some(us) = cfg.replay.as_ref().and_then(|r| r.hashlag_us) {
        // DEV only (`Config::load`): a bound past the spec's 1 ms, for unpinned hosts.
        core.set_hashlag_max(us.saturating_mul(1000));
        eprintln!("vyrn-validator: DEV REP_E_HASHLAG bound {us} us (spec: 1000)");
    }
    let ip = cfg.nic.ip;
    let ncfg = NicConfig::new(BackendKind::Kernel, vec![PortConfig { id: PortId(0), ip }]);
    let mut nic = KernelUdp::open(&ncfg).map_err(|e| e.to_string())?;
    let bind = RxBind {
        lane: LaneId(0),
        port: PortId(0),
        ip,
        udp_port: cfg.nic.order_port,
    };
    let rx = nic.rx_ring(&bind).map_err(|e| e.to_string())?;
    let addr = rx.local_addr();
    // Keyed `[data]`: the `EPOCH <e>` control line's key derivation, and where its keys go.
    let mut control = None;
    let mut rekey = None;
    let rx_b = match cfg.nic.order_port_b {
        Some(udp_port) => Some(
            nic.rx_ring(&RxBind {
                lane: LaneId(2),
                port: PortId(0),
                ip,
                udp_port,
            })
            .map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    let addr_b = rx_b.as_ref().map(|r| r.local_addr());
    let data = match &cfg.data {
        Some(d) => {
            let drx = nic
                .rx_ring(&RxBind {
                    lane: LaneId(1),
                    port: PortId(0),
                    ip,
                    udp_port: cfg.nic.data_port,
                })
                .map_err(|e| e.to_string())?;
            let n = u8::try_from(d.boxes.len()).map_err(|_| "config data.boxes: too many")?;
            let ring = match (&d.xchg, &plan) {
                (None, _) => None,
                (Some(_), None) => {
                    return Err(
                        "config data.xchg needs [consensus]: K_fetch is derived from the roster"
                            .into(),
                    );
                }
                (Some(h), Some(p)) => Some((p.keyring(), consensus::resolve(h)?)),
            };
            let ks = match &ring {
                Some((kr, s)) => Some(derive_keys(kr, d, s, Epoch(cfg.epoch), cfg.dev)?),
                None => None,
            };
            let target = |addr, key| fetch::Target { addr, key };
            let boxes = d
                .boxes
                .iter()
                .enumerate()
                .map(|(b, a)| target(*a, ks.as_ref().and_then(|k| k.boxes.get(b).copied())))
                .collect();
            let peers = d
                .peer
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    target(
                        p.addr,
                        ks.as_ref().and_then(|k| k.peers.get(i).copied().flatten()),
                    )
                })
                .collect();
            let seq = d
                .seq_repair
                .map(|a| target(a, ks.as_ref().and_then(|k| k.seq)));
            let sources = fetch::Sources::new(boxes, peers, seq);
            let peer_addrs: Vec<SocketAddrV4> = d.peer.iter().map(|p| p.addr).collect();
            let keys = ks.as_ref().map_or_else(Vec::new, |k| k.boxes.clone());
            let mut down_auth =
                failover::DownAuth::new(d.peer.iter().map(|p| (p.voter, *p.addr.ip())).collect());
            if let Some(k) = &ks {
                down_auth.set_keys(k.serve.clone(), &k.peers);
            }
            let peer = fetch::PeerServer::new(&peer_addrs, ks.map(|k| serve_keys(&k.serve)));
            if let Some((kr, _)) = ring {
                let (tx, rx) = std::sync::mpsc::channel();
                rekey = Some(rx);
                control = Some((kr, d.clone(), tx));
            }
            // A box keys a requester by its repl_addr's IPv4 (08 §9.6), so fetches leave from
            // [nic] ip: the reading is that it is this voter's repl_addr IP.
            let repair = UdpSocket::bind(SocketAddrV4::new(ip, 0)).map_err(|e| e.to_string())?;
            repair.set_nonblocking(true).map_err(|e| e.to_string())?;
            println!("DATA rx={}", drx.local_addr());
            Some(DataRx {
                feed: DataFeed::new(BookId(cfg.book), n, d.me),
                join: DataJoin::default(),
                replay: None,
                replay_dead: false,
                pending: VecDeque::new(),
                durable_wait: None,
                rx: drx,
                repair,
                boxes: d.boxes.clone(),
                keys,
                max_range: d.max_range,
                fetches: VecDeque::new(),
                sources,
                peer,
                unfinal: VecDeque::new(),
                certs: cert_rx.take(),
                tips: VecDeque::new(),
                replayed: None,
                rekey: rekey.take(),
                failover: plan.as_ref().map(|p| {
                    failover::Failover::new(
                        n,
                        u8::try_from(p.me).unwrap_or(u8::MAX),
                        p.committee.quorum(),
                        cfg.epoch,
                        d.silence_us.saturating_mul(1000),
                    )
                }),
                down_auth,
            })
        }
        None => None,
    };
    let mut data = data;
    if let (Some(r), Some(d)) = (&cfg.replay, data.as_mut()) {
        let n = u8::try_from(N).map_err(|e| e.to_string())?;
        let join = std::mem::take(&mut d.join);
        let mut rep = Box::new(replay::open(
            r,
            n,
            BookId(cfg.book),
            Epoch(cfg.epoch),
            join,
            replay::Out::Discard,
        )?);
        // The ring replaces any ring at its path, so only once the replay is built.
        if let Some(o) = &cfg.observer {
            *rep.payloads_and_sink().1 =
                replay::observer(&o.ring, o.ring_cap, BookId(cfg.book), Epoch(cfg.epoch), N)?;
        }
        d.replay = Some(rep);
        println!("REPLAY lanes={n} sessions={}", r.session.len());
    }
    let view_epoch = Epoch(cfg.epoch);
    // The observer's finality thread stops first, so the order thread's last drain sees every
    // certificate it accepted.
    let obs_stop = Arc::new(AtomicBool::new(false));
    let source = if plan.is_some() {
        consensus::Source::new()
    } else {
        consensus::Source::default()
    };
    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let order = {
        let (stats, stop, source) = (Arc::clone(&stats), Arc::clone(&stop), source.clone());
        let gate = cfg.observer();
        // Path B's receive context (`vyrn_replica::Paths`): this book, epoch and sequencers.
        let senders = u8::try_from(cfg.membership.seq_keys.len()).unwrap_or(u8::MAX);
        let ctx = (BookId(cfg.book), Epoch(cfg.epoch).low16(), senders);
        let repair = match &cfg.repair {
            Some(r) => Some(Rep {
                sock: UdpSocket::bind(SocketAddrV4::new(ip, 0)).map_err(|e| e.to_string())?,
                to: r.nack,
                ports: [
                    r.order_as.unwrap_or(addr.port()),
                    r.order_b_as.or(addr_b.map(|b| b.port())).unwrap_or(0),
                ],
                timers: Repair {
                    hole_wait_ns: r.hole_wait_us.saturating_mul(1000),
                    retry_ns: r.retry_us.saturating_mul(1000),
                    tries: r.tries,
                },
            }),
            None => None,
        };
        std::thread::Builder::new()
            .name("vyrn-validator/order".into())
            .spawn(move || {
                order_thread(
                    core,
                    [Some(rx), rx_b],
                    data,
                    gate,
                    ctx,
                    repair,
                    &source,
                    &stop,
                    &stats,
                )
            })
            .map_err(|e| e.to_string())?
    };
    let observer = match observe {
        Some((committee, sock, certs)) => {
            println!(
                "OBSERVER ctrl={}",
                sock.local_addr().map_err(|e| e.to_string())?
            );
            let (stop, source, epoch) = (Arc::clone(&obs_stop), source.clone(), view_epoch);
            Some(
                std::thread::Builder::new()
                    .name("vyrn-validator/observer".into())
                    .spawn(move || {
                        consensus::observe(committee, epoch, &sock, &source, &certs, &stop)
                    })
                    .map_err(|e| e.to_string())?,
            )
        }
        None => None,
    };
    let voter = match plan {
        Some(plan) => {
            println!("CONSENSUS voter={} repl={}", plan.me, plan.repl_addr());
            let stop = Arc::clone(&stop);
            Some(
                std::thread::Builder::new()
                    .name("vyrn-validator/voter".into())
                    .spawn(move || {
                        // However the voter ends, an error or a panic included, the order
                        // thread stops too, so main joins both and reports the failure.
                        let _stop = StopOnDrop(&stop);
                        consensus::run(plan, source, &stop)
                    })
                    .map_err(|e| e.to_string())?,
            )
        }
        None => None,
    };
    let core_of = cfg
        .cores
        .order
        .map_or_else(|| "unpinned".into(), |c| c.to_string());
    println!("LAYOUT order={core_of} control=main");
    if let Some(b) = addr_b {
        println!("ORDER_B order={b}");
    }
    println!("READY vyrn-validator order={addr}");
    let (eof_tx, eof_rx) = std::sync::mpsc::channel::<()>();
    {
        // Control lines on stdin (crate docs, Control); EOF stops with `--stop-on-stdin-eof`.
        let dev = cfg.dev;
        std::thread::Builder::new()
            .name("vyrn-validator/stdin".into())
            .spawn(move || {
                for line in std::io::stdin().lines() {
                    let Ok(line) = line else { break };
                    match control_line(&line, control.as_ref(), dev) {
                        Ok(Some(ack)) => println!("{ack}"),
                        Ok(None) => {}
                        Err(e) => eprintln!("CONTROL_ERR {e}"),
                    }
                }
                let _ = eof_tx.send(());
            })
            .map_err(|e| e.to_string())?;
    }
    if stdin_stop {
        let _ = eof_rx.recv();
    }
    // Shutdown (stdin EOF): the finality thread stops and is joined first, so the order
    // thread's last drain sees every certificate it accepted. Without `--stop-on-stdin-eof`
    // both run until the process is killed.
    let stop_observer = |o: std::thread::JoinHandle<u64>| -> Result<(), String> {
        obs_stop.store(true, Ordering::Release);
        let refused = o.join().map_err(|_| "observer thread panicked")?;
        println!("FINALITY refused={refused}");
        Ok(())
    };
    let mut observer = observer;
    if stdin_stop {
        if let Some(o) = observer.take() {
            stop_observer(o)?;
        }
        stop.store(true, Ordering::Release);
    }
    let evicted = order.join().map_err(|_| "order thread panicked")?;
    if let Some(o) = observer {
        stop_observer(o)?;
    }
    if let Some(v) = voter {
        stop.store(true, Ordering::Release);
        v.join().map_err(|_| "voter thread panicked")??;
    }
    let g = |c: &AtomicU64| c.load(Ordering::Acquire);
    println!(
        "STATS frames={} blocks={} faults={}",
        g(&stats.frames),
        g(&stats.blocks),
        g(&stats.faults)
    );
    if let Some(e) = evicted {
        println!("DATA_EVICT expired={} capped={}", e.expired, e.capped);
    }
    Ok(())
}

/// How long an idle order thread sleeps (`kernel_udp`, DEV).
const IDLE: std::time::Duration = std::time::Duration::from_micros(50);

/// The data RX queue and the join it fills (07 §5.4).
struct DataRx<const N: usize, R> {
    feed: DataFeed,
    join: DataJoin,
    /// With `[replay]`: the engine, which then owns the join ([`DataRx::join`]).
    replay: Option<Box<replay::Replay>>,
    /// Replay diverged or a block's data faulted: later blocks are no longer replayed.
    replay_dead: bool,
    /// Ready blocks whose ORDER part passed, waiting for their payloads (item 3), each with
    /// the frames it needs on both paths before an observer replays it.
    pending: VecDeque<(BlockInputs<N>, Option<Mark>)>,
    rx: R,
    /// Fetches go out on this socket and their answers come back to it: a data box answers a
    /// KEY fetch to the fetch's source address (07 §5.5), and a `kernel_udp` TX ring sends from
    /// an ephemeral socket nothing polls. RANGE answers come to `rx` as data frames.
    repair: UdpSocket,
    boxes: Vec<std::net::SocketAddrV4>,
    /// `K_fetch` per box, by index (`[data] xchg`); empty: fetches go unsealed (DEV).
    keys: Vec<[u8; 16]>,
    max_range: u64,
    /// Gaps not fully fetched yet, with the box to ask: at most `FETCH_BURST` RANGE fetches go
    /// out per poll and a gap's `from` moves past them. One entry per gap, however long.
    fetches: VecDeque<(u8, Gap)>,
    /// KEY fetches for the payload the front pending block waits for (07 §5.5).
    sources: fetch::Sources,
    /// Peers' KEY fetches, answered from the join (07 §5.5 source 2).
    peer: fetch::PeerServer,
    /// Observer: replayed blocks not final yet, with their last step and header hash.
    unfinal: VecDeque<(Height, StepId, Hash)>,
    /// Observer: certified tips `(last_height, last_hash)` from `consensus::observe`, and the
    /// ones whose block has not replayed yet.
    certs: Option<std::sync::mpsc::Receiver<(Height, Hash)>>,
    tips: VecDeque<(Height, Hash)>,
    /// Observer: the newest replayed height.
    replayed: Option<Height>,
    /// With `[consensus]`: data box failure, 07 §5.7 steps 1–3 (`failover.rs`).
    failover: Option<failover::Failover>,
    /// Who a peer's `DataDown` may come from, under which keys (`failover.rs`).
    down_auth: failover::DownAuth,
    /// Keyed: the key sets `EPOCH <e>` derived, applied at the next poll.
    rekey: Option<std::sync::mpsc::Receiver<(u32, KeySet)>>,
    /// Observer: the block waiting for both paths' frames, and since when (`u64::MAX`: reported).
    durable_wait: Option<(Height, u64)>,
}

/// Every `K_fetch` a keyed validator seals or serves fetches under in one epoch (07 §5.5,
/// 08 §9.6), by `[data]` index.
struct KeySet {
    boxes: Vec<[u8; 16]>,
    peers: Vec<Option<[u8; 16]>>,
    seq: Option<[u8; 16]>,
    /// Peer keys of epochs `e - 1`, `e` and `e + 1` (peers move one at a time), with each
    /// requester's voter index: peer fetches are served under them, and a `DataDown` counts only
    /// under its claimed voter's.
    serve: Vec<(u8, Ipv4Addr, [u8; 16])>,
}

/// The `(IPv4, key)` pairs a peer fetch is served under.
fn serve_keys(serve: &[(u8, Ipv4Addr, [u8; 16])]) -> Vec<(Ipv4Addr, [u8; 16])> {
    serve.iter().map(|(_, ip, k)| (*ip, *k)).collect()
}

/// Derives epoch `e`'s [`KeySet`] (cold path). A box without a key, or a peer or seq box
/// whose roster key is unusable, is an error unless `dev`: then the latter is sent the
/// 32-byte form (07 §5.5).
fn derive_keys(
    kr: &consensus::Keyring,
    d: &Data,
    secret: &[u8; 32],
    e: Epoch,
    dev: bool,
) -> Result<KeySet, String> {
    let boxes = (0..d.boxes.len())
        .map(|b| {
            u8::try_from(b)
                .ok()
                .and_then(|b| kr.fetch_key(e, vyrn_epoch::FETCH_CONTEXT, b, secret))
                .ok_or_else(|| format!("config data.xchg: no K_fetch for box {b} (08 §9.6)"))
        })
        .collect::<Result<_, String>>()?;
    let key = |context: &str, t: u8| match kr.fetch_key(e, context, t, secret) {
        Some(k) => Ok(Some(k)),
        None if dev => {
            eprintln!("vyrn-validator: fetch target {t:#04x} has no K_fetch; unsealed (DEV)");
            Ok(None)
        }
        None => Err(format!(
            "fetch target {t:#04x} has no usable roster xchg_key: unsealed fetches are DEV only \
             (07 §5.5; set dev = true on a DEV validator)"
        )),
    };
    let peers = d
        .peer
        .iter()
        .map(|p| {
            key(
                consensus::PEER_FETCH_CONTEXT,
                vyrn_epoch::VOTER_TARGET.saturating_add(p.voter),
            )
        })
        .collect::<Result<_, String>>()?;
    let seq = match d.seq_repair {
        Some(_) => key(
            vyrn_epoch::FETCH_CONTEXT,
            vyrn_epoch::SEQ_TARGET.saturating_add(d.seq_box),
        )?,
        None => None,
    };
    // Served under e - 1 too: peers move one at a time, and one still on e - 1 must be served
    // until it moves; e + 1 for one that moved first.
    let mut serve = Vec::new();
    for ep in [e.0.checked_sub(1), Some(e.0), e.0.checked_add(1)]
        .into_iter()
        .flatten()
    {
        serve.extend(kr.peer_keys(Epoch(ep), secret)?);
    }
    if serve.is_empty() {
        eprintln!(
            "vyrn-validator: keyed, but no peer has a usable K_fetch; serving no peer fetches"
        );
    }
    Ok(KeySet {
        boxes,
        peers,
        seq,
        serve,
    })
}

/// What `EPOCH <e>` derives keys from, and where it sends them with their epoch.
type Control = (
    consensus::Keyring,
    Data,
    std::sync::mpsc::Sender<(u32, KeySet)>,
);

/// One stdin control line (cold path). `EPOCH <e>` re-derives every `K_fetch` for epoch `e`,
/// and hands it to the order thread, which acks `FETCH_EPOCH <e>` once the keys are installed;
/// empty lines are ignored.
fn control_line(
    line: &str,
    control: Option<&Control>,
    dev: bool,
) -> Result<Option<String>, String> {
    let mut w = line.split_whitespace();
    match (w.next(), w.next().map(str::parse::<u32>), w.next()) {
        (None, ..) => Ok(None),
        (Some("EPOCH"), Some(Ok(e)), None) => {
            let Some((kr, d, tx)) = control else {
                return Err("EPOCH needs a keyed [data] (data.xchg)".into());
            };
            let secret = consensus::resolve(d.xchg.as_deref().unwrap_or_default())?;
            let ks = derive_keys(kr, d, &secret, Epoch(e), dev)?;
            tx.send((e, ks))
                .map_err(|_| "the order thread has stopped")?;
            // The order thread acks `FETCH_EPOCH <e>` once it has installed the keys.
            Ok(None)
        }
        _ => Err(format!("unknown control line {:?}", line.trim())),
    }
}

/// 07 §4.9 `REP_PATH_DOWN_MS`: how long a block waits on one path before `DURABLE_WAIT`.
const REP_PATH_DOWN_NS: u64 = 100_000_000;

/// Observer: the most replayed blocks that may wait for finality, and the most certified tips
/// that may wait for replay, before replay stops. Far above
/// `FIN_GATE_BLOCKS` (8), past which the sequencer itself halts (07 §6.8).
const OBS_MAX_UNFINAL: usize = 1024;

/// RANGE fetches sent per data poll.
const FETCH_BURST: usize = 16;

impl<const N: usize, R: RxRing> DataRx<N, R> {
    /// The join the feed fills and item 3 reads: the replay's when it runs.
    fn join<'a>(
        join: &'a mut DataJoin,
        rep: &'a mut Option<Box<replay::Replay>>,
    ) -> &'a mut DataJoin {
        match rep {
            Some(r) => r.payloads_mut(),
            None => join,
        }
    }

    /// Polls the queue and the repair socket once; sends queued fetches. Returns the datagrams
    /// taken.
    fn poll(&mut self, now: u64) -> usize {
        let rekeyed: Vec<(u32, KeySet)> = self
            .rekey
            .as_ref()
            .map_or_else(Vec::new, |r| r.try_iter().collect());
        if !rekeyed.is_empty() {
            let mut acks = Vec::new();
            for (e, ks) in rekeyed {
                self.sources.set_keys(&ks.boxes, &ks.peers, ks.seq);
                self.down_auth.set_keys(ks.serve.clone(), &ks.peers);
                self.peer.set_keys(serve_keys(&ks.serve));
                self.keys = ks.boxes;
                if let Some(f) = self.failover.as_mut() {
                    f.epoch = e;
                }
                acks.push(e);
            }
            // Acked only once installed: a box may drop the old epoch's keys after it.
            for e in acks {
                println!("FETCH_EPOCH {e}");
            }
        }
        let mut burst = [RxPkt::empty(); RX_BURST];
        let k = self.rx.poll(&mut burst);
        let mut gaps = Vec::new();
        for p in burst.iter().take(k) {
            let Ok(f) = frame::parse(self.rx.bytes(p)) else {
                continue;
            };
            // A peer's KEY fetch: answered to its source, from the join (07 §5.5 source 2).
            if f.payload.get(..2) == Some(&vyrn_data::frame::FETCH_MAGIC.to_le_bytes()[..]) {
                let join = Self::join(&mut self.join, &mut self.replay);
                let from = f.hdr.src;
                let to = SocketAddrV4::new(from.ip, from.port);
                for r in self
                    .peer
                    .serve(join, to, f.payload, now, &mut self.sources.counts)
                {
                    let _ = self.repair.send_to(&r, to);
                }
                continue;
            }
            // A peer's `DataDown{d}` (07 §5.7 step 1).
            if f.payload.get(..2) == Some(&failover::MAGIC.to_le_bytes()[..]) {
                if let Some(fo) = self.failover.as_mut() {
                    match failover::DataDown::parse(f.payload) {
                        Some((m, body, tag))
                            if self.down_auth.authentic(f.hdr.src.ip, m.voter, &body, tag) =>
                        {
                            fo.heard(m);
                        }
                        _ => fo.counts.down_bad = fo.counts.down_bad.saturating_add(1),
                    }
                }
                continue;
            }
            if let Ok(fed) =
                self.feed
                    .on_frame(Self::join(&mut self.join, &mut self.replay), f.payload, now)
                && let Some(g) = fed.gap
            {
                gaps.push(g);
            }
        }
        self.rx.release(k);
        // Answers to KEY fetches, on the repair socket: at most `RX_BURST` per poll, like the
        // data queue, so a flood of datagrams cannot hold the order thread here.
        let mut buf = [0u8; frame::MAX_FRAME_BYTES];
        let mut answers = 0;
        while answers < RX_BURST
            && let Ok(n) = self.repair.recv(&mut buf)
        {
            answers += 1;
            if let Ok(fed) = self.feed.on_frame(
                Self::join(&mut self.join, &mut self.replay),
                buf.get(..n).unwrap_or(&[]),
                now,
            ) && let Some(g) = fed.gap
            {
                gaps.push(g);
            }
        }
        for g in gaps {
            if self.boxes.get(usize::from(g.src)).is_some() {
                self.fetches.push_back((g.src, g));
            }
        }
        let mut budget = FETCH_BURST;
        while budget > 0
            && let Some((to, g)) = self.fetches.front_mut()
        {
            let mut done = g.from > g.to;
            for q in g.fetches(self.max_range).take(budget).collect::<Vec<_>>() {
                budget -= 1;
                if let Fetch::Range { to, .. } = q {
                    match to.checked_add(1) {
                        Some(next) if next <= g.to => g.from = next,
                        _ => done = true,
                    }
                }
                // UDP: a lost fetch is retried by key while its payload stays missing.
                send(&self.repair, &self.boxes, &self.keys, &q, usize::from(*to));
            }
            if done {
                self.fetches.pop_front();
            }
        }
        self.failover(now);
        k + answers
    }

    /// 07 §5.7: gossips this replica's `DataDown`s, and once one is effective for the sessions'
    /// home sends every live box each session's REDIRECT (`failover.rs`).
    fn failover(&mut self, now: u64) {
        let Some(fo) = self.failover.as_mut() else {
            return;
        };
        let silent: Vec<u8> = self.feed.silent_for(now, fo.silence_ns).collect();
        for m in fo.silent(&silent, now) {
            for t in self.sources.peers() {
                let _ = self
                    .repair
                    .send_to(&m.encode(t.key.as_ref()), std::net::SocketAddr::V4(t.addr));
                fo.counts.down_sent = fo.counts.down_sent.saturating_add(1);
            }
        }
        let (newly, due) = fo.step(now);
        for (d, votes) in newly {
            println!("DATA_DOWN box={d} votes={votes} quorum={}", fo.quorum());
        }
        let live: Vec<usize> = (0..self.boxes.len()).filter(|&b| fo.live(b)).collect();
        if !due.is_empty() {
            // Every client record of a pending block counts, resolved here or not: a block
            // that is not final may hold a payload only this replica has (reading t).
            let mut pending = std::collections::BTreeMap::new();
            for (b, _) in &self.pending {
                for r in &b.lanes {
                    let LaneRec::Pkt(p) = r else { continue };
                    if p.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) != 0 {
                        continue;
                    }
                    let e = pending.entry(p.session).or_insert(p.pkt_seq);
                    *e = (*e).min(p.pkt_seq);
                }
            }
            let list = fo.resend_from(&pending);
            for (down, to) in due {
                fo.queue(down, to, &list);
                println!(
                    "REDIRECT_SENT down={down} to={to} sessions={} boxes={}",
                    list.len(),
                    live.len()
                );
            }
        }
        // Paced under the boxes' fetch bucket (`failover::REDIRECT_MSGS`): one message of up to
        // MAX_BATCH sessions is one token; a single session stays kind 4.
        for m in fo.batch(now) {
            for &b in &live {
                match m.entries.as_slice() {
                    &[(session, resend_from)] => {
                        let q = Fetch::Redirect {
                            session,
                            resend_from,
                            down: m.down,
                            to: m.to,
                        };
                        send(&self.repair, &self.boxes, &self.keys, &q, b);
                    }
                    es => send_batch(&self.repair, &self.boxes, &self.keys, &m, es, b),
                }
                fo.counts.redirect_msgs = fo.counts.redirect_msgs.saturating_add(1);
                let n = u64::try_from(m.entries.len()).unwrap_or(u64::MAX);
                fo.counts.redirects = fo.counts.redirects.saturating_add(n);
            }
        }
    }

    /// Item 3 for the pending blocks, in height order: a block whose payloads are all joined
    /// passes or contradicts; a missing payload waits. A payload still missing
    /// `REP_DATA_WAIT_US` after it was first seen missing is fetched by key, from each of 07
    /// §5.5's sources in turn (`fetch.rs`), so a lost RANGE request or reply, or a data box that
    /// lacks it, does not stall the queue.
    ///
    /// With `durable` (an observer), a block also waits until every frame through its [`Mark`]
    /// arrived on both paths (10 §8.2), so the drop copy's `flags.bit2` holds.
    fn check(&mut self, source: &consensus::Source, now: u64, durable: Option<&Paths>) {
        // `final_height` is 0 before the first certificate too: height 0 waits for one above it.
        if let (Some(fo), f @ 1..) = (self.failover.as_mut(), source.final_height()) {
            fo.finalized(f);
        }
        while let Some((b, m)) = self.pending.front() {
            let h = b.header.height;
            let held = !self.replay_dead
                && durable.is_some_and(|p| m.as_ref().is_none_or(|m| !p.durable(m)));
            if held && self.pending.len() >= OBS_MAX_UNFINAL {
                // Held this long, the path will not come back without repair: stop replaying,
                // so the blocks below release their payloads instead of piling up.
                println!(
                    "DURABLE_FAULT height={} {OBS_MAX_UNFINAL} blocks wait for both paths",
                    h.0
                );
                self.replay_dead = true;
            } else if held {
                // A path lost one of its frames (no repair yet, 07 §4.10): printed once, after
                // REP_PATH_DOWN_MS, so a held block is visible.
                match self.durable_wait {
                    Some((w, _)) if w != h => self.durable_wait = Some((h, now)),
                    Some((_, t)) if now.saturating_sub(t) >= REP_PATH_DOWN_NS => {
                        println!("DURABLE_WAIT height={}", h.0);
                        self.durable_wait = Some((h, u64::MAX));
                    }
                    Some(_) => {}
                    None => self.durable_wait = Some((h, now)),
                }
                return;
            }
            // A gated observer that stopped replaying (`DURABLE_FAULT` and the like) attests
            // nothing more: its blocks release their payloads without waiting for them.
            if !(self.replay_dead && durable.is_some()) {
                match Self::join(&mut self.join, &mut self.replay).check(b) {
                    Err(DataErr::Missing { session, pkt_seq }) => {
                        let to = self.sources.due(session, pkt_seq, now);
                        fetch::send_key(&self.repair, session, pkt_seq, &to);
                        return;
                    }
                    Ok(()) => source.valid(h),
                    Err(_) => {
                        source.invalid_from(h);
                        println!("DATA_FAULT height={}", h.0);
                        self.replay_dead = true;
                    }
                }
            }
            let Some((b, _)) = self.pending.pop_front() else {
                return;
            };
            if let Some(fo) = self.failover.as_mut() {
                fo.released(
                    h.0,
                    b.lanes.iter().filter_map(|r| match r {
                        // A shed record was never accepted: it moves no watermark (Codex
                        // r4612821627).
                        LaneRec::Pkt(p)
                            if p.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) == 0 =>
                        {
                            Some((p.session, p.pkt_seq))
                        }
                        _ => None,
                    }),
                );
            }
            // Every path below releases the block's payloads: peers may still ask for them.
            self.peer
                .keep(Self::join(&mut self.join, &mut self.replay), &b.lanes);
            match (&mut self.replay, self.replay_dead) {
                (Some(r), false) => match replay::block(r, &b) {
                    Ok(out) => {
                        println!("{} out={}", block_line(&b, Verdict::Valid), hex(&out.0));
                        if matches!(r.payloads_and_sink().1, replay::Out::Observer(_)) {
                            self.replayed = Some(h);
                            if self.unfinal.len() >= OBS_MAX_UNFINAL {
                                // Finality input lost: stop rather than grow without bound.
                                println!(
                                    "FINALITY_FAULT height={} {OBS_MAX_UNFINAL} replayed blocks wait for finality",
                                    h.0
                                );
                                self.replay_dead = true;
                            } else {
                                self.unfinal.push_back((
                                    h,
                                    b.header.last_step,
                                    vyrn_log::block::header_hash(&b.header),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        self.replay_dead = true;
                        println!("{}", block_line(&b, Verdict::Valid));
                        println!("REPLAY_FAULT height={} {e}", h.0);
                        r.payloads_mut().release(h, &b.lanes);
                    }
                },
                (Some(r), true) => {
                    println!("{}", block_line(&b, Verdict::Valid));
                    r.payloads_mut().release(h, &b.lanes);
                }
                // Without replay nothing else reads these payloads.
                (None, _) => self.join.release(h, &b.lanes),
            }
            // A gated observer replays at most one block per order-thread turn: the gate
            // releases blocks in bursts, and replaying a burst inline would leave ORDER and
            // HASH frames unpolled long enough to trip `REP_E_HASHLAG` for the frames still in
            // the socket (a frame's wait runs from its `rx_ts`, but a burst is only read once
            // the thread polls).
            if durable.is_some() && !self.replay_dead {
                return;
            }
        }
    }

    /// Observer: one `DC_FINAL` per replayed block up to each certified tip, in order, once the
    /// tip's block has replayed and its header hash is the certificate's `last_hash` (the
    /// `prev` links of the replayed chain then commit to every block below it). A tip whose
    /// block has not replayed yet waits. A hash that differs means this observer replayed
    /// another chain than the one certified: `FINALITY_FAULT`, and nothing more is marked final.
    /// A ring error stops replay as in [`DataRx::check`].
    fn finals(&mut self) {
        if let Some(rx) = &self.certs {
            if self.replay_dead {
                // Nothing more is marked final after a fault (the drop copy is rebuilt from
                // the log, 03 §7): take certificates without keeping them.
                rx.try_iter().for_each(drop);
                self.tips.clear();
                return;
            }
            self.tips.extend(rx.try_iter());
            if self.tips.len() > OBS_MAX_UNFINAL {
                // The voters finalize blocks this observer has not replayed (a stalled order
                // stream): stop rather than keep certificates without bound.
                println!(
                    "FINALITY_FAULT height={} {OBS_MAX_UNFINAL} certified tips wait for replay",
                    self.tips.back().map_or(0, |t| t.0.0)
                );
                self.replay_dead = true;
                self.tips.clear();
                return;
            }
        }
        let Some(r) = self.replay.as_mut() else {
            return;
        };
        while !self.replay_dead
            && let Some(&(tip, hash)) = self.tips.front()
        {
            let Some(at) = self.unfinal.iter().position(|u| u.0 == tip) else {
                if self.replayed.is_some_and(|r| tip <= r) {
                    // Replayed and already marked final by a later tip.
                    self.tips.pop_front();
                    continue;
                }
                return; // its block has not replayed yet
            };
            self.tips.pop_front();
            if self.unfinal.get(at).map(|u| u.2) != Some(hash) {
                println!(
                    "FINALITY_FAULT height={} replayed chain differs from the certified one",
                    tip.0
                );
                self.replay_dead = true;
                return;
            }
            for (h, last, _) in self.unfinal.drain(..=at) {
                let out = r.payloads_and_sink().1;
                out.final_block(h, last);
                if let Some(e) = out.error() {
                    println!("REPLAY_FAULT height={} output ring: {e}", h.0);
                    self.replay_dead = true;
                    return;
                }
            }
        }
    }
}

/// Sends `q` to box `d`: the 40-byte form under its `K_fetch` when keyed, else the 32 bytes.
/// A REDIRECT_BATCH (kind 5) to box `d`, sealed under its `K_fetch` when keyed (07 §5.7).
fn send_batch(
    repair: &UdpSocket,
    boxes: &[SocketAddrV4],
    keys: &[[u8; 16]],
    m: &failover::Msg,
    entries: &[(vyrn_types::SessionId, u32)],
    d: usize,
) {
    use vyrn_data::frame::RedirectBatch;
    let Some(to) = boxes.get(d) else {
        return;
    };
    let b = match keys.get(d) {
        Some(k) => RedirectBatch::seal(k, m.down, m.to, entries),
        None => RedirectBatch::encode(m.down, m.to, entries),
    };
    // `Msg` keeps the batch rules (positions, 1 ..= MAX_BATCH, ascending), so encoding holds.
    if let Ok(b) = b {
        let _ = repair.send_to(&b, to);
    }
}

fn send(repair: &UdpSocket, boxes: &[SocketAddrV4], keys: &[[u8; 16]], q: &Fetch, d: usize) {
    let Some(to) = boxes.get(d) else {
        return;
    };
    let _ = match keys.get(d) {
        Some(k) => repair.send_to(&vyrn_data::frame::seal_fetch(k, q), to),
        None => repair.send_to(&q.encode(), to),
    };
}

/// The order thread's repair state: where Nacks go, this box's ORDER port per path (each
/// Nack's `port`), and the timers.
struct Rep {
    sock: UdpSocket,
    to: SocketAddrV4,
    ports: [u16; 2],
    timers: Repair,
}

/// Sets the flag when dropped.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// The most frames `order_thread` holds back for its next poll behind a full burst; past it a
/// frame goes to the core at once.
const CARRY_MAX: usize = 4 * RX_BURST;

/// `rxs`: path A's ORDER queue and, with `order_port_b`, path B's. With both, frames go through
/// [`Paths`] (07 §4.9); with `gate` (an observer) a block replays only once its frames are held
/// from both (10 §8.2).
#[allow(clippy::too_many_arguments)]
fn order_thread<const N: usize, R: RxRing, D: RxRing>(
    mut core: OrderCore<N, View>,
    mut rxs: [Option<R>; 2],
    mut data: Option<DataRx<N, D>>,
    gate: bool,
    ctx: (BookId, u16, u8),
    repair: Option<Rep>,
    source: &consensus::Source,
    stop: &AtomicBool,
    stats: &Stats,
) -> Option<Evictions> {
    let mut last_final = 0;
    let t0 = Instant::now();
    let now = || u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut bursts = [[RxPkt::empty(); RX_BURST]; 2];
    // Frames held back to the next poll behind a full burst, and one poll's receive order.
    let mut carry: Vec<(u64, usize, Vec<u8>)> = Vec::new();
    let mut order: Vec<(u64, u8, usize, usize)> = Vec::with_capacity(2 * RX_BURST + CARRY_MAX);
    let mut faulted = false;
    let mut stalled = false;
    // Two paths, or path A alone with `[repair]` (reorder and gap repair, 07 §4.9).
    let mut paths = match (rxs[1].is_some(), repair.is_some()) {
        (true, _) => Some(Paths::new(ctx.0, ctx.1, ctx.2)),
        (false, true) => Some(Paths::new(ctx.0, ctx.1, ctx.2).one_path()),
        (false, false) => None,
    };
    let mut asks = Vec::new();
    let mut rep_stats = [0u64; 3]; // nacks sent, gaps given up, NackTooOld received
    // Gated observer only: the newest frame the order core accepted per substream. A block's
    // mark is its value when the block becomes ready (`report` queues it), not at the end of
    // the poll. A frame the core refuses (another tenure's, out of order) is not in it.
    let track = gate && paths.is_some();
    let mut frontier: std::collections::BTreeMap<vyrn_replica::paths::Key, u64> =
        std::collections::BTreeMap::new();
    while !stop.load(Ordering::Acquire) {
        let mut k = 0;
        let mut delivered = 0usize;
        // `REP_E_HASHLAG` runs from each frame's receive time (07 §3.7): its `rx_ts`
        // (CLOCK_REALTIME, the kernel's stamp under kernel_udp) moved onto this thread's
        // monotonic clock by the offset read at this poll, so a frame that waited in the socket
        // while the thread was descheduled is not counted late. Both paths are polled first and
        // their frames go to the core in receive order, so a late frame on one path cannot
        // advance the deadlines past a timely HashRun still unread on the other. A path whose
        // burst came back full may hold more unread frames, none received before its last one
        // read: the other path's frames received after that wait, copied, for the next poll
        // (at most `CARRY_MAX`), and are merged in receive order there.
        let mut n = [0usize; 2];
        for (rx, (b, n)) in rxs.iter_mut().zip(bursts.iter_mut().zip(&mut n)) {
            if let Some(rx) = rx {
                *n = rx.poll(b);
            }
        }
        let (mono, real) = (now(), realtime_ns());
        let at_of = |p: &RxPkt| mono.saturating_sub(real.saturating_sub(p.rx_ts().0));
        let cap = (0..2)
            .filter(|&i| n[i] == RX_BURST)
            .filter_map(|i| bursts[i].get(RX_BURST - 1).map(at_of))
            .min()
            .unwrap_or(u64::MAX);
        k += n[0] + n[1];
        let carried = std::mem::take(&mut carry);
        // (receive time, 0 for a carried frame else 1, source, index): carried frames first on
        // a tie, as they were read earlier; the source is 2 for `carried`, else the path.
        order.clear();
        order.extend((0..carried.len()).map(|c| (carried[c].0, 0u8, 2usize, c)));
        for (pi, (b, &m)) in bursts.iter().zip(&n).enumerate() {
            order.extend(
                b.iter()
                    .take(m)
                    .enumerate()
                    .map(|(x, p)| (at_of(p), 1, pi, x)),
            );
        }
        order.sort_unstable();
        for &(at, _, src, x) in &order {
            let (pi, bytes) = match (src, carried.get(x)) {
                (2, Some(c)) => (c.1, c.2.as_slice()),
                _ => (
                    src,
                    rxs.get(src)
                        .and_then(Option::as_ref)
                        .zip(bursts.get(src).and_then(|b| b.get(x)))
                        .map_or(&[][..], |(rx, p)| rx.bytes(p)),
                ),
            };
            if at > cap && carry.len() < CARRY_MAX {
                carry.push((at, pi, bytes.to_vec()));
                continue;
            }
            let path = if pi == 0 { RepPath::A } else { RepPath::B };
            let Ok(f) = frame::parse(bytes) else {
                continue;
            };
            // The sequencer's answer to a Nack for frames its ring no longer holds.
            if let (Some(t), Some(ps)) = (NackTooOld::decode(f.payload), paths.as_mut()) {
                rep_stats[2] = rep_stats[2].saturating_add(1);
                ps.too_old(t.path, t.epoch16, t.tenure, t.stream, t.oldest_seq);
                continue;
            }
            stats.frames.fetch_add(1, Ordering::Relaxed);
            // Deadlines stop at the oldest frame `Paths` holds behind a gap (07 §3.7).
            let hm = paths.as_ref().map_or(u64::MAX, Paths::held_min);
            let mut on = |payload: &[u8], at: u64| {
                delivered += 1;
                // A frame past `cap` that the full carry let through still keeps the deadlines at
                // `cap`, as its path's unread frames may hold a timely HashRun.
                let r = core.on_frame_at(payload, at, at.min(hm).min(cap));
                if track
                    && !matches!(r, Err(FrameErr::OutOfOrder))
                    && let Some((key, q)) = vyrn_replica::paths::frame_key(payload)
                {
                    frontier.insert(key, q);
                }
                report(
                    &mut core,
                    r,
                    &mut faulted,
                    &mut stalled,
                    stats,
                    source,
                    data.as_mut(),
                );
                if let Some(d) = data.as_mut().filter(|_| track) {
                    for x in d.pending.iter_mut().filter(|x| x.1.is_none()) {
                        x.1 = Some(frontier.iter().map(|(k, q)| (*k, *q)).collect());
                    }
                }
            };
            match paths.as_mut() {
                Some(ps) => ps.rx_at(path, f.payload, at, &mut on),
                None => on(f.payload, at),
            }
        }
        for (rx, n) in rxs.iter_mut().zip(n) {
            if let Some(rx) = rx {
                rx.release(n);
            }
        }
        // The final height first: payloads polled below are stamped with it on arrival, and a
        // stale one would expire them early (07 §5.4 retention).
        if let Some(d) = data.as_mut() {
            let f = source.final_height();
            if f > last_final {
                last_final = f;
                DataRx::<N, D>::join(&mut d.join, &mut d.replay).finalized(Height(f));
            }
        }
        let dk = data.as_mut().map_or(0, |d| d.poll(now()));
        if let Some(d) = data.as_mut() {
            d.check(source, now(), paths.as_ref().filter(|_| gate));
            d.finals();
        }
        // No ORDER frame reached the core this turn (none arrived, or `Paths` only buffered
        // them): the deadlines `on_frame` would have checked (REP_E_HASHLAG), whatever the data
        // queue is doing.
        if delivered == 0 {
            let hm = paths.as_ref().map_or(u64::MAX, Paths::held_min);
            // A full burst's unread frames came no later than its last one read (`cap`), even
            // when the frames read were all duplicates and nothing was delivered.
            let carried = carry.first().map_or(u64::MAX, |c| c.0);
            let r = core.tick(now().min(hm).min(carried).min(cap));
            report(
                &mut core,
                r,
                &mut faulted,
                &mut stalled,
                stats,
                source,
                data.as_mut(),
            );
        }
        // Repair (07 §4.10): Nack each hole that is due; report one repair gave up on.
        if let (Some(r), Some(ps)) = (repair.as_ref(), paths.as_mut()) {
            asks.clear();
            ps.poll(now(), &r.timers, gate, &mut asks);
            for a in &asks {
                match *a {
                    Ask::Nack {
                        path,
                        key,
                        from,
                        to,
                    } => {
                        let n = Nack {
                            path,
                            epoch16: key.0,
                            tenure: key.1,
                            stream: key.3,
                            port: r.ports[usize::from(path == RepPath::B)],
                            from_seq: from,
                            to_seq: to,
                        };
                        rep_stats[0] = rep_stats[0].saturating_add(1);
                        // UDP: a lost Nack is asked again at the next retry.
                        let _ = r.sock.send_to(&n.encode(), r.to);
                    }
                    Ask::Gap {
                        path,
                        key,
                        from,
                        to,
                    } => {
                        rep_stats[1] = rep_stats[1].saturating_add(1);
                        let p = match path {
                            Some(RepPath::A) => "A",
                            Some(RepPath::B) => "B",
                            None => "both",
                        };
                        println!(
                            "ORDER_GAP tenure={} stream={} from={from} to={to} path={p}",
                            key.1, key.3
                        );
                    }
                }
            }
        }
        if k == 0 && dk == 0 {
            // kernel_udp only (class E): an idle order thread parks instead of spinning, so
            // several boxes and their voters share a small host. The socket holds what arrives.
            std::thread::park_timeout(IDLE);
        }
    }
    if let Some(d) = data.as_mut() {
        d.finals();
    }
    if repair.is_some() {
        println!(
            "REPAIR nacks={} gaps={} too_old={}",
            rep_stats[0], rep_stats[1], rep_stats[2]
        );
    }
    if let Some(d) = data.as_ref() {
        let c = d.sources.counts;
        println!(
            "FETCH box={} peer={} seq={} served={} missed={} limited={} bad={}",
            c.boxes, c.peer, c.seq, c.served, c.missed, c.limited, c.bad
        );
        if let Some(f) = d.failover.as_ref() {
            let c = f.counts;
            println!(
                "FAILOVER down_sent={} down_heard={} down_bad={} effective={} redirects={} redirect_msgs={}",
                c.down_sent, c.down_heard, c.down_bad, c.effective, c.redirects, c.redirect_msgs
            );
        }
    }
    data.as_mut()
        .map(|d| DataRx::<N, D>::join(&mut d.join, &mut d.replay).evictions())
}

fn report<const N: usize, D: RxRing>(
    core: &mut OrderCore<N, View>,
    r: Result<(), FrameErr>,
    faulted: &mut bool,
    stalled: &mut bool,
    stats: &Stats,
    source: &consensus::Source,
    mut data: Option<&mut DataRx<N, D>>,
) {
    while let Some(b) = core.take_ready() {
        let h = b.header.height;
        stats.blocks.fetch_add(1, Ordering::Relaxed);
        let verdict = core.verdict(h, h);
        // A block that replays prints its line after replay, with `out=` (`DataRx::check`).
        let replays =
            verdict == Verdict::Valid && data.as_ref().is_some_and(|d| d.replay.is_some());
        if !replays {
            println!("{}", block_line(&b, verdict));
        }
        source.header(b.header);
        match (verdict, data.as_deref_mut()) {
            (Verdict::Invalid, _) => source.invalid_from(h),
            (Verdict::Valid, Some(d)) => {
                // Its records reference their payloads from now on (07 §5.4 retention).
                DataRx::<N, D>::join(&mut d.join, &mut d.replay).reference(&b);
                // After a home move its new sessions are redirected now, not at release (R15).
                if let Some(fo) = d.failover.as_mut() {
                    fo.held(b.lanes.iter().filter_map(|r| match r {
                        LaneRec::Pkt(p)
                            if p.flags & (PacketFlags::ADVANCE | PacketFlags::SHED) == 0 =>
                        {
                            Some((p.session, p.pkt_seq))
                        }
                        _ => None,
                    }));
                }
                d.pending.push_back((b, None));
            }
            (Verdict::Valid, None) => source.valid(h),
            (Verdict::Pending, _) => {}
        }
    }
    // A frame that is not its substream's next one: a loss this release does not repair yet
    // (07 §4.10). Printed once per stall, so a stalled order core is visible.
    match r {
        Err(FrameErr::OutOfOrder) if !*stalled => {
            *stalled = true;
            println!("OUT_OF_ORDER next_height={}", core.next_height().0);
        }
        Ok(()) => *stalled = false,
        Err(_) => {}
    }
    if let (Err(FrameErr::Fault(f)), false) = (r, *faulted) {
        *faulted = true;
        source.invalid_from(f.height);
        stats.faults.fetch_add(1, Ordering::Relaxed);
        println!("FAULT {} height={}", f.kind.code(), f.height.0);
    }
}

/// `BLOCK height=<h> first_step=<s> last_step=<s> lanes=<k> steps=<k> verdict=<v>`.
fn block_line<const N: usize>(b: &BlockInputs<N>, verdict: Verdict) -> String {
    format!(
        "BLOCK height={} first_step={} last_step={} lanes={} steps={} verdict={verdict:?}",
        b.header.height.0,
        b.header.first_step.0,
        b.header.last_step.0,
        b.lanes.len(),
        b.steps.len(),
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `CLOCK_REALTIME` in ns, the clock of kernel_udp's `rx_ts`.
fn realtime_ns() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    /// The shipped DEV file loads, and its `seq_key` is the DEV seed's (0x42 × 32).
    #[test]
    fn dev_toml_loads() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
        let c = super::Config::load(std::path::Path::new(p)).unwrap();
        let want = vyrn_crypto::ed25519::public_key(&[0x42; 32]);
        let hex: String = want.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(c.membership.seq_keys, vec![hex]);
    }

    /// `[replay] hashlag_us` other than the spec's 1000 loads only with `dev = true`.
    #[test]
    fn hashlag_us_is_dev_only() {
        let base =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml")).unwrap();
        let load = |dev: &str, us: u64| {
            let dir = std::env::temp_dir().join(format!(
                "vyrn-val-hashlag-{}-{dev}-{us}",
                std::process::id()
            ));
            let text = format!(
                "{dev}\n{base}\n[data]\nboxes = [\"127.0.0.1:1\"]\nme = 1\n\n[replay]\ntick_min = 1\ntick_max = 2\nwin_center = 1\nhashlag_us = {us}\n"
            );
            std::fs::write(&dir, text).unwrap();
            let r = super::Config::load(&dir);
            std::fs::remove_file(&dir).unwrap();
            r
        };
        assert!(load("", 1000).is_ok());
        assert!(load("", 50_000).unwrap_err().contains("DEV only"));
        assert!(load("", 999).is_err());
        assert!(load("dev = true", 50_000).is_ok());
        assert!(load("dev = true", 0).is_err());
    }
}
