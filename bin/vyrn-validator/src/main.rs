//! `vyrn-validator` (03 §1.3, 07, 09; 11 §1.3): everything in `vyrn-replica` plus `vyrn-chain`.
//! main.rs and config wiring only: the order core's checks live in `vyrn-replica`, the bridge
//! and guardian rules in `vyrn-chain`.
//!
//! # Contract
//!
//! **Invocation.** `vyrn-validator --config FILE [--stop-on-stdin-eof]`.
//!
//! **Config**: MINIMAL schema 1, a labelled subset of 11 §10.1. Unknown fields are refused.
//!
//! | Field | Meaning |
//! |---|---|
//! | `schema = 1`, `protocol = 1` | must match this release |
//! | `role = "validator"`, `mode = "BASE"`, `book`, `epoch` | the book and epoch served (`EpochView`) |
//! | `lanes` | the sequencer box's lane count, one substream (07 §2.2); 1–4, 8, 11 or 49 |
//! | `[nic] backend = "kernel_udp", ip, order_port` | where ORDER, HASH and HEADER frames arrive (0: ephemeral) |
//! | `[cores] order` | REF core of the order core (07 §7.2 core 3); reported, not pinned |
//! | `[membership] seq_keys = ["<hex>"]` | `REP_Membership`'s `seq_key` per sequencer index (07 §13.1); public keys, so they may sit in the file |
//! | `[keys] vote` | vote key handle; read but unused until the Simplex voter is wired |
//!
//! **Start sequence** (11 §10.1): load and check config → build the order core
//! (`vyrn_replica::OrderCore`) over the config's `EpochView` → open the NIC queue → start the
//! order thread → print `READY vyrn-validator order=<ip:port>` on stdout.
//!
//! **Threads.** `order` (07 §7.2 core 3): polls the queue, runs `OrderCore::on_frame` and the
//! `REP_E_HASHLAG` timer, and for each ready block prints
//! `BLOCK height=<h> first_step=<s> last_step=<s> lanes=<k> steps=<k> verdict=<Valid|Invalid|Pending>`
//! (07 §6.4 items 2 and 5, the precondition for a vote). A sequencer fault prints
//! `FAULT <code> height=<h>` once; the core then refuses every later frame. main: start,
//! readiness, stop, `STATS frames=<n> blocks=<n> faults=<n>`.
//!
//! **Not wired yet** (PR follow-ups): the Simplex voter (`vyrn-consensus` `voter::config` needs
//! a `BlockSource` over this order core and Commonware p2p), the chain guardian
//! (`vyrn_chain::bridge::Guardian` needs a `vyrn_chain::Replica` over finalized `StateCommit`s,
//! which `vyrn-replica` does not produce yet), replay (`ReplayEngine` over `vyrn-engine`), path B
//! dedupe and repair, data join, CHAIN mode.
#![forbid(unsafe_code)]

use std::io::Read as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use clap::Parser;
use serde::Deserialize;
use vyrn_chain as _;
use vyrn_log::Layout;
use vyrn_nic::frame;
use vyrn_nic::{BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, RxBind};
use vyrn_replica::{EpochView, FrameErr, OrderCore};
use vyrn_types::{BookId, Epoch, Height, LaneId, PubKey};
use vyrn_wire::{RX_BURST, RxPkt, RxRing};

#[derive(Parser)]
#[command(version, about = "The VYRN validator box")]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[arg(long)]
    stop_on_stdin_eof: bool,
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
    nic: Nic,
    #[serde(default)]
    cores: Cores,
    membership: Membership,
    keys: Keys,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nic {
    backend: String,
    ip: Ipv4Addr,
    order_port: u16,
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
        if c.role != "validator" || c.mode != "BASE" {
            return bad(
                "role/mode",
                "must be validator and BASE (CHAIN needs the guardian)",
            );
        }
        if c.nic.backend != "kernel_udp" {
            return bad("nic.backend", "must be kernel_udp in this release");
        }
        if c.membership.seq_keys.is_empty() {
            return bad("membership.seq_keys", "is empty");
        }
        if c.keys.vote.is_empty() {
            return bad("keys.vote", "is empty");
        }
        Ok(c)
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
    let r = Config::load(&cli.config).and_then(|c| start(&c, cli.stop_on_stdin_eof));
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
    let layout = Layout::new(cfg.lanes, 1, 0).map_err(|e| e.to_string())?;
    let core: OrderCore<N, View> = OrderCore::new(layout, view).map_err(|e| e.to_string())?;
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
    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let order = {
        let (stats, stop) = (Arc::clone(&stats), Arc::clone(&stop));
        std::thread::Builder::new()
            .name("vyrn-validator/order".into())
            .spawn(move || order_thread(core, rx, &stop, &stats))
            .map_err(|e| e.to_string())?
    };
    let core_of = cfg
        .cores
        .order
        .map_or_else(|| "unpinned".into(), |c| c.to_string());
    println!("LAYOUT order={core_of} control=main");
    println!("READY vyrn-validator order={addr}");
    if stdin_stop {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        stop.store(true, Ordering::Release);
    }
    order.join().map_err(|_| "order thread panicked")?;
    let g = |c: &AtomicU64| c.load(Ordering::Acquire);
    println!(
        "STATS frames={} blocks={} faults={}",
        g(&stats.frames),
        g(&stats.blocks),
        g(&stats.faults)
    );
    Ok(())
}

fn order_thread<const N: usize, R: RxRing>(
    mut core: OrderCore<N, View>,
    mut rx: R,
    stop: &AtomicBool,
    stats: &Stats,
) {
    let t0 = Instant::now();
    let now = || u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut burst = [RxPkt::empty(); RX_BURST];
    let mut faulted = false;
    while !stop.load(Ordering::Acquire) {
        let k = rx.poll(&mut burst);
        for p in burst.iter().take(k) {
            let Ok(f) = frame::parse(rx.bytes(p)) else {
                continue;
            };
            stats.frames.fetch_add(1, Ordering::Relaxed);
            let r = core.on_frame(f.payload, now());
            report(&mut core, r, &mut faulted, stats);
        }
        rx.release(k);
        if k == 0 {
            let r = core.tick(now());
            report(&mut core, r, &mut faulted, stats);
            std::thread::yield_now();
        }
    }
}

fn report<const N: usize>(
    core: &mut OrderCore<N, View>,
    r: Result<(), FrameErr>,
    faulted: &mut bool,
    stats: &Stats,
) {
    while let Some(b) = core.take_ready() {
        let h = b.header.height;
        stats.blocks.fetch_add(1, Ordering::Relaxed);
        println!(
            "BLOCK height={} first_step={} last_step={} lanes={} steps={} verdict={:?}",
            h.0,
            b.header.first_step.0,
            b.header.last_step.0,
            b.lanes.len(),
            b.steps.len(),
            core.verdict(h, h)
        );
    }
    if let (Err(FrameErr::Fault(f)), false) = (r, *faulted) {
        *faulted = true;
        stats.faults.fetch_add(1, Ordering::Relaxed);
        println!("FAULT {} height={}", f.kind.code(), f.height.0);
    }
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
}
