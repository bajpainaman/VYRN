//! `vyrn-seq`, the sequencer box (03 §1.3, §4.1; 11 §1.3, §10.1): main.rs and config wiring only.
//! Every decision is made in the crates; this file opens them, connects them and starts threads.
//!
//! # Contract
//!
//! **Invocation.** `vyrn-seq --config FILE [--stop-on-stdin-eof]`. The seq key handle in the
//! file resolves at start (`env:NAME` only in this release).
//!
//! **Config** (`config.rs`): MINIMAL schema 1, a labelled subset of 11 §10.1. Unknown fields are
//! refused.
//!
//! | Field | Meaning |
//! |---|---|
//! | `schema = 1`, `protocol = 1` | must match this release |
//! | `role = "seq"`, `mode = "BASE"`, `home`, `book`, `epoch` | the box's book and epoch |
//! | `[engine] dedicated, pooled = 0, tick_min, tick_max, win_center, slot_cap` | lanes and book window |
//! | `[nic] backend, ip, port_base` | `kernel_udp` or `sim`; lane `l` listens on `port_base + l` (0: ephemeral) |
//! | `[cores] pin = false, engine, stream, seal` | `pin = true` pins the engine and stream threads to `engine` and `stream` (both required); a failed pin fail-stops before `READY`; `seal` is `abort`, `count` or `off` |
//! | `[replication] order = ["ip:port", ...], order_b = [...], block_ms` | where ORDER, HASH and HEADER frames go on path A and, flagged `PATH_B`, on path B (optional; 07 §3.1; opt-in cost: one header copy and one send per frame per path-B replica on the stream thread, +30–40% per frame in DEV with 5 replicas, not a latency result); block period |
//! | `[keys] seq` | the `seq_key` handle (Ed25519 seed) |
//! | `[epoch_boundary] next, t_ns, to_home, seq_index` | optional: per-lane `EpochNotice` triggers (08 §2.4) |
//! | `[[dev_session]] lane, slot, account, k_seq, k_out, quote, base` | DEV only: sessions opened at start |
//! | `[repair] port, slots = 65536, max_pps = 50000, session_pps = 2000, xchg` | optional: `SeqDataReq` (07 §5.5 source 3) on its own thread; with `xchg` (needs `[consensus]`) only fetches sealed under `K_fetch` are served; see `repair.rs` |
//! | `[consensus] ctrl, roster, roster_hash, genesis_hash, seq_order` | optional: the finality listener (`finality.rs`) on `REP_UDP_CTRL`; committee from the roster file (08 §9.6), checked against `roster_hash` |
//!
//! **Start sequence** (11 §10.1), each step fail-stops with exit code 2 and one line on stderr:
//! load and check config → resolve keys → (release manifest and Vx hash: not checked yet) →
//! allocate the engine (`Shared`, lanes, BBO) → open the NIC backend, one RX queue per lane and
//! two TX queues → start the threads → the engine thread opens its DEV sessions, then seals
//! (`[cores] seal`) → the control thread prints the readiness line on stdout:
//!
//! ```text
//! READY vyrn-seq lanes=<n> rx=<ip:port>,<ip:port>,...   (one address per lane, in lane order)
//! ```
//!
//! **Threads** (03 §4.1, as far as one engine object allows):
//!
//! | Thread | REF cores | Does |
//! |---|---|---|
//! | `engine` | 1, 2, 6, 8–49 | polls every lane's RX queue, runs `Engine::ingest`, `Engine::run` (cut cores, BBO, lanes); per-lane `Notifier`s. `vyrn-engine` is single-threaded in this version, so these roles share one thread. |
//! | `stream` | 4 (and 3, 5 for responses) | `SeqWriter` (vyrn-log): frames every record, sends ORDER and HASH, closes and signs a block every `block_ms`, then sends the responses those frames cover (`INV-FRAME-FIRST`) |
//! | `repair` | 51 (07 §5.5 source 3) | with `[repair]`: takes the engine's retention copies (`vyrn_engine::retain`, through a second `vyrn_cut::Ring`, [`repair::RETAIN_HANDOFF`] entries, pushed without waiting) and answers replicas' KEY fetches (`repair.rs`) |
//! | `finality` | 51 | with `[consensus]`: `REP_FinalizeVote`s and `REP_FinalityCert`s on `REP_UDP_CTRL`, `final_height`, the gate check (`finality.rs`); prints `CONSENSUS ctrl=<ip:port>` before `READY`, `FINAL height=<h> ...`, `GATE ...`, and `FINALITY ...` at exit |
//! | main | 51 | config, start, readiness, stop, stats |
//!
//! **Handoff.** The engine thread hands its outputs to the stream thread through one
//! `vyrn_cut::Ring` (SPSC, [`HANDOFF`] `Copy` entries), allocated before either thread starts, so
//! a sealed engine thread never allocates on that path. When the ring is full the engine thread
//! waits (back-pressure, 05 §14.2): it retries the push, yielding between tries, and stops polling
//! its RX queues meanwhile, so the kernel holds or drops packets ahead of the box, never inside
//! it. It gives up only once the stream thread has exited, and then fail-stops. `STATS
//! handoff_full` counts the pushes that had to wait. The stream thread exits once the engine
//! thread has been joined and the ring is empty, or on an error, which also sets the stop flag.
//! A block closes `block_ms` after its first packet record or step, and at a clean stop.
//!
//! **Events on stdout**, one line each, for tests and operators: `LAYOUT engine=<core|unpinned>
//! stream=<core|unpinned> control=main` (the core each thread is pinned to; `unpinned` unless
//! `[cores] pin`), `REPAIR addr=<ip:port>` (with `[repair]`), `READY ...`,
//! `BLOCK height=<h> first_step=<s> last_step=<s>`, `NOTICE lane=<l> next=<e> secs=<s>`,
//! `CONTROL step=<id> phase=<halt|resume>` as it frames a finality-gate `Control` step, and at
//! exit `STATS records=<n> steps=<n> blocks=<n> responses=<n> tx=<n> tx_unsent=<n>
//! seal_violations=<n> handoff_full=<n>`, then with `[repair]` `REPAIR_STATS retain_dropped=<n>
//! served=<n> missed=<n> limited=<n> bad=<n>`.
//!
//! **Control** (stdin, one line each; *reading*, like `vyrn-data`'s: 07 and 08 name no
//! transport for it yet). `EPOCH <e>` re-derives a keyed `[repair]`'s `K_fetch` for epochs `e`
//! and `e + 1` and drops older ones (07 §5.5 Epoch boundary); the repair thread prints
//! `FETCH_EPOCHS <e>,<e+1>` once it serves under them. A refused or unknown line prints
//! `CONTROL_ERR <why>` on stderr and changes nothing.
//!
//! **Stop.** With `--stop-on-stdin-eof`, closing stdin stops both threads, flushes the stream
//! and prints `STATS`. Otherwise the process runs until killed (06 §4.8: never restarted).
//!
//! **Not wired yet** (PR follow-ups): maker TX packets (`resp_seq` 0: counted as `tx_unsent`), pooled lanes, two
//! substreams, retransmits and heartbeats, enforcing the finality gate (`HaltReq`), control
//! ops, a class A deadline clock (class-E and S backends use `dev_clock`).
#![forbid(unsafe_code)]

mod config;
mod finality;
mod repair;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::{Duration, Instant};

use clap::Parser;
use vyrn_bbo::admit::FixedClock;
use vyrn_bbo::{Bbo, CutDelta, Phase, Record, StepEntry, TxEntry};
use vyrn_cut::{Consumer, Hw, Producer, Ring};
use vyrn_engine::alloc::SealingAlloc;
use vyrn_engine::{Engine, Fault, Rec, Shared, Sink};
use vyrn_epoch::{Boundary, EpochNotice, Notifier};
use vyrn_lane::{ArenaConfig, Gate, Lane, PathTable, RespPkt, Rx, RxIn, SessionSpec};
use vyrn_log::frame::FrameFlags;
use vyrn_log::stream::has_src;
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_nic::frame::{self, Endpoint, FrameHdr};
use vyrn_nic::{
    BackendKind, KernelUdp, LatencyClass, NicBackend, NicConfig, PortConfig, PortId, RxBind,
    SimNic, TxClass,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, Hash, HomeCode, LaneId, LaneSeq, Nanos, PacketFlags, PacketRecord,
    PktHash, RouteRecord, SessionId, StepFlags, StepId, StepKind, TAG_BYTES,
};
use vyrn_wire::{PROTO_RESP_MAX_BYTES, RX_BURST, RespHeader, RxPkt, RxRing, TxRing};

use crate::config::Config;

#[global_allocator]
static ALLOC: SealingAlloc = SealingAlloc;

/// Lane-local accounts per lane (`vyrn_lane::Lane`'s `NA`), fixed in this release.
pub const NA: usize = 16;
pub const MAX_LANES: usize = vyrn_bbo::MAX_LANES;
/// Entries in flight between the engine and stream threads (a power of two).
const HANDOFF: usize = 8192;
/// Messages the stream thread takes before it drains responses and checks the block timer.
const BATCH: usize = 1024;
/// Records per response packet (01 §6.3).
const MAX_RECS: usize = vyrn_wire::MAX_RECS_PER_PKT as usize;
/// Recent packets whose full hash the stream thread may still ask for.
const RECENT: usize = 4096;

#[derive(Parser)]
#[command(version, about = "The VYRN sequencer box")]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// Stop cleanly when stdin closes (tests, supervised DEV runs).
    #[arg(long)]
    stop_on_stdin_eof: bool,
}

/// Engine thread → stream thread, through the handoff ring: `Copy` data only.
// Boxing the large variant would allocate on the sealed engine thread.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
enum Out {
    /// A lane record. A non-Advance one opens its packet's group: its `MID` Advance records
    /// and `RouteRecord`s follow, then [`Out::GroupEnd`]. The stream core closes no block inside
    /// a group, so they share the packet's block (07 §3.6, §7.1 `REP_MERGE` item 1).
    Pkt(PacketRecord, Option<Hash>),
    Route(RouteRecord),
    GroupEnd,
    Step(StepEntry, u8, [CutDelta; MAX_LANES]),
    /// The payload of the next `Control` step: the engine queued its command (07 §3.8, §6.8).
    Control([u8; vyrn_engine::CONTROL_PAYLOAD_LEN]),
    Resp(LaneId, Endpoint, RespPkt),
    /// A fill TX packet (05 §8.10 rules 1 and 2), its records cut to one response's worth.
    Tx(Endpoint, TxEntry, u8, [Record; MAX_RECS]),
    /// A TX packet this release cannot send (see `EngineSink::tx`).
    Unsent,
    Notice(LaneId, EpochNotice),
}

#[derive(Default)]
struct Stats {
    records: AtomicU64,
    steps: AtomicU64,
    blocks: AtomicU64,
    responses: AtomicU64,
    fills: AtomicU64,
    unsent: AtomicU64,
    seal_violations: AtomicU64,
    /// Engine pushes that found the handoff full and waited.
    full: AtomicU64,
    /// Retention copies lost to a full repair ring (the engine never waits on it).
    retain_dropped: AtomicU64,
}

fn fail(what: &str, e: impl std::fmt::Display) -> ExitCode {
    eprintln!("vyrn-seq: {what}: {e}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return fail("config", e),
    };
    let seed = match config::resolve::<32>(&cfg.keys.seq) {
        Ok(s) => s,
        Err(e) => return fail("keys.seq", e),
    };
    let r = match cfg.nic.backend.as_str() {
        "sim" => run::<SimNic>(&cfg, seed, cli.stop_on_stdin_eof),
        _ => run::<KernelUdp>(&cfg, seed, cli.stop_on_stdin_eof),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail("start", e),
    }
}

/// What `EPOCH <e>` derives the repair keys from, and the repair thread's sender.
type Control = (
    vyrn_epoch::Roster,
    vyrn_epoch::Domain,
    vyrn_types::HomeCode,
    [u8; 32],
    std::sync::mpsc::Sender<(u32, repair::Keys)>,
);

/// One stdin control line (cold path): `EPOCH <e>` hands the repair thread epoch `e`'s key
/// window, which it acks once installed; empty lines are ignored.
fn control_line(line: &str, control: Option<&Control>) -> Result<(), String> {
    let mut w = line.split_whitespace();
    match (w.next(), w.next().map(str::parse::<u32>), w.next()) {
        (None, ..) => Ok(()),
        (Some("EPOCH"), Some(Ok(e)), None) => {
            let Some((roster, domain, home, secret, tx)) = control else {
                return Err("EPOCH needs a keyed [repair] (repair.xchg)".into());
            };
            let keys = repair::window_keys(roster, domain, e, *home, secret)?;
            tx.send((e, keys))
                .map_err(|_| "the repair thread has stopped".into())
        }
        _ => Err(format!("unknown control line {:?}", line.trim())),
    }
}

fn run<B: NicBackend>(cfg: &Config, seed: [u8; 32], stdin_stop: bool) -> Result<(), String>
where
    B::Rx: LocalAddr + 'static,
    B::Tx: 'static,
{
    let n = usize::from(cfg.engine.dedicated);
    let ip = cfg.nic.ip;
    let kind = if B::KIND == BackendKind::Sim {
        BackendKind::Sim
    } else {
        BackendKind::Kernel
    };
    let ncfg = NicConfig::new(kind, vec![PortConfig { id: PortId(0), ip }]);
    let mut nic = B::open(&ncfg).map_err(|e| e.to_string())?;
    let class = nic.caps().latency_class;
    let mut rxs = Vec::with_capacity(n);
    for l in 0..n {
        let lane = LaneId(u8::try_from(l).map_err(|e| e.to_string())?);
        let udp_port = match cfg.nic.port_base {
            0 => 0,
            b => b
                .checked_add(u16::from(lane.0))
                .ok_or("nic.port_base + lane overflows")?,
        };
        let bind = RxBind {
            lane,
            port: PortId(0),
            ip,
            udp_port,
        };
        rxs.push(nic.rx_ring(&bind).map_err(|e| e.to_string())?);
    }
    let order_tx = nic
        .tx_ring(PortId(0), TxClass::OrderStream)
        .map_err(|e| e.to_string())?;
    let resp_tx = nic
        .tx_ring(PortId(0), TxClass::Fill)
        .map_err(|e| e.to_string())?;
    let addrs: Vec<String> = rxs.iter().map(|r| r.local().to_string()).collect();

    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    // Set by the stream thread when it exits; set by this thread once the engine thread joined.
    let stream_done = AtomicBool::new(false);
    let engine_done = AtomicBool::new(false);
    let stream_pin = std::sync::atomic::AtomicU8::new(0);
    let mut ring = Ring::<Out, HANDOFF, 1, Hw>::new(&Hw);
    let (tx, [rx]) = ring.split().ok_or("handoff ring")?;
    let (ready_tx, ready_rx) = sync_channel::<Result<(), String>>(2);
    // 07 §5.5 source 3: its queues, ring and server are allocated before any thread starts.
    let mut retain_ring = cfg.repair.as_ref().map(|_| repair::RetainRing::new(&Hw));
    let mut repair_q = None;
    // Keyed `[repair]`: what `EPOCH <e>` derives keys from, and the repair thread's receiver.
    let mut control = None;
    let mut rekey = None;
    if let Some(r) = &cfg.repair {
        let bind = RxBind {
            lane: LaneId(0),
            port: PortId(0),
            ip,
            udp_port: r.port,
        };
        let rrx = nic.rx_ring(&bind).map_err(|e| e.to_string())?;
        let rtx = nic
            .tx_ring(PortId(0), TxClass::Control)
            .map_err(|e| e.to_string())?;
        let replicas = cfg.replication.order.iter().map(|a| *a.ip()).collect();
        let mut server = repair::Server::new(r.slots, replicas, r.max_pps, r.session_pps);
        if let Some(h) = &r.xchg {
            let c = cfg.consensus.as_ref().ok_or(
                "config repair.xchg needs [consensus]: K_fetch is derived from the roster",
            )?;
            let mode = vyrn_types::Mode::Base;
            let bytes = finality::roster_bytes(&c.roster)?;
            let domain = vyrn_epoch::Domain {
                genesis_hash: vyrn_types::Hash(config::hex::<32>(&c.genesis_hash)?),
                mode,
            };
            if vyrn_epoch::Roster::hash_bytes(&domain, &bytes).0
                != config::hex::<32>(&c.roster_hash)?
            {
                return Err("config consensus.roster does not hash to roster_hash".into());
            }
            let roster =
                vyrn_epoch::Roster::decode(mode, &bytes).map_err(|e| format!("roster: {e}"))?;
            let home = home_code(&cfg.home).ok_or("config home is not TYO, LDN or NYC")?;
            let secret = config::resolve::<32>(h)?;
            server.set_keys(repair::window_keys(
                &roster, &domain, cfg.epoch, home, &secret,
            )?);
            let (tx, rx) = std::sync::mpsc::channel();
            rekey = Some(rx);
            control = Some((roster, domain, home, secret, tx));
        }
        repair_q = Some((server, rekey.take(), rrx, rtx));
    }
    let (retain_tx, retain_rx) = match retain_ring.as_mut().and_then(|r| r.split()) {
        Some((p, [c])) => (Some(p), Some(c)),
        None => (None, None),
    };

    let writer = writer(cfg, n, seed)?;
    let k_out: Vec<(SessionId, [u8; 16])> = cfg
        .dev_session
        .iter()
        .map(|s| Ok((dev_sid(s)?, config::hex::<16>(&s.k_out)?)))
        .collect::<Result<_, String>>()?;
    let block = Duration::from_millis(cfg.replication.block_ms);
    let mut plan = EnginePlan::from(cfg)?;
    let fin = match &cfg.consensus {
        Some(c) => {
            let st = Arc::clone(&stats);
            let home = home_code(&cfg.home).ok_or("config home is not TYO, LDN or NYC")?;
            let f = finality::Finality::start(
                c,
                home,
                Epoch(cfg.epoch),
                vyrn_crypto::ed25519::public_key(&seed),
                Arc::new(move || st.blocks.load(Ordering::Acquire)),
                Arc::clone(&stop),
            )?;
            println!("CONSENSUS ctrl={}", f.ctrl);
            plan.gate = Some(Arc::clone(&f.counts));
            Some(f)
        }
        None => None,
    };
    let r = std::thread::scope(|sc| {
        // However this closure exits, a panic included (stdout closed before `READY` makes
        // `println!` panic), both threads are told to finish, so the scope's join cannot hang.
        let _stop = Done([&*stop, &engine_done]);
        let repair = match (repair_q, retain_rx) {
            (Some((server, rekey, rrx, rtx)), Some(copies)) => {
                let me = Endpoint {
                    mac: [0; 6],
                    ip,
                    port: 0,
                };
                println!("REPAIR addr={}", rrx.local());
                let stop = Arc::clone(&stop);
                let t = std::thread::Builder::new()
                    .name("vyrn-seq/repair".into())
                    .spawn_scoped(sc, move || {
                        repair::run(server, rekey, copies, rrx, rtx, me, &stop)
                    })
                    .map_err(|e| e.to_string())?;
                Some(t)
            }
            _ => None,
        };
        let stream = {
            let (stats, stop, ready) = (Arc::clone(&stats), Arc::clone(&stop), ready_tx.clone());
            let (stream_done, engine_done) = (&stream_done, &engine_done);
            let replicas = cfg.replication.order.clone();
            let replicas_b = cfg.replication.order_b.clone();
            let epoch16 = Epoch(cfg.epoch).low16();
            let (pin, stream_core, stream_pin) = (cfg.cores.pin, cfg.cores.stream, &stream_pin);
            std::thread::Builder::new()
                .name("vyrn-seq/stream".into())
                .spawn_scoped(sc, move || {
                    // A failed pin stops the box before READY; this thread still drains the
                    // ring until the engine is done.
                    let pinned = pin_to(pin, stream_core, "stream");
                    let state = if pinned.is_ok() { PIN_OK } else { PIN_FAILED };
                    stream_pin.store(state, Ordering::Release);
                    let _ = ready.send(pinned);
                    let mut s = StreamCore {
                        writer,
                        order_tx,
                        resp_tx,
                        replicas,
                        path_b_down: vec![false; replicas_b.len()],
                        replicas_b,
                        path_b: Vec::new(),
                        src: ip,
                        k_out,
                        epoch16,
                        cut: vec![LaneSeq(0); n],
                        stats,
                        pending: Vec::new(),
                        pending_tx: Vec::new(),
                        control: std::collections::VecDeque::new(),
                    };
                    // Ends the engine's wait on a full ring, and the engine loop, however this
                    // thread exits: a return, an error, or a panic that unwinds.
                    let _done = Done([stream_done, &stop]);
                    let mut rx = rx;
                    s.run(&mut rx, engine_done, block)
                })
                .map_err(|e| e.to_string())?
        };
        // From here every exit path joins both threads: the stream thread runs until
        // `engine_done`, and the scope would wait for it.
        let engine = {
            let (stats, stop) = (Arc::clone(&stats), Arc::clone(&stop));
            let stream_done = &stream_done;
            let (pin, engine_core, stream_pin) = (cfg.cores.pin, cfg.cores.engine, &stream_pin);
            std::thread::Builder::new()
                .name("vyrn-seq/engine".into())
                .spawn_scoped(sc, move || {
                    if let Err(e) = pin_to(pin, engine_core, "engine") {
                        let _ = ready_tx.send(Err(e.clone()));
                        stop.store(true, Ordering::Release);
                        return Err(e);
                    }
                    // No order is taken before both threads are placed: a stream that fails to
                    // pin must not send frames or responses of a box that never started. The
                    // stream thread reports its own failure.
                    let placed = loop {
                        match stream_pin.load(Ordering::Acquire) {
                            PIN_OK => break true,
                            PIN_FAILED => break false,
                            _ if stop.load(Ordering::Acquire) => break false,
                            _ => std::thread::yield_now(),
                        }
                    };
                    if !placed {
                        stop.store(true, Ordering::Release);
                        return Err("the stream thread was not placed".into());
                    }
                    let h = Handoff {
                        tx,
                        stream_done,
                        dead: false,
                        retain: retain_tx,
                    };
                    engine_thread(plan, rxs, h, &ready_tx, &stop, &stats, class)
                })
        };
        let engine = match engine {
            Ok(t) => t,
            Err(e) => {
                engine_done.store(true, Ordering::Release);
                let _ = stream.join();
                return Err(e.to_string());
            }
        };
        let mut failed = None;
        for _ in 0..2 {
            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => failed = Some(e),
                Err(_) => failed = Some("a thread exited before ready".to_owned()),
            }
            if failed.is_some() {
                break;
            }
        }
        if failed.is_none() {
            start_line(cfg, n, &addrs);
            // Control lines on stdin until EOF (crate docs, Control), on a detached thread: the
            // main thread still joins the workers, so a failure after READY exits the box even
            // with stdin open. With `--stop-on-stdin-eof`, EOF stops it.
            let ctl = control.take();
            let eof = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("vyrn-seq/stdin".into())
                .spawn(move || {
                    for line in std::io::stdin().lines() {
                        let Ok(line) = line else { break };
                        if let Err(e) = control_line(&line, ctl.as_ref()) {
                            eprintln!("CONTROL_ERR {e}");
                        }
                    }
                    if stdin_stop {
                        eof.store(true, Ordering::Release);
                    }
                })
                .map_err(|e| e.to_string())?;
        } else {
            stop.store(true, Ordering::Release);
        }
        let e = engine.join();
        // Every push happened before the join: an empty ring now means the stream has it all.
        engine_done.store(true, Ordering::Release);
        stop.store(true, Ordering::Release);
        let s = stream.join();
        let r = repair.map(|t| t.join());
        if let Some(f) = failed {
            return Err(f);
        }
        let g = |c: &AtomicU64| c.load(Ordering::Acquire);
        println!(
            "STATS records={} steps={} blocks={} responses={} tx={} tx_unsent={} seal_violations={} handoff_full={}",
            g(&stats.records),
            g(&stats.steps),
            g(&stats.blocks),
            g(&stats.responses),
            g(&stats.fills),
            g(&stats.unsent),
            g(&stats.seal_violations),
            g(&stats.full)
        );
        if let Some(Ok(rs)) = &r {
            println!(
                "REPAIR_STATS retain_dropped={} served={} missed={} limited={} bad={}",
                g(&stats.retain_dropped),
                rs.served,
                rs.missed,
                rs.limited,
                rs.bad
            );
        }
        if let Some(Err(_)) = r {
            return Err("repair thread panicked".into());
        }
        let e = e.map_err(|_| "engine thread panicked")?;
        let s = s.map_err(|_| "stream thread panicked")?;
        e.and(s)
    });
    if let Some(f) = fin {
        stop.store(true, Ordering::Release);
        f.join();
    }
    r
}

/// Sets its flags when dropped, so a thread publishes its exit even when it unwinds.
struct Done<'a>([&'a AtomicBool; 2]);

impl Drop for Done<'_> {
    fn drop(&mut self) {
        for f in self.0 {
            f.store(true, Ordering::Release);
        }
    }
}

/// The stream thread's pin result, which the engine waits for before taking orders.
const PIN_OK: u8 = 1;
const PIN_FAILED: u8 = 2;

/// Pins the calling thread to `core` when `[cores] pin` is set.
fn pin_to(pin: bool, core: Option<u16>, name: &str) -> Result<(), String> {
    match core.filter(|_| pin) {
        Some(c) => vyrn_nic::sys::pin_current_thread(usize::from(c))
            .map_err(|e| format!("cores.pin: {name} to cpu {c}: {e}")),
        None => Ok(()),
    }
}

/// The `LAYOUT` and `READY` lines.
fn start_line(cfg: &Config, n: usize, addrs: &[String]) {
    // Applied placement: a core only when `[cores] pin` put the thread there.
    let core = |c: Option<u16>| {
        c.filter(|_| cfg.cores.pin)
            .map_or_else(|| "unpinned".to_owned(), |c| c.to_string())
    };
    println!(
        "LAYOUT engine={} stream={} control=main",
        core(cfg.cores.engine),
        core(cfg.cores.stream)
    );
    println!("READY vyrn-seq lanes={n} rx={}", addrs.join(","));
}

/// The address a lane's RX queue listens on.
trait LocalAddr {
    fn local(&self) -> SocketAddrV4;
}

impl LocalAddr for vyrn_nic::kernel_udp::KernelRx {
    fn local(&self) -> SocketAddrV4 {
        self.local_addr()
    }
}

impl LocalAddr for vyrn_nic::sim::SimRx {
    fn local(&self) -> SocketAddrV4 {
        self.addr()
    }
}

fn dev_sid(s: &config::DevSession) -> Result<SessionId, String> {
    vyrn_wire::session_id(s.slot, LaneId(s.lane), 1).ok_or_else(|| "dev_session slot".to_owned())
}

fn writer(cfg: &Config, n: usize, seed: [u8; 32]) -> Result<SeqWriter, String> {
    let n8 = u8::try_from(n).map_err(|e| e.to_string())?;
    let layout = Layout::new(n8, 1, 0).map_err(|e| e.to_string())?;
    let epoch = Epoch(cfg.epoch);
    let ident = Ident {
        book: BookId(cfg.book),
        epoch,
        tenure: 0,
        sender: 0,
    };
    let ts = TenureStart {
        epoch,
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: vyrn_types::Height(0),
        prev_header_hash: Hash([0; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(0),
                fills_applied: StepId(0),
            };
            n
        ],
        prev_cut: vec![LaneSeq(0); n],
    };
    // Each log frame is one UDP payload of a fast-path frame.
    SeqWriter::new(layout, ident, ts, seed, frame::MAX_PAYLOAD).map_err(|e| e.to_string())
}

#[cfg(test)]
fn writer_for_test() -> SeqWriter {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
    let c = Config::load(std::path::Path::new(p)).unwrap_or_else(|e| panic!("{e}"));
    writer(&c, 2, [0x42; 32]).unwrap_or_else(|e| panic!("{e}"))
}

/// What the engine thread builds, taken from the config before the thread starts.
struct EnginePlan {
    bbo: vyrn_bbo::Config,
    arena: ArenaConfig,
    lanes: Vec<vyrn_lane::Config>,
    sessions: Vec<(usize, SessionSpec, u64, u64)>,
    notifier: Option<Notifier>,
    seal: String,
    /// The finality gate's `HaltReq` (07 §6.8), with `[consensus]`.
    gate: Option<Arc<finality::Counts>>,
}

impl EnginePlan {
    fn from(cfg: &Config) -> Result<Self, String> {
        let e = &cfg.engine;
        let n = e.dedicated;
        let epoch = Epoch(cfg.epoch);
        let book = BookId(cfg.book);
        let (tick_min, tick_max) = (vyrn_types::Tick(e.tick_min), vyrn_types::Tick(e.tick_max));
        let spec = BookSpec::new(1, tick_min, tick_max, 10_000).ok_or("engine tick range")?;
        let bbo = vyrn_bbo::Config {
            n_lanes: n,
            epoch,
            slot_cap: usize::try_from(e.slot_cap).map_err(|e| e.to_string())?,
            seg_cap: e.slot_cap,
            win_center: vyrn_types::Tick(e.win_center),
            phase: Phase::Continuous,
            tick_min,
            tick_max,
            band_half: 0,
            band_hyst: 0,
            band_ref: vyrn_types::Tick(e.win_center),
            pool: 0,
        };
        let arena = ArenaConfig {
            slot_cap: e.slot_cap,
            seg_cap: e.slot_cap,
            tick_min,
            tick_max,
            accounts: u32::try_from(NA).map_err(|e| e.to_string())?,
            journal: e.slot_cap,
        };
        let lanes = (0..n)
            .map(|l| vyrn_lane::Config {
                lane: LaneId(l),
                n_lanes: n,
                epoch,
                book,
                spec,
                path: PathTable::spec(),
                fwd_deadline_ns: vyrn_lane::lane::FWD_DEADLINE_NS,
                phase: Phase::Continuous,
                out_cap: 4096,
            })
            .collect();
        let sessions = cfg
            .dev_session
            .iter()
            .map(|s| {
                let spec = SessionSpec {
                    id: dev_sid(s)?,
                    acct: AcctSlot(s.account),
                    k_seq: config::hex::<16>(&s.k_seq)?,
                    book,
                    buckets: SessionBuckets::default(),
                };
                Ok((usize::from(s.lane), spec, s.quote, s.base))
            })
            .collect::<Result<_, String>>()?;
        let notifier = match &cfg.epoch_boundary {
            None => None,
            Some(b) => {
                let home = |s: &str| home_code(s).ok_or_else(|| format!("unknown home {s:?}"));
                let boundary = Boundary {
                    from: epoch,
                    to: Epoch(b.next),
                    t: Nanos(b.t_ns),
                    from_home: home(&cfg.home)?,
                    to_home: home(&b.to_home)?,
                };
                Some(Notifier::new(&boundary, b.seq_index))
            }
        };
        Ok(Self {
            bbo,
            arena,
            lanes,
            sessions,
            notifier,
            seal: cfg.cores.seal.clone(),
            gate: None,
        })
    }
}

fn home_code(s: &str) -> Option<HomeCode> {
    match s {
        "TYO" => Some(HomeCode::Tyo),
        "LDN" => Some(HomeCode::Ldn),
        "NYC" => Some(HomeCode::Nyc),
        _ => None,
    }
}

/// The engine thread's end of the handoff ring.
struct Handoff<'a> {
    tx: Producer<'a, Out, HANDOFF, 1, Hw>,
    stream_done: &'a AtomicBool,
    /// The stream thread exited: nothing more is pushed and the engine loop stops.
    dead: bool,
    /// Retention copies to the repair thread (07 §5.5 source 3), when `[repair]` is set.
    retain: Option<Producer<'a, vyrn_engine::retain::Kept, { repair::RETAIN_HANDOFF }, 1, Hw>>,
}

/// The source endpoint of each session's last accepted packet.
type Peers = Vec<(SessionId, Endpoint)>;

/// The engine's outputs, forwarded to the stream thread without allocating.
struct EngineSink<'a> {
    tx: Handoff<'a>,
    /// `(pkt_hash, full hash)` of recently received packets, oldest first.
    recent: std::collections::VecDeque<(PktHash, Hash)>,
    peers: Peers,
    /// `(session, pkt_seq, source)` of the packet being ingested, not yet authenticated.
    from: Option<(SessionId, u32, Endpoint)>,
    notifiers: Vec<Notifier>,
    stats: Arc<Stats>,
    /// A packet's group is open (see [`Out::Pkt`]).
    group: bool,
}

impl EngineSink<'_> {
    /// Ends the open packet group. Called before any element that is not the packet's `MID`
    /// or route record, and after each engine call: the engine sends those right after the
    /// packet, in the same lane drain.
    fn flush(&mut self) {
        if self.group {
            self.group = false;
            self.send(Out::GroupEnd);
        }
    }

    /// Pushes `o`; on a full ring waits for the stream thread (back-pressure, never an
    /// allocation or a drop). Only a stream thread that has exited ends the wait: fail-stop.
    fn send(&mut self, o: Out) {
        let h = &mut self.tx;
        let mut o = o;
        let mut waited = false;
        while !h.dead {
            match h.tx.push(&Hw, o) {
                Ok(()) => return,
                Err(back) => o = back,
            }
            if !waited {
                waited = true;
                self.stats.full.fetch_add(1, Ordering::Relaxed);
            }
            if h.stream_done.load(Ordering::Acquire) {
                h.dead = true;
            } else {
                std::thread::yield_now();
            }
        }
    }
}

impl Sink for EngineSink<'_> {
    fn record(&mut self, r: &Rec<'_>) {
        match r {
            Rec::Packet(p) => {
                if p.flags & PacketFlags::MID == 0 {
                    self.flush();
                }
                let full = self
                    .recent
                    .iter()
                    .rev()
                    .find(|(h, _)| *h == p.pkt_hash)
                    .map(|x| x.1);
                if p.count > 0
                    && let Some(n) = self
                        .notifiers
                        .get_mut(usize::from(p.lane.0))
                        .and_then(|n| n.on_packet(p.rx_ts))
                {
                    self.send(Out::Notice(p.lane, n));
                }
                self.stats.records.fetch_add(1, Ordering::Relaxed);
                self.send(Out::Pkt(*p, full));
                self.group |= p.flags & PacketFlags::ADVANCE == 0;
            }
            Rec::Step(e, d) => {
                self.flush();
                let mut ds = [CutDelta::default(); MAX_LANES];
                for (o, i) in ds.iter_mut().zip(d.iter()) {
                    *o = *i;
                }
                self.stats.steps.fetch_add(1, Ordering::Relaxed);
                self.send(Out::Step(*e, e.n_delta, ds));
            }
            Rec::Route(t) => self.send(Out::Route(*t)),
        }
    }
    /// The answer to the packet being ingested goes to its source, accepted or not; every other
    /// response goes to the session's last accepted source.
    fn lane_resp(&mut self, lane: LaneId, p: &RespPkt) {
        self.flush();
        let ep = match self.from {
            Some((s, seq, ep)) if s == p.session && seq == p.echo_pkt => Some(ep),
            _ => self
                .peers
                .iter()
                .find(|(s, _)| *s == p.session)
                .map(|x| x.1),
        };
        if let Some(ep) = ep {
            self.send(Out::Resp(lane, ep, *p));
        }
    }
    /// Only packets with a `resp_seq` are sent: maker packets take theirs from the lane's
    /// `MakerSeq` line (05 §4.15), which `vyrn-engine` does not expose yet (follow-up).
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        self.flush();
        let peer = self
            .peers
            .iter()
            .find(|(s, _)| *s == h.session)
            .map(|x| x.1);
        let (Some(ep), false) = (peer, h.resp_seq == 0 || recs.len() > MAX_RECS) else {
            self.send(Out::Unsent);
            return;
        };
        let mut rs = [Record::default(); MAX_RECS];
        for (o, i) in rs.iter_mut().zip(recs) {
            *o = *i;
        }
        let n = u8::try_from(recs.len()).unwrap_or(0);
        self.send(Out::Tx(ep, *h, n, rs));
    }
}

fn engine_thread<R: RxRing>(
    plan: EnginePlan,
    mut rxs: Vec<R>,
    tx: Handoff<'_>,
    ready: &SyncSender<Result<(), String>>,
    stop: &AtomicBool,
    stats: &Arc<Stats>,
    class: LatencyClass,
) -> Result<(), String> {
    let r = engine_loop(plan, &mut rxs, tx, ready, stop, stats, class);
    if let Err(e) = &r {
        let _ = ready.send(Err(e.clone()));
    }
    stop.store(true, Ordering::Release);
    r
}

fn engine_loop<R: RxRing>(
    plan: EnginePlan,
    rxs: &mut [R],
    tx: Handoff<'_>,
    ready: &SyncSender<Result<(), String>>,
    stop: &AtomicBool,
    stats: &Arc<Stats>,
    class: LatencyClass,
) -> Result<(), String> {
    // Allocate everything (11 §10.1 "allocate all memory").
    let vis = Hw;
    let bbo = Bbo::new(plan.bbo);
    let n = plan.lanes.len();
    let mut shared =
        Shared::new(&vis, n, plan.arena, &bbo.initial_snapshot()).ok_or("engine shape")?;
    let (mut engine, peers) = open_engine(&vis, &mut shared, bbo, &plan)?;
    let mut sink = EngineSink {
        tx,
        recent: std::collections::VecDeque::with_capacity(RECENT),
        peers,
        from: None,
        notifiers: plan.notifier.map_or_else(Vec::new, |x| vec![x; n]),
        stats: Arc::clone(stats),
        group: false,
    };
    // Deadline admission needs a class A or C clock (06 §6.8); DEV backends run without it.
    if !matches!(class, LatencyClass::E | LatencyClass::S) {
        return Err(
            "only class E and S backends are wired; deadline clocks are a follow-up".into(),
        );
    }
    let mut burst = [RxPkt::empty(); RX_BURST];
    let mut newest = Nanos(0);
    match plan.seal.as_str() {
        "abort" => vyrn_engine::alloc::seal(),
        "count" => vyrn_engine::alloc::seal_counting(),
        _ => {}
    }
    let _ = ready.send(Ok(()));
    // A fault stays a `Copy` value until the allocator is unsealed: formatting it here would
    // allocate, and under `seal = "abort"` turn the fail-stop into an abort.
    let mut fault: Option<Fault> = None;
    let gate = plan.gate.clone();
    let mut halted = false;
    while !stop.load(Ordering::Acquire) && !sink.tx.dead {
        let mut got = 0usize;
        for (l, rx) in rxs.iter_mut().enumerate() {
            let k = rx.poll(&mut burst);
            got = got.saturating_add(k);
            for p in burst.iter().take(k) {
                newest = newest.max(p.rx_ts());
                let clock = dev_clock(newest);
                if let Err(f) = ingest(&mut engine, &mut sink, l, rx.bytes(p), p.rx_ts(), &clock) {
                    fault = Some(f);
                }
            }
            rx.release(k);
        }
        if let Err(f) = engine.run(&dev_clock(newest), &mut sink, 64) {
            fault = Some(f);
        }
        sink.flush();
        if fault.is_some() {
            break;
        }
        // 07 §6.8: the gate's HaltReq becomes the BBO core's next step. The stream thread gets
        // the command's payload first, so it frames that Control step with it.
        if let Some(g) = &gate {
            let want = g.halt_req.load(Ordering::Acquire);
            if want != halted {
                let c = finality::gate_cmd(want);
                if let Some(p) = vyrn_engine::control_payload(&c)
                    && engine.command(&c)
                {
                    halted = want;
                    sink.send(Out::Control(p));
                }
            }
        }
        if got == 0 {
            std::thread::yield_now();
        }
    }
    stats
        .seal_violations
        .store(vyrn_engine::alloc::violations(), Ordering::Release);
    vyrn_engine::alloc::unseal();
    if let Some(f) = fault {
        return Err(format!("engine fault {f:?}"));
    }
    if sink.tx.dead && !stop.load(Ordering::Acquire) {
        return Err("stream core stopped".into());
    }
    Ok(())
}

/// The engine with every DEV session open, and each session's response endpoint, unknown until
/// the session's first accepted packet.
fn open_engine<'a>(
    vis: &'a Hw,
    shared: &'a mut Shared<Hw>,
    bbo: Bbo,
    plan: &EnginePlan,
) -> Result<(Engine<'a, Hw, NA>, Peers), String> {
    let mut engine: Engine<'_, Hw, NA> =
        Engine::new(vis, shared, bbo, &plan.lanes, |cfg, aw, ports| {
            let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
            acct.max_open_orders = 1000;
            Lane::<Hw, NA>::new(cfg, aw, ports, acct)
        })
        .ok_or("engine lanes")?;
    let mut peers = Vec::with_capacity(plan.sessions.len());
    for (l, spec, quote, base) in &plan.sessions {
        let lane = engine.lane_mut(*l).ok_or("dev_session lane")?;
        let (_, bal) = lane.account_mut(spec.acct).ok_or("dev_session account")?;
        bal.quote_free = u128::from(*quote);
        bal.base_free = *base;
        if !lane.open_session(spec) {
            return Err(format!("dev_session {:?} did not open", spec.id));
        }
        peers.push((
            spec.id,
            Endpoint {
                mac: [0; 6],
                ip: Ipv4Addr::UNSPECIFIED,
                port: 0,
            },
        ));
    }
    Ok((engine, peers))
}

/// The deadline clock of class-E and S backends: 1 s behind the newest `rx_ts`, so the low-32
/// deadline test (05 §8.2) sheds only ops forwarded more than about 1 s earlier. DEV only: 06
/// §6.8 refuses to sequence on these classes in production, and a class A clock (06 §8.4) is
/// a follow-up.
fn dev_clock(newest: Nanos) -> FixedClock {
    FixedClock(newest.0.saturating_sub(DEV_SLACK_NS))
}

const DEV_SLACK_NS: u64 = 1_000_000_000;

/// One received frame into lane `l`.
fn ingest(
    engine: &mut Engine<'_, Hw, NA>,
    sink: &mut EngineSink<'_>,
    l: usize,
    bytes: &[u8],
    rx_ts: Nanos,
    clock: &FixedClock,
) -> Result<(), Fault> {
    let Ok(f) = frame::parse(bytes) else {
        return Ok(()); // not a fast-path frame: the NIC counters already saw it
    };
    let body = f.payload;
    // PktHash covers bytes 0..16+16n, both tags excluded (01 §3).
    let signed = body
        .get(..body.len().saturating_sub(2 * TAG_BYTES))
        .unwrap_or(&[]);
    let full = vyrn_crypto::hash::hash(signed);
    let pkt_hash = vyrn_crypto::pkt_hash(signed);
    if sink.recent.len() == RECENT {
        sink.recent.pop_front();
    }
    sink.recent.push_back((pkt_hash, full));
    sink.from = vyrn_wire::Request::parse(body)
        .ok()
        .map(|r| (r.header().session(), r.header().pkt_seq.get(), f.hdr.src));
    let input = RxIn {
        bytes: body,
        rx_ts,
        pkt_hash,
    };
    let r = engine.ingest(l, input, clock, sink);
    // Exactly the packets with a PacketRecord are retained (05 §6.10); a full ring drops the copy.
    if let Ok(v @ (Rx::Accepted | Rx::Shed)) = &r
        && let Some(q) = sink.tx.retain.as_mut()
        && let Some(mut k) = vyrn_engine::retain::Kept::new(body, rx_ts, pkt_hash)
        && {
            k.verified = *v == Rx::Accepted;
            q.push(&Hw, k).is_err()
        }
    {
        sink.stats.retain_dropped.fetch_add(1, Ordering::Relaxed);
    }
    // Only a packet the lane authenticated and accepted moves the session's endpoint: a spoofed
    // or replayed one must not redirect its responses.
    if let (Ok(Rx::Accepted), Some((s, _, src))) = (&r, sink.from.take())
        && let Some(peer) = sink.peers.iter_mut().find(|(p, _)| *p == s)
    {
        peer.1 = src;
    }
    r.map(|_| ())
}

/// The stream core: frames, blocks, and the responses those frames release.
struct StreamCore<T: TxRing> {
    writer: SeqWriter,
    order_tx: T,
    resp_tx: T,
    replicas: Vec<SocketAddrV4>,
    /// Path B's replicas, and the buffer their `PATH_B` copy is built in.
    replicas_b: Vec<SocketAddrV4>,
    path_b: Vec<u8>,
    /// Per path B replica: a send to it failed and has not succeeded since (`PATH_B_DOWN`
    /// printed once per outage).
    path_b_down: Vec<bool>,
    src: Ipv4Addr,
    k_out: Vec<(SessionId, [u8; 16])>,
    epoch16: u16,
    cut: Vec<LaneSeq>,
    stats: Arc<Stats>,
    pending: Vec<(LaneId, Endpoint, RespPkt)>,
    pending_tx: Vec<(Endpoint, TxEntry, u8, [Record; MAX_RECS])>,
    /// Payloads of queued commands, for their `Control` steps in order.
    control: std::collections::VecDeque<[u8; vyrn_engine::CONTROL_PAYLOAD_LEN]>,
}

impl<T: TxRing> StreamCore<T> {
    /// Runs until `engine_done` is set and the ring is empty, then closes the open block.
    fn run(
        &mut self,
        rx: &mut Consumer<'_, Out, HANDOFF, 1, Hw>,
        engine_done: &AtomicBool,
        block: Duration,
    ) -> Result<(), String> {
        // The block holds a packet record or a step since `opened`: it closes `block` later.
        let mut open = false;
        let mut opened = Instant::now();
        // Inside a packet's group (see `Out::Pkt`): the block does not close on its timer.
        let mut group = false;
        loop {
            // Read before popping: if the engine was done then, an empty ring is the end.
            let done = engine_done.load(Ordering::Acquire);
            // A bounded batch, so responses and block closure run under sustained input.
            let mut got = 0usize;
            while got < BATCH {
                let Some(o) = rx.pop(&Hw) else { break };
                got = got.saturating_add(1);
                if !open && matches!(o, Out::Pkt(..) | Out::Step(..)) {
                    open = true;
                    opened = Instant::now();
                }
                let ends = matches!(o, Out::GroupEnd);
                match &o {
                    Out::Pkt(p, _) if p.flags & PacketFlags::ADVANCE == 0 => group = true,
                    Out::GroupEnd => group = false,
                    _ => {}
                }
                self.take(o)?;
                // A group's end is a safe cut: close an expired block here, so a batch that
                // keeps ending inside a group cannot postpone the close.
                if ends && open && opened.elapsed() >= block {
                    self.close_block()?;
                    open = false;
                }
            }
            self.drain()?;
            let end = done && got == 0;
            if open && (end || (!group && opened.elapsed() >= block)) {
                self.close_block()?;
                open = false;
            }
            if end {
                return Ok(());
            }
            if got == 0 {
                std::thread::yield_now();
            }
        }
    }

    fn close_block(&mut self) -> Result<(), String> {
        let (frames, h) = self.writer.close_block().map_err(|e| e.to_string())?;
        self.ship(&frames)?;
        self.stats.blocks.fetch_add(1, Ordering::Relaxed);
        println!(
            "BLOCK height={} first_step={} last_step={}",
            h.height.0, h.first_step.0, h.last_step.0
        );
        Ok(())
    }

    fn take(&mut self, o: Out) -> Result<(), String> {
        let frames = match o {
            Out::Pkt(p, full) => self.writer.packet(p, full),
            Out::Route(t) => self.writer.route(t),
            Out::GroupEnd => return Ok(()),
            Out::Control(p) => {
                self.control.push_back(p);
                return Ok(());
            }
            Out::Step(e, n, ds) => {
                for d in ds.iter().take(usize::from(n)) {
                    if let Some(c) = self.cut.get_mut(usize::from(d.lane.0)) {
                        *c = d.seq;
                    }
                }
                let kind = StepKind::from_code(e.kind).ok_or("unknown step kind")?;
                let src = has_src(kind).then_some((e.src_lane, e.src_lane_seq));
                // Spec gap: the engine's StepEntry carries no payload for Rescan (07 §3.8), so it
                // is framed with an empty one; a Seal's payload is empty. A Control step takes
                // the payload of the command the engine queued for it. An opening Uncross step
                // must carry p* and Q, but this release queues only the gate's Phase commands,
                // so an Uncross step here has no command to frame and stops the stream.
                if kind == StepKind::Uncross {
                    return Err("Uncross step without a queued command".into());
                }
                let payload = if kind == StepKind::Control {
                    let p = self
                        .control
                        .pop_front()
                        .ok_or("Control step without a queued command")?;
                    let what = match vyrn_engine::control_of_payload(&p) {
                        Some(vyrn_bbo::ControlCmd::Phase {
                            phase: Phase::Halted,
                            ..
                        }) => "halt",
                        Some(vyrn_bbo::ControlCmd::Phase {
                            phase: Phase::Continuous,
                            ..
                        }) => "resume",
                        _ => "other",
                    };
                    println!("CONTROL step={} phase={what}", e.step.0);
                    p.to_vec()
                } else {
                    Vec::new()
                };
                // The route bit (05 §4.15, 07 §3.8 src byte bit 7) travels with the source op.
                let flags = if src.is_some() && e.flags & vyrn_bbo::STEP_CROSS != 0 {
                    StepFlags::CROSS
                } else {
                    0
                };
                self.writer
                    .step(e.step, kind, src, flags, payload, &self.cut)
            }
            Out::Resp(l, ep, p) => {
                self.pending.push((l, ep, p));
                return Ok(());
            }
            Out::Tx(ep, h, n, rs) => {
                self.pending_tx.push((ep, h, n, rs));
                return Ok(());
            }
            Out::Unsent => {
                self.stats.unsent.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Out::Notice(l, n) => {
                println!("NOTICE lane={} next={} secs={}", l.0, n.next.0, n.secs);
                return Ok(());
            }
        };
        let frames = frames.map_err(|e| e.to_string())?;
        self.ship(&frames)
    }

    /// Flushes the writer, ships its frames, then sends the responses whose gate those frames
    /// opened (`INV-FRAME-FIRST`, 05 §8.10). A response whose packet or step has not reached
    /// this thread yet stays pending, in order.
    fn drain(&mut self) -> Result<(), String> {
        let frames = self.writer.flush().map_err(|e| e.to_string())?;
        self.ship(&frames)?;
        for (l, ep, p) in core::mem::take(&mut self.pending) {
            if !gate_open(&self.writer, l, p.gate) {
                self.pending.push((l, ep, p));
                continue;
            }
            let hdr = RespHeader::new(p.session, p.resp_seq, self.epoch16, p.echo_pkt, false);
            if self.respond(ep, hdr, p.records())? {
                self.stats.responses.fetch_add(1, Ordering::Relaxed);
            }
        }
        for (ep, h, n, rs) in core::mem::take(&mut self.pending_tx) {
            // A TX packet goes out after its step is framed (05 §8.10 rules 1 and 2).
            if self.writer.framed_step().0 < h.step.0 {
                self.pending_tx.push((ep, h, n, rs));
                continue;
            }
            let hdr = RespHeader::new(h.session, h.resp_seq, self.epoch16, h.pkt_seq, false);
            if self.respond(ep, hdr, rs.get(..usize::from(n)).unwrap_or(&[]))? {
                self.stats.fills.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// Encodes and sends one response; `false` if the session has no `k_out` here.
    fn respond(&mut self, ep: Endpoint, hdr: RespHeader, recs: &[Record]) -> Result<bool, String> {
        let Some((_, k)) = self.k_out.iter().find(|(s, _)| *s == hdr.session()) else {
            return Ok(false);
        };
        // The records in their 01 §6.4 bytes, read back as the wire crate's type.
        let recs: Vec<vyrn_wire::Record> = recs
            .iter()
            .filter_map(|r| vyrn_wire::Record::decode(&r.encode()).ok())
            .collect();
        let mut buf = [0u8; PROTO_RESP_MAX_BYTES];
        let len = vyrn_wire::encode_response(&mut buf, hdr, &recs, k).ok_or("response encode")?;
        send(
            &mut self.resp_tx,
            self.src,
            ep,
            buf.get(..len).unwrap_or(&[]),
        )?;
        Ok(true)
    }

    /// Sends each frame on path A, then its `PATH_B` copy on path B (07 §3.1, D4): both before
    /// the responses they release.
    fn ship(&mut self, frames: &[Vec<u8>]) -> Result<(), String> {
        let dst = |r: &SocketAddrV4| Endpoint {
            mac: [0; 6],
            ip: *r.ip(),
            port: r.port(),
        };
        for f in frames {
            for r in &self.replicas {
                send(&mut self.order_tx, self.src, dst(r), f)?;
            }
            if self.replicas_b.is_empty() {
                continue;
            }
            // Only `flags` differs between the copies (07 §3.2, INV-REP-3).
            self.path_b.clear();
            self.path_b.extend_from_slice(f);
            if let Some(b) = self.path_b.get_mut(FLAGS_AT) {
                *b = FrameFlags::PATH_B;
            }
            // Path B is the redundant copy: trading continues on path A alone (07 §4.9), so a
            // refused B send is reported, not returned.
            for (r, down) in self.replicas_b.iter().zip(self.path_b_down.iter_mut()) {
                match send(&mut self.order_tx, self.src, dst(r), &self.path_b) {
                    Ok(()) => *down = false,
                    Err(e) if !*down => {
                        *down = true;
                        println!("PATH_B_DOWN {r}: {e}");
                    }
                    Err(_) => {}
                }
            }
        }
        Ok(())
    }
}

/// `flags`' offset in a log frame header (`vyrn_log::frame`).
const FLAGS_AT: usize = 16;

/// Whether frames already returned by `w` cover what `gate` waits for on `lane`.
fn gate_open(w: &SeqWriter, lane: LaneId, gate: Gate) -> bool {
    match gate {
        Gate::None => true,
        Gate::Packet(s) => w.framed_lane_seq(lane).is_some_and(|f| f.0 >= s.0),
        Gate::Step(s) => w.framed_step().0 >= s.0,
    }
}

fn send<T: TxRing>(tx: &mut T, src: Ipv4Addr, dst: Endpoint, payload: &[u8]) -> Result<(), String> {
    let hdr = FrameHdr {
        src: Endpoint {
            mac: [0; 6],
            ip: src,
            port: 0,
        },
        dst,
    };
    let mut buf = [0u8; frame::MAX_FRAME_BYTES];
    let len = frame::build(&hdr, payload, &mut buf).map_err(|e| format!("frame: {e:?}"))?;
    let bytes = buf.get(..len).unwrap_or(&[]);
    // A full queue is reaped and retried once; a second refusal is a fault.
    if tx.send(bytes).is_err() {
        tx.reap();
        tx.send(bytes).map_err(|_| "tx queue full".to_owned())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    /// The shipped DEV file passes every start-time check.
    #[test]
    fn dev_toml_loads() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
        let c = super::Config::load(std::path::Path::new(p)).unwrap();
        assert_eq!((c.engine.dedicated, c.dev_session.len()), (2, 1));
        assert!(super::EnginePlan::from(&c).unwrap().notifier.is_some());
    }

    /// Without `[cores]` the box takes the table's defaults (seal = count), as with an empty one.
    #[test]
    fn omitted_cores_table_uses_defaults() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
        let text = std::fs::read_to_string(p).unwrap();
        let start = text.find("[cores]").unwrap();
        let end = start + text[start..].find("[replication]").unwrap();
        let dir = std::env::temp_dir().join(format!("vyrn-seq-cores-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("seq.toml");
        std::fs::write(&f, format!("{}{}", &text[..start], &text[end..])).unwrap();
        let c = super::Config::load(&f).unwrap();
        assert_eq!(c.cores.seal, "count");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A packet moves its session's response endpoint only once the lane accepts it: a replay
    /// of an accepted packet, or a packet with a bad tag, from another address leaves it alone
    /// (#49 Codex P2).
    #[test]
    fn only_accepted_packets_move_the_endpoint() {
        use std::net::Ipv4Addr;
        use std::sync::atomic::AtomicBool;
        use vyrn_cut::{Hw, Ring};
        use vyrn_nic::frame::{self, Endpoint, FrameHdr};
        use vyrn_types::{BookId, Epoch, LaneId, Nanos};
        use vyrn_wire::{Msg, ReqHeader, encode_request};

        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
        let c = super::Config::load(std::path::Path::new(p)).unwrap();
        let plan = super::EnginePlan::from(&c).unwrap();
        let bbo = vyrn_bbo::Bbo::new(plan.bbo);
        let init = bbo.initial_snapshot();
        let mut shared = super::Shared::new(&Hw, plan.lanes.len(), plan.arena, &init).unwrap();
        let (mut engine, peers) = super::open_engine(&Hw, &mut shared, bbo, &plan).unwrap();
        let mut ring = Ring::<super::Out, { super::HANDOFF }, 1, Hw>::new(&Hw);
        let (tx, [mut rx]) = ring.split().unwrap();
        let done = AtomicBool::new(false);
        let mut sink = super::EngineSink {
            tx: super::Handoff {
                tx,
                stream_done: &done,
                dead: false,
                retain: None,
            },
            recent: std::collections::VecDeque::new(),
            peers,
            from: None,
            notifiers: Vec::new(),
            stats: std::sync::Arc::default(),
            group: false,
        };
        let ep = |port| Endpoint {
            mac: [0; 6],
            ip: Ipv4Addr::LOCALHOST,
            port,
        };
        let (client, spoof) = (ep(5001), ep(6666));
        let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
        // A resting buy: the lane answers it with an Ack.
        let new = Msg::New {
            flags: vyrn_wire::OrderFlags::from_byte(
                vyrn_bbo::OrderFlags::new(
                    vyrn_bbo::Side::Buy,
                    vyrn_bbo::Tif::Day,
                    false,
                    vyrn_bbo::Stp::None,
                )
                .0,
            )
            .unwrap(),
            tick: vyrn_types::Tick(100),
            qty: vyrn_types::Qty(1),
            client_tag: 1,
        };
        let req = |pkt_seq, key: &[u8; 16]| {
            let hdr = ReqHeader::new(session, pkt_seq, Epoch(0).low16(), BookId(7), false);
            let mut b = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
            let n = encode_request(&mut b, hdr, &[new], key, None).unwrap();
            b[..n].to_vec()
        };
        let mut send = |src, body: &[u8]| {
            let hdr = FrameHdr { src, dst: ep(7000) };
            let mut f = [0u8; frame::MAX_FRAME_BYTES];
            let n = frame::build(&hdr, body, &mut f).unwrap();
            let clock = super::dev_clock(Nanos(1));
            super::ingest(&mut engine, &mut sink, 0, &f[..n], Nanos(1), &clock).unwrap();
            engine.run(&clock, &mut sink, 64).unwrap();
            sink.peers.iter().find(|(s, _)| *s == session).unwrap().1
        };
        let good = req(1, &[0x11; 16]);
        assert_eq!(send(client, &good), client, "accepted");
        assert_eq!(send(spoof, &good), client, "replayed from another address");
        assert_eq!(send(spoof, &req(2, &[0x99; 16])), client, "bad tag");
        // The accepted order's Ack (a TX packet) went to the client; the bad-tag packet's
        // `BAD_MAC` answer went to its own source and moved nothing.
        let (mut acks, mut bad_mac) = (0, 0);
        while let Some(o) = rx.pop(&Hw) {
            match o {
                super::Out::Tx(e, ..) => {
                    assert_eq!(e, client);
                    acks += 1;
                }
                super::Out::Resp(_, e, r) if r.echo_pkt == 2 => {
                    assert_eq!(e, spoof);
                    bad_mac += 1;
                }
                super::Out::Resp(_, e, _) => assert_eq!(e, client),
                _ => {}
            }
        }
        assert_eq!((acks, bad_mac), (1, 1));
    }

    /// An RX queue holding one frame, delivered on the first poll.
    struct OneFrame(Vec<u8>, bool, vyrn_wire::NicCounters);

    impl vyrn_wire::RxRing for OneFrame {
        fn poll(&mut self, out: &mut [vyrn_wire::RxPkt; vyrn_wire::RX_BURST]) -> usize {
            if self.1 || self.0.is_empty() {
                return 0;
            }
            self.1 = true;
            let len = u16::try_from(self.0.len()).unwrap();
            let data = std::ptr::NonNull::new(self.0.as_mut_ptr()).unwrap();
            let ts = vyrn_types::Nanos(1);
            out[0] = vyrn_wire::RxPkt::new(data, len, vyrn_wire::RxFlags(0), 0, ts);
            1
        }
        fn release(&mut self, _n: usize) {}
        fn bytes<'a>(&'a self, _p: &'a vyrn_wire::RxPkt) -> &'a [u8] {
            &self.0
        }
        fn ts_source(&self) -> vyrn_wire::TsSource {
            vyrn_wire::TsSource::Virtual
        }
        fn counters(&self) -> &vyrn_wire::NicCounters {
            &self.2
        }
    }

    /// An engine fault on a sealed engine thread fail-stops without allocating: a frame on an
    /// RX queue past the last lane is `Fault::NoLane`, reported after the thread unseals. Under
    /// `seal = "count"` the old `format!` in the loop showed as a seal violation; under
    /// `seal = "abort"` it aborted the process instead of returning the fault.
    #[test]
    fn sealed_engine_fault_does_not_allocate() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use vyrn_cut::{Hw, Ring};
        use vyrn_nic::frame::{self, Endpoint, FrameHdr};

        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/dev.toml");
        let c = super::Config::load(std::path::Path::new(p)).unwrap();
        let ep = Endpoint {
            mac: [0; 6],
            ip: std::net::Ipv4Addr::LOCALHOST,
            port: 1,
        };
        let mut f = vec![0u8; frame::MAX_FRAME_BYTES];
        let n = frame::build(&FrameHdr { src: ep, dst: ep }, &[0; 32], &mut f).unwrap();
        f.truncate(n);
        for seal in ["count", "abort"] {
            let mut plan = super::EnginePlan::from(&c).unwrap();
            plan.seal = seal.to_owned();
            let counters = || vyrn_wire::NicCounters::default();
            let rxs = vec![
                OneFrame(Vec::new(), false, counters()),
                OneFrame(Vec::new(), false, counters()),
                OneFrame(f.clone(), false, counters()),
            ];
            let mut ring = Ring::<super::Out, { super::HANDOFF }, 1, Hw>::new(&Hw);
            let (tx, _rx) = ring.split().unwrap();
            let (done, stop) = (AtomicBool::new(false), AtomicBool::new(false));
            let stats = std::sync::Arc::<super::Stats>::default();
            let (ready, _ready_rx) = std::sync::mpsc::sync_channel(4);
            let h = super::Handoff {
                tx,
                stream_done: &done,
                dead: false,
                retain: None,
            };
            let r = std::thread::scope(|sc| {
                sc.spawn(|| {
                    let class = vyrn_nic::LatencyClass::E;
                    super::engine_thread(plan, rxs, h, &ready, &stop, &stats, class)
                })
                .join()
                .unwrap()
            });
            assert_eq!(r, Err("engine fault NoLane".to_owned()), "{seal}");
            let v = stats.seal_violations.load(Ordering::Acquire);
            assert_eq!(v, 0, "{seal}: allocations on the sealed fault path");
        }
    }

    /// A response gated on a packet or step opens only once a returned frame carries it.
    #[test]
    fn gates_follow_framed_positions() {
        use vyrn_types::{LaneId, LaneSeq, Nanos, PacketRecord, PktHash, SessionId, StepId};
        let mut w = super::writer_for_test();
        let gp = super::Gate::Packet(LaneSeq(1));
        assert!(super::gate_open(&w, LaneId(0), super::Gate::None));
        assert!(!super::gate_open(&w, LaneId(0), gp), "nothing pushed");
        let p = PacketRecord {
            lane: LaneId(0),
            count: 1,
            flags: 0,
            session: SessionId(0x0010_0001),
            pkt_seq: 1,
            rx_ts: Nanos(1),
            pkt_hash: PktHash(5),
            first_lane_seq: LaneSeq(1),
            fills_applied: StepId(0),
            snap_lag: 0,
        };
        w.packet(p, Some(vyrn_types::Hash([1; 32]))).unwrap();
        assert!(
            !super::gate_open(&w, LaneId(0), gp),
            "pushed but not framed"
        );
        w.flush().unwrap();
        assert!(super::gate_open(&w, LaneId(0), gp));
        assert!(!super::gate_open(&w, LaneId(1), gp), "another lane");
        assert!(!super::gate_open(
            &w,
            LaneId(0),
            super::Gate::Packet(LaneSeq(2))
        ));
        assert!(!super::gate_open(
            &w,
            LaneId(0),
            super::Gate::Step(StepId(1))
        ));
    }
}
