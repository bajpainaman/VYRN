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
//! | `role = "validator"`, `mode = "BASE"`, `book`, `epoch` | the book and epoch served (`EpochView`) |
//! | `lanes` | the sequencer box's lane count, one substream (07 §2.2); 1–4, 8, 11 or 49 |
//! | `[nic] backend = "kernel_udp", ip, order_port` | where ORDER, HASH and HEADER frames arrive (0: ephemeral) |
//! | `[cores] order` | REF core of the order core (07 §7.2 core 3); reported, not pinned |
//! | `[membership] seq_keys = ["<hex>"]` | `REP_Membership`'s `seq_key` per sequencer index (07 §13.1); public keys, so they may sit in the file |
//! | `[keys] vote, node` | vote key handle; `node` (the p2p identity) defaults to `vote`. Only `env:NAME` (seed hex) resolves, and only with `[consensus]` |
//! | `[nic] data_port`, `[data] boxes = ["ip:port"], me, max_range` | optional: the data RX queue (07 §5.4); `boxes[i]` is data box `src = i`, `me` this replica's index in their destination lists. Without `[data]` vote-rule item 3 is not checked (DEV) |
//! | `dev = false` | `true` marks a DEV validator: only then may `[replay] hashlag_us` differ from 1000 |
//! | `[replay] tick_min, tick_max, win_center, slot_cap, hashlag_us, [[replay.session]] lane, slot, account, k_seq, quote, base` | optional, needs `[data]`: replay of every block that passes item 3 on `vyrn-engine` (`replay.rs`), built from the sequencer's `[engine]` and `[[dev_session]]` (no state snapshot encoding yet). `hashlag_us` (DEV only, default 1000 = the spec's 1 ms, 07 §3.7) is the `REP_E_HASHLAG` bound, for unpinned DEV hosts |
//! | `[consensus] roster, roster_hash, genesis_hash, home, seq_order, observers, delta_ms, storage` | optional: the Simplex voter (`consensus.rs`); committee and peers from the roster file (08 §9.6), checked against `roster_hash`; `membership.seq_keys[0]` must be the roster's primary `seq_key` |
//!
//! **Start sequence** (11 §10.1): load and check config → resolve keys → build the order core
//! (`vyrn_replica::OrderCore`) over the config's `EpochView` → open the NIC queues → start the
//! order thread and, with `[consensus]`, the voter thread → print `DATA rx=<ip:port>` (with
//! `[data]`), `CONSENSUS voter=<i> repl=<ip:port>` (with `[consensus]`) and
//! `READY vyrn-validator order=<ip:port>` on stdout.
//!
//! **Threads.** `order` (07 §7.2 core 3): polls the queue, runs `OrderCore::on_frame` and the
//! `REP_E_HASHLAG` timer, and for each ready block prints
//! `BLOCK height=<h> first_step=<s> last_step=<s> lanes=<k> steps=<k> verdict=<Valid|Invalid|Pending>`
//! (07 §6.4 items 2 and 5, the precondition for a vote). A sequencer fault prints
//! `FAULT <code> height=<h>` once; the core then refuses every later frame. A frame that is not
//! its substream's next prints `OUT_OF_ORDER next_height=<h>` once per stall (no repair yet). With `[data]` it also
//! polls the data RX queue: one `DataFeed::on_frame` per payload into the `DataJoin`, a
//! `DataFetch` RANGE to the box for every gap, and item 3 (`DataJoin::check`) for each ready
//! block before the voter may vote for it; a block whose data contradicts its header prints
//! `DATA_FAULT height=<h>`. With `[replay]` such a block's `BLOCK` line is printed after it
//! replays and ends in ` out=<hex>`, its `RustReplay` output hash; the first divergence prints
//! `REPLAY_FAULT height=<h> <why>` and replay stops (so does a `DATA_FAULT`). `voter` (`consensus.rs`): Simplex, `FINAL ...` per certificate.
//! main: start, readiness, stop, `STATS frames=<n> blocks=<n> faults=<n>` and, with `[data]`,
//! `DATA_EVICT expired=<n> capped=<n>`: unreferenced payloads the join dropped (07 §5.4; expiry
//! runs only with `[consensus]`, which reports finality).
//!
//! **Not wired yet** (PR follow-ups): seals in the voter's source (tail reports, Silence), the chain guardian
//! (`vyrn_chain::bridge::Guardian` needs a `vyrn_chain::Replica` over finalized `StateCommit`s,
//! which `vyrn-replica` does not produce yet), path B dedupe and repair, CHAIN mode.
#![forbid(unsafe_code)]

use std::collections::VecDeque;

use std::io::Read as _;
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
use vyrn_replica::{BlockInputs, DataErr, DataFeed, DataJoin, Evictions};

mod consensus;
mod replay;
use vyrn_consensus::Verdict;
use vyrn_log::Layout;
use vyrn_nic::frame;
use vyrn_nic::{BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, RxBind};
use vyrn_replica::{EpochView, FrameErr, OrderCore};
use vyrn_types::{BookId, Epoch, Height, LaneId, PubKey, SessionId};
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
    #[serde(default)]
    dev: bool,
    nic: Nic,
    #[serde(default)]
    cores: Cores,
    membership: Membership,
    keys: Keys,
    #[serde(default)]
    data: Option<Data>,
    #[serde(default)]
    consensus: Option<consensus::Section>,
    #[serde(default)]
    replay: Option<replay::Section>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    boxes: Vec<std::net::SocketAddrV4>,
    me: u8,
    /// The largest RANGE fetch a data box accepts, in frames.
    #[serde(default = "d_range")]
    max_range: u64,
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
        if c.replay.is_some() && c.data.is_none() {
            return bad("replay", "needs [data]: replay reads the blocks' payloads");
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
    let plan = cfg
        .consensus
        .as_ref()
        .map(|s| consensus::Plan::new(s, view.epoch, &cfg.keys.vote, cfg.keys.node.as_deref()))
        .transpose()?;
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
            let repair = UdpSocket::bind(SocketAddrV4::new(ip, 0)).map_err(|e| e.to_string())?;
            repair.set_nonblocking(true).map_err(|e| e.to_string())?;
            println!("DATA rx={}", drx.local_addr());
            Some(DataRx {
                feed: DataFeed::new(BookId(cfg.book), n, d.me),
                join: DataJoin::default(),
                replay: None,
                replay_dead: false,
                pending: VecDeque::new(),
                rx: drx,
                repair,
                boxes: d.boxes.clone(),
                max_range: d.max_range,
                fetches: VecDeque::new(),
                missing: None,
            })
        }
        None => None,
    };
    let mut data = data;
    if let (Some(r), Some(d)) = (&cfg.replay, data.as_mut()) {
        let n = u8::try_from(N).map_err(|e| e.to_string())?;
        let join = std::mem::take(&mut d.join);
        d.replay = Some(Box::new(replay::open(
            r,
            n,
            BookId(cfg.book),
            Epoch(cfg.epoch),
            join,
        )?));
        println!("REPLAY lanes={n} sessions={}", r.session.len());
    }
    let source = if plan.is_some() {
        consensus::Source::new()
    } else {
        consensus::Source::default()
    };
    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let order = {
        let (stats, stop, source) = (Arc::clone(&stats), Arc::clone(&stop), source.clone());
        std::thread::Builder::new()
            .name("vyrn-validator/order".into())
            .spawn(move || order_thread(core, rx, data, &source, &stop, &stats))
            .map_err(|e| e.to_string())?
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
    println!("READY vyrn-validator order={addr}");
    if stdin_stop {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        stop.store(true, Ordering::Release);
    }
    let evicted = order.join().map_err(|_| "order thread panicked")?;
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
    /// Ready blocks whose ORDER part passed, waiting for their payloads (item 3).
    pending: VecDeque<BlockInputs<N>>,
    rx: R,
    /// Fetches go out on this socket and their answers come back to it: a data box answers a
    /// KEY fetch to the fetch's source address (07 §5.5), and a `kernel_udp` TX ring sends from
    /// an ephemeral socket nothing polls. RANGE answers come to `rx` as data frames.
    repair: UdpSocket,
    boxes: Vec<std::net::SocketAddrV4>,
    max_range: u64,
    /// Gaps not fully fetched yet, with the box to ask: at most `FETCH_BURST` RANGE fetches go
    /// out per poll and a gap's `from` moves past them. One entry per gap, however long.
    fetches: VecDeque<(SocketAddrV4, Gap)>,
    /// The payload the front pending block waits for, and when it was last fetched by key.
    missing: Option<(SessionId, u32, u64)>,
}

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
        let mut burst = [RxPkt::empty(); RX_BURST];
        let k = self.rx.poll(&mut burst);
        let mut gaps = Vec::new();
        for p in burst.iter().take(k) {
            let Ok(f) = frame::parse(self.rx.bytes(p)) else {
                continue;
            };
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
            if let Some(to) = self.boxes.get(usize::from(g.src)) {
                self.fetches.push_back((*to, g));
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
                let _ = self.repair.send_to(&Fetch::encode(&q), *to);
            }
            if done {
                self.fetches.pop_front();
            }
        }
        k + answers
    }

    /// Item 3 for the pending blocks, in height order: a block whose payloads are all joined
    /// passes or contradicts; a missing payload waits. A payload still missing
    /// `REP_DATA_WAIT_US` after it was first seen missing, or after its last KEY fetch, is
    /// fetched by key (07 §5.5 source 1), so a lost RANGE request or reply does not stall the
    /// queue.
    fn check(&mut self, source: &consensus::Source, now: u64) {
        while let Some(b) = self.pending.front() {
            let h = b.header.height;
            match Self::join(&mut self.join, &mut self.replay).check(b) {
                Err(DataErr::Missing { session, pkt_seq }) => {
                    match self.missing {
                        Some((s, q, at)) if (s, q) == (session, pkt_seq) => {
                            if now.saturating_sub(at) >= REP_DATA_WAIT_NS {
                                self.fetch_key(session, pkt_seq);
                                self.missing = Some((session, pkt_seq, now));
                            }
                        }
                        _ => self.missing = Some((session, pkt_seq, now)),
                    }
                    return;
                }
                Ok(()) => source.valid(h),
                Err(_) => {
                    source.invalid_from(h);
                    println!("DATA_FAULT height={}", h.0);
                    self.replay_dead = true;
                }
            }
            let Some(b) = self.pending.pop_front() else {
                return;
            };
            match (&mut self.replay, self.replay_dead) {
                (Some(r), false) => match replay::block(r, &b) {
                    Ok(out) => println!("{} out={}", block_line(&b, Verdict::Valid), hex(&out.0)),
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
        }
    }

    /// A KEY fetch to every configured box: the validator has no session-to-data-home map yet
    /// (DEV reading, PR body), and a box that lacks the packet does not answer.
    fn fetch_key(&mut self, session: SessionId, pkt_seq: u32) {
        let q = Fetch::encode(&Fetch::Key { session, pkt_seq });
        for to in &self.boxes {
            let _ = self.repair.send_to(&q, to);
        }
    }
}

/// Sets the flag when dropped.
struct StopOnDrop<'a>(&'a AtomicBool);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// `REP_DATA_WAIT_US` (07 §5.5): how long a missing payload waits before a KEY fetch.
const REP_DATA_WAIT_NS: u64 = 300_000;

fn order_thread<const N: usize, R: RxRing, D: RxRing>(
    mut core: OrderCore<N, View>,
    mut rx: R,
    mut data: Option<DataRx<N, D>>,
    source: &consensus::Source,
    stop: &AtomicBool,
    stats: &Stats,
) -> Option<Evictions> {
    let mut last_final = 0;
    let t0 = Instant::now();
    let now = || u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let mut burst = [RxPkt::empty(); RX_BURST];
    let mut faulted = false;
    let mut stalled = false;
    while !stop.load(Ordering::Acquire) {
        let k = rx.poll(&mut burst);
        for p in burst.iter().take(k) {
            let Ok(f) = frame::parse(rx.bytes(p)) else {
                continue;
            };
            stats.frames.fetch_add(1, Ordering::Relaxed);
            let r = core.on_frame(f.payload, now());
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
        rx.release(k);
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
            d.check(source, now());
        }
        // No ORDER frame this turn: the deadlines `on_frame` would have checked (REP_E_HASHLAG),
        // whatever the data queue is doing.
        if k == 0 {
            let r = core.tick(now());
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
        if k == 0 && dk == 0 {
            // kernel_udp only (class E): an idle order thread parks instead of spinning, so
            // several boxes and their voters share a small host. The socket holds what arrives.
            std::thread::park_timeout(IDLE);
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
                d.pending.push_back(b);
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
