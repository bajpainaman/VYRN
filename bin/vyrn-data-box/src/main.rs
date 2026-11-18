//! `vyrn-data`, the data box (03 §1, 07 §5; 11 §1.3, §8.4, §10.1), package `bin/vyrn-data-box`:
//! main.rs and config wiring only. Every decision is made in the library; this file opens the NIC,
//! the log source and the metrics listener, derives `K_fetch` from the roster, then runs the
//! cores of [`vyrn_data::shards`] (an RX core, `[shards] n` ingest shards and one sender), each
//! on its own thread, pinned when `[shards] cpus` is set.
//!
//! # Contract
//!
//! **Invocation.** `vyrn-data --config FILE [--stop-on-stdin-eof]`.
//!
//! **Config** ([`vyrn_data::config`]): MINIMAL schema 1, a labelled subset of 11 §10.1. Unknown
//! fields are refused.
//!
//! | Field | Meaning |
//! |---|---|
//! | `schema = 1`, `protocol = 1`, `role = "data"`, `mode = "BASE" \| "CHAIN"`, `home` | must match this release |
//! | `dev = false` | `true` marks a DEV box: open-mode fetches and `hex:` keys are allowed only then |
//! | `src`, `books = [..]` | this box's frame `src` index; the books it serves |
//! | `[nic] backend = "kernel_udp", ip, ingest_port, fetch_port` | 0 asks for an ephemeral port |
//! | `[ring] slots, index_key` | ring size; the index secret's handle (omitted: `/dev/urandom`) |
//! | `dests = ["ip:port", ..]` | every voter and the standby, in `dst` order |
//! | `[[session]] id, key` | a session's MAC key handle (the session gateway is not wired) |
//! | `[roster] file, roster_hash, genesis_hash, epoch, box, xchg_secret` | `K_fetch(e, i, d)` of every requester of `home` from the roster (08 §9.6); omitted is refused unless `dev` |
//! | `[fetch] rate, burst` | per-source fetch limit (defaults 20,000/s, 256) |
//! | `[store] dirs = [..]` | `FileStore` drives read as the log source; none: an empty `MemStore` |
//! | `[metrics] listen` | Prometheus text on this address, default `127.0.0.1:9464` (11 §8.4) |
//! | `[shards] n, cpus` | ingest shards (default 1, at most 64; 07 §5.2 RSS by session); `cpus` empty (no pinning) or `n + 2` CPUs: RX core, sender, shard 0, … |
//!
//! A key handle is `env:NAME` (hex in that variable) or, on DEV only, `hex:<32 hex digits>`.
//!
//! **Start** (11 §10.1); each step fail-stops with exit code 2 and one line on stderr: load and
//! check the config → resolve keys → open the log source → open the NIC (ingest, fetch, one TX
//! queue per shard and one for the sender) → bind metrics → start and pin every core → print
//!
//! ```text
//! READY vyrn-data ingest=<ip:port> fetch=<ip:port> metrics=<ip:port>
//! ```
//!
//! **Events on stdout**, one line each: `EVENT bad_mac session=<s> pkt_seq=<q>`, `EVENT
//! copy_conflict session=<s> pkt_seq=<q>` (the transport to the sequencer's control core is a
//! follow-up), written by their own thread from a bounded queue so stdout never blocks the poll
//! loop (a full queue drops and counts the line), and at exit `STATS stored=<n> data_frames=<n>
//! heartbeats=<n> duplicate=<n> fetch_unauth=<n> fetch_limited=<n> bad_mac=<n> events_dropped=<n>
//! events_unprinted=<n> fetch_ring_hit=<n> fetch_log_hit=<n> fetch_miss=<n> fetch_resent=<n>
//! hop_full=<n> redirects=<n> redirect_unknown=<n> redirect_retried=<n> redirect_dropped=<n> shards=<n>`, every counter summed over the
//! cores.
//! A stop waits up to 1 s for queued events to print and counts the rest
//! in `events_unprinted`, so `EVENT` lines + `events_unprinted` + `events_dropped` = `bad_mac` +
//! `conflicts`.
//!
//! **Metrics.** Every [`vyrn_data::Counters`] field as `vyrn_data_<field>_total`, and
//! `vyrn_data_events_unprinted_total` (events dropped by the stdout queue), labels `role`,
//! `home`, `src`. Each core publishes its deltas every 100 ms, so a metric is the box's sum; a
//! std thread serves `GET` on the listener. *Reading:* 11 §8.4 says a tokio task; one blocking thread does the same job here.
//!
//! **Control** (stdin, one line each; *reading*: 07 and 08 name no transport for it yet).
//! `EPOCH <e>` derives `K_fetch` of epochs `e` and `e + 1` from `[roster]` and serves fetches
//! under either (08 §4.6), dropping older epochs' keys, then prints `FETCH_EPOCHS <e>,<e+1>`. At
//! start the box holds `[roster] epoch` and the next one, so requesters that move to the next
//! epoch are served without a restart. A refused or unknown line prints `CONTROL_ERR <why>` on
//! stderr and changes nothing. `REDIRECT <down> <to> <session>:<resend_from>[,…]` sends each
//! session's `DataRedirect{down → to, resend_from}` (07 §5.7 step 3) from the shard that owns it
//! and prints `REDIRECT_QUEUED <n>` (DEV); replicas send the same as REDIRECT fetches on the
//! fetch port (`vyrn-data` crate docs, § Fetch; *reading*, 07 §5.7). Lines
//! reach the RX core through a queue of `CONTROL_QUEUE`; while
//! it is full the stdin reader waits, never a core.
//!
//! **Stop.** With `--stop-on-stdin-eof`, closing stdin stops the RX core; each shard drains its
//! ring, then the sender drains its rings and flushes open frames, then `STATS` is printed.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use vyrn_cut::Hw;
use vyrn_data::config::{Config, hex};
use vyrn_data::shards::{self, RxCore, SenderRing, ShardRing, ShardTx};
use vyrn_data::{Counters, Event, NodeConfig};
use vyrn_log::{BlockStore, FileStore, MemStore};
use vyrn_nic::frame::Endpoint;
use vyrn_nic::{
    BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, RxBind, TxClass,
};
use vyrn_types::{LaneId, Nanos, SessionId};
use vyrn_wire::RxRing;

#[derive(Parser)]
#[command(version, about = "The VYRN data box")]
struct Cli {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// Stop cleanly when stdin closes (tests, supervised DEV runs).
    #[arg(long)]
    stop_on_stdin_eof: bool,
}

fn fail(what: &str, e: impl std::fmt::Display) -> ExitCode {
    eprintln!("vyrn-data: {what}: {e}");
    ExitCode::from(2)
}

/// Every counter, by its metric name.
macro_rules! fields {
    ($m:ident) => {
        $m! {
            rx_pkts, bad_frame, header, book, unknown_session, epoch, bad_mac, duplicate, late, stored,
            conflicts, data_frames, heartbeats, tx_full, events_dropped, fetch_bad, fetch_unauth,
            fetch_limited, fetch_ring_hit, fetch_log_hit, fetch_miss, fetch_resent, log_bad, hop_full, redirects,
            redirect_unknown, redirect_retried, redirect_dropped
        }
    };
}

macro_rules! values {
    ($($f:ident),*) => {
        fn values(c: &Counters) -> Vec<(&'static str, u64)> {
            vec![$((stringify!($f), c.$f)),*]
        }
    };
}
fields!(values);

/// The exported counters and the last values published to them.
struct Exported {
    counters: Vec<Counter>,
    last: Vec<u64>,
}

impl Exported {
    fn new(reg: &mut Registry) -> Self {
        let names = values(&Counters::default());
        let counters: Vec<Counter> = names.iter().map(|_| Counter::default()).collect();
        for ((name, _), c) in names.iter().zip(&counters) {
            reg.register(
                format!("vyrn_data_{name}"),
                format!("vyrn-data counter {name}"),
                c.clone(),
            );
        }
        Self {
            last: vec![0; counters.len()],
            counters,
        }
    }

    /// Another publisher of the same metrics, for another core: each core publishes the deltas
    /// of its own counters, and the exported values are their sums.
    fn handle(&self) -> Self {
        Self {
            counters: self.counters.clone(),
            last: vec![0; self.counters.len()],
        }
    }

    fn publish(&mut self, c: &Counters) {
        for ((m, last), (_, v)) in self.counters.iter().zip(&mut self.last).zip(values(c)) {
            m.inc_by(v.wrapping_sub(*last));
            *last = v;
        }
    }
}

fn serve_metrics(listener: TcpListener, reg: Registry) {
    for s in listener.incoming() {
        let Ok(mut s) = s else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
        let mut req = [0u8; 1024];
        let _ = s.read(&mut req);
        let mut body = String::new();
        if prometheus_client::encoding::text::encode(&mut body, &reg).is_err() {
            continue;
        }
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    }
}

/// Control lines waiting for the RX core; the stdin reader blocks while it is full.
const CONTROL_QUEUE: usize = 16;
/// Events waiting for the output thread; more are dropped and counted (`events_unprinted`).
const EVENT_QUEUE: usize = 4096;
/// How long a stop waits for the output thread to print what is queued.
const DRAIN: Duration = Duration::from_secs(1);

/// Set in [`Drain::claimed`] by a stop: from then on the output thread prints nothing.
const CLOSED: u64 = 1 << 63;

/// The output thread's progress, shared with the stop.
#[derive(Default)]
struct Drain {
    /// Events the output thread has taken to print, with [`CLOSED`] set once the stop has
    /// counted what is left. Claiming and closing are one atomic word, so an event is either
    /// claimed (printed, or the one line being written when the process exits) or abandoned,
    /// never both.
    claimed: AtomicU64,
    /// Events fully written.
    printed: AtomicU64,
}

fn print_events(rx: &std::sync::mpsc::Receiver<Event>, d: &Drain) {
    while let Ok(e) = rx.recv() {
        let claim = d
            .claimed
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v & CLOSED == 0).then_some(v.wrapping_add(1))
            });
        if claim.is_err() {
            return;
        }
        let mut out = std::io::stdout().lock();
        let _ = match e {
            Event::BadMac { session, pkt_seq } => {
                writeln!(out, "EVENT bad_mac session={} pkt_seq={pkt_seq}", session.0)
            }
            Event::CopyConflict {
                session, pkt_seq, ..
            } => writeln!(
                out,
                "EVENT copy_conflict session={} pkt_seq={pkt_seq}",
                session.0
            ),
        };
        let _ = out.flush();
        drop(out);
        d.printed.fetch_add(1, Ordering::Release);
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let cfg = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => return fail("config", e),
    };
    let r = if cfg.store.dirs.is_empty() {
        run(&cfg, MemStore::default(), cli.stop_on_stdin_eof)
    } else {
        match FileStore::open(&cfg.store.dirs) {
            Ok(s) => run(&cfg, s, cli.stop_on_stdin_eof),
            Err(e) => return fail("store", format!("{e:?}")),
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail("start", e),
    }
}

fn ep(a: SocketAddrV4) -> Endpoint {
    Endpoint {
        mac: [0; 6],
        ip: *a.ip(),
        port: a.port(),
    }
}

/// `[roster]`, decoded once: derives `K_fetch(e, i, d)` of every requester of `home(e)`, by its
/// `repl_addr` IPv4 (08 §9.6), for any epoch the roster is in force at. This is config wiring:
/// the roster codec and the derivation are `vyrn-epoch`'s, which the layer-4 library may not link
/// (11 §1.3, §1.4).
struct KeySource {
    roster: vyrn_epoch::Roster,
    domain: vyrn_epoch::Domain,
    home: vyrn_types::HomeCode,
    data_box: u8,
    secret: [u8; 32],
}

impl KeySource {
    /// `None` without `[roster]` (open mode, DEV).
    fn load(cfg: &Config) -> Result<Option<Self>, String> {
        let Some(r) = &cfg.roster else {
            return Ok(None);
        };
        let mode = if cfg.mode == "CHAIN" {
            vyrn_types::Mode::Chain
        } else {
            vyrn_types::Mode::Base
        };
        let home = match cfg.home.as_str() {
            "TYO" => vyrn_types::HomeCode::Tyo,
            "LDN" => vyrn_types::HomeCode::Ldn,
            "NYC" => vyrn_types::HomeCode::Nyc,
            _ => return Err("config home must be TYO, LDN or NYC with [roster]".into()),
        };
        let bytes = roster_bytes(&r.file)?;
        let domain = vyrn_epoch::Domain {
            genesis_hash: vyrn_types::Hash(hex::<32>(&r.genesis_hash)?),
            mode,
        };
        if vyrn_epoch::Roster::hash_bytes(&domain, &bytes).0 != hex::<32>(&r.roster_hash)? {
            return Err("roster: the file does not hash to roster_hash".into());
        }
        let roster =
            vyrn_epoch::Roster::decode(mode, &bytes).map_err(|e| format!("roster: {e}"))?;
        Ok(Some(Self {
            roster,
            domain,
            home,
            data_box: r.data_box,
            secret: cfg.resolve::<32>(&r.xchg_secret)?,
        }))
    }

    fn derive(&self, epoch: u32) -> Result<BTreeMap<Ipv4Addr, [u8; 16]>, String> {
        // R3 (08 §9.6): a roster configures only epochs from its `epoch_from`.
        if self.roster.epoch_from > vyrn_types::Epoch(epoch) {
            return Err(format!(
                "roster: epoch_from {} is after the configured epoch {epoch}",
                self.roster.epoch_from.0
            ));
        }
        let keys = self
            .roster
            .box_fetch_keys(
                vyrn_epoch::FETCH_CONTEXT,
                &self.domain,
                vyrn_types::Epoch(epoch),
                self.home,
                self.data_box,
                &self.secret,
            )
            .ok_or("roster: box is not a data box of home, or xchg_secret is not its key")?;
        let mut out = BTreeMap::new();
        for (i, addr, k) in keys {
            let ip = addr
                .ipv4()
                .ok_or(format!("roster: requester {i} has no IPv4 repl_addr"))?;
            // One key per source address: two requesters behind one address cannot be told apart.
            if out.insert(ip, k).is_some() {
                return Err(format!("roster: two requesters share {ip}"));
            }
        }
        // An empty map is open mode (DEV only): a roster that yields no key must not turn it on.
        if out.is_empty() {
            return Err("roster: no requester has a usable K_fetch".into());
        }
        Ok(out)
    }

    /// Installs `K_fetch` of `e` and `e + 1` (08 §4.6: both epochs of a boundary are served),
    /// which evicts any older epoch's keys.
    fn install<R: RxRing, F: RxRing>(&self, node: &mut RxCore<R, F>, e: u32) -> Result<(), String> {
        for x in [e, e.saturating_add(1)] {
            node.set_fetch_keys(x, self.derive(x)?)
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }
}

/// One control line (cold path). `EPOCH <e>` installs `K_fetch` of e and e + 1 and prints
/// `FETCH_EPOCHS <a>,<b>`. `REDIRECT <down> <to> <session>:<resend_from>[,…]` hands each
/// session's `DataRedirect` (07 §5.7 step 3) to its shard and prints `REDIRECT_QUEUED <n>`. A
/// refused or unknown line prints `CONTROL_ERR <why>` on stderr.
fn control<R: RxRing, F: RxRing>(
    line: &str,
    keys: Option<&KeySource>,
    node: &mut RxCore<R, F>,
    shards: &mut [ShardTx<'_>],
    acks: &std::sync::mpsc::SyncSender<Result<String, String>>,
) {
    let w: Vec<&str> = line.split_whitespace().collect();
    let r = match w.as_slice() {
        [] => return,
        ["EPOCH", e] => match (e.parse::<u32>(), keys) {
            (Ok(e), Some(k)) => k.install(node, e).map(|()| {
                let ep: Vec<String> = node.fetch_epochs().map(|e| e.to_string()).collect();
                format!("FETCH_EPOCHS {}", ep.join(","))
            }),
            (Ok(_), None) => Err("an open-mode box has no fetch keys".into()),
            (Err(_), _) => Err(format!("unknown control line {:?}", line.trim())),
        },
        ["REDIRECT", down, to, list] => redirects(down, to, list).map(|(d, t, sessions)| {
            let n = node.redirect(d, t, &sessions, shards);
            format!("REDIRECT_QUEUED {n}")
        }),
        _ => Err(format!("unknown control line {:?}", line.trim())),
    };
    // Printed by their own thread: a stalled stdout or stderr never blocks the poll loop, and
    // a full queue drops the line (the change is made either way).
    let _ = acks.try_send(r.map_err(|e| format!("CONTROL_ERR {e}")));
}

/// The arguments of `REDIRECT`: `down`, `to` and `session:resend_from` pairs, comma-separated.
#[allow(clippy::type_complexity)]
fn redirects(down: &str, to: &str, list: &str) -> Result<(u8, u8, Vec<(SessionId, u32)>), String> {
    let bad =
        || format!("REDIRECT {down} {to} {list}: expected <down> <to> <session>:<resend_from>[,…]");
    let (d, t) = (
        down.parse().map_err(|_| bad())?,
        to.parse().map_err(|_| bad())?,
    );
    let sessions = list
        .split(',')
        .map(|p| {
            let (s, q) = p.split_once(':').ok_or_else(bad)?;
            Ok((
                SessionId(s.parse().map_err(|_| bad())?),
                q.parse().map_err(|_| bad())?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((d, t, sessions))
}

/// The roster file: raw bytes, or the same bytes as hex text (whitespace ignored).
fn roster_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text: String = String::from_utf8_lossy(&raw)
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Ok(raw);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "roster: bad hex".to_owned())
        })
        .collect()
}

/// Adds every counter of `b` to `a`: the box's totals are the sum over its cores.
macro_rules! summing {
    ($($f:ident),*) => {
        fn add(a: &mut Counters, b: &Counters) {
            $(a.$f = a.$f.wrapping_add(b.$f);)*
        }
    };
}
fields!(summing);

/// How often each core publishes its counter deltas.
const PUBLISH: Duration = Duration::from_millis(100);

/// What every core thread shares.
struct Shared {
    t0: Instant,
    /// The operator asked to stop: the RX core stops taking packets.
    stop: AtomicBool,
    /// The RX core pushed its last entry.
    rx_done: AtomicBool,
    /// Shards that drained their ring after `rx_done`.
    shards_done: AtomicU64,
    /// The first core that could not start (pinning).
    failed: std::sync::OnceLock<String>,
    /// Cores that have pinned and wait for `go`.
    started: AtomicU64,
    /// Every core started: run.
    go: AtomicBool,
    /// A core thread could not be created: every core returns at once, so the scope's join
    /// never waits on a core blocked for a peer that does not exist.
    abort: AtomicBool,
    cpus: Vec<usize>,
}

impl Shared {
    fn now(&self) -> Nanos {
        Nanos(u64::try_from(self.t0.elapsed().as_nanos()).unwrap_or(u64::MAX))
    }

    /// Pins core `k` (0 RX, 1 sender, 2 + i shard i) when `[shards] cpus` is set, then waits
    /// for the main thread's `go` (or `abort`).
    fn start(&self, k: usize, name: &str) {
        if let Some(&cpu) = self.cpus.get(k)
            && let Err(e) = vyrn_nic::sys::pin_current_thread(cpu)
        {
            let _ = self.failed.set(format!("pin {name} to cpu {cpu}: {e}"));
            self.stop.store(true, Ordering::Release);
        }
        self.started.fetch_add(1, Ordering::AcqRel);
        while !self.go.load(Ordering::Acquire) && !self.aborted() {
            std::thread::yield_now();
        }
    }

    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Acquire)
    }
}

/// Polls until `work` returns 0 after `done` was seen, so a core stops only once its inputs
/// are drained.
fn drain_loop(done: impl Fn() -> bool, mut work: impl FnMut() -> usize) {
    let mut last = false;
    loop {
        if work() == 0 {
            if last {
                return;
            }
            last = done();
            std::thread::yield_now();
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run<S: BlockStore + Sync>(cfg: &Config, store: S, stdin_stop: bool) -> Result<(), String> {
    let home = cfg.home()?;
    let keys = KeySource::load(cfg)?;
    let fetch_epoch = cfg.roster.as_ref().map_or(0, |r| r.epoch);
    let fetch_keys = match &keys {
        Some(k) => k.derive(fetch_epoch)?,
        None => BTreeMap::new(),
    };
    let n = cfg.shards.n;
    let ip = cfg.nic.ip;
    let ncfg = NicConfig::new(BackendKind::Kernel, vec![PortConfig { id: PortId(0), ip }]);
    let mut nic = KernelUdp::open(&ncfg).map_err(|e| e.to_string())?;
    let bind = |udp_port| RxBind {
        lane: LaneId(0),
        port: PortId(0),
        ip,
        udp_port,
    };
    let ingest = nic
        .rx_ring(&bind(cfg.nic.ingest_port))
        .map_err(|e| e.to_string())?;
    let fetch = nic
        .rx_ring(&bind(cfg.nic.fetch_port))
        .map_err(|e| e.to_string())?;
    let mut txq = || {
        nic.tx_ring(PortId(0), TxClass::OrderStream)
            .map_err(|e| e.to_string())
    };
    let shard_tx = (0..n).map(|_| txq()).collect::<Result<Vec<_>, _>>()?;
    let tx = txq()?;
    let (in_addr, fetch_addr) = (ingest.local_addr(), fetch.local_addr());

    let mut ncfg = NodeConfig::new(
        home,
        cfg.src,
        ep(in_addr),
        cfg.dests.iter().copied().map(ep).collect(),
    );
    ncfg.fetch_keys = fetch_keys;
    ncfg.fetch_epoch = fetch_epoch;
    (ncfg.fetch_rate, ncfg.fetch_burst) = (cfg.fetch.rate, cfg.fetch.burst);
    let (mut rx, cores, mut sender) = shards::split(&ncfg, ingest, fetch, shard_tx, tx);
    if let Some(k) = &keys {
        k.install(&mut rx, fetch_epoch)?;
    }

    let labels = [
        ("role", "data".to_owned()),
        ("home", cfg.home.clone()),
        ("src", cfg.src.to_string()),
    ];
    let mut reg = Registry::with_labels(
        labels
            .into_iter()
            .map(|(k, v)| (Cow::Borrowed(k), Cow::Owned(v))),
    );
    let exported = Exported::new(&mut reg);
    let unprinted_metric = Counter::<u64>::default();
    reg.register(
        "vyrn_data_events_unprinted",
        "events dropped because the stdout queue was full",
        unprinted_metric.clone(),
    );
    let listener = TcpListener::bind(cfg.metrics.listen).map_err(|e| format!("metrics: {e}"))?;
    let maddr = listener.local_addr().map_err(|e| e.to_string())?;
    std::thread::Builder::new()
        .name("vyrn-data/metrics".into())
        .spawn(move || serve_metrics(listener, reg))
        .map_err(|e| e.to_string())?;

    let shared = Shared {
        t0: Instant::now(),
        stop: AtomicBool::new(false),
        rx_done: AtomicBool::new(false),
        shards_done: AtomicU64::new(0),
        failed: std::sync::OnceLock::new(),
        started: AtomicU64::new(0),
        go: AtomicBool::new(false),
        abort: AtomicBool::new(false),
        cpus: cfg.shards.cpus.clone(),
    };
    // Control input on stdin, one line each (crate docs, Control): `EPOCH <e>` moves the fetch
    // keys to epochs e and e + 1. EOF stops the box with `--stop-on-stdin-eof`. The queue is
    // bounded: a flood of lines blocks the stdin reader, never the RX core.
    let (ctl_tx, ctl) = std::sync::mpsc::sync_channel::<String>(CONTROL_QUEUE);
    let (acks, acks_rx) = std::sync::mpsc::sync_channel::<Result<String, String>>(16);
    std::thread::Builder::new()
        .name("vyrn-data/control".into())
        .spawn(move || {
            for a in acks_rx {
                match a {
                    Ok(l) => {
                        let mut out = std::io::stdout().lock();
                        let _ = writeln!(out, "{l}");
                        let _ = out.flush();
                    }
                    Err(l) => eprintln!("{l}"),
                }
            }
        })
        .map_err(|e| e.to_string())?;

    // Events go to stdout from their own thread through a bounded queue, so a slow or stalled
    // reader of stdout (or a bad-MAC flood) never blocks a shard.
    let (events, events_rx) = std::sync::mpsc::sync_channel::<Event>(EVENT_QUEUE);
    let (unprinted, queued) = (AtomicU64::new(0), AtomicU64::new(0));
    let drain = Arc::new(Drain::default());
    {
        let drain = Arc::clone(&drain);
        std::thread::Builder::new()
            .name("vyrn-data/events".into())
            .spawn(move || print_events(&events_rx, &drain))
            .map_err(|e| e.to_string())?;
    }
    let hand_over = |node_events: std::vec::Drain<'_, Event>| {
        for e in node_events {
            if events.try_send(e).is_ok() {
                queued.fetch_add(1, Ordering::Relaxed);
            } else {
                unprinted.fetch_add(1, Ordering::Relaxed);
                unprinted_metric.inc();
            }
        }
    };

    // The hop rings: RX → shard i, shard i → sender, and RX → sender (RANGE) last.
    let mut shard_rings: Vec<ShardRing> = (0..n).map(|_| ShardRing::new(&Hw)).collect();
    let mut sender_rings: Vec<SenderRing> = (0..=n).map(|_| SenderRing::new(&Hw)).collect();
    let (mut to_shard, shard_in): (Vec<_>, Vec<_>) = shard_rings
        .iter_mut()
        .filter_map(|r| r.split().map(|(p, [c])| (p, c)))
        .unzip();
    let (mut to_sender, mut sender_in): (Vec<_>, Vec<_>) = sender_rings
        .iter_mut()
        .filter_map(|r| r.split().map(|(p, [c])| (p, c)))
        .unzip();
    let mut rx_out = to_sender.pop().ok_or("no sender ring")?;

    let mut total = Counters::default();
    std::thread::scope(|sc| -> Result<(), String> {
        let (shared, store, hand_over) = (&shared, &store, &hand_over);
        // A spawn error stops every core already started before the scope joins them.
        let abort = |e: String| {
            shared.abort.store(true, Ordering::Release);
            e
        };
        let spawn = |name: String| std::thread::Builder::new().name(name);
        let rx_core = spawn("vyrn-data/rx".into())
            .spawn_scoped(sc, {
                let (mut ex, keys, acks) = (exported.handle(), keys.as_ref(), &acks);
                move || {
                    shared.start(0, "rx");
                    let mut published = Instant::now();
                    while !shared.stop.load(Ordering::Acquire) && !shared.aborted() {
                        let work = rx.poll(shared.now(), &mut to_shard, &mut rx_out);
                        while let Ok(l) = ctl.try_recv() {
                            control(&l, keys, &mut rx, &mut to_shard, acks);
                        }
                        if published.elapsed() >= PUBLISH {
                            ex.publish(rx.counters());
                            published = Instant::now();
                        }
                        // A turn with fetch work yields too: under a fetch flood this core never
                        // idles, and on a shared CPU it would take the sender's turns, so DATA_HB
                        // would lose its cadence and replicas would mark the box down.
                        if work == 0 || rx.fetches() > 0 {
                            std::thread::yield_now();
                        }
                    }
                    shared.rx_done.store(true, Ordering::Release);
                    ex.publish(rx.counters());
                    *rx.counters()
                }
            })
            .map_err(|e| abort(e.to_string()))?;
        let mut shard_threads = Vec::with_capacity(n);
        for (i, ((mut core, mut input), mut out)) in
            cores.into_iter().zip(shard_in).zip(to_sender).enumerate()
        {
            let mut ex = exported.handle();
            let t = spawn(format!("vyrn-data/shard{i}"))
                .spawn_scoped(sc, move || {
                    shared.start(2 + i, &format!("shard {i}"));
                    let mut published = Instant::now();
                    drain_loop(
                        || shared.aborted() || shared.rx_done.load(Ordering::Acquire),
                        || {
                            let w = core.poll(&mut input, &mut out, store);
                            // As on the RX core: yield after fetch work (DATA_HB cadence).
                            if core.fetches() > 0 {
                                std::thread::yield_now();
                            }
                            // Never block a shard on stdout: a full queue drops and counts.
                            hand_over(core.drain_events());
                            if published.elapsed() >= PUBLISH {
                                ex.publish(core.counters());
                                published = Instant::now();
                            }
                            w
                        },
                    );
                    shared.shards_done.fetch_add(1, Ordering::AcqRel);
                    ex.publish(core.counters());
                    *core.counters()
                })
                .map_err(|e| abort(e.to_string()))?;
            shard_threads.push(t);
        }
        let sender_core = spawn("vyrn-data/sender".into())
            .spawn_scoped(sc, {
                let mut ex = exported.handle();
                move || {
                    shared.start(1, "sender");
                    let mut published = Instant::now();
                    drain_loop(
                        || {
                            shared.aborted()
                                || shared.shards_done.load(Ordering::Acquire) == n as u64
                        },
                        || {
                            let w = sender.poll(shared.now(), &mut sender_in);
                            if published.elapsed() >= PUBLISH {
                                ex.publish(sender.counters());
                                published = Instant::now();
                            }
                            w
                        },
                    );
                    sender.flush(shared.now());
                    ex.publish(sender.counters());
                    *sender.counters()
                }
            })
            .map_err(|e| abort(e.to_string()))?;

        while shared.started.load(Ordering::Acquire) < n as u64 + 2 {
            std::thread::yield_now();
        }
        shared.go.store(true, Ordering::Release);
        if shared.failed.get().is_none() {
            println!("READY vyrn-data ingest={in_addr} fetch={fetch_addr} metrics={maddr}");
            let _ = std::io::stdout().flush();
            // Not scoped: it blocks in read_line until stdin closes, which may be never.
            let eof = Arc::new(AtomicBool::new(false));
            let stdin_eof = Arc::clone(&eof);
            std::thread::Builder::new()
                .name("vyrn-data/stdin".into())
                .spawn(move || {
                    let eof = stdin_eof;
                    let mut line = String::new();
                    while std::io::stdin()
                        .lock()
                        .read_line(&mut line)
                        .is_ok_and(|n| n > 0)
                    {
                        if ctl_tx.send(std::mem::take(&mut line)).is_err() {
                            return;
                        }
                    }
                    if stdin_stop {
                        eof.store(true, Ordering::Release);
                    }
                })
                .map_err(|e| abort(e.to_string()))?;
            while !eof.load(Ordering::Acquire) && !shared.stop.load(Ordering::Acquire) {
                std::thread::park_timeout(Duration::from_millis(20));
            }
            shared.stop.store(true, Ordering::Release);
        }
        let join = |r: std::thread::Result<Counters>| r.map_err(|_| "a core panicked".to_owned());
        add(&mut total, &join(rx_core.join())?);
        for t in shard_threads {
            add(&mut total, &join(t.join())?);
        }
        add(&mut total, &join(sender_core.join())?);
        Ok(())
    })?;
    if let Some(e) = shared.failed.get() {
        return Err(e.clone());
    }
    // Give the output thread `DRAIN` to print what is queued, then close it: whatever it has not
    // claimed by then is counted and never printed, so every event is either an EVENT line or in
    // `events_unprinted` (at most one line, the one being written as the process exits, may be
    // cut short).
    let queued = queued.load(Ordering::Relaxed);
    let deadline = Instant::now() + DRAIN;
    while drain.printed.load(Ordering::Acquire) < queued && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let claimed = drain.claimed.fetch_or(CLOSED, Ordering::AcqRel) & !CLOSED;
    let abandoned = queued.saturating_sub(claimed);
    let unprinted = unprinted.load(Ordering::Relaxed).wrapping_add(abandoned);
    unprinted_metric.inc_by(abandoned);
    let c = total;
    // A closed stdout (the supervisor went away) is not a reason to fail the stop.
    let _ = writeln!(
        std::io::stdout(),
        "STATS stored={} data_frames={} heartbeats={} duplicate={} fetch_unauth={} fetch_limited={} bad_mac={} events_dropped={} events_unprinted={unprinted} fetch_ring_hit={} fetch_log_hit={} fetch_miss={} fetch_resent={} hop_full={} redirects={} redirect_unknown={} redirect_retried={} redirect_dropped={} shards={n}",
        c.stored,
        c.data_frames,
        c.heartbeats,
        c.duplicate,
        c.fetch_unauth,
        c.fetch_limited,
        c.bad_mac,
        c.events_dropped,
        c.fetch_ring_hit,
        c.fetch_log_hit,
        c.fetch_miss,
        c.fetch_resent,
        c.hop_full,
        c.redirects,
        c.redirect_unknown,
        c.redirect_retried,
        c.redirect_dropped
    );
    Ok(())
}
