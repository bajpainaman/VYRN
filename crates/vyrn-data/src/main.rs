//! `vyrn-data`, the data box (03 §1, 07 §5; 11 §1.3, §8.4, §10.1): main.rs and config wiring
//! only. Every decision is made in the library; this file opens the NIC, the log source and the
//! metrics listener, then runs [`DataNode::poll`] in a loop.
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
//! | `[[fetch_key]] ip, key` | `K_fetch` per requester (07 §5.5); none is refused unless `dev` |
//! | `[fetch] rate, burst` | per-source fetch limit (defaults 20,000/s, 256) |
//! | `[store] dirs = [..]` | `FileStore` drives read as the log source; none: an empty `MemStore` |
//! | `[metrics] listen` | Prometheus text on this address, default `127.0.0.1:9464` (11 §8.4) |
//!
//! A key handle is `env:NAME` (hex in that variable) or, on DEV only, `hex:<32 hex digits>`.
//!
//! **Start** (11 §10.1); each step fail-stops with exit code 2 and one line on stderr: load and
//! check the config → resolve keys → open the log source → open the NIC (ingest, fetch, one TX
//! queue) → bind metrics → print
//!
//! ```text
//! READY vyrn-data ingest=<ip:port> fetch=<ip:port> metrics=<ip:port>
//! ```
//!
//! **Events on stdout**, one line each: `EVENT bad_mac session=<s> pkt_seq=<q>`, `EVENT
//! copy_conflict session=<s> pkt_seq=<q>` (the transport to the sequencer's control core is a
//! follow-up), written by their own thread from a bounded queue so stdout never blocks the poll
//! loop (a full queue drops and counts the line), and at exit `STATS stored=<n> data_frames=<n>
//! heartbeats=<n> duplicate=<n> fetch_unauth=<n> fetch_limited=<n> events_unprinted=<n>`.
//!
//! **Metrics.** Every [`vyrn_data::Counters`] field as `vyrn_data_<field>_total`, labels `role`,
//! `home`, `src`. The loop publishes deltas every 100 ms; a std thread serves `GET` on the
//! listener. *Reading:* 11 §8.4 says a tokio task; one blocking thread does the same job here.
//!
//! **Stop.** With `--stop-on-stdin-eof`, closing stdin flushes open frames and prints `STATS`.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{SocketAddrV4, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use vyrn_data::config::Config;
use vyrn_data::{Counters, DataNode, Event, NodeConfig};
use vyrn_log::{BlockStore, FileStore, MemStore};
use vyrn_nic::frame::Endpoint;
use vyrn_nic::{
    BackendKind, KernelUdp, NicBackend, NicConfig, PortConfig, PortId, RxBind, TxClass,
};
use vyrn_types::{LaneId, Nanos};

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
            rx_pkts, bad_frame, header, book, unknown_session, bad_mac, duplicate, late, stored,
            conflicts, data_frames, heartbeats, tx_full, events_dropped, fetch_bad, fetch_unauth,
            fetch_limited, fetch_ring_hit, fetch_log_hit, fetch_miss, fetch_resent, log_bad
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

/// Events waiting for the output thread; more are dropped and counted (`events_unprinted`).
const EVENT_QUEUE: usize = 4096;

fn print_events(rx: &std::sync::mpsc::Receiver<Event>) {
    while let Ok(e) = rx.recv() {
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

fn run<S: BlockStore>(cfg: &Config, store: S, stdin_stop: bool) -> Result<(), String> {
    let home = cfg.home()?;
    let fetch_keys = cfg.fetch_keys()?;
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
    let tx = nic
        .tx_ring(PortId(0), TxClass::OrderStream)
        .map_err(|e| e.to_string())?;
    let (in_addr, fetch_addr) = (ingest.local_addr(), fetch.local_addr());

    let mut ncfg = NodeConfig::new(
        home,
        cfg.src,
        ep(in_addr),
        cfg.dests.iter().copied().map(ep).collect(),
    );
    ncfg.fetch_keys = fetch_keys;
    (ncfg.fetch_rate, ncfg.fetch_burst) = (cfg.fetch.rate, cfg.fetch.burst);
    let mut node = DataNode::new(ncfg, ingest, fetch, tx, store);

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
    let mut exported = Exported::new(&mut reg);
    let listener = TcpListener::bind(cfg.metrics.listen).map_err(|e| format!("metrics: {e}"))?;
    let maddr = listener.local_addr().map_err(|e| e.to_string())?;
    std::thread::Builder::new()
        .name("vyrn-data/metrics".into())
        .spawn(move || serve_metrics(listener, reg))
        .map_err(|e| e.to_string())?;

    let stop = Arc::new(AtomicBool::new(false));
    if stdin_stop {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("vyrn-data/stdin".into())
            .spawn(move || {
                let mut sink = String::new();
                while std::io::stdin()
                    .lock()
                    .read_line(&mut sink)
                    .is_ok_and(|n| n > 0)
                {
                    sink.clear();
                }
                stop.store(true, Ordering::Release);
            })
            .map_err(|e| e.to_string())?;
    }

    // Events go to stdout from their own thread through a bounded queue, so a slow or stalled
    // reader of stdout (or a bad-MAC flood) never blocks ingest.
    let (events, events_rx) = std::sync::mpsc::sync_channel::<Event>(EVENT_QUEUE);
    let mut unprinted = 0u64;
    std::thread::Builder::new()
        .name("vyrn-data/events".into())
        .spawn(move || print_events(&events_rx))
        .map_err(|e| e.to_string())?;
    println!("READY vyrn-data ingest={in_addr} fetch={fetch_addr} metrics={maddr}");
    let _ = std::io::stdout().flush();
    let t0 = Instant::now();
    let mut published = t0;
    let now = |t0: Instant| Nanos(u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX));
    while !stop.load(Ordering::Acquire) {
        let work = node.poll(now(t0));
        // Never block the poll loop on stdout: a full queue drops and counts the line.
        for e in node.drain_events() {
            if events.try_send(e).is_err() {
                unprinted = unprinted.wrapping_add(1);
            }
        }
        if published.elapsed() >= Duration::from_millis(100) {
            exported.publish(node.counters());
            published = Instant::now();
        }
        if work == 0 {
            std::thread::yield_now();
        }
    }
    node.flush(now(t0));
    let c = *node.counters();
    exported.publish(&c);
    // A closed stdout (the supervisor went away) is not a reason to fail the stop.
    let _ = writeln!(
        std::io::stdout(),
        "STATS stored={} data_frames={} heartbeats={} duplicate={} fetch_unauth={} fetch_limited={}",
        c.stored,
        c.data_frames,
        c.heartbeats,
        c.duplicate,
        c.fetch_unauth,
        c.fetch_limited
    );
    Ok(())
}
