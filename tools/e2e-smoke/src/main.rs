//! `e2e-smoke`: a multi-node end-to-end smoke run on one machine, over `kernel_udp`.
//!
//! # Contract
//!
//! **Invocation.** `e2e-smoke [--bin-dir DIR] [--validators K] [--packets P] [--rate R]
//! [--seed S] [--wait-s T] [--seq-cpus L] [--validator-cpus L] [--strict-hashlag] [--finality]
//! [--data]`. `DIR` holds `vyrn-seq`, `vyrn-validator` and (with `--data`) `vyrn-data`
//! (default: this binary's directory). Exit 0 when every enabled check passes, 1 when one fails,
//! 2 when the run could not start. Every wait has a deadline of `T` seconds (default 30): the
//! harness never blocks on a child, a socket or a pipe without one, and kills every child it
//! started on any exit path.
//!
//! **Topology.** `K` `vyrn-validator` processes (ephemeral order ports), one `vyrn-seq` DEV box
//! with two dedicated lanes whose `[replication] order` lists every validator and the harness's
//! replay tap, and the harness itself as the client of every session.
//!
//! **Workload.** `vyrn-bench`'s generator over `wl-smoke.toml` (two MM sessions on each of lanes
//! 0 and 1), seed `S`, rate `R`, the first `P` packets. The stream is deterministic in
//! `(config, S, R, P)`. Each packet is re-addressed to its DEV session (generation 1, as
//! `vyrn-seq` opens DEV sessions) and re-MACed with that session's key; its messages are
//! unchanged. Handles in Cancel/Reduce/Replace stay the generator's placeholders, so many of
//! them are rejected: deterministically, which is all replay needs. Packets are paced by the
//! stream's `send_ns`.
//!
//! **Checks**, one `CHECK <name> PASS|FAIL|SKIP <detail>` line each:
//!
//! | name | passes when |
//! |---|---|
//! | `seq` | the box exits 0, `records` equals the packets sent, `seal_violations=0`, at least 2 blocks |
//! | `validators` | each validator reports heights `0..=H` contiguous with the box's `first_step`/`last_step`, every verdict `Valid`, no `FAULT` (R5 for `REP_E_HASHLAG`) |
//! | `replay` | the tap's `OrderCore` readies the same blocks, holding every packet sent exactly once, `DataJoin::check` passes on each, `RustReplay` replays every block, and its responses equal the responses the client received from the box |
//! | `replica-out` | with `--data` every validator replays (`[replay]`) and its `out=<hex>` on each `BLOCK` line equals the tap's output hash of that block; one stopped at `REP_E_HASHLAG` is compared on the blocks it printed (R5); SKIP while no validator replays |
//! | `finality` | with `--finality` (default 4 validators, a DEV roster as in `bin/vyrn-validator/tests/committee.rs`, `[consensus]` in every validator and the box): while the box still runs, the box's listener (`FINAL height=<h> ... from=<votes\|cert>`) and every validator that did not stop print `FINAL` through the box's last block. A validator's `OUT_OF_ORDER`, `VOTER_FAULT`, `DATA_FAULT` or `REPLAY_FAULT` line fails `validators`; `REP_E_HASHLAG` follows R5 and R6. SKIP without it |
//! | `data` | with `--data`: the client sends copy 2 of every packet to a `vyrn-data` node (07 §5.1), whose `DATA`/`DATA_HB` frames reach the tap through `vyrn_replica::DataFeed`; the node stores every packet sent (`STATS stored`), `bad_mac`, `events_dropped` and `events_unprinted` are 0 with no `EVENT` line, the feed reports no gap or rejected frame, and that join is the one `replay` reads; SKIP without `--data` |
//!
//! **Readings** (the spec does not settle these; PR body):
//! - R1. The box publishes no output hash. The reference for "replay matches the sequencer" is
//!   what the box put on the wire: every response the client received, per session, sorted by
//!   `(resp_seq, bytes)`. The replay side is every `lane_resp` and every fill `tx` with
//!   `resp_seq ≠ 0` (the box does not send `resp_seq` 0 TX packets yet). Fill TX `step`, `lane`
//!   and `role`, which `output_hash` covers, are not on the wire, so the per-block output hash
//!   itself cannot be recomputed from the box's side.
//! - R2. The tap's engine is built the way `vyrn-seq` builds its DEV engine (`EnginePlan`,
//!   `engine_loop`), copied here. A drift between the two shows as a replay failure.
//! - R3. With `--data`, the tap's `DataJoin` is filled only from `vyrn-data`'s frames through
//!   `vyrn_replica::DataFeed` (the tap is destination 0). Without it, the join gets copy 2 from
//!   the client in process. With `--data` the validators are destinations 1..=n: each reads its
//!   data RX queue, checks `data_root` (vote-rule item 3), fetches gaps from the node, and
//!   replays (`[replay]`, the box's engine and sessions), so `replica-out` runs. Without it they
//!   have no data and no replay.
//! - R4. The validators' `FINAL height=<last_height> view= first= kind= sigs=` and the box's
//!   `FINAL height=<h> view= from=` (#121) are parsed by `height=` only. The committee is a DEV
//!   roster: vote seeds `[i + 1; 32]`, genesis `[0; 32]`, the run's `seq_key` as primary and a
//!   dummy standby, repl and CTRL ports picked below the ephemeral range, `delta_ms = 500`.
//! - R6. With more than `n − Q` validators stopped at `REP_E_HASHLAG` (Q = n − ⌊(n − 1)/3⌋),
//!   no quorum is left and the box cannot finalize the rest: DEV timing, a `WARN`. The box must
//!   still have finalized from votes when quorum held for two heights or more, so a broken vote
//!   path fails. `--strict-hashlag` drops the exception.
//! - R5. `REP_E_HASHLAG` (07 §3.7 INV-REP-8) is a 1 ms real-time bound that the validator
//!   measures with user-space receive times and that 07 §7.2 budgets for pinned cores. On an
//!   unpinned DEV machine one preemption between an ORDER frame and its HASH frame trips it, so
//!   by default a validator that stops at it is a `WARN`: its blocks before the fault must still
//!   be the box's. It stays a `WARN` when every validator stops at it (all of them can stop at
//!   one height when the box is preempted between the two frames): the replay tap's order core,
//!   which has no real-time bound, must still ready every height. Any other fault, an `Invalid`
//!   verdict, a stall or a block that differs from the box's fails. `--strict-hashlag` fails a
//!   `REP_E_HASHLAG` stop too and requires one validator to cover every height. The shipped
//!   bound stays 1 ms; the harness changes no validator rule. `--seq-cpus` and `--validator-cpus` (taskset masks)
//!   keep the box's two polling threads off the validators' cores. Without them all validators
//!   can stop at one height when the box is preempted between an ORDER frame and its HASH frame.
//!
//! **Post-only.** A post-only `New` that crosses the lane's snapshot is forwarded, and the BBO
//! core decides it against the true book (03 ARC-D6), so `wl-smoke.toml`, which sends them,
//! replays byte for byte and gates CI alongside `wl-smoke-nocross.toml`.
//!
//! **Build.** Run release binaries: a debug `vyrn-validator` spends more than
//! `REP_HASHLAG_MAX_NS` (1 ms) on ORDER frames often enough to raise `REP_E_HASHLAG` in most
//! runs (R5).
//!
//! DEV timings on shared machines are not latency results; the harness prints none.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use clap::Parser;
use vyrn_bbo::{Bbo, Phase, Record, TxEntry};
use vyrn_bench::config::{Config as WlConfig, Mode};
use vyrn_bench::generator::{GenOptions, Generator, session_keys};
use vyrn_cut::Hw;
use vyrn_engine::{Engine, NoResponses, Rec, Shared, Sink};
use vyrn_lane::{ArenaConfig, Lane, PathTable, RespPkt, SessionSpec};
use vyrn_log::Layout;
use vyrn_replica::{
    BlockInputs, DataFeed, DataJoin, EpochView, OrderCore, ReplayEngine, RustReplay,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, Hash, Height, LaneId, PacketFlags, PubKey, SessionId, Tick,
};
use vyrn_wire::{ReqHeader, Request, Response, encode_request};

const WORKLOAD: &str = include_str!("../wl-smoke.toml");
const SEQ_SEED: [u8; 32] = [0x42; 32];
const LANES: usize = 2;
const NA: usize = 16;
const BOOK: u16 = 7;
const QUOTE: u64 = 1_000_000_000_000;
const BASE: u64 = 1_000_000_000;
// The box's DEV engine (bin/vyrn-seq: config.toml shape and `EnginePlan`), R2.
const TICK_MIN: u32 = 1;
const TICK_MAX: u32 = 512;
const WIN_CENTER: u32 = 100;
const SLOT_CAP: u32 = 1024;

#[derive(Parser)]
#[command(about = "Multi-node end-to-end smoke run (vyrn-seq, vyrn-validator, replay tap)")]
struct Cli {
    /// Directory holding vyrn-seq and vyrn-validator (default: this binary's directory).
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    /// Workload config (default: the embedded wl-smoke.toml).
    #[arg(long)]
    workload: Option<PathBuf>,
    /// Validators (default 3, or 4 with --finality: n = 3f + 1 with f = 1).
    #[arg(long)]
    validators: Option<usize>,
    #[arg(long, default_value_t = 1500)]
    packets: u64,
    /// Messages per second (replaces the workload's rate).
    #[arg(long, default_value_t = 2000)]
    rate: u64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Deadline of every wait, in seconds.
    #[arg(long, default_value_t = 30)]
    wait_s: u64,
    /// Require finality lines from every validator (R4).
    #[arg(long)]
    finality: bool,
    /// CPU list for vyrn-seq (taskset -c), so the box's threads do not share cores with the
    /// validators' polling threads (R5).
    #[arg(long)]
    seq_cpus: Option<String>,
    /// CPU list for every vyrn-validator (taskset -c).
    #[arg(long)]
    validator_cpus: Option<String>,
    /// Fail a validator's REP_E_HASHLAG too (pinned rigs); by default it is a WARN (R5).
    #[arg(long)]
    strict_hashlag: bool,
    /// Route payloads through a vyrn-data node.
    #[arg(long)]
    data: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("e2e-smoke: {e}");
            ExitCode::from(2)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ----- the workload -----

struct Sess {
    id: SessionId,
    lane: u8,
    acct: u32,
    k_seq: [u8; 16],
    k_out: [u8; 16],
}

struct Pkt {
    send_ns: u64,
    lane: u8,
    session: SessionId,
    pkt_seq: u32,
    bytes: Vec<u8>,
}

/// The generator's first `n` packets, re-addressed to the DEV sessions (module docs).
fn workload(cli: &Cli) -> Result<(Vec<Sess>, Vec<Pkt>), String> {
    let text = match &cli.workload {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => WORKLOAD.to_owned(),
    };
    let cfg = WlConfig::parse(&text).map_err(|e| e.to_string())?;
    let opts = GenOptions {
        seed: cli.seed,
        rate_override: Some(cli.rate),
    };
    let generator = Generator::new(&cfg, &opts).map_err(|e| e.to_string())?;
    let mut sessions: BTreeMap<u32, Sess> = BTreeMap::new();
    let mut pkts = Vec::new();
    for p in generator.take(usize::try_from(cli.packets).map_err(|e| e.to_string())?) {
        let req = Request::parse(p.bytes()).map_err(|e| format!("generator packet: {e:?}"))?;
        let h = req.header();
        let gen0 = h.session();
        let slot = vyrn_wire::session_slot(gen0);
        let id = vyrn_wire::session_id(slot, p.lane, 1).ok_or("session id")?;
        let s = sessions.entry(id.0).or_insert_with(|| {
            let (k_seq, _) = session_keys(cli.seed, id, Mode::Base);
            let k_out = vyrn_crypto::hash::hash(&k_seq).0;
            Sess {
                id,
                lane: p.lane.0,
                acct: u32::from(slot) + 1,
                k_seq,
                k_out: k_out.first_chunk::<16>().copied().unwrap_or_default(),
            }
        });
        let msgs = req
            .msgs()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("generator message: {e:?}"))?;
        let pkt_seq = h.pkt_seq.get();
        let hdr = ReqHeader::new(id, pkt_seq, 0, BookId(BOOK), false);
        let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
        let n = encode_request(&mut buf, hdr, &msgs, &s.k_seq, None).ok_or("re-encode")?;
        pkts.push(Pkt {
            send_ns: p.send_ns,
            lane: p.lane.0,
            session: id,
            pkt_seq,
            bytes: buf.get(..n).unwrap_or_default().to_vec(),
        });
    }
    Ok((sessions.into_values().collect(), pkts))
}

// ----- child processes -----

/// Every line a child prints on stdout, tagged with its node index.
type Lines = Receiver<(usize, String)>;

struct Node {
    name: String,
    child: Child,
    lines: Vec<String>,
}

/// Kills whatever is still running when the harness returns, on every path.
struct Nodes(Vec<Node>);

impl Drop for Nodes {
    fn drop(&mut self) {
        for n in &mut self.0 {
            let _ = n.child.kill();
            let _ = n.child.wait();
        }
    }
}

impl Nodes {
    fn spawn(
        &mut self,
        name: &str,
        cmd: &mut Command,
        tx: &Sender<(usize, String)>,
    ) -> Result<usize, String> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("{name}: {e}"))?;
        let out = child.stdout.take().ok_or("stdout")?;
        let idx = self.0.len();
        let tx = tx.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                let Ok(l) = l else { break };
                if tx.send((idx, l)).is_err() {
                    break;
                }
            }
        });
        self.0.push(Node {
            name: name.to_owned(),
            child,
            lines: Vec::new(),
        });
        Ok(idx)
    }

    /// Takes lines until `want` holds or `deadline` passes.
    fn wait(
        &mut self,
        rx: &Lines,
        deadline: Instant,
        what: &str,
        mut want: impl FnMut(&[Node]) -> bool,
    ) -> Result<(), String> {
        while !want(&self.0) {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok((i, l)) => {
                    if let Some(n) = self.0.get_mut(i) {
                        n.lines.push(l);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("timed out waiting for {what}"));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!("every child exited before {what}"));
                }
            }
        }
        Ok(())
    }

    /// Closes stdin (`--stop-on-stdin-eof`) and waits for the child to exit and its `STATS`.
    fn stop(&mut self, i: usize, rx: &Lines, deadline: Instant) -> Result<bool, String> {
        let n = self.0.get_mut(i).ok_or("node")?;
        drop(n.child.stdin.take());
        let name = n.name.clone();
        self.wait(rx, deadline, &format!("{name} STATS"), |ns| {
            ns.get(i)
                .is_some_and(|n| n.lines.iter().any(|l| l.starts_with("STATS")))
        })?;
        let n = self.0.get_mut(i).ok_or("node")?;
        loop {
            if let Some(st) = n.child.try_wait().map_err(|e| e.to_string())? {
                return Ok(st.success());
            }
            if Instant::now() > deadline {
                return Err(format!("{name} did not exit"));
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
}

fn line<'a>(n: &'a Node, prefix: &str) -> Option<&'a str> {
    n.lines.iter().find_map(|l| l.strip_prefix(prefix))
}

fn field<'a>(l: &'a str, k: &str) -> Option<&'a str> {
    l.split(' ')
        .find_map(|f| f.strip_prefix(k)?.strip_prefix('='))
}

/// `(height, first_step, last_step)` and the whole line of every `BLOCK` line.
fn blocks(n: &Node) -> Vec<((u64, u64, u64), &str)> {
    n.lines
        .iter()
        .filter_map(|l| {
            let b = l.strip_prefix("BLOCK ")?;
            let g = |k| field(b, k)?.parse().ok();
            Some(((g("height")?, g("first_step")?, g("last_step")?), b))
        })
        .collect()
}

/// `bin`, under `taskset -c cpus` when a CPU list is given.
fn command(bin: &Path, cpus: Option<&str>) -> Command {
    match cpus {
        Some(c) => {
            let mut cmd = Command::new("taskset");
            cmd.arg("-c").arg(c).arg(bin);
            cmd
        }
        None => Command::new(bin),
    }
}

// ----- the replay tap -----

struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> BookId {
        BookId(BOOK)
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

/// One sent response as the client saw it, or as replay produced it: session, resp_seq,
/// echo_pkt and the records' 01 §6.4 bytes (R1).
type Resp = (u32, u32, u32, Vec<[u8; 16]>);

#[derive(Default)]
struct Collect(Vec<Resp>);

impl Sink for Collect {
    fn record(&mut self, _: &Rec<'_>) {}
    fn lane_resp(&mut self, _: LaneId, p: &RespPkt) {
        let recs = p.records().iter().map(|r| r.encode()).collect();
        self.0.push((p.session.0, p.resp_seq, p.echo_pkt, recs));
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        if h.resp_seq != 0 {
            let recs = recs.iter().map(|r| r.encode()).collect();
            self.0.push((h.session.0, h.resp_seq, h.pkt_seq, recs));
        }
    }
}

/// The order frames the tap received, until `stop`.
fn tap(sock: UdpSocket, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut frames = Vec::new();
        let mut buf = [0u8; 65536];
        while !stop.load(Ordering::Acquire) {
            if let Ok(k) = sock.recv(&mut buf) {
                frames.push(buf.get(..k).unwrap_or_default().to_vec());
            }
        }
        frames
    })
}

/// The responses the client received, until `stop`, unchecked.
fn client(sock: UdpSocket, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Acquire) {
            if let Ok(k) = sock.recv(&mut buf) {
                got.push(buf.get(..k).unwrap_or_default().to_vec());
            }
        }
        got
    })
}

/// The box's DEV engine (R2), with the sessions open and funded.
fn replay_all(
    sessions: &[Sess],
    data: DataJoin,
    blocks: &[BlockInputs<LANES>],
) -> Result<(Vec<Hash>, Vec<Resp>), String> {
    let n = u8::try_from(LANES).map_err(|e| e.to_string())?;
    let (tick_min, tick_max) = (Tick(TICK_MIN), Tick(TICK_MAX));
    let book = BookId(BOOK);
    let spec = BookSpec::new(1, tick_min, tick_max, 10_000).ok_or("tick range")?;
    let bbo = Bbo::new(vyrn_bbo::Config {
        n_lanes: n,
        epoch: Epoch(0),
        slot_cap: usize::try_from(SLOT_CAP).map_err(|e| e.to_string())?,
        seg_cap: SLOT_CAP,
        win_center: Tick(WIN_CENTER),
        phase: Phase::Continuous,
        tick_min,
        tick_max,
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(WIN_CENTER),
        pool: 0,
    });
    let arena = ArenaConfig {
        slot_cap: SLOT_CAP,
        seg_cap: SLOT_CAP,
        tick_min,
        tick_max,
        accounts: u32::try_from(NA).map_err(|e| e.to_string())?,
        journal: SLOT_CAP,
    };
    let lanes: Vec<_> = (0..n)
        .map(|l| vyrn_lane::Config {
            lane: LaneId(l),
            n_lanes: n,
            epoch: Epoch(0),
            book,
            spec,
            path: PathTable::spec(),
            fwd_deadline_ns: vyrn_lane::lane::FWD_DEADLINE_NS,
            phase: Phase::Continuous,
            out_cap: 4096,
        })
        .collect();
    let vis = Hw;
    let mut shared =
        Shared::new(&vis, LANES, arena, &bbo.initial_snapshot()).ok_or("engine shape")?;
    let mut engine: Engine<'_, Hw, NA> =
        Engine::new(&vis, &mut shared, bbo, &lanes, |cfg, aw, ports| {
            let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
            acct.max_open_orders = 1000;
            Lane::<Hw, NA>::new(cfg, aw, ports, acct)
        })
        .ok_or("engine lanes")?;
    for s in sessions {
        let lane = engine.lane_mut(usize::from(s.lane)).ok_or("lane")?;
        let (_, bal) = lane.account_mut(AcctSlot(s.acct)).ok_or("account")?;
        bal.quote_free = u128::from(QUOTE);
        bal.base_free = BASE;
        let ok = lane.open_session(&SessionSpec {
            id: s.id,
            acct: AcctSlot(s.acct),
            k_seq: s.k_seq,
            book,
            buckets: SessionBuckets::default(),
        });
        if !ok {
            return Err(format!("session {:?} did not open", s.id));
        }
    }
    let mut rep = RustReplay::new(engine, data, NoResponses, Collect::default());
    let mut hashes = Vec::new();
    for b in blocks {
        let h = b.header.height.0;
        rep.payloads_mut()
            .check(b)
            .map_err(|e| format!("height {h}: data join: {e:?}"))?;
        let out = rep.replay_block(b).map_err(|e| {
            let steps: Vec<String> = b
                .steps
                .iter()
                .map(|m| {
                    format!(
                        "{}:{:?}:l{}#{}:f{}",
                        m.rec.step.0,
                        m.rec.kind,
                        m.rec.src_lane.0,
                        m.rec.src_lane_seq.0,
                        m.rec.flags
                    )
                })
                .collect();
            format!("{} (block steps {})", e.0, steps.join(" "))
        })?;
        hashes.push(out.output_hash);
        rep.release(b.header.height);
    }
    rep.finish().map_err(|e| e.0)?;
    Ok((hashes, rep.into_sink().0))
}

// ----- the run -----

struct Report(bool);

impl Report {
    fn check(&mut self, name: &str, r: Result<String, String>) {
        match r {
            Ok(d) => println!("CHECK {name} PASS {d}"),
            Err(d) => {
                self.0 = false;
                println!("CHECK {name} FAIL {d}");
            }
        }
    }
    fn skip(name: &str, why: &str) {
        println!("CHECK {name} SKIP {why}");
    }
}

fn seq_config(
    dir: &Path,
    order: &[String],
    sessions: &[Sess],
    cons: Option<&Cons>,
) -> Result<PathBuf, String> {
    let mut s = format!(
        r#"schema = 1
protocol = 1
role = "seq"
mode = "BASE"
home = "LDN"
book = {BOOK}

[engine]
dedicated = {LANES}
tick_min = {TICK_MIN}
tick_max = {TICK_MAX}
win_center = {WIN_CENTER}
slot_cap = {SLOT_CAP}

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
port_base = 0

[cores]
engine = 2
stream = 4
seal = "count"

[replication]
order = [{}]
block_ms = 5

[keys]
seq = "env:VYRN_E2E_SEQ_SEED"
"#,
        order
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for x in sessions {
        s.push_str(&format!(
            "\n[[dev_session]]\nlane = {}\nslot = {}\naccount = {}\nk_seq = \"{}\"\nk_out = \"{}\"\nquote = {QUOTE}\nbase = {BASE}\n",
            x.lane,
            vyrn_wire::session_slot(x.id),
            x.acct,
            hex(&x.k_seq),
            hex(&x.k_out)
        ));
    }
    if let Some(c) = cons {
        s.push_str(&format!(
            "\n[consensus]\nctrl = \"{}\"\nroster = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\n",
            c.ctrl,
            c.roster.display(),
            c.roster_hash,
            hex(&[0; 32])
        ));
    }
    let p = dir.join("seq.toml");
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

/// `n` free UDP and TCP ports below the kernel's ephemeral range, for the validators' data queues. Ports
/// the kernel hands out (port 0, as every other node binds) never fall there, so a port picked
/// here and released stays free until its validator binds it, whatever starts in between.
fn data_ports(n: usize) -> Result<Vec<u16>, String> {
    let low: u16 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|r| r.split_whitespace().next()?.parse().ok())
        .unwrap_or(32_768);
    let span = low.saturating_sub(20_000).max(1);
    let start = 20_000 + u16::try_from(std::process::id() % u32::from(span)).unwrap_or(0);
    let ports: Vec<u16> = (0..span)
        .map(|k| 20_000 + (start - 20_000 + k) % span)
        .filter(|&p| {
            UdpSocket::bind(("127.0.0.1", p)).is_ok()
                && std::net::TcpListener::bind(("127.0.0.1", p)).is_ok()
        })
        .take(n)
        .collect();
    if ports.len() < n {
        return Err("no free UDP ports below the ephemeral range for the validators".into());
    }
    Ok(ports)
}

/// A validator's config. With `data = Some((fetch, port))` (`--data`): its data RX queue on
/// `port`, the vyrn-data node at `fetch` as box 0 (it is destination `i + 1` there; the tap is
/// 0), and `[replay]` with the sequencer's engine and sessions, so it prints `out=` per block.
fn validator_config(
    dir: &Path,
    i: usize,
    data: Option<(SocketAddrV4, u16)>,
    sessions: &[Sess],
    cons: Option<&Cons>,
) -> Result<PathBuf, String> {
    let key = hex(&vyrn_crypto::ed25519::public_key(&SEQ_SEED));
    let data_port = data.map_or(0, |(_, p)| p);
    // The vote key resolves only with [consensus]; without it the handle is read and unused.
    let vote = if cons.is_some() {
        "env:VYRN_E2E_VOTE_SEED".to_owned()
    } else {
        format!("dev:validator-{i}")
    };
    let mut s = format!(
        r#"schema = 1
protocol = 1
role = "validator"
mode = "BASE"
book = {BOOK}
epoch = 0
lanes = {LANES}

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
order_port = 0
data_port = {data_port}

[membership]
seq_keys = ["{key}"]

[keys]
vote = "{vote}"
"#
    );
    if let Some((fetch, _)) = data {
        s.push_str(&format!(
            "\n[data]\nboxes = [\"{fetch}\"]\nme = {}\n\n[replay]\ntick_min = {TICK_MIN}\ntick_max = {TICK_MAX}\nwin_center = {WIN_CENTER}\nslot_cap = {SLOT_CAP}\n",
            i + 1
        ));
        for x in sessions {
            s.push_str(&format!(
                "\n[[replay.session]]\nlane = {}\nslot = {}\naccount = {}\nk_seq = \"{}\"\nquote = {QUOTE}\nbase = {BASE}\n",
                x.lane,
                vyrn_wire::session_slot(x.id),
                x.acct,
                hex(&x.k_seq)
            ));
        }
    }
    if let Some(c) = cons {
        s.push_str(&format!(
            "\n[consensus]\nroster = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\nhome = \"LDN\"\nobservers = [\"{}\"]\ndelta_ms = 500\n",
            c.roster.display(),
            c.roster_hash,
            hex(&[0; 32]),
            c.ctrl
        ));
    }
    let p = dir.join(format!("validator-{i}.toml"));
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

/// The vyrn-data DEV config: destination 0 the tap's data socket, then the validators', and
/// every session's `K_seq`.
fn data_config(dir: &Path, dests: &[String], sessions: &[Sess]) -> Result<PathBuf, String> {
    let dests = dests
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = format!(
        r#"schema = 1
protocol = 1
role = "data"
mode = "BASE"
home = "LDN"
dev = true
src = 0
books = [{BOOK}]
dests = [{dests}]

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
ingest_port = 0
fetch_port = 0

[ring]
slots = 65536

[metrics]
listen = "127.0.0.1:0"
"#
    );
    for x in sessions {
        s.push_str(&format!(
            "\n[[session]]\nid = {}\nkey = \"hex:{}\"\n",
            x.id.0,
            hex(&x.k_seq)
        ));
    }
    let p = dir.join("data.toml");
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

fn run(cli: &Cli) -> Result<bool, String> {
    // R5's HASHLAG exception needs validators that actually report; zero would pass vacuously.
    let n_val = cli.validators.unwrap_or(if cli.finality { 4 } else { 3 });
    if n_val == 0 {
        return Err("--validators must be at least 1".into());
    }
    let wait = Duration::from_secs(cli.wait_s);
    let bin_dir = match &cli.bin_dir {
        Some(d) => d.clone(),
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("binary directory")?
            .to_path_buf(),
    };
    let (sessions, pkts) = workload(cli)?;
    println!(
        "WORKLOAD packets={} sessions={} seed={} rate={}",
        pkts.len(),
        sessions.len(),
        cli.seed,
        cli.rate
    );
    let dir = std::env::temp_dir().join(format!("vyrn-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let (tx, rx) = channel();
    let mut nodes = Nodes(Vec::new());
    let timeout = Some(Duration::from_millis(50));
    let stop_tap = Arc::new(AtomicBool::new(false));
    // With --data, each validator's data port (07 §5.4), picked before vyrn-data starts and
    // outside the ephemeral range, so no node's port-0 bind can take it meanwhile.
    // With --finality also each validator's TCP repl port and the box's CTRL port, from the
    // same range in one pick, so no two picks overlap.
    let want = if cli.data { n_val } else { 0 } + if cli.finality { n_val + 1 } else { 0 };
    let mut picked = data_ports(want)?;
    let val_data: Vec<u16> = if cli.data {
        picked.drain(..n_val).collect()
    } else {
        Vec::new()
    };
    let cons = if cli.finality {
        Some(Cons::new(&dir, &picked)?)
    } else {
        None
    };
    // --data: a vyrn-data node takes copy 2 from the client and fans DATA frames out to the
    // tap's data socket and every validator's data port (07 §5.1, §5.2). It starts first, so
    // the validators' configs can name its fetch address; their data ports are picked here.
    let data_node = if cli.data {
        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        sock.set_read_timeout(timeout).map_err(|e| e.to_string())?;
        let mut dests = vec![sock.local_addr().map_err(|e| e.to_string())?.to_string()];
        dests.extend(val_data.iter().map(|p| format!("127.0.0.1:{p}")));
        let cfg = data_config(&dir, &dests, &sessions)?;
        let mut c = command(&bin_dir.join("vyrn-data"), cli.seq_cpus.as_deref());
        c.arg("--config").arg(cfg).arg("--stop-on-stdin-eof");
        let i = nodes.spawn("vyrn-data", &mut c, &tx)?;
        nodes.wait(&rx, Instant::now() + wait, "vyrn-data READY", |ns| {
            ns.get(i)
                .is_some_and(|n| line(n, "READY vyrn-data ").is_some())
        })?;
        let ingest: SocketAddrV4 = nodes
            .0
            .get(i)
            .and_then(|n| line(n, "READY vyrn-data "))
            .and_then(|l| field(l, "ingest"))
            .ok_or("vyrn-data READY has no ingest=")?
            .parse()
            .map_err(|e| format!("vyrn-data ingest address: {e}"))?;
        let fetch: SocketAddrV4 = nodes
            .0
            .get(i)
            .and_then(|n| line(n, "READY vyrn-data "))
            .and_then(|l| field(l, "fetch"))
            .ok_or("vyrn-data READY has no fetch=")?
            .parse()
            .map_err(|e| format!("vyrn-data fetch address: {e}"))?;
        // Read from now on: the node heartbeats every destination while the validators start,
        // and an unread socket would overflow and drop the first DATA frames.
        Some((i, ingest, fetch, tap(sock, Arc::clone(&stop_tap))))
    } else {
        None
    };

    let vals: Vec<usize> = (0..n_val)
        .map(|i| {
            let data = data_node
                .as_ref()
                .zip(val_data.get(i))
                .map(|((_, _, fetch, _), port)| (*fetch, *port));
            let cfg = validator_config(&dir, i, data, &sessions, cons.as_ref())?;
            let mut c = command(
                &bin_dir.join("vyrn-validator"),
                cli.validator_cpus.as_deref(),
            );
            c.arg("--config")
                .arg(cfg)
                .arg("--stop-on-stdin-eof")
                .env("VYRN_E2E_VOTE_SEED", hex(&vote_seed(i)));
            nodes.spawn(&format!("validator-{i}"), &mut c, &tx)
        })
        .collect::<Result<_, String>>()?;
    let deadline = Instant::now() + wait;
    nodes.wait(&rx, deadline, "validators READY", |ns| {
        vals.iter().all(|&i| {
            ns.get(i)
                .is_some_and(|n| line(n, "READY vyrn-validator order=").is_some())
        })
    })?;
    let mut order: Vec<String> = vals
        .iter()
        .filter_map(|&i| {
            nodes
                .0
                .get(i)
                .and_then(|n| line(n, "READY vyrn-validator order="))
                .map(str::to_owned)
        })
        .collect();

    let tap_sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    tap_sock
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    order.push(
        tap_sock
            .local_addr()
            .map_err(|e| e.to_string())?
            .to_string(),
    );
    let cl_sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    cl_sock
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    let cl_recv = cl_sock.try_clone().map_err(|e| e.to_string())?;

    let cfg = seq_config(&dir, &order, &sessions, cons.as_ref())?;
    let mut c = command(&bin_dir.join("vyrn-seq"), cli.seq_cpus.as_deref());
    c.arg("--config")
        .arg(cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_E2E_SEQ_SEED", hex(&SEQ_SEED));
    let seq = nodes.spawn("vyrn-seq", &mut c, &tx)?;
    drop(tx);
    let ready = format!("READY vyrn-seq lanes={LANES} rx=");
    nodes.wait(&rx, Instant::now() + wait, "vyrn-seq READY", |ns| {
        ns.get(seq).is_some_and(|n| line(n, &ready).is_some())
    })?;
    let lane_addrs: Vec<SocketAddrV4> = nodes
        .0
        .get(seq)
        .and_then(|n| line(n, &ready))
        .ok_or("READY")?
        .split(',')
        .map(|a| a.parse().map_err(|e| format!("lane address {a}: {e}")))
        .collect::<Result<_, String>>()?;

    let tap_h = tap(tap_sock, Arc::clone(&stop_tap));
    let stop_cl = Arc::new(AtomicBool::new(false));
    let cl_h = client(cl_recv, Arc::clone(&stop_cl));
    let (data_idx, data_ingest, data_h) = match data_node {
        Some((i, ingest, _, h)) => (Some(i), Some(ingest), Some(h)),
        None => (None, None, None),
    };

    // Send, paced by send_ns.
    let t0 = Instant::now();
    for p in &pkts {
        let at = t0 + Duration::from_nanos(p.send_ns);
        while let Some(d) = at.checked_duration_since(Instant::now()) {
            std::thread::park_timeout(d);
        }
        let dst = lane_addrs.get(usize::from(p.lane)).ok_or("lane address")?;
        cl_sock.send_to(&p.bytes, dst).map_err(|e| e.to_string())?;
        // Copy 2 (07 §5.1): the client sends the same bytes to the data node.
        if let Some(d) = data_ingest {
            cl_sock.send_to(&p.bytes, d).map_err(|e| e.to_string())?;
        }
    }
    // Let the box take the last packets before it stops; its stop closes the last block.
    let settle = Instant::now() + Duration::from_millis(300);
    while let Some(d) = settle.checked_duration_since(Instant::now()) {
        std::thread::park_timeout(d);
    }
    // --finality: with the box still up (its listener prints FINAL), wait until the box and
    // every validator that did not stop finalize through the box's last block so far.
    // The target is the box's last BLOCK so far, read inside the wait, so lines still queued
    // from the run count.
    let last = |ns: &[Node]| ns.get(seq).and_then(|n| blocks(n).last().map(|b| b.0.0));
    let fin_wait = if cli.finality {
        nodes.wait(
            &rx,
            Instant::now() + wait,
            "FINAL through the last block",
            |ns| {
                let t = last(ns);
                t.is_some()
                    && ns.get(seq).is_some_and(|n| finals(n).last().copied() >= t)
                    && vals.iter().all(|&i| {
                        ns.get(i)
                            .is_some_and(|n| stopped(n).is_some() || finals(n).last().copied() >= t)
                    })
            },
        )
    } else {
        Ok(())
    };
    let fin_target = last(&nodes.0);
    let seq_ok = nodes.stop(seq, &rx, Instant::now() + wait)?;
    // The data node flushes its open frames on stop.
    let data_ok = data_idx.map(|i| nodes.stop(i, &rx, Instant::now() + wait).unwrap_or(false));
    let seq_node = nodes.0.get(seq).ok_or("seq")?;
    let seq_blocks: Vec<(u64, u64, u64)> = blocks(seq_node).into_iter().map(|b| b.0).collect();
    let stats = line(seq_node, "STATS ").unwrap_or("").to_owned();
    let top = seq_blocks.last().map(|b| b.0);

    // Every validator reaches the box's last block (or its deadline passes, reported below).
    let deadline = Instant::now() + wait;
    let reached = nodes.wait(&rx, deadline, "validators at the last block", |ns| {
        vals.iter().all(|&i| {
            ns.get(i)
                .is_some_and(|n| stopped(n).is_some() || blocks(n).last().map(|b| b.0.0) >= top)
        })
    });
    let mut val_ok = Vec::new();
    for &i in &vals {
        val_ok.push(nodes.stop(i, &rx, Instant::now() + wait).unwrap_or(false));
    }
    stop_tap.store(true, Ordering::Release);
    stop_cl.store(true, Ordering::Release);
    let frames = tap_h.join().map_err(|_| "tap thread")?;
    let data_frames = match data_h {
        Some(h) => Some(h.join().map_err(|_| "data tap thread")?),
        None => None,
    };
    // The tap's join: DATA frames through DataFeed with --data, else copy 2 in process (R3).
    let mut join = DataJoin::default();
    let mut feed_errs = Vec::new();
    let mut fed_stored = 0u64;
    match &data_frames {
        Some(fs) => {
            let mut feed = DataFeed::new(BookId(BOOK), 1, 0);
            for f in fs {
                match feed.on_frame(&mut join, f, 0) {
                    Ok(fed) => {
                        fed_stored += u64::from(fed.stored);
                        if fed.dropped > 0 {
                            feed_errs.push(format!("{} packets dropped", fed.dropped));
                        }
                        if let Some(g) = fed.gap {
                            feed_errs.push(format!("gap {}..={}", g.from, g.to));
                        }
                    }
                    Err(e) => feed_errs.push(e.to_string()),
                }
            }
        }
        None => {
            for p in &pkts {
                join.put(p.session, p.pkt_seq, p.bytes.clone());
            }
        }
    }
    let got = cl_h.join().map_err(|_| "client thread")?;

    let mut rep = Report(true);
    let field_n = |k: &str| field(&stats, k).and_then(|v| v.parse::<u64>().ok());
    rep.check("seq", {
        let records = field_n("records");
        let sv = field_n("seal_violations");
        if !seq_ok {
            Err(format!("exit status not 0: {stats}"))
        } else if records < Some(pkts.len() as u64) {
            // `records` also counts Advance records, so it is at least the packets sent.
            Err(format!(
                "records {records:?} < {} packets sent: {stats}",
                pkts.len()
            ))
        } else if sv != Some(0) {
            Err(stats.clone())
        } else if seq_blocks.len() < 2 {
            Err(format!("{} blocks", seq_blocks.len()))
        } else if seq_blocks.iter().enumerate().any(|(i, b)| b.0 != i as u64) {
            Err("block heights not contiguous from 0".into())
        } else {
            Ok(stats.clone())
        }
    });

    rep.check("validators", {
        let mut errs = Vec::new();
        if let Err(e) = &reached {
            errs.push(e.clone());
        }
        let mut full = 0usize;
        let mut warns = Vec::new();
        for (&i, ok) in vals.iter().zip(&val_ok) {
            let Some(n) = nodes.0.get(i) else { continue };
            let bs = blocks(n);
            let ids: Vec<_> = bs.iter().map(|b| b.0).collect();
            let fault = stopped(n);
            // R5: on an unpinned DEV machine REP_E_HASHLAG is a scheduling alarm. The blocks
            // before it must still be the box's, in order.
            let lag = fault.is_some_and(|f| f.starts_with("FAULT REP_E_HASHLAG "));
            match fault {
                Some(f) if lag && !cli.strict_hashlag => warns.push(format!("{}: {f}", n.name)),
                Some(f) => errs.push(format!("{}: {f}", n.name)),
                None => {}
            }
            let want = if lag && !cli.strict_hashlag {
                seq_blocks.get(..ids.len()).unwrap_or(&seq_blocks)
            } else {
                &seq_blocks[..]
            };
            if ids == seq_blocks {
                full += 1;
            } else if ids != want {
                errs.push(format!(
                    "{}: {} blocks, the box {}; first differs at {:?}",
                    n.name,
                    ids.len(),
                    seq_blocks.len(),
                    ids.iter().zip(&seq_blocks).position(|(a, b)| a != b)
                ));
            }
            if let Some(b) = bs.iter().find(|b| field(b.1, "verdict") != Some("Valid")) {
                errs.push(format!("{}: {}", n.name, b.1));
            }
            if !ok {
                errs.push(format!("{}: did not stop cleanly", n.name));
            }
        }
        // Without --strict-hashlag every stop counted here is a REP_E_HASHLAG WARN (any other
        // stop or stall is already in errs), and the tap still covers every height (R5).
        if full == 0 && cli.strict_hashlag {
            errs.push("no validator reached the last block".into());
        } else if full == 0 && warns.len() == vals.len() {
            println!(
                "WARN every validator stopped at REP_E_HASHLAG; the replay tap covers heights 0..={} (R5)",
                top.unwrap_or(0)
            );
        }
        for w in &warns {
            println!("WARN {w} (R5: a 1 ms bound on an unpinned DEV machine; --strict-hashlag fails it)");
        }
        if errs.is_empty() {
            Ok(format!(
                "{full} of {} validators through heights 0..={}, {} stopped at REP_E_HASHLAG, all Valid",
                vals.len(),
                top.unwrap_or(0),
                warns.len()
            ))
        } else {
            Err(errs.join("; "))
        }
    });

    // The tap: order core, data join, replay.
    let mut out_hashes: Vec<Hash> = Vec::new();
    rep.check(
        "replay",
        (|| {
            let mut core: OrderCore<LANES, View> = OrderCore::new(
                Layout::new(u8::try_from(LANES).map_err(|e| e.to_string())?, 1, 0)
                    .map_err(|e| e.to_string())?,
                View(vyrn_crypto::ed25519::public_key(&SEQ_SEED)),
            )
            .map_err(|e| e.to_string())?;
            let mut ready = Vec::new();
            for f in &frames {
                core.on_frame(f, 0)
                    .map_err(|e| format!("tap order core: {e:?}"))?;
                while let Some(b) = core.take_ready() {
                    ready.push(b);
                }
            }
            let ids: Vec<_> = ready
                .iter()
                .map(|b| {
                    (
                        b.header.height.0,
                        b.header.first_step.0,
                        b.header.last_step.0,
                    )
                })
                .collect();
            if ids != seq_blocks {
                return Err(format!(
                    "tap readied {} blocks, the box closed {}",
                    ids.len(),
                    seq_blocks.len()
                ));
            }
            // Every packet sent is sequenced exactly once: Advance records do not count, so a
            // lost client packet cannot hide behind them.
            let mut seen: Vec<(u32, u32)> = ready
                .iter()
                .flat_map(|b| &b.lanes)
                .filter_map(|r| match r {
                    vyrn_log::LaneRec::Pkt(p) if p.flags & PacketFlags::ADVANCE == 0 => {
                        Some((p.session.0, p.pkt_seq))
                    }
                    _ => None,
                })
                .collect();
            seen.sort_unstable();
            let mut sent: Vec<(u32, u32)> = pkts.iter().map(|p| (p.session.0, p.pkt_seq)).collect();
            sent.sort_unstable();
            if seen != sent {
                return Err(format!(
                    "blocks hold {} packet records, {} packets were sent",
                    seen.len(),
                    sent.len()
                ));
            }
            let (hashes, mut replayed) = replay_all(&sessions, std::mem::take(&mut join), &ready)?;
            out_hashes = hashes;
            let mut live: Vec<Resp> = Vec::new();
            for g in &got {
                let r = Response::parse(g).map_err(|e| format!("response: {e:?}"))?;
                let h = r.header();
                let s = sessions
                    .iter()
                    .find(|s| s.id == h.session())
                    .ok_or("response to an unknown session")?;
                if !r.verify(&s.k_out) {
                    return Err(format!("response tag of {:?}", s.id));
                }
                live.push((
                    h.session.get(),
                    h.resp_seq.get(),
                    h.echo_pkt.get(),
                    r.raw_records().to_vec(),
                ));
            }
            live.sort();
            replayed.sort();
            if live != replayed {
                let at = live.iter().zip(&replayed).position(|(a, b)| a != b);
                let show = |v: &[Resp]| {
                    at.and_then(|i| v.get(i)).map(|(s, q, e, rs)| {
                        let rs: Vec<String> = rs.iter().map(|r| hex(r)).collect();
                        format!("session {s:#x} resp_seq {q} echo {e} [{}]", rs.join(" "))
                    })
                };
                return Err(format!(
                    "responses differ: box sent {}, replay produced {}; first difference at {at:?}: box {:?}, replay {:?}",
                    live.len(),
                    replayed.len(),
                    show(&live),
                    show(&replayed)
                ));
            }
            let digest = |v: &[Resp]| {
                let mut b = Vec::new();
                for (s, q, e, rs) in v {
                    b.extend_from_slice(&s.to_le_bytes());
                    b.extend_from_slice(&q.to_le_bytes());
                    b.extend_from_slice(&e.to_le_bytes());
                    rs.iter().for_each(|r| b.extend_from_slice(r));
                }
                hex(&vyrn_crypto::hash::hash(&b).0)
            };
            Ok(format!(
                "{} blocks replayed, {} responses equal, responses digest {}, last output_hash {}",
                ready.len(),
                live.len(),
                digest(&live),
                out_hashes.last().map(|h| hex(&h.0)).unwrap_or_default()
            ))
        })(),
    );

    // Validators that replay print out=<hex>; compare per block.
    let replaying: Vec<&Node> = vals
        .iter()
        .filter_map(|&i| nodes.0.get(i))
        .filter(|n| cli.data || blocks(n).iter().any(|b| field(b.1, "out").is_some()))
        .collect();
    // With --data every validator replays, so this check always runs: a validator with no
    // out= at all, or a REPLAY_FAULT, fails it rather than skipping it.
    if replaying.is_empty() {
        Report::skip(
            "replica-out",
            "no validator prints out= (validators replay only with --data)",
        );
    } else {
        rep.check("replica-out", {
            let bad: Vec<String> = replaying
                .iter()
                .filter_map(|n| {
                    let theirs: Vec<Option<&str>> =
                        blocks(n).iter().map(|b| field(b.1, "out")).collect();
                    let ours: Vec<String> = out_hashes.iter().map(|h| hex(&h.0)).collect();
                    // R5: a validator stopped at REP_E_HASHLAG is compared on the blocks it
                    // printed; any other validator must print every block.
                    let lag = n
                        .lines
                        .iter()
                        .any(|l| l.starts_with("FAULT REP_E_HASHLAG "));
                    let first_bad = theirs
                        .iter()
                        .zip(&ours)
                        .position(|(a, b)| *a != Some(b.as_str()));
                    let short = theirs.len() < ours.len() && !lag;
                    if let Some(f) = n.lines.iter().find(|l| l.starts_with("REPLAY_FAULT ")) {
                        return Some(format!("{}: {f}", n.name));
                    }
                    match first_bad {
                        Some(k) => Some(format!(
                            "{} at block {k} ({} vs tap {})",
                            n.name,
                            theirs.get(k).copied().flatten().unwrap_or("-"),
                            ours.get(k).map_or("-", String::as_str)
                        )),
                        None if short || theirs.len() > ours.len() => Some(format!(
                            "{} printed {} of {} blocks",
                            n.name,
                            theirs.len(),
                            ours.len()
                        )),
                        None => None,
                    }
                })
                .collect();
            if bad.is_empty() && replaying.len() == vals.len() {
                let printed: Vec<String> = replaying
                    .iter()
                    .map(|n| format!("{}={}", n.name, blocks(n).len()))
                    .collect();
                Ok(format!(
                    "{} validators match the tap on every block they printed of {} (R5): {}",
                    vals.len(),
                    out_hashes.len(),
                    printed.join(" ")
                ))
            } else {
                Err(format!(
                    "mismatch or missing out=: {bad:?}, {} of {} replaying",
                    replaying.len(),
                    vals.len()
                ))
            }
        });
    }

    if cli.finality {
        rep.check("finality", {
            let n = vals.len();
            let q = n - (n - 1) / 3;
            let target = fin_target.unwrap_or(0);
            let seq_final = nodes.0.get(seq).and_then(|x| finals(x).last().copied());
            let mut errs = Vec::new();
            let mut lagged = 0usize;
            let mut lag_at: Vec<u64> = Vec::new();
            for &i in &vals {
                let Some(v) = nodes.0.get(i) else { continue };
                match stopped(v) {
                    Some(f) if f.starts_with("FAULT REP_E_HASHLAG ") && !cli.strict_hashlag => {
                        lagged += 1;
                        lag_at.extend(field(f, "height").and_then(|h| h.parse::<u64>().ok()));
                    }
                    // Any other stop already fails `validators`.
                    Some(_) => {}
                    None if finals(v).last().copied() < Some(target) => errs.push(format!(
                        "{} final {:?}",
                        v.name,
                        finals(v).last()
                    )),
                    None => {}
                }
            }
            // R6: more than n − Q validators stopped at REP_E_HASHLAG leaves no quorum; the
            // box cannot finalize the rest, which is DEV timing, not a fault.
            let no_quorum = n - lagged < q;
            // R6: quorum held below the (n − Q + 1)-th smallest stop height; when that spans at
            // least two heights, the box must still have finalized from votes, so a broken vote
            // path cannot pass.
            lag_at.sort_unstable();
            let quorum_until = lag_at.get(n - q).copied().unwrap_or(target);
            if seq_final < Some(target) && !no_quorum {
                errs.push(format!("vyrn-seq final {seq_final:?}"));
            }
            if no_quorum && quorum_until >= 2 && seq_final.is_none() {
                errs.push(format!(
                    "vyrn-seq finalized nothing, though Q validators ran through height {quorum_until}"
                ));
            }
            if let Err(e) = &fin_wait
                && !no_quorum
            {
                errs.push(e.clone());
            }
            if no_quorum && errs.is_empty() {
                println!(
                    "WARN {lagged} of {n} validators stopped at REP_E_HASHLAG, below Q = {q}; vyrn-seq finalized through {seq_final:?} of {target} (R6)"
                );
            }
            if errs.is_empty() {
                Ok(format!(
                    "vyrn-seq and {} running validators finalized through {target} (Q = {q} of {n}); seq final {seq_final:?}",
                    n - lagged
                ))
            } else {
                Err(format!("not finalized through {target}: {}", errs.join(", ")))
            }
        });
    } else {
        Report::skip("finality", "off (enable with --finality)");
    }
    match (data_idx, data_ok) {
        (Some(i), Some(ok)) => rep.check("data", {
            let n = nodes.0.get(i).ok_or("data node")?;
            let st = line(n, "STATS ").unwrap_or("").to_owned();
            let stored = field(&st, "stored").and_then(|v| v.parse::<u64>().ok());
            let events: Vec<&String> = n.lines.iter().filter(|l| l.starts_with("EVENT")).collect();
            let mut errs = Vec::new();
            if !ok {
                errs.push(format!("vyrn-data did not stop cleanly: {st}"));
            }
            if stored != Some(pkts.len() as u64) {
                errs.push(format!("stored {stored:?} != {} packets sent", pkts.len()));
            }
            // #120: EVENT lines + events_unprinted + events_dropped = bad_mac + copy conflicts.
            // The client sends one byte-identical copy under the right key, so all are 0.
            for k in ["bad_mac", "events_dropped", "events_unprinted"] {
                if field(&st, k) != Some("0") {
                    errs.push(format!("{k} is {:?}, not 0", field(&st, k)));
                }
            }
            if let Some(e) = events.first() {
                errs.push(format!("{} EVENT lines, first {e}", events.len()));
            }
            if !feed_errs.is_empty() {
                errs.push(format!("feed: {}", feed_errs.join(", ")));
            }
            if errs.is_empty() {
                Ok(format!(
                    "vyrn-data stored {} packets, {} data frames (DATA and DATA_HB) fed {fed_stored} packets into the replay join; {st}",
                    pkts.len(),
                    data_frames.as_ref().map_or(0, Vec::len)
                ))
            } else {
                Err(errs.join("; "))
            }
        }),
        _ => Report::skip(
            "data",
            "off (enable with --data; without it the tap joins copy 2 in process and validators do not replay, R3)",
        ),
    }

    let _ = std::io::stdout().flush();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(rep.0)
}

/// The line that stopped or stalled a validator: a sequencer `FAULT`, `OUT_OF_ORDER` (a stall
/// with no repair), `VOTER_FAULT`, `DATA_FAULT` or `REPLAY_FAULT`.
fn stopped(n: &Node) -> Option<&str> {
    const STOP: [&str; 5] = [
        "FAULT ",
        "OUT_OF_ORDER ",
        "VOTER_FAULT ",
        "DATA_FAULT ",
        "REPLAY_FAULT ",
    ];
    n.lines
        .iter()
        .map(String::as_str)
        .find(|l| STOP.iter().any(|p| l.starts_with(p)))
}

fn vote_seed(i: usize) -> [u8; 32] {
    [u8::try_from(i + 1).unwrap_or(u8::MAX); 32]
}

/// The DEV committee of `--finality`: a BASE roster (08 §9.6) of one home, as in
/// `bin/vyrn-validator/tests/committee.rs` (R4): voters `vote_seed(i)` at pre-picked TCP repl
/// ports, this run's `seq_key` as the primary, a dummy standby; and the box's pre-picked CTRL
/// address, which every validator lists as its observer.
struct Cons {
    roster: PathBuf,
    roster_hash: String,
    ctrl: SocketAddrV4,
}

impl Cons {
    /// `ports`: `n` TCP repl ports, then the box's CTRL port (`data_ports`).
    fn new(dir: &Path, ports: &[u16]) -> Result<Self, String> {
        let (repl, ctrl) = ports.split_at(ports.len().saturating_sub(1));
        let n = repl.len();
        use vyrn_epoch::{Addr, Domain, Home, Roster, SeqEntry, Voter};
        let addr = |port: u16| {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..].copy_from_slice(&[127, 0, 0, 1]);
            Addr { ip, port }
        };
        let seq_key = vyrn_crypto::ed25519::public_key(&SEQ_SEED);
        let mut voters = Vec::with_capacity(n);
        for i in 0..n {
            let k = vyrn_crypto::ed25519::public_key(&vote_seed(i)).to_vec();
            voters.push(Voter {
                client: u8::try_from(i % 2).map_err(|e| e.to_string())?,
                facility: u8::try_from(i + 1).map_err(|e| e.to_string())?,
                node_key: k.clone(),
                vote_key: k,
                xchg_key: vec![0x55; 32],
                data_addr: addr(0),
                repl_addr: addr(*repl.get(i).ok_or("repl port")?),
            });
        }
        let seq = [seq_key, [0x77; 32]]
            .iter()
            .zip(1u8..)
            .map(|(k, f)| SeqEntry {
                facility: f,
                node_key: k.to_vec(),
                seq_key: k.to_vec(),
                xchg_key: vec![0x66; 32],
                client_addr: addr(0),
                repl_addr: addr(0),
            })
            .collect();
        let home = Home {
            voters,
            seq,
            recovery: 0,
            data: Vec::new(),
        };
        let r = Roster {
            sig_scheme: 0,
            epoch_from: Epoch(0),
            homes: [home.clone(), home.clone(), home],
            bridge: None,
        };
        let domain = Domain {
            genesis_hash: Hash([0; 32]),
            mode: vyrn_types::Mode::Base,
        };
        let roster = dir.join("roster.hex");
        std::fs::write(&roster, hex(&r.encode())).map_err(|e| e.to_string())?;
        Ok(Self {
            roster,
            roster_hash: hex(&r.hash(&domain).0),
            ctrl: SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                *ctrl.first().ok_or("ctrl port")?,
            ),
        })
    }
}

/// Heights of a validator's `FINAL height=<h>` lines, and of the box's (R4).
fn finals(n: &Node) -> Vec<u64> {
    n.lines
        .iter()
        .filter_map(|l| field(l.strip_prefix("FINAL ")?, "height")?.parse().ok())
        .collect()
}
