//! The sequencer's side of consensus (07 §6.8; 11 §1.3 "as a proposer; it never votes"): the
//! finality listener on `REP_UDP_CTRL` and the finality gate's check.
//!
//! **Proposer side** (reading, **semantics**). Under 07 §6.3 the Simplex leader is a voter, and
//! the sequencer is never a participant (01 §14.4). What the sequencer proposes is the header
//! run: the stream thread signs every header (`seq_sig`) and sends it in HEADER frames, and the
//! leader's `propose` takes the run it holds. So the sequencer runs no Simplex instance; its
//! consensus work is this listener.
//!
//! **Listener** (thread `finality`, 07 §6.8 core 51). Binds `[consensus] ctrl`, decodes each
//! datagram with `vyrn_consensus::ctrl`, counts `REP_FinalizeVote`s in a `Listener` (each
//! signature checked, `Q` distinct voters) and takes `REP_FinalityCert`s whole. Prints
//! `FINAL height=<h> view=<v> from=<votes|cert>` each time `final_height` moves.
//!
//! **Gate.** At every block close the stream thread's block count gives `closed_height`; the
//! listener runs `Gate::check(closed_height, final_height)`, prints `GATE halt ...` or
//! `GATE resume ... halted_ms=<n>`, and sets [`Counts::halt_req`]. The engine loop reads it once a
//! turn and puts [`gate_cmd`] on the BBO control ring (`HaltReq`, 07 §6.8): the next step is
//! `Control(Halt)` (`Phase::Halted`; every lane answers new ops `BOOK_HALTED`) or
//! `Control(Resume)` (`Phase::Continuous`). The stream thread frames that step with the
//! command's payload (`vyrn_engine::control_payload`), so replay queues the same command.
//!
//! **Resume after > `REP_GATE_AUCTION_MS`** (reading, **semantics**): 07 §6.8 reopens through a
//! reopening auction (08) after a halt longer than 1000 ms. The auction is not wired, so this
//! build resumes continuous trading at once and prints `reopen=continuous` on such a resume.
//!
//! **Committee** from the roster file `[consensus] roster` through
//! `vyrn_epoch::Membership::from_roster`, with the DEV `EpoConfig` of `vyrn-validator` (home and
//! epoch from the box config, `sig_scheme` 0, BASE). This box's `seq_key` must be one of the
//! roster's `[primary, standby]`. Genesis: height 0 is final at start (the validator's reading:
//! the tenure's first header is the Simplex genesis).

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vyrn_bbo::{ControlCmd, Phase};
use vyrn_consensus::ctrl::{self, Ctrl};
use vyrn_consensus::{FinalityCert, Gate, GateAction, Listener};
use vyrn_epoch::{Domain, EpoConfig, Membership};
use vyrn_types::{Epoch, Hash, Height, HomeCode, Mode, Nanos, PubKey, Tick};

use crate::config::{Consensus, hex};

/// What the listener counted, printed at exit as `FINALITY votes=<n> refused=<n> final=<h>`.
#[derive(Default)]
pub struct Counts {
    pub votes: AtomicU64,
    pub refused: AtomicU64,
    pub final_height: AtomicU64,
    /// The gate wants the book halted (07 §6.8 `HaltReq`); the engine loop applies changes.
    pub halt_req: AtomicBool,
    /// Nacks dropped because the stream core's queue was full.
    pub nacks_dropped: AtomicU64,
}

/// `REP_GATE_AUCTION_MS` (07 §6.8): a longer halt reopens through an auction.
const REP_GATE_AUCTION_MS: u128 = 1000;

/// The control command for the gate's state: halt, or resume continuous trading (07 §6.8).
/// `lo`/`hi` are unused by a phase change to `Halted` or `Continuous` (05 §8.8).
pub fn gate_cmd(halt: bool) -> ControlCmd {
    ControlCmd::Phase {
        phase: if halt {
            Phase::Halted
        } else {
            Phase::Continuous
        },
        lo: Tick(0),
        hi: Tick(0),
    }
}

/// A running listener: its CTRL address, counts and thread.
pub struct Finality {
    pub ctrl: SocketAddr,
    pub counts: Arc<Counts>,
    thread: JoinHandle<()>,
}

impl Finality {
    /// Binds the CTRL port and starts the thread. `closed` is the number of blocks the stream
    /// thread has closed (heights start at 0).
    #[allow(clippy::too_many_arguments)] // one channel per consumer of the listener
    pub fn start(
        c: &Consensus,
        home: HomeCode,
        epoch: Epoch,
        seq_key: PubKey,
        closed: Arc<dyn Fn() -> u64 + Send + Sync>,
        stop: Arc<AtomicBool>,
        nacks: std::sync::mpsc::SyncSender<crate::rtx::Req>,
        seals: Option<std::sync::mpsc::Sender<FinalityCert>>,
    ) -> Result<Self, String> {
        let (m, _) = membership(c, home, epoch)?;
        if !m.seq().iter().any(|b| b.seq_key == seq_key) {
            return Err("keys.seq is not the roster's primary or standby seq_key".into());
        }
        let committee = m.committee().clone();
        let sock = UdpSocket::bind(c.ctrl).map_err(|e| format!("consensus.ctrl: {e}"))?;
        sock.set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|e| e.to_string())?;
        let ctrl = sock.local_addr().map_err(|e| e.to_string())?;
        let counts = Arc::new(Counts::default());
        let thread = {
            let counts = Arc::clone(&counts);
            std::thread::Builder::new()
                .name("vyrn-seq/finality".into())
                .spawn(move || {
                    listen(
                        &sock,
                        Listener::new(committee, epoch, Height(0)),
                        &*closed,
                        &stop,
                        &counts,
                        &nacks,
                        seals.as_ref(),
                    );
                })
                .map_err(|e| e.to_string())?
        };
        Ok(Self {
            ctrl,
            counts,
            thread,
        })
    }

    /// Waits for the thread (after `stop`) and prints `FINALITY ...`.
    pub fn join(self) {
        let _ = self.thread.join();
        let g = |c: &AtomicU64| c.load(Ordering::Acquire);
        println!(
            "FINALITY votes={} refused={} final={}",
            g(&self.counts.votes),
            g(&self.counts.refused),
            g(&self.counts.final_height)
        );
    }
}

/// The roster's membership for this box's home and epoch, with the DEV `EpoConfig` (module
/// docs), and the roster itself.
pub fn membership(
    c: &Consensus,
    home: HomeCode,
    epoch: Epoch,
) -> Result<(Membership, vyrn_epoch::Roster), String> {
    let bytes = roster_bytes(&c.roster)?;
    let n = u8::try_from(Mode::Base.n()).unwrap_or(u8::MAX);
    let cfg = EpoConfig {
        epoch,
        home,
        t_start: Nanos(0),
        roster_hash: Hash(hex::<32>(&c.roster_hash)?),
        seq_order: c.seq_order.unwrap_or([n, n + 1]),
        lane_map_hash: [Hash([0; 32]); 3],
        n_lanes: [0; 3],
        version: 0,
        endpoint_hash: Hash([0; 32]),
        flags: 0,
        sig_scheme: 0,
    };
    let domain = Domain {
        genesis_hash: Hash(hex::<32>(&c.genesis_hash)?),
        mode: Mode::Base,
    };
    Membership::from_roster(&cfg, &bytes, &domain, None)
        .map_err(|e| format!("config consensus.roster: {e}"))
}

fn listen(
    sock: &UdpSocket,
    mut l: Listener,
    closed: &(dyn Fn() -> u64 + Send + Sync),
    stop: &AtomicBool,
    counts: &Counts,
    nacks: &std::sync::mpsc::SyncSender<crate::rtx::Req>,
    seals: Option<&std::sync::mpsc::Sender<FinalityCert>>,
) {
    let mut buf = [0u8; 9216];
    let mut gate = Gate::default();
    let mut since: Option<Instant> = None;
    while !stop.load(Ordering::Acquire) {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            // A replica's Nack (07 §4.10): to the stream core, which owns the frame ring.
            // It does not end the turn: the gate check below runs whatever arrived (Vercel
            // r4613653820).
            let dgram = buf.get(..n).unwrap_or(&[]);
            let nack = match (vyrn_log::nack::Nack::decode(dgram), from) {
                (Some(nk), SocketAddr::V4(f)) => Some((*f.ip(), nk)),
                _ => None,
            };
            if let Some(req) = nack {
                if nacks.try_send(req).is_err() {
                    counts.nacks_dropped.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                let before = l.final_height();
                let from = match ctrl::decode(buf.get(..n).unwrap_or(&[])) {
                    Ok(Ctrl::Vote(v)) => {
                        counts.votes.fetch_add(1, Ordering::Relaxed);
                        l.on_vote(&v).map(|c| c.map(|c| (c.view, "votes")))
                    }
                    Ok(Ctrl::Cert(c)) => l.on_cert(&c).map(|()| {
                        // A verified seal certificate, for a standby (`standby.rs`).
                        if let Some(tx) = seals.filter(|_| c.seal.is_some()) {
                            let _ = tx.send(c.clone());
                        }
                        Some((c.view, "cert"))
                    }),
                    Err(_) => Ok(None),
                };
                match from {
                    Ok(Some((view, from))) if l.final_height() > before => {
                        counts
                            .final_height
                            .store(l.final_height().0, Ordering::Release);
                        println!(
                            "FINAL height={} view={view} from={from}",
                            l.final_height().0
                        );
                    }
                    Ok(_) => {}
                    Err(_) => {
                        counts.refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        // Gate::check reports only transitions, so checking every turn is cheap.
        let c = closed();
        if c > 0 {
            let closed_h = Height(c.saturating_sub(1));
            match gate.check(closed_h, l.final_height()) {
                GateAction::Halt => {
                    counts.halt_req.store(true, Ordering::Release);
                    since = Some(Instant::now());
                    println!(
                        "GATE halt closed={} final={}",
                        closed_h.0,
                        l.final_height().0
                    );
                }
                GateAction::Resume => {
                    counts.halt_req.store(false, Ordering::Release);
                    let ms = since.take().map_or(0, |t| t.elapsed().as_millis());
                    let reopen = if ms > REP_GATE_AUCTION_MS {
                        " reopen=continuous"
                    } else {
                        ""
                    };
                    println!(
                        "GATE resume closed={} final={} halted_ms={ms}{reopen}",
                        closed_h.0,
                        l.final_height().0
                    );
                }
                GateAction::Hold => {}
            }
        }
    }
}

/// Roster bytes from a file: hex text if it is all hex digits (whitespace ignored), else raw.
pub fn roster_bytes(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if text.is_empty() || !text.len().is_multiple_of(2) || !text.iter().all(u8::is_ascii_hexdigit) {
        return Ok(raw);
    }
    text.as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let p = std::str::from_utf8(p.as_slice()).map_err(|e| e.to_string())?;
            u8::from_str_radix(p, 16).map_err(|e| e.to_string())
        })
        .collect()
}
