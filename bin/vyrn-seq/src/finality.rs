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
//! listener runs `Gate::check(closed_height, final_height)` and prints `GATE halt ...` or
//! `GATE resume ...`. Putting `HaltReq` on the BBO control ring is not wired yet (follow-up): the
//! gate is observed, not enforced.
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
use std::time::Duration;

use vyrn_consensus::ctrl::{self, Ctrl};
use vyrn_consensus::{Gate, GateAction, Listener};
use vyrn_epoch::{Domain, EpoConfig, Membership};
use vyrn_types::{Epoch, Hash, Height, HomeCode, Mode, Nanos, PubKey};

use crate::config::{Consensus, hex};

/// What the listener counted, printed at exit as `FINALITY votes=<n> refused=<n> final=<h>`.
#[derive(Default)]
pub struct Counts {
    pub votes: AtomicU64,
    pub refused: AtomicU64,
    pub final_height: AtomicU64,
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
    pub fn start(
        c: &Consensus,
        home: HomeCode,
        epoch: Epoch,
        seq_key: PubKey,
        closed: Arc<dyn Fn() -> u64 + Send + Sync>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, String> {
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
        let (m, _) = Membership::from_roster(&cfg, &bytes, &domain, None)
            .map_err(|e| format!("config consensus.roster: {e}"))?;
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

fn listen(
    sock: &UdpSocket,
    mut l: Listener,
    closed: &(dyn Fn() -> u64 + Send + Sync),
    stop: &AtomicBool,
    counts: &Counts,
) {
    let mut buf = [0u8; 9216];
    let mut gate = Gate::default();
    while !stop.load(Ordering::Acquire) {
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            let before = l.final_height();
            let from = match ctrl::decode(buf.get(..n).unwrap_or(&[])) {
                Ok(Ctrl::Vote(v)) => {
                    counts.votes.fetch_add(1, Ordering::Relaxed);
                    l.on_vote(&v).map(|c| c.map(|c| (c.view, "votes")))
                }
                Ok(Ctrl::Cert(c)) => l.on_cert(&c).map(|()| Some((c.view, "cert"))),
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
        // Gate::check reports only transitions, so checking every turn is cheap.
        let c = closed();
        if c > 0 {
            let closed_h = Height(c.saturating_sub(1));
            match gate.check(closed_h, l.final_height()) {
                GateAction::Halt => println!(
                    "GATE halt closed={} final={}",
                    closed_h.0,
                    l.final_height().0
                ),
                GateAction::Resume => println!(
                    "GATE resume closed={} final={}",
                    closed_h.0,
                    l.final_height().0
                ),
                GateAction::Hold => {}
            }
        }
    }
}

/// Roster bytes from a file: hex text if it is all hex digits (whitespace ignored), else raw.
fn roster_bytes(path: &std::path::Path) -> Result<Vec<u8>, String> {
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
