//! The `vyrn-dropcopy` binary: serves per-account drop-copy streams over TCP (10 §8.5).
//!
//! Config wiring only; the logic is `vyrn_md::dropcopy`. The records come from the observer's
//! output ring (`--ring`, 10 §8.6): the observer replica's `RustReplay` drives a `SinkStream`
//! whose tap is a `RingTap`, and this process applies every frame to its own `DropCopy`
//! (`RingReader`), writing into the store its sessions serve. `--records` serves a file of
//! `store` lines instead (the format of `tests/dc_vectors.txt`). Every connection gets a fresh
//! challenge, logs in once with an Ed25519 signature and streams from its `from` seq.
//!
//! Config (TOML):
//!
//! ```toml
//! book = 7
//! listen = "0.0.0.0:31600"
//! tick_size = 10        # --ring: quote units per lot per tick (10 §2.1)
//! [[account]]
//! id = 101
//! master = 900          # optional
//! key = "<32-byte Ed25519 public key, hex>"
//! sessions = [1048577]  # --ring: the account's sessions, and its fee rates (10 §5)
//! taker_ppm = 400
//! maker_ppm = -20
//! msg_fee_improve = 8
//! msg_fee_cross = 15
//! ```
//!
//! A ring the writer laps (`RingError::Lagged`), or any ring or drop-copy error, ends the
//! process: the drop copy is then rebuilt from the final log (03 §7).
#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use clap::Parser;
use serde::Deserialize;
use vyrn_md::dropcopy::ring::{RingFrame, RingReader, StoreOut};
use vyrn_md::dropcopy::server::{DcStore, Keys, Session, Wake, serve};
use vyrn_md::dropcopy::wire::DC_LOGIN_TIMEOUT_MS;
use vyrn_md::dropcopy::{DcAccount, DcConfig, DropCopy, MD_DC_REPLAY_EPOCHS};
use vyrn_types::{AccountId, BookId, Epoch, SessionId};

#[derive(Parser)]
#[command(about = "Drop-copy server (spec 10 §8)")]
struct Args {
    /// Config file (TOML, module docs).
    #[arg(long)]
    config: std::path::PathBuf,
    /// The observer's output ring (a file under /dev/shm).
    #[arg(long, conflicts_with = "records", required_unless_present = "records")]
    ring: Option<std::path::PathBuf>,
    /// Records to serve (`store` lines) instead of a ring.
    #[arg(long)]
    records: Option<std::path::PathBuf>,
    /// Overrides `listen` from the config.
    #[arg(long)]
    listen: Option<SocketAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    book: u16,
    listen: Option<SocketAddr>,
    #[serde(default)]
    tick_size: u64,
    #[serde(default)]
    account: Vec<AccountCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountCfg {
    id: u32,
    master: Option<u32>,
    key: String,
    #[serde(default)]
    sessions: Vec<u32>,
    #[serde(default)]
    taker_ppm: i32,
    #[serde(default)]
    maker_ppm: i32,
    #[serde(default)]
    msg_fee_improve: u32,
    #[serde(default)]
    msg_fee_cross: u32,
}

impl Config {
    fn dc(&self) -> DcConfig {
        DcConfig {
            book: BookId(self.book),
            tick_size: self.tick_size,
            accounts: self
                .account
                .iter()
                .map(|a| DcAccount {
                    account: AccountId(a.id),
                    master: a.master.map(AccountId),
                    sessions: a.sessions.iter().copied().map(SessionId).collect(),
                    taker_ppm: a.taker_ppm,
                    maker_ppm: a.maker_ppm,
                    msg_fee_improve: a.msg_fee_improve,
                    msg_fee_cross: a.msg_fee_cross,
                })
                .collect(),
        }
    }
}

/// Follows the ring: a new `DropCopy` per `Begin`, every frame applied to it. Returns only on
/// an error.
fn follow(path: &std::path::Path, cfg: &DcConfig, out: &StoreOut) -> String {
    let idle = Duration::from_micros(200);
    let mut rd = loop {
        match RingReader::open(path) {
            Ok(r) => break r,
            Err(vyrn_md::dropcopy::ring::RingError::Io(_)) => std::thread::park_timeout(idle),
            Err(e) => return e.to_string(),
        }
    };
    // The current epoch's drop copy and the ended ones still in the replay window, which a late
    // `Settled` reaches (10 §8.4 item 11).
    let mut dcs: std::collections::BTreeMap<Epoch, DropCopy<StoreOut>> = Default::default();
    let mut cur: Option<Epoch> = None;
    let mut err: Option<String> = None;
    loop {
        let r = rd.poll(|f| {
            if err.is_some() {
                return;
            }
            if let RingFrame::Begin(e) = f {
                if let Ok(mut s) = out.store.write() {
                    s.begin_epoch(e);
                }
                let d = DropCopy::new(
                    cfg,
                    StoreOut {
                        epoch: e,
                        ..out.clone()
                    },
                );
                // Every configured stream can subscribe from the epoch's start.
                if let Ok(mut s) = out.store.write() {
                    d.streams().for_each(|id| s.open(id));
                }
                dcs.insert(e, d);
                while dcs.len() > MD_DC_REPLAY_EPOCHS {
                    dcs.pop_first();
                }
                cur = Some(e);
            }
            let target = match &f {
                RingFrame::Settled(e, ..) => Some(*e),
                _ => cur,
            };
            let Some(d) = target.and_then(|e| dcs.get_mut(&e)) else {
                if matches!(f, RingFrame::Settled(..)) {
                    // Its epoch left the replay window; sessions rebuild from the statement.
                    tracing::warn!(?f, "settlement for an epoch outside the window");
                } else {
                    err = Some("ring frame before its epoch's Begin".into());
                }
                return;
            };
            if let Err(e) = f.apply(d) {
                err = Some(format!("drop copy: {e:?}"));
            }
            if matches!(f, RingFrame::End(_))
                && let Ok(mut s) = out.store.write()
            {
                s.end_epoch();
            }
            out.wake.bump();
        });
        if let Some(e) = err {
            return e;
        }
        match r {
            Ok(0) => std::thread::park_timeout(idle),
            Ok(_) => {}
            Err(e) => return e.to_string(),
        }
    }
}

fn key(hex: &str) -> Option<[u8; 32]> {
    let b: Option<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|x| u8::from_str_radix(x, 16).ok())
        })
        .collect();
    b?.try_into().ok()
}

/// A fresh per-connection challenge: BLAKE3 of a process secret, the peer and a counter.
fn challenge(secret: &[u8; 32], n: u64, peer: SocketAddr) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(&n.to_le_bytes());
    h.update(peer.to_string().as_bytes());
    *h.finalize().as_bytes()
}

fn run(args: &Args) -> Result<(), String> {
    let text = std::fs::read_to_string(&args.config).map_err(|e| format!("config: {e}"))?;
    let cfg: Config = toml::from_str(&text).map_err(|e| format!("config: {e}"))?;
    let mut keys = Keys::new();
    for a in &cfg.account {
        let k = key(&a.key).ok_or_else(|| format!("account {}: bad key", a.id))?;
        keys.add(AccountId(a.id), k, a.master.map(AccountId));
    }
    let store = match &args.records {
        Some(p) => {
            let recs = std::fs::read_to_string(p).map_err(|e| format!("records: {e}"))?;
            let mut store = DcStore::load_text(&recs)?;
            store.end_epoch();
            store
        }
        None => DcStore::new(),
    };
    let store = Arc::new(RwLock::new(store));
    let wake = Arc::new(Wake::new());
    if let Some(ring) = args.ring.clone() {
        // Fees and statement totals scale with it (10 §2.1: `tick_size` ≥ 1).
        if cfg.tick_size == 0 {
            return Err("config: --ring needs tick_size ≥ 1".into());
        }
        let out = StoreOut {
            store: Arc::clone(&store),
            wake: Arc::clone(&wake),
            epoch: Epoch(0),
        };
        let dc = cfg.dc();
        std::thread::spawn(move || {
            let e = follow(&ring, &dc, &out);
            tracing::error!(%e, "ring follower stopped");
            eprintln!("vyrn-dropcopy: {e}");
            std::process::exit(1);
        });
    }
    let keys = Arc::new(keys);
    let book = BookId(cfg.book);
    let addr = args
        .listen
        .or(cfg.listen)
        .ok_or("no listen address (config `listen` or --listen)")?;
    let l = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    tracing::info!(%addr, "vyrn-dropcopy listening");
    let secret =
        *blake3::hash(format!("{:?}{addr}", std::time::SystemTime::now()).as_bytes()).as_bytes();
    for (n, conn) in (0u64..).zip(l.incoming()) {
        let Ok(mut c) = conn else { continue };
        let Ok(peer) = c.peer_addr() else { continue };
        let (keys, store, wake) = (Arc::clone(&keys), Arc::clone(&store), Arc::clone(&wake));
        let sess = Session::new(book, challenge(&secret, n, peer));
        std::thread::spawn(move || {
            let _ = c.set_nodelay(true);
            // An unauthenticated connection has DC_LOGIN_TIMEOUT_MS in all to log in.
            let r = serve(
                &mut c,
                sess,
                &keys,
                &store,
                &wake,
                Duration::from_millis(DC_LOGIN_TIMEOUT_MS),
                |c, t| {
                    c.set_read_timeout(Some(t))?;
                    c.set_write_timeout(Some(t))
                },
            );
            tracing::debug!(%peer, ?r, "connection closed");
        });
    }
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    match run(&Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vyrn-dropcopy: {e}");
            ExitCode::FAILURE
        }
    }
}
