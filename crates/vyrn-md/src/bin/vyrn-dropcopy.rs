//! The `vyrn-dropcopy` binary: serves per-account drop-copy streams over TCP with Noise
//! (10 §8.5).
//!
//! Config wiring only; the logic is `vyrn_md::dropcopy`. The records come from the observer's
//! output ring (`--ring`, 10 §8.6): the observer replica's `RustReplay` drives a `SinkStream`
//! whose tap is a `RingTap`, and this process applies every frame to its own `DropCopy`
//! (`RingReader`), writing into the store its sessions serve. `--records` serves a file of
//! `store` lines instead (the format of `tests/dc_vectors.txt`). Every connection first
//! completes a `Noise_NK_25519_ChaChaPoly_SHA512` handshake against the server's static key
//! (`vyrn_md::dropcopy::noise`, 10 §8.5 item 5), then gets a fresh challenge, logs in once with
//! an Ed25519 signature and streams from its `from` seq, all inside the Noise transport. The
//! handshake counts against the login deadline.
//!
//! Config (TOML):
//!
//! ```toml
//! book = 7
//! listen = "0.0.0.0:31600"
//! noise_key_file = "/etc/vyrn/dropcopy.noise"   # the server's X25519 secret, 64 hex digits
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
use vyrn_md::dropcopy::noise::NoiseStream;
use vyrn_md::dropcopy::ring::{Follower, RingError};
use vyrn_md::dropcopy::server::{DcStore, Keys, Session, Wake, serve};
use vyrn_md::dropcopy::wire::DC_LOGIN_TIMEOUT_MS;
use vyrn_md::dropcopy::{DcAccount, DcConfig};
use vyrn_types::{AccountId, BookId, SessionId};

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
    noise_key_file: std::path::PathBuf,
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

/// Follows the ring until it fails (`vyrn_md::dropcopy::ring::Follower`).
fn follow(
    path: &std::path::Path,
    cfg: DcConfig,
    store: Arc<RwLock<DcStore>>,
    wake: Arc<Wake>,
) -> String {
    let idle = Duration::from_micros(200);
    let mut f = loop {
        match Follower::open(path, cfg.clone(), Arc::clone(&store), Arc::clone(&wake)) {
            Ok(f) => break f,
            // The observer has not created it yet.
            Err(RingError::Io(_)) => std::thread::park_timeout(idle),
            Err(e) => return e.to_string(),
        }
    };
    loop {
        match f.poll() {
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
        let (dc, store, wake) = (cfg.dc(), Arc::clone(&store), Arc::clone(&wake));
        std::thread::spawn(move || {
            let e = follow(&ring, dc, store, wake);
            tracing::error!(%e, "ring follower stopped");
            eprintln!("vyrn-dropcopy: {e}");
            std::process::exit(1);
        });
    }
    let keys = Arc::new(keys);
    let book = BookId(cfg.book);
    let noise = std::fs::read_to_string(&cfg.noise_key_file)
        .map_err(|e| format!("noise_key_file: {e}"))
        .and_then(|t| key(t.trim()).ok_or_else(|| "noise_key_file: not 64 hex digits".into()))?;
    let noise_pub = vyrn_crypto::x25519::public_key(&noise);
    let noise_pub: String = noise_pub.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(%noise_pub, "noise static key");
    // Clients pin this key (10 §8.5 item 5).
    eprintln!("vyrn-dropcopy: noise static public key {noise_pub}");
    let mut urandom = std::fs::File::open("/dev/urandom").map_err(|e| format!("urandom: {e}"))?;
    let addr = args
        .listen
        .or(cfg.listen)
        .ok_or("no listen address (config `listen` or --listen)")?;
    let l = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    tracing::info!(%addr, "vyrn-dropcopy listening");
    let secret =
        *blake3::hash(format!("{:?}{addr}", std::time::SystemTime::now()).as_bytes()).as_bytes();
    for (n, conn) in (0u64..).zip(l.incoming()) {
        let Ok(c) = conn else { continue };
        let Ok(peer) = c.peer_addr() else { continue };
        // A fresh ephemeral key per connection.
        let mut e = [0u8; 32];
        std::io::Read::read_exact(&mut urandom, &mut e).map_err(|e| format!("urandom: {e}"))?;
        let (keys, store, wake) = (Arc::clone(&keys), Arc::clone(&store), Arc::clone(&wake));
        let sess = Session::new(book, challenge(&secret, n, peer));
        std::thread::spawn(move || {
            let _ = c.set_nodelay(true);
            // An unauthenticated connection has DC_LOGIN_TIMEOUT_MS in all, handshake
            // included, to log in.
            let start = std::time::Instant::now();
            let login = Duration::from_millis(DC_LOGIN_TIMEOUT_MS);
            let r = c
                .set_read_timeout(Some(login))
                .and_then(|()| c.set_write_timeout(Some(login)))
                .and_then(|()| NoiseStream::accept(c, book, &noise, &e))
                .and_then(|mut c| {
                    let left = login.saturating_sub(start.elapsed());
                    if left.is_zero() {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    serve(&mut c, sess, &keys, &store, &wake, left, |c, t| {
                        c.get_mut().set_read_timeout(Some(t))?;
                        c.get_mut().set_write_timeout(Some(t))
                    })
                });
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
