//! The `vyrn-dropcopy` binary: serves per-account drop-copy streams over TCP (10 §8.5).
//!
//! Config wiring only; the logic is `vyrn_md::dropcopy`. Until the observer's output ring
//! feeds a `DropCopy` in this process, the records come from a file of `store` lines
//! (`--records`, the format of `tests/dc_vectors.txt`). Every connection gets a fresh
//! challenge, logs in once with an Ed25519 signature and streams from its `from` seq.
//!
//! Config (TOML):
//!
//! ```toml
//! book = 7
//! listen = "0.0.0.0:31600"
//! [[account]]
//! id = 101
//! master = 900          # optional
//! key = "<32-byte Ed25519 public key, hex>"
//! ```
#![forbid(unsafe_code)]

use std::net::{SocketAddr, TcpListener};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use clap::Parser;
use serde::Deserialize;
use vyrn_md::dropcopy::server::{DcStore, Keys, Session, Wake, serve};
use vyrn_md::dropcopy::wire::DC_LOGIN_TIMEOUT_MS;
use vyrn_types::{AccountId, BookId};

#[derive(Parser)]
#[command(about = "Drop-copy server (spec 10 §8)")]
struct Args {
    /// Config file (TOML, module docs).
    #[arg(long)]
    config: std::path::PathBuf,
    /// Records to serve (`store` lines).
    #[arg(long)]
    records: std::path::PathBuf,
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
    account: Vec<AccountCfg>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountCfg {
    id: u32,
    master: Option<u32>,
    key: String,
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
    let recs = std::fs::read_to_string(&args.records).map_err(|e| format!("records: {e}"))?;
    let mut store = DcStore::load_text(&recs)?;
    store.end_epoch();
    let store = Arc::new(RwLock::new(store));
    // Nothing grows the file-fed store; the observer's ring writer will bump it per push.
    let wake = Arc::new(Wake::new());
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
