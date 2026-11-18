//! The Simplex voter of `vyrn-validator` (07 §6.3–6.8): a `BlockSource` over what the order
//! thread has checked, the voter on `commonware-runtime::tokio`, its Simplex network on
//! `commonware-p2p` `authenticated::lookup` (07 §3.1), and its finalize votes and certificates
//! sent to the sequencer's and the standby's `REP_UDP_CTRL` (07 §6.8).
//!
//! **Committee from the roster** (08 §9.6). `[consensus]` names a roster file (its bytes, raw or
//! hex) and the `EpoConfig` fields that select from it; `vyrn_epoch::Membership::from_roster`
//! checks the bytes against `roster_hash` and gives the committee and `[primary, standby]`. The
//! Simplex peer set is `home(e)`'s voters' `node_key` and `repl_addr` (07 §3.1).
//!
//! **DEV `EpoConfig`** (reading, **config**). 08 gives `EpoConfig` no encoding yet (08 Requests to
//! 01 item 7), so the config carries the fields the voter reads (`roster_hash`, `home`,
//! `seq_order`; `sig_scheme` 0, BASE) and the rest are zero. The log's `EpoConfig` replaces them
//! once 01 encodes it.
//!
//! **Genesis** (reading, **semantics**). Epoch 0 of a DEV run has no `HandoffRecord`, and the
//! tenure's first header is height 0 with `prev = [0; 32]`, which no Simplex genesis below it can
//! chain to. The voter therefore waits for header 0 (checked by the order core) and starts Simplex
//! with it as genesis, as if it were the HandoffRecord's last block (07 §6.3). Height 0 is never
//! finalized by a certificate; the listener at the sequencer starts final at 0 too.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use commonware_consensus::simplex::Engine;
use commonware_runtime::{Runner as _, Supervisor as _};
use serde::Deserialize;
use vyrn_consensus::voter::{Timeouts, VoterConfig};
use vyrn_consensus::{BlockSource, Committee, Genesis, Verdict, ctrl, net};
use vyrn_epoch::{Addr, Domain, EpoConfig};
use vyrn_log::block::header_hash;
use vyrn_types::{BlockHeader, Epoch, Hash, Height, HomeCode, Mode, Nanos, PubKey};

/// `[consensus]`: the roster and the DEV `EpoConfig` fields (see the module docs).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    /// The roster bytes (08 §9.6), raw or as hex text.
    pub roster: PathBuf,
    /// `EpoConfig.roster_hash`, hex.
    pub roster_hash: String,
    /// `Domain.genesis_hash`, hex.
    pub genesis_hash: String,
    /// `EpoConfig.home`: TYO, LDN or NYC.
    pub home: String,
    /// `EpoConfig.seq_order`; default the home's first two `vyrn-seq` boxes, `[n, n + 1]`.
    #[serde(default)]
    pub seq_order: Option<[u8; 2]>,
    /// `REP_UDP_CTRL` of the sequencer and the standby: where finalize votes and certificates go.
    #[serde(default)]
    pub observers: Vec<SocketAddr>,
    /// `REP_DELTA_MS` (07 §6.3); DEV runs on a loaded host may raise it. Default 1.
    #[serde(default = "d_delta")]
    pub delta_ms: u64,
    /// Where the voter's Simplex journal lives. Default: a temporary directory.
    #[serde(default)]
    pub storage: Option<PathBuf>,
}

fn d_delta() -> u64 {
    1
}

/// Blocks the order thread has checked (07 §6.4 items 1–3 and 5), for the voter.
#[derive(Default)]
struct Held {
    headers: BTreeMap<u64, BlockHeader>,
    valid: BTreeSet<u64>,
    /// The lowest height a fault, fence or data contradiction covers.
    invalid_from: Option<u64>,
}

/// The voter's [`BlockSource`]. The order thread writes it; Simplex reads it.
#[derive(Clone, Default)]
pub struct Source(Arc<Mutex<Held>>);

impl Source {
    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A header the order core accepted (its `seq_sig`, chain and steps).
    pub fn header(&self, h: BlockHeader) {
        self.held().headers.insert(h.height.0, h);
    }

    /// The block's body passed: its ORDER bytes and, when the data tier is wired, its payloads.
    pub fn valid(&self, height: Height) {
        self.held().valid.insert(height.0);
    }

    /// Nothing at or above `height` may be voted for (a fault, or a data root that differs).
    pub fn invalid_from(&self, height: Height) {
        let mut h = self.held();
        h.invalid_from = Some(h.invalid_from.map_or(height.0, |f| f.min(height.0)));
    }
}

impl BlockSource for Source {
    fn header(&self, height: Height) -> Option<BlockHeader> {
        self.held().headers.get(&height.0).copied()
    }

    fn check_body(&self, _: Epoch, first: Height, last: Height) -> Verdict {
        let h = self.held();
        if first > last || h.invalid_from.is_some_and(|f| last.0 >= f) {
            return Verdict::Invalid;
        }
        if (first.0..=last.0).all(|x| h.valid.contains(&x)) {
            Verdict::Valid
        } else {
            Verdict::Pending
        }
    }

    /// BASE: 32 zero bytes (CHAIN is refused at config load).
    fn excl_root(&self, _: Epoch, _: Height, _: Height) -> Hash {
        Hash([0; 32])
    }
}

/// What the voter thread needs, resolved from the config before any thread starts.
pub struct Plan {
    pub committee: Committee,
    pub peers: Vec<net::Peer>,
    pub me: usize,
    pub vote_seed: [u8; 32],
    pub node_seed: [u8; 32],
    pub seq_key: PubKey,
    pub epoch: Epoch,
    pub observers: Vec<SocketAddr>,
    pub timeouts: Timeouts,
    pub storage: PathBuf,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err("a key must be 64 hex digits".into());
    }
    let mut out = [0u8; 32];
    for (o, p) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        let p = std::str::from_utf8(p.as_slice()).map_err(|e| e.to_string())?;
        *o = u8::from_str_radix(p, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// A key handle: only `env:NAME` (32-byte seed, hex) resolves in this release.
pub fn resolve(handle: &str) -> Result<[u8; 32], String> {
    let var = handle
        .strip_prefix("env:")
        .ok_or_else(|| format!("key handle {handle:?}: only env:NAME resolves in this release"))?;
    let v = std::env::var(var).map_err(|_| format!("key handle {handle:?}: {var} is not set"))?;
    hex32(v.trim())
}

/// Roster bytes from a file: hex text if it is all hex digits (whitespace ignored), else raw.
pub fn roster_bytes(path: &Path) -> Result<Vec<u8>, String> {
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

fn home_code(s: &str) -> Result<HomeCode, String> {
    match s {
        "TYO" => Ok(HomeCode::Tyo),
        "LDN" => Ok(HomeCode::Ldn),
        "NYC" => Ok(HomeCode::Nyc),
        _ => Err(format!(
            "config consensus.home {s:?} is not TYO, LDN or NYC"
        )),
    }
}

fn sock(a: Addr) -> SocketAddr {
    let ip = Ipv6Addr::from(a.ip);
    match ip.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port),
        None => SocketAddr::new(IpAddr::V6(ip), a.port),
    }
}

impl Plan {
    pub fn new(s: &Section, epoch: Epoch, vote: &str, node: Option<&str>) -> Result<Self, String> {
        let bytes = roster_bytes(&s.roster)?;
        let home = home_code(&s.home)?;
        let n = u8::try_from(Mode::Base.n()).unwrap_or(u8::MAX);
        let cfg = EpoConfig {
            epoch,
            home,
            t_start: Nanos(0),
            roster_hash: Hash(hex32(&s.roster_hash)?),
            seq_order: s.seq_order.unwrap_or([n, n + 1]),
            lane_map_hash: [Hash([0; 32]); 3],
            n_lanes: [0; 3],
            version: 0,
            endpoint_hash: Hash([0; 32]),
            flags: 0,
            sig_scheme: 0,
        };
        let domain = Domain {
            genesis_hash: Hash(hex32(&s.genesis_hash)?),
            mode: Mode::Base,
        };
        let (membership, roster) = vyrn_epoch::Membership::from_roster(&cfg, &bytes, &domain, None)
            .map_err(|e| format!("config consensus.roster: {e}"))?;
        let peers = roster
            .home(home)
            .voters
            .iter()
            .map(|v| {
                let key =
                    |k: &[u8]| <[u8; 32]>::try_from(k).map_err(|_| "a roster key is not 32 bytes");
                Ok(net::Peer {
                    vote_key: key(&v.vote_key)?,
                    node_key: key(&v.node_key)?,
                    repl_addr: sock(v.repl_addr),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let vote_seed = resolve(vote)?;
        let node_seed = node.map_or(Ok(vote_seed), resolve)?;
        let own = vyrn_crypto::ed25519::public_key(&vote_seed);
        let me = peers
            .iter()
            .position(|p| p.vote_key == own)
            .ok_or("keys.vote is not a voter of the roster's home (01 §14.4)")?;
        if vyrn_crypto::ed25519::public_key(&node_seed) != peers[me].node_key {
            return Err("keys.node is not this voter's roster node_key".into());
        }
        let d = Duration::from_millis(s.delta_ms.max(1));
        let timeouts = Timeouts {
            leader: d * 2,
            advance: d * 3,
            retry: d * 3,
            skip: d * 4,
        };
        let storage = s.storage.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("vyrn-validator-{}-{me}", std::process::id()))
        });
        Ok(Self {
            committee: membership.committee().clone(),
            peers,
            me,
            vote_seed,
            node_seed,
            seq_key: membership.seq()[0].seq_key,
            epoch,
            observers: s.observers.clone(),
            timeouts,
            storage,
        })
    }

    pub fn repl_addr(&self) -> SocketAddr {
        self.peers[self.me].repl_addr
    }
}

/// Runs the voter until `stop`: waits for the genesis header, then Simplex. Prints
/// `FINAL height=<last> view=<v> first=<h> kind=<0|1> sigs=<k>` per certificate and
/// `VOTER_FAULT kind=<k> voter=<i>` per piece of evidence.
pub fn run(plan: Plan, source: Source, stop: &AtomicBool) -> Result<(), String> {
    let genesis = loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(h) = BlockSource::header(&source, Height(0)) {
            break Genesis {
                height: h.height,
                hash: header_hash(&h),
                last_step: h.last_step,
            };
        }
        // Before Simplex starts: this thread is idle until the order core accepts header 0.
        std::thread::park_timeout(Duration::from_millis(1));
    };
    let ctrl = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let cfg = commonware_runtime::tokio::Config::new().with_storage_directory(&plan.storage);
    let storage = plan.storage.clone();
    let r = commonware_runtime::tokio::Runner::new(cfg).start(|ctx| async move {
        let n = net::start(
            ctx.child("net"),
            plan.node_seed,
            plan.repl_addr(),
            &plan.peers,
        )
        .map_err(|e| e.to_string())?;
        let (vcfg, mut out) = vyrn_consensus::voter::config(
            ctx.child("voter"),
            n.blocker,
            VoterConfig {
                committee: plan.committee,
                vote_seed: plan.vote_seed,
                seq_key: plan.seq_key,
                epoch: plan.epoch,
                genesis,
                source,
                timeouts: plan.timeouts,
            },
        )
        .map_err(|e| e.to_string())?;
        let engine = Engine::new(ctx.child("engine"), vcfg).start(n.vote, n.cert, n.resolver);
        let send = |b: &[u8]| {
            for a in &plan.observers {
                // UDP: a lost datagram is a lost vote, which the certificate later covers.
                let _ = ctrl.send_to(b, a);
            }
        };
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        while !stop.load(Ordering::Acquire) {
            tokio::select! {
                Some(c) = out.certs.recv() => {
                    send(&ctrl::encode_cert(&c));
                    println!(
                        "FINAL height={} view={} first={} kind={} sigs={}",
                        c.proposal.last_height.0,
                        c.view,
                        c.proposal.first_height.0,
                        c.proposal.kind as u8,
                        c.sigs.len()
                    );
                }
                Some(v) = out.votes.recv() => send(&ctrl::encode_vote(&v)),
                Some(f) = out.faults.recv() => {
                    println!("VOTER_FAULT kind={:?} voter={}", f.kind, f.voter);
                }
                _ = tick.tick() => {}
            }
        }
        engine.abort();
        Ok::<(), String>(())
    });
    let _ = std::fs::remove_dir_all(storage);
    r
}
