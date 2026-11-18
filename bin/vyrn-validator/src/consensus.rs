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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use commonware_consensus::simplex::Engine;
use commonware_runtime::{Runner as _, Supervisor as _};
use serde::Deserialize;
use vyrn_consensus::voter::{Timeouts, VoterConfig};
use vyrn_consensus::{BlockSource, Committee, Genesis, Seal, Verdict, ctrl, net};
use vyrn_epoch::{Addr, Domain, EpoConfig};
use vyrn_log::block::header_hash;
use vyrn_types::{BlockHeader, Epoch, Hash, Height, HomeCode, Mode, Nanos, PubKey};

/// The context of peer fetch keys (08 §9.6): `K_fetch` with `"peerfetch"` for `"fetch"`.
pub const PEER_FETCH_CONTEXT: &str = "vyrn      v1 peerfetch";

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
    /// Where the voter's Simplex journal lives; required for a voter, kept across restarts.
    /// *Reading* (restart safety): no default. A temporary journal is lost on restart, and a
    /// voter that restarts without its own votes can sign one that conflicts with them in the
    /// view it died in (a nullify and a finalize, or two proposals as leader). An observer, which
    /// does not vote, needs none.
    #[serde(default)]
    pub storage: Option<PathBuf>,
    /// `--fresh`: the operator's one-shot acknowledgement that this voter starts with an empty
    /// journal for the epoch; without it, an empty journal refuses to start ([`Plan::new`]). Not a
    /// config key (a TOML `fresh` is an unknown field): a persistent value would disarm the guard
    /// for every later wipe.
    #[serde(skip)]
    pub fresh: bool,
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
    /// The tenure is deposed here (07 §9.2), and this voter's seal candidate (07 §9.4,
    /// `depose.rs`) once it holds one.
    deposed: bool,
    seal: Option<Seal>,
}

/// The voter's [`BlockSource`]. The order thread writes it; Simplex reads it. `default()` is
/// the source of a box without `[consensus]`: it keeps nothing.
#[derive(Clone, Default)]
pub struct Source(Option<Arc<Mutex<Held>>>, Arc<AtomicU64>);

impl Source {
    /// A source that keeps blocks for a voter, until [`Source::finalized`] drops them.
    pub fn new() -> Self {
        Self(Some(Arc::default()), Arc::default())
    }

    /// The highest height a finality certificate covered; 0 before the first (and without a
    /// voter). The order thread reads it for the data join's retention (07 §5.4).
    pub fn final_height(&self) -> u64 {
        self.1.load(Ordering::Acquire)
    }

    fn held(&self) -> Option<std::sync::MutexGuard<'_, Held>> {
        self.0
            .as_ref()
            .map(|m| m.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// A header the order core accepted (its `seq_sig`, chain and steps).
    pub fn header(&self, h: BlockHeader) {
        if let Some(mut held) = self.held() {
            held.headers.insert(h.height.0, h);
        }
    }

    /// The block's body passed: its ORDER bytes and, when the data tier is wired, its payloads.
    pub fn valid(&self, height: Height) {
        if let Some(mut held) = self.held() {
            held.valid.insert(height.0);
        }
    }

    /// `height` is final: drop what is below it. The final block stays, as the next proposal's
    /// parent tip.
    fn finalized(&self, height: Height) {
        self.1.fetch_max(height.0, Ordering::AcqRel);
        if let Some(mut held) = self.held() {
            held.headers = held.headers.split_off(&height.0);
            held.valid = held.valid.split_off(&height.0);
        }
    }

    /// The tenure is deposed at this voter (07 §9.2): from now on it proposes only a seal.
    pub fn set_deposed(&self) {
        if let Some(mut h) = self.held() {
            h.deposed = true;
        }
    }

    /// This voter's seal candidate (07 §9.4).
    pub fn set_seal(&self, seal: Seal) {
        if let Some(mut h) = self.held() {
            h.seal = Some(seal);
        }
    }

    /// Nothing at or above `height` may be voted for (a fault, or a data root that differs).
    pub fn invalid_from(&self, height: Height) {
        if let Some(mut h) = self.held() {
            h.invalid_from = Some(h.invalid_from.map_or(height.0, |f| f.min(height.0)));
        }
    }
}

impl BlockSource for Source {
    fn header(&self, height: Height) -> Option<BlockHeader> {
        self.held()?.headers.get(&height.0).copied()
    }

    fn check_body(&self, _: Epoch, first: Height, last: Height) -> Verdict {
        let Some(h) = self.held() else {
            return Verdict::Pending;
        };
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

    fn seal(&self, _: Epoch) -> Option<Seal> {
        self.held()?.seal.clone()
    }

    fn deposed(&self, _: Epoch) -> bool {
        self.held().is_some_and(|h| h.deposed)
    }

    /// 07 §9.3 items 3–4 on the tail. The voter asks only about its own candidate
    /// ([`BlockSource::seal`]), which this voter built from the frames and payloads it holds
    /// (`depose::seal`): its bytes are the frames it holds, so item 3 has nothing to compare,
    /// and item 4's unavailable list is its own. Any other seal is no candidate here.
    fn check_seal(&self, _: Epoch, seal: &Seal) -> Verdict {
        match self.held() {
            // Heights this voter already rejected stay rejected (Codex r4618629082).
            Some(h) if h.invalid_from.is_some_and(|f| seal.header.height.0 >= f) => {
                Verdict::Invalid
            }
            Some(h) if h.seal.as_ref() == Some(seal) => Verdict::Valid,
            _ => Verdict::Pending,
        }
    }
}

/// `CLOCK_REALTIME` in ns: the clock of a TailReport's `t_last_rx` (07 §9.3, PTP in production).
pub fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// No blob in the journal's partition holds a byte (or the partition does not exist).
fn journal_empty(part: &std::path::Path) -> bool {
    std::fs::read_dir(part).map_or(true, |d| {
        !d.flatten()
            .any(|e| e.metadata().is_ok_and(|m| m.is_file() && m.len() > 0))
    })
}

/// What the voter thread needs, resolved from the config before any thread starts.
pub struct Plan {
    pub committee: Committee,
    pub peers: Vec<net::Peer>,
    pub me: usize,
    pub vote_seed: [u8; 32],
    pub node_seed: [u8; 32],
    pub seq_key: PubKey,
    /// `seq_order`'s `seq_key`s, primary first (07 §9.5): who may report a tail.
    pub seq_order: Vec<PubKey>,
    pub epoch: Epoch,
    pub observers: Vec<SocketAddr>,
    pub timeouts: Timeouts,
    pub storage: PathBuf,
    /// The roster and the facts that select from it, for `K_fetch` ([`Plan::keyring`]).
    roster: vyrn_epoch::Roster,
    domain: Domain,
    home: HomeCode,
}

/// The roster facts a voter derives its `K_fetch` keys from (08 §9.6), apart from the
/// epoch: `EPOCH <e>` on stdin re-derives them for epoch `e` (crate docs, Control).
#[derive(Clone)]
pub struct Keyring {
    roster: vyrn_epoch::Roster,
    domain: Domain,
    home: HomeCode,
    me: usize,
}

impl Keyring {
    /// `K_fetch(e, me, d)` (08 §9.6) under `context` this voter seals its fetches to target `d`
    /// of its home with (a data box, `SEQ_TARGET + j` or, under [`PEER_FETCH_CONTEXT`],
    /// `VOTER_TARGET + j`), from its X25519 `secret`. `None` if the roster has no target `d` or
    /// its key is unusable.
    pub fn fetch_key(&self, e: Epoch, context: &str, d: u8, secret: &[u8; 32]) -> Option<[u8; 16]> {
        let i = u8::try_from(self.me).ok()?;
        self.roster
            .requester_fetch_key(context, &self.domain, e, self.home, i, d, secret)
    }

    /// The keys this voter serves peer fetches under in epoch `e`: `K_fetch(e, i,
    /// VOTER_TARGET + me)` of every requester `i` with a usable key (08 §9.6), with `i` and its
    /// `repl_addr` IPv4. A keyed server with none serves nothing. An `Err` when the roster
    /// gives this voter a usable `xchg_key` and `secret` is not its private half.
    pub fn peer_keys(
        &self,
        e: Epoch,
        secret: &[u8; 32],
    ) -> Result<Vec<(u8, std::net::Ipv4Addr, [u8; 16])>, String> {
        let Some(d) = u8::try_from(self.me)
            .ok()
            .and_then(|m| vyrn_epoch::VOTER_TARGET.checked_add(m))
        else {
            return Ok(Vec::new());
        };
        let keys =
            self.roster
                .box_fetch_keys(PEER_FETCH_CONTEXT, &self.domain, e, self.home, d, secret);
        let Some(keys) = keys else {
            let usable = self
                .roster
                .fetch_target(self.home, d)
                .is_some_and(|k| k.len() >= 32);
            return if usable {
                Err(format!(
                    "[data] xchg is not the private half of voter {}'s roster xchg_key",
                    self.me
                ))
            } else {
                Ok(Vec::new())
            };
        };
        Ok(keys
            .into_iter()
            .filter(|(i, _, _)| usize::from(*i) != self.me)
            .filter_map(|(i, a, k)| Some((i, a.ipv4()?, k)))
            .collect())
    }
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

/// The roster `s` names, checked against its `roster_hash` (08 §9.6), and the home it serves.
fn membership(
    s: &Section,
    epoch: Epoch,
) -> Result<(vyrn_epoch::Membership, vyrn_epoch::Roster, HomeCode, Domain), String> {
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
    Ok((membership, roster, home, domain))
}

/// The committee whose certificates an observer accepts.
pub fn committee(s: &Section, epoch: Epoch) -> Result<Committee, String> {
    Ok(membership(s, epoch)?.0.committee().clone())
}

impl Plan {
    pub fn new(s: &Section, epoch: Epoch, vote: &str, node: Option<&str>) -> Result<Self, String> {
        let (membership, roster, home, domain) = membership(s, epoch)?;
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
        let storage = s
            .storage
            .clone()
            .ok_or("[consensus] storage is required for a voter: its Simplex journal must survive a restart")?;
        // *Reading* (07 §9 names no check): an empty journal for this epoch is a new voter or a
        // wiped disk, and a wiped disk can sign against its own lost votes. It starts only with
        // the operator's `fresh` acknowledgement, which is theirs to give: valid while the
        // committee has not finalized past genesis in this epoch, or as a known risk.
        let index = membership
            .committee()
            .index_of(&own)
            .ok_or("keys.vote is not in the committee")?;
        let part = storage.join(vyrn_consensus::voter::partition(epoch, index));
        if journal_empty(&part) {
            if !s.fresh {
                return Err(format!(
                    "the Simplex journal {} is empty: a voter that lost its votes can equivocate; start with --fresh only if the committee has not finalized past genesis in epoch {}, or knowingly",
                    part.display(),
                    epoch.0
                ));
            }
            println!("FRESH_JOURNAL epoch={} voter={index}", epoch.0);
        }
        Ok(Self {
            committee: membership.committee().clone(),
            peers,
            me,
            vote_seed,
            node_seed,
            seq_key: membership.seq()[0].seq_key,
            seq_order: membership.seq().iter().map(|b| b.seq_key).collect(),
            epoch,
            observers: s.observers.clone(),
            timeouts,
            storage,
            roster,
            domain,
            home,
        })
    }

    /// What this voter derives its `K_fetch` keys from, for any epoch ([`Keyring`]).
    pub fn keyring(&self) -> Keyring {
        Keyring {
            roster: self.roster.clone(),
            domain: self.domain,
            home: self.home,
            me: self.me,
        }
    }

    pub fn repl_addr(&self) -> SocketAddr {
        self.peers[self.me].repl_addr
    }
}

/// An observer's finality (03 §4.5: it runs no votes): binds `ctrl`, which the validators list
/// in their `[consensus] observers`, and takes their finalize votes and certificates through a
/// `vyrn_consensus::Listener`, as the sequencer does. Each time the final height moves it
/// prints `FINAL height=<h> from=<votes|cert>`, marks it in `source` (the data join's
/// retention) and sends the certified tip, `(last_height, last_hash)`, to `certs`: the order
/// thread marks its own replayed blocks final only when their header hash is that tip's.
/// Returns the datagrams refused.
pub fn observe(
    committee: Committee,
    epoch: Epoch,
    sock: &UdpSocket,
    source: &Source,
    certs: &std::sync::mpsc::Sender<(Height, Hash)>,
    stop: &AtomicBool,
) -> u64 {
    let mut l = vyrn_consensus::Listener::new(committee, epoch, Height(0));
    let mut buf = [0u8; 9216];
    let mut refused = 0;
    while !stop.load(Ordering::Acquire) {
        let Ok((n, _)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let before = l.final_height();
        let from = match ctrl::decode(buf.get(..n).unwrap_or(&[])) {
            Ok(ctrl::Ctrl::Vote(v)) => l.on_vote(&v).map(|c| c.map(|c| (c.proposal, "votes"))),
            Ok(ctrl::Ctrl::Cert(c)) => l.on_cert(&c).map(|()| Some((c.proposal, "cert"))),
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        match from {
            Ok(Some((p, from))) if l.final_height() > before => {
                source.finalized(l.final_height());
                let _ = certs.send((p.last_height, p.last_hash));
                println!("FINAL height={} from={from}", l.final_height().0);
            }
            Ok(_) => {}
            Err(_) => refused += 1,
        }
    }
    refused
}

/// Runs the voter until `stop`: waits for the genesis header, then Simplex. Prints
/// `FINAL height=<last> view=<v> first=<h> kind=<0|1> sigs=<k>` per certificate and
/// `VOTER_FAULT kind=<k> voter=<i>` per piece of evidence.
pub fn run(
    plan: Plan,
    source: Source,
    stop: &AtomicBool,
    fo: Option<(crate::depose::Section, crate::depose::Shared)>,
) -> Result<(), String> {
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
    commonware_runtime::tokio::Runner::new(cfg).start(|ctx| async move {
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
                committee: plan.committee.clone(),
                vote_seed: plan.vote_seed,
                seq_key: plan.seq_key,
                epoch: plan.epoch,
                genesis,
                source: source.clone(),
                timeouts: plan.timeouts,
            },
        )
        .map_err(|e| e.to_string())?;
        let engine = Engine::new(ctx.child("engine"), vcfg).start(n.vote, n.cert, n.resolver);
        // 07 §9.1–9.3 (`depose.rs`): this voter's own `Silence`, peers' from the tail channel.
        let mut tail = n.tail;
        let me = u8::try_from(plan.me).unwrap_or(u8::MAX);
        let mut tally = fo.as_ref().map(|(s, _)| {
            crate::depose::Tally::new(
                plan.committee.clone(),
                plan.seq_order.clone(),
                plan.epoch,
                // Reading: this release runs tenure 0 only (promotion is a later change).
                0,
                me,
                s.abort_us,
            )
        });
        let mut own: Option<Vec<u8>> = None;
        let mut resent = std::time::Instant::now();
        let send = |b: &[u8]| {
            for a in &plan.observers {
                // UDP: a lost datagram is a lost vote, which the certificate later covers.
                let _ = ctrl.send_to(b, a);
            }
        };
        // 1 ms with `[failover]`: the abort window is 5 ms and the tail wait 4.05 ms (07 §9.1–9.2).
        let period = if fo.is_some() { 1 } else { 5 };
        let mut tick = tokio::time::interval(Duration::from_millis(period));
        while !stop.load(Ordering::Acquire) {
            if let (Some(t), Some((_, shared))) = (tally.as_mut(), fo.as_ref()) {
                if let Some(b) = t.own(shared, &plan.vote_seed) {
                    println!("SILENCE_SENT epoch={} voter={me}", plan.epoch.0);
                    tail.broadcast(b.clone());
                    own = Some(b);
                    resent = std::time::Instant::now();
                }
                // A peer that was disconnected missed it: again every 2 ms until live.
                if shared.phase() == crate::depose::Phase::Live {
                    own = None;
                } else if let Some(b) = own
                    .as_ref()
                    .filter(|_| resent.elapsed() >= Duration::from_millis(2))
                {
                    tail.broadcast(b.clone());
                    resent = std::time::Instant::now();
                }
                if let Some(line) = t.poll(shared, realtime_ns()) {
                    if line.starts_with("DEPOSED") {
                        source.set_deposed();
                    }
                    println!("{line}");
                }
            }
            tokio::select! {
                Some((_, b)) = tail.recv(), if tally.is_some() => {
                    if let Some(t) = tally.as_mut()
                        && let Err(e) = t.on_silence(&b)
                    {
                        println!("SILENCE_REFUSED {e}");
                    }
                }
                Some(c) = out.certs.recv() => {
                    send(&ctrl::encode_cert(&c));
                    source.finalized(c.proposal.last_height);
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
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod seal_tests {
    use super::*;
    use vyrn_consensus::SealExt;
    use vyrn_types::{BookId, StepId};

    /// Codex r4618629082: once the order core rejected a height, this voter's own seal
    /// candidate covering it is no longer valid, though it equals the held candidate.
    #[test]
    fn a_seal_over_a_rejected_height_is_invalid() {
        let header = BlockHeader {
            height: Height(6),
            epoch: Epoch(0),
            book: BookId(7),
            first_step: StepId(8),
            last_step: StepId(9),
            prev: Hash([1; 32]),
            order_root: Hash([2; 32]),
            data_root: Hash([3; 32]),
            seq_sig: [0; 64],
        };
        let seal = Seal {
            header,
            ext: SealExt {
                end_frame_seq: [12, 0],
                next_seq: 0xFF,
                next_tenure: 1,
                unavail: Vec::new(),
            },
        };
        let s = Source::new();
        s.set_seal(seal.clone());
        assert_eq!(s.check_seal(Epoch(0), &seal), Verdict::Valid);
        s.invalid_from(Height(7));
        assert_eq!(s.check_seal(Epoch(0), &seal), Verdict::Valid);
        s.invalid_from(Height(6));
        assert_eq!(s.check_seal(Epoch(0), &seal), Verdict::Invalid);
    }
}
