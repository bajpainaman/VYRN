//! The roster: every key and replica-plane address of all three homes, named by
//! `EpoConfig.roster_hash` (08 §9.6), and its view as one home's [`Membership`] (07 §13.1).
//!
//! **Writer.** The control path (BASE: admin; CHAIN: 09's `NodeCert`s and governance) publishes the
//! roster bytes with `EpoConfig(e)`; the config carries only their hash, which `HandoffCert(e − 1)`
//! certifies through `log_hash`.
//!
//! **Readers.** [`Membership::from_roster`] is the one door from bytes to keys: it checks the bytes
//! against `roster_hash`, decodes them, and builds the voters and `vyrn-seq` boxes of
//! `home(e)` in `EpoConfig(e).seq_order`. Binaries read addresses from [`Roster::home`].
//!
//! **Rejects** ([`RosterErr`]): a hash, version, scheme or length mismatch, trailing bytes, and
//! every rule of 08 §9.6 (`CLIENT_SPLIT`, a key both voting and sequencing, a recovery service
//! on a Vx voter, a `seq_order` that is not the primary and standby boxes R8 allows).

use crate::Domain;
use crate::bridge::{BRIDGE_SIGNERS, BridgeSignerTable, BridgeSigners, EvmAddress};
use crate::membership::{Membership, MembershipErr, SeqBox};
use crate::schedule::EpoConfig;
use thiserror::Error;
use vyrn_types::{Epoch, Hash, HomeCode, Mode, PubKey};

/// The only roster version a decoder accepts (08 §9.6).
pub const ROSTER_VERSION: u8 = 1;
/// The hashing context, six spaces after "vyrn" like every vyrn-epoch context.
pub const ROSTER_CONTEXT: &str = "vyrn      v1 roster";
/// The `K_fetch` context (08 §9.6), padded like every vyrn-epoch context.
pub const FETCH_CONTEXT: &str = "vyrn      v1 fetch";
/// `HomeCode` order of [`Roster::homes`].
pub const HOMES: [HomeCode; 3] = [HomeCode::Tyo, HomeCode::Ldn, HomeCode::Nyc];

/// Public-key length of a live scheme (01 §3): 0 Ed25519, 1 Ed25519 ‖ ML-DSA-44.
pub fn key_len(sig_scheme: u8) -> Option<usize> {
    match sig_scheme {
        0 => Some(32),
        1 => Some(1_344),
        _ => None,
    }
}

/// `KexKey` length of a live scheme (01 §3, PQ-6(a)): X25519 (32 B) under scheme 0, X25519 ‖
/// ML-KEM-768 encapsulation key (32 + 1,184 B) under scheme 1.
pub fn xchg_len(sig_scheme: u8) -> Option<usize> {
    match sig_scheme {
        0 => Some(32),
        1 => Some(1_216),
        _ => None,
    }
}

/// An IPv6 address (IPv4 as `::ffff:a.b.c.d`) and a port: 18 bytes, port little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub ip: [u8; 16],
    pub port: u16,
}

/// One voter of a home; its voter index is its position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Voter {
    /// 0 Rust, 1 Vx.
    pub client: u8,
    /// k for facility Fk.
    pub facility: u8,
    /// `NK`: `EpoReady`, p2p identity.
    pub node_key: Vec<u8>,
    /// `VK`: votes and certificates.
    pub vote_key: Vec<u8>,
    /// `GXK`: the G-key exchange key, to which 09 §2.4 wraps `G(e, s)`; BASE reads none.
    pub xchg_key: Vec<u8>,
    pub data_addr: Addr,
    pub repl_addr: Addr,
}

/// One `vyrn-seq` box (always Rust); its roster index is `n + position`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqEntry {
    pub facility: u8,
    pub node_key: Vec<u8>,
    /// `SK`: `seq_sig`.
    pub seq_key: Vec<u8>,
    /// `XK`: session keys (`K_seq`, `K_out`).
    pub xchg_key: Vec<u8>,
    pub client_addr: Addr,
    pub repl_addr: Addr,
}

/// One `vyrn-data` box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataBox {
    pub facility: u8,
    pub addr: Addr,
    /// `KexKey` of `sig_scheme` (01 §3). Its X25519 half keys `K_fetch` ([`fetch_key`]).
    pub xchg_key: Vec<u8>,
}

/// The nodes of one home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Home {
    /// `n` voters, `N_BASE` or `N_CHAIN`.
    pub voters: Vec<Voter>,
    /// BASE: at least 2. CHAIN: `2 × N_CHAIN`; box 2k is operator k's F1 box, 2k + 1 its F2 box.
    pub seq: Vec<SeqEntry>,
    /// Voter index of the recovery service (07 §8.5).
    pub recovery: u8,
    pub data: Vec<DataBox>,
}

/// The roster (08 §9.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub sig_scheme: u8,
    /// The first epoch it may configure.
    pub epoch_from: Epoch,
    /// TYO, LDN, NYC.
    pub homes: [Home; 3],
    /// CHAIN: the bridge signer set in force; BASE: none.
    pub bridge: Option<BridgeSigners>,
}

/// Why roster bytes do not configure an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum RosterErr {
    #[error("the bytes do not hash to EpoConfig.roster_hash")]
    Hash,
    #[error("roster version {0} is not 1")]
    Version(u8),
    #[error("sig_scheme {0} is not a live-key scheme (0 or 1)")]
    NotLive(u8),
    #[error("sig_scheme {got} is not EpoConfig's {want}")]
    Scheme { got: u8, want: u8 },
    #[error("the roster is truncated")]
    Short,
    #[error("{0} trailing bytes after the roster")]
    Trailing(usize),
    #[error("epoch_from {from:?} is after the configured epoch {epoch:?}")]
    Early { from: Epoch, epoch: Epoch },
    #[error("home {0}: a client byte is not 0 or 1, or a facility is 0")]
    Field(u8),
    #[error("home {0}: one client holds a quorum of voters (CLIENT_SPLIT)")]
    ClientSplit(u8),
    #[error("home {0}: a vote or seq key repeats")]
    DuplicateKey(u8),
    #[error("home {0}: recovery is not a Rust voter")]
    Recovery(u8),
    #[error("home {0}: an operator's two vyrn-seq boxes differ in SK or XK, or share a facility")]
    OperatorBoxes(u8),
    #[error("home {0}: wrong number of vyrn-seq boxes")]
    SeqCount(u8),
    #[error("the bridge section is malformed or missing")]
    Bridge,
    #[error("seq_order {0:?} is not a primary and a standby R8 allows")]
    SeqOrder([u8; 2]),
    #[error("sig_scheme {0} keys are not supported by vyrn-consensus yet")]
    Unsupported(u8),
    #[error(transparent)]
    Membership(#[from] MembershipErr),
}

impl Roster {
    /// The canonical bytes (08 §9.6).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![ROSTER_VERSION, self.sig_scheme];
        b.extend_from_slice(&self.epoch_from.0.to_le_bytes());
        for h in &self.homes {
            for v in &h.voters {
                b.extend_from_slice(&[v.client, v.facility]);
                b.extend_from_slice(&v.node_key);
                b.extend_from_slice(&v.vote_key);
                b.extend_from_slice(&v.xchg_key);
                put_addr(&mut b, v.data_addr);
                put_addr(&mut b, v.repl_addr);
            }
            b.push(len_u8(h.seq.len()));
            for s in &h.seq {
                b.push(s.facility);
                b.extend_from_slice(&s.node_key);
                b.extend_from_slice(&s.seq_key);
                b.extend_from_slice(&s.xchg_key);
                put_addr(&mut b, s.client_addr);
                put_addr(&mut b, s.repl_addr);
            }
            b.push(h.recovery);
            b.push(len_u8(h.data.len()));
            for d in &h.data {
                b.push(d.facility);
                put_addr(&mut b, d.addr);
                b.extend_from_slice(&d.xchg_key);
            }
        }
        if let Some(set) = &self.bridge {
            b.extend_from_slice(&set.rotation_no.to_le_bytes());
            for k in set.bridge_keys.iter().chain(&set.guardian_keys) {
                b.extend_from_slice(k);
            }
        }
        b
    }

    /// `derive_key(ROSTER_CONTEXT, genesis_hash ‖ mode ‖ bytes)`.
    pub fn hash_bytes(domain: &Domain, bytes: &[u8]) -> Hash {
        Hash(domain.message(ROSTER_CONTEXT, bytes))
    }

    /// The `roster_hash` of this roster.
    pub fn hash(&self, domain: &Domain) -> Hash {
        Self::hash_bytes(domain, &self.encode())
    }

    /// Decodes and checks every rule that does not need an `EpoConfig`.
    pub fn decode(mode: Mode, bytes: &[u8]) -> Result<Self, RosterErr> {
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != ROSTER_VERSION {
            return Err(RosterErr::Version(version));
        }
        let sig_scheme = r.u8()?;
        let k = key_len(sig_scheme).ok_or(RosterErr::NotLive(sig_scheme))?;
        let x = xchg_len(sig_scheme).ok_or(RosterErr::NotLive(sig_scheme))?;
        let epoch_from = Epoch(u32::from_le_bytes(r.array()?));
        let mut home = || -> Result<Home, RosterErr> {
            let voters = (0..mode.n())
                .map(|_| {
                    Ok(Voter {
                        client: r.u8()?,
                        facility: r.u8()?,
                        node_key: r.take(k)?.to_vec(),
                        vote_key: r.take(k)?.to_vec(),
                        xchg_key: r.take(x)?.to_vec(),
                        data_addr: r.addr()?,
                        repl_addr: r.addr()?,
                    })
                })
                .collect::<Result<_, RosterErr>>()?;
            let n_seq = r.u8()?;
            let seq = (0..n_seq)
                .map(|_| {
                    Ok(SeqEntry {
                        facility: r.u8()?,
                        node_key: r.take(k)?.to_vec(),
                        seq_key: r.take(k)?.to_vec(),
                        xchg_key: r.take(x)?.to_vec(),
                        client_addr: r.addr()?,
                        repl_addr: r.addr()?,
                    })
                })
                .collect::<Result<_, RosterErr>>()?;
            let recovery = r.u8()?;
            let n_data = r.u8()?;
            let data = (0..n_data)
                .map(|_| {
                    Ok(DataBox {
                        facility: r.u8()?,
                        addr: r.addr()?,
                        xchg_key: r.take(x)?.to_vec(),
                    })
                })
                .collect::<Result<_, RosterErr>>()?;
            Ok(Home {
                voters,
                seq,
                recovery,
                data,
            })
        };
        let homes = [home()?, home()?, home()?];
        let bridge = match mode {
            Mode::Base => None,
            Mode::Chain => {
                let rotation_no = u64::from_le_bytes(r.array()?);
                let mut keys = [[0u8; 20]; 2 * BRIDGE_SIGNERS];
                for key in &mut keys {
                    *key = r.array::<20>()?;
                }
                let half = |i: usize| -> [EvmAddress; BRIDGE_SIGNERS] {
                    core::array::from_fn(|j| keys[i * BRIDGE_SIGNERS + j])
                };
                Some(BridgeSigners {
                    rotation_no,
                    bridge_keys: half(0),
                    guardian_keys: half(1),
                })
            }
        };
        if !r.0.is_empty() {
            return Err(RosterErr::Trailing(r.0.len()));
        }
        let roster = Self {
            sig_scheme,
            epoch_from,
            homes,
            bridge,
        };
        roster.check(mode)?;
        Ok(roster)
    }

    /// 08 §9.6 rules on one roster.
    fn check(&self, mode: Mode) -> Result<(), RosterErr> {
        if self.bridge.is_some() != (mode == Mode::Chain)
            || self.bridge.is_some_and(|b| !b.well_formed())
        {
            return Err(RosterErr::Bridge);
        }
        for (h, home) in HOMES.iter().zip(&self.homes) {
            let code = h.code();
            if home.voters.iter().any(|v| v.client > 1 || v.facility == 0)
                || home.seq.iter().any(|s| s.facility == 0)
                || home.data.iter().any(|d| d.facility == 0)
            {
                return Err(RosterErr::Field(code));
            }
            for client in 0..=1 {
                if home.voters.iter().filter(|v| v.client == client).count() >= mode.quorum() {
                    return Err(RosterErr::ClientSplit(code));
                }
            }
            // CHAIN: an operator's F1 and F2 boxes come from one NodeCert, so they share SK and
            // XK and sit in different facilities (09 §1, §2.3); SK is counted once per operator.
            if mode == Mode::Chain
                && home.seq.chunks(2).any(|p| {
                    p.len() == 2
                        && (p[0].seq_key != p[1].seq_key
                            || p[0].xchg_key != p[1].xchg_key
                            || p[0].facility == p[1].facility)
                })
            {
                return Err(RosterErr::OperatorBoxes(code));
            }
            let step = if mode == Mode::Chain { 2 } else { 1 };
            let keys: Vec<&[u8]> = home
                .voters
                .iter()
                .map(|v| v.vote_key.as_slice())
                .chain(home.seq.iter().step_by(step).map(|s| s.seq_key.as_slice()))
                .collect();
            if keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k)) {
                return Err(RosterErr::DuplicateKey(code));
            }
            if home
                .voters
                .get(usize::from(home.recovery))
                .is_none_or(|v| v.client != 0)
            {
                return Err(RosterErr::Recovery(code));
            }
            let seq_ok = match mode {
                Mode::Base => home.seq.len() >= 2,
                Mode::Chain => home.seq.len() == 2 * mode.n(),
            };
            if !seq_ok {
                return Err(RosterErr::SeqCount(code));
            }
        }
        Ok(())
    }

    /// CHAIN: the roster's bridge set must be the table's set of that rotation number, activated
    /// or scheduled to activate by `epoch` (08 §9.5).
    pub fn check_bridge(&self, table: &BridgeSignerTable, epoch: Epoch) -> Result<(), RosterErr> {
        match &self.bridge {
            Some(set) if table.for_epoch(set.rotation_no, epoch) == Some(set) => Ok(()),
            _ => Err(RosterErr::Bridge),
        }
    }

    /// The schedule's `seq_order` of `home` (08 §9.6), as roster indices. BASE (`chain` None):
    /// the first box in F1 and the first in F2. CHAIN (`chain` = `(seq_op(e), next_seq(e,
    /// seq_op(e)))`, 09 §3): the F1 box of the first and the F2 box of the second operator.
    pub fn seq_order(&self, home: HomeCode, chain: Option<(u8, u8)>) -> Option<[u8; 2]> {
        let h = self.home(home);
        let index = |pos: usize| u8::try_from(h.voters.len() + pos).ok();
        let (p, s) = match chain {
            None => (
                h.seq.iter().position(|b| b.facility == 1)?,
                h.seq.iter().position(|b| b.facility == 2)?,
            ),
            Some((op, standby)) if op != standby => {
                (2 * usize::from(op), 2 * usize::from(standby) + 1)
            }
            Some(_) => return None,
        };
        if s >= h.seq.len() || p >= h.seq.len() {
            return None;
        }
        Some([index(p)?, index(s)?])
    }

    /// The nodes of `home`.
    pub fn home(&self, home: HomeCode) -> &Home {
        let i = HOMES.iter().position(|h| *h == home).unwrap_or(0);
        &self.homes[i]
    }
}

/// `K_fetch(e, i, d)` (08 §9.6): `derive_key(context, shared ‖ genesis_hash ‖ mode ‖ le(e) ‖
/// [i] ‖ [d])[0..16]`, where `shared` is X25519 of requester `i`'s and target `d`'s `xchg_key`
/// X25519 halves ([`Roster::fetch_target`]). Both ends compute it: the target from its secret
/// and `i`'s public key, the requester from its secret and `d`'s. `context` is
/// [`FETCH_CONTEXT`] for data and `vyrn-seq` fetches; peer fetches pass their own.
pub fn fetch_key(
    context: &str,
    domain: &Domain,
    epoch: Epoch,
    i: u8,
    d: u8,
    shared: &[u8; 32],
) -> [u8; 16] {
    let mut m = Vec::with_capacity(32 + 33 + 6);
    m.extend_from_slice(shared);
    m.extend_from_slice(&domain.prefix());
    m.extend_from_slice(&epoch.0.to_le_bytes());
    m.extend_from_slice(&[i, d]);
    let k = vyrn_crypto::hash::derive_key(context, &m);
    core::array::from_fn(|j| k[j])
}

/// The X25519 half of a `KexKey`: its first 32 bytes (01 §3, PQ-6(a)).
fn x25519_half(k: &[u8]) -> Option<[u8; 32]> {
    k.get(..32)?.try_into().ok()
}

/// Fetch targets 0x80..=0xBF are `vyrn-seq` box `d - SEQ_TARGET` of the home (08 §9.6, reading).
pub const SEQ_TARGET: u8 = 0x80;
/// Fetch targets 0xC0..=0xFF are voter `d - VOTER_TARGET` of the home, for peer fetches.
pub const VOTER_TARGET: u8 = 0xC0;

impl Roster {
    /// The `xchg_key` of fetch target `d` of `home` (08 §9.6, reading): `0..SEQ_TARGET` is data
    /// box `d`, `SEQ_TARGET..VOTER_TARGET` its `vyrn-seq` box `d - SEQ_TARGET`, and from
    /// `VOTER_TARGET` its voter `d - VOTER_TARGET` (peer fetch). `None` if there is no such entry.
    pub fn fetch_target(&self, home: HomeCode, d: u8) -> Option<&[u8]> {
        let h = self.home(home);
        let k = match d {
            VOTER_TARGET.. => &h.voters.get(usize::from(d - VOTER_TARGET))?.xchg_key,
            SEQ_TARGET.. => &h.seq.get(usize::from(d - SEQ_TARGET))?.xchg_key,
            _ => &h.data.get(usize::from(d))?.xchg_key,
        };
        Some(k)
    }

    /// Target `d` of `home` ([`Roster::fetch_target`]): `K_fetch(e, i, d)` under `context` for
    /// every requester `i` of `home` (its voters, then its `vyrn-seq` boxes, by roster index),
    /// with the requester's `repl_addr`. `secret` is target `d`'s X25519 private key. `None` if
    /// `d` is not a target of `home`, or its secret does not match its roster key. A requester
    /// whose key is a low-order point is left out.
    pub fn box_fetch_keys(
        &self,
        context: &str,
        domain: &Domain,
        epoch: Epoch,
        home: HomeCode,
        d: u8,
        secret: &[u8; 32],
    ) -> Option<Vec<(u8, Addr, [u8; 16])>> {
        let h = self.home(home);
        if x25519_half(self.fetch_target(home, d)?)? != vyrn_crypto::x25519::public_key(secret) {
            return None;
        }
        let requesters = h
            .voters
            .iter()
            .map(|v| (v.xchg_key.as_slice(), v.repl_addr))
            .chain(h.seq.iter().map(|s| (s.xchg_key.as_slice(), s.repl_addr)));
        Some(
            requesters
                .enumerate()
                .filter_map(|(i, (pk, addr))| {
                    let i = u8::try_from(i).ok()?;
                    let shared = vyrn_crypto::x25519::shared_secret(secret, &x25519_half(pk)?)?;
                    Some((i, addr, fetch_key(context, domain, epoch, i, d, &shared)))
                })
                .collect(),
        )
    }

    /// Requester `i` of `home` (roster index): its `K_fetch(e, i, d)` under `context` for target
    /// `d` ([`Roster::fetch_target`]), from its own X25519 private key. `None` if `d` is unknown
    /// or its key is a low-order point.
    #[allow(clippy::too_many_arguments)] // each is one input of the 08 §9.6 formula
    pub fn requester_fetch_key(
        &self,
        context: &str,
        domain: &Domain,
        epoch: Epoch,
        home: HomeCode,
        i: u8,
        d: u8,
        secret: &[u8; 32],
    ) -> Option<[u8; 16]> {
        let pk = x25519_half(self.fetch_target(home, d)?)?;
        let shared = vyrn_crypto::x25519::shared_secret(secret, &pk)?;
        Some(fetch_key(context, domain, epoch, i, d, &shared))
    }
}

impl Addr {
    /// The IPv4 address of an `::ffff:a.b.c.d` address, else `None`.
    pub fn ipv4(&self) -> Option<core::net::Ipv4Addr> {
        let mapped = self.ip[..10].iter().all(|&b| b == 0) && self.ip[10..12] == [0xff, 0xff];
        let v4: [u8; 4] = self.ip[12..].try_into().ok()?;
        mapped.then(|| v4.into())
    }
}

impl Membership {
    /// The [`Membership`] of `cfg.epoch` from the roster bytes `cfg` names (08 §9.6): checks
    /// `roster_hash`, decodes, checks `sig_scheme`, `epoch_from` and `seq_order`, then takes
    /// `home(e)`'s voters in index order and `seq_order`'s boxes, spares after them in roster
    /// order. CHAIN needs the node's `bridge` signer table, which the roster's set must match
    /// (R7); BASE ignores it. Returns the decoded roster too, for addresses and the bridge set.
    pub fn from_roster(
        cfg: &EpoConfig,
        bytes: &[u8],
        domain: &Domain,
        bridge: Option<&BridgeSignerTable>,
    ) -> Result<(Self, Roster), RosterErr> {
        if Roster::hash_bytes(domain, bytes) != cfg.roster_hash {
            return Err(RosterErr::Hash);
        }
        let roster = Roster::decode(domain.mode, bytes)?;
        if domain.mode == Mode::Chain {
            roster.check_bridge(bridge.ok_or(RosterErr::Bridge)?, cfg.epoch)?;
        }
        if roster.sig_scheme != cfg.sig_scheme {
            return Err(RosterErr::Scheme {
                got: roster.sig_scheme,
                want: cfg.sig_scheme,
            });
        }
        if roster.epoch_from > cfg.epoch {
            return Err(RosterErr::Early {
                from: roster.epoch_from,
                epoch: cfg.epoch,
            });
        }
        let home = roster.home(cfg.home);
        let n = home.voters.len();
        let at = |index: u8| {
            usize::from(index)
                .checked_sub(n)
                .and_then(|j| home.seq.get(j))
        };
        let [p, s] = cfg.seq_order;
        let (Some(primary), Some(standby)) = (at(p), at(s)) else {
            return Err(RosterErr::SeqOrder(cfg.seq_order));
        };
        let (pos_p, pos_s) = (usize::from(p) - n, usize::from(s) - n);
        let allowed = match domain.mode {
            Mode::Base => primary.facility == 1 && standby.facility == 2,
            // An F1 box and another operator's F2 box (09 §1, §3.2).
            Mode::Chain => {
                pos_p % 2 == 0
                    && pos_s % 2 == 1
                    && pos_p / 2 != pos_s / 2
                    && primary.facility != standby.facility
            }
        };
        if p == s || !allowed {
            return Err(RosterErr::SeqOrder(cfg.seq_order));
        }
        let ed = |k: &[u8]| -> Result<PubKey, RosterErr> {
            k.try_into()
                .map_err(|_| RosterErr::Unsupported(roster.sig_scheme))
        };
        let seq_box = |index: u8, e: &SeqEntry| -> Result<SeqBox, RosterErr> {
            Ok(SeqBox {
                index,
                node_key: ed(&e.node_key)?,
                seq_key: ed(&e.seq_key)?,
                xchg_key: ed(&e.xchg_key)?,
            })
        };
        let voters = home
            .voters
            .iter()
            .map(|v| ed(&v.vote_key))
            .collect::<Result<_, _>>()?;
        let node_keys = home
            .voters
            .iter()
            .map(|v| ed(&v.node_key))
            .collect::<Result<_, _>>()?;
        let seq = [seq_box(p, primary)?, seq_box(s, standby)?];
        let spares = (n..n + home.seq.len())
            .filter_map(|i| u8::try_from(i).ok())
            .filter(|i| *i != p && *i != s)
            .map(|i| at(i).map_or(Err(RosterErr::SeqOrder(cfg.seq_order)), |e| seq_box(i, e)))
            .collect::<Result<_, _>>()?;
        let m = Membership::new(cfg.epoch, cfg.home, domain.mode, voters, node_keys, seq)?
            .with_spares(spares);
        Ok((m, roster))
    }
}

fn len_u8(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

fn put_addr(b: &mut Vec<u8>, a: Addr) {
    b.extend_from_slice(&a.ip);
    b.extend_from_slice(&a.port.to_le_bytes());
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RosterErr> {
        if self.0.len() < n {
            return Err(RosterErr::Short);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RosterErr> {
        self.take(N)?.try_into().map_err(|_| RosterErr::Short)
    }

    fn u8(&mut self) -> Result<u8, RosterErr> {
        Ok(self.array::<1>()?[0])
    }

    fn addr(&mut self) -> Result<Addr, RosterErr> {
        Ok(Addr {
            ip: self.array()?,
            port: u16::from_le_bytes(self.array()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, Local};

    /// Both ends of a fetch derive the same `K_fetch`, and it is bound to the epoch, the requester
    /// and the box: a wrong secret, another epoch, another requester index or another box gives
    /// another key, and the box refuses a secret that is not its roster key.
    #[test]
    fn box_and_requester_derive_the_same_fetch_key() {
        let mode = Mode::Base;
        let domain = testkit::domain(mode);
        let mut r = testkit::roster(mode, 0);
        let req_secret = [0x5a; 32];
        // Voter 2 of LDN gets a real X25519 key, so it can play the requester.
        r.homes[1].voters[2].xchg_key = vyrn_crypto::x25519::public_key(&req_secret).to_vec();
        let (e, ldn) = (Epoch(8), HomeCode::Ldn);
        let box0 = testkit::data_seed(2, 0);
        let keys = r
            .box_fetch_keys(FETCH_CONTEXT, &domain, e, ldn, 0, &box0)
            .unwrap();
        let n = r.homes[1].voters.len() + r.homes[1].seq.len();
        assert_eq!(keys.len(), n);
        let (_, addr, k) = keys.iter().find(|(i, _, _)| *i == 2).copied().unwrap();
        assert_eq!(addr, r.homes[1].voters[2].repl_addr);
        let mine = r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, 2, 0, &req_secret);
        assert_eq!(mine, Some(k));
        // Every other binding changes the key.
        assert_ne!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, Epoch(9), ldn, 2, 0, &req_secret),
            Some(k)
        );
        assert_ne!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, 3, 0, &req_secret),
            Some(k)
        );
        assert_ne!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, 2, 1, &req_secret),
            Some(k)
        );
        assert_ne!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, 2, 0, &[0x5b; 32]),
            Some(k)
        );
        let chain = testkit::domain(Mode::Chain);
        assert_ne!(
            r.requester_fetch_key(FETCH_CONTEXT, &chain, e, ldn, 2, 0, &req_secret),
            Some(k)
        );
        // Keys differ between requesters, and a box with the wrong secret gets none.
        assert!(keys.iter().all(|(i, _, x)| *i == 2 || *x != k));
        assert!(
            r.box_fetch_keys(FETCH_CONTEXT, &domain, e, ldn, 0, &[0x11; 32])
                .is_none()
        );
        assert!(
            r.box_fetch_keys(FETCH_CONTEXT, &domain, e, ldn, 9, &box0)
                .is_none()
        );
        // Another context (peer fetch) gives another key.
        assert_ne!(
            r.requester_fetch_key("vyrn      v1 peerfetch", &domain, e, ldn, 2, 0, &req_secret),
            Some(k)
        );
        // A `vyrn-seq` requester sits at index voters.len() + j.
        let seq_req = [0x78; 32];
        r.homes[1].seq[1].xchg_key = vyrn_crypto::x25519::public_key(&seq_req).to_vec();
        let j = u8::try_from(r.homes[1].voters.len() + 1).unwrap();
        let keys = r
            .box_fetch_keys(FETCH_CONTEXT, &domain, e, ldn, 0, &box0)
            .unwrap();
        let (_, addr, k) = keys.iter().find(|(i, _, _)| *i == j).copied().unwrap();
        assert_eq!(addr, r.homes[1].seq[1].repl_addr);
        assert_eq!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, j, 0, &seq_req),
            Some(k)
        );
        // A `vyrn-seq` box as the target (SEQ_TARGET + j) agrees with voter 2.
        let seq_box = [0x77; 32];
        r.homes[1].seq[0].xchg_key = vyrn_crypto::x25519::public_key(&seq_box).to_vec();
        let keys = r
            .box_fetch_keys(FETCH_CONTEXT, &domain, e, ldn, SEQ_TARGET, &seq_box)
            .unwrap();
        let (_, _, k) = keys.iter().find(|(i, _, _)| *i == 2).copied().unwrap();
        assert_eq!(
            r.requester_fetch_key(FETCH_CONTEXT, &domain, e, ldn, 2, SEQ_TARGET, &req_secret),
            Some(k)
        );
        assert!(r.fetch_target(ldn, SEQ_TARGET + 9).is_none());
    }

    #[test]
    fn the_roster_builds_the_membership_that_hands_off() {
        for mode in [Mode::Base, Mode::Chain] {
            let domain = testkit::domain(mode);
            let roster = testkit::roster(mode, 0);
            let cfg = testkit::config(&domain, &roster);
            let table = testkit::bridge_table(&roster);
            let (next, decoded) =
                Membership::from_roster(&cfg, &roster.encode(), &domain, table.as_ref())
                    .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(decoded, roster);
            let want = testkit::next(mode);
            for i in 0..u8::try_from(mode.n()).unwrap_or(0) {
                assert_eq!(next.committee().voter(i), want.committee().voter(i));
            }
            for i in 0..u8::try_from(mode.n()).unwrap_or(0) {
                assert_eq!(next.node_key(i), want.node_key(i));
            }
            // The boxes are the ones seq_order names, with the roster's keys.
            let ldn = roster.home(HomeCode::Ldn);
            let n = u8::try_from(mode.n()).unwrap_or(0);
            for b in next.seq() {
                let e = &ldn.seq[usize::from(b.index - n)];
                assert_eq!(
                    (&b.node_key[..], &b.seq_key[..], &b.xchg_key[..]),
                    (&e.node_key[..], &e.seq_key[..], &e.xchg_key[..])
                );
            }
            let want_order = match mode {
                Mode::Base => [n, n + 1],
                Mode::Chain => [n, n + 3],
            };
            assert_eq!(next.seq().map(|b| b.index), want_order);
            assert_eq!(next.seq()[0].node_key, want.seq()[0].node_key);
            assert_eq!(next.spares().len(), usize::from(testkit::n_seq(mode)) - 2);
            let cert = testkit::cert(&domain, &[0, 1, 2, 3][..mode.quorum()]);
            let a = testkit::old(mode)
                .hand_off(&next, &cert, &domain, &Local::matching(&cert.record))
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(a.seq_key, want.seq()[0].seq_key);
        }
    }

    #[test]
    fn a_chain_membership_needs_the_tables_bridge_set() {
        let domain = testkit::domain(Mode::Chain);
        let roster = testkit::roster(Mode::Chain, 0);
        let cfg = testkit::config(&domain, &roster);
        let bytes = roster.encode();
        let from = |t: Option<&BridgeSignerTable>| {
            Membership::from_roster(&cfg, &bytes, &domain, t).map(|_| ())
        };
        let table = testkit::bridge_table(&roster);
        assert_eq!(from(table.as_ref()), Ok(()));
        // No table, or a table whose rotation 0 has other keys: no membership.
        assert_eq!(from(None), Err(RosterErr::Bridge));
        let mut other = roster.bridge.unwrap_or_else(|| panic!("chain roster"));
        other.bridge_keys[4] = [0xEE; 20];
        let other = BridgeSignerTable::genesis(other).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(from(Some(&other)), Err(RosterErr::Bridge));
        // Rotation 1, scheduled for epoch 8 and not yet activated: the roster of epoch 8 is
        // accepted before the boundary, the same roster for epoch 7 is not, nor an unknown one.
        let mut later = roster.clone();
        let mut set1 = roster.bridge.unwrap_or_else(|| panic!("chain roster"));
        set1.rotation_no = 1;
        set1.guardian_keys[0] = [0xEF; 20];
        later.bridge = Some(set1);
        let mut pending = table.clone().unwrap_or_else(|| panic!("chain table"));
        pending
            .schedule(set1, Epoch(8))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(later.check_bridge(&pending, Epoch(8)), Ok(()));
        assert_eq!(
            later.check_bridge(&pending, Epoch(7)),
            Err(RosterErr::Bridge)
        );
        // The same answers once epoch 8 has activated the set.
        pending.activate(Epoch(8));
        assert_eq!(later.check_bridge(&pending, Epoch(8)), Ok(()));
        assert_eq!(
            later.check_bridge(&pending, Epoch(7)),
            Err(RosterErr::Bridge)
        );
        assert_eq!(later.check_bridge(&other, Epoch(8)), Err(RosterErr::Bridge));
    }

    #[test]
    fn the_schedule_names_the_seq_order() {
        let base = testkit::roster(Mode::Base, 0);
        assert_eq!(base.seq_order(HomeCode::Nyc, None), Some([4, 5]));
        let chain = testkit::roster(Mode::Chain, 0);
        // Operator 2's F1 box (position 4) and operator 4's F2 box (position 9).
        assert_eq!(chain.seq_order(HomeCode::Tyo, Some((2, 4))), Some([9, 14]));
        assert_eq!(chain.seq_order(HomeCode::Tyo, Some((3, 3))), None);
        assert_eq!(chain.seq_order(HomeCode::Tyo, Some((0, 5))), None);
        // from_roster refuses a same-operator standby and an F2 box as primary.
        let domain = testkit::domain(Mode::Chain);
        let table = testkit::bridge_table(&chain);
        let mut cfg = testkit::config(&domain, &chain);
        for bad in [[5, 6], [6, 8], [5, 7]] {
            cfg.seq_order = bad;
            assert_eq!(
                Membership::from_roster(&cfg, &chain.encode(), &domain, table.as_ref()).err(),
                Some(RosterErr::SeqOrder(bad))
            );
        }
    }

    #[test]
    fn chain_operator_boxes_share_sk_and_split_facilities() {
        let domain = testkit::domain(Mode::Chain);
        let roster = testkit::roster(Mode::Chain, 0);
        let ldn = roster.home(HomeCode::Ldn);
        assert_eq!(ldn.seq[0].seq_key, ldn.seq[1].seq_key);
        assert!(Roster::decode(Mode::Chain, &roster.encode()).is_ok());
        // Different SK within one operator's pair.
        let mut r = roster.clone();
        r.homes[1].seq[1].seq_key = r.homes[1].seq[2].seq_key.clone();
        assert_eq!(
            Roster::decode(Mode::Chain, &r.encode()),
            Err(RosterErr::OperatorBoxes(2))
        );
        // Both boxes of operator 1 in F1: decode refuses, so no same-facility standby is chosen.
        let mut r = roster.clone();
        r.homes[1].seq[3].facility = 1;
        assert_eq!(
            Roster::decode(Mode::Chain, &r.encode()),
            Err(RosterErr::OperatorBoxes(2))
        );
        // A primary and a standby in one facility (positions valid) are refused by R8.
        let mut r = roster.clone();
        r.homes[1].seq[0].facility = 2;
        r.homes[1].seq[1].facility = 1;
        let mut cfg = testkit::config(&domain, &r);
        cfg.roster_hash = r.hash(&domain);
        let table = testkit::bridge_table(&r);
        assert_eq!(
            Membership::from_roster(&cfg, &r.encode(), &domain, table.as_ref()).err(),
            Some(RosterErr::SeqOrder(cfg.seq_order))
        );
    }
}
