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
//! on a Vx voter, a `seq_order` that is not two boxes in different facilities).

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataBox {
    pub facility: u8,
    pub addr: Addr,
}

/// The nodes of one home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Home {
    /// `n` voters, `N_BASE` or `N_CHAIN`.
    pub voters: Vec<Voter>,
    /// At least 2; CHAIN: one per operator, box j is operator j's.
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
    #[error("home {0}: wrong number of vyrn-seq boxes")]
    SeqCount(u8),
    #[error("the bridge section is malformed or missing")]
    Bridge,
    #[error("seq_order {0:?} is not two vyrn-seq boxes in different facilities (BASE: F1, F2)")]
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
            let keys: Vec<&[u8]> = home
                .voters
                .iter()
                .map(|v| v.vote_key.as_slice())
                .chain(home.seq.iter().map(|s| s.seq_key.as_slice()))
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
                Mode::Chain => home.seq.len() == mode.n(),
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

    /// The nodes of `home`.
    pub fn home(&self, home: HomeCode) -> &Home {
        let i = HOMES.iter().position(|h| *h == home).unwrap_or(0);
        &self.homes[i]
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
        let facilities_ok = match domain.mode {
            Mode::Base => primary.facility == 1 && standby.facility == 2,
            Mode::Chain => primary.facility != standby.facility,
        };
        if p == s || !facilities_ok {
            return Err(RosterErr::SeqOrder(cfg.seq_order));
        }
        let ed = |k: &[u8]| -> Result<PubKey, RosterErr> {
            k.try_into()
                .map_err(|_| RosterErr::Unsupported(roster.sig_scheme))
        };
        let seq_box = |index: u8, e: &SeqEntry| -> Result<SeqBox, RosterErr> {
            Ok(SeqBox {
                index,
                seq_key: ed(&e.seq_key)?,
                xchg_key: ed(&e.xchg_key)?,
            })
        };
        let voters = home
            .voters
            .iter()
            .map(|v| ed(&v.vote_key))
            .collect::<Result<_, _>>()?;
        let seq = [seq_box(p, primary)?, seq_box(s, standby)?];
        let spares = (n..n + home.seq.len())
            .filter_map(|i| u8::try_from(i).ok())
            .filter(|i| *i != p && *i != s)
            .map(|i| at(i).map_or(Err(RosterErr::SeqOrder(cfg.seq_order)), |e| seq_box(i, e)))
            .collect::<Result<_, _>>()?;
        let m = Membership::new(cfg.epoch, cfg.home, domain.mode, voters, seq)?.with_spares(spares);
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
            let keys = |m: &Membership| m.seq().map(|b| (b.seq_key, b.xchg_key));
            assert_eq!(keys(&next), keys(&want));
            let n = u8::try_from(mode.n()).unwrap_or(0);
            assert_eq!(next.seq().map(|b| b.index), [n, n + 1]);
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
}
