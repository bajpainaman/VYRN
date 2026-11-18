//! Fixtures shared by the unit and conformance tests.
//!
//! Epoch 7 in TYO hands to epoch 8 in LDN. Voter i of `R_7` has Ed25519 seed `[i + 1; 32]`, voter
//! i of `R_8` has `[0x41 + i; 32]`. The `vyrn-seq` boxes have roster indices 5 (F1) and 6 (F2);
//! TYO's have seeds `[0x80 + j; 32]` and LDN's `[0x90 + j; 32]`.

use crate::Domain;
use crate::handoff::{HandoffCert, LocalView, sign_record};
use crate::membership::{Membership, SeqBox};
use crate::ready::EpoReady;
use vyrn_types::{
    BookId, Epoch, HandoffRecord, Hash, Height, HomeCode, Mode, Nanos, PubKey, StepId,
};

pub const VERSION: u32 = 3;

pub fn seed(i: u8) -> [u8; 32] {
    [i + 1; 32]
}

pub fn next_seed(i: u8) -> [u8; 32] {
    [0x41 + i; 32]
}

pub fn seq_seed(j: u8) -> [u8; 32] {
    [0x90 + j; 32]
}

fn pk(seed: [u8; 32]) -> PubKey {
    vyrn_crypto::ed25519::public_key(&seed)
}

fn n(mode: Mode) -> u8 {
    u8::try_from(mode.n()).unwrap_or(0)
}

pub fn domain(mode: Mode) -> Domain {
    Domain {
        genesis_hash: Hash([0x6E; 32]),
        mode,
    }
}

fn boxes(base: u8) -> [SeqBox; 2] {
    [0u8, 1].map(|j| SeqBox {
        index: 5 + j,
        seq_key: pk([base + j; 32]),
        xchg_key: pk([base + 8 + j; 32]),
    })
}

pub fn old(mode: Mode) -> Membership {
    let voters = (0..n(mode)).map(|i| pk(seed(i))).collect();
    Membership::new(Epoch(7), HomeCode::Tyo, mode, voters, boxes(0x80))
        .unwrap_or_else(|e| panic!("{e}"))
}

pub fn next_voters(mode: Mode) -> Vec<PubKey> {
    (0..n(mode)).map(|i| pk(next_seed(i))).collect()
}

pub fn next(mode: Mode) -> Membership {
    Membership::new(
        Epoch(8),
        HomeCode::Ldn,
        mode,
        next_voters(mode),
        boxes(0x90),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

pub fn record() -> HandoffRecord {
    HandoffRecord {
        book: BookId(1),
        epoch: Epoch(7),
        last_step: StepId(9_001),
        last_height: Height(4_242),
        state_root: Hash([0xA5; 32]),
        log_hash: Hash([0x5C; 32]),
        next_home: HomeCode::Ldn,
        next_seq_key: pk(seq_seed(0)),
    }
}

/// [`record`] signed by the old voters in `signers`, in that order.
pub fn cert(domain: &Domain, signers: &[u8]) -> HandoffCert {
    let r = record();
    HandoffCert {
        record: r,
        sigs: signers
            .iter()
            .map(|&i| (i, sign_record(&seed(i), i, domain, &r).sig))
            .collect(),
    }
}

/// A valid `EpoReady` from `member` of `R_8` (or `SEQ_MEMBER | 5`, `| 6`).
pub fn ready(member: u8, sent: Nanos, domain: &Domain) -> EpoReady {
    let is_seq = member & crate::SEQ_MEMBER != 0;
    let r = EpoReady {
        epoch: Epoch(8),
        member,
        follow_height: Height(4_000),
        lag_ns: 200_000,
        keys_ready: is_seq,
        version: VERSION,
        b4_pass: true,
        sent,
        sig: [0; 64],
    };
    let seed = if is_seq {
        seq_seed((member & !crate::SEQ_MEMBER) - 5)
    } else {
        next_seed(member)
    };
    r.signed(&seed, domain)
}

/// A node's own replay, as a plain struct.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    pub book: BookId,
    pub next_home: HomeCode,
    pub go: Option<(Epoch, PubKey)>,
    pub height: Height,
    pub head: Option<Hash>,
    pub step: StepId,
    pub root: Option<Hash>,
}

impl Local {
    pub fn matching(r: &HandoffRecord) -> Self {
        Self {
            book: r.book,
            next_home: r.next_home,
            go: Some((Epoch(r.epoch.0 + 1), r.next_seq_key)),
            height: r.last_height,
            head: Some(r.log_hash),
            step: r.last_step,
            root: Some(r.state_root),
        }
    }
}

impl LocalView for Local {
    fn book(&self) -> BookId {
        self.book
    }
    fn next_home(&self) -> HomeCode {
        self.next_home
    }
    fn go(&self) -> Option<(Epoch, PubKey)> {
        self.go
    }
    fn final_header_hash(&self, height: Height) -> Option<Hash> {
        (height == self.height).then_some(self.head).flatten()
    }
    fn state_root(&self, s: StepId) -> Option<Hash> {
        (s == self.step).then_some(self.root).flatten()
    }
}

/// A roster whose LDN home holds [`next`]'s voters (in BASE, sequencer boxes at roster indices
/// n and n + 1 with [`next`]'s keys). Other homes and NK use distinct seeds; `scheme` 1 pads each
/// Ed25519 key with a fake ML-DSA-44 part of 1,312 bytes `0xC0 + i` and each X25519 key with a
/// fake ML-KEM-768 part of 1,184 bytes `0xE0 + i`.
pub fn roster(mode: Mode, scheme: u8) -> crate::Roster {
    use crate::{Addr, DataBox, Home, Roster, SeqEntry, Voter};
    let key = |seed: [u8; 32], i: u8| {
        let mut k = pk(seed).to_vec();
        if scheme == 1 {
            k.extend_from_slice(&[0xC0 + i; 1_312]);
        }
        k
    };
    // Scheme 1: X25519 ‖ a fake ML-KEM-768 part of 1,184 bytes `0xE0 + i`.
    let kex = |seed: [u8; 32], i: u8| {
        let mut k = pk(seed).to_vec();
        if scheme == 1 {
            k.extend_from_slice(&[0xE0 + i; 1_184]);
        }
        k
    };
    let addr = |h: u8, i: u8, port: u16| Addr {
        ip: [0x20, 0x01, 0x0d, 0xb8, h, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        port,
    };
    let home = |h: u8, voter_seed: fn(u8) -> [u8; 32], seq_base: u8| {
        let n = n(mode);
        let n_seq = n_seq(mode);
        Home {
            voters: (0..n)
                .map(|i| Voter {
                    // R1 Rust, R2 Vx, R3 Rust, ...: 07 §2.1, 09 §2.1 (3 Rust + 2 Vx).
                    client: i % 2,
                    facility: i + 1,
                    node_key: key([0x10 + 0x08 * h + i; 32], i),
                    vote_key: key(voter_seed(i), i),
                    xchg_key: kex(gxk_seed(h, i), i),
                    data_addr: addr(h, i, 7_000),
                    repl_addr: addr(h, i, 7_001),
                })
                .collect(),
            seq: (0..n_seq)
                .map(|j| SeqEntry {
                    facility: j + 1,
                    node_key: key([0xD0 + 0x08 * h + j; 32], j),
                    seq_key: key([seq_base + j; 32], j),
                    xchg_key: kex([seq_base + 8 + j; 32], j),
                    client_addr: addr(h, 0x40 + j, 9_000),
                    repl_addr: addr(h, 0x40 + j, 9_001),
                })
                .collect(),
            recovery: 0,
            data: (0..n)
                .map(|i| DataBox {
                    facility: i + 1,
                    addr: addr(h, 0x80 + i, 8_000),
                })
                .collect(),
        }
    };
    Roster {
        sig_scheme: scheme,
        epoch_from: Epoch(6),
        homes: [
            home(1, seed, 0x80),
            home(2, next_seed, 0x90),
            home(3, |i| [0x61 + i; 32], 0xA0),
        ],
        bridge: match mode {
            Mode::Base => None,
            Mode::Chain => Some(crate::BridgeSigners {
                rotation_no: 0,
                bridge_keys: core::array::from_fn(|i| [0xB0 + i as u8; 20]),
                guardian_keys: core::array::from_fn(|i| [0xB8 + i as u8; 20]),
            }),
        },
    }
}

/// `vyrn-seq` boxes per home in [`roster`]: 2 in BASE, one per operator in CHAIN.
pub fn n_seq(mode: Mode) -> u8 {
    match mode {
        Mode::Base => 2,
        Mode::Chain => n(mode),
    }
}

/// `EpoConfig(8)` for LDN naming `roster`, primary and standby at roster indices n and n + 1.
pub fn config(domain: &Domain, roster: &crate::Roster) -> crate::EpoConfig {
    let n = n(domain.mode);
    crate::EpoConfig {
        epoch: Epoch(8),
        home: HomeCode::Ldn,
        t_start: Nanos(0),
        roster_hash: roster.hash(domain),
        seq_order: [n, n + 1],
        lane_map_hash: Hash([2; 32]),
        n_lanes: [49, 49, 11],
        version: VERSION,
        endpoint_hash: Hash([3; 32]),
        flags: 0,
        sig_scheme: roster.sig_scheme,
    }
}

/// The GXK seed of voter i of home h (1 TYO, 2 LDN, 3 NYC): `[h, i, 0xC7, 0xC7, …]`.
pub fn gxk_seed(h: u8, i: u8) -> [u8; 32] {
    let mut s = [0xC7; 32];
    s[0] = h;
    s[1] = i;
    s
}

/// CHAIN: the signer table whose genesis set is `roster`'s bridge set; BASE: none.
pub fn bridge_table(roster: &crate::Roster) -> Option<crate::BridgeSignerTable> {
    roster
        .bridge
        .map(|set| crate::BridgeSignerTable::genesis(set).unwrap_or_else(|e| panic!("{e}")))
}
