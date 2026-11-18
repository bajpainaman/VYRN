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
