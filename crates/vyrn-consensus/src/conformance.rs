//! Conformance vectors for the consensus boundary (`vectors/finality_cert.txt`).
//!
//! The file is plain `key = hex` lines, one blank line between cases, so a verifier written in
//! any language (a Vx client through FFI, an auditor's script) can run it without this crate:
//! derive each voter's Ed25519 key from its seed, check `digest`, `header_hash` and `message`
//! against the bytes given, then check `cert` against `verdict`. The test below rebuilds every
//! case from first principles and fails if the file differs; `VYRN_BLESS=1` rewrites it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::Committee;
use crate::cert::{CertErr, FinalityCert, verify_finality_cert};
use crate::proposal::{Proposal, ProposalKind};
use std::fmt::Write as _;
use vyrn_log::block::{encode_header, header_hash, sign_header};
use vyrn_types::{BlockHeader, BookId, Epoch, Hash, Height, Mode, StepId};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/finality_cert.txt");

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn seed(i: u8) -> [u8; 32] {
    [i + 1; 32]
}

fn committee(mode: Mode) -> Committee {
    let n = u8::try_from(mode.n()).unwrap();
    let voters = (0..n)
        .map(|i| vyrn_crypto::ed25519::public_key(&seed(i)))
        .collect();
    Committee::new(mode, voters, &[]).unwrap()
}

fn verdict(r: Result<(), CertErr>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(CertErr::TooFew { .. }) => "too_few",
        Err(CertErr::Order) => "order",
        Err(CertErr::Unknown(_)) => "unknown_voter",
        Err(CertErr::BadSig(_)) => "bad_sig",
        Err(CertErr::Epoch) => "epoch",
        Err(CertErr::Proposal(_)) => "proposal",
        Err(CertErr::Length) => "length",
    }
}

fn generate() -> String {
    let seq_seed = [0x99u8; 32];
    let h = BlockHeader {
        height: Height(101),
        epoch: Epoch(7),
        book: BookId(1),
        first_step: StepId(500),
        last_step: StepId(512),
        prev: Hash([0x11; 32]),
        order_root: Hash([0x22; 32]),
        data_root: Hash([0x33; 32]),
        seq_sig: [0; 64],
    };
    let h = sign_header(&h, &seq_seed);
    let proposal = Proposal {
        kind: ProposalKind::Headers,
        epoch: Epoch(7),
        first_height: Height(101),
        last_height: Height(101),
        last_hash: header_hash(&h),
        excl_root: Hash([0; 32]),
    };

    let mut out = String::from(
        "# vyrn-consensus conformance vectors (spec/07-replication.md §3.10, §6.3, §6.5).\n\
         # Voter i (0-based) has Ed25519 seed [i+1; 32]; the sequencer has seed [0x99; 32].\n\
         # Every line is `key = value`; hex is lowercase, no prefix.\n\n",
    );
    let _ = writeln!(out, "case = header");
    let _ = writeln!(out, "seq_seed = {}", hex(&seq_seed));
    let _ = writeln!(out, "header = {}", hex(&encode_header(&h)));
    let _ = writeln!(out, "header_hash = {}", hex(&header_hash(&h).0));
    let _ = writeln!(out, "\ncase = proposal");
    let _ = writeln!(out, "proposal = {}", hex(&proposal.encode()));
    let _ = writeln!(out, "digest = {}", hex(&proposal.digest().0));

    let sign = |mode: Mode, signers: &[u8], view: u64| {
        let mut c = FinalityCert {
            epoch: Epoch(7),
            view,
            parent_view: view - 1,
            proposal,
            sigs: Vec::new(),
        };
        let msg = c.message();
        c.sigs = signers
            .iter()
            .map(|&i| (i, vyrn_crypto::ed25519::sign(&seed(i), &msg)))
            .collect();
        (mode, c)
    };
    let mut cases = vec![
        ("base_quorum", sign(Mode::Base, &[0, 1, 3], 42)),
        ("chain_quorum", sign(Mode::Chain, &[0, 1, 2, 4], 42)),
        ("base_below_quorum", sign(Mode::Base, &[0, 2], 42)),
        ("chain_with_base_quorum", sign(Mode::Chain, &[0, 1, 2], 42)),
        ("base_unknown_voter", sign(Mode::Base, &[0, 1, 4], 42)),
    ];
    let (m, mut dup) = sign(Mode::Base, &[0, 1, 2], 42);
    dup.sigs[2] = dup.sigs[1];
    cases.push(("base_repeated_voter", (m, dup)));
    let (m, mut wrong_view) = sign(Mode::Base, &[0, 1, 2], 42);
    wrong_view.view = 43;
    cases.push(("base_signed_other_view", (m, wrong_view)));

    for (name, (mode, c)) in cases {
        let _ = writeln!(out, "\ncase = {name}");
        let _ = writeln!(
            out,
            "mode = {}",
            if mode == Mode::Base { "base" } else { "chain" }
        );
        let _ = writeln!(out, "message = {}", hex(&c.message()));
        let _ = writeln!(out, "cert = {}", hex(&c.encode()));
        let _ = writeln!(
            out,
            "verdict = {}",
            verdict(verify_finality_cert(&c, &committee(mode)))
        );
    }
    out
}

#[test]
fn vectors_match_the_file() {
    let fresh = generate();
    if std::env::var_os("VYRN_BLESS").is_some() {
        std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors")).unwrap();
        std::fs::write(PATH, &fresh).unwrap();
    }
    let on_disk = std::fs::read_to_string(PATH).expect("run once with VYRN_BLESS=1");
    assert_eq!(on_disk, fresh, "vectors/finality_cert.txt is stale");
}

#[test]
fn file_verdicts_are_the_spec_verdicts() {
    // Independent of the generator: the expected verdict of each case follows from 07 §6.5.
    let expected = [
        ("base_quorum", "ok"),
        ("chain_quorum", "ok"),
        ("base_below_quorum", "too_few"),
        ("chain_with_base_quorum", "too_few"),
        ("base_unknown_voter", "unknown_voter"),
        ("base_repeated_voter", "order"),
        ("base_signed_other_view", "bad_sig"),
    ];
    let text = generate();
    for (name, want) in expected {
        let block = text
            .split("\n\n")
            .find(|b| b.contains(&format!("case = {name}\n")))
            .unwrap();
        assert!(block.contains(&format!("verdict = {want}")), "{name}");
    }
}
