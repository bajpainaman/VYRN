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
use crate::tail::{SealExt, seal_digest, seal_header, seal_proposal};
use std::fmt::Write as _;
use vyrn_log::block::{encode_header, header_hash, sign_header};
use vyrn_types::{BlockHeader, BookId, Epoch, Hash, Height, Mode, SessionId, StepId};

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
        Err(CertErr::Seal) => "seal",
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
        "# vyrn-consensus conformance vectors (spec/07-replication.md §3.10, §6.3, §6.5, §9.4).\n\
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

    // The seal of the tenure deposed after `h` (07 §9.4): heights 101..=102, the signed header
    // and the seal header, with one unavailable packet.
    let sh = seal_header(&h, StepId(515), Hash([0x44; 32]), Hash([0x55; 32]));
    let seal = seal_proposal(Epoch(7), Height(101), &sh, Hash([0x66; 32])).unwrap();
    let ext = SealExt {
        end_frame_seq: [900, 901],
        next_seq: 1,
        next_tenure: 1,
        unavail: vec![(SessionId(0x0102_0304), 77)],
    };
    let _ = writeln!(out, "\ncase = seal");
    let _ = writeln!(out, "seal_header = {}", hex(&encode_header(&sh)));
    let _ = writeln!(out, "proposal = {}", hex(&seal.encode()));
    let _ = writeln!(out, "seal_ext = {}", hex(&ext.encode()));
    let _ = writeln!(out, "digest = {}", hex(&seal_digest(&seal, &ext).0));

    let sign_any = |mode: Mode, signers: &[u8], view: u64, proposal, seal: Option<SealExt>| {
        let mut c = FinalityCert {
            epoch: Epoch(7),
            view,
            parent_view: view - 1,
            proposal,
            sigs: Vec::new(),
            seal,
        };
        let msg = c.message();
        c.sigs = signers
            .iter()
            .map(|&i| (i, vyrn_crypto::ed25519::sign(&seed(i), &msg)))
            .collect();
        (mode, c)
    };
    let sign = |mode, signers: &[u8], view| sign_any(mode, signers, view, proposal, None);
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
    // A seal certificate: its REP_SealExt follows the entries, and the signers signed the seal
    // digest (07 §6.5, §9.4).
    cases.push((
        "base_seal_quorum",
        sign_any(Mode::Base, &[1, 2, 3], 44, seal, Some(ext.clone())),
    ));
    // The same signers over a REP_SealExt with another next_seq: the bytes they signed differ.
    let (m, mut other_ext) = sign_any(Mode::Base, &[1, 2, 3], 44, seal, Some(ext.clone()));
    other_ext.seal = Some(SealExt {
        next_seq: 2,
        ..ext.clone()
    });
    cases.push(("base_seal_other_ext", (m, other_ext)));
    // Signatures over the bare proposal digest, as a kind-0 certificate would carry: refused.
    let (m, mut plain) = sign_any(Mode::Base, &[1, 2, 3], 44, seal, None);
    plain.seal = Some(ext.clone());
    cases.push(("base_seal_signed_without_ext", (m, plain)));

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
        ("base_seal_quorum", "ok"),
        ("base_seal_other_ext", "bad_sig"),
        ("base_seal_signed_without_ext", "bad_sig"),
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
