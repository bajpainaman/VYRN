//! `vyrn-seq`'s finality listener (07 §6.8) as another implementation sees it: start the box with
//! `[consensus]`, read `CONSENSUS ctrl=<ip:port>`, send `REP_FinalizeVote` datagrams to it, and
//! expect `FINAL height=<h>` once `Q` distinct voters' valid votes agree. A vote with a bad
//! signature is refused and changes nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};

use vyrn_consensus::cert::finalize_message;
use vyrn_consensus::{FinalizeVote, Proposal, ProposalKind, ctrl};
use vyrn_types::{Epoch, Hash, Height, Mode};

const SEED: [u8; 32] = [0x42; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A BASE roster (08 §9.6) of one home, used for all three: voters `vote_keys` (node key = vote
/// key, DEV) at `127.0.0.1:repl[i]`, clients Rust, Vx, Rust, Vx; `vyrn-seq` boxes `seq_keys` in
/// F1 and F2. Returns the hex file text and `roster_hash` under genesis `[0; 32]`.
fn roster(vote_keys: &[[u8; 32]], repl: &[u16], seq_keys: [[u8; 32]; 2]) -> (String, String) {
    use vyrn_epoch::{Addr, Domain, Home, Roster, SeqEntry, Voter};
    let addr = |port: u16| {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&[127, 0, 0, 1]);
        Addr { ip, port }
    };
    let home = Home {
        voters: (0..vote_keys.len())
            .map(|i| Voter {
                client: u8::try_from(i % 2).unwrap(),
                facility: u8::try_from(i + 1).unwrap(),
                node_key: vote_keys[i].to_vec(),
                vote_key: vote_keys[i].to_vec(),
                xchg_key: vec![0x55; 32],
                data_addr: addr(0),
                repl_addr: addr(repl[i]),
            })
            .collect(),
        seq: (0..2)
            .map(|j| SeqEntry {
                facility: u8::try_from(j + 1).unwrap(),
                node_key: seq_keys[j].to_vec(),
                seq_key: seq_keys[j].to_vec(),
                xchg_key: vec![0x66; 32],
                client_addr: addr(0),
                repl_addr: addr(0),
            })
            .collect(),
        recovery: 0,
        data: Vec::new(),
    };
    let r = Roster {
        sig_scheme: 0,
        epoch_from: Epoch(0),
        homes: [home.clone(), home.clone(), home],
        bridge: None,
    };
    let domain = Domain {
        genesis_hash: Hash([0; 32]),
        mode: Mode::Base,
    };
    (hex(&r.encode()), hex(&r.hash(&domain).0))
}

fn vote_seed(i: u8) -> [u8; 32] {
    [i + 1; 32]
}

#[test]
fn quorum_of_votes_on_ctrl_moves_final_height() {
    let dir = std::env::temp_dir().join(format!("vyrn-seq-fin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let keys: Vec<[u8; 32]> = (0..4)
        .map(|i| vyrn_crypto::ed25519::public_key(&vote_seed(i)))
        .collect();
    let seq_key = vyrn_crypto::ed25519::public_key(&SEED);
    let (roster_hex, roster_hash) = roster(&keys, &[1, 2, 3, 4], [seq_key, [0x77; 32]]);
    let roster_file = dir.join("roster.hex");
    std::fs::write(&roster_file, roster_hex).unwrap();
    let cfg = dir.join("seq.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"schema = 1
protocol = 1
role = "seq"
mode = "BASE"
home = "LDN"
book = 7

[engine]
dedicated = 2
tick_min = 1
tick_max = 512
win_center = 100

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
port_base = 0

[replication]
order = ["{}"]
block_ms = 5

[keys]
seq = "env:VYRN_FIN_SEQ_SEED"

[consensus]
ctrl = "127.0.0.1:0"
roster = "{}"
roster_hash = "{roster_hash}"
genesis_hash = "{}"
"#,
            replica.local_addr().unwrap(),
            roster_file.display(),
            hex(&[0; 32])
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vyrn-seq"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_FIN_SEQ_SEED", hex(&SEED))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(Result::unwrap);
    let ctrl_addr: SocketAddr = lines
        .by_ref()
        .find_map(|l| {
            l.strip_prefix("CONSENSUS ctrl=")
                .map(|r| r.split(' ').next().unwrap().parse().unwrap())
        })
        .expect("no CONSENSUS line");
    lines.by_ref().find(|l| l.starts_with("READY")).unwrap();

    let proposal = Proposal {
        kind: ProposalKind::Headers,
        epoch: Epoch(0),
        first_height: Height(1),
        last_height: Height(3),
        last_hash: Hash([7; 32]),
        excl_root: Hash([0; 32]),
    };
    let msg = finalize_message(Epoch(0), 1, 0, &proposal, None);
    let vote = |index: u8, sig| FinalizeVote {
        epoch: Epoch(0),
        view: 1,
        parent_view: 0,
        proposal,
        index,
        sig,
        seal: None,
    };
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    // A forged vote from voter 3, then valid votes from voters 0, 1 and 2 (Q = 3 in BASE).
    s.send_to(&ctrl::encode_vote(&vote(3, [0; 64])), ctrl_addr)
        .unwrap();
    for i in 0..3 {
        let sig = vyrn_crypto::ed25519::sign(&vote_seed(i), &msg);
        s.send_to(&ctrl::encode_vote(&vote(i, sig)), ctrl_addr)
            .unwrap();
    }
    let fin = lines
        .by_ref()
        .find(|l| l.starts_with("FINAL "))
        .expect("no FINAL line");
    assert_eq!(fin, "FINAL height=3 view=1 from=votes");
    drop(child.stdin.take());
    let f = lines.find(|l| l.starts_with("FINALITY")).unwrap();
    assert_eq!(f, "FINALITY votes=4 refused=1 final=3");
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}
