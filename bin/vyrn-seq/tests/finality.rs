//! `vyrn-seq`'s finality listener (07 §6.8) as another implementation sees it: start the box with
//! `[consensus]`, read `CONSENSUS ctrl=<ip:port>`, send `REP_FinalizeVote` datagrams to it, and
//! expect `FINAL height=<h>` once `Q` distinct voters' valid votes agree. A vote with a bad
//! signature is refused and changes nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use vyrn_consensus::cert::finalize_message;
use vyrn_consensus::{FinalizeVote, Proposal, ProposalKind, ctrl};
use vyrn_types::{BookId, Epoch, Hash, Height, LaneId, Mode};
use vyrn_wire::{Msg, ReqHeader, encode_request};

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

/// 07 §6.8 enforced: with no votes, more than `FIN_GATE_BLOCKS` = 9 closed blocks ahead of
/// finality puts `HaltReq` on the control ring, and the engine logs a `Control` step; votes that
/// finalize the closed run resume the book with a second one. Heartbeats make the blocks and no
/// steps, so the box's two steps are exactly the gate's.
#[test]
fn gate_halts_and_resumes_the_book_with_control_steps() {
    const K_SEQ: [u8; 16] = [0x11; 16];
    let dir = std::env::temp_dir().join(format!("vyrn-seq-gate-{}", std::process::id()));
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
block_ms = 2

[keys]
seq = "env:VYRN_GATE_SEQ_SEED"

[[dev_session]]
lane = 0
slot = 1
account = 1
k_seq = "{}"
k_out = "{}"
quote = 1000000000000
base = 1000000000

[consensus]
ctrl = "127.0.0.1:0"
roster = "{}"
roster_hash = "{roster_hash}"
genesis_hash = "{}"
"#,
            replica.local_addr().unwrap(),
            hex(&K_SEQ),
            hex(&[0x22; 16]),
            roster_file.display(),
            hex(&[0; 32])
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vyrn-seq"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_GATE_SEQ_SEED", hex(&SEED))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines() {
            if tx.send(l.unwrap()).is_err() {
                break;
            }
        }
    });
    // Lines read but not yet asked for: the listener's `GATE` and the stream thread's
    // `CONTROL` lines may come in either order.
    let seen = std::cell::RefCell::new(Vec::<String>::new());
    let take = |want: &str, wait: Duration| -> Option<String> {
        let mut seen = seen.borrow_mut();
        if let Some(i) = seen.iter().position(|l| l.starts_with(want)) {
            return Some(seen.remove(i));
        }
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok(l) = rx.recv_timeout(Duration::from_millis(1)) {
                if l.starts_with(want) {
                    return Some(l);
                }
                seen.push(l);
            }
        }
        None
    };
    let next = |want: &str| {
        take(want, Duration::from_secs(20)).unwrap_or_else(|| panic!("no {want} line"))
    };
    let ctrl_addr: SocketAddr = next("CONSENSUS ctrl=")["CONSENSUS ctrl=".len()..]
        .parse()
        .unwrap();
    let lane0: SocketAddr = next("READY vyrn-seq lanes=2 rx=")
        ["READY vyrn-seq lanes=2 rx=".len()..]
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();

    // Heartbeats until the gate halts the book.
    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut pkt_seq = 0u32;
    let halt = loop {
        assert!(Instant::now() < deadline, "no GATE halt");
        pkt_seq += 1;
        let hdr = ReqHeader::new(session, pkt_seq, Epoch(0).low16(), BookId(7), false);
        let n = encode_request(&mut buf, hdr, &[Msg::Heartbeat], &K_SEQ, None).unwrap();
        client.send_to(&buf[..n], lane0).unwrap();
        if let Some(l) = take("GATE halt", Duration::from_millis(3)) {
            break l;
        }
    };
    // `GATE halt closed=<h> final=0`, at the first lag over 9.
    let closed: u64 = halt
        .strip_prefix("GATE halt closed=")
        .and_then(|r| r.split(' ').next())
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(halt, format!("GATE halt closed={closed} final=0"));
    // The listener checks every ~1 ms, so a loaded box may close a block or two more first.
    assert!(
        closed >= 10,
        "halts only past lag FIN_GATE_BLOCKS = 9: {halt}"
    );

    let halt_step = next("CONTROL ");
    assert!(halt_step.ends_with(" phase=halt"), "{halt_step}");

    // Finalize 1..=closed: lag 0 <= REP_GATE_RESUME_BLOCKS resumes.
    let proposal = Proposal {
        kind: ProposalKind::Headers,
        epoch: Epoch(0),
        first_height: Height(1),
        last_height: Height(closed),
        last_hash: Hash([7; 32]),
        excl_root: Hash([0; 32]),
    };
    let msg = finalize_message(Epoch(0), 1, 0, &proposal, None);
    for i in 0..3 {
        let v = FinalizeVote {
            epoch: Epoch(0),
            view: 1,
            parent_view: 0,
            proposal,
            index: i,
            sig: vyrn_crypto::ed25519::sign(&vote_seed(i), &msg),
            seal: None,
        };
        client.send_to(&ctrl::encode_vote(&v), ctrl_addr).unwrap();
    }
    let resume = next("GATE resume");
    // The halt's Control step itself may close one more block (lag 1, still <= 4).
    assert!(
        resume.contains(&format!(" final={closed} halted_ms=")) && !resume.contains("reopen="),
        "{resume}"
    );
    let resume_step = next("CONTROL ");
    assert!(resume_step.ends_with(" phase=resume"), "{resume_step}");
    drop(child.stdin.take());
    let stats = next("STATS");
    assert!(
        stats.contains(" steps=2 "),
        "one Control step each way: {stats}"
    );
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}
