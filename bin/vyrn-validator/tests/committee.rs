//! Four `vyrn-validator` boxes finalize blocks over their Simplex network (07 §3.1, §6.3), and a
//! finality listener learns it from their `REP_FinalizeVote`s on `REP_UDP_CTRL` (07 §6.8), on
//! localhost. The test plays the sequencer: its stream core signs 40 blocks with
//! `vyrn_log::SeqWriter` and sends every frame to each validator's ORDER port, and its listener
//! (`vyrn_consensus::Listener`, as in `vyrn-seq`'s `finality.rs`) reads the CTRL datagrams. Every
//! certificate that arrives verifies offline. The committee comes from a roster file (08 §9.6).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddrV4, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use vyrn_consensus::ctrl::{self, Ctrl};
use vyrn_consensus::{Committee, Listener, verify_finality_cert};
use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_types::{
    BookId, Epoch, Hash, Height, LaneId, LaneSeq, Mode, Nanos, PacketRecord, SessionId, StepId,
    StepKind,
};

const SEQ_SEED: [u8; 32] = [0x42; 32];

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

fn vote_seed(i: usize) -> [u8; 32] {
    [u8::try_from(i + 1).unwrap(); 32]
}

fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A child with its stdout lines on a channel.
struct Box_ {
    child: Child,
    lines: Receiver<String>,
}

impl Box_ {
    fn spawn(bin: &str, cfg: &std::path::Path, env: (&str, String)) -> Self {
        let mut child = Command::new(bin)
            .arg("--config")
            .arg(cfg)
            .arg("--stop-on-stdin-eof")
            .env(env.0, env.1)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for l in out.lines().map_while(Result::ok) {
                if std::env::var_os("VYRN_ECHO").is_some() {
                    eprintln!("{l}");
                }
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// The first line starting with `prefix`, within `secs`.
    fn wait(&self, prefix: &str, secs: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) if l.starts_with(prefix) => return l,
                Ok(_) => {}
                Err(_) => panic!("no {prefix:?} line within {secs} s"),
            }
        }
    }

    fn stop(mut self) -> bool {
        drop(self.child.stdin.take());
        self.child.wait().unwrap().success()
    }
}

/// The frames of blocks `0..n`, one New and its Improve step each, signed with `SEQ_SEED`.
fn blocks(n: u32) -> Vec<Vec<Vec<u8>>> {
    let ts = TenureStart {
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
        first_step: StepId(1),
        first_height: Height(0),
        prev_header_hash: Hash([0; 32]),
        lanes: vec![
            LaneBase {
                next_lane_seq: LaneSeq(1),
                rx_ts: Nanos(0),
                fills_applied: StepId(0),
            };
            2
        ],
        prev_cut: vec![LaneSeq(0); 2],
    };
    let ident = Ident {
        book: BookId(7),
        epoch: Epoch(0),
        tenure: 0,
        sender: 0,
    };
    let mut w = SeqWriter::new(Layout::new(2, 1, 0).unwrap(), ident, ts, SEQ_SEED, 1472).unwrap();
    (1..=n)
        .map(|i| {
            let body = format!("request packet {i}");
            let p = PacketRecord {
                lane: LaneId(0),
                count: 1,
                flags: 0,
                session: SessionId(0x0010_0001),
                pkt_seq: i,
                rx_ts: Nanos(u64::from(i) * 1_000),
                pkt_hash: vyrn_crypto::pkt_hash(body.as_bytes()),
                first_lane_seq: LaneSeq(u64::from(i)),
                fills_applied: StepId(0),
            };
            let mut f = w
                .packet(p, Some(vyrn_crypto::hash::hash(body.as_bytes())))
                .unwrap();
            let cut = [LaneSeq(u64::from(i)), LaneSeq(0)];
            f.extend(
                w.step(
                    StepId(u64::from(i)),
                    StepKind::Improve,
                    Some((LaneId(0), LaneSeq(u64::from(i)))),
                    0,
                    Vec::new(),
                    &cut,
                )
                .unwrap(),
            );
            f.extend(w.close_block().unwrap().0);
            f
        })
        .collect()
}

#[test]
fn four_validators_finalize_and_the_listener_learns_it() {
    let dir = std::env::temp_dir().join(format!("vyrn-committee-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let seq_key = vyrn_crypto::ed25519::public_key(&SEQ_SEED);
    let keys: Vec<_> = (0..4)
        .map(|i| vyrn_crypto::ed25519::public_key(&vote_seed(i)))
        .collect();
    let repl: Vec<u16> = (0..4).map(|_| free_tcp()).collect();

    // The sequencer's CTRL port: this test runs the finality listener itself (07 §6.8).
    let ctrl_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    ctrl_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let ctrl = ctrl_sock.local_addr().unwrap();
    let committee = Committee::new(Mode::Base, keys.clone(), &[seq_key]).unwrap();
    let mut listener = Listener::new(committee.clone(), Epoch(0), Height(0));

    let (roster_hex, roster_hash) = roster(&keys, &repl, [seq_key, [0x77; 32]]);
    let roster_file = dir.join("roster.hex");
    std::fs::write(&roster_file, roster_hex).unwrap();
    let mut vals = Vec::new();
    let mut orders: Vec<SocketAddrV4> = Vec::new();
    for (i, port) in repl.iter().enumerate() {
        let cfg = dir.join(format!("validator-{i}.toml"));
        std::fs::write(
            &cfg,
            format!(
                r#"schema = 1
protocol = 1
role = "validator"
mode = "BASE"
book = 7
lanes = 2

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
order_port = 0

[membership]
seq_keys = ["{}"]

[keys]
vote = "env:VYRN_COMMITTEE_VOTE_SEED"

[consensus]
roster = "{}"
roster_hash = "{roster_hash}"
genesis_hash = "{}"
home = "LDN"
observers = ["{ctrl}"]
delta_ms = 500
storage = "{}"
"#,
                hex(&seq_key),
                roster_file.display(),
                hex(&[0; 32]),
                dir.join(format!("journal-{i}")).display()
            ),
        )
        .unwrap();
        let v = Box_::spawn(
            env!("CARGO_BIN_EXE_vyrn-validator"),
            &cfg,
            ("VYRN_COMMITTEE_VOTE_SEED", hex(&vote_seed(i))),
        );
        assert_eq!(
            v.wait("CONSENSUS", 30),
            format!("CONSENSUS voter={i} repl=127.0.0.1:{port}")
        );
        let a = v.wait("READY vyrn-validator order=", 30);
        orders.push(a.rsplit('=').next().unwrap().parse().unwrap());
        vals.push(v);
    }

    // 40 blocks to every validator in one burst, so each HASH frame is queued right behind its
    // packet: on a loaded 2-vCPU host a gap between them can pass REP_HASHLAG_MAX (1 ms).
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for a in &orders {
        for f in blocks(40).iter().flatten() {
            s.send_to(f, a).unwrap();
        }
    }
    // At least Q = 3 validators finalize (f = 1: on a loaded host one may suspect the stream,
    // e.g. REP_E_HASHLAG, and drop out), and the listener reaches a final height from votes.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut finalized = [false; 4];
    while finalized.iter().filter(|f| **f).count() < 3 {
        assert!(Instant::now() < deadline, "finalized: {finalized:?}");
        for (i, v) in vals.iter().enumerate() {
            while let Ok(l) = v.lines.recv_timeout(Duration::from_millis(3)) {
                finalized[i] |= l.starts_with("FINAL height=");
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut votes, mut certs) = (0, 0);
    let mut buf = [0u8; 9216];
    while listener.final_height() < Height(1) || certs == 0 {
        assert!(Instant::now() < deadline, "votes={votes} certs={certs}");
        let Ok(n) = ctrl_sock.recv(&mut buf) else {
            continue;
        };
        match ctrl::decode(&buf[..n]).unwrap() {
            Ctrl::Vote(v) => {
                votes += 1;
                let _ = listener.on_vote(&v);
            }
            Ctrl::Cert(c) => {
                certs += 1;
                assert_eq!(verify_finality_cert(&c, &committee), Ok(()));
            }
        }
    }
    for v in vals {
        assert!(v.stop());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
