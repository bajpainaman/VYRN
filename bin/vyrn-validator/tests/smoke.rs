//! Smoke test of the `vyrn-validator` box on the `kernel_udp` backend.
//!
//! The contract another implementation can run: start the box, wait for `READY`, send it the
//! frames of one block that `vyrn_log::SeqWriter` (the sequencer's stream core) produces for one
//! order (a `New` and the `Improve` step it causes), and expect
//! `BLOCK height=0 ... lanes=1 steps=1 verdict=Valid`. A block whose header is signed by a key
//! outside `[membership]` must instead print `FAULT`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{BufRead, BufReader, Lines};
use std::net::{SocketAddrV4, UdpSocket};
use std::process::{Child, ChildStdout, Command, Stdio};

use vyrn_log::{Ident, LaneBase, Layout, SeqWriter, TenureStart};
use vyrn_types::{
    BookId, Epoch, Hash, Height, LaneId, LaneSeq, Nanos, PacketRecord, SessionId, StepId, StepKind,
};

const SEED: [u8; 32] = [0x42; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn start(tag: &str) -> (Child, Lines<BufReader<ChildStdout>>, SocketAddrV4) {
    let dir = std::env::temp_dir().join(format!("vyrn-val-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("validator.toml");
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

[cores]
order = 3

[membership]
seq_keys = ["{}"]

[keys]
vote = "hsm:slot=2:label=dev-vote"
"#,
            hex(&vyrn_crypto::ed25519::public_key(&SEED))
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vyrn-validator"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let addr = loop {
        let l = lines.next().expect("exited before READY").unwrap();
        if let Some(a) = l.strip_prefix("READY vyrn-validator order=") {
            break a.parse().unwrap();
        }
    };
    (child, lines, addr)
}

/// The frames of block 0 for one New on lane 0 and its Improve step, signed with `seed`.
fn block(seed: [u8; 32]) -> Vec<Vec<u8>> {
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
    let mut w = SeqWriter::new(Layout::new(2, 1, 0).unwrap(), ident, ts, seed, 1472).unwrap();
    let body = b"one request packet";
    let p = PacketRecord {
        lane: LaneId(0),
        count: 1,
        flags: 0,
        session: SessionId(0x0010_0001),
        pkt_seq: 1,
        rx_ts: Nanos(1_000),
        pkt_hash: vyrn_crypto::pkt_hash(body),
        first_lane_seq: LaneSeq(1),
        fills_applied: StepId(0),
        snap_lag: 0,
    };
    let mut frames = w.packet(p, Some(vyrn_crypto::hash::hash(body))).unwrap();
    let cut = [LaneSeq(1), LaneSeq(0)];
    frames.extend(
        w.step(
            StepId(1),
            StepKind::Improve,
            Some((LaneId(0), LaneSeq(1))),
            0,
            Vec::new(),
            &cut,
            0,
        )
        .unwrap(),
    );
    let (closed, h) = w.close_block().unwrap();
    assert_eq!(h.height, Height(0));
    frames.extend(closed);
    frames
}

fn send_and_read(
    addr: SocketAddrV4,
    frames: &[Vec<u8>],
    lines: &mut Lines<BufReader<ChildStdout>>,
    want: &str,
) -> String {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for f in frames {
        s.send_to(f, addr).unwrap();
    }
    loop {
        let l = lines.next().expect("exited early").unwrap();
        if l.starts_with(want) {
            return l;
        }
    }
}

#[test]
fn one_block_is_valid() {
    let (mut child, mut lines, addr) = start("ok");
    let l = send_and_read(addr, &block(SEED), &mut lines, "BLOCK");
    assert_eq!(
        l,
        "BLOCK height=0 first_step=1 last_step=1 lanes=1 steps=1 verdict=Valid"
    );
    drop(child.stdin.take());
    let stats = lines
        .map(Result::unwrap)
        .find(|l| l.starts_with("STATS"))
        .unwrap();
    assert_eq!(stats, "STATS frames=5 blocks=1 faults=0");
    assert!(child.wait().unwrap().success());
}

#[test]
fn foreign_signer_faults() {
    let (mut child, mut lines, addr) = start("bad");
    let l = send_and_read(addr, &block([0x43; 32]), &mut lines, "FAULT");
    assert!(l.contains("height=0"), "{l}");
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}
