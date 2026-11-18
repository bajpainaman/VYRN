//! Smoke test of the `vyrn-seq` box on the `kernel_udp` backend (11 §10.1 start sequence).
//!
//! The contract another implementation can run: start the box with `tests/dev.toml`'s shape,
//! wait for `READY`, send one signed `New` from a DEV session to lane 0, then
//!
//! 1. the client receives a response with an `Ack`, tagged with the session's `k_out`;
//! 2. a replica socket receives ORDER, HASH and HEADER frames that `vyrn-replica`'s order core
//!    accepts: block 0 is ready, carries the packet with its `pkt_hash`, and its verdict is `Valid`;
//! 3. on stdin EOF the box prints `STATS` with one TX packet sent and zero seal violations.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vyrn_consensus::Verdict;
use vyrn_log::{FrameHeader, FrameKind, LaneRec, Layout};
use vyrn_replica::{EpochView, OrderCore};
use vyrn_types::{BookId, Epoch, Height, LaneId, PubKey, Qty, Tick};
use vyrn_wire::{Msg, OrderFlags, ReqHeader, Response, encode_request};

const SEED: [u8; 32] = [0x42; 32];
const K_SEQ: [u8; 16] = [0x11; 16];
const K_OUT: [u8; 16] = [0x22; 16];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> BookId {
        BookId(7)
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _height: Height) -> bool {
        false
    }
}

#[test]
fn one_order_end_to_end() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let dir = std::env::temp_dir().join(format!("vyrn-seq-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
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

[cores]
engine = 2
stream = 4
seal = "count"

[replication]
order = ["{}"]
block_ms = 2

[keys]
seq = "env:VYRN_SMOKE_SEQ_SEED"

[[dev_session]]
lane = 0
slot = 1
account = 1
k_seq = "{}"
k_out = "{}"
quote = 1000000000000
base = 1000000000
"#,
            replica.local_addr().unwrap(),
            hex(&K_SEQ),
            hex(&K_OUT)
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_vyrn-seq"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_SMOKE_SEQ_SEED", hex(&SEED))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let lane0: SocketAddrV4 = loop {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "exited before READY");
        if let Some(rest) = line.trim().strip_prefix("READY vyrn-seq lanes=2 rx=") {
            break rest.split(',').next().unwrap().parse().unwrap();
        }
    };

    // One New from session (lane 0, slot 1, generation 1).
    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let hdr = ReqHeader::new(session, 1, Epoch(0).low16(), BookId(7), false);
    let flags = OrderFlags::from_byte(
        vyrn_bbo::OrderFlags::new(
            vyrn_bbo::Side::Buy,
            vyrn_bbo::Tif::Day,
            false,
            vyrn_bbo::Stp::None,
        )
        .0,
    )
    .unwrap();
    let msg = Msg::New {
        flags,
        tick: Tick(100),
        qty: Qty(5),
        client_tag: 77,
    };
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let n = encode_request(&mut buf, hdr, &[msg], &K_SEQ, None).unwrap();
    let pkt = &buf[..n];
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(pkt, lane0).unwrap();

    // 1. The response.
    let mut rbuf = [0u8; 2048];
    let (rn, _) = client.recv_from(&mut rbuf).expect("no response");
    let resp = Response::parse(&rbuf[..rn]).unwrap();
    assert!(resp.verify(&K_OUT), "response tag");
    assert_eq!(resp.header().session(), session);
    let recs: Vec<_> = resp.records().map(Result::unwrap).collect();
    assert!(
        recs.iter()
            .any(|r| matches!(r, vyrn_wire::Record::Ack { client_tag: 77, .. })),
        "no Ack in {recs:?}"
    );

    // 2. The order stream, through the replica's order core.
    let mut core: OrderCore<2, View> = OrderCore::new(
        Layout::new(2, 1, 0).unwrap(),
        View(vyrn_crypto::ed25519::public_key(&SEED)),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let block = loop {
        assert!(Instant::now() < deadline, "no ready block");
        let Ok(k) = replica.recv(&mut rbuf) else {
            continue;
        };
        let (h, _) = FrameHeader::parse(&rbuf[..k]).unwrap();
        core.on_frame(&rbuf[..k], 0).unwrap();
        if h.kind == FrameKind::Header
            && let Some(b) = core.take_ready()
        {
            break b;
        }
    };
    assert_eq!(block.header.height, Height(0));
    let signed = &pkt[..n - 2 * vyrn_types::TAG_BYTES];
    let ours = block.lanes.iter().any(|r| {
        matches!(r, LaneRec::Pkt(p) if p.session == session
            && p.pkt_seq == 1
            && p.pkt_hash == vyrn_crypto::pkt_hash(signed))
    });
    assert!(ours, "packet not in block 0: {:?}", block.lanes);
    assert!(!block.steps.is_empty(), "block 0 has no step");
    // The resting buy is an improve: its step names our op and its route bit (07 §3.8 src byte
    // bit 7, StepFlags::CROSS) is clear, end to end through the 07 wire.
    let ours = block
        .steps
        .iter()
        .find(|m| m.rec.src_lane == LaneId(0) && m.rec.src_lane_seq.0 == 1)
        .expect("no step names the order");
    assert_eq!(
        ours.rec.kind,
        vyrn_types::StepKind::Improve,
        "{:?}",
        ours.rec
    );
    assert_eq!(
        ours.rec.flags & vyrn_types::StepFlags::CROSS,
        0,
        "{:?}",
        ours.rec
    );
    assert_eq!(core.verdict(Height(0), Height(0)), Verdict::Valid);

    // 3. Clean stop.
    drop(child.stdin.take());
    let mut stats = String::new();
    for l in out.lines() {
        let l = l.unwrap();
        if l.starts_with("STATS") {
            stats = l;
        }
    }
    assert!(child.wait().unwrap().success());
    assert!(stats.contains(" tx=1 "), "{stats}");
    assert!(stats.contains("seal_violations=0"), "{stats}");
    let _ = std::fs::remove_dir_all(&dir);
}
