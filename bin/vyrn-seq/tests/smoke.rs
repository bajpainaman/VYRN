//! Smoke test of the `vyrn-seq` box on the `kernel_udp` backend (11 §10.1 start sequence).
//!
//! The contract another implementation can run: start the box with `tests/dev.toml`'s shape,
//! wait for `READY`, send one signed `New` from a DEV session to lane 0, then
//!
//! 1. the client receives a response with an `Ack`, tagged with the session's `k_out`;
//! 2. a replica socket receives ORDER, HASH and HEADER frames that `vyrn-replica`'s order core
//!    accepts: block 0 is ready, carries the packet with its `pkt_hash` and, right after it, its
//!    op's `RouteRecord` (07 §3.6), and its verdict is `Valid`;
//! 3. on stdin EOF the box prints `STATS` with one TX packet sent and zero seal violations.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{BufRead, BufReader, Read as _};
use std::net::{SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
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

/// Writes a DEV config with `seal` and `block_ms`, starts the box and returns it with its
/// stdout (read past `READY`) and lane 0's address.
fn start(
    replica: &UdpSocket,
    seal: &str,
    block_ms: u64,
    tag: &str,
) -> (Child, BufReader<ChildStdout>, SocketAddrV4, PathBuf) {
    let (child, out, lane0, _, dir) = start_with(replica, seal, block_ms, tag, "");
    (child, out, lane0, dir)
}

/// [`start`] with `extra` appended to the config; also returns the `REPAIR` address, if any.
fn start_with(
    replica: &UdpSocket,
    seal: &str,
    block_ms: u64,
    tag: &str,
    extra: &str,
) -> (
    Child,
    BufReader<ChildStdout>,
    SocketAddrV4,
    Option<SocketAddrV4>,
    PathBuf,
) {
    let (mut child, dir) = spawn_with(replica, seal, block_ms, tag, extra);
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let mut repair = None;
    let lane0: SocketAddrV4 = loop {
        line.clear();
        assert!(out.read_line(&mut line).unwrap() > 0, "exited before READY");
        if let Some(rest) = line.trim().strip_prefix("REPAIR addr=") {
            repair = Some(rest.parse().unwrap());
        }
        if let Some(rest) = line.trim().strip_prefix("READY vyrn-seq lanes=2 rx=") {
            break rest.split(',').next().unwrap().parse().unwrap();
        }
    };
    (child, out, lane0, repair, dir)
}

/// Writes the DEV config and spawns the box with piped stdin and stdout.
fn spawn(replica: &UdpSocket, seal: &str, block_ms: u64, tag: &str) -> (Child, PathBuf) {
    spawn_with(replica, seal, block_ms, tag, "")
}

fn spawn_with(
    replica: &UdpSocket,
    seal: &str,
    block_ms: u64,
    tag: &str,
    extra: &str,
) -> (Child, PathBuf) {
    spawn_cores(
        replica,
        seal,
        block_ms,
        tag,
        extra,
        "engine = 2\nstream = 4",
        false,
    )
}

/// `spawn_with` with this `[cores]` body; `pipe_err` pipes stderr for the test to read.
fn spawn_cores(
    replica: &UdpSocket,
    seal: &str,
    block_ms: u64,
    tag: &str,
    extra: &str,
    cores: &str,
    pipe_err: bool,
) -> (Child, PathBuf) {
    let dir = std::env::temp_dir().join(format!("vyrn-seq-{tag}-{}", std::process::id()));
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
{cores}
seal = "{seal}"

[replication]
order = ["{}"]
block_ms = {block_ms}

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
{extra}"#,
            replica.local_addr().unwrap(),
            hex(&K_SEQ),
            hex(&K_OUT)
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_vyrn-seq"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_SMOKE_SEQ_SEED", hex(&SEED))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(if pipe_err {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .unwrap();
    (child, dir)
}

/// Waits up to 20 s for the box to exit; kills it and fails if it does not.
fn exits(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("the box did not exit");
        }
        std::thread::yield_now();
    }
}

/// Stdout closed before `READY`: printing it fails and the control thread unwinds, which must
/// still stop the engine and stream threads, so the box exits (not 0) instead of hanging in its
/// thread scope. Stdin stays open, so nothing else stops the box.
#[test]
fn closed_stdout_before_ready_exits() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut child, dir) = spawn(&replica, "abort", 2, "no-stdout");
    drop(child.stdout.take());
    let status = exits(&mut child);
    assert!(!status.success(), "{status}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// One signed `New` at tick 100 from the DEV session (lane 0, slot 1, generation 1).
fn order(
    pkt_seq: u32,
    side: vyrn_bbo::Side,
    qty: u32,
    client_tag: u32,
    buf: &mut [u8; vyrn_types::MAX_REQ_PAYLOAD],
) -> usize {
    orders(pkt_seq, &[side], qty, client_tag, buf)
}

/// One packet with a `New` per side in `sides`.
fn orders(
    pkt_seq: u32,
    sides: &[vyrn_bbo::Side],
    qty: u32,
    client_tag: u32,
    buf: &mut [u8; vyrn_types::MAX_REQ_PAYLOAD],
) -> usize {
    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let hdr = ReqHeader::new(session, pkt_seq, Epoch(0).low16(), BookId(7), false);
    let msgs: Vec<Msg> = sides
        .iter()
        .map(|&side| Msg::New {
            flags: OrderFlags::from_byte(
                vyrn_bbo::OrderFlags::new(side, vyrn_bbo::Tif::Day, false, vyrn_bbo::Stp::None).0,
            )
            .unwrap(),
            tick: Tick(100),
            qty: Qty(qty),
            client_tag,
        })
        .collect();
    encode_request(buf, hdr, &msgs, &K_SEQ, None).unwrap()
}

/// Closes stdin, reads stdout to EOF and returns the `STATS` line and whether the box exited 0.
/// `[cores] pin`: pinned to a CPU this test may use, the box starts, reports the CPU in
/// `LAYOUT` and stops cleanly; unpinned, `LAYOUT` says `unpinned` though cores are set. Either
/// thread pinned past `CPU_SETSIZE` fail-stops it before `READY`, naming that thread. Linux
/// only: `pin_current_thread` is `Unsupported` elsewhere, so a pinned box never starts there.
#[cfg(target_os = "linux")]
#[test]
fn pinned_cores_start_and_a_bad_pin_fail_stops() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let cpu = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .and_then(|l| l.trim().split([',', '-']).next().map(str::to_owned))
        .unwrap_or_else(|| "0".into());
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    for (pin, layout) in [
        (
            true,
            format!("LAYOUT engine={cpu} stream={cpu} control=main"),
        ),
        (
            false,
            "LAYOUT engine=unpinned stream=unpinned control=main".to_owned(),
        ),
    ] {
        let cores = format!("pin = {pin}\nengine = {cpu}\nstream = {cpu}");
        let tag = format!("pin-ok-{pin}");
        let (mut child, dir) = spawn_cores(&replica, "count", 2, &tag, "", &cores, false);
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut seen = Vec::new();
        loop {
            let mut line = String::new();
            assert!(
                out.read_line(&mut line).unwrap() > 0,
                "exited before READY: {seen:?}"
            );
            if line.starts_with("READY vyrn-seq ") {
                break;
            }
            seen.push(line.trim().to_owned());
        }
        assert!(seen.contains(&layout), "{seen:?}");
        let (_, clean) = stop(&mut child, out);
        assert!(clean);
        let _ = std::fs::remove_dir_all(&dir);
    }

    for (engine, stream, who) in [
        ("65535", cpu.as_str(), "engine"),
        (cpu.as_str(), "65535", "stream"),
    ] {
        let bad = format!("pin = true\nengine = {engine}\nstream = {stream}");
        let tag = format!("pin-bad-{who}");
        let (mut child, dir) = spawn_cores(&replica, "count", 2, &tag, "", &bad, true);
        drop(child.stdin.take());
        let (mut text, mut err) = (String::new(), String::new());
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        assert!(!exits(&mut child).success());
        assert!(!text.contains("READY"), "{text}");
        let want = format!("cores.pin: {who} to cpu 65535");
        assert!(err.contains(&want), "{who}: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

fn stop(child: &mut Child, out: BufReader<ChildStdout>) -> (String, bool) {
    drop(child.stdin.take());
    let mut stats = String::new();
    for l in out.lines() {
        let l = l.unwrap();
        if l.starts_with("STATS") {
            stats = l;
        }
    }
    (stats, child.wait().unwrap().success())
}

#[test]
fn one_order_end_to_end() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let (mut child, out, lane0, dir) = start(&replica, "count", 2, "smoke");

    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let n = order(1, vyrn_bbo::Side::Buy, 5, 77, &mut buf);
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
    // Its route (07 §3.6, Improve) follows it in the same block: replay of block 0 needs it.
    let at = block
        .lanes
        .iter()
        .position(|r| matches!(r, LaneRec::Pkt(p) if p.session == session && p.pkt_seq == 1))
        .unwrap();
    let route = vyrn_types::RouteRecord {
        lane: LaneId(0),
        lane_seq: vyrn_types::LaneSeq(1),
        cross: false,
    };
    assert_eq!(
        block.lanes.get(at + 1),
        Some(&LaneRec::Route(route)),
        "{:?}",
        block.lanes
    );
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
    let (stats, ok) = stop(&mut child, out);
    assert!(ok, "{stats}");
    assert!(stats.contains(" tx=1 "), "{stats}");
    assert!(stats.contains("seal_violations=0"), "{stats}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stalls the stream thread and fills the handoff behind it. The caller has stopped reading
/// stdout. Buy, then sell, 1 at one tick: each pair rests and fills, so every packet makes a step
/// and every block_ms closes a block. Lockstep (one response per packet, so no packet is lost)
/// until a response stops coming: stdout's pipe is full and the stream thread is blocked on a
/// `BLOCK` line. Then 2 packets of four orders a millisecond for 4 s: slow enough that a debug
/// or arm engine keeps the sequence, and enough that, with only about two entries a packet once
/// the session's TX window is full, the handoff's 8192 entries fill well before the end.
fn stall_and_fill(lane0: SocketAddrV4) {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let mut rbuf = [0u8; 2048];
    let (b, s) = (vyrn_bbo::Side::Buy, vyrn_bbo::Side::Sell);
    let mut seq = 1u32;
    let t0 = Instant::now();
    loop {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "stream never stalled"
        );
        let side = if seq % 2 == 1 { b } else { s };
        let n = order(seq, side, 1, seq, &mut buf);
        client.send_to(&buf[..n], lane0).unwrap();
        seq += 1;
        if client.recv(&mut rbuf).is_err() {
            break;
        }
    }
    for _ in 0..4000 {
        for _ in 0..2 {
            let n = orders(seq, &[b, s, b, s], 1, seq, &mut buf);
            client.send_to(&buf[..n], lane0).unwrap();
            seq += 1;
        }
        // `thread::sleep` is disallowed.
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(1) {
            std::thread::yield_now();
        }
    }
}

/// Back-pressure with a sealed engine thread (`seal = "abort"`): the stream thread blocks
/// printing `BLOCK` lines while orders keep arriving, the handoff fills and the engine waits for
/// room; once stdout is read again the box drains, closes its blocks and exits 0. An allocation
/// on the engine thread aborts the process instead.
#[test]
fn sealed_engine_survives_a_full_handoff() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut child, out, lane0, dir) = start(&replica, "abort", 1, "full");
    stall_and_fill(lane0);
    let (stats, ok) = stop(&mut child, out);
    assert!(ok, "exit status: {stats}");
    assert!(stats.contains("seal_violations=0"), "{stats}");
    let field = |k: &str| -> u64 {
        let v = stats.split(' ').find_map(|f| f.strip_prefix(k));
        v.unwrap_or("0").parse().unwrap()
    };
    assert!(field("blocks=") > 1, "{stats}");
    assert!(
        field("handoff_full=") > 0,
        "the handoff never filled: {stats}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stream thread that panics still releases the engine waiting on a full handoff: with the
/// handoff full, closing stdout makes the stream thread's blocked `BLOCK` line panic, and once
/// stdin closes the box exits instead of waiting forever.
#[test]
fn stream_panic_stops_the_box() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut child, out, lane0, dir) = start(&replica, "abort", 1, "panic");
    stall_and_fill(lane0);
    drop(out);
    drop(child.stdin.take());
    let status = exits(&mut child);
    // The stream thread's panic is the box's failure (and STATS cannot print).
    assert!(!status.success(), "{status}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block holding a packet record but no step still closes on its deadline: a heartbeat makes
/// a packet record and no step.
#[test]
fn packet_only_block_closes() {
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let (mut child, out, lane0, dir) = start(&replica, "abort", 2, "pkt-only");
    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let hdr = ReqHeader::new(session, 1, Epoch(0).low16(), BookId(7), false);
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let n = encode_request(&mut buf, hdr, &[Msg::Heartbeat], &K_SEQ, None).unwrap();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(&buf[..n], lane0)
        .unwrap();
    let mut rbuf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(10);
    let header = loop {
        if Instant::now() > deadline {
            break false;
        }
        let Ok(k) = replica.recv(&mut rbuf) else {
            continue;
        };
        if FrameHeader::parse(&rbuf[..k]).unwrap().0.kind == FrameKind::Header {
            break true;
        }
    };
    let (stats, ok) = stop(&mut child, out);
    assert!(header, "no HEADER before stop: {stats}");
    assert!(ok, "{stats}");
    assert!(stats.contains("records=1 steps=0 "), "{stats}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 07 §5.5 source 3 end to end: the box retains the packet it accepted and answers a replica's
/// KEY fetch with it as a `FETCH_RESP` that `vyrn-replica`'s `DataFeed` stores, and answers a
/// miss with an empty one. The engine runs sealed (`abort`), so the retention handoff allocates
/// nothing on it.
#[test]
fn seq_data_req_end_to_end() {
    use vyrn_data::frame::{Fetch, Kind, decode};
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (mut child, out, lane0, repair, dir) =
        start_with(&replica, "abort", 2, "repair", "\n[repair]\nport = 0\n");
    let repair = repair.expect("no REPAIR line");
    let session = vyrn_wire::session_id(1, LaneId(0), 1).unwrap();
    let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let n = order(1, vyrn_bbo::Side::Buy, 5, 77, &mut buf);
    let pkt = buf[..n].to_vec();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client.send_to(&pkt, lane0).unwrap();
    let mut rbuf = [0u8; 2048];
    client.recv_from(&mut rbuf).expect("no response");
    // The replica's fetch socket: same IP as the configured replica, so it is allowed.
    let fetcher = UdpSocket::bind("127.0.0.1:0").unwrap();
    fetcher
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let ask = |pkt_seq| {
        let q = Fetch::Key { session, pkt_seq }.encode();
        fetcher.send_to(&q, repair).unwrap();
        let mut b = [0u8; 2048];
        let (k, _) = fetcher.recv_from(&mut b).expect("no FETCH_RESP");
        b[..k].to_vec()
    };
    // The retention copy crosses a ring to the repair thread: ask until it is there.
    let deadline = Instant::now() + Duration::from_secs(10);
    let hit = loop {
        let r = ask(1);
        if decode(&r).unwrap().n_pkts > 0 || Instant::now() > deadline {
            break r;
        }
    };
    let f = decode(&hit).unwrap();
    assert_eq!(
        (f.hdr.kind, f.hdr.src, f.hdr.book, f.hdr.data_seq),
        (
            Kind::FetchResp,
            0xFF,
            BookId(7),
            (u64::from(session.0) << 32) | 1
        )
    );
    assert_eq!(
        f.packets().collect::<Vec<_>>(),
        vec![&pkt[..]],
        "the exact bytes"
    );
    let mut feed = vyrn_replica::DataFeed::new(BookId(7), 1, 0);
    let mut join = vyrn_replica::DataJoin::default();
    assert_eq!(feed.on_frame(&mut join, &hit, 0).unwrap().stored, 1);
    let miss = ask(2);
    assert_eq!(decode(&miss).unwrap().n_pkts, 0);
    let (stats, ok) = stop(&mut child, out);
    assert!(ok, "{stats}");
    assert!(stats.contains("seal_violations=0"), "{stats}");
    let _ = std::fs::remove_dir_all(&dir);
}
