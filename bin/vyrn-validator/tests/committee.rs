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
    BlockHeader, BookId, Epoch, Hash, Height, LaneId, LaneSeq, Mode, Nanos, PacketRecord,
    SessionId, StepId, StepKind,
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

/// A free TCP port below Linux's ephemeral range (32768 and up). A port the kernel picks for
/// `:0` is released before the validator binds it, and a validator's own p2p dial, whose source
/// port is ephemeral, could take it first ("BindFailed"); a port below the range is never
/// handed out that way. Spread by pid so parallel test processes start apart.
fn free_tcp() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    const BASE: u16 = 20_000;
    const SPAN: u16 = 12_000;
    let start = u16::try_from(std::process::id() % u32::from(SPAN)).unwrap();
    loop {
        let k = NEXT.fetch_add(1, Ordering::Relaxed);
        assert!(k < SPAN, "no free TCP port in {BASE}..{}", BASE + SPAN);
        let port = BASE + (start + k) % SPAN;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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
            // Each test's journals start empty (07 §6.3 Journal).
            .arg("--fresh")
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

    /// The first line starting with any of `prefixes`, within `secs`.
    fn wait_any(&self, prefixes: &[&str], secs: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) if prefixes.iter().any(|p| l.starts_with(p)) => return l,
                Ok(_) => {}
                Err(_) => panic!("no {prefixes:?} line within {secs} s"),
            }
        }
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

/// The tenure-0 writer of the test's sequencer, signing with `SEQ_SEED`.
fn writer() -> SeqWriter {
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
    SeqWriter::new(Layout::new(2, 1, 0).unwrap(), ident, ts, SEQ_SEED, 1472).unwrap()
}

const SESSION: SessionId = SessionId(0x0010_0001);

/// Request packet `i` of `SESSION`: one Heartbeat (count 1 fits it, 07 §5.4), book 7.
fn request(i: u32) -> Vec<u8> {
    let mut out = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
    let h = vyrn_wire::ReqHeader::new(SESSION, i, 0, BookId(7), false);
    let n = vyrn_wire::encode_request(&mut out, h, &[vyrn_wire::Msg::Heartbeat], &[7; 16], None)
        .unwrap();
    out[..n].to_vec()
}

/// Data box 0's DATA frame `data_seq` carrying request packet `i` (07 §5.3).
fn data_frame(data_seq: u64, i: u32) -> Vec<u8> {
    use vyrn_data::frame::{DataHdr, FrameBuf, Kind};
    let mut b = FrameBuf::default();
    assert!(b.push(&request(i)));
    b.finish(&DataHdr {
        kind: Kind::Data,
        book: BookId(7),
        epoch16: 0,
        data_seq,
        src: 0,
    })
    .to_vec()
}

/// Packet `i` and its Improve step, framed (`flush`) but in no closed block.
fn records(w: &mut SeqWriter, i: u32) -> Vec<Vec<u8>> {
    let full = vyrn_replica::full_hash(&request(i));
    let p = PacketRecord {
        lane: LaneId(0),
        count: 1,
        flags: 0,
        session: SESSION,
        pkt_seq: i,
        rx_ts: Nanos(u64::from(i) * 1_000),
        pkt_hash: vyrn_data::ingest::pkt_hash_of(&full),
        first_lane_seq: LaneSeq(u64::from(i)),
        fills_applied: StepId(0),
        snap_lag: 0,
    };
    let mut f = w.packet(p, Some(full)).unwrap();
    let cut = [LaneSeq(u64::from(i)), LaneSeq(0)];
    f.extend(
        w.step(
            StepId(u64::from(i)),
            StepKind::Improve,
            Some((LaneId(0), LaneSeq(u64::from(i)))),
            0,
            Vec::new(),
            &cut,
            0,
        )
        .unwrap(),
    );
    f.extend(w.flush().unwrap());
    f
}

/// Blocks `0..n` (block `i` holds packet `i + 1` and its step), and the last header.
fn blocks_with(w: &mut SeqWriter, n: u32) -> (Vec<Vec<u8>>, Option<BlockHeader>) {
    let mut out = Vec::new();
    let mut last = None;
    for i in 1..=n {
        out.extend(records(w, i));
        let (f, h) = w.close_block().unwrap();
        out.extend(f);
        last = Some(h);
    }
    (out, last)
}

/// The frames of blocks `0..n`, one New and its Improve step each, signed with `SEQ_SEED`.
fn blocks(n: u32) -> Vec<Vec<u8>> {
    blocks_with(&mut writer(), n).0
}

/// Four validators of a roster committee on localhost, their CTRL listener socket and ORDER
/// ports. `extra` is appended to every config (`[failover]`), `dev` sets `dev = true`. With
/// `data`, each has a data RX queue (`datas`) fed by one data box, `src = 0`, that is the test.
struct Committee4 {
    dir: std::path::PathBuf,
    committee: Committee,
    ctrl: UdpSocket,
    vals: Vec<Box_>,
    orders: Vec<SocketAddrV4>,
    datas: Vec<SocketAddrV4>,
}

fn committee4(tag: &str, dev: bool, extra: &str) -> Committee4 {
    committee4_with(tag, dev, false, extra)
}

fn committee4_with(tag: &str, dev: bool, data: bool, extra: &str) -> Committee4 {
    let dir = std::env::temp_dir().join(format!("vyrn-{tag}-{}", std::process::id()));
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
    let (roster_hex, roster_hash) = roster(&keys, &repl, [seq_key, [0x77; 32]]);
    let roster_file = dir.join("roster.hex");
    std::fs::write(&roster_file, roster_hex).unwrap();
    let mut vals = Vec::new();
    let mut orders: Vec<SocketAddrV4> = Vec::new();
    let mut datas: Vec<SocketAddrV4> = Vec::new();
    for (i, port) in repl.iter().enumerate() {
        // The data box never answers a fetch (port 9, discard); its silence is never declared.
        let (data_port, data_sec) = if data {
            (
                "data_port = 0\n",
                format!("\n[data]\nboxes = [\"127.0.0.1:9\"]\nme = {i}\nsilence_us = 600000000\n"),
            )
        } else {
            ("", String::new())
        };
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
dev = {dev}

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
order_port = 0
{data_port}
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
{data_sec}{extra}"#,
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
        if data {
            let d = v.wait("DATA rx=", 30);
            datas.push(d.rsplit('=').next().unwrap().parse().unwrap());
        }
        assert_eq!(
            v.wait("CONSENSUS", 30),
            format!("CONSENSUS voter={i} repl=127.0.0.1:{port} standby=none")
        );
        let a = v.wait("READY vyrn-validator order=", 30);
        orders.push(a.rsplit('=').next().unwrap().parse().unwrap());
        vals.push(v);
    }
    Committee4 {
        dir,
        committee,
        ctrl: ctrl_sock,
        vals,
        orders,
        datas,
    }
}

#[test]
fn four_validators_finalize_and_the_listener_learns_it() {
    let Committee4 {
        dir,
        committee,
        ctrl: ctrl_sock,
        vals,
        orders,
        ..
    } = committee4("committee", false, "");
    let mut listener = Listener::new(committee.clone(), Epoch(0), Height(0));

    // 40 blocks to every validator in one burst, so each HASH frame is queued right behind its
    // packet: on a loaded 2-vCPU host a gap between them can pass REP_HASHLAG_MAX (1 ms).
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for a in &orders {
        for f in &blocks(40) {
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

/// Every line `v` prints until it exits, after its stdin closes; and whether it exited 0.
fn stop_and_drain(mut v: Box_) -> (bool, Vec<String>) {
    drop(v.child.stdin.take());
    let ok = v.child.wait().unwrap().success();
    let mut out = Vec::new();
    while let Ok(l) = v.lines.recv_timeout(Duration::from_secs(2)) {
        out.push(l);
    }
    (ok, out)
}

/// 07 §9.1–9.5, no promotable box: the test's sequencer frames 40 blocks and one more packet and
/// step, then goes silent (no heartbeat, no standby). The four voters suspect, exchange
/// `Silence` on the p2p tail channel, depose at Q, and finalize the seal of the prefix with
/// `next_seq = 0xFF`. The seal is checked against one this test computes from the frames it
/// sent (`H*` = block 39, `F*` = its last frame, `order_root` over the tail's ORDER bytes,
/// the tail packet unavailable without `[data]`), so a prefix one frame short or a root over
/// the wrong frames fails, though every voter would agree on it. After `DEPOSED` the sequencer
/// sends block 40's mark and header: no voter applies it (INV-REP-5).
#[test]
fn a_silent_sequencer_is_deposed_and_its_prefix_sealed() {
    use vyrn_consensus::{ProposalKind, SealExt};
    // DEV timers on loopback: 300 ms of silence, a 2 s abort window.
    let Committee4 {
        dir,
        committee,
        ctrl,
        vals,
        orders,
        ..
    } = committee4(
        "depose",
        true,
        "\n[failover]\nsilence_us = 300000\nabort_us = 2000000\n",
    );
    let mut w = writer();
    let (mut frames, star) = blocks_with(&mut w, 40);
    let star = star.unwrap();
    frames.extend(records(&mut w, 41));
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for a in &orders {
        for f in &frames {
            s.send_to(f, a).unwrap();
        }
    }
    // What the seal must be, from the sender's side.
    let f_star = u64::try_from(frames.len()).unwrap();
    let want = vyrn_consensus::tail::seal_header(
        &star,
        StepId(41),
        vyrn_log::block::order_root(w.open_order_bytes(), &[]),
        vyrn_log::block::data_root(&[Hash([0; 32])], &[]),
    );
    let want_ext = SealExt {
        end_frame_seq: [f_star, 0],
        next_seq: 0xFF,
        next_tenure: 1,
        unavail: vec![(SESSION, 41)],
    };
    for v in &vals {
        v.wait("DEPOSED", 60);
    }
    // INV-REP-5: block 40's mark and header, after deposition.
    let (late, _) = w.close_block().unwrap();
    for a in &orders {
        for f in &late {
            s.send_to(f, a).unwrap();
        }
    }
    // A voter deposed by the others' Silence before its own order thread decoded the whole
    // tail holds no candidate (no tail fetch yet, `NO_SEAL`); Q of 4 must hold this one.
    let mut sealed = 0;
    for v in &vals {
        let l = v.wait_any(&["SEAL ", "NO_SEAL "], 30);
        if l.starts_with("SEAL ") {
            assert!(l.contains(&format!("end_a={f_star} ")), "{l}");
            assert!(l.contains("next_seq=255"), "{l}");
            sealed += 1;
        }
    }
    assert!(
        sealed >= committee.quorum(),
        "{sealed} voters hold the seal"
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut buf = [0u8; 9216];
    let cert = loop {
        assert!(Instant::now() < deadline, "no seal certificate");
        let Ok(n) = ctrl.recv(&mut buf) else { continue };
        if let Ctrl::Cert(c) = ctrl::decode(&buf[..n]).unwrap()
            && c.proposal.kind == ProposalKind::Seal
        {
            break c;
        }
    };
    assert_eq!(verify_finality_cert(&cert, &committee), Ok(()));
    assert_eq!(cert.proposal.last_height, Height(40));
    assert_eq!(
        cert.proposal.last_hash,
        vyrn_log::block::header_hash(&want),
        "the seal header differs from the sender's prefix"
    );
    assert_eq!(cert.seal, Some(want_ext));
    for v in vals {
        let (ok, lines) = stop_and_drain(v);
        assert!(ok);
        assert!(
            !lines.iter().any(|l| l.starts_with("BLOCK height=40")),
            "a voter applied a frame of the deposed tenure"
        );
        let drops = lines
            .iter()
            .find_map(|l| l.strip_prefix("DEPOSED_DROPS frames="))
            .and_then(|n| n.parse::<u64>().ok());
        assert!(drops.is_some_and(|d| d >= 1), "{drops:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex r4618710713: with `[data]`, the tail packet's payload reaches voters 0 and 1 before
/// deposition and voters 2 and 3 only after their seal candidates were built (with it in
/// `unavail`). Neither candidate holds Q votes; the late payload rebuilds 2 and 3's candidates
/// (`RESEAL`), and the seal finalizes with the payload joined: `unavail` empty, `data_root`
/// over its full hash.
#[test]
fn a_late_payload_rebuilds_the_seal_candidate() {
    use vyrn_consensus::ProposalKind;
    let Committee4 {
        dir,
        committee,
        ctrl,
        vals,
        orders,
        datas,
    } = committee4_with(
        "reseal",
        true,
        true,
        "\n[failover]\nsilence_us = 300000\nabort_us = 2000000\n",
    );
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Payloads first (each voter's data_seq 1..=40), then packet 41's to voters 0 and 1 only.
    for d in &datas {
        for i in 1..=40 {
            s.send_to(&data_frame(u64::from(i), i), d).unwrap();
        }
    }
    for d in &datas[..2] {
        s.send_to(&data_frame(41, 41), d).unwrap();
    }
    let mut w = writer();
    let (mut frames, star) = blocks_with(&mut w, 40);
    let star = star.unwrap();
    frames.extend(records(&mut w, 41));
    for a in &orders {
        for f in &frames {
            s.send_to(f, a).unwrap();
        }
    }
    let late = vyrn_replica::full_hash(&request(41));
    let want = vyrn_consensus::tail::seal_header(
        &star,
        StepId(41),
        vyrn_log::block::order_root(w.open_order_bytes(), &[]),
        vyrn_log::block::data_root(&[late], &[]),
    );
    let mut sealed = Vec::new();
    for (i, v) in vals.iter().enumerate() {
        let l = v.wait_any(&["SEAL ", "NO_SEAL "], 60);
        if l.starts_with("SEAL ") {
            let want = if i < 2 { "unavail=0" } else { "unavail=1" };
            assert!(l.ends_with(want), "voter {i}: {l}");
            sealed.push(i);
        }
    }
    assert!(
        sealed.iter().filter(|&&i| i >= 2).count() >= 1 && sealed.len() >= committee.quorum(),
        "sealed: {sealed:?}"
    );
    for d in &datas[2..] {
        s.send_to(&data_frame(41, 41), d).unwrap();
    }
    for &i in sealed.iter().filter(|&&i| i >= 2) {
        let l = vals[i].wait("RESEAL ", 30);
        assert!(l.ends_with("unavail=0"), "voter {i}: {l}");
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut buf = [0u8; 9216];
    let cert = loop {
        assert!(Instant::now() < deadline, "no seal certificate");
        let Ok(n) = ctrl.recv(&mut buf) else { continue };
        if let Ctrl::Cert(c) = ctrl::decode(&buf[..n]).unwrap()
            && c.proposal.kind == ProposalKind::Seal
        {
            break c;
        }
    };
    assert_eq!(verify_finality_cert(&cert, &committee), Ok(()));
    assert_eq!(cert.proposal.last_height, Height(40));
    assert_eq!(cert.proposal.last_hash, vyrn_log::block::header_hash(&want));
    assert_eq!(cert.seal.map(|x| x.unavail), Some(Vec::new()));
    for v in vals {
        assert!(v.stop());
    }
    let _ = std::fs::remove_dir_all(&dir);
}
