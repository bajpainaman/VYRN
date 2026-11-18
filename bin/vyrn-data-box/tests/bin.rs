//! The `vyrn-data` binary end to end on `kernel_udp` loopback: `READY`, one client copy fanned
//! out as a `DATA` frame, the Prometheus counters, `STATS` on stdin EOF, and the refusal of
//! open-mode fetches outside DEV.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vyrn_data::frame::{self, Kind};
use vyrn_types::{BookId, MAX_REQ_PAYLOAD, SessionId};
use vyrn_wire::{Msg, ReqHeader, encode_request};

const K: [u8; 16] = [7; 16];

/// The test requester's X25519 secret: LDN voter 0, at 127.0.0.1.
const REQ_SECRET: [u8; 32] = [0x5a; 32];
/// The box's X25519 secret: LDN data box 0.
const BOX_SECRET: [u8; 32] = [0x6b; 32];
const EPOCH: u32 = 8;

fn domain() -> vyrn_epoch::Domain {
    vyrn_epoch::Domain {
        genesis_hash: vyrn_types::Hash([0; 32]),
        mode: vyrn_types::Mode::Base,
    }
}

/// A BASE roster (08 §9.6), one home used for all three: 4 voters at 127.0.0.1..=4 (voter 0 has
/// a real X25519 key), 2 `vyrn-seq` boxes at 127.0.1.1..=2, and one data box with a real key.
fn roster() -> vyrn_epoch::Roster {
    use vyrn_epoch::{Addr, DataBox, Home, Roster, SeqEntry, Voter};
    let addr = |a: [u8; 4]| {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&a);
        Addr { ip, port: 7001 }
    };
    let x = vyrn_crypto::x25519::public_key;
    let home = Home {
        voters: (0..4u8)
            .map(|i| Voter {
                client: i % 2,
                facility: i + 1,
                node_key: vec![0x10 + i; 32],
                vote_key: vec![0x10 + i; 32],
                xchg_key: if i == 0 {
                    x(&REQ_SECRET).to_vec()
                } else {
                    vec![0x55 + i; 32]
                },
                data_addr: addr([127, 0, 0, 1 + i]),
                repl_addr: addr([127, 0, 0, 1 + i]),
            })
            .collect(),
        seq: (0..2u8)
            .map(|j| SeqEntry {
                facility: j + 1,
                node_key: vec![0x20 + j; 32],
                seq_key: vec![0x20 + j; 32],
                xchg_key: vec![0x66; 32],
                client_addr: addr([127, 0, 1, 1 + j]),
                repl_addr: addr([127, 0, 1, 1 + j]),
            })
            .collect(),
        recovery: 0,
        data: vec![DataBox {
            facility: 2,
            addr: addr([127, 0, 2, 1]),
            xchg_key: x(&BOX_SECRET).to_vec(),
        }],
    };
    Roster {
        sig_scheme: 0,
        epoch_from: vyrn_types::Epoch(0),
        homes: [home.clone(), home.clone(), home],
        bridge: None,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn config(dir: &std::path::Path, dest: SocketAddr, dev: bool, keyed: bool) -> std::path::PathBuf {
    let fk = if keyed {
        let r = roster();
        let file = dir.join("roster.hex");
        std::fs::write(&file, hex(&r.encode())).unwrap();
        format!(
            "[roster]\nfile = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\nepoch = {EPOCH}\n\
             box = 0\nxchg_secret = \"env:VYRN_DATA_TEST_XCHG\"\n\n",
            file.display(),
            hex(&r.hash(&domain()).0),
            hex(&[0; 32]),
        )
    } else {
        String::new()
    };
    let text = format!(
        "schema = 1\nprotocol = 1\nrole = \"data\"\nmode = \"BASE\"\nhome = \"LDN\"\ndev = {dev}\n\
         src = 1\nbooks = [3]\ndests = [\"{dest}\"]\n\n\
         [nic]\nbackend = \"kernel_udp\"\nip = \"127.0.0.1\"\ningest_port = 0\nfetch_port = 0\n\n\
         [ring]\nslots = 64\nindex_key = \"env:VYRN_DATA_TEST_KFETCH\"\n\n\
         [[session]]\nid = 5\nkey = \"env:VYRN_DATA_TEST_KSEQ\"\n\n{fk}\
         [metrics]\nlisten = \"127.0.0.1:0\"\n"
    );
    let p = dir.join(format!("data-{dev}-{keyed}.toml"));
    std::fs::write(&p, text).unwrap();
    p
}

fn cmd(cfg: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vyrn-data"));
    c.arg("--config")
        .arg(cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_DATA_TEST_KSEQ", "07".repeat(16))
        .env("VYRN_DATA_TEST_KFETCH", "33".repeat(16))
        .env("VYRN_DATA_TEST_XCHG", hex(&BOX_SECRET));
    c
}

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split(' ').find_map(|w| w.strip_prefix(key)).unwrap()
}

fn scrape(addr: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn serves_a_replica_exports_metrics_and_stops() {
    let dir = std::env::temp_dir().join(format!("vyrn-data-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let cfg = config(&dir, replica.local_addr().unwrap(), false, true);
    let mut child = cmd(&cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = lines.next().unwrap().unwrap();
    assert!(ready.starts_with("READY vyrn-data "), "{ready}");
    let ingest = field(&ready, "ingest=").to_owned();
    let metrics = field(&ready, "metrics=").to_owned();

    let mut out = [0u8; MAX_REQ_PAYLOAD];
    let h = ReqHeader::new(SessionId(5), 1, 9, BookId(3), false);
    let n = encode_request(&mut out, h, &[Msg::Heartbeat], &K, None).unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(&out[..n], &ingest).unwrap();

    // The 5 µs batch timer sends the frame without a flush. An idle destination gets DATA_HB
    // every 100 µs, so heartbeats sent before the packet arrived are skipped.
    let mut buf = [0u8; 2048];
    let t = Instant::now();
    let d = loop {
        assert!(t.elapsed() < Duration::from_secs(5), "no DATA frame");
        let got = replica.recv(&mut buf).unwrap();
        if frame::decode(&buf[..got]).unwrap().hdr.kind != Kind::DataHb {
            break frame::decode(&buf[..got]).unwrap();
        }
    };
    assert_eq!((d.hdr.kind, d.hdr.src, d.hdr.data_seq), (Kind::Data, 1, 1));
    assert_eq!(d.packets().collect::<Vec<_>>(), vec![&out[..n]]);

    // A KEY fetch sealed under the K_fetch the requester derives on its side is served; the
    // same fetch under another epoch's key is refused (08 §9.6).
    let fetch_at = field(&ready, "fetch=").to_owned();
    let q = vyrn_data::frame::Fetch::Key {
        session: SessionId(5),
        pkt_seq: 1,
    };
    let r = roster();
    let ldn = vyrn_types::HomeCode::Ldn;
    let key = |e| r.requester_fetch_key(&domain(), vyrn_types::Epoch(e), ldn, 0, 0, &REQ_SECRET);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .send_to(&q.seal(&key(EPOCH + 1).unwrap()), &fetch_at)
        .unwrap();
    client
        .send_to(&q.seal(&key(EPOCH).unwrap()), &fetch_at)
        .unwrap();
    let got = client.recv(&mut buf).unwrap();
    let resp = frame::decode(&buf[..got]).unwrap();
    assert_eq!(resp.hdr.kind, Kind::FetchResp);
    assert_eq!(resp.packets().collect::<Vec<_>>(), vec![&out[..n]]);

    let t = Instant::now();
    loop {
        let m = scrape(&metrics);
        if m.contains("vyrn_data_stored_total{role=\"data\",home=\"LDN\",src=\"1\"} 1")
            && m.contains("vyrn_data_events_unprinted_total{")
        {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "metrics never showed stored=1:\n{m}"
        );
        std::thread::yield_now();
    }

    drop(child.stdin.take());
    let stats = lines
        .map(Result::unwrap)
        .find(|l| l.starts_with("STATS "))
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(field(&stats, "stored="), "1", "{stats}");
    assert_eq!(field(&stats, "data_frames="), "1", "{stats}");
    assert_eq!(field(&stats, "events_unprinted="), "0", "{stats}");
    assert_eq!(field(&stats, "fetch_unauth="), "1", "{stats}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Open-mode fetches (no `[roster]`) start only on a box marked `dev = true`.
#[test]
fn refuses_open_mode_outside_dev() {
    let dir = std::env::temp_dir().join(format!("vyrn-data-open-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let o = cmd(&config(&dir, dest, false, false))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("open-mode fetches are DEV only"));
    // A hex: key outside DEV is refused without printing it.
    let leaky = dir.join("leaky.toml");
    let text = std::fs::read_to_string(config(&dir, dest, false, true))
        .unwrap()
        .replace(
            "env:VYRN_DATA_TEST_KSEQ",
            "hex:abababababababababababababababab",
        );
    std::fs::write(&leaky, text).unwrap();
    let o = cmd(&leaky).stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(2));
    assert!(err.contains("DEV only") && !err.contains("abab"), "{err}");
    let mut child = cmd(&config(&dir, dest, true, false))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    out.read_line(&mut first).unwrap();
    assert!(first.starts_with("READY "), "{first}");
    drop(child.stdin.take());
    let mut rest = String::new();
    out.read_to_string(&mut rest).unwrap();
    assert!(rest.starts_with("STATS stored=0 "), "{rest}");
    assert!(child.wait().unwrap().success());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stop during a bad-MAC flood loses no event silently: every one the node raised is an
/// `EVENT` line or counted in `STATS` (`events_unprinted`, `events_dropped`).
#[test]
fn a_stop_accounts_for_every_event() {
    let dir = std::env::temp_dir().join(format!("vyrn-data-drain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    let cfg = config(&dir, replica.local_addr().unwrap(), false, true);
    let mut child = cmd(&cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    out.read_line(&mut ready).unwrap();
    let ingest = field(ready.trim(), "ingest=").to_owned();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut pkt = [0u8; MAX_REQ_PAYLOAD];
    for q in 1..=3000u32 {
        let h = ReqHeader::new(SessionId(5), q, 9, BookId(3), false);
        let n = encode_request(&mut pkt, h, &[Msg::Heartbeat], &[9; 16], None).unwrap();
        client.send_to(&pkt[..n], &ingest).unwrap();
    }
    // Stop while the flood is still being ingested, but only once the box has raised an event.
    let mut first = String::new();
    out.read_line(&mut first).unwrap();
    assert!(first.starts_with("EVENT bad_mac "), "{first}");
    drop(child.stdin.take());
    let mut rest = first;
    out.read_to_string(&mut rest).unwrap();
    assert!(child.wait().unwrap().success());
    let printed = rest
        .lines()
        .filter(|l| l.starts_with("EVENT bad_mac "))
        .count() as u64;
    let stats = rest.lines().find(|l| l.starts_with("STATS ")).unwrap();
    let n = |k: &str| field(stats, k).parse::<u64>().unwrap();
    assert!(n("bad_mac=") > 0, "{stats}");
    assert_eq!(
        printed + n("events_unprinted=") + n("events_dropped="),
        n("bad_mac="),
        "{stats}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
