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

fn config(
    dir: &std::path::Path,
    dest: SocketAddr,
    dev: bool,
    fetch_key: bool,
) -> std::path::PathBuf {
    let fk = if fetch_key {
        "[[fetch_key]]\nip = \"127.0.0.1\"\nkey = \"env:VYRN_DATA_TEST_KFETCH\"\n"
    } else {
        ""
    };
    let text = format!(
        "schema = 1\nprotocol = 1\nrole = \"data\"\nmode = \"BASE\"\nhome = \"DEV\"\ndev = {dev}\n\
         src = 1\nbooks = [3]\ndests = [\"{dest}\"]\n\n\
         [nic]\nbackend = \"kernel_udp\"\nip = \"127.0.0.1\"\ningest_port = 0\nfetch_port = 0\n\n\
         [ring]\nslots = 64\nindex_key = \"env:VYRN_DATA_TEST_KFETCH\"\n\n\
         [[session]]\nid = 5\nkey = \"env:VYRN_DATA_TEST_KSEQ\"\n\n{fk}\
         [metrics]\nlisten = \"127.0.0.1:0\"\n"
    );
    let p = dir.join(format!("data-{dev}-{fetch_key}.toml"));
    std::fs::write(&p, text).unwrap();
    p
}

fn cmd(cfg: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vyrn-data"));
    c.arg("--config")
        .arg(cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_DATA_TEST_KSEQ", "07".repeat(16))
        .env("VYRN_DATA_TEST_KFETCH", "33".repeat(16));
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

    // The 5 µs batch timer sends the frame without a flush.
    let mut buf = [0u8; 2048];
    let got = replica.recv(&mut buf).unwrap();
    let d = frame::decode(&buf[..got]).unwrap();
    assert_eq!((d.hdr.kind, d.hdr.src, d.hdr.data_seq), (Kind::Data, 1, 1));
    assert_eq!(d.packets().collect::<Vec<_>>(), vec![&out[..n]]);

    let t = Instant::now();
    loop {
        let m = scrape(&metrics);
        if m.contains("vyrn_data_stored_total{role=\"data\",home=\"DEV\",src=\"1\"} 1") {
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
    let _ = std::fs::remove_dir_all(&dir);
}

/// Open-mode fetches (no `[[fetch_key]]`) start only on a box marked `dev = true`.
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
