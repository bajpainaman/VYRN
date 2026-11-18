//! A fetch flood must not starve the box's `DATA_HB` (07 §5.3): replicas mark a box down after
//! a silence, so a backup box busy serving every replica's KEY fetches for a dead home's packets
//! must keep its heartbeat cadence (#184 saw the backup marked down at a 20 ms DEV silence).
//!
//! The box runs with every core pinned to one CPU, as on a busy host where they share CPUs, and
//! takes one second of KEY fetches that all miss. Each fetch is cheap; the risk is that the RX
//! and shard threads never idle, so they take the sender's turns. The test measures the gaps
//! between frames at a replica during the flood.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vyrn_data::frame::Fetch;
use vyrn_types::SessionId;

/// The flood's length.
const FLOOD: Duration = Duration::from_secs(1);
/// `DATA_HB` to an idle destination every `hb_ns` (the binary's default, 100 µs).
const HB: Duration = Duration::from_micros(100);

#[test]
fn heartbeats_keep_their_cadence_under_a_fetch_flood() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let cpu = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .and_then(|l| l.trim().split([',', '-']).next().map(str::to_owned))
        .unwrap_or_else(|| "0".into());
    let dir = std::env::temp_dir().join(format!("vyrn-data-flood-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let replica = UdpSocket::bind("127.0.0.1:0").unwrap();
    replica
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let text = format!(
        "schema = 1\nprotocol = 1\nrole = \"data\"\nmode = \"BASE\"\nhome = \"LDN\"\ndev = true\n\
         src = 1\nbooks = [3]\ndests = [\"{}\"]\n\n\
         [nic]\nbackend = \"kernel_udp\"\nip = \"127.0.0.1\"\ningest_port = 0\nfetch_port = 0\n\n\
         [ring]\nslots = 65536\n\n[fetch]\nrate = 100000000\nburst = 1000000\n\n\
         [metrics]\nlisten = \"127.0.0.1:0\"\n\n[shards]\nn = 1\ncpus = [{cpu}, {cpu}, {cpu}]\n\n\
         [[session]]\nid = 5\nkey = \"hex:{}\"\n",
        replica.local_addr().unwrap(),
        "07".repeat(16)
    );
    let cfg = dir.join("data.toml");
    std::fs::write(&cfg, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_vyrn-data"))
        .arg("--config")
        .arg(&cfg)
        .arg("--stop-on-stdin-eof")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = lines.next().unwrap().unwrap();
    assert!(ready.starts_with("READY vyrn-data "), "{ready}");
    let fetch_at = ready
        .split(' ')
        .find_map(|w| w.strip_prefix("fetch="))
        .unwrap()
        .to_owned();

    let flooding = AtomicBool::new(true);
    let (sent, gaps) = std::thread::scope(|sc| {
        let flooder = sc.spawn(|| {
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            c.set_nonblocking(true).unwrap();
            let (mut sent, mut buf) = (0u64, [0u8; 2048]);
            let t0 = Instant::now();
            while t0.elapsed() < FLOOD {
                sent += 1;
                let q = Fetch::Key {
                    session: SessionId(5),
                    pkt_seq: u32::try_from(sent % u64::from(u32::MAX)).unwrap(),
                };
                let _ = c.send_to(&q.encode(), &fetch_at);
                while c.recv(&mut buf).is_ok() {}
            }
            flooding.store(false, Ordering::Release);
            sent
        });
        // Frame arrival gaps while the flood runs.
        let mut buf = [0u8; 2048];
        let mut gaps = Vec::new();
        let mut last = None::<Instant>;
        while flooding.load(Ordering::Acquire) {
            if replica.recv(&mut buf).is_ok() {
                let now = Instant::now();
                if let Some(l) = last {
                    gaps.push(now - l);
                }
                last = Some(now);
            }
        }
        (flooder.join().unwrap(), gaps)
    });
    drop(child.stdin.take());
    let stats = lines
        .map_while(Result::ok)
        .find(|l| l.starts_with("STATS"))
        .unwrap();
    assert!(child.wait().unwrap().success());
    let miss = stats
        .split(' ')
        .find_map(|w| w.strip_prefix("fetch_miss="))
        .unwrap()
        .parse::<u64>()
        .unwrap();

    let mut sorted = gaps.clone();
    sorted.sort();
    let p99 = sorted[sorted.len() * 99 / 100];
    let p999 = sorted[sorted.len() * 999 / 1000];
    let frames = gaps.len() + 1;
    let want = FLOOD.as_micros() / HB.as_micros();
    println!(
        "flood: {sent} fetches sent, {miss} served; {frames} frames at the replica \
         (cadence {want}); gaps p99 {p99:?}, p99.9 {p999:?}, max {:?}",
        sorted.last().unwrap()
    );
    assert!(miss > 10_000, "the box served the flood: {stats}");
    // Without the fix (#184's cascade) the RX and shard threads take the sender's turns: on a
    // 2-vCPU host about two thirds of the cadence is lost and p99 is a scheduler slice (~5 ms).
    // With it, ~20% is lost and p99 is a few hundred µs. p99.9 and the maximum are left
    // unchecked: a few host-level slices reach them either way.
    assert!(p99 < Duration::from_millis(2), "p99 heartbeat gap {p99:?}");
    assert!(
        frames as u128 * 2 >= want,
        "{frames} frames for a {want}-heartbeat cadence"
    );
}
