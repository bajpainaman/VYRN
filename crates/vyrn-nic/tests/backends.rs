//! Backend-specific behaviour the conformance suite cannot drive through the traits alone:
//! kernel_udp loopback between processes' sockets, and sim's injected faults and stamps.

use core::net::{Ipv4Addr, SocketAddrV4};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use vyrn_nic::conformance::test_frame;
use vyrn_nic::frame;
use vyrn_nic::sim::SimFault;
use vyrn_nic::{
    BackendKind, ExtCounted, ExtCounters, KernelUdp, NicBackend, NicConfig, PortClock, PortConfig,
    PortId, RxBind, SimNic, TxClass,
};
use vyrn_types::{LaneId, Nanos};
use vyrn_wire::{RX_BURST, RxPkt, RxRing, TsSource, TxRing};

fn cfg(kind: BackendKind) -> NicConfig {
    NicConfig::new(
        kind,
        vec![PortConfig {
            id: PortId(0),
            ip: Ipv4Addr::LOCALHOST,
        }],
    )
}

fn bind(udp_port: u16) -> RxBind {
    RxBind {
        lane: LaneId(0),
        port: PortId(0),
        ip: Ipv4Addr::LOCALHOST,
        udp_port,
    }
}

fn poll_one(rx: &mut impl RxRing) -> RxPkt {
    let mut out = [RxPkt::empty(); RX_BURST];
    let t = Instant::now();
    loop {
        if rx.poll(&mut out) > 0 {
            return out[0];
        }
        assert!(t.elapsed() < Duration::from_secs(5), "nothing arrived");
        std::thread::yield_now();
    }
}

#[test]
fn kernel_udp_loopback_with_plain_sockets() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    assert_eq!(nic.caps().ts, TsSource::Kernel);
    assert_eq!(nic.port_clock(PortId(0)).unwrap(), PortClock::Realtime);
    let mut rx = nic.rx_ring(&bind(0)).unwrap();
    let mut tx = nic.tx_ring(PortId(0), TxClass::Control).unwrap();
    assert_eq!(rx.ts_source(), TsSource::Kernel);

    // A plain socket (another program) to the queue: the frame carries its address.
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr = match peer.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    peer.send_to(b"hello vyrn", rx.local_addr()).unwrap();
    let p = poll_one(&mut rx);
    let f = frame::parse(rx.bytes(&p)).unwrap();
    assert_eq!(f.payload, b"hello vyrn");
    assert_eq!(
        (f.hdr.src.ip, f.hdr.src.port),
        (*peer_addr.ip(), peer_addr.port())
    );
    assert_eq!(
        SocketAddrV4::new(f.hdr.dst.ip, f.hdr.dst.port),
        rx.local_addr()
    );
    assert!(
        p.rx_ts() > Nanos(1_600_000_000_000_000_000),
        "rx_ts is CLOCK_REALTIME"
    );
    rx.release(1);

    // The queue's TX to the plain socket: only the payload goes on the wire.
    let f = test_frame(peer_addr, 5, 3);
    tx.send(&f).unwrap();
    let mut buf = [0u8; 64];
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (n, from) = peer.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], frame::parse(&f).unwrap().payload);
    assert_eq!(from, std::net::SocketAddr::V4(tx.local_addr()));
    assert_eq!(tx.reap(), 1);

    // An oversize datagram is counted, not delivered.
    peer.send_to(&[0u8; frame::MAX_PAYLOAD + 1], rx.local_addr())
        .unwrap();
    peer.send_to(b"after", rx.local_addr()).unwrap();
    let p = poll_one(&mut rx);
    assert_eq!(frame::parse(rx.bytes(&p)).unwrap().payload, b"after");
    assert_eq!(ExtCounters::get(&rx.counters().rx_trunc), 1);
}

#[test]
fn kernel_udp_bind_conflict_is_a_driver_error() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let rx = nic.rx_ring(&bind(0)).unwrap();
    let err = nic.rx_ring(&bind(rx.local_addr().port())).err().unwrap();
    assert!(
        matches!(
            err,
            vyrn_nic::NicError::Driver {
                backend: BackendKind::Kernel,
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn sim_clamps_and_counts_rx_ts_regressions() {
    let mut nic = SimNic::open(&cfg(BackendKind::Sim)).unwrap();
    let mut rx = nic.rx_ring(&bind(20000)).unwrap();
    let dst = rx.addr();
    for ts in [100, 300, 200, 400] {
        assert!(nic.inject(dst, &test_frame(dst, ts, 0), Nanos(ts.into())));
    }
    let mut out = [RxPkt::empty(); RX_BURST];
    assert_eq!(rx.poll(&mut out), 4);
    let ts: Vec<u64> = out[..4].iter().map(|p| p.rx_ts().0).collect();
    assert_eq!(
        ts,
        [100, 300, 300, 400],
        "the regressing stamp returns the previous one"
    );
    assert_eq!(ExtCounters::get(&rx.ext_counters().rx_ts_regress), 1);
    rx.release(4);

    // The shared clock stamps TX frames; stepping it back is clamped too.
    let mut tx = nic.tx_ring(PortId(0), TxClass::Fill).unwrap();
    let clock = nic.clock();
    clock.set(Nanos(1000));
    tx.send(&test_frame(dst, 1, 0)).unwrap();
    clock.set(Nanos(500));
    tx.send(&test_frame(dst, 2, 0)).unwrap();
    assert_eq!(rx.poll(&mut out), 2);
    assert_eq!((out[0].rx_ts(), out[1].rx_ts()), (Nanos(1000), Nanos(1000)));
    assert_eq!(ExtCounters::get(&rx.ext_counters().rx_ts_regress), 2);
}

#[test]
fn sim_faults_and_overflow_are_counters() {
    let mut c = cfg(BackendKind::Sim);
    c.rx_slots = 16;
    let mut nic = SimNic::open(&c).unwrap();
    let mut rx = nic.rx_ring(&bind(20000)).unwrap();
    let dst = rx.addr();
    let mut out = [RxPkt::empty(); RX_BURST];
    for i in 0..20 {
        nic.inject(dst, &test_frame(dst, i, 0), Nanos(0));
    }
    assert_eq!(rx.poll(&mut out), 16);
    assert_eq!(
        ExtCounters::get(&rx.counters().rx_discard),
        4,
        "a full wire discards"
    );
    assert!(!rx.counters().fatal());
    assert!(nic.fault(dst, SimFault::EvqOverflow));
    rx.release(16);
    rx.poll(&mut out);
    assert!(rx.counters().fatal(), "evq_overflow is fatal");
    assert!(!nic.fault(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1), SimFault::FatalHw));
    assert!(
        nic.rx_ring(&bind(20000)).is_err(),
        "two queues on one address"
    );
}

#[test]
fn kernel_udp_poll_is_bounded_by_dropped_datagrams_too() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let mut rx = nic.rx_ring(&bind(0)).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..3 * RX_BURST {
        peer.send_to(&[0u8; frame::MAX_PAYLOAD + 1], rx.local_addr())
            .unwrap();
    }
    let mut out = [RxPkt::empty(); RX_BURST];
    let t = Instant::now();
    while ExtCounters::get(&rx.counters().rx_trunc) == 0 {
        assert_eq!(rx.poll(&mut out), 0);
        assert!(t.elapsed() < Duration::from_secs(5), "nothing arrived");
    }
    let first = ExtCounters::get(&rx.counters().rx_trunc);
    assert!(
        first <= RX_BURST as u64,
        "one poll handled {first} > RX_BURST datagrams"
    );
}

/// Elsewhere than Linux there is no `IP_PKTINFO` path, so a wildcard bind is still refused.
#[cfg(not(target_os = "linux"))]
#[test]
fn kernel_udp_refuses_a_wildcard_bind() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let mut b = bind(0);
    b.ip = Ipv4Addr::UNSPECIFIED;
    assert!(matches!(
        nic.rx_ring(&b).err().unwrap(),
        vyrn_nic::NicError::Config {
            field: "bind.ip",
            ..
        }
    ));
}

/// The payload and `buf_id` of each frame of `ps`.
#[cfg(target_os = "linux")]
fn read(rx: &impl RxRing, ps: &[RxPkt]) -> Vec<(Vec<u8>, u32)> {
    ps.iter()
        .map(|p| {
            let f = frame::parse(rx.bytes(p)).expect("a received frame parses");
            (f.payload.to_vec(), p.buf_id())
        })
        .collect()
}

/// Polls until `n` frames have arrived, releasing each poll's frames once read.
#[cfg(target_os = "linux")]
fn drain(rx: &mut impl RxRing, n: usize) -> Vec<(Vec<u8>, u32)> {
    let mut got = Vec::new();
    let mut out = [RxPkt::empty(); RX_BURST];
    let t = Instant::now();
    while got.len() < n {
        let k = rx.poll(&mut out);
        got.extend(read(rx, &out[..k]));
        rx.release(k);
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "{} of {n} arrived",
            got.len()
        );
    }
    got
}

/// A payload unique to `i`, its length varying with `i`, so a frame read from the wrong slot or
/// cut short does not compare equal.
#[cfg(target_os = "linux")]
fn payload(i: u32) -> Vec<u8> {
    let mut p = i.to_le_bytes().to_vec();
    p.extend((0..(i as usize * 37) % 300).map(|j| (j as u32 ^ i) as u8));
    p
}

/// More datagrams than one `poll` returns, landing in bursts that start mid-ring and cross the end
/// of a 32-buffer ring: no poll returns more than `RX_BURST` or more than the free buffers, a full
/// ring returns nothing, and every datagram arrives once, whole, in order, with consecutive ids.
#[cfg(target_os = "linux")]
#[test]
fn kernel_udp_burst_bigger_than_rx_burst_wraps_the_ring() {
    let mut c = cfg(BackendKind::Kernel);
    c.rx_slots = 32;
    let mut nic = KernelUdp::open(&c).unwrap();
    let mut rx = nic.rx_ring(&bind(0)).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..5 {
        peer.send_to(&payload(i), rx.local_addr()).unwrap();
    }
    let mut all = drain(&mut rx, 5);
    let total = 3 * RX_BURST + 7;
    for i in 5..5 + total as u32 {
        peer.send_to(&payload(i), rx.local_addr()).unwrap();
    }
    // Hold every frame until the ring is full.
    let mut out = [RxPkt::empty(); RX_BURST];
    let mut held = 0;
    let t = Instant::now();
    while held < 32 {
        let k = rx.poll(&mut out);
        assert!(
            k <= RX_BURST.min(32 - held),
            "poll returned {k} frames with {held} of 32 buffers held"
        );
        all.extend(read(&rx, &out[..k]));
        held += k;
        assert!(t.elapsed() < Duration::from_secs(5), "{held} of 32 arrived");
    }
    assert_eq!(rx.poll(&mut out), 0, "a full ring returned a frame");
    rx.release(held);
    all.extend(drain(&mut rx, total - 32));
    assert_eq!(all.len(), 5 + total);
    for (i, (p, id)) in all.iter().enumerate() {
        assert_eq!(
            *p,
            payload(i as u32),
            "datagram {i} changed or out of order"
        );
        assert_eq!(*id, i as u32, "datagram {i} got buf_id {id}");
    }
    assert_eq!(ExtCounters::get(&rx.counters().rx_pkts), (5 + total) as u64);
    assert_eq!(ExtCounters::get(&rx.counters().rx_discard), 0);
}

/// Datagrams one byte over `MAX_PAYLOAD` in the middle of a burst, the kernel cutting each to its
/// buffer: each is counted in `rx_trunc` and makes no frame, and the datagrams after it in the
/// same burst arrive whole in the next buffers, with no gap in `buf_id`.
#[cfg(target_os = "linux")]
#[test]
fn kernel_udp_truncated_datagram_in_a_burst_is_a_drop() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let mut rx = nic.rx_ring(&bind(0)).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let big = vec![0xEE; frame::MAX_PAYLOAD + 1];
    let mut good = Vec::new();
    for i in 0..12u32 {
        if i % 4 == 1 {
            peer.send_to(&big, rx.local_addr()).unwrap();
        } else {
            peer.send_to(&payload(i), rx.local_addr()).unwrap();
            good.push(payload(i));
        }
    }
    let got = drain(&mut rx, good.len());
    let payloads: Vec<_> = got.iter().map(|(p, _)| p.clone()).collect();
    assert_eq!(payloads, good, "a frame after a truncated datagram changed");
    let ids: Vec<u32> = got.iter().map(|&(_, id)| id).collect();
    assert_eq!(ids, (0..good.len() as u32).collect::<Vec<_>>());
    assert_eq!(ExtCounters::get(&rx.counters().rx_trunc), 3);
    assert_eq!(ExtCounters::get(&rx.counters().rx_pkts), good.len() as u64);
    let mut out = [RxPkt::empty(); RX_BURST];
    assert_eq!(rx.poll(&mut out), 0, "a truncated datagram made a frame");
}

/// A burst the kernel takes only part of: a frame to the limited broadcast address (refused,
/// EACCES, as the socket has no SO_BROADCAST) makes `sendmmsg` stop short. `send_burst` counts it
/// in `tx_drop`, sends every frame after it in order, and counts the rest as sent, exactly as
/// calling `send` on each would. Frames that do not parse are dropped in place too.
#[cfg(target_os = "linux")]
#[test]
fn kernel_udp_send_burst_resumes_after_a_partial_send() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let mut tx = nic.tx_ring(PortId(0), TxClass::Fill).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let to = match peer.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    let refused = SocketAddrV4::new(Ipv4Addr::BROADCAST, to.port());
    // 40 frames, more than one sendmmsg takes: refused at 3 and 20 (in the second batch),
    // unparseable at 7 and 30.
    let frames: Vec<Vec<u8>> = (0..40u32)
        .map(|i| match i {
            3 | 20 => test_frame(refused, i, 8),
            7 | 30 => vec![0u8; 10],
            _ => test_frame(to, i, (i as usize * 37) % 300),
        })
        .collect();
    let refs: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    assert_eq!(
        tx.send_burst(&refs),
        40,
        "a refused frame stopped the burst"
    );
    assert_eq!(ExtCounters::get(&tx.counters().tx_pkts), 36);
    assert_eq!(ExtCounters::get(&tx.ext_counters().tx_drop), 4);
    assert_eq!(ExtCounters::get(&tx.counters().tx_full), 0);
    assert_eq!(tx.reap(), 36);
    let mut buf = [0u8; 2048];
    for i in (0..40u32).filter(|i| ![3, 7, 20, 30].contains(i)) {
        let (n, _) = peer
            .recv_from(&mut buf)
            .expect("a sent frame did not arrive");
        let want = frame::parse(&frames[i as usize]).unwrap().payload;
        assert_eq!(&buf[..n], want, "frame {i} out of order or changed");
    }
    peer.set_nonblocking(true).unwrap();
    assert!(
        peer.recv_from(&mut buf).is_err(),
        "an extra datagram arrived"
    );
}

/// A queue bound to `0.0.0.0` gives each frame the destination address its datagram was sent
/// to. Each case's destination differs from its sender's address and from `0.0.0.0`, so a frame
/// built from either fails; the broadcast case also fails `ipi_spec_dst`, which is 127.0.0.1
/// there, in place of `ipi_addr`.
#[cfg(target_os = "linux")]
#[test]
fn kernel_udp_wildcard_bind_frames_carry_each_datagrams_destination() {
    let mut nic = KernelUdp::open(&cfg(BackendKind::Kernel)).unwrap();
    let mut b = bind(0);
    b.ip = Ipv4Addr::UNSPECIFIED;
    let mut rx = nic.rx_ring(&b).unwrap();
    assert_eq!(*rx.local_addr().ip(), Ipv4Addr::UNSPECIFIED);
    let port = rx.local_addr().port();
    for (from, to) in [
        ([127, 0, 0, 2], [127, 0, 0, 1]),
        ([127, 0, 0, 1], [127, 0, 0, 2]),
        ([127, 0, 0, 1], [127, 255, 255, 255]),
    ] {
        let (from, to) = (Ipv4Addr::from(from), Ipv4Addr::from(to));
        let peer = UdpSocket::bind((from, 0)).unwrap();
        peer.set_broadcast(true).unwrap();
        peer.send_to(b"wild", (to, port)).unwrap();
        let p = poll_one(&mut rx);
        let f = frame::parse(rx.bytes(&p)).unwrap();
        assert_eq!(f.payload, b"wild");
        let peer_port = peer.local_addr().unwrap().port();
        assert_eq!((f.hdr.src.ip, f.hdr.src.port), (from, peer_port), "to {to}");
        assert_eq!((f.hdr.dst.ip, f.hdr.dst.port), (to, port), "from {from}");
        rx.release(1);
    }
    assert_eq!(ExtCounters::get(&rx.counters().rx_discard), 0);
}

/// `sys::pin_current_thread` moves the thread to the CPU it names and refuses one past
/// `CPU_SETSIZE`. Runs on a thread of its own, so the test harness thread keeps its mask.
#[cfg(target_os = "linux")]
#[test]
fn pin_current_thread_sets_the_affinity_mask() {
    std::thread::spawn(|| {
        vyrn_nic::sys::pin_current_thread(0).expect("cpu 0");
        let mask = std::fs::read_to_string("/proc/thread-self/status").expect("status");
        let line = mask
            .lines()
            .find(|l| l.starts_with("Cpus_allowed_list:"))
            .expect("Cpus_allowed_list");
        assert_eq!(line.split_whitespace().nth(1), Some("0"), "{line}");
        assert!(vyrn_nic::sys::pin_current_thread(1 << 20).is_err());
    })
    .join()
    .expect("pin thread");
}
