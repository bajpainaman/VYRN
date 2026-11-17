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
