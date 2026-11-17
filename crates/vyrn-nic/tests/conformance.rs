//! The conformance suite (`vyrn_nic::conformance`) against every backend this crate builds.

use core::net::{Ipv4Addr, SocketAddrV4};

use vyrn_nic::conformance::{self, Harness};
use vyrn_nic::kernel_udp::KernelRx;
use vyrn_nic::sim::SimRx;
use vyrn_nic::{BackendKind, KernelUdp, NicConfig, PortConfig, PortId, RxBind, SimNic};
use vyrn_types::LaneId;

fn config(kind: BackendKind, rx_slots: usize, tx_slots: usize) -> NicConfig {
    let mut c = NicConfig::new(
        kind,
        vec![PortConfig {
            id: PortId(0),
            ip: Ipv4Addr::LOCALHOST,
        }],
    );
    (c.rx_slots, c.tx_slots) = (rx_slots, tx_slots);
    c
}

struct Sim;

impl Harness for Sim {
    type Nic = SimNic;
    fn config(rx_slots: usize, tx_slots: usize) -> NicConfig {
        config(BackendKind::Sim, rx_slots, tx_slots)
    }
    fn bind(i: u16) -> RxBind {
        RxBind {
            lane: LaneId(i as u8),
            port: PortId(0),
            ip: Ipv4Addr::LOCALHOST,
            udp_port: 20000 + i,
        }
    }
    fn dest(rx: &SimRx) -> SocketAddrV4 {
        rx.addr()
    }
}

struct Kernel;

impl Harness for Kernel {
    type Nic = KernelUdp;
    fn config(rx_slots: usize, tx_slots: usize) -> NicConfig {
        config(BackendKind::Kernel, rx_slots, tx_slots)
    }
    /// Ephemeral ports, so parallel tests never collide.
    fn bind(i: u16) -> RxBind {
        RxBind {
            lane: LaneId(i as u8),
            port: PortId(0),
            ip: Ipv4Addr::LOCALHOST,
            udp_port: 0,
        }
    }
    fn dest(rx: &KernelRx) -> SocketAddrV4 {
        rx.local_addr()
    }
}

macro_rules! suite {
    ($m:ident, $h:ty) => {
        mod $m {
            use super::*;
            #[test]
            fn arrival_order() {
                conformance::arrival_order::<$h>();
            }
            #[test]
            fn errors_are_counters() {
                conformance::errors_are_counters::<$h>();
            }
            #[test]
            fn whole_frame_or_full() {
                conformance::whole_frame_or_full::<$h>();
            }
            #[test]
            fn release_order() {
                conformance::release_order::<$h>();
            }
            #[test]
            fn forged_descriptors() {
                conformance::forged_descriptors::<$h>();
            }
        }
    };
}

suite!(sim, Sim);
suite!(kernel_udp, Kernel);
