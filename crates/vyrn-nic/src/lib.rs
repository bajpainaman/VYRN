//! NIC backends: efvi, dpdk (Linux, C shim), kernel_udp, sim; platform calls in sys.
//!
//! The per-queue contract is `vyrn_wire::ring` (06 §6.1). This crate adds what the binary sees at
//! start: `NicBackend`, which opens the ports and hands out queues, and the types around it.
//! Every backend meets the four rules of 06 §6.1; `tests/conformance.rs` checks them against
//! each backend built here.
//!
//! `NicCounters` mirrors `vyns_counters` in shim.h, which has no field for two counters this
//! crate needs, so each queue also keeps `ExtCounters` (see there).
#![deny(unsafe_code)]
// 06 §6.1 fixes `NicError::Driver` with the shim's 160-byte message inline. Every function that
// returns it is cold-path (open, rx_ring, tx_ring), so its size costs nothing that matters.
#![allow(clippy::result_large_err)]

use core::fmt;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU64, Ordering};

use vyrn_types::LaneId;
use vyrn_wire::{RX_BURST, RxRing, TsSource, TxRing};

pub mod conformance;
pub mod frame;
pub mod kernel_udp;
mod rx_slots;
pub mod sim;

// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod ffi;
// Listed in UNSAFE.toml; the only module of this crate allowed to contain `unsafe`.
#[allow(unsafe_code)]
pub mod sys;

pub use kernel_udp::KernelUdp;
pub use sim::SimNic;

/// The backends of 06 §6. This crate builds `Kernel` (`kernel_udp`) and `Sim`; the others need
/// the C shim (Linux only) and are not built yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendKind {
    Efvi,
    DpdkMlx5,
    DpdkEna,
    AfXdp,
    Kernel,
    Sim,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Steering {
    /// The NIC delivers lane L's packets only to L's queue.
    Exact,
    /// The NIC hashes; a lane forwards foreign packets to their owner (06 §6.9).
    HashThenForward,
    /// The kernel delivers by UDP port.
    Socket,
}

/// 06 §6.8. `vyrn-seq` refuses to sequence unless the class is A, or C on AWS.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LatencyClass {
    A,
    B,
    C,
    D,
    E,
    S,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Caps {
    pub steering: Steering,
    pub ts: TsSource,
    /// CTPIO-class direct write to the wire.
    pub pio_tx: bool,
    pub max_rx_queues: u16,
    pub latency_class: LatencyClass,
}

/// One NIC port of the box, by its index in `NicConfig::ports`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, PartialOrd, Ord, Hash)]
pub struct PortId(pub u8);

/// Where one lane's receive queue listens.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RxBind {
    pub lane: LaneId,
    pub port: PortId,
    pub ip: Ipv4Addr,
    /// `PORT_BASE + lane`. 0 asks `kernel_udp` for an ephemeral port (tests only).
    pub udp_port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxClass {
    Fill,
    OrderStream,
    Control,
}

/// The clock behind a port's `rx_ts`, for vyrn-timemon (06 §8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortClock {
    /// The card's PTP hardware clock, `/dev/ptp<index>`.
    Phc { index: u32 },
    /// `CLOCK_REALTIME`, read after `recv` (`kernel_udp`).
    Realtime,
    /// The simulator's virtual time (`sim`).
    Virtual,
}

/// One port the backend opens.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PortConfig {
    pub id: PortId,
    pub ip: Ipv4Addr,
}

/// The `[nic]` section of the role config (11 §config), as `NicBackend::open` reads it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NicConfig {
    pub backend: BackendKind,
    pub ports: Vec<PortConfig>,
    /// Receive buffers per queue: a power of two from `RX_BURST` to 65536.
    pub rx_slots: usize,
    /// Transmit descriptors per queue: a power of two from 1 to 65536.
    pub tx_slots: usize,
}

impl NicConfig {
    /// 512 RX and TX slots per queue, ef_vi's ring size (06 §6.3).
    pub fn new(backend: BackendKind, ports: Vec<PortConfig>) -> Self {
        Self {
            backend,
            ports,
            rx_slots: 512,
            tx_slots: 512,
        }
    }

    /// Checks the fields every backend reads, for a backend of kind `kind`.
    fn check(&self, kind: BackendKind) -> Result<(), NicError> {
        let slots = |n: usize, min: usize| n.is_power_of_two() && (min..=65536).contains(&n);
        let config = |field, why| Err(NicError::Config { field, why });
        if self.backend != kind {
            return config(
                "nic.backend",
                "names a different backend than the one opened",
            );
        }
        if self.ports.is_empty() {
            return config("nic.ports", "is empty");
        }
        if self
            .ports
            .iter()
            .enumerate()
            .any(|(i, p)| self.ports.iter().skip(i + 1).any(|q| q.id == p.id))
        {
            return config("nic.ports", "names a port id twice");
        }
        if !slots(self.rx_slots, RX_BURST) {
            return config(
                "nic.rx_slots",
                "must be a power of two from RX_BURST to 65536",
            );
        }
        if !slots(self.tx_slots, 1) {
            return config("nic.tx_slots", "must be a power of two from 1 to 65536");
        }
        Ok(())
    }

    fn port(&self, id: PortId) -> Result<&PortConfig, NicError> {
        self.ports
            .iter()
            .find(|p| p.id == id)
            .ok_or(NicError::Config {
                field: "port",
                why: "is not in nic.ports",
            })
    }
}

/// A vendor error message of at most `VYNS_ERR_LEN` bytes, NUL-padded (06 §7.5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShimMsg(pub [u8; 160]);

impl ShimMsg {
    /// Copies `s`, cut at 160 bytes on a character boundary.
    pub fn new(s: &str) -> Self {
        let mut msg = [0u8; 160];
        let mut end = s.len().min(msg.len());
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        msg[..end].copy_from_slice(&s.as_bytes()[..end]);
        Self(msg)
    }

    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        core::str::from_utf8(&self.0[..end]).unwrap_or("<invalid utf-8>")
    }
}

impl fmt::Debug for ShimMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// A cold-path failure. Hot-path errors are counters, never this (06 §6.1 rule 2).
#[derive(Debug)]
pub enum NicError {
    Driver {
        backend: BackendKind,
        port: PortId,
        rc: i32,
        msg: ShimMsg,
    },
    Unsupported {
        backend: BackendKind,
        what: &'static str,
    },
    Config {
        field: &'static str,
        why: &'static str,
    },
    /// For example a NIC on a different NUMA node than its lanes.
    Topology { why: &'static str },
}

impl NicError {
    fn io(backend: BackendKind, port: PortId, what: &str, e: &std::io::Error) -> Self {
        Self::Driver {
            backend,
            port,
            rc: e.raw_os_error().unwrap_or(-1),
            msg: ShimMsg::new(&format!("{what}: {e}")),
        }
    }
}

impl fmt::Display for NicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Driver {
                backend,
                port,
                rc,
                msg,
            } => write!(f, "{backend:?} port {}: rc {rc}: {}", port.0, msg.as_str()),
            Self::Unsupported { backend, what } => write!(f, "{backend:?} does not support {what}"),
            Self::Config { field, why } => write!(f, "config {field} {why}"),
            Self::Topology { why } => write!(f, "topology: {why}"),
        }
    }
}

impl std::error::Error for NicError {}

/// Counters `vyns_counters` (and so `NicCounters`) has no field for. Each queue of this crate
/// keeps one, with the same single-writer rule as `NicCounters`; neither is fatal.
///
/// `NicCounters` keeps the shim's layout, which a compile-time assertion and the C side pin, so
/// these live beside it rather than in it. A backend built on the shim keeps them in Rust too:
/// the shim reports raw stamps and the Rust wrapper clamps them.
#[derive(Debug, Default)]
#[repr(C)]
pub struct ExtCounters {
    /// Stamps smaller than the queue's previous one, each delivered as the previous value
    /// (06 §6.1 rule 1). An alarm: on a PHC it means the clock stepped, which 06 §8.2 forbids.
    pub rx_ts_regress: AtomicU64,
    /// Frames `send` accepted and dropped without sending: over `frame::MAX_FRAME_BYTES`, or
    /// (`kernel_udp`) not a fast-path frame or refused by the kernel for a reason other than a
    /// full buffer. Like loss on the wire; the frame is never partly sent.
    pub tx_drop: AtomicU64,
}

impl ExtCounters {
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// A queue of this crate that keeps `ExtCounters`.
pub trait ExtCounted {
    fn ext_counters(&self) -> &ExtCounters;
}

/// One NIC backend, picked once at start (06 §6.1). Cold path only.
///
/// Rule 4: a backend opens its devices before the hot threads start, and each queue is created
/// by its owner thread before `seal()`.
pub trait NicBackend: Sized {
    type Rx: RxRing + ExtCounted;
    type Tx: TxRing + ExtCounted;
    const KIND: BackendKind;
    /// Opens every port in `cfg`; every failure comes back as `NicError`.
    fn open(cfg: &NicConfig) -> Result<Self, NicError>;
    fn caps(&self) -> Caps;
    fn rx_ring(&mut self, bind: &RxBind) -> Result<Self::Rx, NicError>;
    fn tx_ring(&mut self, port: PortId, class: TxClass) -> Result<Self::Tx, NicError>;
    /// The clock behind this port's timestamps, for vyrn-timemon (06 §8).
    fn port_clock(&self, port: PortId) -> Result<PortClock, NicError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NicConfig {
        NicConfig::new(
            BackendKind::Sim,
            vec![PortConfig {
                id: PortId(0),
                ip: Ipv4Addr::LOCALHOST,
            }],
        )
    }

    #[test]
    fn config_checks() {
        assert!(cfg().check(BackendKind::Sim).is_ok());
        assert!(cfg().check(BackendKind::Kernel).is_err());
        let mut c = cfg();
        c.ports.push(c.ports[0]);
        assert!(c.check(BackendKind::Sim).is_err(), "duplicate port id");
        for (rx, tx, ok) in [(16, 1, true), (8, 1, false), (24, 8, false), (16, 0, false)] {
            let mut c = cfg();
            (c.rx_slots, c.tx_slots) = (rx, tx);
            assert_eq!(c.check(BackendKind::Sim).is_ok(), ok, "rx {rx} tx {tx}");
        }
        assert!(cfg().port(PortId(1)).is_err());
    }

    #[test]
    fn shim_msg_cuts_on_a_char_boundary() {
        let s = "é".repeat(100); // 200 bytes
        let m = ShimMsg::new(&s);
        assert_eq!(m.as_str(), "é".repeat(80));
        assert_eq!(ShimMsg::new("abc").as_str(), "abc");
    }
}
