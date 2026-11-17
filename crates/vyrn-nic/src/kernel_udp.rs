//! `kernel`: UDP sockets on Linux and macOS (06 §6.6). For DEV, CI and tests; latency class E.
//!
//! One non-blocking `std::net::UdpSocket` per queue. `poll` reads datagrams until the socket is
//! empty and gives each one the fast-path headers (06 §6.2) it would have had on the wire: the
//! sender's address and port as the source, the queue's as the destination, zero MACs. So a lane
//! parses `kernel_udp` frames exactly as it parses NIC frames. `send` takes a fast-path frame and
//! sends its payload to the frame's destination address and port.
//!
//! `rx_ts` is `CLOCK_REALTIME` read right after the datagram is received (`TsSource::Kernel`).
//! That clock can step backwards, so the clamp of 06 §6.1 rule 1 matters here.
//!
//! The spec's `recvmmsg`/`sendmmsg` with `SO_BUSY_POLL` (Linux) and `kqueue` (macOS) are not
//! used yet; std's one-datagram calls meet the same contract.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use vyrn_types::Nanos;
use vyrn_wire::{NicCounters, RX_BURST, RxFlags, RxPkt, RxRing, TsSource, TxFull, TxRing};

use crate::frame::{self, Endpoint, FrameHdr, HDR_BYTES};
use crate::rx_slots::RxSlots;
use crate::{
    BackendKind, Caps, ExtCounted, ExtCounters, LatencyClass, NicBackend, NicConfig, NicError,
    PortClock, PortId, RxBind, Steering, TxClass,
};

pub struct KernelUdp {
    cfg: NicConfig,
}

const KIND: BackendKind = BackendKind::Kernel;

fn socket(port: PortId, addr: SocketAddrV4) -> Result<UdpSocket, NicError> {
    let s = UdpSocket::bind(addr).map_err(|e| NicError::io(KIND, port, "bind", &e))?;
    s.set_nonblocking(true)
        .map_err(|e| NicError::io(KIND, port, "set_nonblocking", &e))?;
    Ok(s)
}

fn local_v4(s: &UdpSocket, port: PortId) -> Result<SocketAddrV4, NicError> {
    match s.local_addr() {
        Ok(SocketAddr::V4(a)) => Ok(a),
        Ok(SocketAddr::V6(_)) => Err(NicError::Unsupported {
            backend: KIND,
            what: "IPv6",
        }),
        Err(e) => Err(NicError::io(KIND, port, "local_addr", &e)),
    }
}

impl NicBackend for KernelUdp {
    type Rx = KernelRx;
    type Tx = KernelTx;
    const KIND: BackendKind = KIND;

    fn open(cfg: &NicConfig) -> Result<Self, NicError> {
        cfg.check(Self::KIND)?;
        Ok(Self { cfg: cfg.clone() })
    }

    fn caps(&self) -> Caps {
        Caps {
            steering: Steering::Socket,
            ts: TsSource::Kernel,
            pio_tx: false,
            max_rx_queues: u16::MAX,
            latency_class: LatencyClass::E,
        }
    }

    /// Binds `bind.ip:bind.udp_port`. Port 0 picks a free port; `KernelRx::local_addr` names it.
    fn rx_ring(&mut self, bind: &RxBind) -> Result<KernelRx, NicError> {
        self.cfg.port(bind.port)?;
        let sock = socket(bind.port, SocketAddrV4::new(bind.ip, bind.udp_port))?;
        let mut local = local_v4(&sock, bind.port)?;
        if local.ip().is_unspecified() {
            // The frame needs one destination address; an unspecified bind reports loopback.
            local.set_ip(Ipv4Addr::LOCALHOST);
        }
        Ok(KernelRx {
            sock,
            local,
            slots: RxSlots::new(self.cfg.rx_slots),
            counters: NicCounters::new(),
            ext: ExtCounters::default(),
        })
    }

    /// Binds an ephemeral port on the port's address.
    fn tx_ring(&mut self, port: PortId, _class: TxClass) -> Result<KernelTx, NicError> {
        let ip = self.cfg.port(port)?.ip;
        let sock = socket(port, SocketAddrV4::new(ip, 0))?;
        let local = local_v4(&sock, port)?;
        Ok(KernelTx {
            sock,
            local,
            done: 0,
            counters: NicCounters::new(),
            ext: ExtCounters::default(),
        })
    }

    fn port_clock(&self, port: PortId) -> Result<PortClock, NicError> {
        self.cfg.port(port).map(|_| PortClock::Realtime)
    }
}

fn realtime() -> Nanos {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Nanos(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

pub struct KernelRx {
    sock: UdpSocket,
    local: SocketAddrV4,
    slots: RxSlots,
    counters: NicCounters,
    ext: ExtCounters,
}

impl KernelRx {
    /// The address senders reach this queue at, and the destination of its frames.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }
}

impl RxRing for KernelRx {
    /// Datagrams over `MAX_PAYLOAD` are counted in `rx_trunc` and dropped; IPv6 senders and
    /// socket errors other than "empty" in `rx_discard`.
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize {
        let mut got = 0;
        while got < RX_BURST && self.slots.free() > 0 {
            let buf = self.slots.next_buf();
            // The slot has room past MAX_PAYLOAD, so an oversize datagram shows as one.
            let (n, src) = match self.sock.recv_from(&mut buf[HDR_BYTES..]) {
                Ok((n, SocketAddr::V4(src))) => (n, src),
                Ok((_, SocketAddr::V6(_))) => {
                    NicCounters::add(&self.counters.rx_discard, 1);
                    continue;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    NicCounters::add(&self.counters.rx_discard, 1);
                    break;
                }
            };
            let ts = realtime();
            if n > frame::MAX_PAYLOAD {
                NicCounters::add(&self.counters.rx_trunc, 1);
                continue;
            }
            let hdr = FrameHdr {
                src: Endpoint {
                    mac: [0; 6],
                    ip: *src.ip(),
                    port: src.port(),
                },
                dst: Endpoint {
                    mac: [0; 6],
                    ip: *self.local.ip(),
                    port: self.local.port(),
                },
            };
            let head: &mut [u8; HDR_BYTES] = (&mut buf[..HDR_BYTES])
                .try_into()
                .unwrap_or_else(|_| unreachable!());
            if frame::write_header(&hdr, n, head).is_err() {
                continue; // n <= MAX_PAYLOAD, so never taken
            }
            let len = (HDR_BYTES + n) as u16;
            out[got] = self
                .slots
                .commit(len, RxFlags(0), ts, &self.counters, &self.ext);
            got += 1;
        }
        got
    }

    fn release(&mut self, n: usize) {
        self.slots.release(n);
    }

    fn bytes<'a>(&'a self, p: &'a RxPkt) -> &'a [u8] {
        self.slots.bytes(p)
    }

    fn ts_source(&self) -> TsSource {
        TsSource::Kernel
    }

    fn counters(&self) -> &NicCounters {
        &self.counters
    }
}

impl ExtCounted for KernelRx {
    fn ext_counters(&self) -> &ExtCounters {
        &self.ext
    }
}

pub struct KernelTx {
    sock: UdpSocket,
    local: SocketAddrV4,
    /// Sends since the last `reap`.
    done: usize,
    counters: NicCounters,
    ext: ExtCounters,
}

impl KernelTx {
    /// The source address of every datagram this queue sends.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }
}

impl TxRing for KernelTx {
    /// Sends the payload of a fast-path frame to its destination. The kernel takes a datagram
    /// whole or not at all. A full socket buffer is `TxFull`; a frame that does not parse, or
    /// that the kernel refuses for any other reason, is dropped and counted (`tx_drop`).
    fn send(&mut self, frame: &[u8]) -> Result<(), TxFull> {
        let Ok(p) = frame::parse(frame) else {
            NicCounters::add(&self.ext.tx_drop, 1);
            return Ok(());
        };
        let dst = SocketAddrV4::new(p.hdr.dst.ip, p.hdr.dst.port);
        loop {
            match self.sock.send_to(p.payload, dst) {
                Ok(n) if n == p.payload.len() => {
                    NicCounters::add(&self.counters.tx_pkts, 1);
                    self.done += 1;
                    return Ok(());
                }
                Ok(_) => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // ENOBUFS is how Linux and macOS report a full interface queue.
                Err(e) if e.kind() == ErrorKind::WouldBlock || is_enobufs(&e) => {
                    NicCounters::add(&self.counters.tx_full, 1);
                    return Err(TxFull);
                }
                Err(_) => break,
            }
        }
        NicCounters::add(&self.ext.tx_drop, 1);
        Ok(())
    }

    fn reap(&mut self) -> usize {
        core::mem::take(&mut self.done)
    }

    fn counters(&self) -> &NicCounters {
        &self.counters
    }
}

fn is_enobufs(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOBUFS)
}

impl ExtCounted for KernelTx {
    fn ext_counters(&self) -> &ExtCounters {
        &self.ext
    }
}
