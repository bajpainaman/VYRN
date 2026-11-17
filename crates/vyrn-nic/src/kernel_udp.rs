//! `kernel`: UDP sockets on Linux and macOS (06 §6.6). For DEV, CI and tests; latency class E.
//!
//! One non-blocking `std::net::UdpSocket` per queue. `poll` reads up to `RX_BURST` datagrams and
//! gives each one the fast-path headers (06 §6.2) it would have had on the wire: the
//! sender's address and port as the source, the queue's as the destination, zero MACs. So a lane
//! parses `kernel_udp` frames exactly as it parses NIC frames. `send` takes a fast-path frame and
//! sends its payload to the frame's destination address and port.
//!
//! `rx_ts` is `CLOCK_REALTIME` read right after the datagram is received (`TsSource::Kernel`);
//! on Linux, one read right after the `recvmmsg` stamps its whole burst. That clock can step
//! backwards, so the clamp of 06 §6.1 rule 1 matters here.
//!
//! On Linux, `poll` takes its burst with one `recvmmsg`, and `send_burst` sends up to `RX_BURST`
//! frames with one `sendmmsg` (06 §6.6, wrappers in `sys`). `TxRing::send` is a burst of one.
//! Other targets use std's one-datagram calls, which meet the same contract. `SO_BUSY_POLL`,
//! `SO_TIMESTAMPING` and `kqueue` are not used yet.

use core::net::{SocketAddr, SocketAddrV4};
use std::io::ErrorKind;
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

use vyrn_types::Nanos;
use vyrn_wire::{NicCounters, RX_BURST, RxFlags, RxPkt, RxRing, TsSource, TxFull, TxRing};

use crate::frame::{self, Endpoint, FrameHdr, HDR_BYTES};
use crate::rx_slots::RxSlots;
#[cfg(target_os = "linux")]
use crate::sys;
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
    /// A wildcard address is refused: each frame's destination IP is the bound one, and
    /// `0.0.0.0` would not say which address the datagram arrived on.
    fn rx_ring(&mut self, bind: &RxBind) -> Result<KernelRx, NicError> {
        self.cfg.port(bind.port)?;
        if bind.ip.is_unspecified() {
            return Err(NicError::Config {
                field: "bind.ip",
                why: "must be a specific address for kernel_udp, not 0.0.0.0",
            });
        }
        let sock = socket(bind.port, SocketAddrV4::new(bind.ip, bind.udp_port))?;
        let local = local_v4(&sock, bind.port)?;
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

impl KernelRx {
    /// Writes the fast-path headers of an `n`-byte datagram from `src` in front of its payload,
    /// which is already in the next slot, and publishes the frame.
    fn deliver(&mut self, src: SocketAddrV4, n: usize, ts: Nanos) -> Option<RxPkt> {
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
        let buf = self.slots.next_buf();
        let head: &mut [u8; HDR_BYTES] = (&mut buf[..HDR_BYTES])
            .try_into()
            .unwrap_or_else(|_| unreachable!());
        // n <= MAX_PAYLOAD, so never `None`.
        frame::write_header(&hdr, n, head).ok()?;
        let len = (HDR_BYTES + n) as u16;
        Some(
            self.slots
                .commit(len, RxFlags(0), ts, &self.counters, &self.ext),
        )
    }
}

impl RxRing for KernelRx {
    /// Datagrams over `MAX_PAYLOAD` are counted in `rx_trunc` and dropped; IPv6 senders and
    /// socket errors other than "empty" in `rx_discard`. At most `RX_BURST` datagrams per `poll`,
    /// dropped ones included, so a flood of bad ones cannot hold the caller: on Linux one
    /// `recvmmsg` for up to `RX_BURST` (fewer when fewer buffers are free), elsewhere at most
    /// `RX_BURST` receive calls.
    #[cfg(target_os = "linux")]
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize {
        let want = self.slots.free().min(RX_BURST);
        if want == 0 {
            return 0;
        }
        let mut got = [sys::Recvd::default(); sys::BATCH];
        // Each buffer ends at MAX_PAYLOAD, so the kernel flags any longer datagram MSG_TRUNC.
        let bufs = (self.slots.next_bufs(want)).map(|b| &mut b[HDR_BYTES..frame::MAX_FRAME_BYTES]);
        let n = match sys::recv_batch(self.sock.as_raw_fd(), bufs, &mut got) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
                return 0;
            }
            Err(_) => {
                NicCounters::add(&self.counters.rx_discard, 1);
                return 0;
            }
        };
        let ts = realtime();
        let mut k = 0;
        for (i, d) in got[..n].iter().enumerate() {
            let Some(src) = d.src else {
                NicCounters::add(&self.counters.rx_discard, 1);
                continue;
            };
            if d.trunc {
                NicCounters::add(&self.counters.rx_trunc, 1);
                continue;
            }
            // Datagram i landed i slots past the start; after a drop, move it up to the next.
            if i > k {
                self.slots.pull(i - k, HDR_BYTES + d.len);
            }
            if let Some(p) = self.deliver(src, d.len, ts) {
                out[k] = p;
                k += 1;
            }
        }
        k
    }

    #[cfg(not(target_os = "linux"))]
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize {
        let mut got = 0;
        for _ in 0..RX_BURST {
            if self.slots.free() == 0 {
                break;
            }
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
            if let Some(p) = self.deliver(src, n, ts) {
                out[got] = p;
                got += 1;
            }
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

    /// Sends `frames` in order, exactly as calling `send` on each until one returns `TxFull`
    /// would, and returns how many it took. Each frame taken was sent (`tx_pkts`) or dropped and
    /// counted (`tx_drop`). Fewer than `frames.len()` means `frames[taken]` met a full socket
    /// buffer, counted in `tx_full`; the caller reaps and sends the rest again. On Linux that is
    /// one `sendmmsg` per `RX_BURST` frames, plus one more after each frame the kernel refuses.
    pub fn send_burst(&mut self, frames: &[&[u8]]) -> usize {
        #[cfg(target_os = "linux")]
        {
            let mut taken = 0;
            while taken < frames.len() {
                match self.send_batch(&frames[taken..]) {
                    Ok(n) => taken += n,
                    Err(n) => return taken + n,
                }
            }
            taken
        }
        #[cfg(not(target_os = "linux"))]
        {
            frames.iter().take_while(|f| self.send(f).is_ok()).count()
        }
    }

    /// Counts the frames from `*taken` up to `to` as dropped and moves `taken` past them.
    #[cfg(target_os = "linux")]
    fn drop_to(&self, taken: &mut usize, to: usize) {
        NicCounters::add(&self.ext.tx_drop, (to - *taken) as u64);
        *taken = to;
    }

    /// Sends the fast-path frames among the first `sys::BATCH` of `frames` with as few
    /// `sendmmsg` calls as the kernel allows. `Ok(n)`: `n` frames taken, at least one. `Err(n)`:
    /// `n` taken, then a full socket buffer at `frames[n]`.
    #[cfg(target_os = "linux")]
    fn send_batch(&mut self, frames: &[&[u8]]) -> Result<usize, usize> {
        let none = SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0);
        let mut msgs: [(&[u8], SocketAddrV4); sys::BATCH] = [(&[], none); sys::BATCH];
        // The index in `frames` of each message.
        let mut at = [0usize; sys::BATCH];
        let mut m = 0;
        let scanned = frames.len().min(sys::BATCH);
        for (i, f) in frames[..scanned].iter().enumerate() {
            if let Ok(p) = frame::parse(f) {
                msgs[m] = (p.payload, SocketAddrV4::new(p.hdr.dst.ip, p.hdr.dst.port));
                at[m] = i;
                m += 1;
            }
        }
        let (mut taken, mut x) = (0, 0);
        while x < m {
            match sys::send_batch(self.sock.as_raw_fd(), &msgs[x..m]) {
                // sendmmsg returns 0 only for an empty batch, which this is not.
                Ok(k) => {
                    let k = k.clamp(1, m - x);
                    self.drop_to(&mut taken, at[x + k - 1] + 1 - k);
                    taken += k;
                    x += k;
                    NicCounters::add(&self.counters.tx_pkts, k as u64);
                    self.done += k;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // ENOBUFS is how Linux and macOS report a full interface queue.
                Err(e) if e.kind() == ErrorKind::WouldBlock || is_enobufs(&e) => {
                    self.drop_to(&mut taken, at[x]);
                    NicCounters::add(&self.counters.tx_full, 1);
                    return Err(taken);
                }
                // The kernel refused this one datagram; the next call sends from the one after.
                Err(_) => {
                    self.drop_to(&mut taken, at[x] + 1);
                    x += 1;
                }
            }
        }
        self.drop_to(&mut taken, scanned);
        Ok(taken)
    }
}

impl TxRing for KernelTx {
    /// Sends the payload of a fast-path frame to its destination. The kernel takes a datagram
    /// whole or not at all. A full socket buffer is `TxFull`; a frame that does not parse, or
    /// that the kernel refuses for any other reason, is dropped and counted (`tx_drop`).
    #[cfg(target_os = "linux")]
    fn send(&mut self, frame: &[u8]) -> Result<(), TxFull> {
        if self.send_burst(&[frame]) == 1 {
            Ok(())
        } else {
            Err(TxFull)
        }
    }

    #[cfg(not(target_os = "linux"))]
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
