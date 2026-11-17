//! `sim`: in-memory queues for `vyrn-sim` and benches (06 §6.7). `rx_ts` is virtual time.
//!
//! Each RX queue has a preallocated wire of `rx_slots` frames between the senders and the
//! queue. A `SimTx` delivers a fast-path frame to the queue bound to its destination IPv4 and
//! UDP port, stamped with the shared `SimClock`. The simulator can also put a frame on a wire
//! with any stamp (`SimNic::inject`, for regressions and preloading) and raise the fatal counters
//! (`SimNic::fault`). Nothing allocates after `rx_ring`/`tx_ring`, and nothing makes a syscall:
//! the per-wire `Mutex` is only ever taken by one thread at a time in `vyrn-sim`, so it never
//! waits.
//!
//! Faults the simulator injects by choosing what to send (loss, duplication, reordering between
//! queues, delay) need nothing here.

use core::net::SocketAddrV4;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vyrn_types::Nanos;
use vyrn_wire::{NicCounters, RX_BURST, RxFlags, RxPkt, RxRing, TsSource, TxFull, TxRing};

use crate::rx_slots::{RxSlots, SLOT_BYTES};
use crate::{
    BackendKind, Caps, ExtCounted, ExtCounters, LatencyClass, NicBackend, NicConfig, NicError,
    PortClock, PortId, RxBind, Steering, TxClass, frame,
};

/// The simulator's virtual time, shared by every queue of one `SimNic`.
#[derive(Clone, Debug, Default)]
pub struct SimClock(Arc<AtomicU64>);

impl SimClock {
    pub fn now(&self) -> Nanos {
        Nanos(self.0.load(Ordering::Relaxed))
    }

    /// Sets the time. Going backwards is allowed: queues clamp and count it (`rx_ts_regress`).
    pub fn set(&self, t: Nanos) {
        self.0.store(t.0, Ordering::Relaxed);
    }

    pub fn advance(&self, ns: u64) {
        self.set(Nanos(self.now().0.saturating_add(ns)));
    }
}

/// A fatal event the simulator raises on one RX queue (06 §6.1 rule 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SimFault {
    EvqOverflow,
    FatalHw,
}

/// Frames between the senders and one RX queue.
struct Wire {
    buf: Box<[u8]>,
    lens: Box<[u16]>,
    ts: Box<[Nanos]>,
    head: usize,
    count: usize,
    /// Frames that found the wire full, for the queue's `rx_discard`.
    discarded: u64,
    evq_overflow: u64,
    fatal_hw: u64,
}

impl Wire {
    fn new(n: usize) -> Self {
        Self {
            buf: vec![0; n * SLOT_BYTES].into_boxed_slice(),
            lens: vec![0; n].into_boxed_slice(),
            ts: vec![Nanos(0); n].into_boxed_slice(),
            head: 0,
            count: 0,
            discarded: 0,
            evq_overflow: 0,
            fatal_hw: 0,
        }
    }

    /// `frame` is at most `MAX_FRAME_BYTES`.
    fn push(&mut self, frame: &[u8], ts: Nanos) -> bool {
        let n = self.lens.len();
        if self.count == n {
            self.discarded += 1;
            return false;
        }
        let slot = (self.head + self.count) % n;
        self.buf[slot * SLOT_BYTES..][..frame.len()].copy_from_slice(frame);
        self.lens[slot] = frame.len() as u16;
        self.ts[slot] = ts;
        self.count += 1;
        true
    }
}

type SharedWire = Arc<Mutex<Wire>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere cannot leave a wire half-written: every write completes before unlock.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The virtual network of one `SimNic`: RX queues by destination address.
type Routes = Arc<Mutex<Vec<(SocketAddrV4, SharedWire)>>>;

fn route(routes: &Routes, dst: SocketAddrV4) -> Option<SharedWire> {
    lock(routes)
        .iter()
        .find(|(a, _)| *a == dst)
        .map(|(_, w)| Arc::clone(w))
}

pub struct SimNic {
    cfg: NicConfig,
    clock: SimClock,
    routes: Routes,
}

impl SimNic {
    pub fn clock(&self) -> SimClock {
        self.clock.clone()
    }

    /// Puts `frame` on the wire of the queue bound to `dst`, stamped `ts`, as if it had arrived
    /// then. Returns false if no queue is bound there, the frame is over `MAX_FRAME_BYTES`, or
    /// the wire is full (counted as the queue's `rx_discard`).
    pub fn inject(&self, dst: SocketAddrV4, frame: &[u8], ts: Nanos) -> bool {
        if frame.len() > frame::MAX_FRAME_BYTES {
            return false;
        }
        route(&self.routes, dst).is_some_and(|w| lock(&w).push(frame, ts))
    }

    /// Raises `fault` on the queue bound to `dst`; its next `poll` counts it. False if none is.
    pub fn fault(&self, dst: SocketAddrV4, fault: SimFault) -> bool {
        let Some(w) = route(&self.routes, dst) else {
            return false;
        };
        let mut w = lock(&w);
        match fault {
            SimFault::EvqOverflow => w.evq_overflow += 1,
            SimFault::FatalHw => w.fatal_hw += 1,
        }
        true
    }
}

impl NicBackend for SimNic {
    type Rx = SimRx;
    type Tx = SimTx;
    const KIND: BackendKind = BackendKind::Sim;

    fn open(cfg: &NicConfig) -> Result<Self, NicError> {
        cfg.check(Self::KIND)?;
        Ok(Self {
            cfg: cfg.clone(),
            clock: SimClock::default(),
            routes: Arc::default(),
        })
    }

    fn caps(&self) -> Caps {
        Caps {
            steering: Steering::Exact,
            ts: TsSource::Virtual,
            pio_tx: false,
            max_rx_queues: u16::MAX,
            latency_class: LatencyClass::S,
        }
    }

    fn rx_ring(&mut self, bind: &RxBind) -> Result<SimRx, NicError> {
        self.cfg.port(bind.port)?;
        let addr = SocketAddrV4::new(bind.ip, bind.udp_port);
        let mut routes = lock(&self.routes);
        if routes.iter().any(|(a, _)| *a == addr) {
            return Err(NicError::Config {
                field: "bind",
                why: "another sim queue is bound to this address",
            });
        }
        let wire = Arc::new(Mutex::new(Wire::new(self.cfg.rx_slots)));
        routes.push((addr, Arc::clone(&wire)));
        Ok(SimRx {
            wire,
            slots: RxSlots::new(self.cfg.rx_slots),
            counters: NicCounters::new(),
            ext: ExtCounters::default(),
            addr,
        })
    }

    fn tx_ring(&mut self, port: PortId, _class: TxClass) -> Result<SimTx, NicError> {
        self.cfg.port(port)?;
        Ok(SimTx {
            routes: Arc::clone(&self.routes),
            clock: self.clock.clone(),
            slots: self.cfg.tx_slots,
            in_flight: 0,
            counters: NicCounters::new(),
            ext: ExtCounters::default(),
        })
    }

    fn port_clock(&self, port: PortId) -> Result<PortClock, NicError> {
        self.cfg.port(port).map(|_| PortClock::Virtual)
    }
}

pub struct SimRx {
    wire: SharedWire,
    slots: RxSlots,
    counters: NicCounters,
    ext: ExtCounters,
    addr: SocketAddrV4,
}

impl SimRx {
    /// The address this queue is bound to.
    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

impl RxRing for SimRx {
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize {
        let mut w = lock(&self.wire);
        for (n, c) in [
            (core::mem::take(&mut w.discarded), &self.counters.rx_discard),
            (
                core::mem::take(&mut w.evq_overflow),
                &self.counters.evq_overflow,
            ),
            (core::mem::take(&mut w.fatal_hw), &self.counters.fatal_hw),
        ] {
            if n != 0 {
                NicCounters::add(c, n);
            }
        }
        let take = w.count.min(self.slots.free()).min(RX_BURST);
        let n = w.lens.len();
        for o in out.iter_mut().take(take) {
            let slot = w.head;
            let len = w.lens[slot];
            let src = &w.buf[slot * SLOT_BYTES..][..usize::from(len)];
            self.slots.next_buf()[..src.len()].copy_from_slice(src);
            *o = self
                .slots
                .commit(len, RxFlags(0), w.ts[slot], &self.counters, &self.ext);
            w.head = (slot + 1) % n;
            w.count -= 1;
        }
        take
    }

    fn release(&mut self, n: usize) {
        self.slots.release(n);
    }

    fn bytes<'a>(&'a self, p: &'a RxPkt) -> &'a [u8] {
        self.slots.bytes(p)
    }

    fn ts_source(&self) -> TsSource {
        TsSource::Virtual
    }

    fn counters(&self) -> &NicCounters {
        &self.counters
    }
}

impl ExtCounted for SimRx {
    fn ext_counters(&self) -> &ExtCounters {
        &self.ext
    }
}

pub struct SimTx {
    routes: Routes,
    clock: SimClock,
    slots: usize,
    in_flight: usize,
    counters: NicCounters,
    ext: ExtCounters,
}

impl TxRing for SimTx {
    /// A frame takes a descriptor until `reap`. One that is over `MAX_FRAME_BYTES` or not a
    /// fast-path frame is dropped and counted (`tx_drop`); one addressed to no queue is sent
    /// and lost, like a frame to a host that is not listening.
    fn send(&mut self, frame: &[u8]) -> Result<(), TxFull> {
        if self.in_flight == self.slots {
            NicCounters::add(&self.counters.tx_full, 1);
            return Err(TxFull);
        }
        let Ok(p) = frame::parse(frame) else {
            NicCounters::add(&self.ext.tx_drop, 1);
            return Ok(());
        };
        self.in_flight += 1;
        let dst = SocketAddrV4::new(p.hdr.dst.ip, p.hdr.dst.port);
        if let Some(w) = route(&self.routes, dst) {
            lock(&w).push(frame, self.clock.now());
        }
        NicCounters::add(&self.counters.tx_pkts, 1);
        Ok(())
    }

    fn reap(&mut self) -> usize {
        core::mem::take(&mut self.in_flight)
    }

    fn counters(&self) -> &NicCounters {
        &self.counters
    }
}

impl ExtCounted for SimTx {
    fn ext_counters(&self) -> &ExtCounters {
        &self.ext
    }
}
