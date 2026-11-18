//! One data box over a `vyrn-nic` backend: the ingest queue, the fetch queue, one TX queue, the
//! fan-out to every destination (07 §5.2 step 6, §5.3), and fetch serving from the RAM ring and
//! a [`BlockStore`] (crate docs, § Fetch).
//!
//! The node is single-threaded: its owner calls [`DataNode::poll`] in its loop with the time.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use vyrn_log::BlockStore;
use vyrn_nic::frame::{self as nic_frame, Endpoint};
use vyrn_types::{BookId, MAX_MSGS_PER_PKT, MSG_BYTES, Nanos, PKT_HDR_BYTES, SessionId, TAG_BYTES};
use vyrn_wire::{RX_BURST, RxPkt, RxRing, TxRing};

use crate::frame::{Fetch, FetchMsg, MAX_BATCH};
use crate::ingest::{DataHome, Event, HomeConfig, Reject};
use crate::redirect::Redirect;
use crate::serve::{Fanout, Gate, Pending, Responder, send_or_queue, send_redirect};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub home: HomeConfig,
    /// This box's index, the `src` of its frames.
    pub src: u8,
    /// This box's address, the source of every frame it builds.
    pub me: Endpoint,
    /// Every voter and the warm standby (07 §5.1), in data-frame `dst` order.
    pub dests: Vec<Endpoint>,
    /// `REP_DATA_BATCH_US` = 5 µs.
    pub batch_ns: u64,
    /// The idle time before a `DATA_HB`: 100 µs.
    pub hb_ns: u64,
    /// `DATA` frames kept per destination for RANGE fetches.
    pub history: usize,
    /// The most frames one RANGE fetch may ask for.
    pub max_range: u64,
    /// How many of the newest logged blocks a KEY fetch searches after missing the ring.
    pub log_scan: u64,
    /// Events kept until drained; more are counted in `events_dropped`.
    pub max_events: usize,
    /// `K_fetch` per requester address (crate docs, § Fetch). Empty: open mode, plain fetches
    /// from anyone, under one shared rate limit (DEV and tests). Otherwise only these sources are
    /// served, and only in the authenticated form: the request, then an 8-byte tag over all of
    /// it (40 bytes for kinds 1 to 4; 16 + 8n + 8 for an n-entry REDIRECT_BATCH,
    /// [`RedirectBatch`](crate::frame::RedirectBatch)).
    pub fetch_keys: BTreeMap<Ipv4Addr, [u8; 16]>,
    /// The epoch `fetch_keys` are for. [`DataNode::set_fetch_keys`] adds the next one.
    pub fetch_epoch: u32,
    /// Fetches per second each source may send, refilled continuously.
    pub fetch_rate: u64,
    /// The most fetches a source may send at once after being idle.
    pub fetch_burst: u64,
    /// The box-wide budget for KEY, BLOCK and RANGE fetches (kinds 1 to 3), per second, charged
    /// after the source's own bucket; a fetch over it is shed (`fetch_shed`). REDIRECTs (kinds 4
    /// and 5) are not charged: a full queue paces them instead.
    pub fetch_box_rate: u64,
    /// The most such fetches the box takes at once after being idle.
    pub fetch_box_burst: u64,
}

impl NodeConfig {
    /// 07's timers and modest buffers.
    pub fn new(home: HomeConfig, src: u8, me: Endpoint, dests: Vec<Endpoint>) -> Self {
        Self {
            home,
            src,
            me,
            dests,
            batch_ns: 5_000,
            hb_ns: 100_000,
            history: 1024,
            max_range: 256,
            log_scan: 64,
            max_events: 1024,
            fetch_keys: BTreeMap::new(),
            fetch_epoch: 0,
            fetch_rate: 20_000,
            fetch_burst: 256,
            fetch_box_rate: 100_000,
            fetch_box_burst: 1024,
        }
    }
}

/// Every drop and every frame, by cause. One writer, the node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub rx_pkts: u64,
    /// Not a fast-path frame (06 §6.2).
    pub bad_frame: u64,
    pub header: u64,
    pub book: u64,
    pub unknown_session: u64,
    /// A copy whose `epoch16` is neither epoch this home serves (08 §4.6).
    pub epoch: u64,
    pub bad_mac: u64,
    pub duplicate: u64,
    pub late: u64,
    pub stored: u64,
    pub conflicts: u64,
    pub data_frames: u64,
    pub heartbeats: u64,
    /// Frames the TX queue refused; a replica repairs a lost `DATA` frame by a RANGE fetch.
    pub tx_full: u64,
    pub events_dropped: u64,
    pub fetch_bad: u64,
    /// A fetch from a source with no `K_fetch`, or whose tag does not verify.
    pub fetch_unauth: u64,
    /// A fetch over its source's rate limit.
    pub fetch_limited: u64,
    /// A KEY, BLOCK or RANGE fetch within its source's limit but over the box's budget
    /// ([`NodeConfig::fetch_box_rate`]): dropped before it reaches a queue.
    pub fetch_shed: u64,
    pub fetch_ring_hit: u64,
    pub fetch_log_hit: u64,
    pub fetch_miss: u64,
    pub fetch_resent: u64,
    /// A logged block whose data region does not split into packets.
    pub log_bad: u64,
    /// Sharded box: a packet or fetch the RX core could not hand to its shard or sender because
    /// that core's queue was full (the RX queue overflowing, one hop later). Always 0 on a
    /// one-core [`DataNode`].
    pub hop_full: u64,
    /// `DataRedirect`s sent (07 §5.7 step 3).
    pub redirects: u64,
    /// A redirect asked for a session with no known address or key: nothing was sent.
    pub redirect_unknown: u64,
    /// A redirect a full TX queue or hop ring refused, queued to retry next turn (the refusal
    /// itself is also counted in `tx_full` or `hop_full`, once per turn it is refused).
    pub redirect_retried: u64,
    /// A refused redirect dropped because the retry queue was full.
    pub redirect_dropped: u64,
}

impl Counters {
    pub(crate) fn reject(&mut self, r: Reject) {
        let c = match r {
            Reject::Header => &mut self.header,
            Reject::Book => &mut self.book,
            Reject::UnknownSession => &mut self.unknown_session,
            Reject::Epoch => &mut self.epoch,
            Reject::BadMac => &mut self.bad_mac,
            Reject::Duplicate => &mut self.duplicate,
            Reject::Late => &mut self.late,
        };
        *c = c.wrapping_add(1);
    }
}

pub(crate) fn bump(c: &mut u64) {
    *c = c.wrapping_add(1);
}

/// Splits the data region of a logged block (07 §8.2: payloads in O-order, self-delimiting by
/// `count`) into packets. `None` ends a region that does not split.
pub fn split_payloads(data: &[u8]) -> impl Iterator<Item = Option<&[u8]>> {
    let mut rest = data;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let count = rest.get(8).copied().unwrap_or(0);
        let len = usize::from(count)
            .saturating_mul(MSG_BYTES)
            .saturating_add(PKT_HDR_BYTES + 2 * TAG_BYTES);
        let ok = (1..=MAX_MSGS_PER_PKT).contains(&count) && rest.len() >= len;
        if !ok {
            rest = &[];
            return Some(None);
        }
        let (p, r) = rest.split_at(len);
        rest = r;
        Some(Some(p))
    })
}

pub(crate) fn pkt_key(p: &[u8]) -> (u32, u32, BookId, u16) {
    let u = |a: usize, n: usize| {
        p.get(a..a + n).map_or(0, |s| {
            s.iter()
                .rev()
                .fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
        })
    };
    (u(0, 4), u(4, 4), BookId(u(12, 2) as u16), u(10, 2) as u16)
}

/// Why [`DataNode::set_fetch_keys`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FetchKeysErr {
    #[error("an open-mode box takes no fetch keys")]
    OpenMode,
    #[error("an empty key set would serve nobody")]
    Empty,
}

pub struct DataNode<R: RxRing, F: RxRing, T: TxRing, S: BlockStore> {
    cfg: NodeConfig,
    home: DataHome,
    ingest: R,
    fetch: F,
    tx: T,
    store: S,
    fanout: Fanout,
    resp: Responder,
    events: Vec<Event>,
    counters: Counters,
    gate: Gate,
    pending: Pending,
}

impl<R: RxRing, F: RxRing, T: TxRing, S: BlockStore> DataNode<R, F, T, S> {
    pub fn new(cfg: NodeConfig, ingest: R, fetch: F, tx: T, store: S) -> Self {
        Self {
            home: DataHome::new(cfg.home.clone()),
            events: Vec::with_capacity(cfg.max_events),
            fanout: Fanout::new(&cfg),
            gate: Gate::new(&cfg),
            resp: Responder::default(),
            cfg,
            ingest,
            fetch,
            tx,
            store,
            counters: Counters::default(),
            pending: Pending::default(),
        }
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn home(&self) -> &DataHome {
        &self.home
    }

    /// The two-epoch boundary (08 §4.6): [`DataHome::add_epoch`] on this box's home.
    pub fn add_epoch(&mut self, current: u32, next: u32, keys: BTreeMap<SessionId, [u8; 16]>) {
        self.home.add_epoch(current, next, keys);
    }

    /// [`DataHome::retire_epoch`] on this box's home.
    pub fn retire_epoch(&mut self, epoch: u32) {
        self.home.retire_epoch(epoch);
    }

    /// Installs `K_fetch` of `epoch` (08 §9.6), replacing that epoch's keys if held. A box holds
    /// two epochs' keys and serves a fetch under either (08 §4.6), so a third evicts the lowest.
    /// Refused on an open-mode box (it stays open: a box's mode is fixed at start) and for an
    /// empty map (which would mean nobody is served).
    pub fn set_fetch_keys(
        &mut self,
        epoch: u32,
        keys: BTreeMap<Ipv4Addr, [u8; 16]>,
    ) -> Result<(), FetchKeysErr> {
        self.gate.set_keys(epoch, keys)
    }

    /// Drops `K_fetch` of `epoch`. The last held epoch is kept: a keyed box never goes open.
    pub fn retire_fetch_keys(&mut self, epoch: u32) {
        self.gate.retire(epoch);
    }

    /// The epochs whose `K_fetch` this box holds, lowest first.
    pub fn fetch_epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.gate.epochs()
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn tx(&self) -> &T {
        &self.tx
    }

    /// The events since the last drain, oldest first.
    pub fn drain_events(&mut self) -> std::vec::Drain<'_, Event> {
        self.events.drain(..)
    }

    /// One turn of the loop at time `now`: ingest, fetches, then the frame timers. Returns the
    /// number of packets and fetches handled.
    pub fn poll(&mut self, now: Nanos) -> usize {
        self.tx.reap();
        let mut work = 0;
        if !self.pending.is_empty() {
            work = self.retry_redirects();
        }
        work = work.saturating_add(self.poll_ingest(now));
        // Fetches wait in their queue while refused redirects do ([`Pending`]).
        if self.pending.is_empty() {
            work = work.saturating_add(self.poll_fetch(now));
        }
        self.fanout
            .timers(now, &mut self.tx, &mut self.counters, &self.cfg);
        work
    }

    /// Sends every open `DATA` frame now, whatever its age.
    pub fn flush(&mut self, now: Nanos) {
        self.fanout
            .flush(now, &mut self.tx, &mut self.counters, &self.cfg);
    }

    fn poll_ingest(&mut self, now: Nanos) -> usize {
        let mut burst = [RxPkt::empty(); RX_BURST];
        let n = self.ingest.poll(&mut burst);
        for p in burst.iter().take(n) {
            bump(&mut self.counters.rx_pkts);
            let Ok(f) = nic_frame::parse(self.ingest.bytes(p)) else {
                bump(&mut self.counters.bad_frame);
                continue;
            };
            let mut ev = None;
            let r = self
                .home
                .ingest_from(f.payload, Some(f.hdr.src), p.rx_ts(), &mut ev);
            if let Some(e) = ev {
                if self.events.len() < self.cfg.max_events {
                    self.events.push(e);
                } else {
                    bump(&mut self.counters.events_dropped);
                }
            }
            match r {
                Err(e) => self.counters.reject(e),
                Ok(ing) => {
                    bump(&mut self.counters.stored);
                    if !ing.forward {
                        bump(&mut self.counters.conflicts);
                        continue;
                    }
                    self.fanout.push(
                        f.payload,
                        ing.book,
                        ing.epoch16,
                        now,
                        &mut self.tx,
                        &mut self.counters,
                        &self.cfg,
                    );
                }
            }
        }
        self.ingest.release(n);
        n
    }

    fn poll_fetch(&mut self, now: Nanos) -> usize {
        let mut burst = [RxPkt::empty(); RX_BURST];
        let n = self.fetch.poll(&mut burst);
        for p in burst.iter().take(n) {
            let Ok(f) = nic_frame::parse(self.fetch.bytes(p)) else {
                bump(&mut self.counters.fetch_bad);
                continue;
            };
            let src = f.hdr.src;
            match self.gate.admit(src, f.payload, now, &mut self.counters) {
                Some(FetchMsg::One(q)) => self.serve(src, q),
                // Each entry as a kind-4 REDIRECT (07 §5.7 step 3), copied out of the RX
                // buffer first, on the stack.
                Some(FetchMsg::Batch(b)) => {
                    // Up to 181 sends at once: reap completions first, so a busy queue has room
                    // (a refused send is counted in `tx_full`, as for every send).
                    self.tx.reap();
                    let mut e = [(SessionId(0), 0u32); MAX_BATCH];
                    let n = e.iter_mut().zip(b.entries()).map(|(d, x)| *d = x).count();
                    let (down, to) = (b.down, b.to);
                    self.redirect(down, to, e.get(..n).unwrap_or(&[]));
                }
                None => {}
            }
        }
        self.fetch.release(n);
        n
    }

    fn serve(&mut self, to: Endpoint, q: Fetch) {
        let (tx, c, cfg) = (&mut self.tx, &mut self.counters, &self.cfg);
        match q {
            Fetch::Key { session, pkt_seq } => {
                self.resp.key(
                    to,
                    session,
                    pkt_seq,
                    self.home.ring(),
                    &self.store,
                    tx,
                    c,
                    cfg,
                );
            }
            Fetch::Range {
                dst,
                from,
                to: last,
            } => self.fanout.resend(dst, from, last, tx, c, cfg),
            Fetch::Block { height } => self.resp.block(to, height, &self.store, tx, c, cfg),
            Fetch::Redirect {
                session,
                resend_from,
                down,
                to,
            } => self.redirect(down, to, &[(session, resend_from)]),
        }
    }

    /// 07 §5.7 step 3: sends `DataRedirect{down → to, resend_from}` to the address of each
    /// session's newest authenticated copy, tagged under its MAC key. `sessions` holds each
    /// affected session with the `resend_from` the replicas computed. A session this box never
    /// heard from is counted in `redirect_unknown`: another live box knows its address.
    pub fn redirect(&mut self, down: u8, to: u8, sessions: &[(SessionId, u32)]) {
        for &(session, resend_from) in sessions {
            let r = Redirect {
                down,
                to,
                session,
                resend_from,
            };
            let (tx, c, wire) = (&mut self.tx, &mut self.counters, &mut self.resp.wire);
            send_or_queue(&mut self.pending, &self.home, tx, wire, c, self.cfg.me, r);
        }
    }

    /// The redirects a full TX queue refused on an earlier turn ([`Pending`]).
    fn retry_redirects(&mut self) -> usize {
        let (tx, c, wire, me) = (
            &mut self.tx,
            &mut self.counters,
            &mut self.resp.wire,
            self.cfg.me,
        );
        let home = &self.home;
        self.pending
            .retry(|r| send_redirect(home, tx, wire, c, me, r))
    }
}
