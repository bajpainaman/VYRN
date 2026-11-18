//! One data box over a `vyrn-nic` backend: the ingest queue, the fetch queue, one TX queue, the
//! fan-out to every destination (07 §5.2 step 6, §5.3), and fetch serving from the RAM ring and
//! a [`BlockStore`] (crate docs, § Fetch).
//!
//! The node is single-threaded: its owner calls [`DataNode::poll`] in its loop with the time.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use vyrn_log::BlockStore;
use vyrn_nic::frame::{self as nic_frame, Endpoint, FrameHdr, MAX_FRAME_BYTES};
use vyrn_types::{
    BookId, Height, MAX_MSGS_PER_PKT, MSG_BYTES, Nanos, PKT_HDR_BYTES, SessionId, TAG_BYTES,
};
use vyrn_wire::{RX_BURST, RxPkt, RxRing, TxRing};

use crate::frame::{DataHdr, Fetch, FrameBuf, FrameErr, Kind, key_seq};
use crate::ingest::{DataHome, Event, HomeConfig, Reject};
use crate::redirect::Redirect;

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
    /// `K_fetch` per requester address (crate docs, § Fetch). Empty: open mode, plain 32-byte
    /// fetches from anyone, under one shared rate limit (DEV and tests). Otherwise only these
    /// sources are served, and only with the 40-byte authenticated form.
    pub fetch_keys: BTreeMap<Ipv4Addr, [u8; 16]>,
    /// Fetches per second each source may send, refilled continuously.
    pub fetch_rate: u64,
    /// The most fetches a source may send at once after being idle.
    pub fetch_burst: u64,
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
            fetch_rate: 20_000,
            fetch_burst: 256,
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
    pub fetch_ring_hit: u64,
    pub fetch_log_hit: u64,
    pub fetch_miss: u64,
    pub fetch_resent: u64,
    /// A logged block whose data region does not split into packets.
    pub log_bad: u64,
    /// `DataRedirect`s sent (07 §5.7 step 3).
    pub redirects: u64,
    /// A redirect asked for a session with no known address or key: nothing was sent.
    pub redirect_unknown: u64,
}

impl Counters {
    fn reject(&mut self, r: Reject) {
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

fn bump(c: &mut u64) {
    *c = c.wrapping_add(1);
}

/// A sent `DATA` frame, as it went on the wire.
#[derive(Clone, Debug)]
struct Sent {
    data_seq: u64,
    len: usize,
    bytes: Box<[u8; MAX_FRAME_BYTES]>,
}

#[derive(Debug)]
struct Dest {
    ep: Endpoint,
    buf: FrameBuf,
    book: BookId,
    epoch16: u16,
    opened: Nanos,
    last_tx: Nanos,
    data_seq: u64,
    hist: Vec<Sent>,
    hist_next: usize,
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

fn pkt_key(p: &[u8]) -> (u32, u32, BookId, u16) {
    let u = |a: usize, n: usize| {
        p.get(a..a + n).map_or(0, |s| {
            s.iter()
                .rev()
                .fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
        })
    };
    (u(0, 4), u(4, 4), BookId(u(12, 2) as u16), u(10, 2) as u16)
}

/// A token bucket in token-nanoseconds: one fetch costs `1e9`, and `rate` tokens/s refill
/// `rate` per elapsed ns. Integer only.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    level: u64,
    at: Nanos,
}

const TOKEN: u64 = 1_000_000_000;

impl Bucket {
    fn full(burst: u64) -> Self {
        Self {
            level: burst.saturating_mul(TOKEN),
            at: Nanos(0),
        }
    }

    fn take(&mut self, now: Nanos, rate: u64, burst: u64) -> bool {
        let dt = now.0.saturating_sub(self.at.0);
        self.at = Nanos(self.at.0.max(now.0));
        let cap = burst.saturating_mul(TOKEN);
        self.level = self.level.saturating_add(dt.saturating_mul(rate)).min(cap);
        if self.level >= TOKEN {
            self.level -= TOKEN;
            true
        } else {
            false
        }
    }
}

pub struct DataNode<R: RxRing, F: RxRing, T: TxRing, S: BlockStore> {
    cfg: NodeConfig,
    home: DataHome,
    ingest: R,
    fetch: F,
    tx: T,
    store: S,
    dests: Vec<Dest>,
    /// Scratch for one frame on the wire.
    wire: Box<[u8; MAX_FRAME_BYTES]>,
    resp: FrameBuf,
    events: Vec<Event>,
    counters: Counters,
    /// One bucket per keyed source, made at construction, so a flood of new addresses grows
    /// nothing; open mode shares `open_bucket`.
    buckets: BTreeMap<Ipv4Addr, Bucket>,
    open_bucket: Bucket,
}

impl<R: RxRing, F: RxRing, T: TxRing, S: BlockStore> DataNode<R, F, T, S> {
    pub fn new(cfg: NodeConfig, ingest: R, fetch: F, tx: T, store: S) -> Self {
        let history = cfg.history.max(1);
        let dests = cfg
            .dests
            .iter()
            .map(|&ep| Dest {
                ep,
                buf: FrameBuf::default(),
                book: BookId(0),
                epoch16: 0,
                opened: Nanos(0),
                last_tx: Nanos(0),
                data_seq: 0,
                hist: (0..history)
                    .map(|_| Sent {
                        data_seq: 0,
                        len: 0,
                        bytes: Box::new([0; MAX_FRAME_BYTES]),
                    })
                    .collect(),
                hist_next: 0,
            })
            .collect();
        let buckets = cfg
            .fetch_keys
            .keys()
            .map(|&ip| (ip, Bucket::full(cfg.fetch_burst)))
            .collect();
        let open_bucket = Bucket::full(cfg.fetch_burst);
        Self {
            home: DataHome::new(cfg.home.clone()),
            events: Vec::with_capacity(cfg.max_events),
            cfg,
            ingest,
            fetch,
            tx,
            store,
            dests,
            wire: Box::new([0; MAX_FRAME_BYTES]),
            resp: FrameBuf::default(),
            counters: Counters::default(),
            buckets,
            open_bucket,
        }
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn home(&self) -> &DataHome {
        &self.home
    }

    /// The two-epoch boundary (08 §4.6): [`DataHome::add_epoch`] on this box's home.
    pub fn add_epoch(&mut self, epoch: u32, keys: BTreeMap<SessionId, [u8; 16]>) {
        self.home.add_epoch(epoch, keys);
    }

    /// [`DataHome::retire_epoch`] on this box's home.
    pub fn retire_epoch(&mut self, epoch: u32) {
        self.home.retire_epoch(epoch);
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
        let mut work = self.poll_ingest(now);
        work = work.saturating_add(self.poll_fetch(now));
        self.timers(now);
        work
    }

    /// Sends every open `DATA` frame now, whatever its age.
    pub fn flush(&mut self, now: Nanos) {
        for i in 0..self.dests.len() {
            self.flush_dest(i, now);
        }
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
                    let pkt = f.payload;
                    for d in 0..self.dests.len() {
                        let reopen = self.dests.get(d).is_some_and(|x| {
                            !x.buf.is_empty()
                                && (x.book != ing.book
                                    || x.epoch16 != ing.epoch16
                                    || !x.buf.fits(pkt.len()))
                        });
                        if reopen {
                            Self::send_data(
                                &mut self.dests,
                                &mut self.tx,
                                &mut self.counters,
                                &self.cfg,
                                d,
                                now,
                            );
                        }
                        if let Some(x) = self.dests.get_mut(d) {
                            if x.buf.is_empty() {
                                (x.book, x.epoch16, x.opened) = (ing.book, ing.epoch16, now);
                            }
                            x.buf.push(pkt);
                        }
                    }
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
            // Authenticate and decode, then charge the source: a forged, unkeyed or malformed
            // fetch costs one SipHash at most and never a token of an honest source's bucket.
            let q = if self.cfg.fetch_keys.is_empty() {
                Fetch::decode(f.payload)
            } else if let Some(key) = self.cfg.fetch_keys.get(&src.ip) {
                Fetch::open(f.payload, key)
            } else {
                Err(FrameErr::Tag)
            };
            let q = match q {
                Ok(q) => q,
                Err(FrameErr::Tag) => {
                    bump(&mut self.counters.fetch_unauth);
                    continue;
                }
                Err(_) => {
                    bump(&mut self.counters.fetch_bad);
                    continue;
                }
            };
            let (rate, cap) = (self.cfg.fetch_rate, self.cfg.fetch_burst);
            let b = match self.buckets.get_mut(&src.ip) {
                Some(b) => b,
                None => &mut self.open_bucket,
            };
            if b.take(now, rate, cap) {
                self.serve(src, q);
            } else {
                bump(&mut self.counters.fetch_limited);
            }
        }
        self.fetch.release(n);
        n
    }

    fn timers(&mut self, now: Nanos) {
        for i in 0..self.dests.len() {
            let Some(d) = self.dests.get(i) else { continue };
            if !d.buf.is_empty() {
                if now.0.saturating_sub(d.opened.0) >= self.cfg.batch_ns {
                    self.flush_dest(i, now);
                }
            } else if now.0.saturating_sub(d.last_tx.0) >= self.cfg.hb_ns {
                let hdr = DataHdr {
                    kind: Kind::DataHb,
                    book: BookId(0),
                    epoch16: 0,
                    data_seq: d.data_seq,
                    src: self.cfg.src,
                };
                let dst = d.ep;
                let payload = self.resp.finish(&hdr);
                if Self::send_to(
                    &mut self.tx,
                    &mut self.wire,
                    &mut self.counters,
                    self.cfg.me,
                    dst,
                    payload,
                ) {
                    bump(&mut self.counters.heartbeats);
                }
                if let Some(d) = self.dests.get_mut(i) {
                    d.last_tx = now;
                }
            }
        }
    }

    fn flush_dest(&mut self, i: usize, now: Nanos) {
        if self.dests.get(i).is_some_and(|d| !d.buf.is_empty()) {
            Self::send_data(
                &mut self.dests,
                &mut self.tx,
                &mut self.counters,
                &self.cfg,
                i,
                now,
            );
        }
    }

    /// Closes destination `i`'s open frame, keeps it in the history and sends it.
    fn send_data(
        dests: &mut [Dest],
        tx: &mut T,
        counters: &mut Counters,
        cfg: &NodeConfig,
        i: usize,
        now: Nanos,
    ) {
        let Some(d) = dests.get_mut(i) else { return };
        d.data_seq = d.data_seq.wrapping_add(1);
        let hdr = DataHdr {
            kind: Kind::Data,
            book: d.book,
            epoch16: d.epoch16,
            data_seq: d.data_seq,
            src: cfg.src,
        };
        let fh = FrameHdr {
            src: cfg.me,
            dst: d.ep,
        };
        let n_hist = d.hist.len();
        let at = d.hist_next;
        d.hist_next = (at + 1) % n_hist;
        let payload = d.buf.finish(&hdr);
        let Some(slot) = d.hist.get_mut(at) else {
            return;
        };
        slot.data_seq = hdr.data_seq;
        slot.len = nic_frame::build(&fh, payload, &mut slot.bytes[..]).unwrap_or(0);
        d.last_tx = now;
        bump(&mut counters.data_frames);
        if tx.send(slot.bytes.get(..slot.len).unwrap_or(&[])).is_err() {
            bump(&mut counters.tx_full);
        }
    }

    fn send_to(
        tx: &mut T,
        wire: &mut [u8; MAX_FRAME_BYTES],
        counters: &mut Counters,
        me: Endpoint,
        dst: Endpoint,
        payload: &[u8],
    ) -> bool {
        let fh = FrameHdr { src: me, dst };
        let Ok(len) = nic_frame::build(&fh, payload, &mut wire[..]) else {
            return false;
        };
        if tx.send(wire.get(..len).unwrap_or(&[])).is_err() {
            bump(&mut counters.tx_full);
            return false;
        }
        true
    }

    fn send_resp(&mut self, to: Endpoint, book: BookId, epoch16: u16, data_seq: u64) {
        let hdr = DataHdr {
            kind: Kind::FetchResp,
            book,
            epoch16,
            data_seq,
            src: self.cfg.src,
        };
        let payload = self.resp.finish(&hdr);
        Self::send_to(
            &mut self.tx,
            &mut self.wire,
            &mut self.counters,
            self.cfg.me,
            to,
            payload,
        );
    }

    fn serve(&mut self, to: Endpoint, q: Fetch) {
        match q {
            Fetch::Key { session, pkt_seq } => {
                let seq = key_seq(session, pkt_seq);
                let mut hit = None;
                for s in self.home.ring().variants(session, pkt_seq) {
                    if hit.is_none() {
                        let (_, _, book, e16) = pkt_key(s.bytes());
                        hit = Some((book, e16));
                    }
                    self.resp.push(s.bytes());
                }
                if let Some((book, e16)) = hit {
                    bump(&mut self.counters.fetch_ring_hit);
                    return self.send_resp(to, book, e16, seq);
                }
                if let Some((book, e16)) = self.search_log(session.0, pkt_seq) {
                    bump(&mut self.counters.fetch_log_hit);
                    return self.send_resp(to, book, e16, seq);
                }
                bump(&mut self.counters.fetch_miss);
                self.send_resp(to, BookId(0), 0, seq);
            }
            Fetch::Range {
                dst,
                from,
                to: last,
            } => {
                let ok = from >= 1 && last >= from && last - from < self.cfg.max_range;
                let Some(d) = self.dests.get(usize::from(dst)).filter(|_| ok) else {
                    bump(&mut self.counters.fetch_bad);
                    return;
                };
                for s in d.hist.iter().filter(|s| {
                    s.len > 0 && (from..=last).contains(&s.data_seq) && s.data_seq <= d.data_seq
                }) {
                    // The frame goes back to its destination's address, as first sent.
                    if self.tx.send(s.bytes.get(..s.len).unwrap_or(&[])).is_err() {
                        bump(&mut self.counters.tx_full);
                    } else {
                        bump(&mut self.counters.fetch_resent);
                    }
                }
            }
            Fetch::Block { height } => self.serve_block(to, height),
        }
    }

    /// 07 §5.7 step 3: sends `DataRedirect{down → to, resend_from}` to the address of each
    /// session's newest authenticated copy, tagged under its MAC key. `sessions` holds each
    /// affected session with the `resend_from` the replicas computed. A session this box never
    /// heard from is counted in `redirect_unknown`: another live box knows its address.
    pub fn redirect(&mut self, down: u8, to: u8, sessions: &[(SessionId, u32)]) {
        for &(session, resend_from) in sessions {
            let (Some(dst), Some(key)) = (self.home.source(session), self.home.key(session)) else {
                bump(&mut self.counters.redirect_unknown);
                continue;
            };
            let r = Redirect {
                down,
                to,
                session,
                resend_from,
            };
            let b = r.seal(key);
            if Self::send_to(
                &mut self.tx,
                &mut self.wire,
                &mut self.counters,
                self.cfg.me,
                dst,
                &b,
            ) {
                bump(&mut self.counters.redirects);
            }
        }
    }

    /// Searches the newest `log_scan` logged blocks for the packet; on a hit it is in `resp`.
    fn search_log(&mut self, session: u32, pkt_seq: u32) -> Option<(BookId, u16)> {
        let (lo, hi) = self.store.range()?;
        let first =
            hi.0.saturating_sub(self.cfg.log_scan.saturating_sub(1))
                .max(lo.0);
        for h in (first..=hi.0).rev() {
            let Some(Ok(b)) = self.store.read(Height(h), Height(h)).next() else {
                continue;
            };
            for p in split_payloads(&b.data) {
                let Some(p) = p else {
                    bump(&mut self.counters.log_bad);
                    break;
                };
                let (s, q, book, e16) = pkt_key(p);
                if (s, q) == (session, pkt_seq) {
                    self.resp.push(p);
                    return Some((book, e16));
                }
            }
        }
        None
    }

    fn serve_block(&mut self, to: Endpoint, height: Height) {
        let block = match self.store.read(height, height).next() {
            Some(Ok(b)) => Some(b),
            _ => None,
        };
        let Some(b) = block else {
            bump(&mut self.counters.fetch_miss);
            return self.send_resp(to, BookId(0), 0, height.0);
        };
        bump(&mut self.counters.fetch_log_hit);
        let mut cur: Option<(BookId, u16)> = None;
        for p in split_payloads(&b.data) {
            let Some(p) = p else {
                bump(&mut self.counters.log_bad);
                break;
            };
            let (_, _, book, e16) = pkt_key(p);
            if let Some((cb, ce)) = cur
                && ((cb, ce) != (book, e16) || !self.resp.fits(p.len()))
            {
                self.send_resp(to, cb, ce, height.0);
            }
            if self.resp.is_empty() {
                cur = Some((book, e16));
            }
            self.resp.push(p);
        }
        let (cb, ce) = cur.unwrap_or((BookId(0), 0));
        self.send_resp(to, cb, ce, height.0);
    }
}
