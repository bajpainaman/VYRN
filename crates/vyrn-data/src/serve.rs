//! The parts of a data box that the one-core [`DataNode`](crate::DataNode) and the sharded box
//! ([`crate::shards`]) share: the fetch gate (authentication and the per-source rate limit), the
//! fan-out to every destination with its RANGE history, and the KEY and BLOCK responder.
//!
//! Each part owns its state and takes the TX queue and the counters it writes as arguments, so
//! the sharded box can put each on a different core.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use vyrn_log::BlockStore;
use vyrn_nic::frame::{self as nic_frame, Endpoint, FrameHdr, MAX_FRAME_BYTES};
use vyrn_types::{BookId, Height, Nanos, SessionId};
use vyrn_wire::TxRing;

use crate::frame::{DataHdr, FetchMsg, FrameBuf, FrameErr, Kind, key_seq};
use crate::ingest::DataHome;
use crate::node::{Counters, FetchKeysErr, NodeConfig, bump, pkt_key, split_payloads};
use crate::redirect::Redirect;
use crate::ring::Ring;

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

/// Fetch authentication and the per-source rate limit (crate docs, § Fetch). One per box: the
/// sharded box runs it on its RX core, so a source's limit is the box's, not a shard's.
#[derive(Debug)]
pub(crate) struct Gate {
    /// `K_fetch` per requester address, for at most two epochs (08 §4.6): a fetch is served
    /// under either. Empty forever on an open-mode box.
    keys: Vec<(u32, BTreeMap<Ipv4Addr, [u8; 16]>)>,
    /// One bucket per keyed source, made when its key is installed, so a flood of new
    /// addresses grows nothing; open mode shares `open`.
    buckets: BTreeMap<Ipv4Addr, Bucket>,
    open: Bucket,
    rate: u64,
    burst: u64,
}

impl Gate {
    pub(crate) fn new(cfg: &NodeConfig) -> Self {
        Self {
            keys: if cfg.fetch_keys.is_empty() {
                Vec::new()
            } else {
                vec![(cfg.fetch_epoch, cfg.fetch_keys.clone())]
            },
            buckets: cfg
                .fetch_keys
                .keys()
                .map(|&ip| (ip, Bucket::full(cfg.fetch_burst)))
                .collect(),
            open: Bucket::full(cfg.fetch_burst),
            rate: cfg.fetch_rate,
            burst: cfg.fetch_burst,
        }
    }

    /// The fetch in `payload` from `src`, if it authenticates and is within `src`'s limit.
    /// A REDIRECT_BATCH costs one token, like any fetch.
    pub(crate) fn admit<'p>(
        &mut self,
        src: Endpoint,
        payload: &'p [u8],
        now: Nanos,
        c: &mut Counters,
    ) -> Option<FetchMsg<'p>> {
        // Authenticate and decode, then charge the source: a forged, unkeyed or malformed
        // fetch costs one SipHash at most and never a token of an honest source's bucket.
        let q = if self.keys.is_empty() {
            FetchMsg::decode(payload)
        } else {
            // Each held epoch's key in turn: at most two SipHashes for a forged fetch.
            let mut q = Err(FrameErr::Tag);
            for (_, m) in &self.keys {
                if let Some(key) = m.get(&src.ip) {
                    q = FetchMsg::open(payload, key);
                    if !matches!(q, Err(FrameErr::Tag)) {
                        break;
                    }
                }
            }
            q
        };
        let q = match q {
            Ok(q) => q,
            Err(FrameErr::Tag) => {
                bump(&mut c.fetch_unauth);
                return None;
            }
            Err(_) => {
                bump(&mut c.fetch_bad);
                return None;
            }
        };
        let b = match self.buckets.get_mut(&src.ip) {
            Some(b) => b,
            None => &mut self.open,
        };
        if b.take(now, self.rate, self.burst) {
            Some(q)
        } else {
            bump(&mut c.fetch_limited);
            None
        }
    }

    /// See [`DataNode::set_fetch_keys`](crate::DataNode::set_fetch_keys).
    pub(crate) fn set_keys(
        &mut self,
        epoch: u32,
        keys: BTreeMap<Ipv4Addr, [u8; 16]>,
    ) -> Result<(), FetchKeysErr> {
        if self.keys.is_empty() {
            return Err(FetchKeysErr::OpenMode);
        }
        if keys.is_empty() {
            return Err(FetchKeysErr::Empty);
        }
        let burst = self.burst;
        for &ip in keys.keys() {
            self.buckets
                .entry(ip)
                .or_insert_with(|| Bucket::full(burst));
        }
        match self.keys.iter_mut().find(|(e, _)| *e == epoch) {
            Some((_, k)) => *k = keys,
            None => self.keys.push((epoch, keys)),
        }
        self.keys.sort_unstable_by_key(|(e, _)| *e);
        if self.keys.len() > 2 {
            self.keys.remove(0);
        }
        Ok(())
    }

    /// Drops `K_fetch` of `epoch`. The last held epoch is kept: a keyed box never goes open.
    pub(crate) fn retire(&mut self, epoch: u32) {
        if self.keys.len() > 1 {
            self.keys.retain(|(e, _)| *e != epoch);
        }
    }

    pub(crate) fn epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.keys.iter().map(|(e, _)| *e)
    }
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

/// The fan-out (07 §5.2 step 6, §5.3): one sender per destination, each with its open `DATA`
/// frame, its `data_seq` and the history RANGE fetches resend from. Every frame to a
/// destination leaves through this one owner, so `data_seq` is per box and destination
/// whatever core stored the packet (07 §5.2, RSS by session).
#[derive(Debug)]
pub(crate) struct Fanout {
    dests: Vec<Dest>,
    hb: FrameBuf,
    wire: Box<[u8; MAX_FRAME_BYTES]>,
}

impl Fanout {
    pub(crate) fn new(cfg: &NodeConfig) -> Self {
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
        Self {
            dests,
            hb: FrameBuf::default(),
            wire: Box::new([0; MAX_FRAME_BYTES]),
        }
    }

    /// Appends a stored packet to every destination's open frame, sending a frame first where
    /// the packet's book or `epoch16` differs or it does not fit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn push<T: TxRing>(
        &mut self,
        pkt: &[u8],
        book: BookId,
        epoch16: u16,
        now: Nanos,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        for d in &mut self.dests {
            if !d.buf.is_empty()
                && (d.book != book || d.epoch16 != epoch16 || !d.buf.fits(pkt.len()))
            {
                send_data(d, tx, c, cfg, now);
            }
            if d.buf.is_empty() {
                (d.book, d.epoch16, d.opened) = (book, epoch16, now);
            }
            d.buf.push(pkt);
        }
    }

    /// Sends frames open for `batch_ns`, and a `DATA_HB` to a destination idle for `hb_ns`.
    pub(crate) fn timers<T: TxRing>(
        &mut self,
        now: Nanos,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        for d in &mut self.dests {
            if !d.buf.is_empty() {
                if now.0.saturating_sub(d.opened.0) >= cfg.batch_ns {
                    send_data(d, tx, c, cfg, now);
                }
            } else if now.0.saturating_sub(d.last_tx.0) >= cfg.hb_ns {
                let hdr = DataHdr {
                    kind: Kind::DataHb,
                    book: BookId(0),
                    epoch16: 0,
                    data_seq: d.data_seq,
                    src: cfg.src,
                };
                let payload = self.hb.finish(&hdr);
                if send_to(tx, &mut self.wire, c, cfg.me, d.ep, payload) {
                    bump(&mut c.heartbeats);
                }
                d.last_tx = now;
            }
        }
    }

    /// Sends every open frame now, whatever its age.
    pub(crate) fn flush<T: TxRing>(
        &mut self,
        now: Nanos,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        for d in &mut self.dests {
            if !d.buf.is_empty() {
                send_data(d, tx, c, cfg, now);
            }
        }
    }

    /// A RANGE fetch: resends destination `dst`'s frames `from..=last` that are still held.
    pub(crate) fn resend<T: TxRing>(
        &self,
        dst: u8,
        from: u64,
        last: u64,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        let ok = from >= 1 && last >= from && last - from < cfg.max_range;
        let Some(d) = self.dests.get(usize::from(dst)).filter(|_| ok) else {
            bump(&mut c.fetch_bad);
            return;
        };
        for s in d.hist.iter().filter(|s| {
            s.len > 0 && (from..=last).contains(&s.data_seq) && s.data_seq <= d.data_seq
        }) {
            // The frame goes back to its destination's address, as first sent.
            if tx.send(s.bytes.get(..s.len).unwrap_or(&[])).is_err() {
                bump(&mut c.tx_full);
            } else {
                bump(&mut c.fetch_resent);
            }
        }
    }
}

/// Closes `d`'s open frame, keeps it in the history and sends it.
fn send_data<T: TxRing>(d: &mut Dest, tx: &mut T, c: &mut Counters, cfg: &NodeConfig, now: Nanos) {
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
    bump(&mut c.data_frames);
    if tx.send(slot.bytes.get(..slot.len).unwrap_or(&[])).is_err() {
        bump(&mut c.tx_full);
    }
}

/// Builds the frame `me → dst` around `payload` in `wire` and sends it; false if not sent.
pub(crate) fn send_to<T: TxRing>(
    tx: &mut T,
    wire: &mut [u8; MAX_FRAME_BYTES],
    c: &mut Counters,
    me: Endpoint,
    dst: Endpoint,
    payload: &[u8],
) -> bool {
    let fh = FrameHdr { src: me, dst };
    let Ok(len) = nic_frame::build(&fh, payload, &mut wire[..]) else {
        return false;
    };
    if tx.send(wire.get(..len).unwrap_or(&[])).is_err() {
        bump(&mut c.tx_full);
        return false;
    }
    true
}

/// Sends `r` to the address of its session's newest authenticated copy, tagged under its MAC
/// key (07 §5.7 step 3). A session `home` never heard from is counted in `redirect_unknown` and
/// taken as handled: another live box knows its address. False only if `tx` refused it.
pub(crate) fn send_redirect<T: TxRing>(
    home: &DataHome,
    tx: &mut T,
    wire: &mut [u8; MAX_FRAME_BYTES],
    c: &mut Counters,
    me: Endpoint,
    r: Redirect,
) -> bool {
    let (Some(dst), Some(key)) = (home.source(r.session), home.key(r.session)) else {
        bump(&mut c.redirect_unknown);
        return true;
    };
    let sent = send_to(tx, wire, c, me, dst, &r.seal(key));
    if sent {
        bump(&mut c.redirects);
    }
    sent
}

/// [`send_redirect`] for a new redirect, behind any refused ones `pending` holds so a
/// session's redirects leave in order. A session `home` does not know is counted
/// (`redirect_unknown`) at once, queued or not, so it never takes a retry slot.
#[allow(clippy::too_many_arguments)]
pub(crate) fn send_or_queue<T: TxRing>(
    pending: &mut Pending,
    home: &DataHome,
    tx: &mut T,
    wire: &mut [u8; MAX_FRAME_BYTES],
    c: &mut Counters,
    me: Endpoint,
    r: Redirect,
) {
    if pending.is_empty() {
        if !send_redirect(home, tx, wire, c, me, r) {
            pending.push(r, c);
        }
    } else if home.source(r.session).is_some() && home.key(r.session).is_some() {
        pending.push(r, c);
    } else {
        bump(&mut c.redirect_unknown);
    }
}

/// KEY and BLOCK answers (`FETCH_RESP`), from a ring and a [`BlockStore`].
#[derive(Debug)]
pub(crate) struct Responder {
    resp: FrameBuf,
    pub(crate) wire: Box<[u8; MAX_FRAME_BYTES]>,
}

impl Default for Responder {
    fn default() -> Self {
        Self {
            resp: FrameBuf::default(),
            wire: Box::new([0; MAX_FRAME_BYTES]),
        }
    }
}

impl Responder {
    #[allow(clippy::too_many_arguments)]
    fn send<T: TxRing>(
        &mut self,
        to: Endpoint,
        book: BookId,
        epoch16: u16,
        data_seq: u64,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        let hdr = DataHdr {
            kind: Kind::FetchResp,
            book,
            epoch16,
            data_seq,
            src: cfg.src,
        };
        let payload = self.resp.finish(&hdr);
        send_to(tx, &mut self.wire, c, cfg.me, to, payload);
    }

    /// A KEY fetch: every variant `ring` holds, else the packet from the newest `log_scan`
    /// logged blocks, else an empty answer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn key<T: TxRing, S: BlockStore>(
        &mut self,
        to: Endpoint,
        session: SessionId,
        pkt_seq: u32,
        ring: &Ring,
        store: &S,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        let seq = key_seq(session, pkt_seq);
        let mut hit = None;
        for s in ring.variants(session, pkt_seq) {
            if hit.is_none() {
                let (_, _, book, e16) = pkt_key(s.bytes());
                hit = Some((book, e16));
            }
            self.resp.push(s.bytes());
        }
        if let Some((book, e16)) = hit {
            bump(&mut c.fetch_ring_hit);
            return self.send(to, book, e16, seq, tx, c, cfg);
        }
        if let Some((book, e16)) = self.search_log(session.0, pkt_seq, store, c, cfg) {
            bump(&mut c.fetch_log_hit);
            return self.send(to, book, e16, seq, tx, c, cfg);
        }
        bump(&mut c.fetch_miss);
        self.send(to, BookId(0), 0, seq, tx, c, cfg);
    }

    /// Searches the newest `log_scan` logged blocks for the packet; on a hit it is in `resp`.
    fn search_log<S: BlockStore>(
        &mut self,
        session: u32,
        pkt_seq: u32,
        store: &S,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) -> Option<(BookId, u16)> {
        let (lo, hi) = store.range()?;
        let first =
            hi.0.saturating_sub(cfg.log_scan.saturating_sub(1))
                .max(lo.0);
        for h in (first..=hi.0).rev() {
            let Some(Ok(b)) = store.read(Height(h), Height(h)).next() else {
                continue;
            };
            for p in split_payloads(&b.data) {
                let Some(p) = p else {
                    bump(&mut c.log_bad);
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

    /// A BLOCK fetch: the block's payloads, one `FETCH_RESP` per run of one book and `epoch16`.
    pub(crate) fn block<T: TxRing, S: BlockStore>(
        &mut self,
        to: Endpoint,
        height: Height,
        store: &S,
        tx: &mut T,
        c: &mut Counters,
        cfg: &NodeConfig,
    ) {
        let block = match store.read(height, height).next() {
            Some(Ok(b)) => Some(b),
            _ => None,
        };
        let Some(b) = block else {
            bump(&mut c.fetch_miss);
            return self.send(to, BookId(0), 0, height.0, tx, c, cfg);
        };
        bump(&mut c.fetch_log_hit);
        let mut cur: Option<(BookId, u16)> = None;
        for p in split_payloads(&b.data) {
            let Some(p) = p else {
                bump(&mut c.log_bad);
                break;
            };
            let (_, _, book, e16) = pkt_key(p);
            if let Some((cb, ce)) = cur
                && ((cb, ce) != (book, e16) || !self.resp.fits(p.len()))
            {
                self.send(to, cb, ce, height.0, tx, c, cfg);
            }
            if self.resp.is_empty() {
                cur = Some((book, e16));
            }
            self.resp.push(p);
        }
        let (cb, ce) = cur.unwrap_or((BookId(0), 0));
        self.send(to, cb, ce, height.0, tx, c, cfg);
    }
}

/// Redirects a full queue refused (#183 follow-ups): a TX queue on the core that sends them, a
/// shard's hop ring on the RX core. *Reading (gap: 07 §5.7 step 3 names no queue policy):* a
/// `DataRedirect` is not repaired by any fetch the way a lost `DATA` frame is, so a refused one
/// waits here and is retried, oldest first, at the start of the core's next turn, before any new
/// work; a turn stops retrying at the first refusal, so order is kept and a full queue costs one
/// refusal per turn. While any wait, the core takes no new fetch datagrams: the failover burst
/// waits in the NIC's fetch queue and is paced by the full queue's drain. One fetch burst
/// (`RX_BURST` kind-5 batches) therefore always fits, allocated once; a redirect is dropped and
/// counted in `redirect_dropped` only past that (an operator list longer than [`Pending::CAP`]).
#[derive(Debug)]
pub(crate) struct Pending(std::collections::VecDeque<Redirect>);

impl Default for Pending {
    fn default() -> Self {
        Self(std::collections::VecDeque::with_capacity(Self::CAP))
    }
}

impl Pending {
    /// One fetch burst of full kind-5 batches (2,896).
    pub(crate) const CAP: usize = vyrn_wire::RX_BURST * crate::frame::MAX_BATCH;

    /// Queues `r` for the next turn (`redirect_retried`), or drops it if full.
    pub(crate) fn push(&mut self, r: Redirect, c: &mut Counters) {
        if self.0.len() < Self::CAP {
            self.0.push_back(r);
            bump(&mut c.redirect_retried);
        } else {
            bump(&mut c.redirect_dropped);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hands queued redirects to `send`, oldest first, until it refuses one (returns false),
    /// which stays at the front. Returns how many were taken.
    pub(crate) fn retry(&mut self, mut send: impl FnMut(Redirect) -> bool) -> usize {
        let mut n = 0usize;
        while let Some(&r) = self.0.front() {
            if !send(r) {
                break;
            }
            self.0.pop_front();
            n = n.saturating_add(1);
        }
        n
    }
}
