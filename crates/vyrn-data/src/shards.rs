//! A data box on `n + 2` cores (07 §5.2, RSS by session): one RX core, `n` ingest shards and
//! one sender core, joined by `vyrn-cut` SPSC rings. The owner (the binary) makes the rings,
//! moves each core to a thread, pins it and calls its `poll` in a loop; nothing here spawns.
//!
//! ```text
//!   ingest queue ─► RxCore ──(shard_of(session))──► ShardCore i ──► SenderCore ─► DATA, DATA_HB
//!   fetch queue  ─►   │ gate: K_fetch + rate limit     │ KEY, BLOCK: FETCH_RESP     to every dest
//!                     └── RANGE ───────────────────────┼──────────────────────►  (resend history)
//! ```
//!
//! - **RxCore** parses the frame, reads the session from bytes 0..4 ([`session_of`]) and hands
//!   the packet to its shard. It also runs the fetch gate ([`Gate`]) for the whole box, so a
//!   source's rate limit and `K_fetch` are the box's, not a shard's.
//! - **ShardCore** `i` is a whole [`DataHome`] for its sessions (07 §5.2 steps 1–5), and sends
//!   their `DataRedirect`s (07 §5.7 step 3, [`RxCore::redirect`]). A KEY fetch
//!   goes to the shard that owns its session, the only one whose ring can hold the packet, and
//!   is answered from that ring or the log on the shard's own TX queue.
//! - **SenderCore** owns every destination (07 §5.2 step 6, §5.3): its open frame, its
//!   `data_seq` and its RANGE history. *Reading (07 §5.2, "one sender"):* one core sends to
//!   every destination, so each destination has exactly one sender and `data_seq` stays per box
//!   and destination; splitting destinations over several sender cores is a follow-up.
//!
//! *Reading (gap: 07 names no per-core queue policy):* a full hop ring drops the packet or fetch
//! and counts it in [`Counters::hop_full`], as a full NIC RX queue would; a replica repairs a
//! lost packet with a KEY fetch. *Reading:* a BLOCK fetch goes to shard `height mod n`, so log
//! reads spread over the shards and never stall the RX core.

use vyrn_cut::{Consumer, Hw, Producer, Ring};
use vyrn_log::BlockStore;
use vyrn_nic::frame::{self as nic_frame, Endpoint};
use vyrn_types::{BookId, MAX_REQ_PAYLOAD, Nanos, SessionId};
use vyrn_wire::{RX_BURST, RxPkt, RxRing, TxRing};

use crate::frame::{Fetch, FetchMsg};
use crate::ingest::{DataHome, Event};
use crate::node::{Counters, FetchKeysErr, NodeConfig, bump};
use crate::redirect::Redirect;
use crate::serve::{Fanout, Gate, Pending, Responder, send_redirect};
use crate::spread::{session_of, shard_of};

/// Entries per hop ring.
pub const HOP_RING: usize = 4096;

/// One request packet as the RX core received it (the UDP payload).
#[derive(Clone, Copy, Debug)]
pub struct Pkt {
    len: u16,
    bytes: [u8; MAX_REQ_PAYLOAD],
}

impl Pkt {
    fn new(b: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MAX_REQ_PAYLOAD];
        bytes.get_mut(..b.len())?.copy_from_slice(b);
        Some(Self {
            len: u16::try_from(b.len()).ok()?,
            bytes,
        })
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// RX core → shard.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub enum ToShard {
    Pkt {
        pkt: Pkt,
        src: Endpoint,
        rx_ts: Nanos,
    },
    /// An admitted KEY or BLOCK fetch, answered to `to`.
    Fetch { to: Endpoint, q: Fetch },
    /// 07 §5.7 step 3 for one session this shard owns.
    Redirect {
        down: u8,
        to: u8,
        session: SessionId,
        resend_from: u32,
    },
}

/// Shard or RX core → sender.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug)]
pub enum ToSender {
    /// A stored packet to forward.
    Pkt {
        pkt: Pkt,
        book: BookId,
        epoch16: u16,
    },
    /// An admitted RANGE fetch.
    Range { dst: u8, from: u64, last: u64 },
}

pub type ShardRing = Ring<ToShard, HOP_RING, 1, Hw>;
pub type SenderRing = Ring<ToSender, HOP_RING, 1, Hw>;
pub type ShardTx<'a> = Producer<'a, ToShard, HOP_RING, 1, Hw>;
pub type ShardRx<'a> = Consumer<'a, ToShard, HOP_RING, 1, Hw>;
pub type SenderTx<'a> = Producer<'a, ToSender, HOP_RING, 1, Hw>;
pub type SenderRx<'a> = Consumer<'a, ToSender, HOP_RING, 1, Hw>;

fn hop<T: Copy, const N: usize>(p: &mut Producer<'_, T, N, 1, Hw>, v: T, c: &mut Counters) -> bool {
    let ok = p.push(&Hw, v).is_ok();
    if !ok {
        bump(&mut c.hop_full);
    }
    ok
}

/// Hands one redirect of a `down → to` move to the shard that owns its session (07 §5.7 step 3):
/// the operator line, kind 4 and each kind-5 entry. `false` when that shard's ring is full
/// (counted in `hop_full`).
fn redirect_to_owner(shards: &mut [ShardTx<'_>], r: Redirect, c: &mut Counters) -> bool {
    let n = shards.len();
    let to = ToShard::Redirect {
        down: r.down,
        to: r.to,
        session: r.session,
        resend_from: r.resend_from,
    };
    shards
        .get_mut(shard_of(r.session, n))
        .is_some_and(|q| hop(q, to, c))
}

/// Hands `r` to its owner, or queues it behind earlier refused ones (the RX core's
/// [`Pending`]). True if handed on now.
fn hand(pending: &mut Pending, c: &mut Counters, shards: &mut [ShardTx<'_>], r: Redirect) -> bool {
    if pending.is_empty() && redirect_to_owner(shards, r, c) {
        return true;
    }
    pending.push(r, c);
    false
}

/// The RX core: both RX queues and the fetch gate.
pub struct RxCore<R: RxRing, F: RxRing> {
    ingest: R,
    fetch: F,
    gate: Gate,
    counters: Counters,
    fetches: usize,
    /// Redirects a full shard ring refused ([`Pending`]): one queue for the box, so a full
    /// shard holds back the others' too until it drains, and each session's stay in order.
    pending: Pending,
}

impl<R: RxRing, F: RxRing> RxCore<R, F> {
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Fetch datagrams the last [`RxCore::poll`] took. A core loop yields after a turn with
    /// fetch work, so a fetch flood cannot keep this thread on a CPU the sender needs for its
    /// `DATA_HB` cadence (07 §5.3); ingest-only turns keep spinning.
    pub fn fetches(&self) -> usize {
        self.fetches
    }

    /// See [`DataNode::set_fetch_keys`](crate::DataNode::set_fetch_keys).
    pub fn set_fetch_keys(
        &mut self,
        epoch: u32,
        keys: std::collections::BTreeMap<std::net::Ipv4Addr, [u8; 16]>,
    ) -> Result<(), FetchKeysErr> {
        self.gate.set_keys(epoch, keys)
    }

    pub fn retire_fetch_keys(&mut self, epoch: u32) {
        self.gate.retire(epoch);
    }

    pub fn fetch_epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.gate.epochs()
    }

    /// 07 §5.7 step 3 on a sharded box: hands each `(session, resend_from)` to the shard that
    /// owns the session, the only one that holds its MAC key and its newest copy's address.
    /// That shard sends `DataRedirect{down → to, resend_from}` on its own TX queue, as
    /// [`DataNode::redirect`](crate::DataNode::redirect) does. Returns how many were handed on
    /// now; one a full ring refuses waits in a retry queue ([`Pending`]) for the next
    /// [`RxCore::poll`] (`redirect_retried`, or `redirect_dropped` if that queue is full).
    pub fn redirect(
        &mut self,
        down: u8,
        to: u8,
        sessions: &[(SessionId, u32)],
        shards: &mut [ShardTx<'_>],
    ) -> usize {
        sessions
            .iter()
            .filter(|&&(session, resend_from)| {
                let r = Redirect {
                    down,
                    to,
                    session,
                    resend_from,
                };
                hand(&mut self.pending, &mut self.counters, shards, r)
            })
            .count()
    }

    /// One turn: an ingest burst to the shards, then a fetch burst to its owners. `shards` are
    /// the producers of every shard's ring, in shard order. Returns the frames handled.
    pub fn poll(
        &mut self,
        now: Nanos,
        shards: &mut [ShardTx<'_>],
        sender: &mut SenderTx<'_>,
    ) -> usize {
        let n_shards = shards.len();
        // Redirects refused last turn go first, paced by the shards' rings (#183 (b)).
        let mut retried = 0;
        if !self.pending.is_empty() {
            let c = &mut self.counters;
            retried = self.pending.retry(|r| redirect_to_owner(shards, r, c));
        }
        let mut burst = [RxPkt::empty(); RX_BURST];
        let n = self.ingest.poll(&mut burst);
        for p in burst.iter().take(n) {
            bump(&mut self.counters.rx_pkts);
            let Ok(f) = nic_frame::parse(self.ingest.bytes(p)) else {
                bump(&mut self.counters.bad_frame);
                continue;
            };
            // A runt names no session and an oversized packet fails 01 §6.1's length rule:
            // both are what the shard's own parse would reject as `Header`.
            let (Some(s), Some(pkt)) = (session_of(f.payload), Pkt::new(f.payload)) else {
                bump(&mut self.counters.header);
                continue;
            };
            let to = ToShard::Pkt {
                pkt,
                src: f.hdr.src,
                rx_ts: p.rx_ts(),
            };
            if let Some(q) = shards.get_mut(shard_of(s, n_shards)) {
                hop(q, to, &mut self.counters);
            }
        }
        self.ingest.release(n);
        let m = self.fetch.poll(&mut burst);
        self.fetches = m;
        for p in burst.iter().take(m) {
            let Ok(f) = nic_frame::parse(self.fetch.bytes(p)) else {
                bump(&mut self.counters.fetch_bad);
                continue;
            };
            let src = f.hdr.src;
            let q = match self.gate.admit(src, f.payload, now, &mut self.counters) {
                Some(FetchMsg::One(q)) => q,
                // Each entry to its owning shard, exactly as a kind-4 REDIRECT.
                Some(FetchMsg::Batch(b)) => {
                    for (session, resend_from) in b.entries() {
                        let r = Redirect {
                            down: b.down,
                            to: b.to,
                            session,
                            resend_from,
                        };
                        hand(&mut self.pending, &mut self.counters, shards, r);
                    }
                    continue;
                }
                None => continue,
            };
            let shard = match q {
                Fetch::Range {
                    dst,
                    from,
                    to: last,
                } => {
                    hop(
                        sender,
                        ToSender::Range { dst, from, last },
                        &mut self.counters,
                    );
                    continue;
                }
                Fetch::Key { session, .. } => shard_of(session, n_shards),
                Fetch::Block { height } => {
                    usize::try_from(height.0 % n_shards.max(1) as u64).unwrap_or(0)
                }
                // A replica's `resend_from` (07 §5.7 step 3): the owning shard seals and sends
                // the redirect, as for the operator's `REDIRECT` line.
                Fetch::Redirect {
                    session,
                    resend_from,
                    down,
                    to,
                } => {
                    let r = Redirect {
                        down,
                        to,
                        session,
                        resend_from,
                    };
                    hand(&mut self.pending, &mut self.counters, shards, r);
                    continue;
                }
            };
            if let Some(s) = shards.get_mut(shard) {
                hop(s, ToShard::Fetch { to: src, q }, &mut self.counters);
            }
        }
        self.fetch.release(m);
        n.saturating_add(m).saturating_add(retried)
    }
}

/// Ingest shard `i`: its sessions' [`DataHome`] and a TX queue for its fetch answers.
pub struct ShardCore<T: TxRing> {
    cfg: NodeConfig,
    home: DataHome,
    tx: T,
    resp: Responder,
    events: Vec<Event>,
    counters: Counters,
    fetches: usize,
    /// Redirects a full TX queue refused ([`Pending`]).
    pending: Pending,
}

impl<T: TxRing> ShardCore<T> {
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    /// Fetches and redirects the last [`ShardCore::poll`] served; see [`RxCore::fetches`].
    pub fn fetches(&self) -> usize {
        self.fetches
    }

    pub fn home(&self) -> &DataHome {
        &self.home
    }

    /// The events since the last drain, oldest first.
    pub fn drain_events(&mut self) -> std::vec::Drain<'_, Event> {
        self.events.drain(..)
    }

    /// Handles up to `RX_BURST` entries of `rx`; stored packets go on to `out`.
    pub fn poll<S: BlockStore>(
        &mut self,
        rx: &mut ShardRx<'_>,
        out: &mut SenderTx<'_>,
        store: &S,
    ) -> usize {
        self.tx.reap();
        let mut n = 0;
        self.fetches = 0;
        if !self.pending.is_empty() {
            let (tx, c, wire, me) = (
                &mut self.tx,
                &mut self.counters,
                &mut self.resp.wire,
                self.cfg.me,
            );
            let home = &self.home;
            self.fetches = self
                .pending
                .retry(|r| send_redirect(home, tx, wire, c, me, r));
        }
        while n < RX_BURST {
            let Some(e) = rx.pop(&Hw) else { break };
            n += 1;
            match e {
                ToShard::Pkt { pkt, src, rx_ts } => {
                    let mut ev = None;
                    let r = self
                        .home
                        .ingest_from(pkt.bytes(), Some(src), rx_ts, &mut ev);
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
                            let f = ToSender::Pkt {
                                pkt,
                                book: ing.book,
                                epoch16: ing.epoch16,
                            };
                            hop(out, f, &mut self.counters);
                        }
                    }
                }
                ToShard::Fetch { to, q } => {
                    self.fetches += 1;
                    let (tx, c, cfg) = (&mut self.tx, &mut self.counters, &self.cfg);
                    match q {
                        Fetch::Key { session, pkt_seq } => {
                            let ring = self.home.ring();
                            self.resp.key(to, session, pkt_seq, ring, store, tx, c, cfg);
                        }
                        Fetch::Block { height } => self.resp.block(to, height, store, tx, c, cfg),
                        // The RX core sends RANGE fetches to the sender and REDIRECTs as
                        // `ToShard::Redirect`.
                        Fetch::Range { .. } | Fetch::Redirect { .. } => bump(&mut c.fetch_bad),
                    }
                }
                ToShard::Redirect {
                    down,
                    to,
                    session,
                    resend_from,
                } => {
                    self.fetches += 1;
                    let r = Redirect {
                        down,
                        to,
                        session,
                        resend_from,
                    };
                    // Behind earlier refused ones, so a session's redirects leave in order.
                    let (tx, c, wire) = (&mut self.tx, &mut self.counters, &mut self.resp.wire);
                    if !self.pending.is_empty()
                        || !send_redirect(&self.home, tx, wire, c, self.cfg.me, r)
                    {
                        self.pending.push(r, &mut self.counters);
                    }
                }
            }
        }
        n
    }
}

/// The sender core: every destination's frames and history.
pub struct SenderCore<T: TxRing> {
    cfg: NodeConfig,
    fanout: Fanout,
    tx: T,
    counters: Counters,
}

impl<T: TxRing> SenderCore<T> {
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn tx(&self) -> &T {
        &self.tx
    }

    /// Up to `RX_BURST` entries from each ring of `rx`, then the frame timers.
    pub fn poll(&mut self, now: Nanos, rx: &mut [SenderRx<'_>]) -> usize {
        self.tx.reap();
        let mut n = 0usize;
        let (tx, c, cfg) = (&mut self.tx, &mut self.counters, &self.cfg);
        for r in rx.iter_mut() {
            for _ in 0..RX_BURST {
                let Some(e) = r.pop(&Hw) else { break };
                n += 1;
                match e {
                    ToSender::Pkt { pkt, book, epoch16 } => {
                        self.fanout
                            .push(pkt.bytes(), book, epoch16, now, tx, c, cfg);
                    }
                    ToSender::Range { dst, from, last } => {
                        self.fanout.resend(dst, from, last, tx, c, cfg);
                    }
                }
            }
        }
        self.fanout.timers(now, tx, c, cfg);
        n
    }

    /// Sends every open `DATA` frame now, whatever its age.
    pub fn flush(&mut self, now: Nanos) {
        self.fanout
            .flush(now, &mut self.tx, &mut self.counters, &self.cfg);
    }
}

/// Splits one box's config into its cores: the RX core over `ingest` and `fetch`, one shard per
/// entry of `shard_tx` (its fetch-answer TX queue; at least one), and the sender over `tx`.
/// Shard `i` holds the sessions [`shard_of`] gives it and `ring_slots / n` slots
/// ([`HomeConfig::shard`](crate::HomeConfig::shard)).
pub fn split<R: RxRing, F: RxRing, T: TxRing>(
    cfg: &NodeConfig,
    ingest: R,
    fetch: F,
    shard_tx: Vec<T>,
    tx: T,
) -> (RxCore<R, F>, Vec<ShardCore<T>>, SenderCore<T>) {
    let n = shard_tx.len();
    let lite = lite(cfg);
    let rx = RxCore {
        ingest,
        fetch,
        gate: Gate::new(cfg),
        counters: Counters::default(),
        fetches: 0,
        pending: Pending::default(),
    };
    let shards = shard_tx
        .into_iter()
        .enumerate()
        .map(|(i, tx)| ShardCore {
            home: DataHome::new(cfg.home.shard(i, n)),
            events: Vec::with_capacity(cfg.max_events),
            cfg: lite.clone(),
            tx,
            resp: Responder::default(),
            counters: Counters::default(),
            fetches: 0,
            pending: Pending::default(),
        })
        .collect();
    let sender = SenderCore {
        fanout: Fanout::new(cfg),
        cfg: lite,
        tx,
        counters: Counters::default(),
    };
    (rx, shards, sender)
}

/// `cfg` without its key tables, for the shards and the sender: they read only timers, limits
/// and addresses, so every session's MAC key and every requester's `K_fetch` stay where they
/// are used (a shard's own `DataHome`, the RX core's gate), once each.
fn lite(cfg: &NodeConfig) -> NodeConfig {
    let h = &cfg.home;
    NodeConfig {
        home: crate::HomeConfig {
            mode: h.mode,
            books: h.books.clone(),
            keys: std::collections::BTreeMap::new(),
            ring_slots: h.ring_slots,
            index_key: h.index_key,
        },
        src: cfg.src,
        me: cfg.me,
        dests: cfg.dests.clone(),
        batch_ns: cfg.batch_ns,
        hb_ns: cfg.hb_ns,
        history: cfg.history,
        max_range: cfg.max_range,
        log_scan: cfg.log_scan,
        max_events: cfg.max_events,
        fetch_keys: std::collections::BTreeMap::new(),
        fetch_epoch: cfg.fetch_epoch,
        fetch_rate: cfg.fetch_rate,
        fetch_burst: cfg.fetch_burst,
    }
}
