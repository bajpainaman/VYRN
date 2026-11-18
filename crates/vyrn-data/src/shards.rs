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
//! - **ShardCore** `i` is a whole [`DataHome`] for its sessions (07 §5.2 steps 1–5). A KEY fetch
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
use vyrn_types::{BookId, MAX_REQ_PAYLOAD, Nanos};
use vyrn_wire::{RX_BURST, RxPkt, RxRing, TxRing};

use crate::frame::Fetch;
use crate::ingest::{DataHome, Event};
use crate::node::{Counters, FetchKeysErr, NodeConfig, bump};
use crate::serve::{Fanout, Gate, Responder};
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

/// The RX core: both RX queues and the fetch gate.
pub struct RxCore<R: RxRing, F: RxRing> {
    ingest: R,
    fetch: F,
    gate: Gate,
    counters: Counters,
}

impl<R: RxRing, F: RxRing> RxCore<R, F> {
    pub fn counters(&self) -> &Counters {
        &self.counters
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

    /// One turn: an ingest burst to the shards, then a fetch burst to its owners. `shards` are
    /// the producers of every shard's ring, in shard order. Returns the frames handled.
    pub fn poll(
        &mut self,
        now: Nanos,
        shards: &mut [ShardTx<'_>],
        sender: &mut SenderTx<'_>,
    ) -> usize {
        let n_shards = shards.len();
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
        for p in burst.iter().take(m) {
            let Ok(f) = nic_frame::parse(self.fetch.bytes(p)) else {
                bump(&mut self.counters.fetch_bad);
                continue;
            };
            let src = f.hdr.src;
            let Some(q) = self.gate.admit(src, f.payload, now, &mut self.counters) else {
                continue;
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
            };
            if let Some(s) = shards.get_mut(shard) {
                hop(s, ToShard::Fetch { to: src, q }, &mut self.counters);
            }
        }
        self.fetch.release(m);
        n.saturating_add(m)
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
}

impl<T: TxRing> ShardCore<T> {
    pub fn counters(&self) -> &Counters {
        &self.counters
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
                    let (tx, c, cfg) = (&mut self.tx, &mut self.counters, &self.cfg);
                    match q {
                        Fetch::Key { session, pkt_seq } => {
                            let ring = self.home.ring();
                            self.resp.key(to, session, pkt_seq, ring, store, tx, c, cfg);
                        }
                        Fetch::Block { height } => self.resp.block(to, height, store, tx, c, cfg),
                        // The RX core sends RANGE fetches to the sender.
                        Fetch::Range { .. } => bump(&mut c.fetch_bad),
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
    let rx = RxCore {
        ingest,
        fetch,
        gate: Gate::new(cfg),
        counters: Counters::default(),
    };
    let shards = shard_tx
        .into_iter()
        .enumerate()
        .map(|(i, tx)| ShardCore {
            home: DataHome::new(cfg.home.shard(i, n)),
            events: Vec::with_capacity(cfg.max_events),
            cfg: cfg.clone(),
            tx,
            resp: Responder::default(),
            counters: Counters::default(),
        })
        .collect();
    let sender = SenderCore {
        fanout: Fanout::new(cfg),
        cfg: cfg.clone(),
        tx,
        counters: Counters::default(),
    };
    (rx, shards, sender)
}
