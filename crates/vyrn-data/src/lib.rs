//! The data tier (`vyrn-data`): stores the client's second copy of each request packet, fans it
//! out to every replica, and answers fetches from its RAM ring and from the logged blocks it can
//! read through a [`vyrn_log::BlockStore`].
//!
//! Spec: spec/07-replication.md §5 (this crate's chapter), 01 §6.1 (the packet), 03 ARC-D12 and
//! flows F2/F7, 04 P3/D6, 07 §8.2 (the block record whose payloads are served), 11 §1.4
//! (layer 4: this crate depends on `vyrn-log` and `vyrn-nic`, and on `vyrn-wire`,
//! `vyrn-crypto` and `vyrn-types` below them).
//!
//! # Contract
//!
//! The byte formats below are the contract; [`frame`] implements them and
//! `tests/golden/vyrn_data_vectors.{py,out}` holds vectors another implementation can check.
//! Every multi-byte field is little-endian (01 §6). Items marked *gap* are this crate's choice
//! where 07 is silent; each is listed in the PR as a spec gap.
//!
//! ## Roles
//!
//! - **Writer.** A client sends copy 2 of each request packet (01 §6.1, exact UDP payload) to its
//!   data home's ingest queue (`PROTO_DATA_PORT`). Only the [`DataNode`] that owns the queue
//!   writes its [`ring::Ring`]; nothing else mutates it.
//! - **Readers.** (a) The destinations (every voter and the warm standby, 07 §5.1) receive `DATA`
//!   and `DATA_HB` frames. (b) Any replica may send a fetch (§ Fetch) to the fetch queue and gets
//!   the answer at the request's source address. (c) The control core drains [`Event`]s.
//! - **Log source.** A [`vyrn_log::BlockStore`] the node reads, never writes. *Gap:* 07 §5 gives
//!   a data box only its RAM ring; this crate also serves packets of logged blocks so a fetch that
//!   misses the ring (older than its retention) still has an answer before the sequencer.
//!
//! ## Ingest (07 §5.2), in order, with its reject reasons ([`Reject`])
//!
//! 1. Parse (01 §6.1, `vyrn_wire::Request`): `count ∈ 1..=10`, `len = 32 + 16·count`, flags bits
//!    1–7 and `reserved` are 0, and `pkt_seq ≥ 1` → else `Header`. `book` must be one this home
//!    serves → else `Book`.
//! 2. MAC: BASE checks `tag_seq` under the session's `K_seq`, CHAIN checks `tag_com` under
//!    `K_com` ([`Mode`]). No key for the session → `UnknownSession`. A failed tag → `BadMac` and
//!    an [`Event::BadMac`]. The data tier never closes a session.
//! 3. Dedupe by `(session, pkt_seq)` with `hi` and a 256-bit window below it ([`dedupe`]):
//!    a new `pkt_seq` is stored; a repeat with the stored copy's logical content (04 D3:
//!    `session`, `pkt_seq`, `count`, `book`, the messages; `flags` bit 0, `epoch16` and the tags
//!    may differ) is a resend: byte-identical → `Duplicate`, otherwise a new variant that is
//!    stored and forwarded too, because the sequencer may accept those exact bytes (04 D2), up
//!    to `MAX_VARIANTS` per `pkt_seq` (*gap*); a repeat with different logical content is client
//!    equivocation (04 §2.4): both are stored, the first is
//!    the one forwarded and served, and [`Event::CopyConflict`] carries both packets;
//!    `pkt_seq ≤ hi − 256` → `Late` (*gap:* dropped and counted, never forwarded).
//! 4. Hash: full BLAKE3-256 over bytes `0..16+16n`; `pkt_hash` is its first 8 bytes (01 §3).
//! 5. Store in the RAM ring, indexed by a fixed open-addressed table ([`ring`]) whose entries are
//!    `(session, pkt_seq, pkt_hash, slot)`. *Gap:* the bucket is a keyed hash of `(session,
//!    pkt_seq)`, not `pkt_hash`, because the box looks packets up by key. *Gap:* the ring evicts
//!    by slot count, not by `REP_DATA_RING_S`; size it as rate × retention.
//! 6. Fan out: append to every destination's open `DATA` frame.
//!
//! ## Data frame (07 §5.3)
//!
//! ```text
//! off size field
//!   0   2  magic 0x4450 ("PD")      2 1 version 1     3 1 kind (1 DATA, 2 DATA_HB, 3 FETCH_RESP)
//!   4   2  book                     6 2 epoch16       8 8 data_seq
//!  16   1  src data box index      17 1 n_pkts       18 2 body_len     20 4 reserved 0
//!  24   …  n_pkts × { pkt_len u16, pkt bytes (pkt_len), pad to 2 with 0 }
//! ```
//!
//! Ordering and meaning of `data_seq`:
//! - `DATA`: per destination, starts at 1, +1 per frame, gapless. A frame holds packets of one
//!   `(book, epoch16)` in the order they were stored. It is sent when the next packet would not
//!   fit, when `(book, epoch16)` changes, or when it is `REP_DATA_BATCH_US` old. *Gap:* the
//!   frame is capped by the NIC's 1514-byte fast-path frame, not 9000 B.
//! - `DATA_HB`: sent to a destination idle for `hb_ns` (07: 100 µs); `n_pkts` 0, `book` and
//!   `epoch16` 0, and `data_seq` = the last `DATA` sent to it (0 before any). *Gap:* this lets a
//!   replica see a lost tail frame.
//! - `FETCH_RESP`: answers one fetch; `data_seq` echoes the request (below).
//!
//! A decoder rejects ([`frame::FrameErr`]) a wrong magic, version, kind or reserved field, a
//! `body_len` other than the bytes after the header, `n_pkts` other than the entries, a packet
//! cut short, nonzero padding, and a `DATA_HB` with a body.
//!
//! ## Fetch (07 §5.3, §5.5) — *gap:* 07 names the messages, this crate fixes their bytes
//!
//! ```text
//! off size field
//!   0   2  magic 0x4650 ("PF")      2 1 version 1     3 1 kind     4 4 reserved 0
//!   8  24  body by kind, unused bytes 0:
//!          1 KEY    session u32, pkt_seq u32        DataFetch{session, pkt_seq}
//!          2 RANGE  dst u8, 7 × 0, from u64, to u64 DataFetch{from, to} of dst's data_seq
//!          3 BLOCK  height u64                      the payloads of a logged block
//!          4 REDIRECT session u32, resend_from u32, down u8, to u8, 14 × 0
//!                                                    a replica's resend_from (07 §5.7 step 3)
//!
//! kind 5 REDIRECT_BATCH (ruled, 07 §5.7), the one variable-length fetch:
//!   0   8  as above, kind 5      8 1 down u8     9 1 to u8     10 2 count u16   12 4 reserved 0
//!  16  8n  count × { session u32, resend_from u32 }, sessions strictly ascending
//! ```
//!
//! - KEY: one `FETCH_RESP` with `data_seq = session << 32 | pkt_seq` and every variant of the
//!   packet in the ring (in the order stored), else the copy in the newest `log_scan` blocks of the log
//!   source, or `n_pkts` 0 if neither has it.
//! - RANGE: the stored `DATA` frames `from..=to` resent byte for byte, those still in the
//!   destination's history; `to − from < max_range` and `from ≥ 1`, `dst` known.
//! - BLOCK: the block's payloads (07 §8.2 data region, split by `count`) in O-order, as
//!   `FETCH_RESP` frames with `data_seq = height`; one empty frame if the block has none or is
//!   not stored. The block is read through `BlockStore::read`, which checks `order_root`.
//! - REDIRECT (*reading*, wire, recorded in 07 §5.7): no answer to the requester. The box
//!   sends the session's `DataRedirect{down → to, resend_from}` (04 §7.6) as its operator
//!   `REDIRECT` line does: to the session's newest copy's address, from the owning shard.
//!   `down` and `to` must be below 8 and differ (04 DR1), else `FrameErr::Position`. Each
//!   message costs one token of the requester's bucket, like any fetch. The box acts on every
//!   admitted one, without a quorum: the client's DR2 makes the replicas' duplicates no-ops.
//! - REDIRECT_BATCH: kind 4 for 1 ..= [`frame::MAX_BATCH`] (181) sessions of one `down → to`
//!   move, so a failover is not capped at one session per message. The sealed form (16 + 8n
//!   bytes, then the tag over all of them) fits one UDP payload of a 1514-byte frame. Decoding
//!   is strict: `count` equals the entries, the sessions are strictly ascending (*reading*: no
//!   duplicates, one canonical encoding; [`frame::FrameErr::Order`]), `down` and `to` as for
//!   kind 4. One token per message; each entry is handled as one kind-4 REDIRECT.
//!
//! **Authentication and rate (*reading*, recorded in 07 §5.5).** A box configured with
//! `K_fetch` keys ([`NodeConfig::fetch_keys`], one 16-byte key per requester address; the `vyrn-data`
//! binary, `bin/vyrn-data-box`, derives them from the roster, 08 §9.6, `Roster::box_fetch_keys`) serves only
//! the authenticated form: the request body, then `tag` u64 = SipHash-2-4(`K_fetch`, the whole
//! body). The body is 32 bytes for kinds 1 to 4 (40 in all) and 16 + 8 × `count` for kind 5
//! (32 in all for one entry).
//! A fetch from an unkeyed address, a plain fetch, or a bad tag is dropped and counted
//! (`fetch_unauth`). Each keyed address has a token bucket (`fetch_rate` per second, burst
//! `fetch_burst`, one token per fetch), made at construction; a fetch over it is dropped and
//! counted (`fetch_limited`). Forged and malformed fetches are refused before a bucket is
//! charged, so they cannot spend an honest source's rate. A box with no keys is in open mode
//! (DEV, tests): plain fetches from anyone, under one shared bucket. Replies are not tagged:
//! a replica checks every fetched packet against `pkt_hash` (07 §5.4), and RANGE resends go to
//! the frame's original destination, so a reply cannot be steered or trusted blindly.
//!
//! A malformed or out-of-range fetch is dropped and counted (`fetch_bad`).
//!
//! ## Two-epoch boundary (08 §4.6) — *reading*, recorded there
//!
//! One key table checks every `epoch16`. From T, [`DataHome::add_epoch`] adds e + 1's keys and
//! `epoch16` picks the table; a copy of neither epoch is [`Reject::Epoch`] (counted in `epoch`),
//! before the MAC, so it raises no event. [`DataHome::retire_epoch`] drops e at activation (new
//! home) or after `EPO_REDIRECT_HOLD_S` (old home).
//!
//! # Hot path
//!
//! The ring slots, its index, the dedupe windows (one per keyed session, made at construction),
//! frame buffers and send history are sized at construction, so [`DataHome::ingest`] allocates
//! nothing (`vyrn-bench`'s `data_ingest` bench counts it with the sealing allocator). Fetches
//! are the cold path.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod config;
pub mod dedupe;
pub mod frame;
pub mod ingest;
pub mod node;
pub mod redirect;
pub mod ring;
mod serve;
pub mod shards;
pub mod spread;

pub use ingest::{DataHome, Event, HomeConfig, Ingested, Mode, Packet, Reject};
pub use node::{Counters, DataNode, FetchKeysErr, NodeConfig};
pub use spread::Spread;
