# 01. Conventions: the contract every chapter follows

This chapter is normative. If another chapter disagrees with it, this chapter wins and the other
chapter has a bug. A chapter that needs a name, constant or layout that is not here defines it in
its own **Local definitions** section, using its chapter prefix (for example `ENG_` or `REP_`), and
lists it in its **Requests to 01** section so that it can be promoted here.

## 1. Words

| Term | Meaning |
|---|---|
| **book** | One instrument's central limit order book with price-time priority. One book runs on exactly one sequencer box at a time. |
| **home** | The region whose facilities run the active book: `TYO`, `LDN` or `NYC`. |
| **epoch** | One 8-hour period in which one home is active. Numbered by `Epoch` (u32). |
| **facility** | One data center in a home's metro. A home has `F1…Fn` (n = 4 in base mode, 5 in chain mode). |
| **sequencer** | The box (process `vyrn-seq`) that receives orders, matches them, and sends fills. There is exactly one per book per epoch. |
| **replica** | A box (process `vyrn-replica`) that replays the order stream with the same engine and votes in consensus. In chain mode a replica is a **validator** (process `vyrn-validator`). |
| **lane** | A pinned core in the sequencer that owns a fixed shard of accounts: their sessions, risk, and resting orders. Identified by `LaneId`. |
| **lane FIFO** | A lane's own queue of its own resting orders at one price level, on one side. |
| **level FIFO** | The book's queue at a price level: the merge of all lane FIFOs at that level, ordered by (rx timestamp, lane id). It is never stored. The BBO core computes it when it consumes from it. |
| **cut** | A vector with one `LaneSeq` per lane. Lane ops at or below the cut are ordered before a step, and later ops after it. |
| **cut core** | The pinned core that reads all lane counters and publishes cuts. |
| **BBO core** | The pinned core that executes every step: crosses, improves, depletions and rescans. It is the only writer of fills and of the BBO. |
| **step** | One atomic action of the BBO core, identified by `StepId`. Every step logs the cut it used. |
| **join** | A passive order priced at or behind its lane's BBO snapshot on its own side. A join stays in its lane. |
| **improve** | A passive order priced strictly inside the spread of its lane's snapshot. It goes to the BBO core. |
| **cross** | An order priced at or through the opposite side of its lane's snapshot. It goes to the BBO core. |
| **depletion** | A step in which the best level on one side turns out to be empty, so the BBO core rescans the lane FIFOs to find the new best level. |
| **rescan** | A step in which the BBO core scans lane FIFOs over a price range: the slow path of the crossing lemma (`05-engine.md`). |
| **snapshot** | A versioned BBO `(bid, ask, version)` that the BBO core publishes. Lanes classify orders against it. |
| **order stream** | The sequencer's ordering records: per-packet records and per-step records. It does not contain client payloads. |
| **data** | The client payloads (packets) themselves, stored by hash. |
| **block** | 1 ms of order stream with a header. It is the unit of consensus. |
| **certificate** | Signatures from a quorum of replicas over a block header, or over a handoff record. |
| **data tier** | The `vyrn-data` processes that receive the client copy of each packet and fan it out to the replicas. |
| **mode** | `BASE` (off-chain, n = 4) or `CHAIN` (on-chain, n = 5). The binaries are the same and the mode is configuration. |

## 2. Hard constraints (repeated from 00)

`C-UNIX`, `C-NOCHIP`, `C-COTS`, `C-ONEBIN`. Every chapter must state how its design meets them.
For example: a NIC backend list that names only COTS NICs, and a statement that no GPU, FPGA or
P4 switch is used.

## 3. Primitive types

All multi-byte integers on the wire and on disk are **little-endian**. In Rust these are newtypes
over the listed integer type, defined in crate `vyrn-types`.

| Type | Repr | Meaning |
|---|---|---|
| `Tick` | u32 | Absolute price index in the book's tick ladder. price = `tick × tick_size`. |
| `Qty` | u32 | Quantity in lots. Notional arithmetic uses u128 with checked operations. |
| `AccountId` | u32 | One account. An account belongs to exactly one lane per epoch. |
| `SessionId` | u32 | One client session. A session belongs to one account. |
| `LaneId` | u8 | 0 … `N_LANES − 1`. |
| `LaneSeq` | u64 | Per-lane sequence of applied ops. Starts at 1 each epoch. |
| `StepId` | u64 | Per-book sequence of BBO-core steps. Starts at 1 each epoch. |
| `Handle` | u32 | A lane-local order handle: bits 0–23 are the slot, bits 24–31 the generation. The lane is implied by the session. |
| `Epoch` | u32 | Epoch number. The wire carries its low 16 bits. |
| `Height` | u64 | Block height. Never resets. |
| `Nanos` | u64 | Nanoseconds of PTP time (TAI). Only the NIC RX timestamp enters the order stream. |
| `BookId` | u16 | Instrument. |
| `Hash` | [u8; 32] | BLAKE3-256. |
| `PktHash` | u64 | The first 8 bytes of BLAKE3-256 of a packet's bytes 0..end-of-messages (the tags excluded). |
| `Tag` | u64 | SipHash-2-4 MAC output. |
| `SigScheme` | u8 | Signature scheme of a key and of every signature it makes (§14.20): 0 Ed25519, 1 hybrid Ed25519 + ML-DSA-44, 2 hybrid Ed25519 + ML-DSA-65. Fixed per key in its certificate and per epoch in `EpoConfig.sig_scheme` (08 §2.3); the wire carries no scheme byte. |
| `PubKey`, `Sig` | bytes | A public key and a signature of the scheme in force: 32 and 64 B (scheme 0), 1,344 and 2,484 B (scheme 1), 1,984 and 3,373 B (scheme 2). A hybrid value is the Ed25519 part followed by the ML-DSA part. `Ed25519Sig` = `[u8; 64]`. |

## 4. Cryptography

| Purpose | Algorithm |
|---|---|
| Packet MAC | SipHash-2-4, 128-bit key, 64-bit tag. The first failed MAC on a session closes the session. |
| Hash | BLAKE3-256 everywhere (blocks, data, log chain, KDF via `derive_key`). |
| Validator votes, sequencer block signatures, certificates | Ed25519 (scheme 0) until the post-quantum switch, then hybrid Ed25519 + ML-DSA-44 (scheme 1, FIPS 204). A hybrid signature is valid only if both parts verify. `EpoConfig.sig_scheme` selects the scheme per epoch (§14.20). A certificate is a list of (validator index, signature). |
| Release keys, operator identity keys (cold, long-lived) | Hybrid Ed25519 + ML-DSA-65 (scheme 2, §14.20). |
| Session open (wallet signature) | Ed25519 or secp256k1 (EVM wallets). Chain mode only. Not post-quantum; 09 §6.8 states the exposure and the migration hook. |
| Key agreement for session keys | X25519 with each validator's static key, then BLAKE3 `derive_key` with context `"vyrn v1 session"`. |
| State commitment (chain mode) | A lattice hash (LtHash-style) over the per-second net diff. Details in `09-chain.md`. |

## 5. Constants

All values are **budgets** unless marked otherwise. A constant written as `name = value` here is
the only definition of that name.

| Name | Value | Meaning |
|---|---|---|
| `N_LANES_REF` | 49 | Lanes on the reference box: 42 dedicated + 7 pooled (§14.15) |
| `N_LANES_CONSUMER` | 11 | Lanes on the consumer box (one core is the hasher, 06) |
| `MSG_BYTES` | 16 | Every client message and every response record |
| `PKT_HDR_BYTES` | 16 | Request and response packet header |
| `MAX_MSGS_PER_PKT` | 10 | Every accepted packet, up to 10 messages, meets `LAT_MAX_NS` for every message in it |
| `TAG_BYTES` | 8 | One MAC tag; every request packet carries two |
| `MAX_REQ_PAYLOAD` | 192 | 16 + 10 × 16 + 2 × 8 |
| `LAT_MAX_NS` | 1000 | **Hard maximum**, not a percentile: first bit in → first bit of the response out, every message type, every message index 0–9 (REQ-LAT-1). Enforced by deadline admission (§14.1) |
| `NIC_FLOOR_NS` | 560 | **Maximum** NIC echo (RX + TX, wire to wire) over the whole B1 run for a NIC to qualify; the TX tail after the doorbell is not covered by deadline admission, so it must be bounded at the NIC. Budgets use RX 320 + TX 240 |
| `LANE_NS_PER_MSG` | 30 | Average lane work per message, all costs amortized; inside a packet, the marginal cost is `LANE_PASS1_NS` + `LANE_APPLY_NS` (§14.2) |
| `BBO_CROSS_NS` | 15 | BBO-core work per step, maximum: 8 fills or one level per step, then continuation steps (§14.15) |
| `BBO_IMPROVE_NS` | 8 | BBO-core work per improve or depletion |
| `BBO_MAX_LOAD` | 0.60 | Maximum busy fraction of the BBO core |
| `CROSS_CAP` | 10_000_000 | Crosses per second per book at `BBO_MAX_LOAD` |
| `CUT_REFRESH_NS` | 100 | Maximum age of the newest published cut, with two cut cores that read 25 lanes each (§14.3) |
| `BLOCK_NS` | 1_000_000 | Block length |
| `FINALITY_MAX_MS` | 10 | REQ-FIN-1: hard maximum for every accepted order while the metro network meets its delay bound (§14.0 fact 3) |
| `EPOCH_HOURS` | 8 | Epoch length |
| `EPOCH_BOUNDARIES_UTC` | 00:00 TYO, 08:00 LDN, 16:00 NYC | Start of each home's epoch |
| `N_BASE`, `Q_BASE` | 4, 3 | Replica-set size and quorum in base mode (f = 1) |
| `N_CHAIN`, `Q_CHAIN` | 5, 4 | Validator-set size and quorum in chain mode (f = 1) |
| `F` | 1 | Byzantine faults tolerated |
| `CLIENT_SPLIT_BASE` | 2 Rust, 2 Vx | Neither client can reach `Q_BASE` alone |
| `CLIENT_SPLIT_CHAIN` | 3 Rust, 2 Vx | Neither client can reach `Q_CHAIN` alone |
| `FAILOVER_SILENCE_MS` | 2 | Sequencer silence that starts a failover |
| `FAILOVER_TARGET_MS` | 20 | Published sequencer-failover outage |
| `SLOT_BITS`, `GEN_BITS` | 24, 8 | `Handle` layout: 16M slots per lane |
| `RESP_RETAIN_PKTS` | 65_536 | Response packets per session kept by the **recovery service** on a replica; the sequencer keeps `RESP_HOT_RING_BYTES` per lane (§14.6) |
| `MAX_SESSIONS_PER_LANE` | 4_096 | Sessions one lane serves |
| `TICK_HOT_WINDOW` | 4_096 | Levels per side kept in the lane's dense level array; the rest go to its overflow structure |
| `SNAPSHOT_REFRESH` | once per inbound packet | When a lane re-reads the BBO snapshot |
| `REPL_PATHS` | 2 | Independent switch paths for order frames |
| `CACHE_LINE` | 64 (x86-64, Graviton), 128 (Apple M-series) | Alignment of every hot shared structure |
| `PQ_HEDGE` | 4 on `vyrn-seq` (and the standby once promoted), 2 on a voter, 8 for a `HandoffSig` | Parallel ML-DSA signing attempts per hybrid signature, each with fresh randomness, one per PQ core; the first to finish is used (§14.20) |
| `PQ_SIGN_MAX_US` | 400 at 4 attempts, 750 at 2, 250 at 8 | **Maximum** (budget) from the signed bytes to the ML-DSA-44 part (§14.20). Exceeded with probability ≤ 10⁻⁹ per signature (analytic, from the rejection-loop model fitted to the measured distribution); a later signature counts as a slow box, which is the one fault f |
| `PQ_VERIFY_US` | 35 | ML-DSA-44 verification per signature (budget; 29–32 µs measured, §14.20) |

## 6. Wire layouts

These layouts are canonical. `04-protocol.md` gives the semantics and the state machines.

### 6.1 Request packet (client → sequencer and → data tier, UDP)

```
off size field
  0   4  session    SessionId
  4   4  pkt_seq    u32    per session, starts at 1, +1 per packet, gapless
  8   1  count      u8     1..=MAX_MSGS_PER_PKT
  9   1  flags      u8     bit0 = resend of an earlier pkt_seq; other bits 0
 10   2  epoch16    u16    low 16 bits of the epoch the client believes is active
 12   2  book       BookId
 14   2  reserved   u16    must be 0
 16 16n  msgs       count × 16-byte messages
16+16n 8 tag_seq    SipHash-2-4(K_seq,  bytes 0 .. 16+16n)
24+16n 8 tag_com    SipHash-2-4(K_com,  bytes 0 .. 16+16n)   0 in BASE mode
```

### 6.2 Messages (16 bytes each)

`flags` for orders: bit 0 = side (0 buy, 1 sell); bits 1–2 = TIF (0 day, 1 IOC, 2 FOK,
3 auction-only); bit 3 = post-only; bits 4–5 = STP (0 none, 1 cancel newest, 2 cancel oldest,
3 cancel both); bits 6–7 = 0.

| Code | Name | Bytes 0–1 | 2–3 | 4–7 | 8–11 | 12–15 |
|---|---|---|---|---|---|---|
| 0x01 | `New` | type, flags | 0 | tick | qty | client_tag u32 |
| 0x02 | `Cancel` | type, 0 | 0 | handle | 0 | client_tag |
| 0x03 | `Reduce` | type, 0 | 0 | handle | reduce_by qty | client_tag |
| 0x04 | `Replace` | type, flags (side must match) | 0 | handle | new tick | new qty |
| 0x10 | `Heartbeat` | type, 0 | 0 | 0 | 0 | 0 |
| 0x11 | `ResendReq` | type, 0 | 0 | from resp_seq | to resp_seq | 0 |
| 0x12 | `CancelAll` | type, 0 | 0 | 0 | 0 | client_tag |

A message is identified by `(session, pkt_seq, index)`, where `index` is its position 0–9 in its
packet. A `Replace` loses time priority unless it only reduces quantity at the same tick. A
same-tick reduction is a `Reduce`.

### 6.3 Response packet (sequencer → client)

```
off size field
  0   4  session
  4   4  resp_seq   u32   per session, starts at 1, gapless
  8   1  count      u8    1..=16
  9   1  flags      u8    bit0 = resend
 10   2  epoch16
 12   4  echo_pkt   u32   pkt_seq of the request this answers (0 for unsolicited, e.g. maker fills)
 16 16n  records
16+16n 8 tag        SipHash-2-4(K_out, bytes 0 .. 16+16n)
```

### 6.4 Response records (16 bytes each)

| Code | Name | 0 | 1 | 2–3 | 4–7 | 8–11 | 12–15 |
|---|---|---|---|---|---|---|---|
| 0x81 | `Ack` (resting) | type | index | 0 | handle | tick | client_tag |
| 0x82 | `Fill` | type | index (0xFF = maker or auction fill) | liq (0 maker, 1 taker, 2 auction) | handle | tick | qty |
| 0x83 | `Reject` | type | index | reason u16 | detail u32 | 0 | client_tag |
| 0x84 | `CancelAck` | type | index | 0 | handle | canceled qty | client_tag |
| 0x85 | `Out` | type | index | cause u16 (1–8, §14.10, 04 §7.3) | handle | qty out | client_tag |
| 0x86 | `EpochNotice` | type | 0 | 0 | next epoch | next home code | seconds to boundary |
| 0x87 | `Bust` (CHAIN only) | type | 0xFF | liq (as `Fill`) | handle | tick | reversed qty |
| 0x88 | `Attest` (out of stream) | type | level (1 `DURABLE`, 2 `FINAL`, 3 `SETTLED`) | 0 | upto (`resp_seq`) | low 32 bits of the block height | 0 |

`Out` causes (§14.10): 1 IOC remainder, 2 STP, 3 auction unfilled, 4 expired, 5 post-only,
6 lane moved, 7 disconnect, 8 admin. No cause means FOK: an unfillable `FOK` is
`Reject FOK_UNFILLABLE`. `Bust` is defined in 09 §17.2 and `Attest` in 04 §7.5; `vyrn-wire`
(`crates/engine/vyrn-wire/src/record.rs`) encodes and decodes all eight records.

A taker gets one `Fill` per price level it trades at. A maker gets one `Fill` per order of its
own that is hit. A fill's execution ID is `(StepId, ordinal in step)`. The fill does not carry it;
the drop copy and the market data do.

### 6.5 Reject reasons (u16)

| Code | Name | Code | Name |
|---|---|---|---|
| 1 | `BAD_MAC` (session closed) | 11 | `FOK_UNFILLABLE` |
| 2 | `BAD_SEQ` | 12 | `UNKNOWN_HANDLE` |
| 3 | `BAD_TYPE` | 13 | `TOO_LATE` (already filled) |
| 4 | `BAD_TICK` (outside band) | 14 | `BOOK_HALTED` |
| 5 | `BAD_QTY` | 15 | `EPOCH_MISMATCH` |
| 6 | `RISK_CREDIT` | 16 | `STP` |
| 7 | `RISK_POSITION` | 17 | `WRONG_LANE` |
| 8 | `RISK_ORDER_COUNT` | 18 | `SESSION_CLOSED` |
| 9 | `RATE_LIMIT` | 19 | `AUCTION_PHASE` |
| 10 | `POST_ONLY_WOULD_CROSS` | 20 | `SIDE_MISMATCH` |

### 6.6 Order-stream records (sequencer → replicas)

The logical records are below. On the wire they are delta-encoded with LEB128 varints, as
`07-replication.md` specifies.

```
PacketRecord  { lane: LaneId, count: u8, flags: u8,   // bit0 SHED, bit1 ADVANCE (count = 0)
                session: SessionId, pkt_seq: u32,
                rx_ts: Nanos, pkt_hash: PktHash, first_lane_seq: LaneSeq,
                fills_applied: StepId }   // the last step whose fill events this lane applied
                                          // before it processed this packet; this makes balance
                                          // checks that use fill proceeds replayable
StepRecord    { step: StepId, kind: StepKind, src_lane: LaneId, src_lane_seq: LaneSeq,
                flags: u8,                     // bit1 CROSS: the source's lane route was Cross,
                                               // clear = Improve; 0 without a source (05 §4.15)
                cut: [LaneSeq; N_LANES] }      // kind = Cross | Improve | Depletion | Rescan | Idle
RouteRecord   { lane: LaneId, lane_seq: LaneSeq, cross: bool }
                                          // an op the lane classified Cross (true) or Improve,
                                          // forwarded or rejected; replay routes it the same way
                                          // (05 §10, 10 M8)
BlockHeader   { height: Height, epoch: Epoch, book: BookId, first_step: StepId,
                last_step: StepId, prev: Hash, order_root: Hash, data_root: Hash,
                seq_sig: Sig }            // scheme of `epoch` (§14.20): 64 B, or 2,484 B hybrid
AcctTake      { lane: LaneId, account: AccountId, ver: u32, lane_seq: LaneSeq }
                                          // pooled lanes only: one per token take (§14.17.4)
HandoffRecord { book: BookId, epoch: Epoch, last_step: StepId, last_height: Height,
                state_root: Hash, log_hash: Hash, next_home: HomeCode, next_seq_key: PubKey }
```

`HomeCode`: 1 = TYO, 2 = LDN, 3 = NYC.

## 7. Invariants

Every chapter refers to these by name. A chapter can add invariants of its own, named
`INV-<CHAPTER>-<n>`.

| Name | Statement |
|---|---|
| `INV-WRITER` | Every mutable field in the engine has exactly one writer core. Lanes write orders and tombstones. The BBO core writes filled quantities, the BBO and snapshots. The cut core writes cuts. |
| `INV-DET` | The engine's output (every response, every state byte) is a pure function of (snapshot at height h, order stream and data from h onward). No clock read, random number, hash-map iteration order, float or thread timing affects it. |
| `INV-FRAME-FIRST` | The order-stream record for a step is written to both replication TX queues before the step's first fill is written to any client TX queue. |
| `INV-UNCROSSED` | Every published snapshot has bid < ask, or one side empty. |
| `INV-LANE-NOMATCH` | A lane never decides a fill. Only the BBO core does. |
| `INV-CUT-MONO` | Successive cuts are pointwise non-decreasing. A step's cut is at least the previous step's cut. |
| `INV-FENCE` | After cert(HandoffRecord e, S), no replica accepts a record of epoch e with a step greater than S. |
| `INV-NOALLOC` | No heap allocation happens on a pinned core after `seal()`. |
| `INV-QUORUM` | A block is final when it has `Q_BASE` (base) or `Q_CHAIN` (chain) valid signatures from distinct replicas. |
| `INV-ACK-AFTER-CUT` | A lane sends an `Ack` or `CancelAck` only after a published cut includes the op. |

## 8. Requirement IDs

`02-requirements.md` defines them. Other chapters cite them, and none redefine them.

| Prefix | Area |
|---|---|
| `REQ-LAT-*` | Latency |
| `REQ-THR-*` | Throughput |
| `REQ-FIN-*` | Finality and durability |
| `REQ-EPO-*` | Epochs and handoff |
| `REQ-CHN-*` | Chain mode |
| `REQ-PLT-*` | Platform (Unix, COTS, no custom chips) |
| `REQ-OPS-*` | Operations |
| `REQ-SEC-*` | Security |

Benchmarks are `B1, B2, …` and are defined in `11-build.md`. B1–B5 are fixed by `DESIGN.md` §9.

## 9. Software names

| Kind | Names |
|---|---|
| Binaries | `vyrn-seq`, `vyrn-replica`, `vyrn-validator`, `vyrn-data`, `vyrn-md` (market data), `vyrn-dropcopy`, `vyrn-admin`, `vyrn-sim` (deterministic simulator), `vyrn-bench` |
| Rust crates | `vyrn-types`, `vyrn-wire`, `vyrn-crypto`, `vyrn-nic` (Rust side) with `vyrn-nic-shim` (C), `vyrn-lane`, `vyrn-cut`, `vyrn-bbo`, `vyrn-engine` (joins lane, cut and BBO for live and replay), `vyrn-risk`, `vyrn-log`, `vyrn-data`, `vyrn-consensus` (on Commonware), `vyrn-replica`, `vyrn-epoch`, `vyrn-chain`, `vyrn-md`, `vyrn-sim`, `vyrn-bench` |
| Vx | `vyrn-vx-client` (validator replay client), `vyrn-vx-oracle` (reference book, also built as a shared library through `pub fn`) |
| C | `vyrn-nic-shim` only. About 100–300 lines wrapping ef_vi and DPDK. |

Languages are fixed: Rust for every binary, C only for `vyrn-nic-shim`, Vx for `vyrn-vx-client` and
`vyrn-vx-oracle`. There is no C++.

## 10. Hardware targets

| Target | CPU | NIC | OS | Role |
|---|---|---|---|---|
| `REF` | 1 × AMD EPYC 9575F (64 cores, 8 CCDs of 8, 256 MB L3), 12 × DDR5 | 4 × AMD Solarflare X2541 100GbE (ef_vi + CTPIO) | Linux 6.6+ LTS | sequencer, replica, validator |
| `CONSUMER` | AMD Ryzen 9 9950X3D (16 cores, 128 MB L3) | 1 × 100GbE COTS (Solarflare X2541 or ConnectX-6 Dx) | Linux 6.6+ | full latency, ~250M msgs/s per book |
| `AWS` | the largest 200 Gbps `.metal` instance; use one NUMA node | ENA via DPDK | Linux | 1 µs inside the instance; wire latency is Nitro's |
| `DEV` | Apple M-series Mac | none (sim NIC) or kernel UDP | macOS | development, `vyrn-sim`, Vx oracle |

### Reference core map (EPYC 9575F)

| Cores | CCD | Use |
|---|---|---|
| 0 | 0 | fill TX core C (§14.17) |
| 1 | 0 | cut core A (lanes 0–24) |
| 2 | 0 | BBO core |
| 3 | 0 | fill TX core A (CTPIO; lanes 0–24) |
| 4 | 0 | order-stream core A (lanes 0–24) |
| 5 | 0 | fill TX core B (lanes 25–48) |
| 6 | 0 | cut core B (lanes 25–48) |
| 7 | 0 | order-stream core B (lanes 25–48) |
| 8–49 | 1–6 | 42 dedicated lanes (lanes 0–41; one firm each) |
| 50 | 6 | order hasher (BLAKE3 for the HASH frames) |
| 51 | 6 | OS, IRQs, housekeeping, control (admin, epoch, metrics, lane watchdog); the only core that is not isolated |
| 52–55 | 6 | spare cores for planned, cooperative lane evacuation; a lane silent for > 1 ms fail-stops the sequencer. Under scheme 1 they are also the PQ signing cores: the four attempts of `seq_sig`'s ML-DSA part (`PQ_HEDGE`, §14.20). An evacuation may take 55 and 54 only, which lowers `PQ_HEDGE` to 3 or 2 while it lasts; 52 and 53 are never taken under scheme 1 |
| 56–62 | 7 | the pooled lane group: lanes 42–48, 7 cores in one CCD (§14.15) |
| 63 | 7 | spare; under scheme 1, the ML-DSA half of the finality listener's vote checks (07 §6.8) |

## 11. Determinism rules (for all engine code)

1. No floating point in any state or any decision.
2. No `HashMap`/`HashSet` with a random seed. Use a fixed hasher, or better, use arrays indexed
   by dense IDs.
3. The clock enters state on exactly one path: the NIC RX timestamp written into the
   `PacketRecord`. The deadline-admission check (§14.1) may also read the clock, because its
   decision is logged (SHED / `Shed`) and replay reads that decision instead of the clock.
   Timers fire on order-stream time, never on the wall clock.
4. Every arithmetic operation on `Qty`, `Tick` and notional is checked. Overflow is a defined
   reject, never a wrap.
5. Iteration order of every collection is a function of logged data only.
6. A replica's engine is the live engine with the NIC replaced by the order stream, and with the
   cut core replaced by reading `StepRecord.cut`.

## 12. Product and ownership decisions (v1)

1. **Product:** v1 is fully collateralized spot. A buy reserves `qty × price + max fee` in quote
   when it enters, and a sell reserves `qty` in base. v2 adds isolated-margin linear perpetuals.
   Cross-margin is out of scope.
2. **Balances live in lanes.** An account's balances for a book are lane-local state, in the
   account's lane. The BBO core never writes a balance. It emits fill events on one BBO → lane ring
   per lane, and each lane settles its own side of each fill (`INV-WRITER`). The `fills_applied`
   field of `PacketRecord` makes the order of settlement against new orders replayable.
3. **One book per sequencer box** for a hot book. A **book group** of up to `K` cold books can
   share one box. Each book in the group has its own BBO core, and the group shares the lanes.
   `03-architecture.md` defines `K` and the core map.
4. **Balances across books:** an account allocates part of a balance to each book (escrow). Moving
   an allocation between books is an ordinary transaction that consensus finalizes in
   milliseconds. It is never on the 1 µs path.
5. **A source address is bound to a session.** A packet with a bad MAC from an address that is not
   bound to its session is dropped and counted, and the session stays open. A packet with a bad MAC
   from the bound address closes the session.

## 13. Writing rules for chapters

- Use short, direct sentences. State the decision, then the reason.
- Do not hedge. Mark each number as budget, measured or vendor (see `00-index.md`). Make every
  claim checkable.
- Pseudocode is Rust-like and uses the names in this chapter.
- Draw diagrams in ASCII so that they render in a terminal and in Markdown. Mermaid is allowed in
  addition to ASCII, never instead of it.
- Every chapter ends with these sections:
  - **Interfaces to other chapters:** what it consumes and what it provides.
  - **Local definitions:** constants and types that are new in this chapter.
  - **Requests to 01:** anything that should be promoted to this chapter.
  - **Open questions:** each with an owner chapter and a benchmark or test that settles it.

## 14. Draft 0.2 decisions (binding; override any chapter)

These decisions come from merging the ten chapters. A chapter that disagrees with them has a bug.

### 14.0 The hard requirements are not negotiable

The original requirements hold for every accepted packet:

- 1 µs from first bit in to first bit of the response out, as a maximum
- 1B msgs/s on one book
- 10 ms finality for every accepted order
- a book that moves every 8 h
- CHAIN mode with 5 validators

No chapter may exempt a packet size, a message index or a message type, or swap a hard bound for a percentile. Where a budget does not fit, the design changes and the requirement stays. Exactly three facts of physics or mathematics are stated as facts, not as exemptions:

1. **AWS.** The wire belongs to the Nitro card, so on AWS the 1 µs is measured inside the instance, and 1B/s depends on the instance's packet rate (B16). The full specification, with every number at the same time, is stated against bare metal (`REF`).
2. **The handoff window.** For one WAN one-way latency plus one quorum round (W ≤ t_wan + `FINALITY_MAX_MS` + `EPO_WINDOW_SLACK_MS` = 3 ms, proof in 08 §6.3), the new home cannot fill. The opening auction serves that window (08), and every order in it still gets a 1 µs `Ack` that it joined the auction. This is the only window without a 1 µs fill.
3. **Finality needs a timely network.** No BFT protocol can finalize while messages are delayed past the network's bound; this is FLP and partial synchrony. VYRN therefore never issues fills that it cannot finalize in time: the sequencer halts when finality lags more than `FIN_GATE_BLOCKS` (in both modes). A sequencer that crashes, censors or stalls is replaced by failover. Failover is the one fault case without fills, for at most `FAILOVER_TARGET_MS` = 20 ms. It is a fault, not a normal state, and every order acked before it survives (§14.5), and the orders it delayed are final within `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS`. Under an honest sequencer and a timely network, every order is final within 10 ms, forced packets included (§14.9).

### 14.1 Deadline admission

This is what makes the 1 µs a maximum. A lane computes `age = now_ns − rx_ts` when it dequeues a packet, with TSC↔PHC mapping (06). If `age + predicted_path_ns(packet) > LAT_MAX_NS − DEADLINE_GUARD_NS`, the lane answers the whole packet with `Reject BUSY` (~20 ns of lane work) and does not apply it.

The BBO core applies the same test to forwarded ops, sheds the late ones with `StepKind::Shed`, and their lane answers `BUSY`. Every shed decision is written to the order stream: `PacketRecord.flags.SHED` or a `Shed` step. Replay reads the decision from the log and never recomputes it, so `INV-DET` holds, in the same way that cuts make timing replayable.

- `DEADLINE_GUARD_NS` = 20 (06: the quiet-core probe bounds gaps at ≤ 20 ns; the ≤ 10 ns TSC↔PHC error is added to `age` itself, so the shed threshold is 980 ns).
- A lane BUSY covers the whole packet. A BBO-core `Shed` covers only that op and the ops in its in-packet dependency list, because pass 2 has already applied that packet's independent joins and cancels.
- **Backlog bound:** a line-rate burst outruns a 20 ns shed, so each lane's ingress is policed at the leaf switch (an ACL policer per destination UDP port, that is per lane) to `LANE_POLICE_PPS` = 40M packets/s with a burst of `LANE_POLICE_BURST` = 8. With that bound a BUSY itself always leaves within 1 µs (04 §3.5).
- Under the reference workload at 1B msgs/s, `BUSY` must be ≤ 1e-6 of packets (B3). It is how overload is answered within 1 µs. It is never a normal outcome.

### 14.2 The lane processes a packet in two passes (early dispatch)

- **Pass 1, in index order:** session, bound address, epoch, seq, `tag_seq`, then for each message: parse, risk and reservation, and classification against the snapshot. Each improve, cross, IOC, FOK or post-only-would-cross is pushed to the BBO ring as soon as it is classified. The push carries the **in-packet dependency list**: the earlier ops of the same packet that touch the opposite side within its price range, or its own handles. The lane pre-assigns the slot handles for those ops, so the BBO core can apply STP to them and fill them as if they rest at their own priority, while keeping `INV-WRITER` (the BBO core writes only filled quantity).
- **Pass 2:** apply joins and cancels in index order, and release the lane counter after each op.
- `LANE_PASS1_NS` = 5 per message, plus 45 per packet (MAC and session). `LANE_APPLY_NS` = 9 per message.
- **Budgets at message index 9, the worst case (REF, NIC RX 320 / TX 240):**
  - cross fill: 320 + 45 + 50 + 10 + 100 (hop) + 100 (step) + 60 (frame gate) + 40 (TX core) + 240 = **965 ns**
  - join or cancel ack: 320 + 45 + 50 + 90 + 160 (logged cut via `LaneCut`) + 10 (frame gate) + 20 + 240 = **935 ns**
  - with the 15 ns BBO step of §14.15, the cross fill at index 9 is **880 ns**

  Index 0 is ~90 ns faster.

### 14.3 Two cut cores

Core 1 reads lanes 0–24 and core 6 reads lanes 25–48. Each writes its own half-cut line. A step reads both lines, and `INV-CUT-MONO` holds per half. `CUT_REFRESH_NS` = 100. The order hasher is on core 50 (§10).

### 14.4 Who votes, and the client split

- `vyrn-seq` **never votes.** `N_BASE` and `N_CHAIN` count voting replicas only.
- BASE: F1 holds `vyrn-seq` and a voting replica R1; F2–F4 hold one voting replica each. That is 4 voters with Q = 3, split 2 Rust and 2 Vx.
- CHAIN: the 5 validator boxes vote, 3 Rust and 2 Vx. The sequencing operator votes from its validator box (09).
- Each home keeps a **warm standby `vyrn-seq`** (Rust) in F2. Failover promotes the standby and never a voting replica, so the client split survives a failover.
- 07's "the sequencer votes" is replaced by this rule.

### 14.5 Ordering frames, and gating every response

- Lanes pre-encode their `PacketRecord`s into per-lane order rings during pass 1.
- Core 4 drains every lane up to the step's cut and writes the frames to both replication ports (07's rule; 03's "lanes post their own" is replaced).
- `INV-FRAME-FIRST` now covers every response, including acks: the records of every op in a step's cut, and the record of the step itself, leave on both paths before any response that depends on them. Because pass-1 pre-encoding runs early, the gate is normally already open (10 ns budget for acks).
- An acked order is never lost when the sequencer crashes.

### 14.6 Response retention

- The sequencer keeps `RESP_HOT_RING_BYTES` = 4 GiB per lane (~8 s of responses).
- The recovery service, a role on one replica per home, keeps `RESP_RETAIN_PKTS` per session.
- `RESEND_GONE` is returned only when both have dropped the packet.

### 14.7 Hardware

- REF `vyrn-seq`: 4 × X2541 facing clients, plus 2 × dual-port X2542 for replication: card A on leaf A and card B on leaf B. Port a carries stream-A and port b stream-B, so each port has one CTPIO writer (06/07). TX-A sends on NIC0, TX-B on NIC2, and TX-C on NIC1 and NIC3.
- REF replica: 4 × X2541 and 12 × 61.44 TB NVMe: ~7.9 h on the box at sustained peak and 12 h at ≤ 20% load. A separate archive node per facility keeps 7 days.
- CONSUMER adds an X2522 card for replication path B.
- No GPU, FPGA, ASIC, P4 switch or SmartNIC logic anywhere (`C-NOCHIP`). A future GPU echo benchmark, B-GPU, may reopen this only if it shows RX + TX ≤ `NIC_FLOOR_NS`.

### 14.8 Sessions and epochs

- Sessions survive epoch boundaries (08). Only an account that moves to another lane gets its sessions closed. After its seal, the old home closes no session at all; it answers strays within 1 µs for as long as the box runs (08 §7).
- A bad MAC closes a session only when it comes from the bound address **and** `epoch16` matches the receiver's epoch.

### 14.9 Chain gate and forced inclusion

- `FIN_GATE_BLOCKS` = 8. In both modes, the sequencer never runs more than 8 blocks ahead of finality. If finality lags more than that, the book halts rather than issue fills that cannot be final within 10 ms.
- A forced packet, under an honest sequencer, is positioned at the first block boundary after the block that includes it is notarized. It is final ≤ 10 ms after it is sent, like any order. `FIN_GATE_BLOCKS` = 8 is only the deadline after which validators treat its absence as censorship (evidence plus failover, §14.0 fact 3).
- Orders through the normal path are final ≤ `FINALITY_MAX_MS` = 10 ms.

### 14.10 New codes

- **Reject reasons:** 21 `ACCOUNT_KILLED`, 22 `RESEND_GONE`, 23 `BAD_BOOK`, 24 `BUSY`, 26 `DATA_MISSING` (draft 0.3, §14.19 C).
- **`StepKind` adds:** `Shed`, `Control`, `Seal`, `Uncross`.
- **Response record:** 0x87 `Bust` (CHAIN, 09).
- `Fill.liq` = 2 means an auction fill.
- `Out` causes: 1 IOC rest, 2 STP, 3 auction, 4 expired, 5 post-only, 6 lane moved, 7 disconnect, 8 admin. An unfillable FOK uses `Reject FOK_UNFILLABLE`.
- Response record 0x88 `Attest` (04 §7.5) carries the durability, finality and settlement facts.

### 14.11 Accepted chapter requests

These are promoted as the chapters define them:

- **05:** `INV-ENG-1` (the snapshot is only a routing hint), `INV-ENG-2` (slot fields are written once), Advance records (`PacketRecord.count = 0`), the clamped step-cut rule, and `LaneCut` written by core 4.
- **07:** `INV-REP-1`, `INV-REP-6` (self-fence at 250 µs), and finality = 4 hops.
- **09:** `INV-CHN-KEYSPLIT`, one vote per (epoch, view), and keccak256/EIP-712 only for the parts that face Ethereum L1.
- **10:** `QuoteAmt`, `BaseLots`, `BookSpec`, the fill-event layout, control session 0 with codes 0x20–0x2F and 0xA0–0xAF, and the observer `vyrn-md` box per facility.
- **06:** on AWS, `rx_ts` is the TSC read at RX completion.
- **11:** the `unsafe` allowlist, ZIP-215 Ed25519 verification, the ID prefixes (B, WL, SF, M), and that the Vx parts ship as shared libraries hosted by Rust binaries.

### 14.12 Name

The project is **VYRN** (github.com/bajpainaman/VYRN). The crate and binary prefix is `vyrn-` (`vyrn-seq`, `vyrn-engine`, …), and the C shim prefix is `vyns_`.

### 14.13 Adopted from onebook (github.com/bajpainaman/onebook/docs), decided 2026-11-13

1. **Segment FIFOs.** A lane FIFO is a chain of `Segment16` blocks, not an intrusive linked list
   of slots. One segment holds 16 order slot indices (u32), 16 open quantities (u32), a 16-bit
   active mask, a generation, a successor index and the level's tick/side. It spans three cache
   lines and is aligned to `CACHE_LINE`. A cancel clears one active bit (the tombstone keeps its
   `LaneSeq`). The BBO core sweeps a segment with one AVX-512 compare and mask, with no pointer
   chasing inside a segment. A segment is reclaimed once all 16 bits are clear and no step that
   can read it is in flight (reader epoch). This replaces 05's intrusive FIFO lists.
2. **Immutable queue positions.** An order's FIFO position is fixed at admission: (segment,
   lane-in-segment) assigned in lane pass 1, in priority-key order. It never moves. Only a cancel
   or a fill removes it, by clearing its bit. A partial fill changes only its quantity. Replace
   that loses priority is a cancel plus a new admission.
3. **Separate attestations, never merged into one "confirmed" flag.** The order is: volatile
   execution (the 1 µs `Fill`/`Ack`; its records are already on both replication paths, by
   `INV-FRAME-FIRST`) → durability (held by ≥ F + 1 replicas) → finality (the BFT certificate, ≤ 10 ms) → settlement (CHAIN mode: bridge or ledger). APIs,
   the drop copy and market data label each fact separately.
4. **Shed load before sequencing.** This is deadline admission (§14.1). Onebook's latency contract
   is prior art: "an overload rejection is preferable to a late financial acknowledgement".
5. **Epoch-settled balance domains.** This is our per-book allocation (§12.4), plus an optional
   **router domain**: an account that holds inventory in every book of a group and gives
   immediate cross-book routes. Its inventory risk is a product setting, not a correctness issue.

VYRN stays a standalone system with its own chain mode. It does not integrate with ETO.

### 14.14 Maker fills also within 1 µs

A maker fill is caused by the taker's packet, so it gets the same bound: the maker's `Fill` leaves
within `LAT_MAX_NS` of the first bit of the taker's packet. The TX core sends maker fills directly,
in the same step as the taker fill, so there is no extra hop through the maker's lane. It numbers
them from a per-session `resp_seq` range that the maker's lane reserves in advance (16 numbers,
refilled when half used). That keeps one writer per number (`INV-WRITER`). The maker's lane still
settles the balances from the fill event, off the latency path. This replaces
`PROTO_MAKER_FILL_NS` = 1.2 µs.

### 14.15 Closing the queueing gap: dedicated and pooled lanes (decided 2026-11-13)

**The problem.** With one core per lane, a packet that arrives while its lane is busy waits. At
1B msgs/s the lane load is ~0.41 and a packet's service is ~140 ns. The slack left after the
fixed path is 35–90 ns, which is smaller than one service time, so ~23% of packets would be shed
(02 §13). The BBO core at load 0.58 with a 40 ns step would shed ~8% of crosses. A hard 1 µs
maximum with ≤ 1e-6 BUSY does not close for shared lanes on any COTS CPU. Only a pipelined front
end that takes one packet per clock does that, which `C-NOCHIP` forbids. The decision below keeps
both hard requirements: every accepted packet is answered within 1 µs, and 1B msgs/s per book are
accepted.

1. **Two lane classes.**
   - **Dedicated lane:** one core serves the accounts of one firm only. That firm's packets
     arrive in its own order. A client that leaves at least `predicted_path_ns` of its previous
     packet between packets on its lane (`LANE_PACE`, computed by the SDK from the published
     table) never queues, so it never gets BUSY: **BUSY = 0 by construction**. Only the firm's
     own bursts can make it wait, and no other client can.
   - **Pooled lane:** the cores of one CCD (7 on REF) form a pool for small clients. Any pool
     core can process any of the pool's packets. The account's state moves under a per-account
     token, acquired with CAS inside the CCD's L3 (~20 ns). Session order is kept by a check of
     the next expected `pkt_seq`. A core whose own RX queue is empty steals from a sibling's
     queue under a per-queue consumer lock. Each pool core is still a lane in the cut vector,
     and it writes its own `Segment16` blocks. A cancel of an order in a sibling's segment clears
     the bit with an atomic `fetch_and` inside the CCD. Each order bit has one logical owner, so
     `INV-WRITER` holds per field, and determinism holds because each core's `LaneSeq` logs the
     order in which it took tokens.
   - **Pooled BUSY (M/M/c bound, c = 7):** ≈ 1e-3 of packets when the book runs at a full
     1B msgs/s, and ≤ 1e-6 when the book runs at ≤ 20% load. B3 publishes the measured curve.
2. **BBO step ≤ 15 ns** (`BBO_CROSS_NS` = 15), using the `Segment16` sweep and prefetched heads.
   This brings the BBO load to ~0.21 at 10M crosses/s plus 20M improves or depletions/s. The
   shed tail is P(W > 90 ns) ≈ 4e-8.
3. **The TX and order-stream cores are split in two:** TX-A on core 3 and TX-B on core 5,
   stream-A on core 4 and stream-B on core 7, each serving one half of the lanes. Stream-A also writes every `StepRecord`; stream-B carries only `PacketRecord`s and `AcctTake`s of lanes 25–48, and a step's `released_step` waits for both halves' records up to the step's cut. §14.17 adds TX-C on core 0 and moves the OS and control to core 51. Earlier text said control moves
   to core 0 (with the OS) and the hasher to core 50. The pool is CCD 7 (cores 56–62). Each of these single servers then runs at
   load ≤ 0.25 with a step ≤ 20 ns.
4. **Lane assignment (10 §1.3):**
   - The top firms by message volume get dedicated lanes, about 42 on REF.
   - One CCD (7 cores) is the pool for all other clients.
   - The lane map publishes each account's class.
5. **Requirements (02):** REQ-LAT-1 is unchanged: a hard 1 µs maximum for every accepted
   packet. REQ-LAT-5 becomes two bounds:
   - dedicated, paced lanes: BUSY = 0
   - pooled lanes: BUSY ≤ 1e-3 at full book load, and ≤ 1e-6 at ≤ 20% book load

   Both are measured by B3.
6. **Per-step fill cap.** One step writes at most `STEP_FILL_CAP` = 64 fill records. A longer
   sweep continues in further steps, and each one meets its own deadline (03 ARC-D14). So a
   maker's 16-number relative `resp_seq` credit (04 §7.1) is never exceeded. That removes 04's
   ">256 records" exception.

### 14.16 Other cross-chapter rulings (draft 0.2)

- **INV-REP-6 (self-fence):** the sequencer fences itself unless it holds fresh acks from
  n − Q + 1 + f voters (3 in BASE). Acks from the co-located R1 alone never keep it alive (07).
- **Data home:** a session's data home is never in the sequencer's facility (07). 09's "primary
  data box in F1" is replaced by "primary data box in the operator's F2–F5 facility".
- **Observer box (10):** 3 × dual-port ConnectX-6 Dx plus 3 × X2541. This replaces 06's
  6 × X2541, because full MBO out (~208 Gbps) plus the taps does not fit in 600 Gbps of X2541
  ports.
- **Replica retention:** at least 6 h on the box at sustained peak, and 12 h at ≤ 20% average
  load. The archive node streams continuously and keeps 7 days. Retention never blocks
  replication.
- **The frame gate is defined as** "written to both replication TX queues and, by B-REP-2W, on the
  wire no later than the dependent response". The wording "leave on both paths" is replaced.
- **A packet older than its BUSY deadline at dequeue** (past the 500 ns age at which a `BUSY` can
  still leave in time, 04 §3.5) cannot occur while the E4 policer (04 §3.4) holds the lane's
  backlog. If it occurs, E4 has failed: the lane drops the packet without a response and counts
  it as ingress loss, not as `BUSY` (§14.19 A). The run fails B3 and B21. *(Amended in draft 0.3;
  draft 0.2 counted it with `BUSY`, which hid a dropped packet inside the 1 µs contract.)*
- **TX ≤ 240 ns** is a qualification maximum of its own, next to RX + TX ≤ 560 (06).
- **A maker fill is ≤ `LAT_MAX_NS` from the taker packet's first bit (§14.14).** 03's
  `ARC_MAKER_FILL_MAX_NS` = 1250 is replaced.

### 14.17 Rulings on 05's draft-0.2 findings (final for draft 0.2)

01 wins wherever a chapter disagrees with these rulings. The chapters follow them in draft 0.3.

1. **Ack budget.** The lane's poll of `LaneCut` costs ~20 ns, so the worst-case cut term is
   170 ns. An ack at message index 9 is 955 ns typical and **965 ns worst**, against the 980 ns
   shed threshold (`DEADLINE_GUARD_NS` = 20). The slack shrinks by ~9 ns per later index. The SDK
   therefore puts a packet's cancels first: a cancel at index 0 has ~100 ns of slack. Message
   order is the client's choice, so this changes no semantics.
2. **Dedicated lanes: what "zero BUSY" means.** A paced client on a dedicated lane never waits in
   the **lane** stage. The BBO core, TX cores and order-stream cores are shared by every client,
   so a BBO-bound op of a dedicated client can still wait there. The REQ-LAT-5 bound for dedicated
   lanes is: lane-stage BUSY = 0; total BUSY ≤ 1e-5 at full book load (crosses and improves
   only); ≤ 1e-8 at ≤ 20% load. Pooled lanes stay at ≈ 1e-3 at full load and ≤ 1e-6 at ≤ 20% load.
   B3 measures every class and publishes the curves. This replaces the "BUSY = 0 by construction"
   wording of §14.15.
3. **Three TX cores.** A, B and C on cores 3, 5 and 0, each at load ≈ 0.22 (05 measured 0.33 with
   two). The OS and control move to core 51. CCD 0 now holds only latency-critical cores: the BBO
   core, cuts A/B, TX A/B/C and streams A/B.
4. **Pooled-lane determinism.** Each token take is logged as `AcctTake { account, ver, lane }`
   (05 R15), so replay knows which pool core did which account's work in which order.
5. **Maker fills in long sweeps.** The maker fills of the first steps of a sweep, about 40 makers
   at index 9 and more at lower indices, leave within `LAT_MAX_NS` of the taker packet's first
   bit. Maker fills from later continuation steps leave within `LAT_MAX_NS` of the start of their
   own step. The taker's response (its first fill record) is always within 1 µs. A maker fill is a
   notification to another client, not the response to the maker's own packet, so this exempts no
   response. It refines §14.14.

### 14.18 Open items carried into draft 0.3

Each item has an owner chapter and a benchmark that settles it.

| # | Item | Owner | Settles it |
|---|---|---|---|
| O1 | Each stream core runs at ~0.41 load, above §14.15's ≤ 0.25. Fix candidates: a third stream core, or moving record encoding into lane pass 1 | 07, 05 | B-REP-2, B3 |
| O2 | The cross fill at index 9 is 947 ns with 07's 142 ns worst-case frame gate, not 880 ns. That leaves 33 ns below the 980 ns threshold | 07, 05 | B3 |
| O3 | Linux may not allow the boot CPU (core 0, now TX-C) in `nohz_full`. The fallback is to remap TX-C and keep the BSP for housekeeping | 06 | PLT jitter probe |
| O4 | At sustained peak the archive feed (≤ 25 Gbps) is below ingest (~180 Gbps), so a peak longer than ~7.9 h leaves an archive gap | 06, 07 | B-REP storage test |
| O5 | 09 counts closed blocks for the finality gate (limit 9.00 ms, margin 0.89 ms), the same way 07 does. Both use `FIN_GATE_BLOCKS` = 8 closed blocks | 07, 09 | B-CHN-3 |
| O6 | The 5 ns/msg pass-1 budget and the 15 ns BBO step are budgets, not measurements | 05 | B2, B6 |
| O7 | PTM cross-timestamping on the X2541 / SP5 combination is unconfirmed. If it is missing, the X2541 fails qualification | 06 | PLT-B-PTM |

### 14.19 Draft 0.3 rulings (decided 2026-11-16)

These close two contradictions in draft 0.2. They override any chapter, including §14.0's
wording where they refine it.

**A. The 1 µs contract has an ingress scope, and drops are not responses.**

Draft 0.2 said both that a session's next valid packet has "no third outcome" (04 §0) and that a
packet past its deadline at dequeue is dropped without a response (§14.16). Both cannot hold.

1. **REQ-LAT-1 covers every received packet.** A *received packet* is one that passed the edge
   ACLs and policers E1–E4 (04 §3.4) and reached the live sequencer's NIC. For each one, VYRN
   sends the first record of every message, or an explicit reject (`BUSY` included), within
   `LAT_MAX_NS`, first bit in to first bit out at `M-WIRE`. There is no third outcome for a
   received packet. The handoff window of §14.0 item 2 is unchanged.
2. **Ingress loss is a separate fact with its own bound.** A packet that a policer drops, that the
   network loses, or that reaches a crashed box was never received. It gets no response, and the
   client's timer resends it by `pkt_seq` (04). 02 bounds it as REQ-LAT-14, with counters that are
   reported next to `BUSY` and never merged into it.
3. **A dequeue-age drop is an E4 failure.** 04 §3.5 proves that with E4 working, every pending
   packet can still be shed in time. A drop at dequeue therefore means the policer failed. It is
   counted as ingress loss and fails the run (§14.16).
4. **No benchmark may count a drop as a met deadline.** B3, B9, B21 and B32 reconcile
   `sent = received + policed + wire loss` per port, and `received = answered`.

**B. A fill has exactly two ways to be undone, and both end at finality.**

Draft 0.2's DESIGN §0 said a fill "does not revert" except after a double drop, while 07 §9.6
listed five revert cases, 09 busts fills in CHAIN, and 04 said a `Bust` follows a failed
settlement. The rule is:

1. **Revert (log exclusion).** The final log does not contain the execution. This is possible only
   before the block that holds it is final, and only in the cases (a)–(e) of 07 §9.6: double path
   loss plus sequencer death, dual-path isolation of a live sequencer, in-box power loss while
   `lead < 0`, an unavailable or excluded packet, and a Byzantine sequencer's truncated tail. 07
   §9.6 is the exhaustive list. Clients learn it from `DC_REVERT` and `MD_TRADE_BUST`.
2. **Bust (CHAIN only, compensating reversal).** The execution stays in the final log, and
   matching replays exactly as it ran. Lane ops at the next boundary reverse its balance effects
   and the session bond pays (09 §5.9). A fill is busted only when one side's packet failed
   `tag_com`. That verdict is in the exclusion list of the block that holds the bad packet, which
   is final no later than the fill's own block.
3. **`FINAL` fixes an execution's fate.** After the block that holds an execution is final, nothing
   reverts it, and no new bust verdict can apply to it. A bust whose verdict was already final
   still executes later as lane ops; its `DC_REVERT` is sent before the `DC_FINAL` that covers the
   fill's step (10 §8.2). Settlement never undoes a final fill. A failure to settle is an
   operational incident handled by 09's custody rules, not a `Bust`.
4. **A revert voids the trade.** A reverted execution never happened: no balance moved, no fee is
   charged, and both parties' orders are as if the packet carried no such fill (the canonical
   replay decides what rests). Nobody pays compensation in cases (a)–(c), where no party
   misbehaved. In case (d) the withholding or equivocating session's losses stay its own, and in
   case (e) the sequencer operator is slashed in CHAIN (09). A client that hedged on a fill that
   later reverts carries that risk; 12 §4 says what a client may rely on before `FINAL`.
5. **Who pays** for a bust: the busted session's bond, then the insurance fund (09 §5.9).
6. **One fault can revert, in one case.** Every revert needs two independent faults, a Byzantine
   sequencer or a misbehaving client, except case (c): an in-box power loss while `lead < 0`, a
   window of ≤ 100 ns per response (12 §2, B-REP-2W).

**C. Withheld data copies are attributed and contained (13 §5).** DAV-1 to DAV-4 are binding:

1. **DAV-1.** Each voter counts, per session, records it resolved only from the sequencer
   (07 §5.5 source 3). Over `DAV_MISS_MAX` = 16 in any `DAV_WINDOW_MS` = 10 ms window, it signs
   `DataMissing{session, window, count}`. Q such reports close the session through the control op
   of 07 §5.6, with reject reason 26 `DATA_MISSING` (25 is reserved for `RESEND_RECOVERY`, 03 Request 10).
2. **DAV-2.** The sequencer serves source-3 repairs for one session at ≤ `DAV_SESSION_REPAIR_PPS`
   = 2,000 packets/s.
3. **DAV-3.** The leader may mark a DAV-1-reported session's unrepaired packets unavailable while
   the sequencer lives (extends 07 §9.4), so one client cannot trip the finality gate. Their
   executions revert as case (d).
4. **DAV-4.** The service contract publishes `DAV_TOLERANCE` (1.3 × 10⁻³ of a block's packets,
   all misbehaving sessions together) and states that no session can delay another session's
   finality.

12 (`12-commitment.md`) states the whole lifecycle. 13 and 14 hold the data-availability model and
the workload envelope.

### 14.20 Post-quantum signatures (decided 2026-11-18)

**Why.** Every signature in draft 0.3 is classical: Ed25519 for votes, `seq_sig`, certificates,
`NodeCert`s, operator identity keys and release keys; secp256k1 for EVM wallets and the L1 bridge
(09). A large quantum computer recovers the private key of either from its public key (Shor), so
an attacker who has one forges votes, headers and release manifests at will, live or after the
fact. [Certain] The hashes (BLAKE3, Keccak-256, SHA-256) keep about 128-bit security against
Grover-style search and need no change. [Likely] The owner approved the change with speed as the
main concern, so this section keeps every signature off the per-message path and keeps the
finality budget of 07 §6.6.

**A. The scheme.** `SigScheme` (§3) names the scheme of a key and of every signature it makes.

| Code | Scheme | Public key | Signature | Used for |
|---|---|---|---|---|
| 0 | Ed25519 (today) | 32 B | 64 B | everything, until the switch |
| 1 | hybrid Ed25519 + ML-DSA-44 (FIPS 204, NIST category 2) | 32 + 1,312 = 1,344 B | 64 + 2,420 = 2,484 B | live keys after the switch: `VK`, `SK`, `NK`, vote and handoff signatures, `seq_sig`, every certificate |
| 2 | hybrid Ed25519 + ML-DSA-65 (category 3) | 32 + 1,952 = 1,984 B | 64 + 3,309 = 3,373 B | cold, long-lived keys: operator identity keys `OIK` (09 §2.2), release keys (11 §9.5) |

- **Validity.** A hybrid signature is valid only if both parts verify. Each part signs
  `scheme ‖ msg`, where `msg` is the byte string the scheme-0 rule signs today (the `derive_key`
  digest with its context, 09 §17.3). The leading scheme byte stops a stripped Ed25519 part from
  passing as a scheme-0 signature. A key is never reused across schemes: a hybrid key's Ed25519
  half is fresh.
- **Parts and rules.** The Ed25519 part follows the ZIP-215 rules (11 §2.5). The ML-DSA part is
  pure ML-DSA (not HashML-DSA), hedged signing with 32 fresh random bytes per attempt, verified
  under FIPS 204 Algorithm 3 with an empty context string (11 §2.5a). Hedged signing means two
  signatures of one message differ. Nothing that is hashed into state or chained depends on
  signature bytes: `header_hash` covers header bytes 0..126 (07 §2.2), and equivocation is two
  different signed bytes 0..126 at one height, never two signatures of the same bytes (09 §8.2).
- **Why ML-DSA-44 for live keys.** It is the fastest FIPS 204 set and the smallest, and the
  Ed25519 half keeps classical security if a lattice attack appears. Live keys rotate by
  `NodeCert` (09 §2.3). ML-DSA-65 costs 1.5–1.7× in time and 889 B more per signature (table B)
  on every block and vote, which buys nothing the cold keys need speed for. [Likely] The owner
  decided ML-DSA-44 for live keys (PQ-1, 2026-11-18).
- **Not ML-DSA-87, not SLH-DSA, not Falcon.** ML-DSA-87 is larger and slower again. SLH-DSA
  signatures are 7.8 KB at the smallest and signing takes milliseconds. Falcon (FN-DSA) needs
  floating-point sampling, which §11 forbids in anything every replica must reproduce, and it has
  no final FIPS yet. [Likely]

**B. Measured cost.** Measured 2026-11-18 on an Amp orb: Intel Xeon @ 2.6 GHz, x86_64 with AVX2
and AVX-512, 2 vCPUs, Linux, rustc 1.100.0, `--release` with `lto = "thin"`, `codegen-units = 1`
and this repository's `target-cpu=x86-64-v3`. The message is 126 bytes (a header's signed part).
Each mean is the median of 7 rounds of 2,000 calls. The sign distribution is 20,000 single calls
with distinct messages. A scratch benchmark produced the numbers; it is not in the repository.
These are DEV figures, not `REF` results (01 §10): `REF`'s EPYC 9575F clocks higher, so the
budgets that follow use these numbers unscaled. [Certain for the numbers on this machine;
Likely that `REF` is not slower]

| Crate, version | Set | Keygen | Sign mean | Sign p50 / p99 / p99.9 / max (µs) | Verify |
|---|---|---|---|---|---|
| `ed25519-dalek` 3.0.0 (in the workspace today) | Ed25519 | — | 16.7 | 15.9 / 31.3 / 48.4 / 598 (one outlier) | 34.5 (strict 39.5; batch of 4: 22.9 per signature) |
| `libcrux-ml-dsa` 0.0.11, `simd256` | ML-DSA-44 | 28 | 97 | 78 / 331 / 467 / 696 | 29.8 |
| `libcrux-ml-dsa` 0.0.11, `simd256` | ML-DSA-65 | 49 | 149 | 130 / 547 / 798 / 1,273 | 51.4 |
| `aws-lc-rs` 1.19.0 (AWS-LC, C and assembly) | ML-DSA-44 | 31 | 107 | 90 / 396 / 570 / 997 | 29.3–31.1 |
| `aws-lc-rs` 1.19.0 | ML-DSA-65 | 56 | 174 | 132 / 557 / 802 / 1,358 | 48.5–51.6 |
| `ml-dsa` 0.1.2 (RustCrypto, pure Rust) | ML-DSA-44 | 151 | 486 | 395 / 2,171 / 3,300 / 5,621 | 61.0–68.4 |
| `ml-dsa` 0.1.2 | ML-DSA-65 | 242 | 973 | 687 / 4,031 / 6,408 / 17,069 | 84.0–87.7 |

ML-DSA signing is a rejection loop: each attempt repeats a step until the candidate passes, 4.25
repetitions on average for ML-DSA-44 (FIPS 204), with a geometric tail. That tail, not the mean,
is the cost that matters at 1 kHz. The model `t = 27 µs + 17 µs × repetitions`, with repetitions
geometric at p = 1/4.25, matches the measured libcrux ML-DSA-44 percentiles within 2 µs (p50 78,
p90 181, p99 331, p99.9 467). [Certain for the fit]

**Hedging.** `PQ_HEDGE` attempts run at once on separate cores, each with its own randomness, and
the first to finish wins. The minimum of k attempts has a tail k times steeper. Measured as the
minimum of consecutive single calls (a simulation of parallel cores, not a run on parallel
cores; B-PQ-1 measures the real thing):

| libcrux ML-DSA-44 | p50 | p99 | p99.9 | max over the run | ≤ 10⁻⁹ bound (model) = `PQ_SIGN_MAX_US` |
|---|---|---|---|---|---|
| 1 attempt | 78 | 331 | 467 | 696 | 1,353 |
| 2 attempts | 59 | 184 | 249 | 401 | 690 → **750** |
| 4 attempts | 45 | 111 | 135 | 199 | 367 → **400** |
| 8 attempts | — | — | — | — | 197 → **250** |

**C. Crate.** `libcrux-ml-dsa` (Cryspen), on the 11 §2.2 allowlist at tier S, with RustCrypto
`ml-dsa` at tier T as the differential reference.

| | `libcrux-ml-dsa` 0.0.11 | `aws-lc-rs` 1.19.0 | RustCrypto `ml-dsa` 0.1.2 |
|---|---|---|---|
| Speed (ML-DSA-44 sign mean / verify) | 97 / 30 µs, fastest | 107 / 30 µs | 486 / 61 µs: 5× slower to sign; at 4 attempts its measured p99.9 is 841 µs and the 10⁻⁹ bound ≈ 1.8 ms, past a metro hop |
| Language, `unsafe` | Rust; `#![deny(unsafe_code)]` at the root, `unsafe` only in the AVX2 instantiation (32 uses) and in `libcrux-intrinsics` (101 in the AVX2 module); portable path for aarch64 | C and assembly through FFI, plus a 68 MB vendored C tree built by `aws-lc-sys` | pure Rust, no `unsafe` in the crate |
| Assurance | README: field arithmetic, NTT and serialization formally verified with hax and F\*, portable and AVX2. Independent audit: unknown, not checked | AWS-LC has a FIPS 140-3 module (`aws-lc-fips-sys`); whether its validated version covers ML-DSA: unknown, not checked | README: "never been independently audited" |
| Dependencies (normal + build) | 17 crates, all Cryspen plus `rand` | 21, plus cmake/clang for the C build | 36 |
| Policy fit (11 §2.2) | fits | a second crypto stack in C, which the ban on `openssl` and `ring` ("one crypto stack, not two") rules out | fits; too slow for the live path |

[Certain for the table's facts, from the crates' sources and READMEs at these versions. Web
search was unavailable when this was written, so audit and validation status beyond the READMEs
is unknown, not assumed.] The owner decided libcrux with VYRN's own cargo-vet audit (PQ-2,
2026-11-18): no independent audit is required before `E_pq`, but the switch waits until the audit
and the differential tests of 11 §2.5a pass.

**D. Where the cost goes, and the hot path.**

- **The hot path is unchanged.** No lane, cut, BBO, TX or hasher core runs any new instruction;
  packets stay authenticated by SipHash tags (09 §5.1: a signature per packet would need ~2,900
  cores). On core 4 the only change is to push the 126 signed bytes onto an SPSC ring to the PQ
  cores and later post one DMA descriptor for the HEADER_PQ frame (07 §3.3): about 25 ns per 1 ms
  block (budget), 0.0025% of the core. The frame gate does not move, because HEADER_PQ goes by
  DMA, not CTPIO (07 §4.4). [Likely: budget, not measured; B-REP-13 and B-REP-4 re-run with
  scheme 1 check it]
- **The per-step budgets of §5 are unchanged:** `LAT_MAX_NS`, `LANE_NS_PER_MSG`, `BBO_CROSS_NS`,
  `BBO_IMPROVE_NS`, `CUT_REFRESH_NS` and `BLOCK_NS` keep their values. [Certain: nothing in them
  signs or verifies]
- **Sizes.** The `BlockHeader` grows from 190 B to 2,610 B (126 + 2,484). A `REP_FinalityCert`
  grows from 301 B to 7,561 B at Q = 3 (BASE) and from 366 B to 10,046 B at Q = 4 (CHAIN); with all
  5 CHAIN signatures it is 12,531 B. A `HandoffCert` grows from 315 B to 8,887 B (BASE) and from
  380 B to 11,372 B (CHAIN), because `next_seq_key` grows to 1,344 B (08 §5.1). Bandwidth per
  replication path rises by about 2.5 MB/s of HEADER_PQ frames (1,000/s × ~2.54 KB with framing), 0.08% of 3,310 MB/s (07 §3.13).
- **Per-block budgets.** The ML-DSA part of `seq_sig` travels in its own frame and is checked in
  parallel with the data lag, so it adds nothing to the maximum (07 §6.6). Votes are signed
  speculatively, in parallel with the hops that precede them (07 §6.5a). The leader fixes its
  proposal range before its `verify` and announces it in an Ed25519-signed `RangeFix` (07 §6.3,
  PQ-8), so voter and leader sign the one notarize the view can carry, and in BASE no signature is
  made after the proposal arrives in the fault-free case. `RangeFix` is a hint: no voter rejects a
  proposal for differing from it, so a forged one costs a late signature, never finality. Vote checking costs 0.10 → 0.15 ms (max,
  budget). BASE finality: typical 2.59 → 2.69 ms, max with no fault 5.65 → 5.70 ms, max with one fault
  8.65 → 8.70 ms (reserve 1.30 ms). In CHAIN the proposal also carries `excl_root`, known only
  after the leader's `verify`, so the leader signs its proposal then and hop 2 starts up to 0.75 ms
  later (07 §6.5a): CHAIN's worst case moves from 8.11 to 8.91 ms from block start
  (09 §4.8). [Likely: budgets built from the measured figures; the speculative signing depends on
  open question PQ-3]
- **The finality gate** keeps `FIN_GATE_BLOCKS` = 8: block h is final ≤ 7.70 ms after it closes
  (BASE spare 0.30 ms; CHAIN 0.09 ms, accepted by PQ-9; 07 §6.8, 09 §4.6). [Likely]
- **The cost of a fixed range.** A header that reaches the leader after it sent its `RangeFix`
  waits for the next view instead of joining the current proposal. Before PQ-8 the cutoff was the
  leader's `verify` completion, so the window in which that happens grows by at most the leader's
  `verify` time (≤ 0.81 ms at the maximum); views and blocks both run at ~1 kHz, so normally the
  leader fixes the range on the arrival of the header it proposes. The 07 §6.6 maxima assume, as
  before, that a header is in the first proposal after it reaches the leader, so they do not yet
  include the extra view; open question PQ-10 holds it until B-PQ-2 measures it. [Likely]
- **If speculative signing is not possible**, the leader's notarize and each voter's notarize
  are signed after `verify`, at ≤ 0.75 ms each, and the one-fault maximum becomes ~10.2 ms, above
  `FINALITY_MAX_MS` = 10. Scheme 1 must then not activate until votes run with `PQ_HEDGE` ≥ 4 on
  voters too. [Likely]

**E. The switch.** Rules SG1–SG7 follow 04 §12's VR4: the set of accepted schemes changes only at
an epoch boundary.

| ID | Rule |
|---|---|
| SG1 | `EpoConfig(e).sig_scheme` (08 §2.3) fixes the scheme of every live signature made for epoch e: votes, `seq_sig`, `HandoffSig`, root and commit votes. A verifier takes the scheme from the epoch the message names, never from the message. |
| SG2 | A scheme-0 signature is accepted only on a message of an epoch e < `E_pq`, the first epoch with `sig_scheme` ≥ 1. Old signatures stay valid as history; a new one under the old scheme is rejected, so a forged Ed25519 vote for a current epoch is worthless. |
| SG3 | `sig_scheme` never decreases. A broken ML-DSA is covered by the Ed25519 half, so no rollback is needed; a downgrade would hand a quantum attacker every later epoch. |
| SG4 | Hybrid keys are included at least `CHN_KEY_LEAD_EPOCHS` (4) before `E_pq` and become active at `E_pq` (CHAIN: `NodeCert` with `scheme` = 1 and `valid_from = E_pq`, 09 §2.3; BASE: `REP_Membership` with `epoch_from = E_pq`, 07 §13). A key of one scheme is never in force in an epoch of another. The roster of `EpoConfig(E_pq)` then holds only hybrid keys, and `HandoffCert(E_pq − 1)`, the last certificate signed with scheme 0, certifies them. |
| SG5 | CHAIN activates `E_pq` by an `Upgrade` with the 72 h timelock and both clients ready (09 §14.2); BASE by an admin record. Both client kinds verify both schemes before any switch is scheduled (U5, 08 §9.4). |
| SG6 | `pq_anchor` = the hash of `HandoffRecord(E_pq − 1)` goes into every release manifest from the switch on, signed by the hybrid release keys (11 §9.5). A light client or a node syncing from genesis accepts only a history through that record. A quantum attacker who forges an older Ed25519 history cannot also forge the anchor. |
| SG7 | From `E_pq`, evidence that relies on any scheme-0 signature (an offending signature or a certificate its check uses, 09 §8.1 item 2a) slashes or jails only if it, or an `EvidenceCommit` of its hash, was final on chain before `E_pq` began. An authentic hybrid signature elsewhere in the item does not exempt it. A quantum attacker can forge old classical signatures, so new classical evidence must not move bonds or jails. |

**F. What cannot be made post-quantum here, and how VYRN handles it.** 09 §6.8 holds the detail.

- **The L1 bridge.** The contract checks secp256k1 through `ecrecover`, the only signature check
  Ethereum prices low enough (09 §6.1), and the bridge and guardian keys reveal their public keys
  on L1 whenever they sign. A quantum attacker who recovers 5 bridge keys can override a veto with
  5-of-5 at once, so every defense of 09 §6.4–6.6 falls and the whole balance of the contract is
  exposed. VYRN cannot fix this inside an immutable contract. It states the exposure and adds a
  migration hook: a second bridge with a pluggable verifier, deposits moved by users, and a
  `PqAlarm` under which tooling stops new deposits to the old bridge and posts go only to recorded
  exit addresses; the contract itself is not paused (09 §6.8). [Certain for the dependency on
  `ecrecover`; Guessing on when Ethereum offers a post-quantum precompile]
- **EVM wallet sessions.** An account whose `OwnerKey` is secp256k1 is as safe as that key.
  Hook: a hybrid `OwnerKey` variant and a `SetOwnerKey` item; after a governance cutoff epoch,
  classical owner keys are frozen to their exit address for good, even after a later key change (09 §6.8).
- **Key agreement.** X25519 for `K_seq`, `K_out`, `K_com` transport and the p2p handshake is also
  quantum-breakable, and an attacker who recovers a validator's static `XK` derives every
  session's MAC keys. This section covers signatures only. Open question PQ-6 asks for a hybrid
  X25519 + ML-KEM-768 change. [Certain that X25519 is not post-quantum]

**Decided by the owner (2026-11-18)**

| # | Question | Ruling |
|---|---|---|
| PQ-1 | Is ML-DSA-44 (category 2) enough for live keys? | Yes: live keys use ML-DSA-44; cold keys stay ML-DSA-65 (A). |
| PQ-2 | Accept `libcrux-ml-dsa` at 0.0.11 with our own cargo-vet audit, or require an independent audit first? | `libcrux-ml-dsa` with VYRN's own audit; `E_pq` waits for that audit and the differential tests of 11 §2.5a. |
| PQ-8 | Remove the voter's notarize misprediction with a proposal range fixed before the proposal arrives? | Yes: the leader's `RangeFix` (07 §6.3, §6.5a). BASE maxima 5.70 / 8.70 ms; `FIN_GATE_BLOCKS` stays 8. In CHAIN the leader still signs after `verify` (PQ-9). `RangeFix` is a hint: voters never reject a proposal for differing from it. |
| — | Codex review of #51: operator identity keys need an ML-DSA-65 transaction scheme | Adopted: `TxEnvelope.scheme` 3 (09 §4.4). |
| — | Codex review of #51: forged classical evidence after the switch | Adopted: SG7 (09 §8.1 item 2a). |
| PQ-9 | CHAIN's one-fault case under scheme 1 is 8.91 ms from block start, 0.09 ms inside the 9.00 ms gate (07 §6.5a, 09 §4.8). Accept that margin, or raise CHAIN's gate, add PQ cores or lag `excl_root`? | Accept the 0.09 ms margin: `FIN_GATE_BLOCKS` stays 8 in CHAIN. B-CHN-3 and B-PQ-2 on CHAIN re-check it; PQ-10 and PQ-11 can still move the number. |

**Open questions for the owner**

| # | Question | Default if not decided | Settled by |
|---|---|---|---|
| PQ-3 | Can `commonware-consensus::simplex` take a custom hybrid scheme and speculative signing (07 §6.5a)? Its schemes are Ed25519, BLS12-381 and secp256r1. | a hybrid `Scheme` implemented in `vyrn-crypto`; a patch upstream if the trait does not allow speculative signing | 07: a `vyrn-sim` run of B-PQ-2 |
| PQ-4 | When is `E_pq`? It needs a date or a trigger (a published estimate of a cryptographically relevant quantum computer), and an earlier switch costs only the budgets above. | at the first epoch after B-PQ-1 to B-PQ-3 pass on `REF` | owner |
| PQ-5 | The L1 bridge: when does governance deploy the post-quantum bridge and raise `PqAlarm`, and is a 10% daily cap on the old bridge acceptable until then? | at the first Ethereum post-quantum verifier VYRN can afford (09 §6.8) | owner, 09 |
| PQ-6 | Make key agreement hybrid (X25519 + ML-KEM-768) for session keys and the p2p handshake? | not in this change | owner, 04, 09 |
| PQ-7 | Release keys on hardware tokens (11 §9.5): which token holds an ML-DSA-65 key? | an HSM with ML-DSA support for the ML-DSA half, the current tokens for the Ed25519 half | owner, 11 |
| PQ-10 | A header that reaches the leader between its `RangeFix` and the end of its `verify` waits a whole extra view (07 §6.3), and the 07 §6.6 maxima do not include that view. How large is the extra view at the maximum, and does it break the 5.70 / 8.70 ms (BASE) or 8.91 ms (CHAIN) budgets? | budget it once B-PQ-2 measures it; if it breaks a budget, let the leader extend its range at `verify` time with one late signature | 07: B-PQ-2 |
| PQ-11 | In CHAIN, a header late in a view plus the data lag, `verify` and the post-verify leader signature (≤ 0.75 ms) can push an honest proposal past `t_l` = 2 ms, so an honest view can nullify (07 §6.5a). Lengthen CHAIN's `t_l` under scheme 1 (and recompute the one-fault budget), add PQ cores for the CHAIN leader, or lag `excl_root`? | unchanged `t_l`; B-PQ-2 on CHAIN counts honest-leader nullifies | 07, 09: B-PQ-2 |
