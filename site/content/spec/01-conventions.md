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

## 4. Cryptography

| Purpose | Algorithm |
|---|---|
| Packet MAC | SipHash-2-4, 128-bit key, 64-bit tag. The first failed MAC on a session closes the session. |
| Hash | BLAKE3-256 everywhere (blocks, data, log chain, KDF via `derive_key`). |
| Validator votes, sequencer block signatures, certificates | Ed25519. A certificate is a list of (validator index, signature). |
| Session open (wallet signature) | Ed25519 or secp256k1 (EVM wallets). Chain mode only. |
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
| 0x82 | `Fill` | type | index (0xFF = maker fill) | liq (0 maker, 1 taker) | handle | tick | qty |
| 0x83 | `Reject` | type | index | reason u16 | detail u32 | 0 | client_tag |
| 0x84 | `CancelAck` | type | index | 0 | handle | canceled qty | client_tag |
| 0x85 | `Out` | type | index | cause u16 (IOC rest, FOK, STP, auction) | handle | qty out | client_tag |
| 0x86 | `EpochNotice` | type | 0 | 0 | next epoch | next home code | seconds to boundary |

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
                cut: [LaneSeq; N_LANES] }      // kind = Cross | Improve | Depletion | Rescan | Idle
BlockHeader   { height: Height, epoch: Epoch, book: BookId, first_step: StepId,
                last_step: StepId, prev: Hash, order_root: Hash, data_root: Hash,
                seq_sig: Ed25519Sig }
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
| 52–55 | 6 | spare cores for planned, cooperative lane evacuation only; a lane silent for > 1 ms fail-stops the sequencer |
| 56–62 | 7 | the pooled lane group: lanes 42–48, 7 cores in one CCD (§14.15) |
| 63 | 7 | spare |

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

- **Reject reasons:** 21 `ACCOUNT_KILLED`, 22 `RESEND_GONE`, 23 `BAD_BOOK`, 24 `BUSY`.
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
- **A packet older than its BUSY deadline at dequeue** (≥ 520 ns, which only happens when overload
  exceeds `LANE_POLICE_*`) is not accepted. It is dropped like a wire loss and counted with BUSY
  in B3 (03).
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
