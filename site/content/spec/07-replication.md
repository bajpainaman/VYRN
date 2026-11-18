# 07. Replication: log, order frames, data tier, Simplex, storage, failover

Draft 0.2, 2026-11-13. Normative for `vyrn-seq` stream cores 4 and 7, the frame gate of TX cores
3, 5 and 0, the order hasher (core 50) and the finality listener (control, core 51), `vyrn-data`, `vyrn-replica`, `vyrn-validator`
(replication shell), `vyrn-log`, `vyrn-consensus`. It follows `01-conventions.md` (§6.6 records,
`INV-FRAME-FIRST`, `INV-DET`, `INV-QUORUM`) and the binding decisions of 01 §14. Rationale:
`DESIGN.md` §5 and §7.

## 0. Decisions in one table

| # | Decision | Reason (section) |
|---|---|---|
| D1 | The log has two parts. The **order stream** comes from the sequencer. The **data** (client packets) comes from the data tier. They join at the replica by `(session, pkt_seq)` and are checked by `pkt_hash` and `data_root`. | The sequencer's NICs carry fills, not 3 × 155 Gbps of payload copies (§2, §5). |
| D2 | The order stream is delta-encoded per lane with LEB128. `pkt_seq`, `first_lane_seq` and `StepId` are implicit. A `PacketRecord` costs ~6 B and a `StepRecord` ~3 B plus its share of two half-cut deltas. | ~25 Gbps per path at peak instead of ~70 Gbps raw (§3.13). |
| D3 | The 8-byte `pkt_hash` travels in separate HASH frames, up to `REP_HASH_LAG_NS` behind its record. The hash is not on the fill path. | BLAKE3 of 176 B on the lane's critical path costs more than the lane budget (§3.7, §4.7). |
| D4 | Two stream cores each own one substream: stream-A (core 4) lanes 0–24, stream-B (core 7) lanes 25–48. Each writes its ORDER frames by CTPIO to both paths, then publishes its own `released[H]` and the `LaneCut` of its lanes. A TX core sends no fill of step `s` until `released[A] ≥ need_A(s)` and `released[B] ≥ need_B(s)`. A lane sends no response of an op until `LaneCut` covers it. | `INV-FRAME-FIRST` holds by construction for **every** response, and the frame is on the wire no later than the response (§4). |
| D5 | The BBO core pushes a step's record when its kind, source and cut are fixed, before it writes fills. ORDER frames are ≤ 160 B of body. | The gate then runs in parallel with the step and is a **maximum** of 60 ns past the step budget, not a percentile (§4.7). |
| D6 | Repair: a replica NACKs the sequencer first (the substream's stream core re-posts a buffered frame), then a peer. | Re-posting a descriptor costs ~15 ns. Peers cover the rest (§4.10). |
| D7 | One `vyrn-data` box per facility. A session sends its data copy to one data home. The data home dedupes, stores and fans out to every replica. | 50 Gbps in and ≤ 124 Gbps out per data box fits COTS NICs (§5). |
| D8 | `data_root` is computed over the **full** 32-byte BLAKE3 of every packet. The 8-byte `pkt_hash` is a locator and an early check only. | An 8-byte hash allows a 2^32 birthday attack by a client that controls both copies (§5.6). |
| D9 | Simplex (`commonware-consensus::simplex`, Ed25519 scheme; hybrid Ed25519 + ML-DSA-44 from `E_pq`, 01 §14.20) runs over **ranges of sequencer-signed headers**. Only the n voting replicas vote and lead. `vyrn-seq` **never votes** (01 §14.4). | Proposal traffic stays off the sequencer, a dead sequencer never costs a leader timeout, and a failover never changes the voting set (§6.3). |
| D10 | A replica votes only when it holds every referenced payload, every root checks, CHAIN tags verify, and no divergence is flagged. Votes never wait for replay. | Finality must not depend on replay lag (§6.4). |
| D11 | Finality = block close + seal + 4 metro hops (header, proposal, notarize, finalize): **~2.6 ms typical, ≤ 5.65 ms max with no fault, ≤ 8.65 ms max with one fault.** | Every accepted order is final ≤ 10 ms (§6.6). |
| D12 | State roots every 1000 blocks in both modes, certified with `commonware-consensus::aggregation`. A missing root certificate stops votes after 5000 blocks. A mismatch stops votes at once. | Client diversity must halt the book, not fork it (§7.4, §11). |
| D13 | Failover finalizes the longest prefix: signed headers from any reporter, plus the unsigned tail held by any reporter and consistent across all reporters. | When the sequencer is the fault, f = 1 is used up, so every reporter is honest (§9.3). |
| D14 | The sequencer **self-fences** (01 §14.16): no stream core releases anything when fewer than `REP_FENCE_ACKS` = n − Q + 1 + f = 3 voters have acked within 250 µs; a fence on either stream core silences both. Acks from the co-located R1 alone never keep it alive. | A deposition needs Q = 3 voters, so no quorum can depose a sequencer that is still releasing (§4.8, §9.6). |
| D15 | Membership changes only at epoch boundaries. A dead replica restarts under the **same** key on its facility's spare box, after the old box is fenced. | It keeps the quorum sets fixed for the whole epoch (§13). |
| D16 | Failover promotes the **warm standby** `vyrn-seq` in F2, never a voter. With no promotable standby the book stays halted after the seal, and a facility spare warms up as the next standby. | `CLIENT_SPLIT` survives every failover (§9.5). |
| D17 | **Finality gate** in both modes: the sequencer never runs more than `FIN_GATE_BLOCKS` = 8 closed blocks ahead of finality; beyond that the book halts by a logged `Control` step. | No fill is issued while the 10 ms bound is already known to be broken (§6.8). |
| D18 | The **recovery service**, a role on one Rust voter per home (R3), keeps `RESP_RETAIN_PKTS` responses per session. | Resends survive the sequencer's 8 s hot ring and a failover (§8.5). |

## 1. Scope and hard constraints

This chapter owns the following:

- the order-stream wire format
- the frame transport between `vyrn-seq` and the replicas
- the data tier
- block cutting and signing
- the use of Simplex, the vote rule and certificates
- replay inputs, snapshots and state roots
- storage, sequencer failover, Byzantine handling, the client-diversity alarm, WAN followers,
  recovery and membership

It does not own the following. `05-engine.md` owns lane, cut and BBO semantics and the replay
schedule. `09-chain.md` owns the K_com tag rules, exclusion semantics and slashing. `08-epochs.md`
owns handoff and fencing across epochs. `04-protocol.md` owns client-visible messages.

How this chapter meets the constraints:

- **C-UNIX:** every process here is a Linux userspace process. `vyrn-sim` runs the whole protocol
  on macOS with a simulated network.
- **C-NOCHIP:** frames are built, hashed and signed on CPU cores. The NICs only do what an ASIC
  NIC does as shipped: DMA, CTPIO, hardware timestamps, flow steering. No GPU hashes anything on
  the live path. No switch runs our logic. Switches forward, replicate multicast and apply static
  ACLs.
- **C-COTS:** the parts are Solarflare X2541 and X2542 and ConnectX-6 Dx/7 NICs, merchant 100GbE switches
  with PTP, and U.2/E3.S NVMe drives.
- **C-ONEBIN:** the warm standby box runs `vyrn-seq` in standby beside a non-voting `vyrn-replica`.
  Both link the same `vyrn-engine`, and promotion hands over the replayed engine arenas in place
  (§9.5). Voters run `vyrn-replica` only. AWS uses the same frames over ENA, using DMA in place of
  CTPIO (§4.4).

**Boxes of one home (01 §14.4, §14.7).**

| Box | BASE | CHAIN | Votes | Hardware (REF) |
|---|---|---|---|---|
| active `vyrn-seq` | F1 | the sequencing operator's facility (F1, 09 §2.1) | never | 4 × X2541 client ports; 2 × dual-port X2542 replication cards on leaf switches A and B, one port per stream core (06 §2.3) |
| voters R1–Rn | R1 in F1 (Rust), R2 in F2 (Vx), R3 in F3 (Rust), R4 in F4 (Vx) | 5 validators, 3 Rust and 2 Vx (09) | yes, `Q` = 3 or 4 | 4 × X2541 (2 data, 2 replication), 12 × 61.44 TB NVMe |
| warm standby `vyrn-seq` (Rust) | F2 | F2 | never | the `vyrn-seq` spec; it replays live (§9.5) |
| spare (Rust, cold) | one per facility | one per facility | only after it replaces a dead voter of its facility (§13.2) | the `vyrn-seq` spec plus 12 NVMe |
| archive node | one per facility | one per facility | never | §8.4 |

The fault budget `F` = 1 counts every box of the home, so a faulty sequencer uses it up.

## 2. The log

### 2.1 Two parts

```
   client ──copy 1──► vyrn-seq─order stream (ORDER + HASH + HEADER frames, 2 paths)──┐
     │                                                                                ▼
     └────copy 2──► vyrn-data (session's data home) ──data frames──────────────► vyrn-replica
                                                                                     │
                     join key (session, pkt_seq); checks: pkt_hash, data_root ◄──────┘
```

| Part | Content | Producer | Peak rate (budget) | Key |
|---|---|---|---|---|
| Order stream | `PacketRecord`, `AcctTake`, `RouteRecord`, `StepRecord`, `BlockMark`, `SessionBind`, `TenureStart`, `BlockHeader` | `vyrn-seq` stream cores 4 and 7, hasher core 50 | 3.3 GB/s per path, framed (§3.13) | `(epoch, tenure, stream, frame_seq)` |
| Data | the exact UDP payload of each request packet (§6.1 of 01) | `vyrn-data` | 19.2 GB/s to each replica (§5.1) | `(session, pkt_seq)`, checked by `pkt_hash` |

The log of a home is the sequence of blocks. Block `h` is the triple (header `h`, the order bytes of
`h`, the payloads referenced by `h`). Block `h` is **final** when it carries a finalization
certificate (§6.6) or is an ancestor of a final block.

### 2.2 Identities

| Name | Definition |
|---|---|
| tenure | One sequencer's continuous run inside an epoch. `tenure` (u8) starts at 0 in each epoch and increments at every failover. |
| stream | u8. 0 = substream A (lanes 0..`N_HALF`, stream core 4), 1 = substream B (lanes `N_HALF`..`N_LANES`, stream core 7). CONSUMER and AWS have one stream core and use stream 0 only. |
| `frame_seq` | u64. Starts at 1 for each `(epoch, tenure, stream)`. +1 per frame of any kind on that substream, gapless. Identical on both paths. |
| voter index | u8. A voter's position in `REP_Membership.voters` (§13). Simplex and certificates use it. |
| sequencer index | u8. A box's position in `REP_Membership.seq_order`: primary, standby, then spares. Frame headers use it. |
| `header_hash(h)` | `BLAKE3("vyrn v1 header" ‖ header_bytes(h)[0..126])`. This is the `prev` field of header `h+1` (§3.10). |
| `log_hash` (HandoffRecord) | `header_hash(last_height)`. It commits to the whole chain through `prev`. |

## 3. Order-stream wire encoding

### 3.1 Transport

- **UDP over IPv4 multicast** runs on two dedicated VLANs, one per path: `REP_VLAN_A` and
  `REP_VLAN_B`. Path A uses switch A and path B uses switch B. The two paths have separate NIC
  ports, separate switches and diverse metro fibre routes. Nothing else shares those switches.
- Each box `b` has its own group pair, `G_ord(b, A)` and `G_ord(b, B)`. A **static ingress ACL**
  on each switch admits traffic to `G_ord(b, ·)` only from box `b`'s replication ports. A replica
  subscribes to the groups of the current sequencer. At failover it changes its subscription. The
  ACLs never change.
- UDP ports: `REP_UDP_ORDER` = 7400 (frames), `REP_UDP_CTRL` = 7401 (NACK, acks, retransmits,
  unicast), `REP_UDP_DATA` = 7402 (data frames), `REP_UDP_REPAIR` = 7403 (peer repair).
  Consensus, TailReports and state-root votes use `commonware-p2p` (authenticated, encrypted,
  TCP) on the same VLANs. From `E_pq` its handshake is hybrid X25519 + ML-KEM-768: VYRN's `HybridSake`
  (01 §14.20 G, H).
- MTU 9216 on both VLANs. ORDER frames are ≤ 250 B on the wire (`REP_ORDER_FRAME_MAX`, §4.5),
  because CTPIO write time grows with size and bounds the gate (§4.7). HASH frames are ≤ 9000 B
  and go by DMA.
- Frames carry no per-frame MAC or CRC. Ethernet FCS checks each hop. `order_root` checks every
  block within ≤ 1 ms (§6.1). A frame that fails the root is repaired (§4.10). Section 10.2 gives
  the authenticity argument.

### 3.2 Frame header (24 bytes, little-endian)

```
off size field
  0   2  magic       u16   0x4250 ("PB")
  2   1  version     u8    1
  3   1  kind        u8    1 ORDER, 2 HASH, 3 HEADER, 4 HEARTBEAT, 5 HEADER_PQ (01 §14.20)
  4   2  book        BookId
  6   2  epoch16     u16   low 16 bits of the epoch
  8   8  frame_seq   u64
 16   1  flags       u8    bit0 path (0 A, 1 B); bit1 retransmit; bit2 peer-repaired; others 0
 17   1  tenure      u8
 18   2  body_len    u16   bytes of body after this header
 20   1  sender      u8    sequencer index (§2.2)
 21   1  stream      u8    0 A, 1 B (§2.2)
 22   2  reserved    0
 24   …  body        sections (§3.4) or a header (§3.10)
```

`flags` is the only field that differs between the two path copies and retransmissions of one
frame. **INV-REP-3:** for a fixed `(epoch, tenure, stream, frame_seq)`, the bytes at offsets 0–15 and
17–end are identical on both paths and in every retransmission.

### 3.3 Frame kinds

| Kind | Body | Sent by | Path mechanism (REF) |
|---|---|---|---|
| ORDER | sections `LaneRun`, `StepRun`, `SessionBind`, `BlockMark`, `TenureStart` | the substream's stream core | CTPIO on its port of each path |
| HASH | sections `HashRun` for its own lanes | the substream's stream core | DMA on its port of each path |
| HEADER | one 190-byte `BlockHeader` | core 4 (substream A only) | DMA on both of core 4's ports |
| HEARTBEAT | `last_step` u64, `last_height` u64, `ptp_now` u64 | each stream core, on its substream | CTPIO on its port of each path |
| HEADER_PQ | `height` u64, then the 2,420-byte ML-DSA-44 part of `seq_sig` (scheme 1 only, §3.10) | core 4 (substream A only), from the PQ cores' result | DMA on both of core 4's ports |

### 3.4 Sections

Every section starts with one tag byte. Sections never straddle frames.

| Tag | Section | Layout after the tag |
|---|---|---|
| `0x00–0x3F` | `LaneRun` for lane = tag | `k` LEB128, then `k` PacketRecord O-encodings (§3.6) |
| `0x40` | `StepRun` | `m` LEB128, then `m` StepRecord encodings (§3.8) |
| `0x41` | `HashRun` | `lane` u8, `k` LEB128, then `k` × `pkt_hash` u64 (§3.7) |
| `0x42` | `BlockMark` | §3.9 |
| `0x43` | `SessionBind` | `lane` u8, `slot` LEB128, `session` u32, `next_pkt_seq` LEB128 |
| `0x44` | `TenureStart` | §3.9 |
| `0x45–0xFE` | reserved | a decoder that sees one stops and raises `REP_E_TAG` |
| `0xFF` | `Pad` | the rest of the body is padding |

N_LANES ≤ 64 is required by the 6-bit lane tag. REF has 49 lanes (0–48, 01 §10; 01 §5's
`N_LANES_REF` = 50 is a request below) and `N_LANES_CONSUMER` = 11. A `LaneRun` appears only on
the substream of its lane's half.

### 3.5 Decoder state

The encoding is a delta against state that both sides hold. The encoder state lives in each lane
for its own records (lanes pre-encode, §4.2) and in each stream core for the step records of its
substream. The decoder state lives in the replica, one `StepDec` per substream. Both are part of the snapshot (§7.4).

```rust
struct LaneDec {                       // one per lane
    next_lane_seq: LaneSeq,            // first_lane_seq expected for the next PacketRecord
    prev_rx_ts: Nanos,
    prev_fills_applied: StepId,
    last_pkt: (LaneSeq, u8),           // (first_lane_seq, count) of the last non-Advance
                                       // PacketRecord: the base of RouteRecord.back
    slot_session: [SessionId; MAX_SESSIONS_PER_LANE],   // set by SessionBind
    slot_next_pkt_seq: [u32; MAX_SESSIONS_PER_LANE],
    awaiting_hash: Fifo<RecordRef>,    // PacketRecords whose pkt_hash has not arrived
}
struct StepDec {                       // one per substream H
    prev_step: StepId,                 // the last step this substream carried a record of
    prev_cut: [LaneSeq; N_HALF_MAX],   // this half's lanes only
}
const N_HALF: usize = (N_LANES + 1) / 2;   // 25 on REF: half A = lanes 0–24 (cut core 1, stream
                                           // core 4), half B = lanes 25–48 (cut core 6, stream core 7)
```

`TenureStart` sets every base (§3.9). There are no keyframes. Decoding is strictly sequential in
`frame_seq` order, and a gap stalls decoding until it is repaired (§4.9). The stall is bounded by
repair time (≤ 100 µs in a facility, ≤ 600 µs across the metro, budget). Keyframes would cost
bandwidth on every block and would still need the slot map, which is epoch-scoped.

### 3.6 PacketRecord (O-part) encoding inside `LaneRun(l)`

```
byte h:   bits 0–3  count              (0..10; 11..15 → REP_E_COUNT); numbered messages (05 §3.1)
          bit 4     SEQ_EXC            pkt_seq ≠ slot_next_pkt_seq[slot]; on an Advance record MID
          bit 5     LSEQ_EXC           first_lane_seq ≠ next_lane_seq
          bit 6     FA_NZ              fills_applied ≠ prev_fills_applied
          bit 7     SHED               PacketRecord.flags.SHED (01 §14.1): the lane shed the packet;
                                       on an Advance record PASS2 (only with MID)
slot      LEB128 u16                   lane-local session slot, < MAX_SESSIONS_PER_LANE (pool-wide
                                       on pooled lanes); REP_SLOT_ADVANCE = MAX_SESSIONS_PER_LANE marks
                                       an Advance record, REP_SLOT_TAKE = MAX_SESSIONS_PER_LANE + 1 an
                                       AcctTake, REP_SLOT_ROUTE = MAX_SESSIONS_PER_LANE + 2 a
                                       RouteRecord (below)
rx_ts     ZigZag LEB128 of (rx_ts − prev_rx_ts) as i64
[FA_NZ]   LEB128 (fills_applied − prev_fills_applied)          // non-decreasing per lane
[LSEQ_EXC] LEB128 (first_lane_seq − next_lane_seq)             // > 0; lane ops that are not packets
[MID]     LEB128 back = next_lane_seq − first_lane_seq          // MID Advance record only; 0 ≤ back ≤ count
[SEQ_EXC] LEB128 pkt_seq                                       // absolute; never in an Advance record
[PKT]     LEB128 snap_lag                                      // packet record without SHED only; ≤ u16::MAX
                                                               // on the wire, ≤ W = min(u16::MAX,
                                                               // REPLAY_SNAP_HIST − 1) = 4095 from an
                                                               // honest lane (05 §6.5 rule 3)
```

Decoding rebuilds the full logical record of 01 §6.6:

```rust
fn decode_pkt(l: LaneId, d: &mut LaneDec, r: &mut Reader) -> Rec {   // Rec::Pkt, Rec::Take or Rec::Route
    let h = r.u8();
    let count = h & 0x0F;
    let shed = h & 0x80 != 0;
    if count as usize > MAX_MSGS_PER_PKT { fail(REP_E_COUNT) }
    let slot = r.leb_u16();
    if slot as usize == REP_SLOT_TAKE {                          // 01 §14.17 item 4: pooled lanes only
        if h != 0 || !is_pool_lane(l) { fail(REP_E_COUNT) }
        return Rec::Take(AcctTake { account: AccountId(r.leb_u32()), ver: r.leb_u64(), lane: l });
    }
    if slot as usize == REP_SLOT_ROUTE {                         // 05 §10: a classified op's route
        let (first, n) = d.last_pkt;
        let back = h & 0x0F;
        if h & 0x70 != 0 || back >= n { fail(REP_E_COUNT) }
        return Rec::Route(RouteRecord { lane: l, lane_seq: first + (n - 1 - back) as u64,
                                        cross: h & 0x80 != 0 });
    }
    let advance = slot as usize == REP_SLOT_ADVANCE;             // 05 §6.2: a boundary, no packet
    let mid = advance && h & 0x10 != 0;                          // 05 §6.2: a boundary inside the packet
    if advance && (count != 0 || h & 0x20 != 0 || (shed && !mid)) { fail(REP_E_COUNT) }
    let rx_ts = d.prev_rx_ts.checked_add_signed(r.zigzag_i64()).unwrap_or_else(|| fail(REP_E_TS));
    let fills_applied = if h & 0x40 != 0 { d.prev_fills_applied + r.leb_u64() } else { d.prev_fills_applied };
    let first_lane_seq = if mid {                                // an op of the last packet, or its end
        let back = r.leb_u64();
        if back > d.last_pkt.1 as u64 { fail(REP_E_COUNT) }
        d.next_lane_seq - back
    } else if h & 0x20 != 0 { d.next_lane_seq + r.leb_u64() } else { d.next_lane_seq };
    d.prev_rx_ts = rx_ts; d.prev_fills_applied = fills_applied;
    if !mid { d.next_lane_seq = first_lane_seq + count as u64 }  // a shed packet keeps its LaneSeqs
    if !advance { d.last_pkt = (first_lane_seq, count) }
    if advance {
        let flags = ADVANCE | if mid { MID } else { 0 } | if mid && shed { PASS2 } else { 0 };
        return Rec::Pkt(PacketRecord { lane: l, count: 0, flags, session: 0, pkt_seq: 0,
                              rx_ts, pkt_hash: PktHash(0), first_lane_seq, fills_applied, snap_lag: 0 });
    }
    let pkt_seq = if h & 0x10 != 0 { r.leb_u32() } else { d.slot_next_pkt_seq[slot] };
    d.slot_next_pkt_seq[slot] = pkt_seq + 1;
    let snap_lag = if shed { 0 } else { r.leb_u16() };
    let rec = PacketRecord { lane: l, count, flags: if shed { SHED } else { 0 }, session: d.slot_session[slot],
                             pkt_seq, rx_ts, pkt_hash: PktHash::PENDING, first_lane_seq, fills_applied,
                             snap_lag };
    d.awaiting_hash.push(rec.r#ref());                           // shed packets are hashed, not joined
    Rec::Pkt(rec)
}
```

`rx_ts` uses ZigZag because a lane polls up to 4 NIC RX queues, so its processing order is not
timestamp order. `SEQ_EXC` covers a resend and the first packet after a `SessionBind` whose
`next_pkt_seq` is unknown. `LSEQ_EXC` covers lane ops that are not packets, if `05-engine.md`
defines any.

- **SHED** (01 §14.1). Deadline admission answered the whole packet `Reject BUSY`. Its messages
  keep their LaneSeqs, so `LaneCut` gates the answers (§4.11). Replay reads the bit and never
  recomputes the decision (`INV-DET`). The record keeps its `pkt_hash` (its HashRun entry), but
  its payload is not joined and it has no `data_root` entry (§6.1): its `Reject BUSY`s carry
  `client_tag` 0 and replay rebuilds them from the record alone (05 §6.8, §18 Q17). This holds for
  both shed points. A dequeue shed skips the MAC check, so its bytes are never trusted or needed.
- **`flags`** is 01 §6.6's byte: bit 0 `SHED`, bit 1 `ADVANCE`. Neither bit costs a byte on the
  wire: `SHED` is bit 7 of `h`, and `ADVANCE` is the slot value `REP_SLOT_ADVANCE`. Every other
  bit is 0.
- **Advance record** (05 §6.2, 01 §14.11): `flags = ADVANCE`, `count = 0`, `session = 0`, `pkt_seq = 0`,
  `pkt_hash = 0`. It carries only `rx_ts` (05: the lane's previous `prio_ts`) and
  `fills_applied`. It has no payload, no HashRun entry and no `data_root` entry. A real packet
  whose messages take no number also has `count = 0`, but it has a real slot and a payload.
- **`MID` Advance record** (05 §6.2, R11). A `LaneCut` boundary the lane ran inside the packet
  whose PacketRecord precedes it: `flags = ADVANCE | MID`, plus `PASS2` when it ran before pass 2
  of its op. `h` bit 4 is `MID` and bit 7 `PASS2` (`PASS2` without `MID` is `REP_E_COUNT`); after
  `fills_applied` comes one LEB128 `back = next_lane_seq − first_lane_seq`, where
  `first_lane_seq` is the op before which the boundary ran. `0 ≤ back ≤ count` of the lane's
  last non-Advance PacketRecord, else `REP_E_COUNT`. `back = 0` is a boundary after the packet's
  last numbered op: the lane polls `LaneCut` before every message, and a trailing `Heartbeat` or
  `ResendReq` takes no `LaneSeq` (05 §3.1), so the boundary before it names the next LaneSeq.
  A `MID` record does not move `next_lane_seq`, so later route records still name the packet's
  ops. Like a route record it travels with its packet: the sequencer frames a packet's `MID` and
  route records in the packet's block, because §7.1 replays them in one lane call. `LSEQ_EXC` on any Advance record is `REP_E_COUNT`. Size ~6 B; near zero at peak.
- **`AcctTake { account, ver, lane }`** (01 §14.17 item 4, 05 R15). A pooled lane logs one each
  time it takes an account's token, in its `LaneRun` just before the first record that uses the
  account: `h` = 0, `slot` = `REP_SLOT_TAKE`, then `account` LEB128 and `ver` LEB128 (the token's
  version after the take). It takes no `LaneSeq`, no `rx_ts`, no hash and no payload. Replay
  lane `l` applies its next record only after the account's previous holder has applied every
  record before its own take of `ver − 1`, so the pool's work order is replayed exactly. A take
  on a dedicated lane is `REP_E_COUNT`. Size ~7 B. A take happens only when an account changes pool core,
  ≤ 3M/s at peak, ~0.2 B per record over the whole book (budget, §3.13).
- **`RouteRecord { lane, lane_seq, cross }`** (01 §6.6, 05 §10). A lane logs one for each `New`
  or new-priority `Replace` that it classifies `Cross` or `Improve` (05 §6.5), whether it then
  forwards the op or rejects it itself (for example `POST_ONLY_WOULD_CROSS` or a cross bucket,
  10 M8). Risk charged the op by its route, so replay must give pass 1 the same route, and the
  record travels with its packet: the step that names a forwarded op may fall in a later block
  than the packet, so a replica that waited for it could not replay the packet. Wire form:
  `h` = `back` in bits 0–3, bits 4–6 0, bit 7 `CROSS` (`cross`); `slot` = `REP_SLOT_ROUTE`;
  nothing else. `lane_seq` = `last − back`, where `last` = `first_lane_seq + count − 1` of the
  lane's last non-Advance PacketRecord (`LaneDec.last_pkt`); `back ≥ count`, or a reserved bit,
  is `REP_E_COUNT`. It follows its packet's PacketRecord in the `LaneRun`, after or between that
  packet's `MID` Advance records, and before the lane's next PacketRecord or non-`MID` Advance
  record; it need not come right after the PacketRecord. It takes no `LaneSeq`, `rx_ts`, hash or
  payload. A forwarded op's `StepRecord.flags.CROSS` (§3.8) repeats its route; `replay_step`
  checks that the two agree. Size 3 B per classified op, 0 B for a `Join`; ≤ 30M/s at peak
  (budget, §3.13).
- **Pooled slots.** On a pooled lane `slot` indexes the pool's shared session table, and
  `slot_next_pkt_seq` is kept per pool, so consecutive packets of a session may sit on different
  pool lanes. A packet framed out of `pkt_seq` order across pool lanes takes `SEQ_EXC`.

**Size (budget):** `h` 1 + `slot` 1.6 + `rx_ts` 2.2 + exceptions 0.2 ≈ **5.0 B**. Budget 6 B.
An Advance record is ~5 B; at full load its rate is near zero (05 §6.2). The `LaneRun` header
adds 2 B per lane per frame.

### 3.7 HashRun (H-part)

`HashRun(l, k)` gives `pkt_hash` for the next `k` records in `LaneDec[l].awaiting_hash`, in order.
Lanes compute the full BLAKE3-256 of each packet in batches of `REP_HASH_BATCH` = 16 with the
`hash_many` SIMD path. They push the 8-byte prefix to their half's stream core and the 32-byte hash
to the order hasher on core 50 (§4.6).
**INV-REP-8:** the HashRun for a record is in a frame sent at most `REP_HASH_LAG_NS` = 4000 ns
(budget) after the record's ORDER frame, on the same substream. A replica raises `REP_E_HASHLAG` if a record waits more
than 1 ms. That is a sequencer fault.
DEV only: `vyrn-validator`'s `[replay] hashlag_us` (with `dev = true`) sets a larger bound for
unpinned DEV and CI hosts, which do not meet the pinned-core budget of §7.2. A validator without
`dev = true` refuses any value other than the 1 ms above, so production behaviour is unchanged.

The H-part is not part of `order_root` (§6.1). It is implied by `data_root`, which covers the full
hashes. The 8-byte `pkt_hash` is used for three things: the lookup key into the data store, an
early per-packet check, and the only check available for an unsigned failover tail (§9.3).

### 3.8 StepRecord encoding inside `StepRun`

**A step is logged as one or two half records.** Its **home** record (kind, source, payload, and
the home half's cut delta) goes on the substream of the home half: the half of `src_lane`, or A
when `src_lane` = 0xFF. When the other half's cut also moved at that step, the other substream
carries a **cut-only** record with that half's delta. So each stream core frames only its own
lanes' records and its own half-cut, and a step that spans both halves is the one with two
records (§4.2 gives its gate).

```
byte 0:  bits 0–3  kind        0 Cross, 1 Improve, 2 Depletion, 3 Rescan, 4 Idle, 5 Shed,
                               6 Control, 7 Seal, 8 Uncross; 9–15 → REP_E_KIND (01 §14.10);
                               a cut-only record repeats the home record's kind
         bit 4     HOME        1 home record, 0 cut-only record
         bits 5–6  mode        this half's cut delta: 0 SAME, 1 DENSE, 2 SPARSE, 3 → REP_E_CUT
         bit 7     OTHER       the other substream carries a record of this step too
gap      LEB128 (step − prev_step − 1)                      // steps this substream does not carry
[HOME]   src u8: 0xFF = none, else bits 0–5 src_lane, bit 6 0, bit 7 CROSS (StepRecord.flags bit 1);
         [src≠0xFF] ZigZag LEB128 (src_lane_seq − cut[src_lane]);
         [payload] kinds Rescan, Control, Seal, Uncross only: plen LEB128, then plen bytes (05 owns
         them: the Rescan band, the Control code and argument, the uncross cut reference)
[DENSE]  |H| × LEB128 (cut[l] − prev_cut[l])                 // ≥ 0 by INV-CUT-MONO per half
[SPARSE] bitmap ceil(|H|/8) bytes (bit i = lane H.first + i changed),
         then LEB128 (cut[l] − prev_cut[l]) for each set bit, in lane order; each value ≥ 1
```

`step` is `prev_step + 1 + gap` on that substream; StepId stays gapless per epoch across the two,
and `TenureStart` sets each substream's base. **The step's cut is the union of two half-cuts**
(01 §14.3): half A from cut core A (core 1) and half B from cut core B (core 6). A half with no
record at step `s` keeps its previous half-cut. The replica merges the two StepRuns by StepId:
step `s` is complete when its home record and, if OTHER is set, its cut-only record are decoded.
`INV-CUT-MONO` holds per half, so it holds for the union. For each record the encoder picks SAME
when the half is unchanged, and otherwise the shorter of DENSE and SPARSE. Both clients must decode
every form. The choice does not affect replay, because replay consumes the decoded cut. A decoder
rejects a SPARSE delta of 0, any decrease, a cut-only record with mode SAME, and a home record whose
`src_lane` is not in its substream's half (`REP_E_CUT`). A `src` byte with bit 6 set names no lane
(lanes are < 64) and is `REP_E_CUT` too.

**`CROSS`** (bit 7 of `src`) is `StepRecord.flags` bit 1 (01 §6.6), copied from the source's
`FwdEntry` (05 §4.12, §4.15): the route the lane classified the op with, `Cross` when set,
`Improve` when clear. Lane risk charged by it (10 M8), and the kind does not show it, so replay
reads it (05 §10). It is only on a record with a source; an encoder refuses it on `src` 0xFF or
with any other flag bit (`REP_E_KIND`). It costs no byte. The clamped step-cut rule of 05 (01
§14.11) is applied before encoding, so the logged cut is the clamped one.

| Kind | `src_lane` | Payload | Meaning in the stream |
|---|---|---|---|
| Cross, Improve | the forwarded op | — | 05 §8.1 |
| Depletion, Idle | 0xFF | — | Idle logs a cut that no other step logs (it releases acks, §4.11) |
| Rescan | 0xFF | band: `band_lo` u32 LE, `band_hi` u32 LE (`plen` 8; 0 = all ticks, §7.1) | 05 §8.6 |
| Shed | the shed op | — | the BBO core's deadline test failed (01 §14.1); its lane answers `BUSY` |
| Control | 0xFF | code, argument | phase, band, halt, resume (§6.8), and uncross request (05 §8.8) |
| Seal | 0xFF | — | the book's last step of an epoch (08) |
| Uncross | 0xFF | uncross data | the auction uncross (05 §8.8, 08) |

**Control payload** (reading, **wire**; 05 and 07 name the fields only): `plen` 10, `code` u8
(1 phase, 2 band), `phase` u8 (05 `Phase` code: 0 continuous, 1 auction, 2 halted, 3 frozen;
0 for band), `lo` u32 LE, `hi` u32 LE. The finality gate's halt is phase 2 and its resume
phase 0, both with `lo` = `hi` = 0. Replay queues the command a Control step's payload names
before replaying the step; any other payload is a replay divergence. Uncross and Seal have their
own kinds.

**Size (budget):** each cut core publishes every ≤ `CUT_REFRESH_NS` = 100 ns, so each half changes
≤ 10M times/s and the two halves ≤ 20M times/s together. A changed half moves ~2 ops per lane, so
its DENSE form is ~25 B + 1 B. A home record is ~4 B with its gap byte, and ≤ 10M cut-only records/s
add ~2 B each. Per step at 30M steps/s: 4 B + 20M × 26 B / 30M + 10M × 2 B / 30M ≈ **22 B**,
summed over both substreams. Budget 23 B.

### 3.9 BlockMark and TenureStart

```
BlockMark:   height LEB128, last_step LEB128 (delta from the previous BlockMark's last_step),
             lane_bounds: bitmap ceil(|H|/8) + LEB128 delta per set bit, this half's lanes only
             // lane_bounds[l] = last lane_seq of lane l whose PacketRecord precedes this mark
TenureStart: epoch u32, tenure u8, sender u8, first_step u64, first_height u64,
             prev_header_hash [32], then for each lane of the half: next_lane_seq LEB128,
             rx_ts_base u64, fills_applied_base LEB128; then prev_cut: |H| × LEB128 (absolute)
```

Each substream ends block `h`'s ORDER bytes with its own `BlockMark(h)`, with the same `height` and
`last_step`. Both cut the block at the same step: when core 4's PTP-disciplined clock crosses
`k × BLOCK_NS`, it posts a close request, the BBO core puts a mark entry into `R_step` after its
current step, and each stream core appends its mark when it reaches that entry (§6.1). The mark
makes the boundary part of the stream. Replay therefore never reads a clock (`INV-DET`, 01 §11.3).
`TenureStart` is the first section of frame 1 of each substream in every tenure.

### 3.10 HEADER frame: BlockHeader bytes and seq_sig

```
off size field                         (01 §6.6, field order kept)
  0   8  height        Height
  8   4  epoch         Epoch
 12   2  book          BookId
 14   8  first_step    StepId          = previous header's last_step + 1
 22   8  last_step     StepId          = first_step − 1 for a block with no step
 30  32  prev          Hash            header_hash(height − 1)
 62  32  order_root    Hash            §6.1
 94  32  data_root     Hash            §6.1
126  64  seq_sig       Ed25519Sig      Sign(seq_key, "vyrn      v1 block" ‖ bytes 0..126)
190      end
```

**Scheme 1 (hybrid, 01 §14.20).** The HEADER frame keeps this 190-byte layout, with bytes 126..190
the Ed25519 part of a hybrid `seq_sig`. The 2,420-byte ML-DSA-44 part follows in a HEADER_PQ frame
for the same height, at most `PQ_SIGN_MAX_US` (400 µs, `PQ_HEDGE` = 4) after the HEADER frame. The
logical `BlockHeader` is the concatenation, 2,610 B; the journal (§8.2), snapshots, the WAN feed
and every certificate that embeds a header store all 2,610 B. Both parts sign
`scheme ‖ "vyrn      v1 block" ‖ bytes 0..126`. A header is valid only when both parts verify
(§6.4 item 1). `header_hash` is unchanged, because it covers bytes 0..126 only (§2.2). Why split:
the Ed25519 part is ready ≤ `REP_SEAL_US` after close as today, and the large part neither delays
the HEADER frame nor occupies core 4 for the 2.4 KB copy.

`seq_key` is the sequencer key that `REP_Membership` (§13) registers for the sender. A seal block
(§9.4) has `seq_sig` = 64 zero bytes and is valid only with its seal certificate.

### 3.11 Worked example

Lane 7 has a packet with 10 messages, slot 300, the expected `pkt_seq`, `rx_ts` +512 ns after its
previous packet, and `fills_applied` unchanged. Then the BBO core takes a Cross from lane 7 whose
op is inside the new cut. Half-cut A moves lanes 3, 7 and 12 by +2, +10 and +1. Half-cut B is
unchanged.

```
LaneRun   07 01                    tag lane 7, k = 1
  record  0A AC 02 80 08 00        h = count = 10; slot 300 = AC 02; zigzag(512) = 1024 = 80 08;
                                   snap_lag 0
StepRun   40 01                    tag, m = 1
  step    50 00 07 00              Cross 0 | HOME (1<<4) | SPARSE (2<<5), OTHER 0; gap 0; src 7; zigzag(0)
          88 10 00 00              half A bitmap: bits 3, 7 (0x88), bit 12 (0x10); 25 lanes = 4 bytes
          02 0A 01                 deltas for lanes 3, 7, 12
```

All of it is on substream A, because lane 7 is in half A and half B did not move. That is 21 bytes
for one packet of 10 messages and one cross. 01's logical records hold 43 B and 410 B respectively
(the cut alone is 49 × 8 B).

### 3.12 Decoder loop (replica core 3)

```rust
fn on_frame(f: &Frame, st: &mut DecState) -> Result<(), RepErr> {
    match f.kind {
        ORDER => for sec in f.sections() { match sec.tag {
            0x00..=0x3F => { check_half(sec.tag, f.stream)?;           // a lane only on its half's substream
                             for _ in 0..sec.k { let r = decode_pkt(sec.tag, &mut st.lane[sec.tag], sec);
                                                 st.emit(r); } },
            0x40 => for _ in 0..sec.m { let h = decode_step_half(&mut st.step[f.stream], sec)?;
                                        st.merge_step(h)?; },        // emits Rec::Step when complete
            0x42 => { let m = decode_mark(f.stream, sec)?; check_mark(&m, st)?; st.close_block_half(m); },
            0x43 => st.bind(sec.lane, sec.slot, sec.session, sec.next_pkt_seq),
            0x44 => return Err(REP_E_TENURE),        // only valid as the first section of frame 1
            _    => return Err(REP_E_TAG),
        }},
        HASH => for run in f.hash_runs() { st.attach_hashes(run)?; },   // checks against data copies
        HEADER => st.on_header(BlockHeader::parse(f.body)?)?,           // §6.4
        HEARTBEAT => st.on_heartbeat(f),
    }
    st.order_root[f.stream].update_bytes(f.order_body());   // ORDER section bytes only, per substream
    Ok(())
}
```

`check_step` enforces the structural rules that a vote needs (§6.4): `INV-CUT-MONO` per half, no
`cut[l]` above the lane's decoded `next_lane_seq − 1`, a `src_lane_seq` that names a decoded op of
`src_lane`, the `src_lane` and payload rules of the kind table (§3.8), and no `Shed` step for an op
whose packet carries `SHED` (it was never forwarded). Every error is a sequencer fault. The replica
stops voting for the block, records the error with `(epoch, tenure, stream, frame_seq)` and raises the
sequencer-fault alarm (§10.1).

### 3.13 Bandwidth budget per link (peak, budget)

The inputs are 1B msgs/s, 100M pkts/s (10 msgs/pkt), 30M steps/s (10M crosses plus 20M improves
or depletions), 20M half-cut changes/s and ≤ 12M ORDER frames/s over both substreams (one flush
per gated step and substream at worst, a step that spans both halves flushing both; the 160 B
body cap needs ≥ 8.9M/s). Advance, Shed and Control records are near zero at peak. A path is the
pair of replication ports on one leaf, one per substream (06 §2.3); the table sums both.

| Item | Rate | Bytes each | MB/s per path |
|---|---|---|---|
| PacketRecord O-part, with `snap_lag` (1 B when < 128) | 100M/s | 7.0 | 700 |
| `AcctTake` (pooled lanes) | ≤ 3M/s | 7 | 20 |
| `RouteRecord` (one per op classified `Cross` or `Improve`) | ≤ 30M/s | 3 | 90 |
| LaneRun headers | 12M frames × ~5 lanes | 2 | 120 |
| StepRecord home part, with gap | 30M/s | 4 | 120 |
| Cut-only records, fixed part | ≤ 10M/s | 2 | 20 |
| Half-cut deltas | 20M/s | 26 | 520 |
| StepRun headers | 12M/s | 2 | 24 |
| ORDER frame overhead (Eth 14 + IP 20 + UDP 8 + PB 24 + FCS 4 + preamble/IFG 20) | 12M/s | 90 | 1,080 |
| HashRun payload | 100M/s | 8 | 800 |
| HASH frame overhead (9000 B frames) | ~0.1M/s | 90 | 9 |
| HEADER, BlockMark, HEARTBEAT, SessionBind | ~25k/s | ≤ 220 | < 1 |
| HEADER_PQ (scheme 1 only, 01 §14.20) | 1k/s per book | ~2,540 | 2.5 |
| **Total per path** | | | **3,500 MB/s ≈ 28.0 Gbps** (3,503 under scheme 1) |

Record payload (O + H + steps) is 2.43 GB/s ≈ 19.4 Gbps. Frame overhead is the rest, and it falls
when flushes coalesce under load (§4.5). On the sequencer each path is two 100GbE ports at ≤ 14%
each; at a replica each path is one port at ≤ 28%, carrying both substreams. `snap_lag` (05 §6.5)
added 1 B per packet record (+100 MB/s, +0.8 Gbps per path). Replicas send
the sequencer ≤ 1 Mbps of acks and NACKs.

Other links at peak (budget):

| Link | Rate | Note |
|---|---|---|
| clients → data tier (sum over data boxes) | ~200 Gbps | 100M pkts/s × (192 B payload + 58 B framing) |
| one data box → each destination | 155/n_data Gbps | payloads in 9000 B data frames (§5.3); destinations = voters + standby |
| all data boxes → one replica | 19.4 GB/s ≈ 155 Gbps | over the replica's 2 data ports, 78% each |
| sequencer → one replica (both paths) | 2 × 26.5 Gbps | the replica's 2 replication ports, one per path, both substreams on each |
| consensus + state roots + repair, per replica | < 0.5 Gbps | commonware-p2p |
| finalize votes and certificates, voters → sequencer and standby | < 0.1 Gbps | §6.8 |
| recovery service → clients | ≤ 4.5 Gbps | §8.5 |
| active home → each follower home | ≤ 62 Gbps (BASE), ≤ 75 Gbps (CHAIN) | §12 |

## 4. Order frames from the sequencer

### 4.1 Cores and rings

The order stream has two substreams (01 §14.15 item 3). Stream-A (core 4) owns lanes 0–24 and
stream-B (core 7) owns lanes 25–48. Each owns one port on each path (06 §2.3: port a and port b of
the two X2542 cards), its own `frame_seq`, frame ring, heartbeats, HASH frames, NACK service and
`released` word, and the `LaneCut` of its lanes. Stream-A also closes blocks, signs headers and
runs the finality gate. The three fill TX cores (A = 3, B = 5, C = 0, 01 §14.17) each own client
ports (06 §2.3) and check both release words.

```
 half A: lanes 0–24 (cores 8–32)                  CCD 0
 ┌──────────────┐ R_pkt[l], R_hash8[l]           ┌──────────────────────────────────────────┐
 │ lane l       ├───────────────────────────────►│ core 4  stream-A                         │
 │  parse, MAC, │                                │  CTPIO → port A.a, port B.a; sfence      │
 │  risk,       │                                │  released[A]; LaneCut[l ∈ A]             │
 │  classify,   │                                │  block close, signer, HEADER, fence, gate│
 │  encode O,   │ half B: lanes 25–48            ├──────────────────────────────────────────┤
 │  AcctTake,   │ (cores 33–49, pool 56–62)      │ core 7  stream-B                         │
 │  hash batch  ├───────────────────────────────►│  CTPIO → port A.b, port B.b; sfence      │
 └──────┬───────┘                                │  released[B]; LaneCut[l ∈ B]; fence      │
        │ R_hash32[l]                            └──────▲───────────────▲───────────────────┘
        └────────────────► core 50 order hasher ◄───────┼─ frame rings  │ R_step (+ need, marks)
 ┌──────────────┐ R_step: one writer, three cursors ────┴───────────────┘
 │ core 2  BBO  │ R_fill_X: fills tagged (s, need_A, need_B), X = the TX core of the recipient's port
 │  step s      ├──────► core 3 TX-A, core 5 TX-B, core 0 TX-C
 └──────────────┘        wait: released[A] ≥ need_A(s) and released[B] ≥ need_B(s), then CTPIO fill
 lanes: every response of op q waits for LaneCut[l].cut ≥ q (written by l's stream core after sfence)
```

| Ring / word | Writer | Reader | Entry | Size |
|---|---|---|---|---|
| `R_pkt[l]` | lane l | stream core of l's half | `(first_lane_seq, len u8, bytes[≤ 32])`: the record (or `AcctTake`) pre-encoded against the lane's own `LaneDec` mirror | 64 Ki entries |
| `R_hash8[l]` | lane l | stream core of l's half | `(first_lane_seq, pkt_hash u64)` | 64 Ki |
| `R_hash32[l]` | lane l | core 50 | `(first_lane_seq, hash [32])` | 64 Ki |
| `R_step` | core 2 | stream-A, stream-B and core 50, each with its own cursor | `StepRecord` with `need_A`, `need_B` (pushed early, §4.2), and block-mark entries | 16 Ki |
| `R_fill_A`, `_B`, `_C` | core 2 | TX-A, TX-B, TX-C | fill events tagged `(step, need_A, need_B)` | 05 owns |
| `released[A]`, `released[B]` | core 4, core 7 | the three TX cores, core 2 (back-pressure) | u64 each, own cache line | — |
| `LaneCut[l]` (05 §4.15) | stream core of l's half | lane l | `(step, cut)`, written only after the frame that holds this half's record of `step` is released | 13 lines |
| `step_done` | core 2 | both stream cores | `(step, fill_lanes u64)`, written at step end | own line |
| `close_req` | core 4 | core 2 | the height to close (§3.9) | own line |
| `seq_fenced` | either stream core | both stream cores | set once, never cleared in a tenure (§4.8) | own line |
| `final_height` | core 51 (finality listener) | core 4 | newest finalized height seen (§6.8) | own line |
| frame ring A, B (`REP_RTX_RING_BYTES` each) | its stream core | NICs (DMA), core 50, its stream core (retransmit) | finished frame bytes | 64 MiB each |

Every ring is SPSC except `R_step` (one writer, three cursors, `INV-WRITER`). Lanes encode their
own records, because lane `l`'s encoder state is lane-local: ~5 ns per packet, 1.7% of its budget.

**`need_H(s)`.** It is the newest step ≤ `s` whose records on substream H a response of `s`
depends on: `s` itself when H carries a record of `s` (H is the home half, or H's half-cut moved
at `s`), else `need_H(s − 1)`. The BBO core keeps both values as it pushes each step, at ~1 ns.

### 4.2 The gate protocol

Lane `l`, per packet (05 owns the surrounding loop):

```rust
let enc = lane_enc.encode(&pkt_rec);            // §3.6, against the lane's LaneDec mirror
R_pkt[l].push(enc);                             // (1) plain store into the ring slot, then ring tail Release
lane_counter[l].store(new_lane_seq, Release);   // (2) publish; the cut core may now include the op
// ... every response of the packet waits for LaneCut[l].cut ≥ its last LaneSeq (§4.11)
hash_batch.push(pkt);                           // full BLAKE3 done 16 at a time, off the response path
```

Lanes encode in pass 1 (01 §14.2), so (1) precedes the BBO push of any forwarded op of the packet.
A pooled lane pushes its `AcctTake` into `R_pkt[l]` before the first record that uses the token.

BBO core (core 2), per step `s`:

```rust
// as soon as kind, src and the (clamped) cut are fixed, before any fill (05 states the point per kind)
let need = need.advance(s, home_half(src_lane), moved_halves(&cut, &prev_cut));   // §4.1
R_step.push(StepEntry { rec: StepRecord { step: s, kind, src_lane, src_lane_seq, cut }, need });
for fill in step_fills { R_fill[tx_of(fill.lane)].push(fill.tagged(s, need)); }   // Release on tail
step_done.store((s, fill_lanes), Release);                                       // step end
if let Some(h) = close_req.take() { R_step.push(StepEntry::mark(h, s)); }       // §3.9
```

Stream core H (4 or 7), main loop:

```rust
loop {
    // A. steps: drain this half's lanes up to each step's half-cut, then append this half's record.
    while let Some(e) = R_step.peek_acquire(H) {
        if let Some(h) = e.mark() { frame.append_mark(h, e.last_step, lane_bounds(H)); R_step.pop(H); continue; }
        if e.need[H] == e.step {                             // H carries a record of this step
            for l in lanes_changed(H, &e.cut, &framed_to) {  // only this half's lanes whose cut moved
                let upto = max(e.cut[l], if e.src_lane == l { e.src_lane_seq } else { 0 });
                while framed_to[l] < upto { frame.append_lane(l, R_pkt[l].pop_acquire()); } // INV-REP-2
            }
            if frame.len() + e.enc_len(H) > REP_ORDER_FRAME_MAX { flush_order(); }
            frame.append_step_half(H, &e);                   // home or cut-only record (§3.8)
            pending_gate = e.step;
        }
        seen = e.step;
        R_step.pop(H);
    }
    // B. records ahead of any cut, so that the next step's drain is short; never a flush on its own
    //    while the BBO core is mid-step (step_busy), so a gated step never queues behind it
    for l in round_robin_slice(H) { frame.append_lane_all_upto(l, &mut R_pkt[l], REP_ORDER_FRAME_MAX); }
    // C. flush rule (§4.5)
    if pending_gate > released[H] || (frame.age_ns() >= REP_FLUSH_MAX_NS && !frame.is_empty() && !step_busy()) {
        flush_order();
    }
    // D. LaneCut for this half's lanes that received fills in released steps (step_done.fill_lanes)
    publish_fill_lane_cuts(H);
    // E. background, each item ≤ REP_SIGN_SLICE_NS: HASH frames, NACKs, heartbeats, acks RX,
    //    self-fence; on core 4 also block close, one signer slice and the finality gate (§4.8, §6.8)
    background_slice(H);
}

fn flush_order() {
    if seq_fenced.load(Acquire) || !self_fence_ok() {  // INV-REP-6: REP_FENCE_ACKS fresh voter acks
        seq_fenced.store(true, Release); go_silent(); return;   // silences both stream cores
    }
    let bytes = frame.seal(H, next_frame_seq(H));       // header + sections, into frame ring H
    ctpio_write(PORT_A[H], bytes);                      // WC stores into this core's port on path A
    ctpio_write(PORT_B[H], bytes.with_path_bit());      // and on path B
    sfence();                                           // both WC buffers drained to the uncore
    released[H].store(seen, Release);                   // every record H carries for steps ≤ seen is out
    for (l, c) in frame.cut_lanes() { lane_cut[l].store16((pending_gate, c)); }  // the ack gate (§4.11)
}
```

Fill TX core X (3, 5 or 0), per fill:

```rust
let (s, na, nb) = (fill.step, fill.need_a, fill.need_b);
while released[A].load(Acquire) < na || released[B].load(Acquire) < nb { core::hint::spin_loop(); } // INV-REP-1
ctpio_write(client_port(fill), fill_frame);
```

**A step that spans both halves** has `need_A(s) = need_B(s) = s`: it has a record on each
substream, so its fills wait for the later of the two releases. The two stream cores frame it in
parallel, each from its own `R_step` cursor, so the wait is the slower core's, not the sum (§4.7).
A step that touches one half waits for that half's core, plus the other half's `need`, which is an
older step that is normally released long before.

### 4.3 Why INV-FRAME-FIRST holds

**INV-REP-2 (drain before step, per half):** stream core H appends its record of step `s` only
after it has appended every PacketRecord of its half with `lane_seq ≤ cut_s[l]`, and the src op
when `src_lane` is in H. The records are present by happens-before. The lane writes `R_pkt[l]` (1)
before its release store of the counter (2). The cut core acquires (2) and then releases the cut.
The BBO core acquires the cut and then releases `R_step`. Core H acquires `R_step`. So when core H
reads step `s`, every `R_pkt` entry of its half at or below `cut_s` is visible. The src op of a
cross may be above the cut. Its entry was pushed before the lane pushed the order to the BBO ring,
so it is visible too.

**INV-REP-1 (order before response):** a TX core writes a fill of step `s` only after it reads
`released[A] ≥ need_A(s)` and `released[B] ≥ need_B(s)` with acquire. Core H stores `released[H]`
with release after the `sfence` that follows the CTPIO writes of its frame on both paths, and its
frames are flushed in `frame_seq` order. Every record that a response of `s` depends on is on the
substream of its lane's half, and the newest step whose records on H it needs is `need_H(s)` by
definition. So the step's records, every record in its cut, and every earlier frame of both
substreams that holds them, are written to both replication TX queues before any fill of `s` is
written. That is `INV-FRAME-FIRST` (01 §7, §14.16). Responses that a step produces other than fills
(05 decides whether an improve's `Ack` comes from a TX core) pass the same check.

**INV-REP-11 (every lane response is gated):** a lane of half H writes a response of op `q` only
after it reads `LaneCut[l].cut ≥ q` with acquire. Core H stores `LaneCut[l] = (s, C_s[l])` only
after the `sfence` of its frame that holds its record of step `s`, which logs half H's cut, and
that frame follows every PacketRecord of lane `l` up to `C_s[l]` (INV-REP-2). So the op's record,
and the record that logs the cut covering it, are on both TX paths before the response. An ack
needs only its own half: if a crash loses the home record of `s` on the other substream, the seal
drops the orphan cut-only record and `q` stays in the prefix as a trailing lane op (§9.4), so an
acked order still survives. This covers joins, cancels, rejects, `BUSY` answers and settled maker
fills: **every** response (01 §14.5). `INV-ACK-AFTER-CUT` becomes "after a *released* cut includes
the op".

**Test:** `vyrn-sim` runs a model checker over the seven threads (a lane of each half, cut, BBO,
stream-A, stream-B, one TX core) with loom-style exhaustive interleavings on a 2-lane, 3-step
workload that includes a spanning step (T-REP-1). On hardware, B-REP-2 checks INV-FRAME-FIRST for
every response, acks included, and asserts zero violations (§4.4).

### 4.4 Why CTPIO, and the frame lead

The decision is that ORDER and HEARTBEAT frames go by CTPIO on the REF box, and HASH and HEADER
frames go by DMA.

- With DMA, the doorbell would be written first, but the NIC fetches the descriptor and the data
  over PCIe (~0.6–1.0 µs, vendor). The fill goes out by CTPIO in ~250 ns. The fill would lead its
  frame on the wire by ~0.5 µs, and a power loss in that window loses the frame.
- With CTPIO, the frame's bytes are in the replication NIC before the fill's first byte is
  written to the client NIC. Both start transmitting ~250 ns after the write (vendor). So the
  frame leaves the box no later than the fill, except for PCIe and NIC jitter.

**Two different checks.** `INV-FRAME-FIRST` is a correctness invariant the code enforces: the TX
cores and the lanes wait on `released[A]`, `released[B]` and `LaneCut`. **B-REP-2** logs the frame's and the
response's TX-queue writes for every response, acks included, and asserts **zero** violations.
It is pass/fail, never a percentile.

The **wire lead** is a separate, physical quantity: `lead(r) = t_wire(response r) −
t_wire(ORDER frame that r depends on)`, from the hardware TX timestamps of both NICs, which share
one PHC source on one box (06). The written order cannot make the NICs transmit in order, so
`lead < 0` can occur through PCIe or NIC jitter. It matters only if the box loses power in that
window. **B-REP-2W** measures its distribution, and §9.6 (c) uses the measured fraction.

On AWS (ENA via DPDK), frames go by DMA. The gate still holds as written, at the doorbell. The
in-box exposure of §9.6 is then ~1 µs per sequencer death instead of ~0. This is published for
the AWS target (01 §14.0 fact 1). On CONSUMER, path B runs on its own X2522 port (01 §14.7) with
CTPIO, about 6 Gbps at ~250M msgs/s, so CONSUMER has two independent paths and the same revert
analysis as REF.

### 4.5 Flush policy

A frame is flushed when any one of these holds:

1. A step that can release a response has been appended (`pending_gate > released`): it has
   fills, or it moved a half-cut (any mode ≠ SAME), since a moved cut releases lane responses.
   This is the latency-critical trigger.
2. The next section would take the frame body past `REP_ORDER_FRAME_MAX` = 160 B.
3. The oldest record in the frame is `REP_FLUSH_MAX_NS` = 1000 ns old, and the BBO core is not
   mid-step.

The rules apply per substream. There is no minimum interval. Under load, coalescing comes for
free: while a stream core writes one frame (≤ 32 ns busy), further steps queue in `R_step`, and
they go into its next frame. The ORDER frame rate is therefore ≤ min(gated steps/s, 1 / t_flush)
≈ 6M/s per substream and ≤ 12M/s together at peak. A step with a SAME cut
and no fills does not trigger a flush.

### 4.6 Core 50: order hasher

Core 50 (CCD 6, the order hasher of 01 §10) does three jobs:

- It follows both frame rings behind the stream cores and keeps `order_root_A(h)` and
  `order_root_B(h)`, BLAKE3 incremental hashes over each substream's ORDER section bytes of block
  `h` (§6.1).
- It follows `R_step` (its own cursor) and the decoded O-order of each substream. From
  `R_hash32[l]` it appends each packet's full 32-byte hash to that substream's `data_root` hasher,
  in O-order, skipping `SHED` records (§6.1).
- It keeps the full-hash list of each block for `REP_SEQ_HASHLIST_MS` = 50 ms (~3.2 MB per block
  at peak) and serves `HashListReq` (§5.6).

When both substreams' `BlockMark(h)` have passed, it hands `(order_root, data_root)` to core 4
through an SPSC word pair. It reads the rings across CCDs, prefetched; it is on no response path,
so the distance costs only seal latency (§6.2). Load (budget): 2.24 GB/s + 3.2 GB/s of BLAKE3 at
~0.5 cycles/byte ≈ 2.7 G cycles/s, about **54%** of a 5 GHz core (**B-REP-6**).

### 4.7 Load and latency budget of a stream core

Per stream core, each with half the lanes (budget):

| Work | Rate (peak) | ns each | Load |
|---|---|---|---|
| Copy pre-encoded O-records from 24–25 rings (cross-CCD reads, prefetched) | 50M/s | 1.2 | 0.06 |
| Encode and append home and cut-only records | ~20M/s | 3 | 0.06 |
| CTPIO writes, 2 ports, ≤ 250 B of frame each | 6M frames/s | 2 × 12 | 0.14 |
| Frame seal, `sfence`, release | 6M/s | 6 | 0.04 |
| `LaneCut` writes after release (~2 lines per flush, 05 §4.15) | 6M/s | 8 | 0.05 |
| HASH frames: copy 8-byte hashes, DMA post | 50M hashes/s | 0.5 | 0.03 |
| Background: NACK, heartbeat, acks, fence; on core 4 also block close, signer and gate | — | — | 0.03 (A: 0.04) |
| **Total** | | | **0.41** on core 4, **0.40** on core 7 (budget `REP_STREAM_MAX_LOAD` = 0.50, **B-REP-4**) |

This is above the ≤ 0.25 of 01 §14.15 item 3: the CTPIO writes per frame do not halve when the
lanes do (Requests to 01). The gate bound below does not depend on load.

**The gate as a maximum.** 01 §14.2 charges a cross `100 (step) + 60 (frame gate) + 40 (TX core)`,
so the gate must be open ≤ 160 ns after the step **starts**, always. Three rules make that a bound
and not a percentile:

1. **Early push.** The BBO core pushes `StepRecord s` when kind, source and cut are fixed,
   ≤ `REP_KIND_FIX_NS` = 10 ns into the step (05 states the point per kind). The stream cores frame
   it while the BBO core is still matching.
2. **Small frames.** `REP_ORDER_FRAME_MAX` = 160 B of body (≤ 250 B on the wire), so one flush keeps
   a stream core busy ≤ `REP_FLUSH_BUSY_NS` = 32 ns (seal 6 + 2 × ≤ 8 of CTPIO + `sfence` 10).
3. **No blind flush.** Part B never flushes on its own while `step_busy` is set, so a gated step
   waits behind at most one flush per stream core that started before the step did.

Worst case from step start, max (budget), for a step that spans both halves: kind fixed 10 +
`R_step` hop on CCD 0 30 + one in-progress flush 32 + drain of the src lane 3 (pre-encoded in pass 1,
normally drained in part B) + own flush 32 = 107 on each stream core, in parallel; then the TX core
sees both release lines, 30 for the first and 5 more for the second, whose load it issues at the
same time = **142 ns ≤ 160 ns**. A step that touches one half is ≤ 137 ns. `REP_FRAME_GATE_NS` =
60 is therefore a maximum past the 100 ns step budget; a burst coalesces into the next capped frame
and adds no second wait. With 01 §14.15's 15 ns step the gate still opens ≤ 142 ns after the step
starts, so the cross fill at index 9 is 320 + 45 + 50 + 10 + 100 + 142 + 40 + 240 = 947 ns, not
01 §14.2's 880 (Requests to 01). The BBO core's deadline test (01 §14.1) uses these terms, so a
step that would still miss the deadline is shed before it fills (`StepKind::Shed`).

### 4.8 Heartbeats, acks and self-fence

- **Heartbeat.** When a stream core has sent no frame for `REP_HB_US` = 50 µs, it sends a
  HEARTBEAT on its substream on both paths. The highest `frame_seq` of each substream is therefore
  never older than 50 µs at any live replica, and a lost final frame is detected (§4.9).
- **Ack.** Every voter and the standby send `RepAck { epoch, tenure, contiguous_frame_seq: [u64;
  2], path_mask }` (one value per substream) every `REP_ACK_US` = 50 µs, unicast to the
  `REP_UDP_CTRL` port of **each** stream core, on both paths. A box sends an ack only if it received
  a frame of the tenure in the last `REP_ACK_LIVE_US` = 100 µs, so a box that can send but not
  receive stops acking. Each stream core polls the RX rings of its own replication VIs in its
  background slice and keeps its own `last_ack_ns[v]` per voter.
- **Self-fence (INV-REP-6, 01 §14.16).** The sequencer fences itself unless it holds fresh acks
  from `REP_FENCE_ACKS` = n − Q + 1 + f = 3 distinct voters (3 in BASE and in CHAIN). If a stream
  core finds fewer than 3 voters with `now − last_ack_ns[v] ≤ REP_SELF_FENCE_US` = 250 µs, it sets
  `seq_fenced`. Both stream cores read `seq_fenced` before every flush, so both stop advancing
  `released[·]` and `LaneCut` and stop all frames, heartbeats included, within one flush. No
  response passes the gate after that. The silence makes the voters start a failover (§9.1). It
  never resumes in the same tenure. Acks from the co-located R1 alone never keep it alive: R1 is
  one voter of the three.
- **Why 3.** A deposition needs `Q` Silence messages from voters (§9.2), at most f = 1 of them
  Byzantine. With ≥ 3 fresh voters, ≥ 2 honest voters receive frames and stay silent, so at most
  n − 2 can send Silence: 2 < 3 (BASE), 3 < 4 (CHAIN). `REP_FENCE_ACKS = n − Q + 1 + f` = 3. The old rule (the newest ack from *any* replica) is unsafe once the sequencer does not
  vote: an F1 cut off from F2–F4 would keep the co-located R1 acking while R2–R4 depose.
- A sequencer cut off from enough voters stops releasing within `REP_ACK_LIVE_US` + one one-way
  delay + 250 µs (≤ 1.15 ms, max budget), then falls silent and is deposed. A stalled sequencer
  (an SMI, a page fault, a hung core) finds the stale acks at its next flush and fences before it
  sends anything more.

### 4.9 Loss detection at the replica

Replica core 1 runs one receive loop over both replication ports. Each substream has its own
`next_expected` and holes; the loop below runs per substream (`f.stream`):

```rust
fn on_rx(f: Frame) {
    if f.epoch16 != cur.epoch16 || f.tenure != cur.tenure || f.sender != cur.seq { drop_count(); return }
    if f.frame_seq < next_expected || have(f.frame_seq) { dup_count(f.path()); return }   // other path's copy
    store(f);                                          // frame store, §4.10
    while have(next_expected) { deliver(next_expected); next_expected += 1; }
    if f.frame_seq > next_expected { holes.open(next_expected .. f.frame_seq, now) }
}
fn tick(now) {
    for hole in holes.older_than(now, REP_HOLE_WAIT_US) { nack_seq(hole) }           // 5 µs
    for hole in holes.nacked_older_than(now, REP_NACK_RETRY_US) { nack_peer(hole); nack_seq(hole) } // 50 µs
    if now − last_rx_any > FAILOVER_SILENCE_MS { failover::suspect(now) }            // §9.1
}
```

`REP_HOLE_WAIT_US` = 5 µs covers the skew between the two paths (budget: path skew ≤ 2 µs,
**B-REP-3**). A replica counts per-path losses. If a path loses more than `REP_PATH_LOSS_ALARM` =
1e-6 of frames over 10 s, or is silent for `REP_PATH_DOWN_MS` = 100 ms while the other path is
live, the replica raises the alarm `REP_A_PATH`. Trading continues on one path (§14).

### 4.10 Repair

**Sequencer retransmit (first choice).** `Nack { epoch, tenure, stream, from_seq, to_seq }` goes
unicast to that substream's stream core at `REP_UDP_CTRL`. It looks up each frame in its frame
ring. Each ring is `REP_RTX_RING_BYTES` = 64 MiB, about 40 ms of its substream at peak. The core
re-posts the frame by **DMA**, unicast to the requesting replica, on the path the NACK came from,
with `flags.retransmit` set. It does not copy the frame and does not use CTPIO, so a retransmit
costs ~15 ns of the stream core per frame. Each stream core serves at most `REP_RTX_MAX_FPS` = 200k frames/s. More than that is dropped and counted,
and the replica falls back to its peers. A frame that has left the ring gets
`NackTooOld { oldest_seq }`.

**Peer repair (fallback, and the only source for older frames).** `RepairReq { epoch, tenure,
stream, from_seq, to_seq }` goes to one peer (a voter or the standby), chosen in round-robin order by
index. Peers serve from their in-memory frame store (`REP_PEER_RING_MS` = 2000 ms,
~6 GB at peak) and then from their NVMe order journal (§8). A peer-repaired frame is stored with
`flags.peer_repaired` set. Two rules follow from that flag:

- A peer-repaired frame is trusted only once the `order_root` of its block checks (§6.4).
- It does not count as a direct holding in a failover TailReport (§9.3).

A peer serves at most `REP_PEER_RTX_MAX_FPS` = 1M frames/s. Peer repair runs on replica core 6.

**Repair time (budget):** hole wait 5 µs + NACK one-way ~5–250 µs (metro) + ring lookup 1 µs +
return. That is ≤ 100 µs within one facility and ≤ 600 µs across the metro, max under a timely
network. The finality budget charges one cross-metro repair (§6.6).

### 4.11 Lane responses are gated too

Draft 0.2 gates **every** response (01 §14.5). A lane sends an `Ack`, `CancelAck`, `Reject`,
`BUSY`, `Out` or settled maker `Fill` of op `q` only when `LaneCut[l].cut ≥ q` (INV-REP-11). The
lane reads `LaneCut` anyway to settle (05 §6.2; ~20 ns per poll, inside the 170 ns cut term of
01 §14.17 item 1), so the gate adds no cross-CCD miss. Its only cost is that the lane's stream core
writes `LaneCut` after the `sfence` of its frame and not right after it reads the step: **`REP_ACK_GATE_NS` = 10 ns** (max, budget, 01 §14.2). The gate is normally already open, for
two reasons. Lanes pre-encode their PacketRecords in pass 1, so the record of `q` is in `R_pkt[l]`
before the cut core can publish `q`. And part B of the stream core's loop frames those records ahead of
any step, so the step that logs the cut finds them drained and its frame holds only the step.

A cut that covers `q` is logged by the next step, an Idle step if nothing else runs (05 §8.1),
and that frame triggers a flush (§4.5 rule 1).

**No exposure remains.** Acks, rejects and `BUSY` answers are in the log before the client sees
them, so §9.6 applies to them exactly as to fills: **an acked order is never lost** outside the
cases that also revert a fill. 04 needs no ack-revert note.

## 5. The data tier (`vyrn-data`)

### 5.1 Placement and sizing

The decision is one `vyrn-data` box per facility: `n_data` = 4 in BASE and 5 in CHAIN, where each
validator operator runs its own. The data tier is not a consensus participant. Its failures
affect liveness only (§5.7). Data boxes are separate from replica boxes, so a replica crash (which
uses up f) does not also cost a data home.

Each session has one **data home**, assigned at session open (04 owns the message, 10 owns the
policy, and the default is the client's nearest facility, balanced by expected rate). The client
sends copy 2 of every request packet to its data home's `REP_UDP_DATA` port.

| Per data box at peak (budget) | BASE (n_data 4; 4 voters + standby) | CHAIN (n_data 5; 5 validators + standby) |
|---|---|---|
| ingress from clients | 50 Gbps | 40 Gbps |
| egress (5 or 6 destinations) | 194 Gbps | 186 Gbps |
| RAM ring (`REP_DATA_RING_S` = 10 s) | 48 GB | 39 GB |
| Hardware | 1 socket, 32 cores, 2 × dual-port 100GbE COTS (ConnectX-6 Dx/7, ~97 Gbps TX per card), 256 GB | same |

**A data home is never in the active sequencer's facility.** If F1 held both the sequencer and a
session's data home, losing F1 would lose both copies of every packet the data box had not yet
forwarded (≤ `REP_DATA_BATCH_US` + one hop). Those packets become unavailable, and their fills
revert (§9.6 d): ~0.1 F1 losses/yr × 5 µs × 20M fills/s ≈ 10 fills/yr. So the default policy
homes each session in the nearest facility other than the sequencer's, and the F1 data box only
serves as a backup home. The rule holds in both modes (01 §14.16): in CHAIN each operator's
primary data box is in the operator's F2–F5 facility, never in F1 (09 §4.8). The cost is one more
metro hop on the data path than on the order path, ≤ 0.71 ms of data lag, which §6.6 and 09 §4.8
budget.

Egress means the box sends its share of packets to every voter and to the warm standby. The
active sequencer is not a destination: it has its own copy. When the standby is promoted, it
leaves the destination set, and the next standby joins it once it starts warming (§9.5).

### 5.2 Ingest pipeline

```
 RX queue (RSS by session) ─► parse header ─► MAC check ─► dedupe ─► full BLAKE3 ─► store ─► fan-out
   ~12 cores at peak          16 B            K_seq (BASE)  (session,   32 B kept    RAM ring   data frames
                                              K_com (CHAIN) pkt_seq)    pkt_hash=8   + index    to replicas
```

**RSS by session (reading, `vyrn-data`).** A data box runs `n` ingest shards, and every session
belongs to exactly one: shard = ⌊(`session` × 0x9E3779B9 mod 2^32) × n / 2^32⌋. Each shard owns its
sessions' keys, dedupe windows and a `1/n` share of the ring, so steps 1–5 share no state between
cores, and dedupe and `CopyConflict` stay exact because every copy of a `(session, pkt_seq)` meets
the same shard. The NIC cannot hash a UDP payload, so the box steers in software from bytes 0..4
of the packet (`session`); a packet too short to carry them is a parse failure. Fan-out order is
per shard: `data_seq` stays per box and destination (§5.4), so shards that share a destination
serialize their frames through one sender.

1. **Parse.** A packet is valid if `count ∈ 1..=10`, `len = 32 + 16·count`, `reserved = 0`, and
   `book` is a book this home serves. Anything else is dropped and counted.
2. **MAC.** In BASE, the data box holds `K_seq` (the operator holds all keys) and checks `tag_seq`.
   In CHAIN, it holds the operator's `K_com` and checks `tag_com` (09 owns key schedules). A failed
   MAC is dropped and reported to the sequencer's control core as `DataBadMac{session, pkt_seq}`.
   The data tier never closes a session. 01 §12.5 rules, and the sequencer applies them.
3. **Dedupe** by `(session, pkt_seq)`, with `hi` (the highest stored `pkt_seq`) and a 256-bit
   window below it per session. A new `pkt_seq` is stored. A repeat with an equal full hash is
   dropped (`flags.resend` packets land here). A repeat with a different full hash is **client
   equivocation**: the box stores both, emits `CopyConflict{session, pkt_seq, h1, h2}` with both
   packets as evidence, and keeps forwarding the first. A `pkt_seq` below the window is late.
4. **Hash.** The full BLAKE3-256 is taken over bytes `0..16+16n` with the tags excluded (01 §3).
   `pkt_hash` is its first 8 bytes.
5. **Store.** The bytes go into a RAM ring, indexed by a fixed open-addressed table keyed by
   `pkt_hash` that holds `(session, pkt_seq, ring offset)`. 8-byte collisions do occur at 100M/s
   (~3e-4 per 10 s window), so a lookup always matches `(session, pkt_seq)` too.
   **Data box layout (reading, `vyrn-data`):** the data box looks packets up by `(session,
   pkt_seq)` (dedupe, `DataFetch{session, pkt_seq}`), so its table's bucket is SipHash-2-4 of
   `(session u32, pkt_seq u32)` LE under a per-box secret that never leaves the box, and each
   entry stores `(session, pkt_seq, pkt_hash, ring offset)`. A lookup by hash matches all three
   of `session`, `pkt_seq` and `pkt_hash`. The table is fixed at load ≤ 0.5 and never
   allocates. A replica's join table (§5.4) may still key by `pkt_hash`.
6. **Fan-out.** The packet is appended to one data frame per destination replica (§5.3). A frame
   is sent when it reaches 9000 B or is `REP_DATA_BATCH_US` = 5 µs old.

### 5.3 Data frame

```
off size field
  0   2  magic 0x4450 ("PD")      2 1 version 1     3 1 kind (1 DATA, 2 DATA_HB, 3 FETCH_RESP)
  4   2  book                     6 2 epoch16       8 8 data_seq (per data box, per destination)
 16   1  src data box index      17 1 n_pkts       18 2 body_len     20 4 reserved
 24   …  n_pkts × { pkt_len u16, pkt bytes (pkt_len), pad to 2 } 
```

`data_seq` lets a replica detect loss from one data box. A gap is fetched by `DataFetch{from,
to}` from that box's RAM ring. A data box sends `DATA_HB` every 100 µs when idle. A replica that
hears nothing from a data box for `REP_DATA_SILENCE_MS` = 1 ms marks it down (§5.7).

### 5.4 The replica's data store

A replica keeps the same table as §5.2 step 5, filled from data frames. It also computes the full
hash of every received packet itself, on replica cores 50, 52–55 and 63 (§7.2). It does not trust a data
box's hash. If it did, a faulty data box could feed the same wrong bytes to every replica of both
clients, and the state roots would agree on a wrong state.

**Join.** For each decoded PacketRecord `r`, the replica looks up `r.pkt_hash` and matches
`(r.session, r.pkt_seq)`. The record is **resolved** when a payload with that key is present, its
8-byte hash equals `r.pkt_hash`, and its number of numbered messages (05 §3.1) equals `r.count`.
Advance records have no payload and are never joined. Until the HashRun arrives, the
record is matched on `(session, pkt_seq)` only and stays **unhashed**.

**Data RX.** The replica reads `DATA`, `DATA_HB` and `FETCH_RESP` frames from every data box:
- A data box numbers `data_seq` once per destination, across every book it serves. A frame of any
  book therefore moves that box's position and liveness, but only packets of the served book are
  stored.
- `DATA n` above the highest `data_seq` seen, `h`, means frames `h+1 ..= n−1` were lost. A
  `DATA_HB n` (its `data_seq` is the last `DATA` sent) means frames `h+1 ..= n` were lost.
- Each gap is fetched once, by `DataFetch{from, to}` RANGE requests no longer than the box
  accepts. A run the box no longer holds is fetched by key under §5.5.
- A `DATA` frame at or below `h` is a resend, and only stores its packets. `FETCH_RESP` carries
  no position.
- Every data box lists its destinations in the same order (the voters, then the warm standby,
  §5.1), so a replica's `dst` index is the same for every box.
- A stored packet has passed 01 §6.1 V1, the header half of V9, the served book and
  `pkt_seq ≥ 1`. The replica checks no tag and does not filter on `epoch16` (04 D3): the record's
  `pkt_hash` picks the variant, against the replica's own hash.
- The `REP_DATA_SILENCE_MS` clock of a box starts at its first frame.

**Retention.** A payload is **referenced** once a ready block's PacketRecord names its
`(session, pkt_seq)`, whether the payload arrived before or after; it then stays until that block's
release (after replay), and a released `SHED` record's variant stays `REP_SHED_KEEP_BLOCKS` = 128
more blocks for its retry. A payload no record has referenced (a packet the sequencer never
logged, or bytes a sender pushed unasked) is **unreferenced**:
- It expires once `REP_SHED_KEEP_BLOCKS` = 128 blocks have become final after it arrived:
  arrival stamps the replica's final height `f`, and the payload goes when `f + 128` is final.
- At most `REP_DATA_UNREF_MAX` = 65,536 are held. Storing one more evicts the oldest
  unreferenced payload first. 65,536 is the `vyrn-data` RAM ring's slot count, so the box still
  holds what the cap dropped and a later record fetches it under §5.5.
- Each eviction is counted, by cause (expired, capped). Referenced payloads never count toward the
  cap and are never evicted by it.
[Coordinator ruling for the expiry; the cap's size is a reading, `vyrn-replica` PR]

### 5.5 Fetching a missing packet

A record that stays unresolved for `REP_DATA_WAIT_US` = 300 µs after its ORDER frame triggers a
fetch, with these sources in order:

1. the session's data home: `DataFetch{session, pkt_seq}`
2. one peer replica in round-robin order: `PeerDataFetch`
3. the sequencer's control core (core 51): `SeqDataReq`, served from lane packet retention
   (`REP_SEQ_PKT_RETAIN_MS` = 50 ms, owned by 05) at ≤ `REP_SEQ_DATA_MAX_PPS` = 50k pkts/s

**Fetch request bytes (reading, `vyrn-data`).** `DataFetch` is a 32-byte request (`magic`
0x4650 "PF", version 1, kind 1 KEY `{session, pkt_seq}`, 2 RANGE `{dst, from, to}`, 3 BLOCK
`{height}`; layout and vectors in `crates/vyrn-data` docs and `tests/golden/vyrn_data_vectors`).
A data box with fetch keys accepts only the 40-byte authenticated form: those 32 bytes, then
`tag` u64 LE = SipHash-2-4(`K_fetch`, bytes 0..32), with one `K_fetch(e, i, d)` per requester,
derived per epoch from the roster's X25519 keys (08 §9.6) and keyed by the requester's `repl_addr`
IPv4, so a requester sends its fetches from that address (*reading*). Across an epoch boundary
the box holds the keys of both epochs (08 §4.6) and serves a fetch under either; moving to the
next pair drops the older epoch's keys (*reading*). It rate-limits each requester with a token bucket
(03 §1: "rate-limit by source address") and drops forged, unkeyed and over-rate fetches before
any work. Replies are not tagged (next paragraph).

Every fetched packet is checked like a pushed one. Source 3 is the only source of the bytes the
sequencer actually matched, so it settles every conflict (§5.6).

**Escalation (reading, semantics).** Each source gets `REP_DATA_WAIT_US` in turn: a record still
unresolved 300 µs after its ORDER frame is fetched from source 1, and each further 300 µs without
its payload moves to the next source (2, then 3, then 1 again), skipping any source the replica
has not configured. Source 2's peer turns round-robin across fetches.

**`PeerDataFetch` bytes (reading, wire; source 2).** The request is the same 32-byte KEY fetch
as `DataFetch` and `SeqDataReq`, sent to the peer's data port; the answer goes to the request's
source address. It is `FETCH_RESP` data frames like the sequencer's below, but with `src` = 0xFE,
carrying every variant the peer holds of the key, split over as many frames as they need; a miss
is one frame with no packets. A peer holds a key's variants in its join and, after it releases
them (§5.4), in a FIFO of its last 16,384 released payloads, so a slower peer can still fetch
them (reading, config). A replica answers at most `REP_SEQ_DATA_MAX_PPS` packets/s (a miss costs
one, 10 ms of tokens) and refuses RANGE and BLOCK fetches. Its key is
`K_fetch(e, i, VOTER_TARGET + j)` under the context `"vyrn      v1 peerfetch"` (08 §9.6), for
requester `i` and serving voter `j`; source 3's is `K_fetch(e, i, SEQ_TARGET + j)` for
`vyrn-seq` box `j`. A keyed replica serves only fetches that open under a key of a requester at
the source's IPv4; an unkeyed one serves the 32-byte form to its configured peers. A target
whose roster key is unusable holds no keys, so it is sent the 32-byte form (reading, DEV).

**`SeqDataReq` bytes (source 3).** The request is the data tier's 32-byte KEY fetch
(`vyrn-data` frame docs: magic `PF`, kind 1, `session u32, pkt_seq u32`), sent to the
sequencer's repair port.
- **Answer.** One `FETCH_RESP` data frame (§5.3) with:
  - `src` = 0xFF, a value no data box index takes;
  - `data_seq` = `session << 32 | pkt_seq`;
  - `book` and `epoch16` of the first variant;
  - every variant held under 05 §6.10, in arrival order.
- **Miss.** The same frame with no packets and `book`, `epoch16` 0.
- **Requester.** Only an address of a configured replica is answered.
- **Refused without an answer:** RANGE and BLOCK fetches, which only data boxes serve, and
  malformed requests.
- **Cost.** An answer takes one `REP_SEQ_DATA_MAX_PPS` token per packet it carries, and a miss
  takes one. Each packet also takes one `DAV_SESSION_REPAIR_PPS` token of its session; a miss
  takes no session token, so only sessions with a retained packet hold a bucket. Each bucket
  holds 10 ms of tokens, and at least four (the most variants one answer carries). A request that either bucket cannot cover gets no answer, and the
  replica asks again or moves on in the order above.
- **At the replica.** A replica takes a `FETCH_RESP` from any `src`, so this answer is stored
  like a data box's, and the join checks it by `pkt_hash` (§5.4). `DATA` and `DATA_HB` still need
  a configured data box index.

**Withheld copies (draft 0.3, 01 §14.19 C).** Source 3 serves one session at most
`DAV_SESSION_REPAIR_PPS` = 2,000 packets/s (DAV-2). A voter that resolves more than 16 of a
session's records from source 3 in 10 ms signs `DataMissing`; Q of them close the session with
`Reject DATA_MISSING` (DAV-1), and the leader may then mark its unrepaired packets unavailable
while the sequencer lives (DAV-3, extending §9.4). 13 §3–§5 gives the capacity analysis.

### 5.6 Mismatch between the client's two copies

The two copies of one packet can differ in three ways.

| Case | Detection | Action |
|---|---|---|
| 8-byte hashes differ | at the join, as soon as the HashRun arrives | Fetch the sequencer's copy (§5.5 source 3) and check it against `pkt_hash`. It is the canonical payload. Emit `CopyMismatch{session, pkt_seq, seq_hash, data_hash}`. The sequencer closes the session through a control op that 04 and 10 define, with the evidence attached. |
| 8-byte hashes match but `data_root` differs | at the vote check of the block (§6.4) | This is a deliberate 2^32 birthday collision, or a fault. Fetch the block's full-hash list from the sequencer's order hasher, core 50 (`HashListReq{height}`), compare it entry by entry, then fetch the sequencer's copy of each differing packet. Same evidence and session close. |
| `count` differs | at the join | Same as row 1. |

The vote for a block waits until each mismatch is settled (§6.4). This is the only data-tier event
that can make the vote wait on the sequencer. It happens once per misbehaving session, because the
session is closed. If the sequencer is dead and the canonical copy cannot be fetched, the packet
is **unavailable**. The seal proposal lists it, and replay excludes it (§9.4). The exclusion
semantics are the same as CHAIN's `excl` rule (09 owns them).

### 5.7 Data box failure

1. Replicas mark data box `d` down after `REP_DATA_SILENCE_MS` = 1 ms of silence, and gossip
   `DataDown{d}`. Q such messages make it effective.
2. Each session homed on `d` is reassigned to the backup data home `d' = next live box in facility
   order`. This is deterministic, so no message is needed to choose it.
3. Every live data box sends `DataRedirect{d → d', resend_from}` to the affected sessions' bound
   addresses. 04 owns the record. The data boxes know those addresses from the copies they have
   received. `resend_from` is per session: the lowest `pkt_seq` that no replica has resolved. The
   replicas compute it and send it to the data boxes.
4. Clients resend copy 2 from `resend_from` to `d'`. Clients keep sent request packets for
   `REP_CLIENT_RETAIN_MS` = 100 ms (04 DR4). The resends are the retained bytes of each
   transmission unchanged, not new copies with `flags.resend`, so each one's `PktHash` still matches
   the `PacketRecord` (04 DR3); dedupe drops anything already stored.

**`DataRedirect` bytes and address.** 04 §7.6 owns the record: its 24 bytes, the tag under the
session's `K_seq` (BASE) or `K_com` (CHAIN), and the client rules DR1–DR4. `down` and `to` are
positions in the session's `KeyBundle.data` list, so "facility order" in step 2 is that list's
order for the session (reading, 04 §7.6). It goes to the source address of the
session's copy with the highest `pkt_seq` and a valid MAC; a duplicate, late or out-of-order copy never moves
that address, so replayed bytes cannot steer a redirect. A box that never heard from a session
sends it nothing and counts it; another live box has its address. Vectors: V19 (04 §11) and
`tests/golden/vyrn_data_vectors`.

Effect: fills and acks are unaffected. Blocks that reference the affected sessions cannot be voted
until their data arrives. Finality stalls for those blocks for ≤ 1 + 0.5 + 1 + 0.5 = **3 ms**
(budget) and then catches up (§6.7).

## 6. Blocks and consensus

### 6.1 Block cut and roots

- **Cut.** Core 4 asks for block `h`'s close when its PTP-disciplined clock passes
  `t_h = epoch_start + h_local × BLOCK_NS`; the BBO core places the mark entry after its current
  step, and each stream core appends its `BlockMark(h)` there (§3.9). The gate does not hold a mark
  back. Block `h`'s ORDER bytes on substream H are all its ORDER section bytes after
  `BlockMark(h−1)`, up to and including `BlockMark(h)`, in `frame_seq` order. The first block of a
  tenure starts after `TenureStart`.
- **`order_root(h)`** = `BLAKE3(order_root_A(h) ‖ order_root_B(h))`, each the `BLAKE3` of that
  substream's ORDER section bytes of `h`, with the frame headers, HASH frames and HEADER frames
  excluded. A replica computes it from what it decoded. Byte identity (INV-REP-3) makes it equal
  at every replica. With one stream core (CONSUMER, AWS), `order_root_B` is `BLAKE3` of nothing.
- **`data_root(h)`** = `BLAKE3(data_root_A(h) ‖ data_root_B(h))`, each the `BLAKE3` of the
  concatenated full 32-byte hashes of the packets of every PacketRecord of that substream in
  block `h`, in O-order, except Advance and `SHED` records (§3.6; 05 §18 Q17). The data join
  (§5.4) and DAV fetches (§5.5) skip `SHED` records for the same reason. O-order is the order of records in a substream's ORDER bytes.
- **`first_step`, `last_step`** are the first and last StepIds in the block. An empty block has
  `last_step = first_step − 1`.
- **Blocks with no traffic.** Core 4 still asks for their close, so heights advance at 1 kHz and
  `BlockMark` doubles as a liveness beat. An empty block costs one ~200 B HEADER frame.

### 6.2 Signing seq_sig on core 4

Core 4 signs, so that one core owns the key and the order of headers. Ed25519 signing (RFC 8032,
deterministic nonce) costs
~10 µs of CPU (budget at 5 GHz, **B-REP-5**). Run in one piece, it would stall the gate for 10 µs.
The decision is to make the signer a resumable state machine:

```rust
enum Signer { Idle, HashNonce(Sha512State), ScalarMul(CombState, u8 /*window*/), HashChallenge(Sha512State), Done(Sig) }
// background_slice() advances it by one step of ≤ REP_SIGN_SLICE_NS = 50 ns:
// one SHA-512 block, or one fixed-base comb addition (~40 ns), then returns to the main loop.
```

About 200 slices finish one signature. Core 4 spends ≥ 50% of its time outside the hot loop (1 −
`REP_STREAM_MAX_LOAD`), so a signature completes ≤ 35 µs after the roots arrive. The roots come ≤ 10
µs after `BlockMark`, because core 50 lags by one frame batch on each substream. The HEADER frame therefore leaves ≤
`REP_SEAL_US` = 100 µs (max, budget) after the block closes. The signing key stays in core 4's
memory only. It is loaded from the secret store at tenure start and is never written to disk (06
owns the secret store).

**Scheme 1 (01 §14.20).** Core 4 keeps the sliced Ed25519 part unchanged. When the roots are
ready it also pushes the 126 signed bytes onto an SPSC ring (`vyrn-cut`) read by the four PQ
cores 52–55 (01 §10), about 20 ns of core 4's time. Each PQ core runs one hedged ML-DSA-44 attempt
with its own 32 random bytes; the first to finish writes the 2,420-byte part into a slot, and the
others abandon theirs. Core 4 posts the HEADER_PQ DMA descriptor when it polls the slot (about
5 ns). The ML-DSA half of the seq key lives on the PQ cores only, with the same storage rule.
Measured: the ML-DSA-44 sign at four attempts is 45 µs p50, 111 µs p99 and ≤ 367 µs at 10⁻⁹
(model, 01 §14.20 B). A PQ core is busy ≤ 10% at 1 kHz.

### 6.3 Simplex mapping

| Item | VYRN use (`commonware-consensus` v2026.10.0, module `simplex`) |
|---|---|
| Participants | The `n` voters of the active home, in `REP_Membership.voters` order: BASE R1–R4, CHAIN the 5 validators. `vyrn-seq`, the standby and the spares are **not** participants (01 §14.4). |
| Signing scheme | `simplex::scheme::ed25519`, namespace `b"vyrn-v1"`. |
| Round | `(Epoch, View)`. Epoch = the VYRN epoch. One Simplex instance per (home, epoch). |
| Elector | Plain `RoundRobin` over the voters: the leader of `(epoch, view)` is `REP_Membership.voters[(epoch + view) mod n]` (u64 arithmetic, wrapping, no shuffle), Commonware `RoundRobin`'s formula over the membership order instead of the sorted keys. No index is skipped, and a failover does not change it. With f = 1, a faulty voter leads one view in n, never two in a row. |
| Observers | The sequencer (its finality listener on core 51) and the standby receive every finalize vote and every finalization certificate (§6.8). They sign nothing. |
| Δ (timeouts) | `REP_DELTA_MS` = 1 ms. Leader timeout `t_l = 2Δ` = 2 ms. Advance timeout `t_a = 3Δ` = 3 ms. The skip policy for an inactive leader is enabled. |
| `Automaton::propose` | §6.4 (leader side) |
| `Automaton::verify` | §6.4 (voter side). This gates the notarize vote. |
| certify hook | Returns the result of `verify` for the same payload. It adds no check of its own. |
| `Relay` | No-op. Payloads are already at every participant through frames and data frames. |
| Reporter (activity) | Feeds finalizations to `vyrn-log` (§8), and conflict evidence (`ConflictingNotarize`, `ConflictingFinalize`, `NullifyFinalize`) to §10. |
| Not used | `marshal` (block sync). Frames and repair do that job. |

**Payload.** A Simplex payload is a digest of a `REP_Proposal`:

```
REP_Proposal (encoded LE, 1 + 4 + 8 + 8 + 32 + 32 = 85 bytes)
  kind         u8      0 = Headers, 1 = Seal (§9.4)
  epoch        u32
  first_height u64
  last_height  u64     last_height − first_height < REP_MAX_HDRS_PER_PROPOSAL (16)
  last_hash    Hash    header_hash(last_height); prev links commit to the whole range
  excl_root    Hash    BASE: [0; 32]. CHAIN: BLAKE3 over sorted (session, pkt_seq) excluded in the range (09)
digest = BLAKE3("vyrn      v1 proposal" ‖ REP_Proposal bytes)
```

The parent rule is that `first_height` equals the parent proposal's `last_height + 1`. Genesis of
an epoch is the HandoffRecord's `last_height` (08). An epoch with no HandoffRecord before it (epoch 0
of a fresh deployment) has no certified block to chain to: its genesis is the tenure's height-0
header (`prev = [0; 32]`), once the voter's order core accepts it, and the first proposal starts
at height 1. Height 0 is final by definition, at the voters and at the sequencer's listener.
[Reading, `vyrn-validator`]

**Leader `propose`.** The leader takes every contiguous header after the parent's `last_height`
that it holds with a valid `seq_sig`, up to 16 of them. It waits for at least one, and for its own
`verify` of that range to pass. It then returns the digest. Usually the range has 1 header,
because views and blocks both run at ~1 kHz. After a nullified view the range catches up.

**Under scheme 1 the range is fixed before `verify` (01 §14.20 PQ-8, decided).** The leader fixes
the range when it enters the view, or when the first new header arrives if it holds none then:
every contiguous header after the parent's `last_height` that it holds at that moment with a valid
Ed25519 part of `seq_sig`, up to 16. It sends every voter
`RangeFix { epoch, view, parent_view, first_height, last_height, last_hash }`, signed with the
Ed25519 half of its vote key under context `"vyrn      v1 rangefix"` (≤ 17 µs), and then runs
`verify` on exactly that range. An honest leader's proposal in the view is that range or
nothing: a header that arrives after the fix waits for the next view. **`RangeFix` is a hint, never
a filter:** a voter never rejects or withholds a vote because a proposal differs from a
`RangeFix`. It judges the proposal by §6.4 alone, and a mismatch only means it signs the actual
proposal late (§6.5a). So a forged `RangeFix` cannot block an honest proposal; at worst it costs a
voter one late signature. Why fix the range then: voters and leader then sign the one notarize
the view can carry, starting ≥ 0.76 ms before the proposal can arrive, so in BASE no signature is
made after it (§6.6). In CHAIN the payload also commits to `excl_root`, which the leader knows only
after its `verify`; §6.5a gives that cost. Why not a clock rule such as "every header closed `REP_HOP_MAX_MS` before the view
started": Simplex views have no start time that all voters agree on. `RangeFix` is not a vote: it
is never counted, persisted or slashed, and a forged or lost one costs only one signature made
late. Its Ed25519-only signature is therefore enough: a quantum attacker who forges `RangeFix`es
every view only returns voters to signing after the proposal (+0.75 ms per view, outside the fault
model), and cannot stop finality. [Likely]

### 6.4 The vote rule (when a replica votes)

**INV-REP-4.** A voter returns `verify(ctx, digest) = true` only when all of these hold for
the proposal `P` behind `digest`:

1. **Headers.** It holds headers `P.first_height ..= P.last_height`. Each has a valid `seq_sig`
   under the current tenure's `seq_key`, the `prev` links chain, `header_hash(last) = P.last_hash`,
   and the steps are contiguous: `first_step(h+1) = last_step(h) + 1`.
2. **Order bytes.** It holds every ORDER frame through `BlockMark(P.last_height)` with no gap. Its
   decoder accepted them with no error (§3.12), and its `order_root(h)` equals each header's.
3. **Payloads.** Every PacketRecord in the range is resolved (§5.4). Every mismatch is settled
   (§5.6). Its own `data_root(h)` equals each header's.
4. **CHAIN tags.** Every packet in the range has a `tag_com` verdict, and the set that fails gives
   `excl_root = P.excl_root`. 09 owns the tag rules, the key schedule and the exclusion
   semantics. 07 owns this timing: the check is done by the replay lane cores as data arrives
   (§7.2), before any replay of the block.
5. **Fences.** No header in the range is above an `INV-FENCE` boundary (08) or after a seal of the
   tenure (§9.4). No `REP_A_DIVERGE` is active, and the state-root gate holds (§7.4).

`verify` stays pending while items 1–4 are incomplete. It returns false at once on a
contradiction, such as a root mismatch after repair or a bad signature. It also returns false
after `REP_VERIFY_WAIT_MS` = 4 ms pending. A false result leads to `nullify`. **A vote never waits
for replay or for the state root of the block it votes on.** Replay only gates the state-root
certificates, and those trail by up to 5000 blocks.

Cost per block at peak, on top of continuous work: finishing two BLAKE3 hashes and up to 16
Ed25519 verifies (~40 µs each budget, batched). That is ≤ 0.1 ms (max, budget).

Under scheme 1, item 1 also needs the HEADER_PQ part of each header, and checks it under the ML-DSA
half of `seq_key` (`PQ_VERIFY_US` = 35 µs each, budget; 30 µs measured). A header usually
verifies as its HEADER_PQ frame arrives, in parallel with the data join of items 2–3, so the
pending `verify` gains nothing. Each header is checked once, when its HEADER_PQ frame arrives,
and the verdict is cached. A catch-up proposal of 16 headers after a nullified view therefore
re-reads 16 cached verdicts and verifies nothing new.

### 6.5 Notarization, finalization, certificates

Simplex's own messages carry `notarize(c, v)`, `nullify(v)` and `finalize(c, v)`. A notarization
is `Q` notarize votes, which lets the next view start. A finalization is `Q` finalize votes
(`INV-QUORUM`). It makes every header in the proposal final, and every ancestor with it.

**VYRN finality certificate** (exported by `vyrn-consensus`, consumed by 08, 09, 10 and
clients):

```
REP_FinalityCert
  off size
    0   4  epoch       u32
    4   8  view        u64
   12   8  parent_view u64
   20  85  proposal    REP_Proposal
  105   1  count       u8          ≥ Q_BASE or Q_CHAIN
  106  65·count entries  { index u8, sig [u8; 64] }   ascending index, distinct (01 §4)
  106+65·count  seal_ext  REP_SealExt (§9.4), present exactly when proposal.kind = 1:
                22 + 8·n_unavail bytes
```

A kind-1 (seal) certificate carries its `REP_SealExt` after the entries, and its signatures
cover the seal digest (§9.4), so anyone holding the certificate verifies it on its own with
`REP_Membership`. A kind-0 certificate ends after its entries; a decoder refuses trailing bytes,
and refuses a kind-1 certificate without a complete `REP_SealExt`. A seal certificate is
106 + 65·count + 22 + 8·n_unavail B under scheme 0 (BASE, Q = 3, no unavailable packets: 323 B).

Each `sig` is the participant's Ed25519 finalize signature as produced by
`simplex::scheme::ed25519` over `Proposal{ round: (epoch, view), parent: parent_view, payload:
digest }` under namespace `b"vyrn-v1"`. The exact signed bytes are those of the pinned
`commonware-consensus` version. `vyrn-consensus` exports `verify_finality_cert(&cert, &membership)
-> Result<(), CertErr>`. No other crate reimplements the check. A Vx verifier links that function
through FFI. A certificate is about 0.37 KB (Q = 4).

**Sizes by scheme** (header 105 B plus `count` × (1 + signature)):

| Certificate | Scheme 0 | Scheme 1 (hybrid, 2,484 B signatures) | Growth |
|---|---|---|---|
| `REP_FinalityCert`, BASE (Q = 3) | 301 B | 7,561 B | ×25 |
| `REP_FinalityCert`, CHAIN (Q = 4) | 366 B | 10,046 B | ×27 |
| `REP_FinalityCert`, all 5 CHAIN votes | 431 B | 12,531 B | ×29 |
| `REP_RootCert` (same layout, 40 B in place of the 85 B proposal), Q = 4 | 321 B | 10,001 B | ×31 |

At 1,000 certificates per second per book a voter sends each certificate to the sequencer and
the standby: 2 × 10 MB/s ≈ 0.16 Gbps per voter in CHAIN, still inside the < 0.5 Gbps consensus
budget of §3.13 with the votes (2.5 KB each, 3 kinds, ~1 kHz, n − 1 peers ≈ 0.24 Gbps).
[Likely: budget, from the sizes above]

### 6.5a Speculative vote signing (scheme 1)

An ML-DSA-44 signature is ≤ 750 µs at `PQ_HEDGE` = 2 on a voter, nearly a metro hop. Signed after
the event that triggers each vote, three votes per view would add ~2.2 ms to finality. So a voter
signs before it knows it will send:

- **Notarize.** A voter signs the notarize of the range in the leader's `RangeFix` (§6.3) on its
  two PQ cores (replica cores 0 and 63, §7.2), in parallel with its own `verify`. In BASE it starts
  when the `RangeFix` arrives, since `excl_root` is zero. In CHAIN it starts when its own `verify`
  completes, because only then does it know `excl_root`; every honest member computes the same one
  (`INV-CHN-EXCL`, 09 §17.4). It sends the vote when the proposal passes §6.4 and equals what it
  signed. If the proposal differs, it signs the actual proposal late and sends that; it never
  rejects a proposal for differing from a `RangeFix`.
- **The leader** signs its own notarize (its proposal): in BASE from the moment it sends `RangeFix`,
  in parallel with its `verify`; in CHAIN after its `verify`, because the proposal carries
  `excl_root`. In CHAIN the leader therefore proposes ≤ `PQ_SIGN_MAX_US` = 0.75 ms after its
  `verify`, which delays hop 2 by that much; a voter's CHAIN signature (started at its own
  `verify`) is still done before the delayed proposal can arrive. 09 §4.8 carries the 0.75 ms.
  The owner accepted the resulting CHAIN margin (PQ-9, 01 §14.20). Whether the post-verify
  signature can push an honest CHAIN proposal past `t_l` is open question PQ-11.
- **In BASE, no signature is made after the proposal in the fault-free case.** At the maximum (§6.6) the
  `RangeFix` leaves the leader ≤ 0.05 ms after hop 1 and reaches every voter ≤ 0.85 ms after it,
  so each notarize signature is done ≤ 1.60 ms after hop 1. The proposal cannot leave before the
  leader's `verify` (data lag 0.71 + completion 0.10) and arrives ≤ 1.61 ms after hop 1. The
  leader's own signature (≤ 0.80 ms) is done before its `verify` (≤ 0.81 ms). Finalize and nullify
  have content fixed when signing starts. A lost or forged `RangeFix` costs one voter signature
  after the proposal, ≤ 0.75 ms, and counts as the one fault f. [Likely: from the 07 §6.6 budgets and
  the measured `PQ_SIGN_MAX_US`; B-PQ-2 measures it]
- **Finalize.** A voter starts the finalize signature when it sends its notarize, in parallel with
  hop 3. It sends it only if Simplex would (a notarization seen and no nullify sent).
- **Nullify** is signed when its timer starts, `t_l` before it can be sent.
- **Safety.** Signing is not voting: an unsent signature is never stored, logged or sent, and is
  zeroed after the view. The persisted high-water mark of 09 §2.5 is written before **sending**,
  as today. A crash between signing and sending leaks nothing. [Certain: the one-vote rule counts
  sent votes] The extra CPU is at most one wasted signature per view, when a view nullifies after
  its `RangeFix`.
- **Mechanism (PQ-3, decided).** Simplex signs through `commonware-cryptography`'s
  `certificate::Scheme` trait. VYRN's hybrid scheme implements it in `vyrn-crypto`, so no fork or
  upstream patch is needed. Simplex's voter calls the trait's synchronous `sign(&self, subject)`
  only when it decides to send a vote. The scheme keeps a cache of the signatures the PQ cores
  started above, keyed by the subject's encoding (round, vote kind, proposal digest), and returns
  the cached signature on a hit. On a miss (a proposal that differs from its `RangeFix`), it signs
  on the PQ cores and blocks the voter task until the signature is done, ≤ `PQ_SIGN_MAX_US`; that
  is the late signature the one-fault budget already counts. The cache holds the current view only
  and is zeroed with it (Safety, above). [Likely: from `commonware-cryptography` and
  `commonware-consensus` 2026.10.0's sources; B-PQ-2 confirms it in `vyrn-sim`]

A **fill is final** when the block holding its step is final. The finality event is the moment
the local voter has `Q` finalize votes. 02 owns where that is measured. Finality is a different
fact from durability, and §6.9 keeps them apart.

### 6.6 Finality latency

The fill lands uniformly inside a block. The hop count is four: the header goes from the
sequencer to every participant, the leader proposes, everyone votes notarize, and everyone votes
finalize. Simplex's "3 network hops to finality" counts from the proposal. The header hop comes
before it.

`FINALITY_MAX_MS` = 10 is a **maximum** for every accepted order while the metro network meets
its delay bound (01 §14.0 fact 3). The bound is `REP_HOP_MAX_MS` = 0.8 ms one-way. A box whose
links break it counts as the one fault f.

| Stage | Typical (ms) | Max (ms, budget) | Notes |
|---|---|---|---|
| Fill → block close | 0.50 | 1.00 | uniform in a 1 ms block |
| Seal: roots, seq_sig, HEADER out | 0.03 | 0.10 | §6.2; under scheme 1 the HEADER_PQ part follows ≤ 0.40 later and is checked inside the data-lag row, which already allows 0.71 beyond hop 1 |
| Hop 1: HEADER → leader and voters | 0.50 | 0.80 | metro one-way, ~0.5 ms as DESIGN §5 assumes |
| Data lag beyond the order path | 0.00 | 0.71 | the data home is in another facility (§5.1): client → data box → replica is two metro hops, client → seq → replica one; less the seal |
| One frame repair | 0.00 | 0.39 | cross-metro, ≤ 0.60 (§4.10); it runs in parallel with the data lag, and `verify` waits for the later, so the pair costs ≤ 0.71 and this row is 0.39 of reserve |
| `verify` completion | 0.02 | 0.10 | §6.4 |
| Hop 2: leader's notarize (the proposal) | 0.50 | 0.80 | |
| Hop 3: notarize votes; certify; send finalize | 0.51 | 0.85 | scheme 1: the notarize is signed from the leader's `RangeFix`, before the proposal arrives (§6.3, §6.5a) |
| Hop 4: finalize votes → Q at each voter | 0.50 | 0.80 | |
| Vote signature checks | 0.03 (0.08 scheme 1) | 0.10 (0.15 scheme 1) | scheme 1: Ed25519 parts batched on core 4, ML-DSA parts at 35 µs each on a PQ core, in parallel |
| **Total, no fault** | **2.59** (2.69 scheme 1) | **5.65** (5.70 scheme 1) | |
| One fault (f = 1) | | +3.00 | the larger of a nullified view (`t_l` 2 ms + 1 hop ≈ 2.8) and a data-box stall (§5.7, 3.0) |
| **Total, one fault** | | **8.65** (8.70 scheme 1) | ≤ `FINALITY_MAX_MS` = 10; reserve 1.35 (1.30 scheme 1). Under scheme 1 a lost `RangeFix` (+0.75) is the one fault in place of the 3.00 row, so it stays inside this total |
| Sequencer fault | | ≤ 9.0 | the seal finalizes the tail ≤ 7.85 ms after the last frame (§9.7) |

A fill at the end of its block sees ~3.1 ms typical, which is DESIGN §5's "~3 ms". In a single
facility (hops ~10 µs) the floor is ~1.1 ms. Under f = 1 two failed views in a row cannot happen:
the elector is round-robin over the voters and the sequencer is not one of them, so a faulty
voter leads one view in n. A Byzantine sequencer that stalls is deposed, and the orders it
delayed are final ≤ `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` (01 §14.0 fact 3). Beyond the fault
model, the finality gate halts the book (§6.8). Benchmark **B-REP-1** measures every fill's
finality with the voters in 4 real facilities.

### 6.7 Pipelining and backlog

- Views advance at notarization (~2 hops ≈ 1 ms), and blocks arrive at 1 kHz. A view whose leader
  has no new header waits up to `t_l`, then nullifies. Normally the header arrives first.
- When verification is late (a data box failure, a repair), headers queue. The next proposal
  covers up to 16 of them. A backlog of `B` blocks clears in about `B/16` views. A 3 ms stall
  clears within ~2 views.
- A voter that has notarized view `v` may vote in `v+1` before `v` is final. Simplex
  finalizes `v` and `v+1` independently, so heights become final in order: a final proposal makes
  its ancestors final.

### 6.8 The finality gate (both modes)

`FIN_GATE_BLOCKS` = 8 (01 §14.9) applies in BASE and in CHAIN. **INV-REP-10:** the sequencer
never releases a response while more than 8 **closed** blocks are not final at the sequencer:
block `h + 9` opens only when block `h` is final. 09 §4.6 (`INV-CHN-TXGATE`) uses the same count.

- **Voters → sequencer.** Every voter sends its finalize vote to the sequencer's and the
  standby's `REP_UDP_CTRL` as well as to the other voters (09 §4.6), and later the
  `REP_FinalityCert`. On `REP_UDP_CTRL` a finalize vote is a **`REP_FinalizeVote`**: a
  `REP_FinalityCert` (§6.5) with `count = 1`, so one decoder and one signed message serve both.
  It is 106 + 65 = 171 B under scheme 0, and 106 + 1 + 2,484 = 2,591 B under scheme 1. The
  finality listener, a thread of control on core 51 (01 §10), batch-verifies the votes (≤ 4 ×
  ~40 µs per block at ≤ 1 kHz, ≤ 16% of core 51; under scheme 1 the ML-DSA parts, 4 × 35 µs, run in parallel on the sequencer's core 63, ≤ 14% of it) and stores `final_height` once
  it holds Q valid votes for a proposal. So the sequencer learns finality at hop 4, like the
  voters, not one hop later. No single voter can forge it.
- **Core 4** checks at every flush: `lag = closed_height − final_height`. If `lag >
  FIN_GATE_BLOCKS`, it puts `HaltReq` on the BBO control ring. The BBO core emits
  `Control(Halt)` as its next step (≤ 1 µs). From that step's cut on, every lane answers new ops
  `BOOK_HALTED`. Those rejects are logged and gated like any response, so replay reproduces them
  (`INV-DET`). Frames, blocks and heartbeats keep flowing on both substreams, so finality can catch
  up.
- **Resume.** `Control(Resume)` at `lag ≤ REP_GATE_RESUME_BLOCKS` = 4; after > 1000 ms, via a
  reopening auction (08).
  Until the 08 reopening auction is wired, a resume after a halt of more than 1000 ms also
  goes straight to continuous trading, and the sequencer logs it (reading, **semantics**;
  DEV only).
- **It never trips within f = 1.** Block `h` is final at every voter and at the sequencer ≤ 7.65 ms
  after it closes (§6.6, signature checks included). `h + 8` closes 8 ms after `h` closes, so ≤ 8
  closed blocks are open (0.35 ms spare). Under scheme 1 the bound is 7.70 ms after close (0.30 ms
  spare), so `FIN_GATE_BLOCKS` stays 8 (01 §14.20 D). In CHAIN the bound is 7.11 ms after close (09 §4.8).
- **What it bounds.** Outside the fault model (no Q, a slow metro), at most ~9 ms of fills are
  released unfinal before the halt, none reverted; they finalize when Q returns. Draft 0.1's
  100 ms halt (a 10 ms escape) is removed.

### 6.9 Durability and finality: two separate attestations

01 §14.13 item 3 fixes the order: volatile execution (the 1 µs `Fill` or `Ack`) → **durability**
→ **finality** → settlement (CHAIN, 09). 07 defines the middle two. They are never merged into one
"confirmed" flag in any API, the drop copy or market data.

| Attestation | Fact | Evidence | Who can check it |
|---|---|---|---|
| `DUR_PATHS` | the op's records, and the step that covers it, were written to both replication paths | INV-FRAME-FIRST and INV-REP-11: implied by the response itself | the client, from receiving the response |
| `DUR_QUORUM` | Q voters hold the frame contiguously | `REP_DurableMark { epoch, tenure, step, height }`: core 4 raises it when Q voters' `RepAck.contiguous_frame_seq` cover, on both substreams, the frames up to `need_A(step)` and `need_B(step)` | anyone who trusts the sequencer's report; voters' acks are not signed |
| `FINAL` | the block holding the step is final | `REP_FinalityCert` (§6.5), self-verifying | anyone with `REP_Membership` |

- **Clients.** `DUR_PATHS` is the response itself. `DUR_QUORUM` and `FINAL` arrive as two
  separate unsolicited watermark records from control on core 51 (`Durable` per ≤ 1 ms, `Final` per
  finalization, each with `StepId` and height; codes requested from 01).
- **Drop copy and market data (10).** Every fill and ack carries its `StepId` and height. Two
  separate streams follow it: `durable_step` (from `REP_DurableMark`) and `final_height` with the
  certificate. A fill record shows three separate fields: executed, durable, final. A replay of
  the drop copy never infers one from another.
- **Times.** `DUR_PATHS` with the response (≤ 1 µs); `DUR_QUORUM` ~0.6 ms; `FINAL` ≤ 10 ms (§6.6).

## 7. Determinism and replay

### 7.1 Replay mode

`vyrn-engine` in replay mode is the live engine with two substitutions (01 §11.6). Decoded
PacketRecords and their resolved payloads replace the NIC, and `StepRecord.cut` replaces the cut
core. 07 delivers the following to the engine:

| Input | Order guarantee from 07 | Consumer |
|---|---|---|
| `(PacketRecord, payload bytes)` for lane `l` | increasing `first_lane_seq`, gapless except for `LSEQ_EXC` | replay lane `l` |
| `StepRecord` | increasing `StepId`, gapless | replay BBO core |
| `BlockMark(h)` with `lane_bounds` | after every record of block `h` | replay driver (block boundary, root heights) |
| `excl` set of the proposal (CHAIN, unavailable packets) | before the block's first record is replayed | replay lane (the packet becomes a no-op; 09 owns semantics) |

The schedule is owned by 05. It must respect two dependencies:

- Lane `l` processes record `p` only after the replay BBO core has emitted every fill event of
  steps `≤ p.fills_applied`.
- The BBO core executes step `s` only after every lane `l` has applied its ops `≤ cut_s[l]`.

**Canonical merge order (`REP_MERGE`).** A block's inputs reach the engine as each lane's
records in O-order (§3.6) and the merged steps in StepId order (§3.8). Every replica merges them
into one sequence by this rule, so the Rust and Vx clients run the same schedule:

1. A lane record `r` of lane `l` is *due at* `f(r)`: its `fills_applied`, raised to the largest
   `fills_applied` of the `MID` Advance records (§3.6: `h` bit 4 on an Advance record) that
   follow it in the same lane's O-order, up to
   the lane's next PacketRecord or non-`MID` Advance record (05 §6.2). Those `MID` records, and
   any lane record of the same packet between them (such as a route record), are replayed with
   `r`, as one lane call.
2. Before step `s`, every lane in increasing lane id replays, in O-order, each of its remaining
   records with `f(r) < s`. Then step `s` is replayed.
3. After the block's last step, every lane in increasing lane id replays its remaining records
   with `f(r)` at most the last step, in O-order, and stops at the first record with `f(r)`
   greater than the last step. That record and every later record of its lane, with their route
   records, **carry** into the next block, where they come before the next block's records. A
   packet's routes are its route records (§3.6), which travel with it, so no record waits for a
   later block's steps. A record carried past a cut that covers one of its ops is
   `REP_E_ORDER`.

`REP_MERGE` respects both dependencies above: a lane reads a step's fill events only after the
step, and a step's cut covers only ops that its lane applied before the step was published, so
their records were due before it. It is not the live interleaving. The live engine may run a lane
further ahead or behind. The outputs are the same because of 05 §9, where a step's outcome depends
only on its logged cut and source and a lane's only on its records and the fill events of
`≤ f(r)`. A live sequencer's own journal can be checked against this order by replaying both and
comparing their outputs. One case needs 05's op-level scheduler (05 §10) and is not covered by
`REP_MERGE`: a packet whose `MID` boundary at step `f` follows an op of the same packet that
`cut_f` already covers. A lane call cannot stop mid-packet for a step, so a replica rejects such a
record with `REP_E_ORDER` until 05 defines a split lane call.

**Snapshot history (05 §6.5).** Replay keeps the snapshot of each version the replayed BBO
publishes, in a ring of `REPLAY_SNAP_HIST` = `ENG_SNAP_HIST` = 4096 versions, and
`LaneCut` gives each replay lane `base`, the version of its `fills_applied` step. Before a packet
record, the lane restores version `v = base + snap_lag` and classifies the packet against it. The
record is *due* (item 2 above) only once `v` is published as well as once `f(r) < s`. A lane's
snapshot never moves back, so a later record of the lane never needs an older version than an
earlier one, and the wait never blocks another lane's record. A `v` that the ring no longer
holds (more than 4096 versions older than the newest when the record is due) is a divergence
(`Why::NoSnapshot` in `vyrn-engine`). An honest log never names one. Without a `MID`, a record is
replayed right after the later of its `fills_applied` step and the step that published `v`, and no
later version exists then. A `MID` raises the due step, and the live lane takes a `MID` only
while that step's version is within `W` of the packet's snapshot. The lag itself stays within
`W = min(u16::MAX, REPLAY_SNAP_HIST − 1)` (05 §6.5 rule 3; §3.6).

**Fields replay derives.** 07's `StepRecord` carries the kind, the source with its `CROSS`
route bit (§3.8), the cut and the kind payload; the lane's route records (§3.6) carry the route
of each op it classified, forwarded or rejected. Everything else in 05's `StepEntry` is an output of the replayed step, not an input:
`n_tx`, `n_fills`, `fill_lanes`, the half-cut publication ids `pub_a`/`pub_b`, and the `CONT`
flag. The replay BBO core knows whether a continuation is pending, and when it is, the next step
must be that continuation (05 §8.5, §8.6). The `Rescan` band is the kind payload (§3.8):
`band_lo` u32 LE, then `band_hi` u32 LE, so `plen = 8`. `plen = 0` means all ticks (05 §10, the
superset corollary of Lemma 9.7). A continuation's band is not read, because the first step of
the sweep fixed it.

The live engine classifies an op against a snapshot version. Replay does not need that version:
the snapshot is only a routing hint (`INV-ENG-1`, 01 §14.11), so draft 0.1's `SNAP` bit is gone.

Replay outputs are every response record (with `resp_seq`), every fill event, the per-lane and BBO
state, and the root at root heights (§7.4). `INV-DET` makes them identical at every replica of
either client. `vyrn-sim` checks this on every CI run with the Rust engine, `vyrn-vx-client` and
`vyrn-vx-oracle` (benchmark B4).

### 7.2 Replica core map (REF box, Rust client)

| Cores | Use |
|---|---|
| 0 | isolated spare (TX-C after a promotion, §9.5); under scheme 1 also PQ core 1 of a voter: ML-DSA vote signing and the ML-DSA half of vote and header checks (§6.5a) |
| 1 | order RX on the 2 replication ports, both substreams: dedupe by `(stream, frame_seq)`, hole detection, NACK, `RepAck` |
| 2 | replay BBO core (the same core as live, so the standby's promotion keeps it in place) |
| 3 | order decoder for both substreams, step merge by StepId (§3.8), structural checks, `order_root`, data join, `data_root` |
| 4 | voter: Simplex, `aggregation` (state roots), `commonware-p2p`, `FinalityCert` push (§6.8) |
| 5 | control, failover coordinator, metrics |
| 6 | peer repair server, block server for the facility's archive node (§8.4, §12); on R3 also the recovery service's resend server (§8.5) |
| 7 | storage writer (`io_uring`, `O_DIRECT`), snapshot serializer |
| 8–49 | replay lanes 0–41, one to one with the live map; in CHAIN also the `tag_com` pass (§6.4 item 4) |
| 50, 52–55, 63 | data RX from the 2 data ports, data index, full BLAKE3, mismatch checks. Under scheme 1 a voter moves core 63 to PQ core 2 and runs data RX on 5 cores (open question 13). After a promotion the standby no longer receives data frames, so 52–55 become the sequencer's PQ signing cores (01 §10) and 63 its listener's ML-DSA core |
| 51 | OS, IRQs, housekeeping (06 `HK`, the one non-isolated core on every REF box) |
| 56–62 | replay lanes 42–48, the pool, one to one with the live map; they apply `AcctTake` records in log order (§3.6) |

**Ports.** Ports 0–1 are data ports on the facility fabric: data frames (78% each at peak),
`commonware-p2p`, the archive feed and recovery-service resends. Ports 2–3 are replication
paths A and B (27% each, both substreams): ORDER, HASH and HEADER frames, acks, NACKs, peer repair and catch-up.

A Vx replica runs the same Rust shell (network, data, consensus, storage, §11). Its replay
engine is `vyrn-vx-client` on cores 2, 8–49 and 56–62. The warm standby runs this map without core 4's
voting and without core 7's journal; core 4 keeps its TailReport and certificate listener.

### 7.3 Replay speed (budget)

Replay must run faster than live at every load, or a replica that falls behind never catches up.

| Stage | Live at peak | Replay cost | Max speed vs live at peak |
|---|---|---|---|
| Replay lane | 30 ns/msg, 0.60 load | ≤ 20 ns/msg (no NIC, no `tag_seq` MAC, no TX), 0.40 load | 1 / 0.4 = 2.5× |
| Replay BBO core | 0.60 load | same work, no spin on cuts | 1 / 0.6 = **1.67×** |
| Decoder (core 3) | 130M records/s × 4 ns = 0.52 | same | 1.9× |
| Full hashing (6 cores) | 19.2 GB/s at ~6 GB/s/core = 0.53 | same (catch-up re-verifies) | 1.9× |
| Local NVMe read (catch-up) | — | 12 drives × 6 GB/s | 3.4× |

**`REP_REPLAY_SPEEDUP_PEAK` = 1.5×** (budget, the BBO core bounds it, **B-REP-7**). At 10% average
load, the BBO core and lanes run at ~6% load, and replay is bounded by the network and NVMe:
**`REP_REPLAY_SPEEDUP_AVG` = 10×**. A replica `L` seconds behind closes the gap at
`speedup − 1`: in `2L` seconds at peak and in `L/9` at average load. **vyrn-vx-client** must reach
≥ 1.2× at peak (**B-REP-VX**). This is a release gate, not a target: a Vx build that misses it
does not ship (11), because a slower Vx client would stop root certificates under sustained
1B msgs/s, and 1B msgs/s is a hard requirement (01 §14.0) with no limit on its duration.

Steady-state replay lag (receipt to applied), budget: ≤ 2 ms. Nothing waits on it. It sets
the age of state roots and of market data (10).

### 7.4 State roots and the gate

- **Root heights.** A root height is a height `h` with `(h + 1) % REP_ROOT_BLOCKS == 0`, where
  `REP_ROOT_BLOCKS` = 1000 (≈ 1 s). The rule uses heights, so it is deterministic. The state root
  `R(h)` is the commitment over state after block `h`.
- **Function.** CHAIN uses 09's lattice commitment over the interval's net diff. BASE calls the
  same function. 09 owns it, and 07 schedules it in both modes. One function means one cross-client
  test vector set.
- **Vote.** Each participant signs `digest = BLAKE3("vyrn v1 root" ‖ epoch ‖ h ‖ R(h))` and
  submits it to a `commonware-consensus::aggregation` engine. Item index = `(h + 1) / 1000 − 1`,
  Ed25519 scheme (hybrid from `E_pq`), namespace `b"vyrn-v1-root"`. Q signatures form `REP_RootCert`, which has
  the layout of `REP_FinalityCert` with `proposal` replaced by `(h u64, R(h) [32])`.
- **Gate (INV-REP-7).** `verify(P)` requires a `REP_RootCert` for every root height `≤
  P.last_height − REP_ROOT_GATE_BLOCKS`, where `REP_ROOT_GATE_BLOCKS` = 5000. Normal operation
  never waits: roots certify ~3–10 ms after their block is replayed. If replay stalls at so many
  participants that no root reaches Q, finality stops 5000 blocks later. This is the backstop
  against silent divergence.
- **Divergence (INV-REP-9).** `REP_A_DIVERGE` fires at a participant in either of two cases:
  - Two different digests for one root index each have ≥ f + 1 = 2 valid signatures.
  - No digest has Q signatures `REP_ROOT_TIMEOUT_MS` = 2000 ms after the root height was
    finalized.

  On `REP_A_DIVERGE`, the participant votes for nothing more (`verify` returns false, and it
  nullifies every view), and it sends `Diverge{index, digests, sigs}` to the sequencer's control
  core. The sequencer halts the book with a `Control(Halt)` step (§6.8) within 1 ms of receiving it. §11 gives the
  procedure.

One Byzantine participant cannot fire the first case, because its wrong root has 1 < f + 1
signatures. Its root is recorded as a fault (§10.2). It also cannot block a certificate: the
remaining `n − 1 ≥ Q` participants certify without it.

### 7.5 Snapshot format

Snapshots are taken at root heights where `(h + 1) % 60,000 == idx × (60,000 / n)`, with
`REP_SNAP_INTERVAL_S` = 60 and `idx` the participant index (BASE offsets of 15 s, CHAIN offsets
of 12 s; both are multiples of 1000 blocks). Each participant snapshots every 60 s, and at most
one is paused at a time.

```
REP_Snapshot file                         (little-endian, fixed-width, no maps dumped)
  off size field
    0   8  magic       "PBSNAP01"
    8   4  version     1
   12   2  book        14 1 n_lanes      15 1 client (0 Rust, 1 Vx; informative only)
   16   4  epoch       20 4 reserved
   24   8  height      state after this block
   32   8  last_step
   40  32  state_root  must equal the certified R(height)
   72  32  header_hash header_hash(height)
  104   4  n_sections  108 4 reserved   112 8 table_off   120 8 file_len
  table:   n_sections × { id u16, encoding u16, reserved u32, off u64, len u64, blake3 [32] }
  file hash = BLAKE3(header ‖ table)       (the table already commits to every section)
```

| Section id | Content, canonical order |
|---|---|
| 1 `BookParams` | the book's fixed parameters (05/10 define the fields) |
| 2 `Lane[l]` | per lane, ascending `l`: `next_lane_seq`, `fills_applied`, accounts ascending by `AccountId` with balances and reservations, sessions ascending by slot, live orders ascending by slot (slot, gen, side, tick, open qty, rx_ts, lane_seq, flags), level FIFOs per side per tick ascending (handle lists in FIFO order), overflow levels ascending by tick |
| 3 `Bbo` | filled-qty entries ascending by (lane, slot), BBO, snapshot version, undelivered fill events per lane ring in ring order |
| 4 `Timers` | order-stream-time timers ascending by (fire time, id) |
| 5 `Decoder` | `LaneDec` and `StepDec` (§3.5) |
| 6 `Sessions` | session → (account, lane, slot, next `pkt_seq`, next `resp_seq`), ascending by `SessionId` |
| 7 `Replication` | tenure, `seq_order`, deposed set, `REP_Membership` hash, root-gate cursor |

**Taking a snapshot.** At the boundary, replay pauses and the live state is copied into a staging
arena (budget ≤ 4 GB at ~20 GB/s across 49 lane threads ≈ 200 ms). Replay then resumes and
catches up at ≥ 1.5×. Core 7 serializes from the staging arena at ~2 GB/s and writes it to the
NVMe snapshot area. Votes do not pause, because they never wait for replay. **Response rings are
not in the snapshot.** A standby loaded from a snapshot can resend only responses produced after
it, so it may be promoted only after `REP_PROMOTE_HISTORY_S` = 10 s of replay since loading,
which fills its 8 s hot response ring (01 §14.6). Older resends go to the recovery service (§8.5).

**Loading.** The loader checks every section hash and the file hash. It then recomputes the state
commitment from sections 1–4 and 6 and compares it with the certified `R(height)`. A mismatch
rejects the snapshot, and the loader tries the next source. A snapshot is therefore trusted
through the certificate, not through its source.

### 7.6 Catch-up from snapshot plus log

```
 t0 ── subscribe to live frames + data; verify and vote at once (votes need no history) ──────────►
  │
  ├─ fetch the newest snapshot ≤ the newest RootCert (local NVMe, else peers via REPAIR, else archive)
  ├─ verify it (§7.5)
  ├─ fetch finalized blocks snapshot.height+1 .. live, striped by height across all peers
  │     (block record + cert, §8.2), verify certs and roots, write them to the local journal
  ├─ replay at max speed; buffer live input; live input already counts toward votes
  └─ replay lag ≤ REP_LIVE_LAG_MS (10 ms): the replica joins root votes and is "caught up"
```

Time to catch up (budget). The fetch runs on the two replication ports, which have ~150 Gbps free
at peak and ~190 Gbps at average load:

| Case | Snapshot | Log | Replay | Total |
|---|---|---|---|---|
| Restart at 10% average load, 60 s behind the snapshot | 0.4 s | 138 GB → 5.5 s | 60 s / 9 ≈ 7 s (overlaps the fetch) | ~13 s |
| Restart at sustained peak | 0.4 s | 1.37 TB → 73 s | catches up at 0.5 s/s | ~3.5 min |
| New box with an empty disk | as above | plus a backfill of the hot window in the background, capped at 50 Gbps | — | votes in seconds, state in ≤ 3 min |

## 8. Storage

### 8.1 Hardware and layout (replica, REF)

The decision is 12 × 61.44 TB Gen5 NVMe (U.2 or E3.S, TLC), ~737 TB, with no RAID (06 §2.2; 01
§14.7's 30.72 TB cannot hold §14.16's 6 h at peak, Requests to 01). Redundancy
comes from the n voters and the archive nodes.

| Per replica at peak (budget) | Voter, GB/s | R3 with the recovery service, GB/s |
|---|---|---|
| Block data (payloads in O-order) | 19.20 | 19.20 |
| Block order bytes (records only, no frame overhead) | 2.23 | 2.23 |
| 8-byte `pkt_hash` list (in O-order, kept for fast lookup and audit) | 0.80 | — (recomputed from data) |
| Block records' headers, certs, root certs | < 0.01 | < 0.01 |
| Snapshots (4 GB / 60 s) | 0.07 | 0.07 |
| Recovery-service response store (§8.5) | — | 5.90 |
| **Raw ingest** | **22.3** | **27.4** |
| Headroom (resends, bursts above the nominal peak) | 3.7 | — |
| **Ingest budget** | **26.0** (DESIGN §7) | **27.4**, with no catch-up reads |

Writes go to drive `h mod 12` for block `h`, at about 2.2 GB/s per drive. Reads at peak on a
voter are at most ~12.5 GB/s, which is one peer catch-up plus the archive pull, about 1.05 GB/s
per drive. R3 is last in every peer's catch-up order and serves ≤ 0.1 GB/s of resend reads, so
its mix (27.4 W + 0.1 R) is lighter than a voter's (26 W + 12.5 R). Gen5 TLC sustains both
mixes at ≤ 50% of its vendor sequential rates (vendor, 61.44 TB class: ~5 GB/s write, ~12 GB/s
read; 2.2 W is 44%). That is
benchmark **B-REP-9**. PCIe lanes: 4 × X2541 (x16) = 64 and 12 NVMe (x4) = 48, total 112 of the
EPYC 9575F's 128.

### 8.2 Block journal

A block is written once, when its `verify` passes. It is complete then. Packets the sequencer
never sequenced (bad MAC, rate limit, epoch mismatch) and duplicates are never written. They age
out of the RAM ring. **That is the compaction: there is no rewrite pass.**

```
REP_BlockRecord   (4 KiB aligned, on drive h mod 12)
  off size field
    0   8  magic "PBBLK001"         8 8 height        16 4 epoch     20 1 tenure   21 1 kind (0 normal, 1 seal)
   22   2  reserved                24 190 BlockHeader (§3.10)
  214   4  order_len              218 4 hash_len       222 4 data_len 226 4 n_unavail  230 26 reserved
  256   …  order bytes │ pkt_hash list (8 B × records) │ data bytes (O-order; self-delimiting by count)
           │ unavailable (session, pkt_seq) list │ pad to 4 KiB
```

- **Cert journal.** Each finality cert, root cert and seal ext is appended to a small append-only
  journal mirrored on drives 0 and 1, about 1 MB/s.
- **Index.** `height → (drive, offset, len)` and `(session, pkt_seq) → height`, the second at
  1-second granularity. Both are built on `commonware-storage` journal and archive primitives.
- **Durability point.** A replica acks nothing to anyone based on NVMe. Durability before finality
  is Q replicas' RAM, and after finality it is Q replicas' NVMe within ≤ 5 ms (one `io_uring`
  batch). A replica crash loses at most its own RAM tail, which its peers hold.

### 8.3 Retention per mode

01 §14.16 fixes the on-box window: at least 6 h at sustained peak and 12 h at ≤ 20% average load,
with the archive node streaming continuously. Retention never blocks replication.

| Tier | BASE | CHAIN |
|---|---|---|
| On the replica (737 TB raw) | `REP_HOT_HOURS_PEAK` ≥ 6 h at sustained peak (budget 7.9 h at 26 GB/s; 7.5 h on R3 at 27.4 GB/s); `REP_HOT_HOURS` = 12 h at ≤ 20% average load (~193 TB) | same |
| Archive node, one per facility | 7 days (§8.4) | same |
| Long-term | every finalized block plus hourly snapshots, compressed, 7 years (10 owns the records policy) | forever, public archive nodes (09) |

At 10% average load the log grows by 22.3 × 0.1 × 86,400 ≈ **193 TB/day** of raw blocks (DESIGN
§7's ~230 TB/day uses the 26 GB/s budget). Local snapshots: the last 10, plus hourly ones for 12 h.
The on-box log is a ring: the oldest block goes first. A replica deletes blocks the archive node
has acknowledged before others; when the ring is full it deletes the oldest block even if the
archive has not taken it, raises `REP_A_ARCHIVE`, and keeps receiving, storing and voting. So a
slow archive never stops replication or votes. `REP_A_ARCHIVE` also fires early, when the archive
lag reaches 5 h. At 90% disk use the replica stops serving catch-up reads.

### 8.4 Archive node

One archive node per facility (06 §2.2: a single-socket storage chassis, 24 × 122.88 TB QLC,
~2.9 PB) keeps **7 days** at ≤ ~18% average load (1.35 PB raw at 10%). It streams continuously:
it pulls each block from its voter's data ports as soon as the block is final, never in batches,
at ≤ 25 Gbps at sustained peak (ports ≤ 90%) and ≤ 50 Gbps otherwise. At sustained peak the feed
is below the ~180 Gbps ingest, so the archive falls behind and the ≥ 6 h on-box window covers the
gap; a sustained peak longer than that window loses archive coverage of its oldest hours (Open
question 10). Hourly objects (header + cert + `zstd -3 --long` of order bytes and data, plus the
hour's last snapshot) go to the long-term erasure-coded store across ≥ 3 facilities (RS 6+3);
compression ≥ 2.5× (**B-REP-10**). At ~8 cores of compression it is a separate box. It is also the
WAN feeder (§12) and the catch-up source beyond the on-box window.

### 8.5 Recovery service (01 §14.6)

The sequencer keeps `RESP_HOT_RING_BYTES` = 4 GiB per lane (~8 s at peak). The **recovery
service** keeps the rest: the last `RESP_RETAIN_PKTS` = 65,536 response packets of every session.
It is a role on one voter per home, **R3** (Rust, F3). F3 holds neither the sequencer (F1) nor the
standby (F2), so one facility loss never takes both the hot ring and the service.

- **Source.** R3's replay produces every response packet with its `resp_seq` (§7.1, `INV-DET`).
- **Encoding.** `REP_RspEntry`: `echo_pkt` delta, `count`, then each record with every field kept
  and delta-coded per session (tick, handle and `client_tag` against the session's previous
  values, qty as LEB128). Budget ~5.5 B per record, ~53 B per packet at the peak mix. No tag is
  stored. A resend is rebuilt from the entry alone, with no lookup of the request.
- **Storage.** Per session, a chain of 4 KiB pages covering its last 65,536 entries; freed pages
  return to a free list, and a slow session's open page is flushed every 10 s. Capacity: ≤ 200,704
  sessions (49 × `MAX_SESSIONS_PER_LANE`) × 65,536 × 53 B ≈ 700 GB, so `REP_RSP_STORE_BYTES` = 1 TB
  (0.14% of R3's NVMe). Writes: ~110M packets/s × 53 B ≈ 5.8 GB/s at peak plus ≤ 0.1 GB/s of
  partial pages (§8.1), ~0.6 GB/s at average load. RAM: an open page and an index per session, ≈ 2 GB.
- **Serving.** A lane whose hot ring no longer holds a `ResendReq` range hands it to control on
  core 51, which
  relays it to R3 on `REP_UDP_CTRL`. R3 core 6 rebuilds the packets, tags them with `K_out`
  (SipHash, ~60 ns each), sets `flags.resend` and sends them from a data port. Clients accept them
  by session and MAC, not by source address (04). The cap is `REP_RSP_MAX_PPS` = 2M packets/s
  (≤ 4.5 Gbps out, ~0.1 GB/s of page reads). `Reject RESEND_GONE` is sent only when neither the
  hot ring nor R3 holds the packet.
- **Failure.** If R3 is down, R4 takes the role from its own replay at once; older resends get
  `RESEND_GONE` until R3 returns. That loses history, never correctness.

## 9. Sequencer failover

### 9.1 Detection

A voter **suspects** the sequencer when any one of these holds:

- No frame of the current tenure has arrived on either path for `FAILOVER_SILENCE_MS` = 2 ms.
  Heartbeats come every 50 µs, so that is 40 missed beats.
- It holds valid equivocation evidence (§10.1).
- A decoded block failed `order_root` after repair from the sequencer and from every peer, or
  `REP_E_HASHLAG` fired.

On suspicion, the voter **freezes** its tail. It stops accepting frames of the tenure into its
tail state, and buffers any that still arrive. It then broadcasts a signed
`Silence{epoch, tenure, seq, reason, report}`, where `report` is its TailReport (§9.3). If fewer
than Q voters have sent `Silence` within `REP_SUSPECT_ABORT_MS` = 5 ms, it unfreezes, applies the
buffered frames and repairs the rest. A single isolated voter therefore cannot depose a live
sequencer. The standby sends a TailReport too, but its Silence never counts toward Q.

### 9.2 Deposition

When a voter holds Silence messages from Q distinct voters, the tenure is **deposed** at that
voter: BASE 3 of 4, CHAIN 4 of 5. **INV-REP-5:** a deposed voter never again accepts a frame,
header or retransmission of `(epoch, tenure)` into its log. The next Simplex leader in plain
round-robin order builds the seal proposal. The self-fence (§4.8) guarantees that the sequencer
had stopped releasing before Q voters could freeze (fence ≤ 1.15 ms < `FAILOVER_SILENCE_MS`), so
a voter outside the Q set (for example R1, co-located with the sequencer) may still hold the
newest frames. The leader therefore waits for every voter's and the standby's report, but no
longer than `T* + REP_TAIL_WAIT_MS`, where `T*` is the newest `t_last_rx` in the reports it holds
and `REP_TAIL_WAIT_MS` = 4.05 ms (fence 1.15 + detection 2.0 + one hop 0.8 + 0.1). It starts
fetching what it lacks at the Q-th report, in parallel. After a crash all reports arrive together.

### 9.3 Tail reports and the prefix rule

**Two substreams.** Every frame quantity of this section is a pair, one value per substream: `F_i`,
`extra`, `direct`, `F*`, and `F*` in `REP_SealExt`. Each pair is computed and checked on its own.
A step is in the prefix only when its home record, and its cut-only record if OTHER is set, are
both in it (§3.8).

```
Silence (LE; one signature covers the Silence and its TailReport)
  seq u8, reason u8                  0 = silence, 1 = equivocation, 2 = order_root / HASHLAG
TailReport (inside Silence; its epoch and tenure are the Silence's)
  epoch u32, tenure u8, reporter u8, reporter: a voter index < n, or n + j for seq_order[j]
  H_i      u64       highest height whose header i holds with a valid seq_sig, together with
                     every ORDER frame through BlockMark(H_i)
  then, for substream A and then B:
  mark     u64       frame_seq of BlockMark(H_i) on this substream; mark ≤ F_i
  F_i      u64       highest frame_seq such that i holds every frame 1..F_i of the tenure
  n_extra  u8        ≤ 64
  extra    n_extra × (a u64, b u64)   ranges held above F_i: ascending, disjoint, the first
                     with a > F_i + 1; later ranges may be adjacent to the one before
  direct   ⌈frames / 8⌉ bytes, LSB first: one bit per frame of (mark, F_i], then of each extra
                     range in order; 1 = received from a sequencer path. A decoder refuses more
                     than 2^20 frames.
  then:
  t_last_rx u64      PTP time in nanoseconds at which i received its newest frame of the tenure
  replay_lag_us u32, promotable u8   (§9.5)
sig      [u8; 64]    Ed25519 by the reporter over "vyrn      v1 silence" ‖ every byte above:
                     a voter with its vote_key, seq_order[j] with its seq_key
```

The suspected sequencer, `seq_order[seq]`, never reports on its own tenure: a Silence with
`reporter = n + seq` is refused even when its signature verifies, because the safety argument
below needs every reporter honest when the sequencer is the fault.

The leader computes the prefix from every report it holds when the wait of §9.2 ends (≥ Q):

1. **Signed part.** `H* = max_i H_i`. One reporter is enough, because `seq_sig` is verifiable and
   no voter can forge it. This is the "longest prefix with a verifiable seq_sig".
2. **Unsigned tail.** `F*` = the largest `k` such that every frame `1..k` of the tenure is held by
   at least one reporter, counting `F_i` and `extra`. The leader fetches the frames it lacks from
   their holders. That takes one RTT, and the budget is ≤ 1 ms.
3. **Consistency.** Each voter compares every frame in `(BlockMark(H*), F*]` that it holds with
   the leader's bytes (INV-REP-3, `flags` excluded). On any difference it refuses to vote and
   broadcasts `TailConflict{frame_seq, its bytes, its direct bit}`. The next proposal uses
   `F* := lowest conflicting frame_seq − 1`. Only a sequencer that sent different bytes under one
   `frame_seq` can cause a conflict, so that is evidence of a faulty sequencer.
4. **Data.** Every PacketRecord in frames `≤ F*` must be resolved at each voter (§5.4). Fetches
   start `REP_DATA_WAIT_US` after each record's frame, before the crash is even detected. If the
   leader still cannot resolve one from any source `REP_SEAL_DATA_WAIT_MS` = 2 ms after the
   record's frame arrived (so at the latest when it proposes), it lists the packet as unavailable. A voter accepts an unavailable entry only if it
   cannot resolve the packet either. If it can, it sends the bytes to the leader and refuses, and
   the next proposal includes the packet. A record with no HashRun in the prefix is **unhashed**.
   Its payload is accepted on `(session, pkt_seq)` alone (§9.6, case d).

**Why this is safe.** A failover happens only with Q Silence messages from voters. Under f = 1
there are two cases:

- The sequencer is the faulty box. Then every reporter is honest. Every frame an honest reporter
  holds came from the sequencer's multicast group (static ACL, §3.1) or was repaired from an
  honest peer, so the union of the reports contains only frames that the sequencer sent.
- The sequencer is correct and one voter is Byzantine. A deposition then needs Q − 1 honest
  voters that saw 2 ms of silence. The self-fence (§4.8) stopped every release before that, so
  every released frame is held by an honest voter that kept receiving, and the leader waits for its
  report (§9.2). A Byzantine voter that sends `Silence` alone achieves nothing.

Beyond f = 1 (a dead sequencer plus a lying replica), a forged tail frame would still need to pass
the static ACL, and every frame at or below `H*` is covered by `seq_sig`. **Property:** a frame
that any reporter holds is in the prefix, unless a lower frame is held by no reporter, or the
sequencer equivocated.

### 9.4 Seal proposal and seal block

The seal is one Simplex proposal of kind 1:

```
REP_Proposal { kind: 1, epoch, first_height: parent.last_height + 1, last_height: Hs = H* + 1,
               last_hash: header_hash(seal header), excl_root: over unavailable ∪ CHAIN-excluded }
REP_SealExt  { end_frame_seq: [F*_A, F*_B] [u64; 2], next_seq: u8, next_tenure: u8, n_unavail: u32,
               unavail: [(SessionId, u32)] }
digest = BLAKE3("vyrn      v1 proposal" ‖ REP_Proposal bytes ‖ REP_SealExt bytes)
seal header  { height: Hs, epoch, book, first_step: last_step(H*) + 1,
               last_step: last StepId in frames ≤ F*, prev: header_hash(H*),
               order_root: as §6.1, over each substream's ORDER section bytes after its
                           BlockMark(H*) through its F*,
               data_root: as §6.1, with 32 zero bytes for each unavailable packet,
               seq_sig: [0; 64] }
```

- The seal's digest extends the §6.3 rule with the encoded `REP_SealExt` (LE: `end_frame_seq`
  16 B, `next_seq` 1, `next_tenure` 1, `n_unavail` 4, then `n_unavail` × (`SessionId` u32,
  `pkt_seq` u32) in ascending order). It is not `digest(REP_Proposal)`, so a kind-1
  `REP_FinalityCert` carries its `REP_SealExt` after the signature entries (§6.5) and verifies on
  its own. A `REP_FinalizeVote` for a seal carries it the same way.
- A kind-1 range may hold up to `REP_MAX_SEAL_RANGE` = 64 heights: the signed headers
  `(parent.last, H*]` plus the seal header.
- The seal block's `lane_bounds` are the last `lane_seq` of each lane in frames `≤ F*` of its
  substream. A cut-only record whose home record is not in the prefix is dropped, and so is every
  later record of either substream's StepRun. PacketRecords above the last kept step's cut are
  part of the prefix. The next tenure's first cut
  starts at these bounds, so `INV-CUT-MONO` holds across the boundary (05 applies those trailing
  ops as lane-local ops).
- Voters run §6.4 items 1, 3 and 4 on the range and §9.3 items 3 and 4 on the tail.
  Finalization of the seal proposal makes the seal block final. Its certificate stands in for
  `seq_sig`.
- **Where a voter gets the seal.** `Relay` is a no-op (§6.3), so a seal payload, like any other,
  travels as its digest alone. Each voter holds its own seal candidate: the seal header and
  `REP_SealExt` it computes from the reports it holds (§9.3 is a pure function of them), or that
  its replica received from the leader. It accepts a seal payload only when the payload is that
  candidate on top of the view's parent; any other seal payload stays pending and is refused at
  `REP_VERIFY_WAIT_MS`, and the view nullifies. A later leader holding the same reports proposes
  the same seal. A full run of signed headers that matches no kind-0 range is therefore no
  contradiction while a seal may still arrive.
- **The checks split.** A voter checks §6.4 item 1 itself for the signed headers `(parent.last,
  H*]` and for the seal header's link to `H*` (`prev`, height, `first_step`). Items 2–5 for the
  signed headers are the same check as for a kind-0 range. Items 3–4 for the seal header and
  §9.3 items 3–4 for the tail are the seal check. `excl_root` covers the unavailable packets
  and, in CHAIN, the excluded ones (09).
- **A deposed leader proposes only the seal.** From deposition on (§9.2), a leader never
  proposes a kind-0 range. When the seal does not extend the view's parent, for example when the
  parent is already the seal, it proposes nothing and the view nullifies (INV-REP-5).
- After the seal is final, `next_seq` emits frame 1 of tenure `next_tenure` with `TenureStart{
  first_step: last_step(Hs) + 1, first_height: Hs + 1, prev_header_hash: header_hash(Hs), lane
  bases, prev_cut = lane_bounds }`.

### 9.5 Next sequencer, promotion, client redirect

**Deterministic choice (01 §14.4).** `REP_Membership.seq_order` lists only non-voting Rust
`vyrn-seq` boxes: the epoch's primary, then the warm standby in F2, then the spares in the
fallback order F3, F4, F1 (08 assigns the primary). No voter is ever in `seq_order`, so no
failover changes the voting set or `CLIENT_SPLIT`. `next_seq` is the first entry after the deposed
one, scanning towards the end of `seq_order` without wrapping around, that meets all of these:

- it has not been deposed in this epoch
- it sent a TailReport in this failover
- it reported `promotable = 1`: at least `REP_PROMOTE_HISTORY_S` = 10 s replayed since its last
  snapshot load, and `replay_lag_us ≤ 2,000`

So the warm standby is chosen first. A cold spare is promotable only after it has warmed (below).
Voters recompute the choice and refuse a seal that names another box.

**No promotable box.** The seal still finalizes the prefix (every response sent is final), with
`REP_SealExt.next_seq = 0xFF`. The book stays halted, and data boxes send `SeqChange{new_seq:
none}`. No voter is promoted, so neither client reaches Q alone. This needs two sequencer faults
inside one warm-up window, which is beyond f = 1.

**Warming the next standby.** When the standby is promoted or fails, the first free spare in
fallback order boots a non-voting `vyrn-replica` beside `vyrn-seq` standby, joins the data-box
destinations, catches up (§7.6, ≤ 3.5 min at peak) and is promotable 10 s later. Trading goes on;
only the second-failure margin is missing (`REP_A_STANDBY`). A spare that replaced a voter is not free.

**Promotion (on `next_seq`, budget 3 ms, B-REP-8).**

1. During the seal it keeps replaying. It holds every frame `≤ F*` by the time the seal is final
   (it fetches missing ones from the leader), so replay reaches the seal within ~1 ms.
2. The standby `vyrn-seq` process adopts the replay engine's arenas, which live in a shared 1 GB
   hugepage mapping. `vyrn-replica` stops writing to them first, so `INV-WRITER` holds across
   processes. `vyrn-seq` pins the sequencer core map (01 §10): cut cores 1 and 6, fill TX 3, 5 and
   0, stream cores 4 and 7, order hasher 50, control and finality listener 51. The lane and BBO
   threads keep cores 8–49, 56–62 and 2. The replica threads on 0, 1 and 3–7 stop first, and the
   data RX threads on 50, 52–55 and 63 stop; core 50 becomes the hasher.
3. It loads its `seq_key` and the epoch's sequencer session keys. In BASE they are preloaded from
   the secret store. CHAIN keys are 09's question (see **Interfaces**).
4. It arms the NIC flow filters (UDP port = lane) on its 4 client ports, which carried data
   frames until now, and emits `TenureStart`.
5. Data boxes stop sending data frames to it.

**Client redirect.** Every data box sends `SeqChange{epoch, tenure, new_seq, address}` to every
session it serves, using the bound addresses it already knows. The new sequencer also sends it on
first contact. 04 owns the record. Clients also hold `seq_order` and addresses from the epoch
notice, so a client can switch without waiting.

**Resend dedupe by (session, pkt_seq).** The new sequencer knows `last(session)`, the highest
`pkt_seq` in the sealed prefix, from replay. For a packet with `pkt_seq`:

| `pkt_seq` | Action |
|---|---|
| ≤ `last(session)` | Duplicate. It is not executed again. The responses from the replayed hot ring, or from the recovery service (§8.5), are resent with `flags.resend`. |
| = `last(session) + 1` | New. It is processed. |
| > `last(session) + 1` | `Reject BAD_SEQ` with `detail = last(session) + 1`. The client resends from there. |

Clients resend every packet that has no response, from their retained buffer.

### 9.6 The fill-revert condition

**Exact condition.** The condition is the same for every response, because every response is gated
(§4.3, §4.11): read "fill" as "fill, ack, reject or `BUSY`", `f(s)` as the pair of frames, one per
substream, up to `need_A(s)` and `need_B(s)`, and for an ack as its own half's frame that holds the
step whose released cut covers the op. Let fill `F` belong to step `s`, carried in ORDER frame
`f(s)` of tenure `t`. `F` is in the final log if and only if the tenure is never deposed, or the
seal has `F* ≥ f(s)` and no packet that step `s` depends on is unavailable. So `F` reverts if and
only if `t` is deposed and one of these holds:

- (a) or (b) Some frame `k ≤ f(s)` of `t` is held by no reporter.
- (c) `lead < 0` on the wire (§4.4, B-REP-2W) and the sequencer box lost power inside that
  window. This is the in-box case: the response left and its frame never did.
- (d) A packet of step `s` was unavailable or excluded. That needs client equivocation plus a dead
  sequencer, or a CHAIN tag failure (09).
- (e) A tail conflict truncated the prefix below `f(s)`, which needs a Byzantine sequencer.

**When does no reporter hold frame `k`?** Either `k` was lost on both paths for every voter and
the standby and was not repaired before the sequencer stopped, or the sequencer was cut off from
every box that reports. A box that keeps receiving is a holder, and the leader waits for its
report (§9.2), so isolating F1 from F2–F4 reverts nothing while R1 lives. Path loss is at switch
ingress, so a loss on a path hits every replica behind that path at once. The paths are
independent: separate NICs, switches and fibre. The budget assumptions in the table are inputs
to B-REP-11.

| Case | Mechanism | Assumptions (budget) | Expected reverted fills per year |
|---|---|---|---|
| (a) double drop + death | `k` lost on A and on B, and the sequencer dies within the repair window `W` | `p_A = p_B = 1e-9` per frame; 12M frames/s; `λ_seq` = 4/yr; `W` = 0.5 ms | `3.8e14 × 1e-18 × 1.3e-7/s × 5e-4 s` ≈ **2e-14 events/yr** |
| (b) both paths cut at the sequencer, sequencer alive | it keeps responding until the self-fence | `λ_iso` = P(second path fails while the first is down) ≈ 1/yr × 1/yr × MTTR 1 h ≈ 1.1e-4/yr; exposure = `REP_ACK_LIVE_US` + one-way 0.5 ms + `REP_SELF_FENCE_US` = 0.85 ms; 2M fills/s average | `1.1e-4 × 2e6 × 0.85e-3` ≈ **0.19** |
| (c) in-box | power loss during `lead < 0` | measured `P(lead < 0) ≤ 1e-4` (B-REP-2W), the magnitude of `lead` ≤ 100 ns, `λ_power` = 0.1/yr, 20M fills + ~200M lane responses/s peak | `0.1 × 2.2e8 × 1e-4 × 1e-7` ≈ **2e-4** |
| (d) | client equivocation + death | only the equivocating session and its counterparties | by design |
| (e) | Byzantine sequencer | bounded by `FAILOVER_SILENCE_MS` of its own fills; attributable only through 10's fill-quality monitoring and 09's bond | not a crash case |

Case (b) dominates the crash cases. `REP_SELF_FENCE_US` = 250 µs. Lowering
it below ~200 µs risks spurious fences from ack jitter, and each spurious fence costs a 20 ms
failover. The number to publish is that, with both paths healthy, a crash-fault revert of any
response, fill or ack, needs the same frame lost on both independent paths followed by sequencer
death within 0.5 ms, and the expected count is below 1e-13 per year. **An acked order is never
lost** outside these cases (01 §14.5). Partition exposure is published separately: ≤ 0.85 ms of
responses per dual-path isolation of the sequencer, and ~0.2 fills per year at average load. This
matches DESIGN §0.3 and §10.

### 9.7 Failover budget (`FAILOVER_TARGET_MS` = 20)

The clock starts at `T`, the sequencer's last frame. Every number is a max (budget) under a timely
network (hop ≤ `REP_HOP_MAX_MS` = 0.8 ms), with an honest sequencer that crashed.

| # | Stage | Max (ms) | At (ms) | Notes |
|---|---|---|---|---|
| 1 | Last frame reaches the farthest voter | 0.8 | 0.8 | |
| 2 | Silence detection (`FAILOVER_SILENCE_MS`) | 2.0 | 2.8 | |
| 3 | Silence + TailReport all-to-all | 0.8 | 3.6 | every live voter and the standby |
| 4 | Fetch missing tail frames and payloads | 1.6 | 5.2 | one RTT, usually 0; the wait of §9.2 (≤ 4.85 when R1 died with F1) runs in parallel |
| 5 | Seal proposal, voters' `verify` | 0.9 | 6.1 | hop + 0.1 |
| 6 | Notarize votes | 0.85 | 6.95 | |
| 7 | Finalize votes, signature checks | 0.9 | **7.85** | **the tail is final ≤ 7.9 ms after `T`** (≤ 9 required) |
| 8 | Standby replay reaches the seal | 0.5 | — | overlaps 4–7 |
| 9 | Promotion: re-pin, keys, filters, `TenureStart` | 3.0 | 10.85 | B-REP-8 |
| 10 | `SeqChange` and the first resend reach the new sequencer | 1.0 | 11.85 | partly in parallel with 9 |
| | Reserve: one TailConflict round, or one nullified view | 8.15 | | |
| | **Published outage** | **20** | | no fills from `T` through step 10 |

**Detection stays at 2 ms**: the seal fits 9 ms with 1.15 ms to spare. A 1 ms detection would
need the fence to act first (`REP_ACK_LIVE_US` + `REP_HOP_MAX_MS` + `REP_SELF_FENCE_US` < 1 ms),
which leaves ~0.2 ms for the fence timers and makes spurious 20 ms failovers likely. Typical: ~4.5 ms.

**Every response already sent**, fills and acks alike, is in the prefix. A response in the tail
was sent ≤ 1.1 ms before `T` (its block closed, and its header did not leave), so it is final
≤ 1.1 + 7.85 ≈ **9.0 ms** after it was sent: ≤ `FINALITY_MAX_MS`. Clients resend only packets
with no response.

## 10. Byzantine cases

### 10.1 Sequencer equivocation

| Form | Evidence | Attributable |
|---|---|---|
| Two headers for one `(epoch, height)` with different bytes, both with valid `seq_sig` | `SeqEquivocation{epoch u32, height u64, header_a [190], header_b [190]}`, 392 B LE, self-verifying | yes |
| ORDER bytes that do not match a signed header's `order_root` at every source | the signed header plus the frames held by Q participants | no (frames are unsigned), but the sequencer is still at fault |
| Different bytes under one `frame_seq` in the tail | `TailConflict` from two participants | no |

Action on a valid `SeqEquivocation`:

1. The holder broadcasts it, and every participant suspects at once (§9.1, reason `EQUIV`).
2. The failover runs as in §9. Simplex finalizes at most one of the two headers. If either is
   already in a notarized proposal, that one stands. The other one never enters the log.
3. The sequencer's index enters the epoch's deposed set, and it leaves `seq_order` from the next
   `REP_Membership` until operators clear it (BASE).
4. In CHAIN, the evidence is submitted as a slashing transaction. The bond is slashed
   automatically (09 owns the amount and the path).

The sequencer has no vote, so nothing changes in Simplex. The fault budget f = 1 is used up by
it for the rest of the failover.

### 10.2 Byzantine replica

| Behaviour | Effect | Response |
|---|---|---|
| Votes for an invalid proposal | none, because it needs Q and at most f = 1 is Byzantine | none |
| Conflicting votes in one view | none | `ConflictingNotarize`, `ConflictingFinalize` or `NullifyFinalize` from Simplex's reporter becomes evidence, as a `VoterFault` (below). It is removed at the next epoch, and slashed in CHAIN (09). |
| A wrong state root | its digest has 1 < f + 1 signatures, so no divergence fires and the others certify | recorded as `RootFault{index, sig}` and removed at the next epoch |
| Withholds data or repair | the requester moves to its next source (§4.10, §5.5) | `REP_A_PEER` when it fails > 1% of requests over 60 s. Not provable, so ops act on it. |
| As leader: proposes nothing, or an invalid range | the view nullifies after `t_l` = 2 ms (fits the reserve in §6.6) | the skip policy shortens its later views |
| As leader: proposes a short range | liveness only | the next leader extends the range |
| TailReport claims frames it does not hold | the leader's fetch from it fails within 1 ms | the leader drops that claim and recomputes `F*` |
| TailReport hides frames | it can shorten the prefix only if it is the sole holder. That needs the sequencer to be faulty as well, which is beyond f. | none needed |
| Floods p2p or repair | — | per-peer rate limits: `commonware-p2p` quotas, `REP_PEER_RTX_MAX_FPS` |

**`VoterFault`** is the wire form of that evidence: `kind u8` (0 = ConflictingNotarize, 1 =
ConflictingFinalize, 2 = NullifyFinalize) ‖ `voter u8` (voter index, §13.1) ‖ the two votes in
the pinned `commonware-consensus` encoding, as §6.5 already pins the signed bytes. It is
self-verifying given `REP_Membership`: both votes are in one round by the named voter, they
conflict, and each signature verifies over its namespace (`b"vyrn-v1"` plus `_NOTARIZE`,
`_NULLIFY` or `_FINALIZE`). `vyrn_consensus::evidence::VoterFault::verify` is the check.

**Frame authenticity** (referenced from §3.1). Frames carry no MAC. These are the threats and
what stops each one:

- Outsiders and Byzantine replicas cannot inject into `G_ord(seq, ·)`: the VLANs are dedicated,
  and the static switch ACLs are keyed by ingress port.
- A Byzantine peer that repairs with fake frames is caught by `order_root` for every signed block.
  Under f = 1, the unsigned tail is used only when the sequencer is the fault (§9.3), and then no
  replica is Byzantine.
- A compromised switch together with a dead sequencer is two faults, and only the unsigned tail
  is exposed. That is accepted for v1. MACsec on the replication links is the upgrade path. It is
  a COTS NIC and switch feature and needs no change to the frame format.

### 10.3 Partitions: safety over liveness

- **No conflicting finality, ever.** Two quorums intersect in `2Q − n ≥ 2 ≥ f + 1` participants:
  BASE 2·3 − 4 = 2, CHAIN 2·4 − 5 = 3. No timeout finalizes anything, and no timeout deposes
  without Q.
- **The sequencer is cut off from voters.** It self-fences once fewer than 3 voters ack within
  250 µs (INV-REP-6, ≤ 1.15 ms). If the voters still have Q among themselves, they fail over (§9).
  If not, everything stays halted.
- **Voters split with no Q on either side** (for example BASE 2/2). Nothing finalizes and no
  failover can start. The finality gate (INV-REP-10, §6.8) halts the book once more than 8 closed
  blocks are not final: ≤ ~9 ms of fills, none reverted. Voters hold their frames, and those
  frames finalize when the partition heals. The only exception is a sequencer that dies before
  then, which is the §9.6 condition.
- **Heal.** Views resume and the backlog finalizes 16 blocks per view, so a 9-block backlog clears
  in 1 view, and a longer halt's empty blocks clear at 16 per view.

## 11. Client diversity (`CLIENT_SPLIT`)

### 11.1 What is diverse

| Mode | Rust voters | Vx voters | Neither can reach Q alone |
|---|---|---|---|
| BASE (Q 3) | 2: R1, R3 | 2: R2, R4 | 2 < 3 |
| CHAIN (Q 4) | 3 | 2 | 3 < 4 and 2 < 4 |

The sequencer, the standby and the spares are Rust but never vote, so a failover never changes
this table (01 §14.4).

A Vx box runs the Rust shell (network, data tier client, consensus, storage, structural checks)
and `vyrn-vx-client`, which contains its own Vx decoder of §3 and its own replay engine. The
decision is that the Vx client decodes the raw ORDER bytes itself. Otherwise a bug in the shared
Rust decoder would feed both clients the same wrong records, and the roots would agree on a wrong
state. The encoding in §3 is therefore implemented twice, and its fuzz corpus is cross-checked
(T-REP-2). What stays common-mode is the consensus and network code, whose faults cost liveness
(Simplex safety does not depend on the replay), and the frame transport.

### 11.2 Detection and alarm

- **Signal.** `REP_A_DIVERGE` (INV-REP-9, §7.4): two root digests for one index, each signed by
  ≥ f + 1, or no root certified within 2 s.
- **Latency (budget).** The divergent block becomes final at `t`. Its root height is ≤ 1 s later,
  and the roots are computed and voted ≤ 10 ms after that. Detection therefore happens at
  ≤ `t + 1.01 s`, and the book halts within 1 ms more.
- **Alarm.** The alarm pages, carrying `(index, digests, signer sets)`. Clients receive
  `BOOK_HALTED`. Fills that were already final keep their place in the final order log, and only
  the state that follows from them is in question.

### 11.3 Procedure

1. **Halt.** This is automatic. Participants stop voting and the sequencer halts the book. An
   epoch handoff that falls in a halt is postponed (08).
2. **Freeze.** Every participant keeps its full log and its snapshots. No compaction or archive
   deletion happens until the procedure closes.
3. **Locate.** `vyrn-sim` replays from the last certified root `R(i−1)` with the Rust engine,
   `vyrn-vx-client` and `vyrn-vx-oracle`, diffs the state after every message, and reports the first
   divergent `(height, StepId | PacketRecord)`.
4. **Classify.** The three vote 2 of 3, checked against 05: a Rust bug, a Vx bug, or a spec
   ambiguity, which is fixed in the spec first.
5. **Fix.** The faulty client is fixed and released under 11's process. The fixed binary must
   reproduce the majority root for every root index since the divergence.
6. **Resume.** Participants restart on the fixed binary and replay from `R(i−1)`. Roots certify
   and votes resume. If the Rust engine was wrong, the sequencer restarts on the fixed binary
   through an orderly tenure change, and the fills that differ from the correct semantics are
   handled under 10's error-trade policy. **The order log is never rewritten.**

The target for steps 2 to 6 is ≤ 4 h. That is an ops budget, and 11 owns the runbook.

### 11.4 Why this halts and does not fork

A fork would need two certified histories. The order has one history, because one Simplex
instance finalizes it. A state needs a root certificate, which needs Q signatures, and no single
client has Q. A disagreement between clients therefore produces no root certificate. INV-REP-9
then stops new order finality at once, and the gate stops it within 5000 blocks in any case.

## 12. WAN followers

- **Role.** All three homes run a full set at all times (DESIGN §6). The voters, standby and
  spares of an inactive home are **followers**. They receive finalized blocks, verify them, store them and
  replay them. They do not vote in the active home's Simplex.
- **Feed.** The facility's archive node (§8.4) pulls finalized blocks from its voter and sends
  block `h` when `h mod n_fac` equals its facility index (`n_fac` = 4 BASE, 5 CHAIN).
  Each feeder sends to one gateway per follower home, and the gateway fans out inside its metro.
  A gateway that has missed a height for 5 ms requests it from any other feeder.
- **Unit.**

  ```
  REP_WanBlock { BlockRecord header part (§8.2), FinalityCert or seal cert, order bytes,
                 data in O-order coded with pbz, unavailable list }
  ```

  The `pkt_hash` list is dropped, because followers recompute the hashes.
- **Codec `pbz`.** Message fields are delta-coded per session: `type, flags` 1 B; tick as a ZigZag
  LEB128 delta against the session's previous tick; qty as LEB128; `client_tag` as a delta. The
  packet header is implicit from the PacketRecord.
  - Tags: **BASE drops them**. `data_root` excludes the tags, so followers still verify every
    packet. **CHAIN keeps them**, because K_com tags are publicly re-verifiable after disclosure
    (09).
  - The ratio budget is 3× on messages (**B-REP-12**). The cost is ~5 ns per message, spread
    over the feeder boxes.

| Per follower home at peak (budget) | BASE | CHAIN |
|---|---|---|
| Messages (16 B ÷ 3) | 5.3 GB/s | 5.3 GB/s |
| Packet headers (~4 B) | 0.4 | 0.4 |
| Tags (16 B per packet) | — | 1.6 |
| Order bytes | 2.1 | 2.1 |
| **Total** | **7.8 GB/s ≈ 62 Gbps** | **9.4 GB/s ≈ 75 Gbps** |
| At 10% average load | ~6 Gbps | ~8 Gbps |

- **Links.** Each pair of homes has `REP_WAN_LINKS` = 2 × 100G waves on diverse routes.
- **Lag (budget).** Finality ≤ 5.65 ms + pull and encode ≤ 2 ms + WAN one-way (35–110 ms) +
  decode and verify ≤ 2 ms gives **`REP_WAN_LAG` = WAN one-way + ≤ 10 ms**. The next home
  in the schedule has priority on shared links. The other follower may lag ≤ 10 min at sustained
  peak, and it must be caught up 1 h before its epoch (`REP_A_WANLAG` fires otherwise).
- **To 08.** At handoff, the next home holds the blocks through `last_height` within
  `REP_WAN_LAG` of their finalization, and its replay is within 2 ms of them. 08 checks the
  HandoffRecord's `state_root` and `log_hash` (§2.2) against the follower's own values. Followers
  verify certificates against the active home's `REP_Membership`.

## 13. Replica recovery and membership

### 13.1 Membership record

```
REP_Membership(e) { home: home(e), mode, sig_scheme (01 §3; every key below is of this scheme),
  voters: n × { node_key, vote_key, xchg_key, client (0 Rust, 1 Vx), facility, data_addr, repl_addr },
  seq_order: [primary, standby, spares…] × { node_key, seq_key, xchg_key, facility, client_addr, repl_addr },
  recovery (voter index of the recovery service, §8.5),
  data_boxes: [{ facility, addr }] }
```

`REP_Membership(e)` is a view, not a record of its own: `home(e)`'s part of the roster that
`EpoConfig(e).roster_hash` names, with `seq_order` starting at `EpoConfig(e).seq_order` (08 §9.6
gives the bytes, the hash and the order). A voter index is the voter's position; a sequencer
index is the box's position in `seq_order`. `HandoffCert(e − 1)` certifies it through
`EpoConfig(e)`, so it carries no signature of its own.

The rules are these:

- Membership changes **only at epoch boundaries**, at `epoch_from`.
- The `EpoConfig` that names it must be final ≥ `REP_MEMBERSHIP_LEAD_S` = `EPO_CONFIG_LEAD_S` =
  3600 s before its boundary.
- Validation rejects any record in which one client's voter count reaches Q (`CLIENT_SPLIT`),
  `q ≠ Q_BASE` or `Q_CHAIN` for the mode, `seq_order` names a Vx box, any key appears both as a
  `vote_key` and a `seq_key`, the standby is not in F2, or `recovery` names a Vx voter.
- In CHAIN mode, 09 decides validator-set changes, and 07 only applies them at the boundary.

### 13.2 Recovering a failed replica (same identity)

1. **Fence the old box.** Power it off through the BMC (Redfish or IPMI) and confirm, or disable
   its switch ports and confirm. **Two boxes never hold one vote key at the same time.**
2. Start `vyrn-replica` on the facility's spare box, and load the key from the secret store (06).
   That spare leaves `seq_order` for the rest of the epoch.
3. Catch up as in §7.6. Votes resume once live frames and data flow, before the state is caught
   up.

Budget: fence ≤ 30 s, start ≤ 60 s, votes ≤ 2 min, state ≤ 5 min. Until then there is no fault
margin (BASE: 3 of 4 = Q), and a second fault halts the book within 8 blocks (§6.8).

### 13.3 Adding or replacing a replica (new identity)

A new identity enters only through a new `REP_Membership` at the next boundary. Before
`epoch_from`, the new box runs as a follower (§12), so it is caught up when its first epoch
starts. A box that is not caught up at `epoch_from` counts as a faulty voter until it is.

## 14. Failure matrix

| Failure | Detection | Response latency | Finality | Correctness | Recovery |
|---|---|---|---|---|---|
| One frame lost on one path | duplicate count shows the other path's copy | none | none | none | none needed |
| Frame lost on both paths to one replica | hole after 5 µs | none | none (Q forms without it) | none | NACK repair ≤ 100 µs (cross-metro ≤ 600 µs) |
| One order path down | `REP_A_PATH` after 100 ms | none | none | revert exposure becomes single-path (§9.6 b) | fix the path; trading continues |
| Sequencer process crash | 2 ms silence | no responses for ≤ 20 ms | tail final in the seal ≤ 7.85 ms after the last frame | §9.6 (a), fills and acks alike; ~2e-14/yr | standby promoted ≤ 20 ms; a spare warms |
| Sequencer box power loss | 2 ms silence | no responses for ≤ 20 ms | as above | §9.6 (a) + (c); ≤ 2e-4/yr | as above; repair the box |
| F1 lost (sequencer and R1) | 2 ms silence | ≤ 20 ms | seal with 3 voters; Q = 3, no margin | as above | standby promoted; R1 on F1's spare (§13.2) |
| Sequencer stall 0.25–2 ms (SMI, page fault) | self-fence at its next flush | the stall plus ≤ 20 ms | as above | none: nothing is released after the fence | failover 20 ms |
| Sequencer cut off from ≥ 2 voters | self-fence ≤ 1.15 ms (< 3 fresh voter acks) | outage ≤ 20 ms | seal | ≤ 0.85 ms of responses revert only if no reporter holds them (§9.6 b) | failover |
| Sequencer equivocates | `SeqEquivocation` | outage ≤ 20 ms | one header wins | none for the final log | failover; slashing in CHAIN |
| Standby down | p2p liveness, `REP_A_STANDBY` | none | none | none | first free spare warms, promotable ≤ 4 min |
| Sequencer fails with no promotable standby | seal names no `next_seq` | book halted | prefix final | none; no voter is promoted, split intact | spare promotable ≤ 4 min, then a new tenure |
| One voter crash | p2p liveness; missing votes | none | none (Q still live) | none; no fault margin left | spare box: votes ≤ 2 min |
| Two voters down (BASE), or a metro partition with no Q | no Q | halted within 8 blocks (gate) | stops | none | restore or heal; backlog clears 16 blocks per view |
| Leader of one view down | `t_l` timeout | none | +2.8 ms, ≤ 8.65 ms max | none | round-robin moves on |
| Finality lags > 8 closed blocks (any cause) | core 4 gate check | `BOOK_HALTED` (logged `Control` step) | catches up | none | `Control(Resume)` at lag ≤ 4 |
| Data box down | 1 ms silence | none | +3 ms for affected blocks, ≤ 8.65 ms max | none | redirect to the backup data home (§5.7) |
| Client sends two different copies | hash or root mismatch | none | +1 fetch RTT for that block | its session closed; others unaffected | none |
| Byzantine voter (any of §10.2) | evidence or counters | none | ≤ +2.8 ms per view it leads badly | none | removed at the next epoch |
| Recovery replica (R3) down | p2p liveness | none | none | resends older than the hot ring get `RESEND_GONE` | R4 takes the role; R3 restored |
| State-root divergence (Rust vs Vx) | `REP_A_DIVERGE` ≤ 1.01 s | book halted | stops | order final, state under procedure | §11.3, ≤ 4 h |
| Replay slower than live | replay-lag metric | none | none, unless ≥ 2 voters lag > 5 s | none | catches up at speedup − 1; Vx < 1.2× does not ship |
| NVMe drive failure on a replica | I/O error | none | none | none; blocks on that drive are refetched from peers | replace the drive and backfill |
| Archive behind the on-box ring | `REP_A_ARCHIVE` at 5 h of lag; 90% use | none | none: the oldest block is deleted, voting goes on (§8.3) | none for the final log; archive coverage gap | archive catch-up; Open question 10 |
| PTP loss on the sequencer | 06 alarm | none | none | `rx_ts` quality drops (06); block cut timing drifts but is logged | restore PTP |
| WAN link to the next home down | `REP_A_WANLAG` | none | none | none | second wave; 08 delays the handoff and extends the auction |

## 15. Benchmarks and tests owned here

| ID | Measures | Pass (budget) |
|---|---|---|
| B-REP-1 | Finality of every fill and ack across 4 real facilities at peak load | max ≤ 5.65 ms with no fault, ≤ 8.65 ms with one injected fault; `FINALITY_MAX_MS` = 10 never exceeded |
| B-REP-2 | INV-FRAME-FIRST for **every** response, acks included (§4.4) | zero violations over the whole run |
| B-REP-2W | Wire lead from NIC TX timestamps (input to §9.6 c, not a correctness test) | measured fraction with `lead < 0` ≤ 1e-4 |
| B-REP-3 | Path skew between A and B | ≤ 2 µs |
| B-REP-4 | Each stream core's load at the peak mix | ≤ 0.50 |
| B-REP-5 | Sliced Ed25519 sign on core 4: CPU per signature, longest slice | ≤ 12 µs, ≤ 50 ns |
| B-PQ-1 | Scheme 1 on `REF`: ML-DSA-44 sign with `PQ_HEDGE` = 4 on cores 52–55 and = 2 on a voter, 10⁹ signatures; verify per signature | max ≤ `PQ_SIGN_MAX_US` (400, 750 µs); verify ≤ `PQ_VERIFY_US`; ML-KEM-768 decapsulation ≤ 40 µs (01 §14.20 G) |
| B-PQ-2 | Scheme 1 finality: B-REP-1 with hybrid keys and speculative signing (§6.5a); the frame gate (B-REP-13) and stream-core load (B-REP-4) re-run | BASE max ≤ 5.70 ms no fault, ≤ 8.70 ms one fault, with one `RangeFix` dropped as the injected fault; CHAIN ≤ 8.91 ms from block start with one nullified view, and a forged `RangeFix` never makes a voter reject an honest proposal; also measures the extra view for a header that arrives between `RangeFix` and `verify` (PQ-10) and counts honest CHAIN leaders that miss `t_l` (PQ-11); B-REP-13 and B-REP-4 pass values unchanged |
| B-PQ-3 | The switch at `E_pq` in `vyrn-sim`: scheme-0 votes and headers for epoch ≥ `E_pq` injected; forged scheme-0 `DoubleVote` evidence for epoch `E_pq − 1`, and a forged scheme-0 `CrossHomeVote` carrying a genuine hybrid-signed `NodeCert`, submitted after the switch with and without a pre-switch `EvidenceCommit`; a `SessionOpen`, `CommitteeKey` and p2p handshake for an epoch ≥ `E_pq` without their ML-KEM part; history before it replayed | every injected signature and every classical-only key agreement rejected (KG1); uncommitted classical evidence moves no bond and no jail, committed evidence slashes; replay from genesis bit for bit (01 §14.20 SG1–SG7) |
| B-REP-6 | Sequencer core 50 BLAKE3 load | ≤ 0.60 |
| B-REP-7 | Replay speed at peak and at average load | ≥ 1.5×, ≥ 10× |
| B-REP-8 | Promotion time of the standby | ≤ 3 ms |
| B-REP-9 | NVMe mixed load, 12 × 61.44 TB: voter mix and R3 mix; archive lag at sustained peak | 26 GB/s W + 12.5 GB/s R; 27.4 GB/s W + 0.1 GB/s R; sustained 8 h, with the ring full and deleting |
| B-REP-10 | Archive compression | ≥ 2.5× |
| B-REP-11 | Per-path frame loss, spurious self-fences with one voter down, and the failure-injection run of §9.6 | `p ≤ 1e-9`; no spurious fence in 24 h; zero reverts in 10⁴ random kills (B5) |
| B-REP-12 | `pbz` ratio on messages | ≥ 3× |
| B-REP-13 | Frame gate from step start, every gated step at the peak mix, spanning steps reported apart | ≤ 160 ns, never exceeded (§4.7: 142 ns budget for a spanning step) |
| B-REP-14 | Recovery-service entry size at the peak mix | ≤ 53 B per packet |
| B-REP-VX | `vyrn-vx-client` replay speed at peak (release gate) | ≥ 1.2× |
| T-REP-1 | Exhaustive interleavings of the gates (a lane per half, cut, BBO, stream-A, stream-B, a TX core), spanning steps and pooled `AcctTake`s included | INV-REP-1, INV-REP-2 and INV-REP-11 never violated |
| T-REP-2 | Decoder fuzz: Rust and Vx decoders on one corpus, every kind, SHED and Advance records | identical records or identical error codes |
| T-REP-3 | `vyrn-sim` failover at random points, including during repair, during a seal and with F1 isolated | every response the sequencer sent is final, except injected §9.6 cases |
| T-REP-4 | Byzantine suites using the simplex test mocks (equivocator, conflicter, nuller, twins) plus VYRN mocks (lying TailReport, wrong root, fake repair, acking-while-silent voter) | safety holds; liveness within the matrix |
| T-REP-5 | `vyrn-sim`: kill standby then primary, both inside one warm-up; stall finality 20 ms | voter set and split never change; halt, then resume on a spare; `Control(Halt)` after > 8 open blocks, replayed exactly |

## Interfaces to other chapters

| Chapter | 07 consumes | 07 provides |
|---|---|---|
| 01 | §6.6 records, constants, invariants, §14 | the wire encoding of §6.6; `REP_` definitions below |
| 02 | REQ-FIN-*, REQ-OPS-* | the finality breakdown as maxima (§6.6), the finality gate (§6.8), the failover budget (§9.7), the revert table (§9.6) |
| 03 | core maps, box roles | the replica core map and ports (§7.2); sequencer stream cores 4 and 7, the gate on TX cores 3, 5 and 0, hasher 50, finality listener on 51 (§4, §6.8); the box table (§1) |
| 04 | client protocol | requirements on 04: `SeqChange` (including `new_seq: none`) and `DataRedirect` records; clients retain sent packets ≥ 100 ms; the resend rule of §9.5; resends accepted from the recovery service's address (§8.5); a data home assigned at session open; the `Durable` and `Final` watermarks (§6.9). The ack-revert note of 0.1 is withdrawn (§4.11) |
| 05 | lane, cut and BBO semantics; replay schedule; lane packet retention 50 ms; Advance records; the clamped step cut; `AcctTake` (R15) and the pool's shared session table | the rings of §4.1; `need_A`/`need_B` on every `R_step` entry and fill event, and the block-mark entry (§4.2); the `AcctTake` encoding and its replay order (§3.6); lanes pre-encode in pass 1 and batch-hash packets; every lane response waits for `LaneCut`, written after release (§4.11); **the early `StepRecord` push ≤ 10 ns into the step and `step_done.fill_lanes` (§4.7)**; Shed/Control/Seal/Uncross encoding and payload (§3.8); decoded inputs of §7.1; trailing PacketRecords at a seal (§9.4); `Control(Halt/Resume)` from the gate (§6.8) |
| 06 | NICs, PTP, secret store, BMC fencing, NVMe and PCIe | requirements: the box table of §1; two dual-port replication cards on the sequencer, one port per stream core per path; replica ports 2 data + 2 replication; 12 × 61.44 TB and 112 PCIe lanes on a replica (§8.1); CTPIO on the replication VIs; MTU 9216; static switch ACLs; the archive node (§8.4) |
| 08 | handoff, `INV-FENCE`, the primary of `seq_order` per epoch, the reopening auction | finalized blocks at followers within `REP_WAN_LAG` (§12); `log_hash`; halts postpone handoffs |
| 09 | K_com rules, exclusion semantics, state commitment, slashing; data homes in F2–F5 | when tags are checked (§6.4 item 4); `excl_root`; evidence records (§10); finalize votes to the live and standby sequencer (§6.8); the closed-block gate count (§6.8); data homes outside the sequencer's facility (§5.1); **request:** the keys a failover sequencer and the recovery service use in CHAIN (§9.5 step 3, §8.5) |
| 10 | data-home policy, error-trade policy, records retention, MD placement | replay outputs for MD and drop copy; the separate durable and final streams (§6.9); per-sequencer fill quality inputs |
| 11 | crate layout, CI | benchmarks and tests of §15; B-REP-VX as a release gate; `vyrn-consensus::verify_finality_cert`; the divergence runbook (§11.3) |

## Local definitions (prefix REP_)

| Name | Value | Kind | Meaning |
|---|---|---|---|
| `REP_VLAN_A`, `REP_VLAN_B` | site config | — | one dedicated VLAN per order path |
| `REP_UDP_ORDER`, `_CTRL`, `_DATA`, `_REPAIR` | 7400, 7401, 7402, 7403 | — | UDP ports |
| `REP_FRAME_HDR_BYTES` | 24 | — | frame header (§3.2) |
| `REP_ORDER_FRAME_MAX` | 160 B | budget | ORDER body cap (≤ 250 B on the wire), bounds the gate (§4.7) |
| `REP_FLUSH_MAX_NS` | 1000 | budget | oldest record in an unflushed frame |
| `REP_HASH_BATCH` | 16 | budget | packets per lane BLAKE3 batch |
| `REP_HASH_LAG_NS` | 4000 | budget | HashRun lag behind its record |
| `REP_FRAME_GATE_NS` | 60 | budget | gate past the 100 ns step budget, max (§4.7) |
| `REP_KIND_FIX_NS`, `REP_FLUSH_BUSY_NS` | 10, 32 | budget | early push point; a stream core busy per flush, max |
| `REP_ACK_GATE_NS` | 10 | budget | `LaneCut` written after release instead of on read, max (§4.11) |
| `REP_STREAM_MAX_LOAD` | 0.50 | budget | busy fraction of each stream core (§4.7) |
| `REP_STREAMS` | 2 (REF), 1 (CONSUMER, AWS) | — | substreams, one per stream core (§2.2) |
| `need_A`, `need_B` | StepId | — | the newest step per half that a response of a step depends on (§4.1) |
| `REP_SIGN_SLICE_NS` | 50 | budget | longest signer slice on core 4 |
| `REP_SEAL_US` | 100 | budget | block close → HEADER out, max; HEADER_PQ follows ≤ `PQ_SIGN_MAX_US` later under scheme 1 (§3.10) |
| `REP_HB_US`, `REP_ACK_US` | 50, 50 | budget | heartbeat and replica-ack periods |
| `REP_SELF_FENCE_US`, `REP_ACK_LIVE_US`, `REP_FENCE_ACKS` | 250, 100, 3 | budget | the self-fence: fresh-ack window, ack only while receiving, voters needed (§4.8) |
| `REP_HOP_MAX_MS` | 0.8 | budget | metro one-way bound of a timely network (§6.6) |
| `REP_GATE_RESUME_BLOCKS`, `REP_GATE_AUCTION_MS` | 4, 1000 | budget | finality-gate resume and reopening (§6.8) |
| `REP_TAIL_WAIT_MS` | 4.05 | budget | longest wait for a late TailReport, from `T*` (§9.2) |
| `REP_HOLE_WAIT_US`, `REP_NACK_RETRY_US` | 5, 50 | budget | loss detection timers |
| `REP_RTX_RING_BYTES` | 64 MiB | budget | retransmit buffer per stream core |
| `REP_RTX_MAX_FPS`, `REP_PEER_RTX_MAX_FPS` | 200k, 1M | budget | retransmit rate caps |
| `REP_PEER_RING_MS` | 2000 | budget | replica in-memory frame store |
| `REP_PATH_LOSS_ALARM`, `REP_PATH_DOWN_MS` | 1e-6, 100 | budget | path alarms |
| `REP_SEQ_HASHLIST_MS`, `REP_SEQ_PKT_RETAIN_MS` | 50, 50 | budget | sequencer retention of hash lists and packets |
| `REP_DATA_UNREF_MAX` | 65,536 | reading | unreferenced payloads a replica holds (§5.4); expiry after `REP_SHED_KEEP_BLOCKS` = 128 final blocks |
| `REP_SEQ_DATA_MAX_PPS` | 50k | budget | sequencer data-repair cap |
| `REP_DATA_RING_S` | 10 | budget | data box RAM ring |
| `REP_DATA_BATCH_US`, `REP_DATA_SILENCE_MS`, `REP_DATA_WAIT_US` | 5, 1, 300 | budget | data tier timers |
| `REP_CLIENT_RETAIN_MS` | 100 | budget | client retention of sent packets (04) |
| `REP_DELTA_MS` | 1 | budget | Simplex Δ (`t_l` 2 ms, `t_a` 3 ms) |
| `REP_MAX_HDRS_PER_PROPOSAL`, `REP_MAX_SEAL_RANGE` | 16, 64 | budget | proposal range caps |
| `REP_VERIFY_WAIT_MS` | 4 | budget | `verify` pending limit |
| `REP_ROOT_BLOCKS`, `REP_ROOT_GATE_BLOCKS` | 1000, 5000 | budget | root interval and gate |
| `REP_ROOT_TIMEOUT_MS` | 2000 | budget | an uncertified root counts as divergence |
| `REP_SNAP_INTERVAL_S` | 60 | budget | snapshot period per participant (staggered 15 s) |
| `REP_PROMOTE_HISTORY_S` | 10 | budget | replay history needed to be promotable (fills the 8 s hot ring) |
| `REP_HOT_HOURS` | 12 | budget | blocks kept on the replica at ≤ 20% average load (§8.3, 01 §14.16) |
| `REP_HOT_HOURS_PEAK` | ≥ 6 (7.9 budget) | budget | blocks kept on the replica at sustained peak (§8.3) |
| `REP_RSP_STORE_BYTES`, `REP_RSP_MAX_PPS` | 1 TB, 2M | budget | recovery-service store and resend cap (§8.5) |
| `REP_SLOT_ADVANCE`, `REP_SLOT_TAKE`, `REP_SLOT_ROUTE` | `MAX_SESSIONS_PER_LANE`, + 1, + 2 | — | slot values of an Advance record, an `AcctTake` and a `RouteRecord` (§3.6) |
| `REP_LIVE_LAG_MS` | 10 | budget | "caught up" threshold |
| `REP_REPLAY_SPEEDUP_PEAK`, `_AVG` | 1.5×, 10× | budget | replay speed vs live |
| `REP_SUSPECT_ABORT_MS` | 5 | budget | a suspicion without Q is abandoned |
| `REP_SEAL_DATA_WAIT_MS` | 2 | budget | leader's wait before marking a packet unavailable |
| `REP_MEMBERSHIP_LEAD_S` | 3600 | budget | certification lead before a boundary |
| `REP_WAN_LINKS`, `REP_WAN_LAG` | 2 × 100G, one-way + 10 ms | budget | follower links and lag |
| `REP_NVME_PER_REPLICA` | 12 × 61.44 TB | budget | §8.1 (06 §2.2) |
| tenure | u8 | type | §2.2 |
| `REP_Proposal`, `REP_SealExt`, `REP_FinalityCert`, `REP_RootCert`, `REP_DurableMark`, `REP_RspEntry`, `REP_Membership`, `REP_BlockRecord`, `REP_Snapshot`, `REP_WanBlock`, `TailReport`, `Silence`, `RepAck`, `Nack`, `SeqEquivocation`, `TailConflict`, `REP_FinalizeVote`, `VoterFault` | — | type | defined where first used |
| `REP_E_*` | `TAG, COUNT, TS, KIND, CUT, TENURE, HASHLAG, ORDER` | error | decoder and stream errors; each is a sequencer fault |
| `REP_A_*` | `PATH, PEER, DIVERGE, ARCHIVE, WANLAG, STANDBY` | alarm | §4.9, §10.2, §7.4, §8.3, §12, §9.5 |
| `DUR_PATHS`, `DUR_QUORUM`, `FINAL` | — | attestation | three separate facts, never merged (§6.9) |
| INV-REP-1 … INV-REP-11 | §4.3, §4.3, §3.2, §6.4, §9.2, §4.8, §7.4, §3.7, §7.4, §6.8, §4.3 | invariant | the gate, drain-before-step, frame identity, vote rule, tenure fence, self-fence, root gate, hash lag, divergence halt, finality gate, lane-response gate |

## Requests to 01

Resolved by 01 and removed: `PacketRecord.flags` (§6.6: `SHED`, `ADVANCE`), INV-REP-6's condition
(§14.16), the mode-neutral `FIN_GATE_BLOCKS` (§14.9), the data-home rule (§14.16) and `AcctTake`
(§14.17 item 4). Open:

1. **§1 Words:** add **tenure**, **voter** (a replica that votes; `N_BASE`/`N_CHAIN` count
   them), **warm standby**, **spare** and **substream**. The "replica" entry says "votes in
   consensus", but the standby replays and never votes.
2. **§6.6:** add a kind payload to `StepRecord` (Rescan band, Control code, Uncross data; 05 R1,
   R2); note that `StepRecord.cut` is the union of two half-cuts, logged as a home record plus at
   most one cut-only record (§3.8); add `AcctTake { account, ver, lane }` to the record list.
3. **§7:** `INV-ACK-AFTER-CUT` should read "after a *released* cut includes the op (`LaneCut`,
   written by the lane's stream core after its frame's `sfence`)". Add INV-REP-11 next to it, and
   list INV-REP-6 by name with §14.16's "R1 alone never keeps it alive".
4. **§14.9:** state that `FIN_GATE_BLOCKS` counts **closed** blocks: block h + 9 opens only when
   block h is final. 07 §6.8 needs it (7.65 ms after close in BASE), and 09 §4.6 now uses it
   (7.11 ms after close in CHAIN, with the data home outside F1).
5. **§6.4:** response codes for the client watermarks of §6.9: `Durable { step, height }` and
   `Final { height, view }`, as two separate records.
6. **§5:** promote `REP_SELF_FENCE_US`, `REP_FENCE_ACKS`, `REP_HOP_MAX_MS`, `REP_ROOT_BLOCKS`,
   `REP_HASH_LAG_NS`, `REP_SEAL_US` and `REP_ORDER_FRAME_MAX`. Other chapters reason with them.
7. **§6:** promote the frame header (§3.2, with its `stream` byte), `REP_Proposal` and
   `REP_FinalityCert` (§6.3, §6.5), `REP_DurableMark`, and the `log_hash` definition (§2.2).
8. **§10 and §14.7:** the sequencer's replication cards are 2 × dual-port X2542, one port per
   stream core per path (06 §2.3); two stream cores on one single-port X2541 would be two CTPIO
   writers. A replica has 12 × 61.44 TB (§8.1). The standby and spares are built to the `vyrn-seq`
   spec and a spare adds 12 NVMe.
9. **§14.15 item 3:** a stream core runs at ~0.41, not ≤ 0.25, because the per-frame CTPIO cost
   does not halve with the lanes (§4.7). The gate bound does not depend on it.
10. **§14.2:** the cross fill at index 9 with the 15 ns step is 947 ns, not 880: the gate opens
    ≤ 142 ns after the step starts for a step that spans both halves (§4.7).
11. **§5:** *Resolved by 01:* §5 has `N_LANES_REF` = 49, which 07 uses (§3.4).

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | At which point in each step kind are kind, source and cut fixed, so that the BBO core can push `StepRecord` early (≤ 10 ns for a Cross)? Can a step's kind change after that point? | 05 | B-REP-13 + T-REP-1 |
| 2 | Can lanes afford pre-encoding (~5 ns per packet) and batched BLAKE3 (~15 ns per packet) inside 30 ns per message? | 05 | B2 with replication enabled |
| 3 | How large is the wire-lead fraction (`lead < 0`) with CTPIO on two replication VIs plus the client VIs on X2541, now that every lane response counts? | 06 | B-REP-2W |
| 4 | Which K_seq does a failover sequencer use in CHAIN, and which K_out does the recovery service use? | 09 | review plus a `vyrn-sim` failover and resend test in CHAIN |
| 5 | Does `vyrn-vx-client` reach the 1.2× release gate at peak? | 11 | B-REP-VX |
| 6 | Does the 3-of-n self-fence cause spurious fences with one voter down and the others in far facilities? | 06 | B-REP-11 |
| 7 | Is the 4-hop finality ≤ 5.65 ms max in the real metro, with leaders in the far facility, and is the 0.8 ms hop bound real? | 02 | B-REP-1 |
| 8 | Is MACsec on the replication links worth enabling in v1, given the §10.2 accepted risk? | 06 | B-REP-2W and B-REP-4 with MACsec on |
| 9 | Does the compact response entry stay ≤ 53 B per packet for real session mixes, so R3's drives hold their 27.4 GB/s mix? | 05 / 04 | B-REP-14, B-REP-9 |
| 10 | The archive's feed is ≤ 25 Gbps at sustained peak against ~180 Gbps of ingest, so a peak longer than the ≥ 6 h on-box window leaves an archive gap. Is a direct archive subscription to frames and data needed? | 06 / 07 | B-REP-9 at sustained peak for 8 h |
| 11 | Replay order of a pooled account across pool lanes: does `AcctTake.ver` alone order every cross-lane dependency, including fills settled on the account while another pool core holds its token? | 05 | T-REP-1 with pooled accounts; B4 |
| 12 | Do both ports of an X2542, each with its own CTPIO writer, keep the wire lead of B-REP-2W, and does a spanning step stay ≤ 142 ns? | 06 | B-REP-2W, B-REP-13 |
| 13 | Under scheme 1 (01 §14.20), does data RX on 5 cores (50, 52–55) keep up with 155 Gbps of data frames at peak, now that core 63 signs votes? If not, voters need a larger box or `PQ_HEDGE` = 1 with the 1.35 ms tail budgeted. | 06 | B-REP-9 data mix plus B-PQ-1 on one voter |

Resolved and removed: 14 (a seal `REP_FinalityCert` carries its `REP_SealExt` after the entries; §6.5, §9.4).
