# 04. Client protocol: sessions, packets, messages, responses, reliability, rate limits

Draft 0.2, 2026-11-13. Normative. The byte layouts are in `01-conventions.md` §6 and this chapter
does not change them. This chapter gives their semantics, the state machines on both sides, the
order of checks, and the test vectors. Local names use the prefix `PROTO_`. 01 §14 is binding
here: where this chapter and 01 §14 differ, 01 §14 wins.

**The latency contract, from the client's side (01 §14.0, §14.19 A, REQ-LAT-1).** Every received
packet of 1 to 10 messages gets the first record of every message, at every index 0–9 and of every
type, within `LAT_MAX_NS` = 1 µs from its first bit in. A received packet is one that passed the
edge filters E1–E4 (§3.4) and reached the sequencer's NIC. This is a maximum, not a percentile, and
it has no rate, size or position condition. A packet that the exchange cannot serve in time gets
`Reject BUSY` within the same 1 µs (§3.5). A received packet that is the session's next valid
packet has no third outcome. A packet that a policer drops, or that the network loses, was never
received: it gets no response, the client's timer resends it, and REQ-LAT-14 bounds how often that
happens. The only window without a 1 µs answer is the handoff window of 01 §14.0 item 2 (H6). On
AWS the 1 µs is measured inside the instance (01 §14.0 item 1).

## 0. Scope and constraints

This chapter covers the order-entry path between a client and the home that runs the book:

- request packets from a client to the sequencer and to the data tier;
- response packets from the sequencer (and from the recovery service) to the client;
- the session life cycle, the keys, the admin channel that opens a BASE-mode session;
- reliability across loss, failover and epoch handoff;
- rate limits and the message fee classes.

It does not cover market data or drop copy (`10-accounts-risk-md.md`), the order stream between
the sequencer and the replicas (`07-replication.md`), or the on-chain session transaction
(`09-chain.md`).

How the protocol meets the hard constraints:

| Constraint | How |
|---|---|
| C-UNIX | The client needs only a Unix UDP socket. The exchange side runs on ef_vi, DPDK or kernel UDP (`06-platform.md`). The admin channel is TLS 1.3 over TCP on any Unix. |
| C-NOCHIP | Every check in §3 runs on a lane core. SipHash-2-4 is plain 64-bit integer code. Edge filtering (§3.4) uses the fixed-function ACLs and policers of a merchant switch. Nothing is programmed into a switch or NIC. |
| C-COTS | IPv4 and UDP, 1500-byte MTU, no jumbo frames, no NIC feature beyond flow steering on the UDP destination port and RX hardware timestamps. |
| C-ONEBIN | The protocol is the same on REF, CONSUMER, AWS and DEV. Only the endpoint list in the key bundle (§4.4) differs. |

## 1. Decisions at a glance

| # | Decision | Reason (section) |
|---|---|---|
| P1 | UDP over IPv4, one 16-byte header, up to 10 fixed 16-byte messages, two tags. | Datagram boundaries carry the MAC and the message count. The protocol needs its own resend for failover anyway, so TCP's reliability buys nothing (§2.1). |
| P2 | UDP destination port = `PROTO_LANE_PORT_BASE + LaneId`. | The NIC steers by port, so a packet lands on its lane with no software hop (§2.2). |
| P3 | Every packet is sent twice with identical logical content: to the sequencer and to one data node. | The sequencer sends only the order. Replicas get payloads from the data tier (§2.4). |
| P4 | The cheapest checks run first. No SipHash runs for an unbound source address. | A spoofed flood costs ≤ 5 ns per packet (budget) (§3). |
| P5 | `pkt_seq` is gapless and the sequencer accepts only `expected`. A gap is answered with `BAD_SEQ` and the client goes back to `expected` (go-back-N). | No reorder buffer in the lane. Acceptance is a pure function of logged packets (§5.1). |
| P6 | `resp_seq` has exactly one allocator per session: the session's lane. The TX cores (A, B, C on CCD 0, 01 §14.17.3) send taker records under a `resp_seq` the lane reserved, and maker fills from a 16-number maker range the lane reserves ahead (01 §14.14). `resp_seq = 0` marks an out-of-stream response. | One writer per field (`INV-WRITER`); taker and maker fills both leave within 1 µs from CCD 0 (§7.1). |
| P7 | Every accepted packet gets at least one in-stream record with `echo_pkt = pkt_seq`. | The client always learns that a packet was accepted (rule R-ANSWER, §7.2). |
| P8 | Each lane keeps a `RESP_HOT_RING_BYTES` = 4 GiB byte ring of its sessions' responses (~8 s). The recovery service on one replica per home keeps `RESP_RETAIN_PKTS` per session. `RESEND_GONE` only when both dropped it. | 65,536 packets for every session do not fit in a lane's memory (§5.4, 01 §14.6). |
| P11 | Deadline admission: a packet that cannot be answered in time gets `Reject BUSY` within 1 µs and is not applied. | The 1 µs is a maximum (§3.5, 01 §14.1). |
| P13 | Two lane classes (01 §14.15). A client on a **dedicated** lane paces its packets (`LANE_PACE`, §3.6) and then never waits in the lane stage; a **pooled** client shares 7 cores. The SDK puts a packet's cancels first. | Each class gets a stated `BUSY` bound (§3.6, 01 §14.17.2); cancels get the most slack (01 §14.17.1). |
| P12 | Execution, durability, finality and settlement are separate attestations, each with its own signal. | A 1 µs `Fill` is not a final fill (§7.5, 01 §14.13). |
| P9 | Replace uses total-quantity semantics. A same-tick reduction keeps the handle and the priority. | A replace never over-fills, and the lane decides the priority question from its own data (§6.5). |
| P10 | Rate limits are GCRA buckets on `rx_ts`. They are part of the deterministic state. | Replicas reproduce every `RATE_LIMIT` reject bit for bit (§9). |

## 2. Transport

### 2.1 Why UDP, and not TCP or kernel-bypass TCP

UDP is the transport. The reasons, strongest first:

1. **The protocol needs application-level sequencing anyway.** A TCP connection ends at one box.
   When the sequencer fails over (≤ `FAILOVER_TARGET_MS`) or the book moves home every
   `EPOCH_HOURS`, the client must resend its unacknowledged packets to a different box and the
   new box must deduplicate them. That needs `pkt_seq`, `resp_seq` and resend rules at the
   application layer (§5). With those in place, TCP's own retransmission is a second, redundant
   reliability layer.
2. **Head-of-line blocking.** TCP delivers bytes in order. One lost segment stalls every later
   message until a retransmission arrives. The Linux minimum RTO is 200 ms by default (vendor:
   kernel default) and ≥ 1 ms when tuned. A stall of that size breaks `LAT_MAX_NS` for every
   message behind the loss. With UDP, the lane rejects the packets behind a gap in tens of
   nanoseconds and the client resends after one round trip (§5.1).
3. **Lane cost.** TCP needs per-connection send and receive state, ACK generation, window
   updates and timers. For `MAX_SESSIONS_PER_LANE` sessions this is extra state and extra
   packets (ACKs) on a core that has a budget of `LANE_PASS1_NS` + `LANE_APPLY_NS` per message. UDP needs one
   compare on `pkt_seq`.
4. **Message boundaries.** The MAC covers exactly one packet, and `count` fixes the length. On a
   byte stream, the lane would need a framing layer before it could check either.
5. **Kernel-bypass TCP does not remove 2–4.** Stacks such as Onload or TCPDirect remove the
   syscall cost. They keep the stream semantics, the head-of-line blocking and the per-connection
   state, and they run their timers outside the order stream.

IPv4, not IPv6: the IPv4 header is 20 bytes shorter. At 100M packets/s that is 16 Gbps per
direction (computed). Every COTS NIC filter and the AWS ENA path support IPv4. IPv6 is a v2 item
(§12).

The admin channel (§4.3) is TLS 1.3 over TCP. It is never on the 1 µs path, so the cost of TCP
does not matter there.

### 2.2 Endpoints and ports

| Endpoint | Address | UDP port | Who listens |
|---|---|---|---|
| Order entry, lane `l` | the box's order address for that lane, from the key bundle | `PROTO_LANE_PORT_BASE + l` | lane `l` of the box that is the sequencer now |
| Data copy | one data node from the key bundle | `PROTO_DATA_PORT` | `vyrn-data` |
| Recovery | the recovery address of a box, from the key bundle | `PROTO_RECOVERY_PORT` | the recovery service on a `vyrn-replica` (§5.4) |
| Inclusion (CHAIN only) | each validator's inclusion address | `PROTO_INCLUSION_PORT` | `vyrn-validator` (`09-chain.md`) |
| Admin (BASE only) | `vyrn-admin` | TCP 443 | `vyrn-admin` |

Rules:

- The client sends a session's packets only to its lane's port. The lane is fixed for the life of
  the session and is encoded in the `SessionId` (§4.1).
- The NIC steers each packet by (destination address, destination port) to the lane's RX queue.
  On REF, `06-platform.md` assigns lanes to NIC ports, and the key bundle carries the resulting
  address for each lane.
- On AWS, ENA steers by RSS only. A packet can land on the wrong lane, which forwards it to the
  owning lane over an SPSC ring (+100 ns, budget, from DESIGN §4). The client does nothing
  different.
- Responses always go to the session's **bound address** (§4.2), never to the source address of
  the packet that caused them. So a replayed or spoofed packet cannot redirect any response.
- Responses come from the order address of the box that sends them. After a failover the source
  changes. The client accepts responses from any box listed in its key bundle and selects the
  tag key by the source box (§4.4).

### 2.3 Sizes and MTU

| Item | Bytes | Derivation |
|---|---|---|
| Smallest request (1 message) | 48 | 16 + 16 + 2 × 8 |
| Largest request (10 messages) | 192 = `MAX_REQ_PAYLOAD` | 16 + 160 + 16 |
| Smallest response (1 record) | 40 | 16 + 16 + 8 |
| Largest response (16 records) | 280 = `PROTO_RESP_MAX_BYTES` | 16 + 256 + 8 |
| Largest request frame on the wire | 238 + 20 | 192 + UDP 8 + IPv4 20 + Ethernet 14 + FCS 4, plus preamble and IFG |
| Largest response frame on the wire | 326 + 20 | 280 + 46 |

Decisions:

- **The standard 1500-byte MTU is enough.** No jumbo frames are needed, so every COTS NIC and every
  cloud network carries the protocol unchanged.
- **No fragmentation.** Clients set DF. The lane drops IPv4 fragments and packets with IPv4
  options, and counts them (`PROTO_CNT_MALFORMED`).
- **The UDP checksum is optional for the client** (IPv4 allows 0). The MAC covers integrity. The
  NIC verifies a nonzero checksum in hardware and drops a packet that fails.
- **Wire load (computed):** 100M full requests/s is 100M × 258 B × 8 = 206 Gbps, which loads
  4 × 100GbE to 52%. This matches DESIGN §4.

### 2.4 The dual send

Every request packet goes to two places:

```
 client ──(1) sequencer copy ──► vyrn-seq lane l      (latency path; decides acceptance)
   │
   └────(2) data copy ─────────► vyrn-data node d     (payload path; feeds the replicas)
                                     │
                                     └──► replicas fetch by PktHash, vote when complete
```

**Client obligations:**

| ID | Obligation |
|---|---|
| D1 | Send the sequencer copy first and the data copy immediately after, from the same thread. The data copy leaves at most `PROTO_DATA_LAG_MAX_US` after the sequencer copy (budget). |
| D2 | Send both copies of **every** transmission, including resends (flags bit0 = 1) and resends to a new sequencer. A resend has a different `PktHash`, because `flags` is hashed, and the replicas need the exact copy that the sequencer accepted. |
| D3 | Keep the **logical content** of a `pkt_seq` fixed forever. The logical content is (`session`, `pkt_seq`, `count`, `book`, the message bytes). Only `flags` bit0, `epoch16` and the tags may differ between transmissions of one `pkt_seq`. |
| D4 | Pick the data node from the key bundle's `data` list (§4.4): the first entry that the latest `DataTierStatus` does not mark down. The first entry is the session's **data home**, which is never in the sequencer's facility (01 §14.16, 07); the list is ordered per session by rendezvous hash among the other facilities, so sessions spread evenly over the data nodes. |
| D5 | Switch data nodes only when a `DataTierStatus` says so (admin channel in BASE, chain state in CHAIN). Data nodes never answer clients, so the client cannot detect a dead data node itself. |
| D6 | A client may send the data copy to two data nodes. The data tier deduplicates by `PktHash`. This costs bandwidth and buys nothing unless a data node is failing. |

**Why D3.** A packet that the sequencer never answered may still have been accepted, and its data
copy exists either way. If the client could reuse the `pkt_seq` for other content, the log would
hold two packets under one name. So the client never does that. To change its mind, it sends a
new packet that cancels or replaces.

**When the copies differ.** `07-replication.md` detects it by `PktHash`: the replicas look up the
payload named by the `PacketRecord`, and a missing or different payload starts its check. The
outcomes, as the client sees them:

| Case | Outcome |
|---|---|
| The two copies differ only in fields D3 allows to differ | Normal. The data tier holds both. Replicas use the one the `PacketRecord` names. |
| The data copy is missing or arrives after the block closes | The replicas repair the payload from the sequencer (`07-replication.md`). The packet stands. `vyrn-data` counts a late copy against the session (`PROTO_CNT_DATA_LATE`). `10-accounts-risk-md.md` sets the penalty for a persistent offender. |
| A copy fails its tag check (`tag_seq` in BASE, `tag_com` in CHAIN) | That copy is ignored and counted. A copy without a valid tag is not evidence against the client, so a spoofer cannot frame a session. |
| Two copies with valid tags have different logical content | **Equivocation.** The exchange closes the session (`SESSION_CLOSED`, detail `PROTO_D_EQUIVOCATION`), through an admin control record in the order stream. In CHAIN mode the session bond pays the counterparties (`09-chain.md`). |

Note for `07`: two transmissions of one `pkt_seq` have different `PktHash` values when only
`flags` bit0 or `epoch16` differ. Equivocation is therefore a difference in logical content
(D3), not a difference in `PktHash`. See Requests to 01.

## 3. The validation pipeline in the lane

### 3.1 Order of checks

The lane runs these checks in this order on every received packet. The cheapest check runs
first, and no check that can close a session runs before the checks that prove the packet is
for this session, from its bound address, and in its epoch. All costs are **budgets** on REF
at 5 GHz. Benchmark B2 (`11-build.md`) measures them. V0–V8 are the packet part of pass 1
(01 §14.2): together they fit the 45 ns per packet of `LANE_PASS1_NS`. Test D (§3.5) is
computed at dequeue; a shed is taken right after V5.

| Step | Check | Cost | On failure | Response | Counter |
|---|---|---|---|---|---|
| V0 | NIC: destination port, IPv4 without options or fragments, UDP checksum if nonzero | 0 (NIC) | NIC drops | none | NIC stats |
| V1 | UDP payload length = 32 + 16 × `count`, and 1 ≤ `count` ≤ `MAX_MSGS_PER_PKT` | 1 ns | drop | none | `PROTO_CNT_MALFORMED` |
| V2 | Session lookup: lane bits of `session` = this lane; slot generation = `session` generation; slot not `FREE` | 2 ns | other lane: §3.2 slow path. Unknown: drop | none, or out-of-stream `WRONG_LANE` | `PROTO_CNT_UNKNOWN_SESSION` |
| V3 | Source (IPv4 address, UDP port) = the session's bound address (01 §12.5) | 1 ns | drop | none | `PROTO_CNT_UNBOUND_SRC` |
| V4 | `epoch16` = low 16 bits of the box's current epoch | 1 ns | drop | out-of-stream `EPOCH_MISMATCH`, detail = current epoch | `PROTO_CNT_EPOCH` |
| V5 | `expected − PROTO_SEQ_BACK ≤ pkt_seq ≤ expected + PROTO_SEQ_AHEAD` | 1 ns | drop | none | `PROTO_CNT_SEQ_WINDOW` |
| V6 | `tag_seq` = SipHash-2-4(`K_seq(e, this box)`, bytes 0 .. 16+16n). Reached only with a bound source (V3) and a matching `epoch16` (V4) | 10 ns (n = 1) to 40 ns (n = 10), inside the 45 ns | **close the session** (cause `BAD_MAC`, 01 §14.8) | in-stream `Reject BAD_MAC`, index 0xFF, final record | `PROTO_CNT_BAD_MAC` |
| V7 | Session state is `CLOSED` | 1 ns | drop | out-of-stream `SESSION_CLOSED`, detail = close cause | `PROTO_CNT_CLOSED` |
| V8 | `pkt_seq` vs `expected`: equal → accept; less → duplicate (§5.2); greater → gap (§5.1) | 1 ns | duplicate or gap handling | resend, or out-of-stream `BAD_SEQ` | `PROTO_CNT_DUP`, `PROTO_CNT_GAP` |
| — | **Accept.** Write the `PacketRecord` (`07-replication.md`). `expected += 1`. | 3 ns | — | — | — |
| V9 | Header semantics: request `flags` bits 1–7 = 0, `reserved` = 0; `book` is one of the session's books | 1 ns | every message is rejected | in-stream `Reject BAD_TYPE` (`PROTO_D_BAD_HDR`), or `Reject BAD_BOOK` (23), per message | `PROTO_CNT_BAD_HDR` |
| V10 | Packet buckets of the session and the account (§9) | 2 ns | every message is rejected | in-stream `Reject RATE_LIMIT` per message | `PROTO_CNT_RATE` |
| V11 | Per message, in index order (§3.3): pass 1, then pass 2 | `LANE_PASS1_NS` 5 + `LANE_APPLY_NS` 9 each | that message is rejected | in-stream records | per reason |

Why this order:

- **V3 before V6.** A packet from an unbound address never costs a SipHash. That is the DoS
  defence (§3.4). It also gives 01 §12.5 its meaning: a bad MAC from an unbound address is
  dropped and counted at V3, and the session stays open. A bad MAC at V6 can only come from the
  bound address with the receiver's own epoch, so it closes the session (01 §14.8).
- **V4 before V6.** The tag key depends on the epoch. An honest client that is a few
  milliseconds late at a boundary sends a packet tagged with last epoch's key. If V6 ran first,
  that packet would fail the MAC and close an honest session. With V4 first, the client gets
  `EPOCH_MISMATCH` and switches keys. Sessions survive the boundary (01 §14.8), so this matters
  for every session at every handoff.
- **V5 before V6.** A far-out `pkt_seq` cannot come from an honest client. Dropping it costs one
  compare and closes nothing.
- **V6 before every response that is not `EPOCH_MISMATCH`.** The lane never answers an
  unauthenticated packet, except at V4 (where it cannot authenticate) and then only under the
  holdoff of §3.2.
- **Acceptance before V9–V11.** Once a packet passes V6 and V8, it is authenticated and it is
  the next packet. The lane accepts it and records it even if its contents are wrong. If the lane
  dropped it, the client would have to resend a different packet under the same `pkt_seq`, which
  D3 forbids. Every rejection after acceptance is an in-stream record.

**Speculative work.** The lane may parse and classify the messages while SipHash runs. It changes
no state and forwards nothing to the BBO core until V6 passes. This hides most of the MAC time
on the cross path.

**Two passes (01 §14.2).** Pass 1 runs M1–M8 on every message in index order and pushes each
improve, cross, `IOC`, `FOK` and post-only-would-cross to the BBO ring as soon as it is
classified, with its in-packet dependency list and pre-assigned handles. Pass 2 applies the joins
and cancels in index order. A cross at index i waits only for the pass-1 work of messages
0 … i−1 (5 ns each), not for their apply. Worst case, index 9 of a full packet (budget, REF):
cross fill 880 ns, join or cancel ack 965 ns (955 typical), against the 980 ns shed threshold
(`DEADLINE_GUARD_NS` = 20, 01 §14.17.1). A pooled packet adds 20 ns for the account token. Index 0
is ~90 ns faster, and an ack's slack grows by ~9 ns per earlier index, so **the SDK puts a
packet's cancels first** (index 0 has ~100 ns of slack). Message order is the client's choice, so
this changes no semantics. **Every index meets `LAT_MAX_NS`.**

**Two passes do not change outcomes.** The records of every message are exactly those that
applying the messages one at a time, in index order, would produce: the same fills, prices,
quantities, STP outcomes, rejects and handles. The dependency list makes the BBO core treat each
earlier op of the packet as resting at its own priority. A client can rely on the outcome of
index order. It cannot rely on the arrival order of records across the B-packet and the
L-packet (R-ACROSS, §7.2); inside one response packet, records are in index order (R-INDEX).

```rust
fn on_rx(&mut self, p: &RxPkt) {
    let late = self.must_shed(p);                                           // D, §3.5, at dequeue
    let n = p.data[8] as usize;
    if n == 0 || n > MAX_MSGS_PER_PKT || p.len != 32 + 16 * n { return self.cnt.malformed.inc(); }
    let sid = SessionId(le_u32(&p.data[0..4]));
    if !self.serves(sid.lane()) { return self.other_lane(p, sid); }          // §3.2, §4.7
    let s = &mut self.sessions[sid.slot()];
    if s.gen != sid.gen() || s.state == State::Free { return self.cnt.unknown_session.inc(); }
    if p.src != s.bound { return s.cnt.unbound_src.inc(); }
    if le_u16(&p.data[10..12]) != self.epoch.low16() { return self.oos(s, p, EPOCH_MISMATCH, self.epoch.0); }
    let seq = le_u32(&p.data[4..8]);
    if !s.seq_in_window(seq) { return s.cnt.seq_window.inc(); }
    if late { return self.busy(s, p, seq); }   // PacketRecord.flags bit0 SHED + Reject BUSY, ~20 ns
    let end = 16 + 16 * n;
    if siphash24(&s.k_seq, &p.data[..end]) != le_u64(&p.data[end..end + 8]) {
        return self.close(s, Close::BadMac { pkt_seq: seq });               // in-stream, final
    }
    if s.state == State::Closed { return self.oos(s, p, SESSION_CLOSED, s.close_cause as u32); }
    match seq.cmp(&s.expected) {
        Ordering::Less => self.duplicate(s, p, seq),                          // §5.2
        Ordering::Greater => self.oos(s, p, BAD_SEQ, s.expected),             // §5.1
        Ordering::Equal => self.accept(s, p, seq),                            // V9..V11
    }
}
```

### 3.2 Out-of-stream responses and the other-lane path

An **out-of-stream** response answers a packet that the lane did not accept. It has:

- `resp_seq = 0`, `count = 1`, `flags = 0`, `echo_pkt` = the `pkt_seq` of the packet it answers;
- one `Reject` record with index 0xFF (the whole packet), the reason, the detail, and
  `client_tag = 0`;
- a tag with `K_out(e, this box)`, and the session's bound address as destination.

Rules:

- The lane sends at most one out-of-stream response per (session, reason) per
  `PROTO_OOS_HOLDOFF_US`. Later ones in that window are only counted.
- Out-of-stream responses are not retained, not resent, and not part of any state. They are not
  engine output: they depend on packets that the order stream does not contain. Their frame gate
  (01 §14.5) is empty.
- The four out-of-stream reasons are `EPOCH_MISMATCH`, `BAD_SEQ`, `SESSION_CLOSED` and
  `WRONG_LANE`. No other reason is ever sent out of stream. A lane-shed `BUSY` is in stream
  (§3.5).

**Other-lane path.** A packet whose `session` names another lane goes to a slow path with a
budget of `PROTO_WRONG_LANE_PPS` per lane. Above that budget the lane drops and counts.

- **Port steering (REF, CONSUMER).** The client sent to the wrong port. The lane reads the owning
  lane's session slot (read-only; keys do not change while a session exists), runs V3–V6 against
  it, and if they pass, sends out-of-stream `WRONG_LANE` with detail = the correct `LaneId`. It
  never accepts the packet. A V6 failure here is dropped and counted: only the owning lane can
  close a session (`INV-WRITER`).
- **RSS steering (AWS).** The NIC put the packet on the wrong lane, and the client did nothing
  wrong. The lane forwards the packet to the owning lane over an SPSC ring (`05-engine.md`) and
  sends no response. The owning lane uses the original `rx_ts`.

### 3.3 Per-message checks

For each message, in index order, the lane runs these checks. The first failure decides the
reject reason. The order is fixed, so replicas reproduce the same reason.

| Step | Check | Reason on failure |
|---|---|---|
| M1 | Message bucket of the session and the account (§9). The type byte selects the cancel reserve. | `RATE_LIMIT` |
| M2 | Type code is defined for the session's protocol version | `BAD_TYPE` (`PROTO_D_UNKNOWN_TYPE`) |
| M3 | Every field that the layout marks 0 is 0; order flags bits 6–7 are 0; the flags byte of a non-order message is 0 | `BAD_TYPE` (`PROTO_D_RESERVED`) |
| M4 | Session state allows the type: in `DRAINING`, `New` and `Replace` fail. Account state is `Active` for `New` and `Replace` (10) | `SESSION_CLOSED` (`PROTO_D_DRAINING`), `ACCOUNT_KILLED` |
| M5 | Book phase allows the message (§6.9) | `BOOK_HALTED`, `AUCTION_PHASE` |
| M6 | Field checks of the type (§6) | `BAD_TICK`, `BAD_QTY`, `UNKNOWN_HANDLE`, `TOO_LATE`, `SIDE_MISMATCH`, `BAD_SEQ` |
| M7 | Risk (`10-accounts-risk-md.md`): order count, then exposure, then balance | `RISK_ORDER_COUNT`, `RISK_POSITION`, `RISK_CREDIT` |
| M8 | Classify against the lane's snapshot (join, improve, cross); BBO bucket (§9). A post-only order the snapshot calls a cross is routed to the BBO core, which decides it (03 ARC-D6) | `RATE_LIMIT` |
| M9 | Apply: a lane-local op, or a push to the BBO-core ring | — (later outcomes in §6) |

Budget per message (01 §14.2): M1–M8 and the forward push are pass 1, `LANE_PASS1_NS` = 5 ns. M9
for a join or a cancel is pass 2, `LANE_APPLY_NS` = 9 ns. `LANE_NS_PER_MSG` = 30 is the average
with every amortized cost (risk misses, overflow levels, settles) and is what admission (§9.1)
uses; it is not a per-message latency term.

A rejected message changes no order state. It does consume its message token (M1), so a flood
of invalid messages is limited like any other flood.

### 3.4 Spoofed sources and denial of service

| Attack | What the lane does | Cost to the lane (budget) | Effect on the victim |
|---|---|---|---|
| Random `session` values from any source | drop at V2 | ≤ 4 ns | none |
| A valid `session` from an unbound source, any MAC | drop at V3, count | ≤ 5 ns | none; the session stays open |
| The bound source, a wrong epoch | out-of-stream `EPOCH_MISMATCH` under holdoff | ≤ 6 ns | at most one extra response per holdoff |
| The bound source, `pkt_seq` outside the window | drop at V5 | ≤ 6 ns | none |
| The bound source, `pkt_seq` in the window, bad MAC | close the session at V6 | ≤ 45 ns once | the session closes |
| Replay of a captured valid packet | duplicate (§5.2): dropped, or a resend to the bound address under the resend bucket | ≤ 50 ns | none |
| Reflection toward a third party | impossible: every response goes to a bound address | — | — |

The lane alone cannot absorb a full-rate flood. One 100GbE port carries up to 148.8M minimum
frames per second (computed), and at 5 ns per drop one lane handles 200M/s, but the flood still
fills the lane's RX ring and delays real packets. So the edge does the first filtering, with
fixed-function features of a merchant switch (`C-NOCHIP`):

| ID | Edge control |
|---|---|
| E1 | Strict uRPF and an ingress ACL per client cross-connect. A cross-connect can source only the client's registered prefixes. `vyrn-admin` builds the ACL from the session directory. |
| E2 | A packet-rate policer per cross-connect at the contracted rate. |
| E3 | On AWS, the VPC source/destination check forbids spoofed sources, and security groups admit only registered client addresses. |
| E4 | A policer per lane (destination address and UDP port) on the switch port that faces the sequencer: at most `LANE_POLICE_PPS` packets/s with a burst of `LANE_POLICE_BURST` (01 §14.1). It bounds the lane's RX backlog so that every `BUSY` fits in 1 µs (§3.5). A packet it drops was never accepted; the client's timer resends it. |

With E1–E3, the only party that can send from a session's bound address is the owner of that
address's link. So a bad MAC from the bound address is the owner's bug or compromise, and closing
the session at the first failure is correct. It also limits a key-guessing attacker to one guess
per session.

### 3.5 Deadline admission and `BUSY` (01 §14.1)

**Test D.** When the lane dequeues a packet it computes `age = now − rx_ts` (TSC↔PHC mapping,
`06-platform.md`; on AWS `rx_ts` is the TSC at RX completion, 01 §14.11). It sheds the packet if
either holds:

1. `age + predicted_path_ns(p) > LAT_MAX_NS − DEADLINE_GUARD_NS`. For a packet with forwarded
   ops, the prediction includes the BBO-ring backlog that the lane can see.
2. Serving p fully would leave a packet behind it unable to get its own `BUSY` in time: for some
   pending packet k (those in the RX ring, plus the most that E4 admits during p's work),
   `age_k + L_p + PROTO_SHED_NS × k + PROTO_BUSY_TAIL_NS > LAT_MAX_NS − DEADLINE_GUARD_NS`,
   where `L_p` is p's lane work and k its position behind p.

**Why every `BUSY` arrives within 1 µs.** Rule 2 holds the backlog where every pending packet can
still be shed in time. A shed costs `PROTO_SHED_NS` = 20 ns, and E4 admits at most one packet per
25 ns, so the backlog cannot grow while the lane sheds. A lane `BUSY` waits for the logged cut like
an ack, because its `SHED` record is frame-gated: `PROTO_BUSY_TAIL_NS` = 460 (cut 170 + `LaneCut`
poll 20 + gate 10 + lane TX 20 + NIC TX 240). Rule 2 keeps every pending packet's dequeue age
≤ 500 ns (03 `ARC_ADMIT_AGE_MAX_NS`), so the worst case (budget, REF) is RX 320 + wait 180 + shed
20 + 460 = **980 ns**, the threshold. The BBO core applies the same two rules to forwarded ops
(`05-engine.md`). Its `BUSY` path, from the `Shed` step, is 10 + one BBO → lane hop 100 + lane 40
+ NIC TX 240 = 390 ns, now 35 ns longer than the 355 ns fill path from a step. So a head that
cannot start its step now is shed once its age + 390 + 15 > 980 (03 §6.0), and every BBO `BUSY`
also arrives in time.

**The two kinds of `BUSY`, as the client sees them:**

| | Lane shed | BBO-core shed |
|---|---|---|
| Decided by | the lane, test D, after V1–V5 and before V6 | the BBO core, as a `Shed` step |
| Logged as | `PacketRecord.flags.SHED` | `StepRecord`, kind `Shed` |
| Record | in-stream: one response packet with the next `resp_seq` and `echo_pkt` = the shed `pkt_seq`, holding one `Reject BUSY` (24) per message of the packet (a `Heartbeat` or `ResendReq` included) at its index, detail 0, `client_tag` 0; frame-gated on the `SHED` record (01 §14.5) | in-stream `Reject BUSY` (24) at the shed message's index, its `client_tag`, sent by the session's lane |
| Packet accepted | no: **the whole packet was not applied**, `expected` is unchanged | yes: `pkt_seq` is consumed |
| What took effect | nothing; no bucket, no fee | every message of the packet except the shed ops, with the outcome of index order minus those ops |
| Client action | resend from `echo_pkt` (go-back-N), same `pkt_seq` and the same logical content (D3), bit0 = 1 | send the shed message again in a new packet |
| Arrives | ≤ `LAT_MAX_NS` | ≤ `LAT_MAX_NS` |

**Matching a lane `BUSY` (05 §6.8, §18 Q17).** A lane-shed `Reject BUSY` carries `client_tag` 0:
the lane reads none of a shed packet's messages, and replay rebuilds the response from the
`SHED` record alone. The client matches it to its packet by `echo_pkt` (the shed `pkt_seq`) and
to a message by `index`, and takes the tag from its own copy of that packet. A BBO-core `BUSY`
keeps the message's `client_tag`. Every shed packet gets its own `BUSY` run, with no holdoff.

A later message of the same packet that lists a shed op in its dependency list, or names the
handle pre-assigned to it, is shed with it and gets its own `Reject BUSY`. Every shed decision is
read from the log on replay, never recomputed, so `INV-DET` holds. A lane shed skips V6 because
it changes no state: no packet is applied and nothing can close. The `BUSY` goes only to the
bound address, tagged with `K_out`.

**`BUSY`, gapless `pkt_seq` and deduplication.**

- A lane `BUSY` never acknowledges a request. Its packet takes a `resp_seq` like every in-stream
  response, so the response stream of §5.3 stays gapless and the client finds a lost `BUSY` run
  as it finds any lost response. It is the one in-stream response that is not an
  acknowledgement: `echo_pkt` = p says only that p was shed (§5.1).
- After a lane shed of p, packets p + 1, … of the session are shed too while the lane sheds
  (each with its own `BUSY` run), or are gaps once it stops (§5.1). Either way the client goes
  back to the lowest shed `pkt_seq` it holds unacknowledged. Go-back-N needs no special case.
- A resend of a shed p is a first acceptance, not a duplicate. G1 holds: p executes once.
- Test D runs before V8, so a duplicate can be shed too. The client resends it with bit0 = 1, and
  the duplicate path of §5.2 answers (the ring's copies, or `BAD_SEQ` with detail = `expected`).
- What each lane class can expect at the reference workload is §3.6. `BUSY` answers overload
  within 1 µs. It is never a normal outcome, and a client counts it.

### 3.6 Lane classes and `LANE_PACE` (01 §14.15, §14.17.2)

The lane map in the key bundle (§4.4) gives each account its class. A **dedicated** lane serves the
accounts of one firm only (a large firm may hold several lanes). A **pooled** session belongs to
the pool of 7 cores (lanes 42–48 on REF); its `SessionId` names its home pool core, and any pool
core may process its packets (§4.7).

**`LANE_PACE`, the SDK pacing rule for dedicated lanes.** The SDK keeps one pacer per dedicated
lane, shared by all of the firm's sessions on that lane, and sends packet n+1 on the lane no
earlier than

```
t_send(n+1) ≥ t_send(n) + lane_ns(n) + PROTO_PACE_MARGIN_NS + PROTO_PACE_JITTER_NS
lane_ns(n)   = 45 + count(n) × (LANE_PASS1_NS + LANE_APPLY_NS) + PROTO_RESP_BUILD_NS   (01 §14.2)
             = 45 + 14 × count(n) + 20        (REF; the bundle publishes the table per target)
```

The margin (10 ns) pays for the lane's background slices (fill-event settlement, control ops,
credit refills); the jitter term (25 ns) covers compression of the gap by the leaf switch. So at
the NIC the gap is never shorter than the previous packet's lane work, and the packet never waits
in the lane (02 §4.4.1). A 10-message packet then occupies a 240 ns slot, so one dedicated lane
takes ≤ 4.2M full packets/s from a paced firm. Packets the pacer delays wait in the SDK; that
delay is not part of the 1 µs, which starts at the exchange NIC. A firm whose sessions send from
several hosts either gives each host its own lanes or coordinates one pacer. A firm that does not
pace can make only its own packets wait; no other client can reach its lane.

**What each class can expect for `BUSY` (02 REQ-LAT-5, 01 §14.17.2):**

| Lane class | Lane stage | Total, full book load (1B msgs/s) | Total, ≤ 20% book load |
|---|---|---|---|
| dedicated, paced | 0 | ≤ 10⁻⁵ of packets, crosses and improves only (shared BBO, TX and order-stream stages) | ≤ 10⁻⁸ |
| dedicated, unpaced | only from the firm's own bursts | as paced, plus its own lane waits | — |
| pooled | M/M/7 queue | ≈ 10⁻³ of packets (computed 4.2 × 10⁻⁴) | ≤ 10⁻⁶ |

B3 measures every class and publishes the curves. Under every class, every packet still gets its
first record or its `BUSY` within `LAT_MAX_NS`.

## 4. Sessions

### 4.1 SessionId layout

The exchange assigns every `SessionId`. Its bits have this meaning:

```
 31            20 19        12 11           0
┌────────────────┬────────────┬──────────────┐
│ generation u12 │ LaneId u8  │ slot u12     │
└────────────────┴────────────┴──────────────┘
```

- `slot` indexes the lane's session table directly (`MAX_SESSIONS_PER_LANE` = 4,096 = 2^12).
- `LaneId` names the lane, so the lane decides V2 with one compare and one load, with no hash
  table that an attacker could probe.
- `generation` increases each time a slot is reused, so a stale `SessionId` never matches a new
  session. It wraps after 4,096 reuses of one slot.
- A session never changes lane. An account that the operator moves gets new sessions (§4.7).
- The same `SessionId` is valid in every home. Every home runs the same lane count.

### 4.2 Session state

The session's lane is the only writer of every field below (`INV-WRITER`). Control records from
`vyrn-admin` or the chain reach the lane through the order stream, and the lane applies them.

| Field | Meaning |
|---|---|
| `id`, `account`, `books` | Identity. `books` is the set of `BookId` the session may trade, all on this box. |
| `state` | `OPENING`, `ACTIVE`, `DRAINING`, `CLOSED`, `FREE` (§4.3) |
| `bound` | One (IPv4 address, UDP port). The source of every accepted packet and the destination of every response. |
| `k_seq`, `k_out`, `k_com_hash` | Keys of the current epoch for this box; the next epoch's keys once issued (§4.6). |
| `expected` | Next `pkt_seq` to accept. Starts at 1. |
| `next_resp` | Next in-stream `resp_seq`. Starts at 1. |
| `ring_oldest` | Oldest `resp_seq` of the session still in the lane's response ring (§5.4). |
| `buckets` | GCRA state of the session's buckets (§9). |
| `cod`, `timeout_ms`, `last_rx`, `stale` | Cancel-on-disconnect option and liveness (§4.8). |
| `close_cause` | Set when the session enters `CLOSED`. |

Everything except `ring_oldest`, the lane's response ring, the counters and the out-of-stream
holdoff is part of the replicated state. The ring is derived state: in-stream responses are a
function of the order stream, so the warm standby `vyrn-seq` (01 §14.4) and the next home's
sequencer rebuild it by replay. It is not committed in the state root. Sessions survive epoch
boundaries (01 §14.8, H8).

### 4.3 State machine

```
            OpenSession accepted (admin channel in BASE, chain tx in CHAIN)
                                  │
                                  ▼
                           ┌────────────┐  open record not in the final log
                           │  OPENING   │─────────────────────────────► gone (client opens again)
                           └─────┬──────┘
                                 │ lane applies SessionOpen; reply to the client once it is final
                                 ▼
       timeout: COD fires  ┌────────────┐  Logout or admin drain
       stale = true ┌──────│   ACTIVE   │──────────────────────┐
       next packet  └─────►│            │                      ▼
       clears it           └─────┬──────┘               ┌────────────┐
                                 │                      │  DRAINING  │── no resting orders,
          bad MAC from bound,    │                      └─────┬──────┘   or PROTO_DRAIN_MAX_MS
          equivocation, admin    │                            │                 │
          kill, lane move        ▼                            ▼                 ▼
                           ┌──────────────────────────────────────────────────────────┐
                           │ CLOSED: no packet accepted. Resting orders stay unless   │
                           │ COD; their later records still enter the session stream. │
                           └─────────────────────────┬────────────────────────────────┘
                                                     │ no resting orders, PROTO_CLOSED_KEEP_S
                                                     ▼
                                                   FREE (slot reusable; generation + 1)
```

| State | Lane accepts | Notes |
|---|---|---|
| `OPENING` | nothing (V2 fails: the slot is not yet live) | `vyrn-admin` does not give the client its keys until `ACTIVE` is final. |
| `ACTIVE` | everything | `stale` is a flag inside `ACTIVE`, not a state. |
| `DRAINING` | `Cancel`, `Reduce`, `CancelAll`, `Heartbeat`, `ResendReq`. `New` and `Replace` get `SESSION_CLOSED`. | Lets a client leave cleanly while it still sees its last fills. |
| `CLOSED` | nothing; out-of-stream `SESSION_CLOSED` under holdoff | The response stream still grows if resting orders trade. The recovery service serves it. |
| `FREE` | nothing (V2 fails) | — |

When a session enters `CLOSED`, the lane emits a final in-stream record: `Reject BAD_MAC` with
detail = the offending `pkt_seq` (cause `BAD_MAC`), or `Reject SESSION_CLOSED` with detail = the
close cause (every other cause). Both have index 0xFF.

| Close cause (`PROTO_D_*`) | Value | Trigger |
|---|---|---|
| `LOGOUT` | 1 | the client's `Logout`, at the end of `DRAINING` |
| `BAD_MAC` | 2 | V6 failure from the bound address with a matching `epoch16` (01 §14.8) |
| `EQUIVOCATION` | 3 | two validly tagged copies with different logical content (§2.4) |
| `ADMIN_KILL` | 4 | operator session kill (`CtlKillSession`, `10-accounts-risk-md.md`). An account kill does not close sessions: their `New` and `Replace` get `ACCOUNT_KILLED` (21), and cancels still work |
| `LANE_MOVED` | 5 | the account moves lane at an epoch boundary (§4.7) |
| `BOND` | 6 | CHAIN: the session bond fell below its minimum (`09-chain.md`) |
| `DRAINING` | 7 | used only as the detail of a `SESSION_CLOSED` for `New` or `Replace` in `DRAINING` |

### 4.4 BASE mode: open over the admin channel

In BASE mode the client opens a session over a TLS 1.3 connection to `vyrn-admin`, outside the
order-entry path:

- Mutual TLS. Each account has a client certificate from the exchange's CA. TLS 1.2 and earlier
  are refused.
- The channel stays open for the life of the session. `vyrn-admin` pushes status and key bundles
  on it. If it drops, the client reconnects. The UDP session is not affected.
- `vyrn-admin` implements the admin messages (`11-build.md`). This chapter fixes their fields,
  and the tables after the structs fix their bytes. `tests/golden/vyrn_admin_vectors.out` holds
  an `OpenSessionReq` and an `OpenSessionResp` built from these tables, and frames a receiver
  must refuse.

```rust
struct OpenSessionReq {
    account: AccountId, books: Vec<BookId>, proto_version: u16,   // 2 for this chapter (§12)
    src: SocketAddrV4,                                            // becomes the bound address
    cod: Cod,                                                     // Off | On
    timeout_ms: u32,                                              // §4.8
    rate_tier: u8,                                                // §9, limits from 10
    attest: bool,                                                 // §7.5 Attest records
}
struct OpenSessionResp {
    session: SessionId, lane: LaneId, epoch: Epoch,
    bundle: KeyBundle, limits: Limits, active_from_step: StepId,
}
struct KeyBundle {
    epoch: Epoch, home: HomeCode, boundary_ts: Nanos,             // end of this epoch (TAI)
    seq_index: u8,                                                // box that is the sequencer now
    failover_order: [u8; N_MAX],                                  // order of successors
    boxes: [BoxKeys; N_MAX],                                      // every box of the home
    data: [SocketAddrV4; 8],                                      // D4 preference order
    next_home: HomeCode, lane_move: Option<LaneId>,               // §4.7
}
struct BoxKeys {
    index: u8, order: SocketAddrV4, recovery: SocketAddrV4,
    k_seq: [u8; 16], k_out: [u8; 16],
}
// Other operations: GetKeyBundle(epoch), Rebind(src), Logout, SetCod(Cod).
// Pushes: KeyBundle(e+1), DataTierStatus, SequencerStatus.
```

**Encoding.** Every admin message on the TLS stream is one frame: `len` u32 (bytes after this
field), `type` u16, then the body. All integers are little-endian, like 01 §6. `SocketAddrV4` is 4 bytes of IPv4 address in network order, then the
port u16 little-endian. A receiver rejects a frame with a nonzero reserved byte, an unknown
`type`, or a `len` that does not match the body (VR1). Types: 0x0001 `OpenSessionReq`,
0x8001 `OpenSessionResp`, 0x8002 `KeyBundle` push, 0x80FF `Error` (body: a 01 §6.5 reason u16,
reserved u16, detail u32).

`OpenSessionReq` body (20 + 2 × `n_books` bytes):

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | `account` | `AccountId` |
| 4 | 2 | `proto_version` | 2 (§12) |
| 6 | 1 | `cod` | 0 `Off`, 1 `On` |
| 7 | 1 | `rate_tier` | 0–3 (T0–T3, 10) |
| 8 | 6 | `src` | `SocketAddrV4` |
| 14 | 1 | `attest` | 0 or 1 |
| 15 | 1 | `n_books` | 1–255 |
| 16 | 4 | `timeout_ms` | `PROTO_TIMEOUT_MIN_MS` ..= `_MAX_MS` |
| 20 | 2 × `n_books` | `books` | `BookId` each, no duplicates |

`OpenSessionResp` body: `session` u32 | `lane` u8 | reserved u8 | `n_limits` u16 | `epoch` u32 |
`active_from_step` u64 | then `n_limits` entries of { limit id u8 (10 §3.4), reserved [u8; 7],
value u64 } | then the `KeyBundle` body.

`KeyBundle` body: `epoch` u32 | `boundary_ts` u64 | `home` u8 | `seq_index` u8 | `next_home` u8 |
`n_boxes` u8 | `lane_move` u8 (0xFF = none) | reserved [u8; 3] | `failover_order` [u8; n_boxes] |
`data` 8 × `SocketAddrV4` | then `n_boxes` entries of `BoxKeys` { `index` u8, reserved u8,
`order` `SocketAddrV4`, `recovery` `SocketAddrV4`, `k_seq` [u8; 16], `k_out` [u8; 16] } (46 bytes
each).

```
 client                    vyrn-admin                      sequencer lane      replicas
   │── TLS 1.3 (mTLS) ───────►│                                   │                 │
   │── OpenSessionReq ───────►│ pick slot, gen+1, derive keys     │                 │
   │                          │── SessionOpen control record ────►│ OPENING→ACTIVE  │
   │                          │                                   │── PacketRecord ►│
   │                          │◄───────────────── block with the record is final ───│
   │◄─ OpenSessionResp ───────│ (keys, lane, endpoints)           │                 │
   │── request pkt_seq 1 (UDP) ──────────────────────────────────►│                 │
```

Budget: an open takes ≤ 50 ms, most of it TLS and the finality of the open record. Opens are
never on the 1 µs path. From `E_pq` (01 §14.20 G) the admin TLS 1.3 stream accepts only the hybrid
key-exchange group `X25519MLKEM768`, because it carries `k_seq` and `k_out`: +2,272 B and under
0.1 ms per handshake. Which TLS provider does it is open question PQ-12.

`vyrn-admin` gives each box only the keys of that box. The replicas of the home also receive
every box's `k_seq`, so they can check `tag_seq` on the data copies they use (§2.4). BASE mode
trusts the operator with client keys. CHAIN mode does not (§4.5).

`Rebind(src)` changes the bound address. It reaches the lane as a control record and takes effect
at that record's place in the order stream. From then on, V3 checks the new address and responses
go to it.

### 4.5 CHAIN mode: open by transaction (summary)

`09-chain.md` is normative for everything in this section.

- The wallet signs an `OpenSession` transaction (Ed25519 or secp256k1, 01 §4). It carries the
  account, an X25519 public key of the client, the source address to bind, the COD option, the
  timeout, the protocol version, the bond, and the hash-chain commitments for `K_com`. For each
  epoch from `E_pq` it also carries ML-KEM-768 ciphertexts to the validators' and committee keys
  (09 §5.2).
- When the transaction is final, the state machine assigns the `SessionId` deterministically from
  the account's lane. The client reads it from the receipt.
- Each validator `v` and the client derive the per-epoch keys from X25519 between the client key
  and `v`'s static key, then BLAKE3 `derive_key` with context `"vyrn v1 session"`, the
  session and the epoch. That yields `K_seq(e, v)` and `K_out(e, v)`. From `E_pq` the derivation
  also takes the ML-KEM-768 secret of the session's ciphertext to `v` (01 §14.20 G); the keys keep
  their 16-byte size, so the packet path does not change.
- `K_com(e, s)` exists for each validator `s` that can be the sequencer in epoch e. Every
  validator except `s` holds it. A packet uses `K_com(e, s)` for the current sequencer `s`. So
  after a failover to `s'`, the new sequencer does not hold the commit key that its own packets
  use, and forging still needs two byzantine validators.
- `K_com` values are disclosed after the epoch's last block is final (TESLA style), so anyone can
  verify every `tag_com` in the log afterwards.
- A client that cannot reach the sequencer may send the same packet to any validator's inclusion
  port. The state machine places it at a block boundary. Deduplication by (`session`, `pkt_seq`)
  applies there too.

### 4.6 Keys and rotation

| Key | One per | Held by | Covers | Rotates |
|---|---|---|---|---|
| `K_seq(e, b)` | session, epoch, box `b` of the home | client, box `b`; in BASE also the home's replicas | `tag_seq` of packets sent to box `b` | every epoch |
| `K_out(e, b)` | session, epoch, box `b` | client, box `b` | `tag` of responses sent by box `b` | every epoch |
| `K_com(e, s)` | session, epoch, sequencer `s` (CHAIN only) | client, every validator except `s` | `tag_com` | every epoch; disclosed after it ends |

All three are 16-byte SipHash-2-4 keys. In BASE mode `tag_com` is 0 and the lane ignores it. In
CHAIN mode the sequencer ignores `tag_com`, and the other validators check it before they vote.

Timeline around the boundary T between epoch e and e + 1:

```
 T − PROTO_KEY_PREISSUE_S   bundle for e+1 available (BASE: pushed over admin; CHAIN: derivable)
 T − 600 s … T − 1 s        EpochNotice countdown (§7.4)
 T                          client switches: epoch16 = e+1, K_seq(e+1, ·), new home's endpoints
 T + PROTO_KEY_GRACE_S      client may delete K_out(e, ·); the exchange has deleted K_seq(e, ·)
```

A client that has no bundle for e + 1 at T cannot send in e + 1. Its session stays `ACTIVE` and
its timeout clock is paused (§4.8) until it fetches the bundle and sends.

Key load (computed): one key handles at most 100M packets/s × 28,800 s = 2.9 × 10^12 MACs per
epoch, below 2^42. A forger gets one try per session, because a bad MAC from the bound address
closes the session, and the chance that one try succeeds is 2^−64.

### 4.7 Lane assignment

- `vyrn-admin` (BASE) or the state machine (CHAIN) puts every session of an account on the
  account's lane (01 §1: an account belongs to one lane per epoch). The top firms by volume get
  dedicated lanes; every other account is pooled, and its sessions name a home pool core
  (10 §1.3, 01 §14.15).
- A pool core serves every session whose `LaneId` is in the pool (`serves()` in §3.1), so a packet
  another pool core takes from the home core's queue is not `WRONG_LANE`. The account token keeps
  one core per account at a time, and each take is logged (`AcctTake`, 01 §14.17.4).
- An operator moves an account to another lane only at an epoch boundary, and only to rebalance
  load. The move appears in the bundle for e + 1 as `lane_move`.
- At the boundary, the account's sessions on the old lane go `CLOSED` (cause `LANE_MOVED`) and
  their resting orders end with `Out` cause `LANE_MOVED`. The client opens new sessions on the
  new lane.

This rule keeps `Handle` and `SessionId` lane-local with no translation table. Moves are rare, so
their cost (one re-quote) is acceptable.

### 4.8 Heartbeats and timeouts

| Rule | Value |
|---|---|
| The client sends at least one packet every `PROTO_HB_IDLE_MS`. When it has nothing else to send, it sends a `Heartbeat`. | default 100 ms |
| The session timeout is chosen at open, in [`PROTO_TIMEOUT_MIN_MS`, `PROTO_TIMEOUT_MAX_MS`], and must be ≥ 3 × the client's heartbeat interval. | default `PROTO_TIMEOUT_DEFAULT_MS` = 350 ms |
| A packet that holds only `Heartbeat` messages gets an in-stream `EpochNotice` (R-ANSWER, §7.2). The client uses it to measure liveness and round-trip time. | — |

**Order-stream time.** The lane measures the timeout on order-stream time, never on the wall clock
(01 §11 rule 3). Lane time is the larger of the `rx_ts` of the last packet the lane processed and
the time of the last `TimerTick` record. `05-engine.md` and `07-replication.md` provide a
`TimerTick` for every lane at least once per `BLOCK_NS`, so an idle lane still sees time pass.

**On timeout:** the lane sets `stale`. If `cod = On`, it cancels the session's resting orders
(§4.9). The session stays `ACTIVE`: the next accepted packet clears `stale`. UDP has no
connection to lose, so a short outage on the client side costs its orders (if COD is on) and
not its session.

**The clock pauses** from the end of an epoch until the new sequencer's first step, and during a
failover, from the old sequencer's last record until the new one's first. The client cannot send
during those windows, so they do not count against it.

**Exchange silence, client side:** if the client has unacknowledged packets and gets no in-stream
response for `PROTO_CLIENT_SILENCE_MS`, it assumes a failover is under way (§5.6). It keeps
resending with backoff, and it asks `vyrn-admin` for `SequencerStatus` if no notice arrives within
`PROTO_CLIENT_FAILOVER_MS`.

### 4.9 Cancel-on-disconnect

Each session has a COD option, set at open and changed with `SetCod` (it takes effect at its
control record):

| Option | On timeout | On `CLOSED` (any cause) |
|---|---|---|
| `Off` | nothing | orders keep resting |
| `On` | cancel every resting order of the session, in every book of the session, auction orders included | the same |

COD cancels only orders that this session entered, not orders of other sessions of the same
account. Each canceled order gets `Out` with cause `DISCONNECT` in the session's stream. COD runs
once per stale episode. It is a deterministic op at the `TimerTick` or control record that
triggers it, so the replicas run it too.

## 5. Reliability

### 5.1 Request direction: gapless `pkt_seq`, go-back-N

- A session's packets carry `pkt_seq` = 1, 2, 3, … with no gap and no reuse (01 §6.1).
- The lane accepts only `pkt_seq = expected`. It never buffers a packet that arrives early. A
  lane with no reorder buffer has nothing to replay except the packets it accepted.
- **Acknowledgement is cumulative.** The lane accepts in order and allocates `resp_seq` in order,
  so any in-stream response with `echo_pkt = p ≥ 1` proves that every `pkt_seq ≤ p` was
  accepted, except a lane-shed `Reject BUSY` packet (§3.5): it takes a `resp_seq` but proves
  nothing about `pkt_seq`, because test D also sheds a duplicate or a packet after a gap. An
  out-of-stream `BAD_SEQ` with detail x proves that every `pkt_seq < x` was accepted.
- **Gap.** If `expected < pkt_seq ≤ expected + PROTO_SEQ_AHEAD` and the MAC is good, the lane
  drops the packet and sends out-of-stream `BAD_SEQ` with detail = `expected`, under the holdoff.
  The client then resends every packet from `expected` to its highest sent `pkt_seq`, in order,
  with flags bit0 = 1 (go-back-N).
- **Client timer.** If the oldest unacknowledged packet has no acknowledgement after
  `PROTO_REQ_RTO_US`, the client resends from it with bit0 = 1. The timer doubles on each
  expiry up to `PROTO_REQ_RTO_MAX_MS`, and resets on progress. Set `PROTO_REQ_RTO_US` to at least
  4 × the measured round trip.
- **Window.** The client keeps at most `PROTO_SEQ_AHEAD` packets unacknowledged. A packet beyond
  that is dropped at V5.

```
 client                                        lane (expected = 7)
   │── 7 ──────────────────────────────────────►│ accept, expected = 8
   │── 8 ────────────────────X (lost)           │
   │── 9 ──────────────────────────────────────►│ gap: drop, out-of-stream BAD_SEQ(8)
   │── 10 ─────────────────────────────────────►│ gap: drop (holdoff, counted only)
   │◄── resp(echo 7) ───────────────────────────│
   │◄── BAD_SEQ, detail 8 (resp_seq 0) ─────────│
   │── 8 (bit0) ── 9 (bit0) ── 10 (bit0) ──────►│ accept 8, 9, 10
```

Go-back-N costs one round trip of extra packets after a loss. Inside a colo, the round trip is a
few microseconds and loss is rare, so this is cheaper than a reorder buffer in every lane.

### 5.2 Duplicates and the resend flag

A packet with a good MAC and `pkt_seq < expected` is a duplicate. Flags bit0 says why the
client sent it:

| bit0 | Meaning | Lane action |
|---|---|---|
| 0 | The network duplicated the packet. | drop, count `PROTO_CNT_DUP` |
| 1 | The client resent it because it saw no answer. | resend, with bit0 = 1, every packet with `echo_pkt = pkt_seq` that is still in the lane's ring. If none is left there, send out-of-stream `BAD_SEQ` with detail = `expected`, which tells the client that the packet was accepted. Both draw from the session's `RESEND` bucket (§9). |

**Idempotency.** Each (`session`, `pkt_seq`) is accepted at most once, ever. `expected` is
replicated state, so this holds on a new sequencer after a failover and in a new home after a
handoff. A client may therefore resend any packet at any time, and the exchange executes it
once or not at all.

A resend to the lane carries the same logical content (D3) and goes to the data tier too (D2).
The lane does not compare a duplicate with the accepted packet. If the content differs, the
replicas detect equivocation (§2.4).

### 5.3 Response direction: gapless `resp_seq`

- In-stream response packets carry `resp_seq` = 1, 2, 3, … per session with no gap. Out-of-stream
  packets carry 0 and are outside this sequence.
- Two producers send a session's packets (§7.1), from different TX queues. So packets can arrive
  out of order by up to about 1 µs (budget). The client buffers out-of-order packets and
  processes them in `resp_seq` order.
- **Gap.** If `resp_seq` r is missing for `PROTO_RESP_GAP_WAIT_US` after a higher one arrived,
  the client sends `ResendReq(r, r')` for the missing range.
- **Tail loss.** If the last response is lost, nothing reveals the gap until the next response.
  A packet that holds only a `Heartbeat` gets an in-stream answer, so tail loss is found within
  one heartbeat interval at worst. A client that needs faster detection sends a `Heartbeat` sooner.
- The lane serves a `ResendReq` from its ring if the range is at most
  `PROTO_LANE_RESEND_MAX` packets and is still in the ring. Otherwise it rejects it with
  `BAD_SEQ` (§6.7), and the client uses the recovery service. `RESEND_GONE` (22) means that
  neither store holds the range (§5.4).

### 5.4 Retention: the lane ring and the recovery service

01 §5 sets `RESP_RETAIN_PKTS` = 65,536 response packets per session. They cannot all live in the
lanes:

| Store | Per session | Per lane (4,096 sessions) | Per box (49 lanes) |
|---|---|---|---|
| `RESP_RETAIN_PKTS` × 280 B (worst case) | 18.4 MB | 75 GB | 3.8 TB |
| `RESP_HOT_RING_BYTES` (01 §14.6) | shared | 4 GiB | 200 GiB |

(computed). So retention has two tiers (01 §14.6):

- **Response ring, on the sequencer.** One byte ring of `RESP_HOT_RING_BYTES` = 4 GiB per lane, in
  the lane's DRAM, shared by its sessions: ~8 s of in-stream responses at peak (budget), about
  15M packets of 280 B. The lane appends each in-stream packet as it sends it, and the oldest
  bytes are overwritten first. Each session's `ring_oldest` follows. The standby rebuilds the ring
  by replay (§4.2).
- **Recovery service, on a replica.** One `vyrn-replica` per home runs the `recovery` role. It
  keeps the last `RESP_RETAIN_PKTS` packets of every session, built from its own replay, on NVMe.
  At peak the response stream is of the same order as the request stream (budget ≤ 26 GB/s;
  `06-platform.md` sizes the drives). It keeps the stream of a `CLOSED` session for
  `PROTO_CLOSED_KEEP_S`.

**Recovery request.** The client sends to the recovery address of box b, port
`PROTO_RECOVERY_PORT`, a request packet with:

- `pkt_seq = 0` (never valid on the order port, so a recovery request can never be confused with
  order entry and never consumes a `pkt_seq`);
- `count = 1`, one `ResendReq(from, to)`, the current `epoch16`;
- `tag_seq` with `K_seq(e, b)` and `tag_com = 0`.

The service runs V1–V6 with the session's bound address, then sends the packets in the range with
bit0 = 1, tagged with `K_out(e, b)`, at most `PROTO_RECOVERY_PPS` per session. A V6 failure here
is dropped and counted and closes nothing: the service changes no state. A range newer than
the replica's replay is cut at the newest packet it holds, and the rest gets an out-of-stream
`BAD_SEQ` with detail = that newest `resp_seq`.

**`RESEND_GONE` (22).** Both stores are functions of the order stream, so each one knows the
other's oldest `resp_seq` per session: the lane computes the recovery bound as `next_resp −
RESP_RETAIN_PKTS`, and the recovery service tracks the ring's `ring_oldest` without storing its
bytes. A store that does not hold a range answers `BAD_SEQ` with detail = the oldest `resp_seq`
the **other** store holds, so the client goes there. Only a range that both stores have dropped
gets `Reject RESEND_GONE`, detail = the oldest `resp_seq` either holds. The client then rebuilds
its order state from the drop copy (`10-accounts-risk-md.md`).

### 5.5 Gaps in both directions: summary

| Event | Who detects | Signal | Recovery |
|---|---|---|---|
| Request lost | lane (next packet) or client (timer) | out-of-stream `BAD_SEQ`, or no acknowledgement | client resends from `expected`, bit0 = 1 |
| Request duplicated by the network | lane | — | dropped silently |
| Response lost, later ones arrive | client | `resp_seq` gap | `ResendReq` to the lane, or recovery |
| Last response lost | client | heartbeat answer reveals the gap | `ResendReq` |
| Request and its responses all lost | client (timer) | — | resend with bit0 = 1; lane resends from its ring |
| Lane overloaded | lane or BBO core (test D) | `Reject BUSY` ≤ 1 µs | lane shed: resend from `echo_pkt` (go-back-N); BBO shed: resend the message (§3.5) |
| Data copy lost | replicas | missing payload | `07-replication.md` repair; the client does nothing |

### 5.6 Sequencer failover

```
 t0          old sequencer sends its last frame, then dies
 t0 + 2 ms   replicas detect silence (FAILOVER_SILENCE_MS) and finalize the longest prefix they hold
 ≤ t0+20 ms  box b, the home's warm standby vyrn-seq (01 §14.4), starts as sequencer at the next step
             each lane of b emits, for every live session, one in-stream EpochNotice
             with next_epoch = current epoch (the sequencer-change variant, §7.4), resp_seq = r
 client      on that notice: switch the order endpoint and K_seq to box b,
             then resend every unacknowledged packet, bit0 = 1, to b (and to the data tier)
```

What the client sees, case by case:

| Case | What happens at box b |
|---|---|
| The old sequencer accepted the packet and its `PacketRecord` is in the final log | Duplicate. b resends the responses from its ring, rebuilt by replay, with the same `resp_seq` and the same records. |
| The old sequencer never accepted the packet | `pkt_seq = expected` at b. b executes it now, against the current book. |
| The old sequencer accepted it, but its records are not in the final log | The same as never accepted: b executes it now. |

**The rewind rule.** Let r be the `resp_seq` of the sequencer-change notice. Every in-stream
response that the client received from the old sequencer with `resp_seq ≥ r` is **void**: its
records are not in the final log, and box b will reuse those `resp_seq` values. The client undoes
the effect of the void records on its order state (§10) and treats their requests as unanswered.

A void response exists only if the old sequencer's frames were lost on both replication paths
before it died, because every in-stream response leaves after its records left on both paths
(rule R-FIRST, §7.2; 01 §14.5). A sequencer crash alone never voids a response: an acked order
is never lost. DESIGN §0 point 3 gives the odds of the double loss. The protocol makes that case visible and exact. It does not
make it common.

Until the notice arrives, the client keeps resending to the old box, and those packets are lost.
If no notice arrives within `PROTO_CLIENT_FAILOVER_MS`, the client asks `vyrn-admin` (BASE) or chain
state (CHAIN) for `SequencerStatus`.

### 5.7 Epoch handoff

```
 old home (epoch e)                      client                        new home (epoch e+1)
  │── EpochNotice T−600 … T−1 s ────────►│                                  │
  │   last step S at T; then drops all   │── from T: epoch16 = e+1 ────────►│ stages packets
  │   packets                            │   new K_seq, new endpoints       │ (08-epochs.md)
  │── finalize S, cert(e, S), log tail ─────────────────────────────────────►│ state at S
  │                                      │◄── EpochNotice (epoch start) ────│ starts at S+1
  │                                      │◄── answers to staged packets ────│ auction phase
  │                                      │◄── uncross fills (liq 2) ────────│ then continuous
```

| ID | Rule |
|---|---|
| H1 | Before T, the client holds the key bundle for e + 1 (§4.6). |
| H2 | At T, by its own clock (synchronized to ±1 ms, budget), the client stops sending to the old home. It sends every later packet to the new home's sequencer with `epoch16` = e + 1, `K_seq(e+1, b)`, and the new home's data tier. |
| H3 | It resends every packet not yet acknowledged to the new home, with bit0 = 1. Deduplication works because `expected` at step S is replicated state. |
| H4 | Between T and the epoch-start notice, the client sends each unacknowledged packet once and suspends its resend timer. The new home stages packets; it does not answer them yet. The silent window lasts one WAN one-way latency plus finality: 45–120 ms (DESIGN §6). |
| H5 | A packet with `epoch16` = e + 1 that reaches the old home before T, or one with `epoch16` = e that reaches the new home, gets out-of-stream `EPOCH_MISMATCH`, detail = the receiver's current epoch. |
| H6 | When the new sequencer starts, it runs §3 on the staged packets in `rx_ts` order. Before any other record, each session gets an epoch-start `EpochNotice`. Staged packets are the handoff window of 01 §14.0 item 2, the only window without a 1 µs answer: test D (§3.5) does not shed them, and the opening auction serves them. Packets sent after the epoch-start notice meet `LAT_MAX_NS` as usual. |
| H7 | Staged messages and messages until the uncross are in the auction phase (§6.9). |
| H8 | Sessions survive the boundary (01 §14.8): `expected`, `next_resp`, resting orders and handles carry over unchanged. A client does not reopen anything at a handoff unless its account moved lane (§4.7). |
| H9 | At the first step of each TYO epoch, before the auction, every resting `Day` order ends with `Out` cause `EXPIRED` (§6.2). |

## 6. Messages

### 6.1 Rules for every message

- Bytes 2–3 are 0 in every v1 message, and so is every field that 01 §6.2 marks 0 (M3).
- `client_tag` is opaque. The exchange echoes it and never checks it for uniqueness. `Replace`
  has no `client_tag`; its records carry the stored tag of the order it replaces.
- **Handles.** The lane assigns a `Handle` when it accepts a `New` or a priority-losing `Replace`.
  An operation on a handle succeeds only if the slot is live, its generation matches, and the
  order belongs to the session's account. Any other case is `UNKNOWN_HANDLE`, so a client cannot
  learn anything about another account's orders. `PROTO_HANDLE_ALL` = 0xFFFF_FFFF is never a real
  handle (slot 0xFF_FFFF is never allocated).
- **Handle reuse.** `05-engine.md` allocates slots so that a slot is reused no sooner than
  `PROTO_HANDLE_REUSE_MIN_S` after its order ended. The client never sends a handle older than
  that past the order's last record. With an 8-bit generation a much older handle could match a
  newer order of the same account.
- **Effective point.** Each message takes effect at one place in the total order: its `LaneSeq`
  for a lane op, its step for a BBO-core op. Messages of one packet take effect in index order.
  `canceled qty` and `TOO_LATE` are evaluated at that place.
- **Order flags** (01 §6.2): bit 0 side; bits 1–2 TIF (0 `Day`, 1 `IOC`, 2 `FOK`, 3
  `AUCTION_ONLY`); bit 3 post-only; bits 4–5 STP mode; bits 6–7 zero.
- **Invalid flag combinations** get `BAD_TYPE` with detail `PROTO_D_FLAGS`: post-only with
  `IOC` or `FOK` (one must not take, the other must take or die), and post-only with
  `AUCTION_ONLY` (an auction has no maker).

### 6.2 `New` (0x01)

Fields: flags, `tick`, `qty`, `client_tag`.

Validation, in M-order (§3.3; 10 §3.1 gives the full order with the rate buckets):

| Check | Reason | Detail |
|---|---|---|
| phase (§6.9) | `BOOK_HALTED`, `AUCTION_PHASE` | halt cause from 10; phase code |
| `qty` = 0, or > the account's `max_order_qty` | `BAD_QTY` | `RSK_D_QTY_ZERO` (1) / `RSK_D_QTY_MAX` (2) (10 §3.1) |
| `tick` below `min_tick` (0 included), above `max_tick`, or outside the price band of the lane's snapshot | `BAD_TICK` | the nearest acceptable tick: `min_tick`, `max_tick` or the band edge (10 §3.1 check 8) |
| notional above the account's `max_notional`; any overflow in the risk arithmetic | `BAD_QTY` | `RSK_D_NOTIONAL` (3); `RSK_D_OVERFLOW` (4) |
| resting orders of the account ≥ its limit; the lane's slot pool is full | `RISK_ORDER_COUNT` | the limit; `RSK_D_LANE_FULL` (5) |
| open exposure on that side would pass its limit (v2 only; v1 spot has no such limit, 10 §3.1) | `RISK_POSITION` | the limit |
| reservation (buy: `R_buy(qty, tick)` plus the message fee in quote; sell: `qty` in base and the message fee in quote, 10 §3.2) > free balance | `RISK_CREDIT` | `RSK_CREDIT_QUOTE` (1) or `RSK_CREDIT_BASE` (2): the asset that is short |

Routing after validation:

| TIF | Class against the lane's snapshot | Goes to | Possible records, in order |
|---|---|---|---|
| `Day` | join | lane | `Ack` (after a cut includes it, `INV-ACK-AFTER-CUT`) |
| `Day` | improve | BBO core | `Ack`; or, if the true book has moved, `Fill`… then `Ack` or nothing (fully filled) |
| `Day` | cross | BBO core | `Fill`… then `Ack` for a rested remainder, or nothing if fully filled; `Reject STP` or `Out STP` (§6.8) |
| `IOC` | any | BBO core | `Fill`… then `Out IOC_REMAINDER` unless fully filled. Zero fills give `Out IOC_REMAINDER` with the full qty. |
| `FOK` | any | BBO core | `Fill`… summing to `qty`; or `Reject FOK_UNFILLABLE`, detail = qty available at or better than the limit (capped) |
| `AUCTION_ONLY` | none (auction phase only) | lane | `Ack`; at the uncross `Fill` (liq 2)… then `Out AUCTION_UNFILLED` for any remainder |

Notes:

- `IOC` and `FOK` always go to the BBO core, even if they look non-marketable against the lane's
  snapshot. A snapshot can be stale in the unsafe direction after an improve, and an IOC must
  trade against the true book. They are charged as crosses (§9).
- A post-only order goes to the BBO core when the lane's snapshot classifies it as an improve or a
  cross (03 ARC-D6). The BBO core rejects it with `POST_ONLY_WOULD_CROSS` if the true book
  crosses it, with detail the best opposite tick of the true book, and rests it otherwise. The
  lane never decides it against the snapshot, whose version is not logged, so replay reproduces
  the outcome and the detail. If a rescan (`05-engine.md`) finds a resting post-only
  order as the aggressor, that order ends with `Out` cause `POST_ONLY`, after its `Ack`.
- A taker gets one `Fill` per price level, best level first (01 §6.4). The remainder of a `Day`
  order rests at its own limit `tick`, and its `Ack` carries that tick.
- `Day` means the trading day. The trading day ends at the TYO boundary (00:00 UTC,
  `EPOCH_BOUNDARIES_UTC`). Resting `Day` orders survive the LDN and NYC handoffs and end with
  `Out EXPIRED` at the first step of the next TYO epoch (H9).

### 6.3 `Cancel` (0x02)

Fields: `handle`, `client_tag`.

| Order state at the Cancel's effective point | Records |
|---|---|
| live (resting, or in the auction) | `CancelAck(handle, canceled qty = open qty, client_tag)` |
| ended, slot not yet reused | `Reject TOO_LATE`, detail = how it ended: `PROTO_D_FILLED` 1, `PROTO_D_CANCELED` 2, `PROTO_D_OUT` 3 |
| slot free, generation differs, or another account's order | `Reject UNKNOWN_HANDLE`, detail 0 |

Cancel against fill: the cut orders them (DESIGN §3). Fills at earlier steps reduce the open qty
first, so `canceled qty` is what was left. If nothing was left, the answer is `TOO_LATE`. Every
`Fill` of the order that precedes the Cancel in the total order has a lower `resp_seq` than the
`CancelAck` (R-HANDLE, §7.2).

### 6.4 `Reduce` (0x03)

Fields: `handle`, `reduce_by`, `client_tag`.

- `reduce_by = 0` → `Reject BAD_QTY`.
- Live order: `canceled = min(reduce_by, open)`. The open qty and the order's total qty both fall
  by `canceled`. The order keeps its handle and its time priority. Record:
  `CancelAck(handle, canceled, client_tag)`.
- **Reduce to 0.** If `reduce_by ≥ open`, the order ends. The record is the same `CancelAck`, with
  `canceled = open`. The client knows the order ended because its open qty, tracked in
  `resp_seq` order, is now 0 (§10).
- Ended order → `TOO_LATE`. Unknown handle → `UNKNOWN_HANDLE`. Both as for `Cancel`.

### 6.5 `Replace` (0x04)

Fields: flags (the full order flags of the replacement; the side must match), `handle`, new
`tick`, new `qty`.

**`qty` is the new total quantity of the order**, filled part included. Let `total` be the order's
quantity after earlier Reduces, `cum` its filled quantity, and `open = total − cum`. Total-qty
semantics mean that a fill racing the Replace can never make the account trade more than the new
`qty`.

Lane checks, in this order. Any failure gives one `Reject` with the order's stored `client_tag`
and **leaves the old order untouched**:

| Check | Reason |
|---|---|
| handle unknown / ended | `UNKNOWN_HANDLE` / `TOO_LATE` |
| side differs | `SIDE_MISMATCH` |
| phase (§6.9) | `BOOK_HALTED`, `AUCTION_PHASE` |
| new `tick` out of band or 0 | `BAD_TICK` |
| new `qty` = 0 (use `Cancel`); or same tick, same `total`, same flags | `BAD_QTY` (detail 0, or `PROTO_D_NO_CHANGE`; the new order's risk checks give 10's `RSK_D_*`, §8) |
| invalid flag combination | `BAD_TYPE` (`PROTO_D_FLAGS`) |
| risk of the new reservation, net of the old one | `RISK_*` |

Then one of two cases:

| Case | Condition | Effect | Records |
|---|---|---|---|
| **Reduction** | same `tick`, same flags, new `qty` < `total` | executed as `Reduce` by `total − qty`: same handle, priority kept | `CancelAck(handle, min(total − qty, open))` |
| **Priority loss** | anything else | at the effective point, the old order is canceled. If `qty > cum`, a new order enters with a new handle, `open = qty − cum`, the new tick and flags, and is classified and routed like a `New`. If `qty ≤ cum`, no new order enters. | `CancelAck(old handle, open of old)`, then the new order's records (§6.2), all with the Replace's index |

- A priority-loss Replace whose new order goes to the BBO core has all its records, the
  `CancelAck` of the old order included, in the B-packet (§7.1). So the `CancelAck` always comes
  first.
- Outcomes that only the BBO core can decide (fills, `STP`, `POST_ONLY_WOULD_CROSS` against the
  true book, `FOK_UNFILLABLE`) happen after the old order is canceled. They are outcomes of the
  new order, not a rejection of the Replace.
- The client tells the cases apart by the handle: the same handle in the `CancelAck` and no `Ack`
  means a reduction. A new handle means priority was lost.

### 6.6 `CancelAll` (0x12)

Fields: `client_tag`. Scope: every live order that this session entered in the packet's `book`
and whose `New` or `Replace` precedes the CancelAll in the total order. Orders of other sessions
of the same account are not touched (use `vyrn-admin` for an account-wide kill).

Records, all with the CancelAll's index and `client_tag`:

1. one `CancelAck(handle, canceled qty)` per canceled order, in ascending handle order;
2. then a summary `CancelAck(PROTO_HANDLE_ALL, number of orders canceled)`. The summary is always
   sent, also when the count is 0, so the client knows the CancelAll is complete.

The CancelAll takes effect at once, at its effective point, with one `AcctKill` write
(`05-engine.md` §4.7): from that point no covered order can trade. So its apply cost does not grow
with the order count, and its first record leaves within `LAT_MAX_NS` like any message. Only the
per-order records grow with the count. They follow in later L-packets with `echo_pkt = p` at the
lane's record rate, and the summary comes last. `CancelAll` draws `PROTO_CANCELALL_TOKENS`
message tokens, so it cannot be used to stall a lane.
An order still at the BBO core at the CancelAll's effective point is canceled if it comes to
rest; `05-engine.md` defines how the lane learns that.

### 6.7 `Heartbeat` (0x10) and `ResendReq` (0x11)

`Heartbeat` has no fields. It produces no record of its own. A packet whose messages produce no
record gets an `EpochNotice` (R-ANSWER, §7.2), so a heartbeat sent alone is always answered. It consumes a `pkt_seq` like any packet and draws from the packet bucket.

`ResendReq(from, to)` asks the lane to resend in-stream packets `from` … `to`, inclusive:

| Condition | Result |
|---|---|
| `from = 0`, or `from > to` | `Reject BAD_SEQ`, detail = `next_resp − 1` |
| `to ≥ next_resp` (not yet sent) | `Reject BAD_SEQ`, detail = `next_resp − 1` |
| `to − from + 1 > PROTO_LANE_RESEND_MAX` | `Reject BAD_SEQ`, detail = `from + PROTO_LANE_RESEND_MAX − 1` |
| `from` older than the lane's ring, still held by recovery | `Reject BAD_SEQ`, detail = the oldest `resp_seq` the recovery service holds; use recovery (§5.4) |
| `from` older than both stores | `Reject RESEND_GONE` (22), detail = the oldest `resp_seq` either holds (§5.4) |
| otherwise | the packets, resent with bit0 = 1 |

A resent packet keeps its `resp_seq`, `echo_pkt`, `count` and records. Its `epoch16` and tag are
those of the epoch and the box that resends it. The resends are not in-stream records, so a
packet that holds only `ResendReq` messages also gets an `EpochNotice` (R-ANSWER). Resends draw
from the `RESEND` bucket (§9). The resent packets are copies and change no state.

### 6.8 STP

STP prevents a trade between two orders of the same `AccountId`. Only the aggressor's mode
applies (the order that is later in the total order, also in a rescan).

| Mode | Resting order | Aggressor, no fill yet | Aggressor, after some fills |
|---|---|---|---|
| 0 none | trades | trades | trades |
| 1 cancel newest | untouched | `Reject STP`, detail = the resting handle | `Out STP`, qty out = remaining |
| 2 cancel oldest | `Out STP` (unsolicited, to its session) | continues matching | continues matching |
| 3 cancel both | `Out STP` (unsolicited) | `Reject STP` | `Out STP` |

Mode 0 allows self-trades. `10-accounts-risk-md.md` monitors them. STP in the opening auction
uncross follows `08-epochs.md`.

### 6.9 Book phases

| Message | `CONTINUOUS` | `AUCTION` (opening auction after a handoff) | `HALTED` |
|---|---|---|---|
| `New Day` | yes | yes: rests in the auction, `Ack` now, fills at the uncross, then rests on | `BOOK_HALTED` |
| `New IOC`, `New FOK` | yes | `AUCTION_PHASE` | `BOOK_HALTED` |
| `New` post-only | yes | `AUCTION_PHASE` | `BOOK_HALTED` |
| `New AUCTION_ONLY` | `AUCTION_PHASE` | yes: ends at the uncross | `BOOK_HALTED` |
| `Replace` | yes | yes, with the rules of the new order's TIF | `BOOK_HALTED` |
| `Cancel`, `Reduce`, `CancelAll` | yes | yes | yes |
| `Heartbeat`, `ResendReq` | yes | yes | yes |

The `AUCTION_PHASE` detail is the current phase (`PROTO_PHASE_*`: 1 continuous, 2 auction,
3 halted). Resting orders stay in a halted book. `08-epochs.md` owns the auction's timing and its
uncross. `10-accounts-risk-md.md` owns halts.

## 7. Responses

### 7.1 Producers and the `resp_seq` allocator

Two kinds of core send a session's response packets: its lane and the TX cores (TX-A, TX-B,
TX-C on cores 3, 5 and 0, 01 §14.17.3). Only the lane allocates `resp_seq`; a TX core uses
numbers the lane reserved for it.

| Producer | Sends | `resp_seq` |
|---|---|---|
| The session's **lane** | records of lane-local messages (joins, cancels, reduces, lane rejects, `CancelAll`); auction fills; `EpochNotice`; COD and expiry `Out`; overflow records of the B-packet | allocates |
| The **TX core** on CCD 0 | the **B-packet**: the records of the BBO-routed messages of one request packet (taker `Fill`, `Ack` of a rested remainder or an improve, `Out`, BBO-core `Reject`, the old-order `CancelAck` of a priority-loss Replace); **maker packets**: the maker `Fill` and unsolicited `Out STP` of a resting order, in the step that caused them | B-packet: the value the lane reserved; maker packets: the session's maker range |

**Reservation.** When the lane accepts a request packet with at least one BBO-routed message, it
allocates `resp_seq` r for the B-packet before any other `resp_seq` of that packet, and passes r
with the first message it pushes to the BBO core. The lane's own packet for the same request (the
L-packet) gets r + 1. A request packet with no BBO-routed message gets only an L-packet.

```
 request pkt p:  [0] Cancel h1   [1] New cross   [2] New join
                      │               │               │
 lane:                │  reserve r ───┼──► BBO ring   │
                      ▼               │               ▼
                 L-packet r+1: CancelAck(0), Ack(2)   (after a cut includes them)
 BBO core → TX core:  └────────────► B-packet r: Fill(1) … Ack(1)   (≤ 1 µs path)
```

Rules:

- A B-packet is never empty: every BBO-routed message yields at least one record.
- The B-packet holds up to 16 records of the packet's BBO-routed messages, in index order. The TX
  core keeps one slot free for each later BBO-routed message of the packet (the lane passes their
  count with the first push), so **every BBO-routed message has its first record in the
  B-packet**, which leaves within `LAT_MAX_NS`. A message's records that do not fit are its later
  fills and terminal record. The lane settles the taker side from the fill events, so it knows
  which records did not fit. It sends them in its next packets with `echo_pkt = p`, before any
  later record of the session. The L-packet follows the same rule for lane-local messages.
- **Maker fills** (01 §14.14, §14.17.5). The TX cores send them in the step that made them, right
  after the taker's B-packet, with no hop through the maker's lane: +16 ns per maker packet on
  each TX core (`PROTO_MAKER_PKT_NS`, budget). The maker fills of the **first steps** of a sweep
  leave within `LAT_MAX_NS` of the first bit of the taker's packet; 01 puts this at about 40
  makers at index 9, more at lower indices. The maker fills of **later continuation steps** leave
  within `LAT_MAX_NS` of the start of their own step. The taker's first fill is always within
  1 µs. A maker fill is a notice to another client, not the response to the maker's own packet, so
  this exempts no response. The maker's lane still settles the balance from the fill event, off
  the latency path, and appends the packet to its response ring then.
- **Maker range.** For each session with resting orders, the lane keeps a credit of
  `PROTO_MAKER_RANGE` = 16 numbers in the session's maker-range line, which the lane writes and
  the TX core reads. The TX core takes the next number of the credit for each maker packet and
  writes its own `used` counter. The lane refills the credit by 16 when its applied fill events
  show 8 used. One step writes at most `STEP_FILL_CAP` = 64 fill records (01 §14.15), so it
  needs at most 4 maker packets of one session, and a longer sweep continues in further steps. The
  credit is therefore never exceeded, and every order hit gets its maker record from the TX core.
- **Numbering rule (gapless, R-DET).** A session's `resp_seq` order is the merge of the maker
  packets, in step order, with the lane-numbered packets (B-packet reservations, L-packets,
  unsolicited lane packets), each of which sits at a lane position q (a `LaneSeq`). A maker packet
  of step s comes before a lane packet at q exactly when `cut_s[lane] < q`. To place a packet at q,
  the lane writes `(close_seq = q, n)` to the maker-range line before it publishes q, so every step
  whose cut includes q shifts the rest of the credit up by n. The lane numbers its packet after it
  has applied the fill events of every step before the first cut that includes q; it already
  waits for that before a `CancelAck` (R-HANDLE). So the numbers are relative, not a fixed
  absolute block: an unused number of the credit is never a gap, and an order's fills always
  follow its `Ack` in `resp_seq` order.
- This keeps `INV-WRITER`: the lane is the only writer of `next_resp`, of the credit and of
  `close_seq`; the TX core is the only writer of `used`. Both fill paths stay inside CCD 0 as in
  DESIGN §4.

### 7.2 Rules for in-stream packets

| ID | Rule |
|---|---|
| R-ANSWER | Every accepted request packet gets at least one in-stream record with `echo_pkt = pkt_seq`. If its messages produce no in-stream record (only `Heartbeat` and `ResendReq`), the lane adds one `EpochNotice`. |
| R-ECHO | A packet with `echo_pkt = p ≥ 1` holds only records that answer request p. Unsolicited records, maker packets included, go in packets with `echo_pkt = 0`. No producer delays a record to fill a packet. |
| R-MAKER | In one step, the taker's B-packet leaves before any maker packet. Maker packets of the first steps of a sweep leave within `LAT_MAX_NS` of the taker packet's first bit; those of later continuation steps within `LAT_MAX_NS` of their own step's start (01 §14.17.5). A maker packet may arrive before a lower-numbered lane packet of the maker's session; the client reorders by `resp_seq` (§5.3). |
| R-FIRST | Every response is frame-gated (01 §14.5, `INV-FRAME-FIRST`). An in-stream response, acks included, leaves only after the records of every op in the cut it depends on, and the record of its step, left on both replication paths. Core 4 drains the lanes' pre-encoded order rings, so the gate is normally open already (10 ns budget for acks, 60 ns for fills). |
| R-1US | The first record of every message of an accepted packet, at every index 0–9, leaves within `LAT_MAX_NS` (01 §14.0). So do the whole B-packet and the first L-packet. Maker packets follow R-MAKER. Only overflow records of a message or order already answered, `CancelAll`'s per-order records after the first, and resends follow later. |
| R-INDEX | Inside one packet, records are in ascending message index. Records of one message are in execution order: fills best level first, then the terminal record. |
| R-HANDLE | For one handle, records appear in `resp_seq` order in the order of their events in the total order. A `CancelAck` or `TOO_LATE` follows every `Fill` that precedes it. |
| R-ACROSS | Records of different messages of one request may sit in different packets (B and L) in either `resp_seq` order. The client matches them by index. Arrival order across B and L says nothing about execution order; the outcome is always that of index order (§3.1). |
| R-DET | The records of every in-stream packet are a function of the order stream. After a failover or a handoff, a resent packet has the same `resp_seq` and the same records. |
| R-MAX | At most 16 records per packet (01 §6.3). |

### 7.3 Records

| Record | Emitted when | Fields as used |
|---|---|---|
| `Ack` 0x81 | An order comes to rest: a join after its cut, an improve at its step, the remainder of a cross, a priority-loss Replace's new order, an order that enters the auction. Never for an order that never rests. | index; `handle`; `tick` = resting tick; `client_tag`. The resting qty is the order qty minus the fills before the `Ack`. |
| `Fill` 0x82 | An order trades. | index = the taker's message index, or 0xFF for a maker or auction fill; liq: 0 maker, 1 taker, 2 auction fill (01 §14.10); `handle`; `tick` = execution price; `qty`. |
| `Reject` 0x83 | A message, a packet (index 0xFF) or the session (index 0xFF, final record) is refused. | index; reason (§8); `detail`; bytes 8–11 = 0; `client_tag` (0 for index 0xFF). |
| `CancelAck` 0x84 | A `Cancel`, `Reduce`, reduction `Replace`, priority-loss `Replace` (old order), or `CancelAll` takes effect. | index; `handle` or `PROTO_HANDLE_ALL`; `canceled qty`, or the order count for the summary; `client_tag`. |
| `Out` 0x85 | The exchange ends an order, or the rest of one. | index = the message index if it answers a message, else 0xFF; cause (below); `handle`; `qty out`; `client_tag` = the order's stored tag. |
| `EpochNotice` 0x86 | §7.4 | — |
| `Bust` 0x87 | CHAIN only: a fill against a packet that failed `tag_com` is reversed by compensating transfers; the fill stays in the final log (01 §14.19 B, 09 §5.9). | layout in 09 |
| `Attest` 0x88 (01 §14.10) | Out of stream: a cumulative durability, finality or settlement point for the session (§7.5). | §7.5 |

`Reject` versus `Out`: `Reject` means the message had no effect on the book. `Out` means an order
that was in the matching step leaves the book. `Reject STP` and `Reject FOK_UNFILLABLE` are kills
with no fill; `Out STP` and `Out IOC_REMAINDER` follow fills or a match attempt.

| `Out` cause (`PROTO_OUT_*`) | Value | When |
|---|---|---|
| `IOC_REMAINDER` | 1 | the unfilled part of an `IOC` (01 §14.10) |
| `STP` | 2 | §6.8 (01 §14.10) |
| `AUCTION_UNFILLED` | 3 | the unfilled part of an `AUCTION_ONLY` order at the uncross (01 §14.10) |
| `EXPIRED` | 4 | a `Day` order at the end of the trading day (H9) (01 §14.10) |
| `POST_ONLY` | 5 | a resting post-only order that a rescan found as the aggressor (01 §14.10) |
| `LANE_MOVED` | 6 | the account moved lane at a boundary (§4.7) (01 §14.10) |
| `DISCONNECT` | 7 | cancel-on-disconnect (§4.9) (01 §14.10) |
| `ADMIN` | 8 | operator or risk action, account kill included (`10-accounts-risk-md.md`) (01 §14.10) |

There is no FOK cause: an unfillable `FOK` is always `Reject FOK_UNFILLABLE` (01 §14.10).

### 7.4 `EpochNotice`

Fields: bytes 4–7 `next epoch` (u32); bytes 8–11 the **home word**: byte 8 = `HomeCode`, byte 9
= the sequencer box index in that epoch (0xFF if not yet fixed), bytes 10–11 = 0; bytes 12–15
`seconds to boundary` = ⌊(boundary_ts − lane time) / 10^9⌋, saturating at 0. Lane time is
order-stream time (§4.8), so the value is deterministic.

| Variant | When | `next epoch` | home word |
|---|---|---|---|
| Answer | R-ANSWER, for example a `Heartbeat` | e + 1 | home and box of e + 1 |
| Countdown | unsolicited, at T − 600 s, T − 60 s, T − 10 s, T − 1 s | e + 1 | home and box of e + 1 |
| Epoch start | the first in-stream record of each session in a new epoch (H6) | e + 1 of the new epoch | home and box of that next epoch |
| Sequencer change | the first record from a new sequencer after a failover (§5.6) | **e, the current epoch** | current home, the new box index |

The client reads the variant from `next epoch`: equal to the current epoch means a sequencer
change, which also starts the rewind rule (§5.6). The current epoch is the full epoch whose low
16 bits are the packet's `epoch16`.

### 7.5 What a record attests: execution, durability, finality, settlement

01 §14.13 item 3 separates four facts. They come in this order. The protocol never merges them
into one "confirmed" flag, and a client must not either.

| Level | Fact | Holds when | The client learns it from |
|---|---|---|---|
| 0 `EXECUTED` | The sequencer executed the op. Volatile. | The in-stream record leaves (≤ `LAT_MAX_NS`). By R-FIRST its frames had left on both paths, so a sequencer crash alone cannot void it. | The record itself: `Fill`, `Ack`, `CancelAck`, `Out`, `Reject`. |
| 1 `DURABLE` | At least `F + 1` replicas hold the records, so no single fault can lose them. | The replicas' frame acknowledgements (`07-replication.md`). | `Attest` level 1; the drop copy. |
| 2 `FINAL` | The block that holds the records has a certificate (`INV-QUORUM`). | ≤ `FINALITY_MAX_MS` = 10 ms for every accepted order (01 §14.9). | `Attest` level 2; the drop copy, which is authoritative. |
| 3 `SETTLED` | CHAIN only: the fill is settled on the ledger or the bridge. | `09-chain.md`. | `Attest` level 3; the drop copy. Settlement never undoes a final fill (01 §14.19 B). |

**`Attest` (0x88, 01 §14.10).** An out-of-stream response packet (`resp_seq` 0,
`echo_pkt` 0) with one record:

```
off size field
  0   1  type      0x88
  1   1  level     1 DURABLE, 2 FINAL, 3 SETTLED
  2   2  reserved  0
  4   4  upto      every in-stream record of this session with resp_seq ≤ upto has this level
  8   4  height    low 32 bits of the block Height that reached it
 12   4  reserved  0
```

- The lane sends it from idle time, never on the 1 µs path, at most once per level per
  `BLOCK_NS` per session, and only when `upto` moved. A lost `Attest` is replaced by the next one,
  so it is not retained or resent. Its frame gate is empty: it reports, it changes nothing.
- A client that wants it sets `attest` at open (`OpenSessionReq`, §4.4). Every client can get
  the same facts per fill from the drop copy, which labels each level separately (10).
- A record at level 1 or above is never voided by the rewind rule (§5.6): a void record is one
  whose frames no replica holds. A level-1 record can still be excluded before finality, but only
  in 07 §9.6 cases (d) and (e). A level-2 record's fate is fixed: it is never reverted, and in
  CHAIN it is busted only if its `Bust` verdict was already final with it (01 §14.19 B, 09 §5.9).

## 8. Reject reasons

"In" means in-stream (accepted packet, consumes `pkt_seq`, retained, resendable). "Out" means
out-of-stream (`resp_seq` 0, not accepted, the client resends the same logical content later).

| Code | Name | Stream | Where | Detail | Client action |
|---|---|---|---|---|---|
| 1 | `BAD_MAC` | in, final | V6 | offending `pkt_seq` | session is `CLOSED`; find the key bug; open a new session |
| 2 | `BAD_SEQ` | out (gap, duplicate not in ring); in (`ResendReq`) | V8; §6.7 | `expected`, or the limit of §6.7 | gap: resend from detail; `ResendReq`: fix the range or ask the other store (§5.4) |
| 3 | `BAD_TYPE` | in | V9, M2, M3 | `PROTO_D_UNKNOWN_TYPE`, `_RESERVED`, `_FLAGS`, `_BAD_HDR` | client bug; do not resend the same content |
| 4 | `BAD_TICK` | in | M6 | the nearest acceptable tick (`min_tick`, `max_tick` or the band edge, 10 §3.1) | reprice |
| 5 | `BAD_QTY` | in | M6 | `RSK_D_QTY_ZERO` 1, `_QTY_MAX` 2, `_NOTIONAL` 3, `_OVERFLOW` 4 (10 §3.1), for a `New` and for the new order of a priority-losing `Replace`; a `Replace` field check (§6.5) also gives 0 or `PROTO_D_NO_CHANGE` | fix the qty |
| 6 | `RISK_CREDIT` | in | M7 | the asset that is short: 1 quote, 2 base (10 §3.1) | fund the book allocation (01 §12.4) |
| 7 | `RISK_POSITION` | in | M7 | the limit | reduce exposure |
| 8 | `RISK_ORDER_COUNT` | in | M7 | the limit | cancel orders first |
| 9 | `RATE_LIMIT` | in | V10, M1, M8 | bucket id: 1–7 are 04's, 8–11 are 10's (§9.1) | slow down; the bucket refills on `rx_ts` time |
| 10 | `POST_ONLY_WOULD_CROSS` | in | BBO core (03 ARC-D6) | best opposite tick of the true book | reprice |
| 11 | `FOK_UNFILLABLE` | in | BBO core | qty available at or better than the limit (capped) | — |
| 12 | `UNKNOWN_HANDLE` | in | M6 | 0 | check the client's handle table |
| 13 | `TOO_LATE` | in | M6, BBO core | `PROTO_D_FILLED`, `_CANCELED`, `_OUT` | the order already ended; its records precede this one |
| 14 | `BOOK_HALTED` | in | M5 | halt cause (10) | wait for the book to reopen |
| 15 | `EPOCH_MISMATCH` | out | V4 | the receiver's current epoch | switch keys and endpoints (§5.7); resend |
| 16 | `STP` | in | BBO core | the resting handle that stopped it | — |
| 17 | `WRONG_LANE` | out | §3.2 | the correct `LaneId` | fix the port; resend |
| 18 | `SESSION_CLOSED` | out (closed session); in (`DRAINING`, final record) | V7, M4, close | close cause (§4.3) | open a new session, or stop sending `New` |
| 19 | `AUCTION_PHASE` | in | M5 | `PROTO_PHASE_*` | resend after the phase changes, with a TIF that fits |
| 20 | `SIDE_MISMATCH` | in | M6 | 0 | cancel and send a `New` |
| 21 | `ACCOUNT_KILLED` | in | M4 | 0 | the account is killed (10 §3.7); cancels still work; wait for an unkill |
| 22 | `RESEND_GONE` | in (lane `ResendReq`); out (recovery) | §6.7, §5.4 | the oldest `resp_seq` either store holds | rebuild order state from the drop copy |
| 23 | `BAD_BOOK` | in | V9 | the packet's `book` | client bug: the session may not trade that book |
| 24 | `BUSY` | in (lane shed: every message's index, `client_tag` 0; BBO shed: the message's index) | test D (§3.5) | 0 | lane: resend from `echo_pkt`, same `pkt_seq`; BBO: resend the message in a new packet |
| 26 | `DATA_MISSING` | in (index 0xFF, final record) | 01 §14.19 C (DAV-1) | 0 | the session is closed: Q voters reported its data-tier copies missing; send copy 2 of every packet to the data home |

## 9. Rate limits and fee classes

### 9.1 Buckets

Every bucket is a GCRA (a token bucket written as one timestamp). All values are integers in
nanoseconds of `rx_ts`, so a replica that replays the `PacketRecord`s gets the same decisions
(`INV-DET`). The bucket state is part of the lane's replicated state.

```rust
struct Gcra { tat: Nanos, t_ns: u64, burst: u64 }        // t_ns = ceil(10^9 / rate), set at open
impl Gcra {
    /// Takes `cost` tokens at order-stream time `now` unless fewer than `keep` would be left.
    fn take(&mut self, now: Nanos, cost: u64, keep: u64) -> bool {
        let base = max(self.tat, now);
        let next = base + cost * self.t_ns;              // checked in the real code (01 §11 rule 4)
        if next > now + (self.burst - keep) * self.t_ns { return false; }
        self.tat = next;
        true
    }
}
```

**Period rounding.** `t_ns = ⌈10^9 / rate⌉`, rounded up, so the integer bucket never admits more
than `rate` tokens per second (220_000/s gives 4_546 ns, an admitted rate of 219_974/s). A rate of
0 is not a bucket: `CtlSetLimit` refuses it (10 §3.4). Every bucket of 04 and 10 uses this one
type and rounding (`Gcra::from_rate`, `crates/engine/vyrn-risk/src/gcra.rs`).

| Bucket id | Bucket | Scope | Charged at | Cost | Default, tier T1 (budget) |
|---|---|---|---|---|---|
| 1 / 4 | `PKT` | session / account | V10, every accepted packet | 1 | 1M/s, burst 256 |
| 2 / 5 | `MSG` | session / account | M1, every message | 1; `CancelAll` `PROTO_CANCELALL_TOKENS` | 5M/s, burst 2,560 |
| 3 / 6 | `BBO` | session / account | M8, after classification | cross, `IOC`, `FOK`: 5; improve: 1 | 100k cross-equivalents/s, burst 640 units |
| 7 | `RESEND` | session | §5.2, §6.7 | 1 per resent packet | 100k/s, burst 1,024 |

10 §3.8's account and lane buckets report their own ids, 8–11, in the same `RATE_LIMIT` detail
(10 §3.1, `vyrn-risk` `consts.rs`):

| Detail | 10 bucket | Charged at |
|---|---|---|
| 8 `RSK_BUCKET_NEW` | account `new_bucket` | 10 check 6, after M5 |
| 9 `RSK_BUCKET_CROSS` | account `cross_bucket` | M8, cross |
| 10 `RSK_BUCKET_LANE_CROSS` | lane or pool `lane_cross` | M8, cross |
| 11 `RSK_BUCKET_LANE_IMPROVE` | lane or pool `lane_improve` | M8, improve |

**One id per bucket.** 04's ids are 1–7 and 10's are 8–11, so every `RATE_LIMIT` detail names
exactly one bucket. A new bucket in either chapter takes the next free id, from 12. The golden
reject vectors S23–S26 carry ids 8–11 (`tests/golden/vyrn_reject_vectors.out`).

- **Cancel reserve.** `New` and priority-losing `Replace` take from `MSG` with
  `keep = PROTO_CANCEL_RESERVE` (a quarter of the burst). `Cancel`, `Reduce` and `CancelAll` use
  `keep = 0`. So a client at its limit can still cancel.
- **BBO units.** The BBO core spends `BBO_CROSS_NS` per cross and `BBO_IMPROVE_NS` per improve,
  a 5 : 1 ratio, so the `BBO` bucket counts improves as 1 unit and crosses as 5. One book can
  take 0.6 × 10^9 / 8 = 75M units/s at `BBO_MAX_LOAD` (computed), which covers `CROSS_CAP` crosses
  (50M units) plus 20M improves (DESIGN §3).
- **Admission.** `vyrn-admin` admits a session only if the committed `MSG` rates of the lane's
  sessions sum to ≤ 0.6 × 10^9 / `LANE_NS_PER_MSG` = 20M/s, and the committed `BBO` rates of the
  book sum to ≤ 70M units/s (budget). Admission does not make the 1 µs hold; test D does, at
  any load (§3.5). Admission keeps `BUSY` within each lane class's bound (§3.6, B3).
- `10-accounts-risk-md.md` owns the tiers T0–T3 and their prices. The defaults above are this
  chapter's budget for T1.

### 9.2 Fee classes

Each message gets one fee class from its routing. `10-accounts-risk-md.md` owns the amounts and
how they are settled. The lane accrues the count per class in the account's lane state.

| Class | Messages | Price level |
|---|---|---|
| `CONTROL` | `Heartbeat`, `ResendReq`; any message rejected with `RATE_LIMIT` or `BUSY` | free |
| `CANCEL` | `Cancel`, `Reduce`, `CancelAll`, reduction `Replace` | cheap |
| `JOIN` | `New` or `Replace` classified as a join; any other lane-level reject | cheap |
| `IMPROVE` | classified as an improve | priced |
| `CROSS` | classified as a cross; every `IOC` and `FOK`; BBO-core rejects | priced |

A priority-loss `Replace` is charged `CANCEL` plus the class of its new order. A lane-level reject
is charged `JOIN` because it used lane time. A `RATE_LIMIT` reject is free because the bucket
already stops the flood.

## 10. The order as the client sees it

### 10.1 Client state machine

The client runs one machine per order, keyed by (`pkt_seq`, index) until the first record gives
it a handle, and by handle after that. It feeds records in `resp_seq` order (§5.3). It tracks
`open` = order qty − fills − canceled qty.

```
                    send New (pkt_seq p, index i)
                                │
                                ▼
                         ┌─────────────┐ no answer: resend p with bit0 = 1 (§5.1)
                         │   SENT      │◄──────────────┐
                         └──────┬──────┘───────────────┘
        Reject ─────────────────┼────────────────────────────────────► REJECTED
        Fill… with open = 0 ────┼────────────────────────────────────► FILLED
        Fill… then Out ─────────┼────────────────────────────────────► OUT
        Fill… then Ack, or Ack  │
                                ▼
                         ┌─────────────┐  maker Fill: open −= qty; open = 0 ──► FILLED
                         │    LIVE     │  Out (STP, POST_ONLY, EXPIRED, DISCONNECT,
                         │  (handle h) │       LANE_MOVED, ADMIN, AUCTION_UNFILLED) ──► OUT
                         └──┬───┬───┬──┘
              send Cancel   │   │   │ send Replace
                            ▼   │   ▼
                 ┌──────────────┐ │ ┌────────────────┐
                 │CANCEL_PENDING│ │ │REPLACE_PENDING │ Reject (not TOO_LATE): back to LIVE, h kept
                 └──────┬───────┘ │ └───────┬────────┘ CancelAck(h), no new handle: LIVE (reduced)
     CancelAck: CANCELED│         │         │          CancelAck(h) + records of h': h ends
     TOO_LATE: the fills│  send   │         │          (CANCELED), h' starts in SENT-like
     before it ended it │  Reduce ▼         │          state with its records
     (FILLED or OUT)    │  REDUCE_PENDING: CancelAck: open −= qty; open = 0 ──► CANCELED
                        ▼                   otherwise back to LIVE
             CANCELED / FILLED / OUT (terminal)
```

Maker fills can arrive in every pending state. They lower `open` there too. A `CancelAck` after
them reports only what was left. `Reject BUSY` is not `REJECTED`: the order never reached the
book, so the client may send it again (§3.5). Each terminal state is level 0 (`EXECUTED`) until
an `Attest` or the drop copy raises it (§7.5).

**Rewind.** On a sequencer-change notice with `resp_seq` r, the client drops the effects of every
record with `resp_seq ≥ r` that it got from the old sequencer, by replaying its own record log up
to r − 1. Then it resends its unacknowledged packets (§5.6).

### 10.2 What the client can rely on

| ID | Guarantee | Source |
|---|---|---|
| G1 | Each (`session`, `pkt_seq`) is executed at most once, in every box and every home. A resend is always safe. | §5.2 |
| G2 | Every accepted packet gets at least one in-stream record that names it. | R-ANSWER |
| G3 | Every message gets at least one record with its index. The message is complete when its records reach one of the end shapes of §6. | §6 |
| G4 | The messages of one packet take effect in index order. | §6.1 |
| G5 | The records of one handle are in `resp_seq` order of their events in the total order. | R-HANDLE |
| G6 | `resp_seq` has no gaps. A gap is always a loss, never a skipped number. | §5.3 |
| G7 | A resent or regenerated packet has the same records as the original. | R-DET |
| G8 | Every in-stream record left after its order-stream records left on both paths; a sequencer crash alone never voids it. It is void only after a sequencer-change notice says so, and never once it is `DURABLE`. | R-FIRST, §5.6, §7.5 |
| G9 | Every message, at every index 0–9 and of every type, of every accepted packet of up to 10 messages gets its first record within `LAT_MAX_NS`, as a maximum; the B-packet and the first L-packet leave within it too. A packet or op that cannot meet it gets `Reject BUSY` within `LAT_MAX_NS`. No load, rate or position condition applies. | R-1US, §3.5, 01 §14.0 |
| G10 | A paced client on a dedicated lane never gets a lane-stage `BUSY`; its total `BUSY` is ≤ 10⁻⁵ at full book load and ≤ 10⁻⁸ at ≤ 20%. A pooled client gets ≈ 10⁻³ and ≤ 10⁻⁶ (§3.6). | `LANE_PACE`, 01 §14.17.2 |
| G10 | A record attests execution only. Durability, finality (≤ `FINALITY_MAX_MS` = 10 ms for every accepted order) and settlement are separate facts, reported by `Attest` and the drop copy (`10-accounts-risk-md.md`). | §7.5, 07, 10 |

## 11. Conformance test vectors

The script below is pure Python 3 with only the standard library. It first checks SipHash-2-4
against the reference vector of the SipHash paper (key = bytes 00..0f, message = bytes 00..0e →
`0xa129ca6149be45e5`) and two more vectors of the same table, then builds the packets. Run it with
`python3 -I`. `11-build.md` turns every vector into a test of `vyrn-wire`.

Keys (test only, never production):

| Key | Bytes |
|---|---|
| `K_seq` | `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f` |
| `K_out` | `10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f` |
| `K_com` | `20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f` |

Scenario: epoch 1000 (`epoch16` = 0x03e8), book 1. Session A = slot 7, lane 3, generation 1
(`0x00103007`). Session B = slot 9, lane 5, generation 1 (`0x00105009`), another account.
Session C = slot 2, lane 0, generation 4 (`0x00400002`), CHAIN mode. The lane's snapshot bid is
100001 or better when V1 and V3 arrive, so both orders are joins and go in L-packets. Before V5,
the only bids are A4 (8 @ 100001) and 1 lot @ 100000. V11 answers the first transmission of V12,
which carried `epoch16` = 999; V12 is the same logical content resent with `epoch16` = 1000 (D3).
V12 also gets an R-ANSWER `EpochNotice` as `resp_seq` 5 (not printed), so V15 is `resp_seq` 6.
V16 reaches lane 3 when test D (§3.5) fails, so the lane sheds it: V17 is its in-stream `BUSY`
run (`resp_seq` 7, `echo_pkt` 6, one `Reject BUSY` at index 0, detail 0, `client_tag` 0), and
nothing was applied. V18 is the client's resend of the same `pkt_seq` with the same logical
content and bit0 = 1; the lane accepts it as a first acceptance, and its answer takes `resp_seq` 8
(not printed). V19 (`pkt_seq` 7, a New and a Heartbeat) is shed too: V20 is its `BUSY` run, one
record per message, the Heartbeat's included, as `resp_seq` 9.

```python
#!/usr/bin/env python3
"""VYRN      04-protocol conformance vectors. Pure Python 3, standard library only."""
import struct

MASK = (1 << 64) - 1


def rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & MASK


def siphash24(key: bytes, msg: bytes) -> int:
    """SipHash-2-4, 128-bit key, 64-bit tag (as an integer; on the wire it is little-endian)."""
    if len(key) != 16:
        raise ValueError(f"SipHash key must be 16 bytes, got {len(key)}")
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D,
         k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rnd() -> None:
        v[0] = (v[0] + v[1]) & MASK; v[1] = rotl(v[1], 13); v[1] ^= v[0]; v[0] = rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & MASK; v[3] = rotl(v[3], 16); v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & MASK; v[3] = rotl(v[3], 21); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & MASK; v[1] = rotl(v[1], 17); v[1] ^= v[2]; v[2] = rotl(v[2], 32)

    end = len(msg) - len(msg) % 8
    for i in range(0, end, 8):
        m = struct.unpack_from("<Q", msg, i)[0]
        v[3] ^= m; rnd(); rnd(); v[0] ^= m
    b = ((len(msg) & 0xFF) << 56) | int.from_bytes(msg[end:], "little")
    v[3] ^= b; rnd(); rnd(); v[0] ^= b
    v[2] ^= 0xFF
    for _ in range(4):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


# Reference vectors from the SipHash paper (key 00..0f, message 00..len-1).
for n, want in [(15, 0xA129CA6149BE45E5), (0, 0x726FDB47DD0E0E31), (8, 0x93F5F5799A932462)]:
    got = siphash24(bytes(range(16)), bytes(range(n)))
    if got != want:
        raise SystemExit(f"SipHash-2-4 self-test FAILED for len {n}: {got:#018x}")
print("siphash24(00..0f, 00..0e) = 0xa129ca6149be45e5  reference vector OK (also len 0, 8)")

K_SEQ = bytes(range(0x00, 0x10))   # test keys only
K_OUT = bytes(range(0x10, 0x20))
K_COM = bytes(range(0x20, 0x30))


def sid(slot, lane, gen): return slot | lane << 12 | gen << 20          # section 4.1
def hdl(slot, gen): return slot | gen << 24                             # 01 section 3
def of(side, tif=0, post=0, stp=0): return side | tif << 1 | post << 3 | stp << 4
def rec(t, b1=0, w=0, a=0, b=0, c=0): return struct.pack("<BBHIII", t, b1, w, a, b, c)


def new(f, tick, qty, tag): return rec(0x01, f, 0, tick, qty, tag)
def cancel(h, tag): return rec(0x02, 0, 0, h, 0, tag)
def reduce(h, by, tag): return rec(0x03, 0, 0, h, by, tag)
def replace(f, h, tick, qty): return rec(0x04, f, 0, h, tick, qty)
def heartbeat(): return rec(0x10)
def resend_req(lo, hi): return rec(0x11, 0, 0, lo, hi, 0)
def cancel_all(tag): return rec(0x12, 0, 0, 0, 0, tag)
def ack(i, h, tick, tag): return rec(0x81, i, 0, h, tick, tag)
def fill(i, liq, h, tick, qty): return rec(0x82, i, liq, h, tick, qty)
def reject(i, why, detail, tag): return rec(0x83, i, why, detail, 0, tag)
def cancel_ack(i, h, qty, tag): return rec(0x84, i, 0, h, qty, tag)
def out(i, cause, h, qty, tag): return rec(0x85, i, cause, h, qty, tag)
def epoch_notice(e, home, secs): return rec(0x86, 0, 0, e, home, secs)


def request(s, seq, e16, book, msgs, k_com=None, flags=0):
    body = struct.pack("<IIBBHHH", s, seq, len(msgs), flags, e16, book, 0) + b"".join(msgs)
    tag_com = siphash24(k_com, body) if k_com else 0                    # 0 in BASE mode
    return body + struct.pack("<QQ", siphash24(K_SEQ, body), tag_com)


def response(s, rseq, e16, echo, recs, flags=0):
    body = struct.pack("<IIBBHI", s, rseq, len(recs), flags, e16, echo) + b"".join(recs)
    return body + struct.pack("<Q", siphash24(K_OUT, body))


def verify_request(pkt, key):
    n = pkt[8]
    end = 16 + 16 * n
    ok_len = 1 <= n <= 10 and len(pkt) == end + 16
    return ok_len and siphash24(key, pkt[:end]) == struct.unpack_from("<Q", pkt, end)[0]


def dump(name, pkt, req):
    print(f"\n{name} ({len(pkt)} B)")
    for off in range(0, len(pkt), 16):
        print(f"  {off:03x}: " + " ".join(f"{x:02x}" for x in pkt[off:off + 16]))
    tags = struct.unpack_from("<QQ", pkt, len(pkt) - 16) if req else struct.unpack_from("<Q", pkt, len(pkt) - 8)
    print("  " + "  ".join(f"{n}={t:#018x}" for n, t in zip(("tag_seq", "tag_com") if req else ("tag",), tags)))


E, B = 1000, 1                                   # epoch 1000 (epoch16 0x03e8), book 1
A, Bs, C = sid(7, 3, 1), sid(9, 5, 1), sid(2, 0, 4)
A1, A2, A3, A4, B1 = hdl(42, 1), hdl(43, 1), hdl(44, 1), hdl(45, 1), hdl(7, 3)
V = [
    ("V1 req  A: New buy Day 5 @ 100000, STP 1", request(A, 1, E, B, [new(of(0, stp=1), 100_000, 5, 0x11111111)]), True),
    ("V2 resp A: Ack (lane, L-packet)", response(A, 1, E, 1, [ack(0, A1, 100_000, 0x11111111)]), False),
    ("V3 req  A: Cancel A1, Reduce A2 by 2, Replace A3 -> buy 8 @ 100001",
     request(A, 2, E, B, [cancel(A1, 0x22222222), reduce(A2, 2, 0x33333333), replace(of(0, stp=1), A3, 100_001, 8)]), True),
    ("V4 resp A: CancelAck, CancelAck, CancelAck(old) + Ack(new), stored tag 0x44444444",
     response(A, 2, E, 2, [cancel_ack(0, A1, 5, 0x22222222), cancel_ack(1, A2, 2, 0x33333333),
                           cancel_ack(2, A3, 4, 0x44444444), ack(2, A4, 100_001, 0x44444444)]), False),
    ("V5 req  B: New sell IOC 10 @ 100000", request(Bs, 1, E, B, [new(of(1, tif=1), 100_000, 10, 0x55555555)]), True),
    ("V6 resp B: B-packet Fill 8 @ 100001, Fill 1 @ 100000, Out IOC_REMAINDER 1",
     response(Bs, 1, E, 1, [fill(0, 1, B1, 100_001, 8), fill(0, 1, B1, 100_000, 1), out(0, 1, B1, 1, 0x55555555)]), False),
    ("V7 resp A: maker Fill of A4 from the TX core, maker range (echo_pkt 0)", response(A, 3, E, 0, [fill(0xFF, 0, A4, 100_001, 8)]), False),
    ("V8 req  A: Heartbeat", request(A, 3, E, B, [heartbeat()]), True),
    ("V9 resp A: EpochNotice (answer): next 1001, LDN box 1, 3600 s",
     response(A, 4, E, 3, [epoch_notice(E + 1, 2 | 1 << 8, 3600)]), False),
    ("V10 req C: CHAIN mode, New sell post-only 3 @ 100002",
     request(C, 1, E, B, [new(of(1, post=1), 100_002, 3, 0x66666666)], k_com=K_COM), True),
    ("V11 resp A: out-of-stream Reject EPOCH_MISMATCH, detail 1000",
     response(A, 0, E, 4, [reject(0xFF, 15, E, 0)]), False),
    ("V12 req A: ResendReq(1, 1)", request(A, 4, E, B, [resend_req(1, 1)]), True),
    ("V13 resp A: resend of V2 (flags bit0, same resp_seq, new tag)",
     response(A, 1, E, 1, [ack(0, A1, 100_000, 0x11111111)], flags=1), False),
    ("V14 req A: CancelAll", request(A, 5, E, B, [cancel_all(0x77777777)]), True),
    ("V15 resp A: CancelAck x2, summary CancelAck(HANDLE_ALL, 2)",
     response(A, 6, E, 5, [cancel_ack(0, A2, 3, 0x77777777), cancel_ack(0, hdl(46, 1), 6, 0x77777777),
                           cancel_ack(0, 0xFFFFFFFF, 2, 0x77777777)]), False),
    ("V16 req A: New buy IOC 2 @ 100000 (arrives in overload)",
     request(A, 6, E, B, [new(of(0, tif=1), 100_000, 2, 0x88888888)]), True),
    ("V17 resp A: lane shed of V16, in-stream Reject BUSY at index 0, detail 0, client_tag 0",
     response(A, 7, E, 6, [reject(0, 24, 0, 0)]), False),
    ("V18 req A: resend of V16, same pkt_seq and content, bit0 = 1",
     request(A, 6, E, B, [new(of(0, tif=1), 100_000, 2, 0x88888888)], flags=1), True),
    ("V19 req A: New sell Day 1 @ 100005 + Heartbeat (arrives in overload)",
     request(A, 7, E, B, [new(of(1), 100_005, 1, 0x99999999), heartbeat()]), True),
    ("V20 resp A: lane shed of V19, BUSY run: one Reject BUSY per message, client_tag 0",
     response(A, 9, E, 7, [reject(0, 24, 0, 0), reject(1, 24, 0, 0)]), False),
]
for name, pkt, req in V:
    dump(name, pkt, req)

v1, v10 = V[0][1], V[9][1]
bad = bytearray(v1); bad[32] ^= 0x01                                    # one bit of tag_seq
for what, ok in [("V1 verifies with K_SEQ", verify_request(v1, K_SEQ)),
                 ("V1 fails with K_OUT", not verify_request(v1, K_OUT)),
                 ("V1 with one tag bit flipped fails (bound source: close session)",
                  not verify_request(bytes(bad), K_SEQ)),
                 ("V10 tag_com = SipHash(K_COM, bytes 0..32)",
                  struct.unpack_from("<Q", v10, 40)[0] == siphash24(K_COM, v10[:32])),
                 ("V13 tag differs from V2 tag", V[12][1][-8:] != V[1][1][-8:]),
                 ("V17 is in stream (resp_seq 7), echo_pkt 6, Reject BUSY 24 at index 0, detail 0, tag 0",
                  struct.unpack_from("<I", V[16][1], 4)[0] == 7 and V[16][1][16:18] == b"\x83\x00"
                  and struct.unpack_from("<HII", V[16][1], 18) == (24, 0, 0)
                  and struct.unpack_from("<I", V[16][1], 12)[0] == 6),
                 ("V20 answers every message of V19 (count 2, Heartbeat included) with BUSY, tag 0",
                  V[19][1][8] == V[18][1][8] == 2 and struct.unpack_from("<I", V[19][1], 12)[0] == 7
                  and all(V[19][1][16 + 16 * i:18 + 16 * i] == bytes([0x83, i])
                          and struct.unpack_from("<HII", V[19][1], 18 + 16 * i) == (24, 0, 0)
                          for i in range(2))),
                 ("V18 has V16's logical content (D3) and verifies", V[17][1][16:32] == V[15][1][16:32]
                  and V[17][1][:9] == V[15][1][:9] and verify_request(V[17][1], K_SEQ))]:
    if not ok:
        raise SystemExit(f"FAILED: {what}")
    print(f"check OK: {what}")
```

Output of `python3 -I vyrn_proto_vectors.py` on 2026-11-18 (all checks pass):

```
siphash24(00..0f, 00..0e) = 0xa129ca6149be45e5  reference vector OK (also len 0, 8)

V1 req  A: New buy Day 5 @ 100000, STP 1 (48 B)
  000: 07 30 10 00 01 00 00 00 01 00 e8 03 01 00 00 00
  010: 01 10 00 00 a0 86 01 00 05 00 00 00 11 11 11 11
  020: ce a6 ae 0c 10 82 13 8e 00 00 00 00 00 00 00 00
  tag_seq=0x8e1382100caea6ce  tag_com=0x0000000000000000

V2 resp A: Ack (lane, L-packet) (40 B)
  000: 07 30 10 00 01 00 00 00 01 00 e8 03 01 00 00 00
  010: 81 00 00 00 2a 00 00 01 a0 86 01 00 11 11 11 11
  020: 7b 0a dd 3a 35 20 db 3c
  tag=0x3cdb20353add0a7b

V3 req  A: Cancel A1, Reduce A2 by 2, Replace A3 -> buy 8 @ 100001 (80 B)
  000: 07 30 10 00 02 00 00 00 03 00 e8 03 01 00 00 00
  010: 02 00 00 00 2a 00 00 01 00 00 00 00 22 22 22 22
  020: 03 00 00 00 2b 00 00 01 02 00 00 00 33 33 33 33
  030: 04 10 00 00 2c 00 00 01 a1 86 01 00 08 00 00 00
  040: 21 7c cc dc 1c 1c 91 3a 00 00 00 00 00 00 00 00
  tag_seq=0x3a911c1cdccc7c21  tag_com=0x0000000000000000

V4 resp A: CancelAck, CancelAck, CancelAck(old) + Ack(new), stored tag 0x44444444 (88 B)
  000: 07 30 10 00 02 00 00 00 04 00 e8 03 02 00 00 00
  010: 84 00 00 00 2a 00 00 01 05 00 00 00 22 22 22 22
  020: 84 01 00 00 2b 00 00 01 02 00 00 00 33 33 33 33
  030: 84 02 00 00 2c 00 00 01 04 00 00 00 44 44 44 44
  040: 81 02 00 00 2d 00 00 01 a1 86 01 00 44 44 44 44
  050: 17 d2 51 0e 46 ae 13 4a
  tag=0x4a13ae460e51d217

V5 req  B: New sell IOC 10 @ 100000 (48 B)
  000: 09 50 10 00 01 00 00 00 01 00 e8 03 01 00 00 00
  010: 01 03 00 00 a0 86 01 00 0a 00 00 00 55 55 55 55
  020: 23 7b 64 e3 77 6d 4d 3f 00 00 00 00 00 00 00 00
  tag_seq=0x3f4d6d77e3647b23  tag_com=0x0000000000000000

V6 resp B: B-packet Fill 8 @ 100001, Fill 1 @ 100000, Out IOC_REMAINDER 1 (72 B)
  000: 09 50 10 00 01 00 00 00 03 00 e8 03 01 00 00 00
  010: 82 00 01 00 07 00 00 03 a1 86 01 00 08 00 00 00
  020: 82 00 01 00 07 00 00 03 a0 86 01 00 01 00 00 00
  030: 85 00 01 00 07 00 00 03 01 00 00 00 55 55 55 55
  040: 42 85 5c 79 88 cf e3 f2
  tag=0xf2e3cf88795c8542

V7 resp A: maker Fill of A4 from the TX core, maker range (echo_pkt 0) (40 B)
  000: 07 30 10 00 03 00 00 00 01 00 e8 03 00 00 00 00
  010: 82 ff 00 00 2d 00 00 01 a1 86 01 00 08 00 00 00
  020: b6 25 c0 08 da 1d e7 d1
  tag=0xd1e71dda08c025b6

V8 req  A: Heartbeat (48 B)
  000: 07 30 10 00 03 00 00 00 01 00 e8 03 01 00 00 00
  010: 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  020: 15 e1 48 48 1e f2 ba bf 00 00 00 00 00 00 00 00
  tag_seq=0xbfbaf21e4848e115  tag_com=0x0000000000000000

V9 resp A: EpochNotice (answer): next 1001, LDN box 1, 3600 s (40 B)
  000: 07 30 10 00 04 00 00 00 01 00 e8 03 03 00 00 00
  010: 86 00 00 00 e9 03 00 00 02 01 00 00 10 0e 00 00
  020: 4d f2 47 1a ea 6b 28 80
  tag=0x80286bea1a47f24d

V10 req C: CHAIN mode, New sell post-only 3 @ 100002 (48 B)
  000: 02 00 40 00 01 00 00 00 01 00 e8 03 01 00 00 00
  010: 01 09 00 00 a2 86 01 00 03 00 00 00 66 66 66 66
  020: 2f 67 e7 30 b4 b6 e4 b2 9c a5 89 aa 10 23 6a 3a
  tag_seq=0xb2e4b6b430e7672f  tag_com=0x3a6a2310aa89a59c

V11 resp A: out-of-stream Reject EPOCH_MISMATCH, detail 1000 (40 B)
  000: 07 30 10 00 00 00 00 00 01 00 e8 03 04 00 00 00
  010: 83 ff 0f 00 e8 03 00 00 00 00 00 00 00 00 00 00
  020: 2d f4 0f bc 51 46 ce 1a
  tag=0x1ace4651bc0ff42d

V12 req A: ResendReq(1, 1) (48 B)
  000: 07 30 10 00 04 00 00 00 01 00 e8 03 01 00 00 00
  010: 11 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00
  020: 44 52 2e b1 e1 40 0c 9c 00 00 00 00 00 00 00 00
  tag_seq=0x9c0c40e1b12e5244  tag_com=0x0000000000000000

V13 resp A: resend of V2 (flags bit0, same resp_seq, new tag) (40 B)
  000: 07 30 10 00 01 00 00 00 01 01 e8 03 01 00 00 00
  010: 81 00 00 00 2a 00 00 01 a0 86 01 00 11 11 11 11
  020: cb 0a 1c 2c f0 0b 2f 66
  tag=0x662f0bf02c1c0acb

V14 req A: CancelAll (48 B)
  000: 07 30 10 00 05 00 00 00 01 00 e8 03 01 00 00 00
  010: 12 00 00 00 00 00 00 00 00 00 00 00 77 77 77 77
  020: c4 17 c2 a9 56 95 1a ee 00 00 00 00 00 00 00 00
  tag_seq=0xee1a9556a9c217c4  tag_com=0x0000000000000000

V15 resp A: CancelAck x2, summary CancelAck(HANDLE_ALL, 2) (72 B)
  000: 07 30 10 00 06 00 00 00 03 00 e8 03 05 00 00 00
  010: 84 00 00 00 2b 00 00 01 03 00 00 00 77 77 77 77
  020: 84 00 00 00 2e 00 00 01 06 00 00 00 77 77 77 77
  030: 84 00 00 00 ff ff ff ff 02 00 00 00 77 77 77 77
  040: f5 85 d4 43 dd fd c5 b5
  tag=0xb5c5fddd43d485f5

V16 req A: New buy IOC 2 @ 100000 (arrives in overload) (48 B)
  000: 07 30 10 00 06 00 00 00 01 00 e8 03 01 00 00 00
  010: 01 02 00 00 a0 86 01 00 02 00 00 00 88 88 88 88
  020: fd 45 e4 3b dc 2a da 03 00 00 00 00 00 00 00 00
  tag_seq=0x03da2adc3be445fd  tag_com=0x0000000000000000

V17 resp A: lane shed of V16, in-stream Reject BUSY at index 0, detail 0, client_tag 0 (40 B)
  000: 07 30 10 00 07 00 00 00 01 00 e8 03 06 00 00 00
  010: 83 00 18 00 00 00 00 00 00 00 00 00 00 00 00 00
  020: 7d 93 f7 a9 0a e1 d0 0d
  tag=0x0dd0e10aa9f7937d

V18 req A: resend of V16, same pkt_seq and content, bit0 = 1 (48 B)
  000: 07 30 10 00 06 00 00 00 01 01 e8 03 01 00 00 00
  010: 01 02 00 00 a0 86 01 00 02 00 00 00 88 88 88 88
  020: 37 e2 a3 17 d7 27 2c 64 00 00 00 00 00 00 00 00
  tag_seq=0x642c27d717a3e237  tag_com=0x0000000000000000

V19 req A: New sell Day 1 @ 100005 + Heartbeat (arrives in overload) (64 B)
  000: 07 30 10 00 07 00 00 00 02 00 e8 03 01 00 00 00
  010: 01 01 00 00 a5 86 01 00 01 00 00 00 99 99 99 99
  020: 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  030: fc 00 f4 62 6c 63 16 ae 00 00 00 00 00 00 00 00
  tag_seq=0xae16636c62f400fc  tag_com=0x0000000000000000

V20 resp A: lane shed of V19, BUSY run: one Reject BUSY per message, client_tag 0 (56 B)
  000: 07 30 10 00 09 00 00 00 02 00 e8 03 07 00 00 00
  010: 83 00 18 00 00 00 00 00 00 00 00 00 00 00 00 00
  020: 83 01 18 00 00 00 00 00 00 00 00 00 00 00 00 00
  030: 1a 57 e8 f8 72 1f 54 51
  tag=0x51541f72f8e8571a
check OK: V1 verifies with K_SEQ
check OK: V1 fails with K_OUT
check OK: V1 with one tag bit flipped fails (bound source: close session)
check OK: V10 tag_com = SipHash(K_COM, bytes 0..32)
check OK: V13 tag differs from V2 tag
check OK: V17 is in stream (resp_seq 7), echo_pkt 6, Reject BUSY 24 at index 0, detail 0, tag 0
check OK: V20 answers every message of V19 (count 2, Heartbeat included) with BUSY, tag 0
check OK: V18 has V16's logical content (D3) and verifies
```

Expected lane behaviour for the negative vector: the flipped `tag_seq` comes from A's bound
address, so the lane closes session A at V6 and sends `Reject BAD_MAC` (index 0xFF, detail 1) as
the final in-stream record. The same bytes from any other address are dropped at V3 and counted,
and A stays open. The same bytes with `epoch16` = 999 get `EPOCH_MISMATCH` at V4 and close nothing
(01 §14.8). For V17, the expected client action is: keep `expected` = 6, resend from 6 (V18), do
not count V16 as acknowledged, and take each record's tag from its own copy of V16. For V20 the
same holds from 7.

## 12. Versioning

**The wire carries no version field.** The protocol version is fixed per session at open
(`proto_version` in BASE, the open transaction in CHAIN). This keeps the header at
`PKT_HDR_BYTES` and the lane never branches on a per-packet version. This chapter is version 2
(`PROTO_VERSION` in vyrn-wire).

Version 2 differs from version 1 in one place: the `RATE_LIMIT` detail ids of 10's buckets moved
from 1–4 to 8–11 (§9.1, Q13), so they no longer overlap §9's buckets 1–7. That changes the meaning
of a v1 field value, which VR2 forbids; it was allowed once because version 1 was never released.
No box accepts `proto_version` 1, and `OpenSessionReq` with it is refused (admin vector B08). Every
other rule and layout of version 1 is unchanged, so "v1" in VR1–VR3 and in the table below means
the base layout that versions 1 and 2 share. Protocol versions are numbered apart from product
scope: "v2" in 01, 02 and 10 (isolated-margin perpetuals) is a product release, which will need
a later protocol version.

| ID | Rule |
|---|---|
| VR1 | A receiver rejects every nonzero reserved field or bit (`BAD_TYPE`, `PROTO_D_RESERVED` or `PROTO_D_BAD_HDR`). A v1 client therefore cannot set a reserved bit by accident and see it ignored, and a later version can give that bit a meaning with no ambiguity. |
| VR2 | A new version adds meaning only in new type codes or in fields that v1 reserves. It never changes the meaning of a v1 field, for any session. |
| VR3 | The exchange sends a session only the record types and field values of that session's version. A client treats an unknown record type or value as a protocol error: it stops sending `New` and alerts its operator. |
| VR4 | The set of accepted versions changes only at an epoch boundary. The key bundle for e + 1 lists the versions that the new home accepts. A session changes version by opening a new session. |
| VR5 | The byte layouts change only by an edit of 01 §6. |

Code space: request types 0x01–0x0F are order messages, 0x10–0x1F control, 0x20–0x7F reserved.
Response types are 0x80–0xFF; v1 uses 0x81–0x88 (0x87 `Bust` in CHAIN only, 0x88 `Attest`,
01 §6.4, §14.10).

Planned use of reserved fields (informative; not part of v1):

| Field | v1 | Planned |
|---|---|---|
| request header `reserved` (bytes 14–15) | 0 | v2: isolated-margin bucket of the account for perpetuals (01 §12.1) |
| request header `flags` bits 1–7 | 0 | bit 1: the packet carries a v2 extension block |
| order flags bits 6–7 | 0 | bit 6: reduce-only (v2 perpetuals) |
| message bytes 2–3 | 0 | `New`: an STP group (u16) so that STP can span the accounts of one firm; `Replace`: the low 16 bits of a new `client_tag` |
| response `flags` bits 1–7 | 0 | bit 1: more records for the same request follow in the next packet |
| `Out` causes 9–65535 | never sent | free for v2 (causes 1–8 are v1, §7.3; cause 2 is `STP`) |
| transport | IPv4 | the same payloads over IPv6/UDP |

## 13. Interfaces to other chapters

**Consumes:**

| From | What |
|---|---|
| 01 | The layouts of §6, the constants of §5, the invariants of §7, the decisions of §12. |
| 02 | `REQ-LAT-1`, REQ-LAT-4 (maker fills), REQ-LAT-5 per lane class and its pacing analysis (02 §4.4.1), and the security and epoch requirements that this chapter serves. |
| 05 | Classification against a versioned snapshot; the BBO-core ring with the reserved `resp_seq`; the BBO → lane fill-event ring; B-packet records and their overflow; slot allocation with `PROTO_HANDLE_REUSE_MIN_S`; `CancelAck` only after the fill events of all earlier steps are applied (R-HANDLE); `Out POST_ONLY` from rescans; CancelAll against orders still at the BBO core; the other-lane SPSC ring on AWS; `TimerTick`; two-pass lanes with the dependency list (01 §14.2); test D for forwarded ops and the `Shed` step with its fill-event answer to the lane; ops that depend on a shed op shed with it; `AcctKill` for `CancelAll`; the later-message count with the first push (§7.1). |
| 06 | NIC steering by destination port; the lane → NIC-port map that fills the key bundle; RX hardware timestamps; recovery-node NVMe; edge ACLs and policers (E1–E3). |
| 07 | The `PacketRecord` at acceptance, with `flags` bit 0 `SHED` (bit 1 `ADVANCE` is engine-only, 01 §6.6); the data-home rule (never in the sequencer's facility); R-FIRST for every response (01 §14.5); frame acknowledgements for `DURABLE` (§7.5); payload repair; equivocation detection by logical content (D3); control records `SessionOpen`, `SessionClose`, `Rebind`, `SetCod`, `AdminKill`, `SequencerChange`; `failover_order`. |
| 08 | `boundary_ts`; staging at the new home; the auction phase, its uncross and STP inside it. |
| 09 | The CHAIN open transaction, key derivation, `K_com(e, s)`, TESLA disclosure, the inclusion port, the bond, close evidence. |
| 10 | Risk checks and limits, rate tiers, fee amounts, `max_order_qty`, price bands, halts, drop copy, self-trade surveillance, the penalty for late data copies. |
| 11 | The `vyrn-admin` encoding; benchmark B2 for the costs in §3; tests built from §11. |

**Provides:**

| To | What |
|---|---|
| 05 | The check order (V1–V11, M1–M9), routing (IOC and FOK always to the BBO core), Replace semantics, the `resp_seq` reservation, the B-packet rules, `LANE_PACE` and its margin (lane background slices ≤ 10 ns), `serves()` for the pool. |
| 07 | Client obligations D1–D6, the definition of logical content, the list of control records. |
| 08 | Client handoff rules H1–H9 and the `EpochNotice` variants. |
| 09 | The session state machine, the key roles, the out-of-stream rules. |
| 10 | Fee classes, bucket ids, `Out` causes, reject details; the four attestation levels that the drop copy labels separately (§7.5). |
| 11 | Vectors V1–V20, the script, and the negative checks. |

## 14. Local definitions

All values are **budgets** unless marked otherwise.

| Name | Value | Meaning |
|---|---|---|
| `PROTO_LANE_PORT_BASE` | 20000 | UDP port of lane 0; lane l listens on base + l |
| `PROTO_DATA_PORT` | 19998 | `vyrn-data` ingest port |
| `PROTO_RECOVERY_PORT` | 19999 | recovery service port |
| `PROTO_INCLUSION_PORT` | 19997 | CHAIN inclusion port (09) |
| `PROTO_RESP_MAX_BYTES` | 280 | largest response payload (computed from 01 §6.3) |
| `PROTO_SEQ_BACK` | 65,536 | how far behind `expected` a packet is still checked as a duplicate |
| `PROTO_SEQ_AHEAD` | 1,024 | client window; how far ahead a packet is still checked as a gap |
| `PROTO_LANE_RESEND_MAX` | 16 | packets per `ResendReq` that the lane serves |
| `PROTO_RECOVERY_PPS` | 100,000 | recovery pacing per session |
| `PROTO_RESP_GAP_WAIT_US` | 20 | client wait before it asks for a missing `resp_seq` |
| `PROTO_REQ_RTO_US`, `PROTO_REQ_RTO_MAX_MS` | 200, 20 | client resend timer, initial and maximum |
| `PROTO_OOS_HOLDOFF_US` | 100 | one out-of-stream response per (session, reason) per holdoff |
| `PROTO_WRONG_LANE_PPS` | 1,000 | other-lane slow-path budget per lane |
| `PROTO_DATA_LAG_MAX_US` | 100 | data copy at most this long after the sequencer copy |
| `PROTO_MAKER_RANGE` | 16, refilled at 8 used | maker-range credit per session (01 §14.14, §7.1) |
| `PROTO_SHED_NS` | 20 | lane work to shed one packet (01 §14.1) |
| `PROTO_BUSY_TAIL_NS` | 460 | logged cut 170 + `LaneCut` poll 20 + frame gate 10 + lane TX 20 + NIC TX 240, after a shed |
| `LANE_PACE` | rule (§3.6) | SDK pacing on a dedicated lane: gap ≥ `lane_ns(prev)` + margin + jitter |
| `PROTO_PACE_MARGIN_NS`, `PROTO_PACE_JITTER_NS` | 10, 25 | pacing margin for lane background slices; leaf-switch gap compression (B3 measures it) |
| `PROTO_RESP_BUILD_NS` | 20 | lane response build, the last term of `lane_ns` |
| `PROTO_MAKER_PKT_NS` | 16 | per maker packet on one TX core (§7.1; 02 `REQ_MAKER_PKT_NS`) |
| `PROTO_ATTEST_*` | 1 `DURABLE`, 2 `FINAL`, 3 `SETTLED` | `Attest` level (§7.5); 0 `EXECUTED` is the record itself |
| `Attest` | record 0x88 (01 §14.10) | field layout of the attestation record (§7.5) |
| `PROTO_HB_IDLE_MS` | 100 | client sends at least this often |
| `PROTO_TIMEOUT_MIN_MS`, `_DEFAULT_MS`, `_MAX_MS` | 10, 350, 10,000 | session timeout range |
| `PROTO_CLIENT_SILENCE_MS`, `PROTO_CLIENT_FAILOVER_MS` | 5, 50 | client failover detection (§4.8) |
| `PROTO_DRAIN_MAX_MS` | 1,000 | longest `DRAINING` |
| `PROTO_CLOSED_KEEP_S` | 86,400 | a closed session's slot and stream are kept this long |
| `PROTO_KEY_PREISSUE_S`, `PROTO_KEY_GRACE_S` | 900, 60 | key bundle lead time; old-key grace |
| `PROTO_HANDLE_ALL` | 0xFFFF_FFFF | "all orders" in the `CancelAll` summary; slot 0xFF_FFFF is never allocated |
| `PROTO_HANDLE_REUSE_MIN_S` | 60 | minimum time before an ended order's slot is reused |
| `PROTO_CANCELALL_TOKENS` | 16 | `MSG` tokens per `CancelAll` |
| `PROTO_CANCEL_RESERVE` | burst / 4 | `MSG` tokens kept for cancels |
| `PROTO_PHASE_*` | 1 continuous, 2 auction, 3 halted | `AUCTION_PHASE` detail |
| `PROTO_OUT_*` | 1–8 (01 §14.10) | `Out` cause names (§7.3) |
| `PROTO_D_*` (close causes) | 1–7, §4.3 | `SESSION_CLOSED` detail |
| `PROTO_D_*` (`BAD_TYPE`) | 1 `UNKNOWN_TYPE`, 2 `RESERVED`, 3 `FLAGS`, 4 `BAD_HDR`; 5 retired (now `BAD_BOOK` 23) | detail |
| `PROTO_D_*` (`BAD_QTY`) | `NO_CHANGE` 0xFFFF_FFFE (`Replace` field check); risk checks of a `New` or of a `Replace`'s new order use 10's `RSK_D_*` 1–4; `OVERFLOW` 0xFFFF_FFFF is retired (now `RSK_D_OVERFLOW` 4) | detail |
| `PROTO_D_*` (`TOO_LATE`) | 1 `FILLED`, 2 `CANCELED`, 3 `OUT` | detail |
| `PROTO_CNT_*` | `MALFORMED`, `UNKNOWN_SESSION`, `UNBOUND_SRC`, `EPOCH`, `SEQ_WINDOW`, `BAD_MAC`, `CLOSED`, `DUP`, `GAP`, `BAD_HDR`, `RATE`, `DATA_LATE`, `BUSY` | per-lane and per-session counters, exported by the control core |

Types: the `SessionId` bit layout (§4.1); `OpenSessionReq`, `OpenSessionResp`, `KeyBundle`,
`BoxKeys` (§4.4); `Cod` = `Off | On`; `Gcra` (§9.1); bucket ids 1–7 and 10's 8–11 (§9.1); the B-packet and
L-packet (§7.1); the `Attest` record (§7.5).

## 15. Requests to 01

Resolved by 01 §14 and dropped from this list: the bad-MAC close rule (now with `epoch16`, §14.8),
`Out` causes 5–8, `Attest` 0x88 and `DURABLE` (§14.10, §14.13), BBO-core `Shed` scope and the
E4 policer (§14.1), maker fills within 1 µs (§14.14) and in long sweeps (§14.17.5), the maker
credit bound (`STEP_FILL_CAP`, §14.15), `PacketRecord.flags` (§6.6),
`INV-FRAME-FIRST` for every response (§14.5), `Fill.liq` = 2 (§14.10), the FOK cause (§14.10),
`RESP_RETAIN_PKTS` ownership and the lane ring (§14.6), and `BAD_BOOK` (§14.10).

1. **§4 vs §12.5.** §4 still says "the first failed MAC on a session closes the session". Reword
   it to §12.5 plus §14.8: bound address and matching `epoch16`.
2. **`INV-DET`** says "every response". Out-of-stream responses depend on packets that the order
   stream does not hold. Restrict it to in-stream responses (a lane `BUSY` is one, §3.5).
3. **`PktHash`.** A resend (flags bit0) and a resend into a new epoch (`epoch16`) change the hashed
   bytes. Compute `PktHash` with `flags` bit0 and `epoch16` set to 0, so that every transmission of
   one `pkt_seq` hashes the same and equivocation is exactly a `PktHash` mismatch. Until then, 07
   compares logical content (D3).
4. **Reserved sequence values.** State in §6.1 and §6.3: `pkt_seq = 0` is a recovery request
   (§5.4); `resp_seq = 0` is an out-of-stream response (§3.2). Response `flags` bits 1–7 are 0.
5. **`EpochNotice`.** Define the home word (byte 8 `HomeCode`, byte 9 box index) and the
   sequencer-change variant (`next epoch` = current epoch).
6. **`BUSY` stream.** State in §14.1 that a lane `BUSY` is in stream (a response packet with the
   next `resp_seq`, one `Reject BUSY` per message, `client_tag` 0, gated on the `SHED` record, no
   holdoff) and a BBO-core `BUSY` is in stream at the message index (§3.5).
7. **Maker numbering.** State in §14.14 that the 16-number range is a relative credit placed by
   the merge rule of §7.1, not a fixed block: a fixed block leaves gaps when a maker stops trading,
   and lets a fill number below its order's `Ack`.
8. **Promote** the `SessionId` layout, `PROTO_HANDLE_ALL` (and the reserved slot 0xFF_FFFF), the
    reject detail codes of §14, the `Day` definition (the trading day ends at 00:00 UTC), and a
    `TimerTick` record in §6.6 with the control records listed in §13.
9. **`LANE_PACE` wording.** §14.15 says a paced client leaves "at least `predicted_path_ns`"
   between packets. `predicted_path_ns` is the remaining path to the wire (~560–645 ns), which
   would cap a dedicated lane at ~1.6M packets/s and 1B msgs/s would not close. §3.6 paces by the
   lane's occupancy `lane_ns` plus margin and jitter; say so in §14.15.
10. **Maker count.** §14.17.5's ~40 makers at index 9 needs ≤ 7.5 ns per maker packet per TX core;
   `PROTO_MAKER_PKT_NS` = 16 gives 18 on three TX cores. State the cost the 40 assumes.
11. **Pool sessions.** Say in §14.15 that a pooled `SessionId` names its home pool core and that
   every pool core accepts the pool's sessions (§4.7), and that `WRONG_LANE` is never sent inside
   the pool.

## 16. Open questions

Settled and removed: Q13 (10's `RATE_LIMIT` ids moved to 8–11, §9.1, reject vectors S23–S26) and
Q14 (the §4.4 admin encoding is normative, vectors in `tests/golden/vyrn_admin_vectors.out`).

| # | Question | Owner | Settled by |
|---|---|---|---|
| Q1 | Do V1–V8 with SipHash-2-4 over a 10-message packet fit the 45 ns of `LANE_PASS1_NS`, and M1–M8 the 5 ns per message? | 05 | B2 with the packet-size sweep |
| Q2 | Is every index 0–9 and every type under `LAT_MAX_NS` as a maximum, with 880 ns (cross) and 965 ns (ack) at index 9 against the 980 ns threshold, and does cancels-first give cancels ~100 ns of slack? | 05 | B3 with the cross position swept 0–9; one sample over 1 µs fails |
| Q3 | Is the reorder between B-packet and L-packet below 1 µs, and is `PROTO_RESP_GAP_WAIT_US` = 20 µs right? | 05, 06 | capture-NIC test in `11-build.md` on the B3 rig |
| Q4 | How many makers of a sweep's first steps meet `LAT_MAX_NS` from the taker's first bit (01: ~40; 16 ns per packet on three TX cores: 18), do continuation-step makers meet it from their step's start, and does a lane packet's wait for earlier steps' fill events fit the 965 ns ack budget? | 05 | B3 extended to time maker fills and acks under maker-heavy load |
| Q5 | In CHAIN mode a `BAD_MAC` close rests on the sequencer's word. What evidence goes into the close record so that a byzantine sequencer cannot close sessions at will? | 09 | `vyrn-sim` scenario with a byzantine sequencer |
| Q6 | Can one recovery replica per home write the response stream at peak (≤ 26 GB/s)? | 06, 07 | recovery soak test at B3 load |
| Q7 | Does slot allocation guarantee `PROTO_HANDLE_REUSE_MIN_S` at 20M allocations/s per lane (16M slots, 8-bit generation)? | 05 | `vyrn-sim` allocation trace at peak rate |
| Q8 | Do the E1–E2 ACLs and the E4 per-lane policers (40M/s, burst 8) fit the edge switch, and does E4 drop ≤ 10⁻⁶ of packets at the reference load? | 06 | switch lab test with the full ACL at B3 load |
| Q9 | Is closing sessions on a lane move acceptable to market makers, or does 05 need handle translation? | 10, 05 | `vyrn-sim` re-quote time after a move, reviewed with ops |
| Q10 | Until Request 3 lands, does 07 detect equivocation by logical content across resends and epochs with no false positive? | 07 | `vyrn-sim` resend-across-handoff test |
| Q11 | Does every `BUSY`, lane and BBO-core, leave within 1 µs at 2× overload, and does each lane class meet §3.6 at the reference load? | 05 | B3 overload sweep with the capture NIC; per-class curves |
| Q12 | Does the leaf switch keep a paced gap within `PROTO_PACE_JITTER_NS` = 25 ns at 60% port load, and is a 35 ns pacing overhead per packet acceptable to market makers? | 06, 10 | B3 rx-gap histogram per dedicated lane; review with MM firms |
