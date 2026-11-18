# 02. Requirements: measurement points, SLOs, budgets, acceptance

Draft 0.2, 2026-11-13. Normative. This chapter defines every `REQ-*` ID (01 §8) and every workload
ID (`WL-*`). Other chapters cite them and never redefine them. It fixes where each number is
measured, the load under which it holds, and the benchmark that passes or fails it. It allocates
the latency and throughput budgets to stages. Local names use the prefix `REQ_`. 01 §14 overrides
anything here.

This chapter states what must hold, not how. Mechanisms belong to the owner chapter named in each
requirement. Where a requirement constrains a mechanism (REQ-LAT-3, REQ-LAT-5), the reason is a
computation here. The hard constraints (01 §2) are the testable requirements REQ-PLT-1 to
REQ-PLT-4 (§10).

The hard requirements of 01 §14.0 are not negotiable: 1 µs as a maximum for every accepted packet,
every message type and every index 0–9; 1B msgs/s on one book; 10 ms finality for every accepted
order; the 8 h move; CHAIN mode with 5 validators. No requirement below exempts a packet size, a
message index or a message type, or replaces a bound with a percentile. Three facts are
stated as facts (§3.5): on AWS the wire belongs to Nitro, light sets the handoff window, and
finality needs a network that meets its delay bound.

## 1. How to read a requirement

Each requirement gives a **statement** (decision first), a **point** of measurement (§2), a
**bound** (a maximum over every sample of the run, a rate, or a limit), the **conditions** of the
run, and a **test**. B1–B20 are 11 §7; B21–B39 are new here (§13), and 11 defines them fully.

Number labels follow 00: **budget**, **measured** (none in draft 0.2), **vendor**. A number marked
**computed** is arithmetic on budgets and has the status of a budget.

Terms local to this chapter:

| Term | Meaning |
|---|---|
| received packet | A request packet that passed the edge filters E1–E4 (04 §3.4) and reached the NIC of the live sequencer of the active home (01 §14.19 A). |
| ingress loss | A request packet that was sent but never received: dropped by a policer, lost on the wire, or sent to a crashed box. It gets no response (REQ-LAT-14). |
| accepted packet | A received packet that is not answered `BUSY`. It may still get rejects (`RATE_LIMIT`, `BOOK_HALTED`, …); those are outcomes, not exemptions. |
| shed packet | A received packet that deadline admission (01 §14.1) answers with `Reject BUSY` and does not apply. |
| first record | The first response record that carries a message's outcome: its `index`, or for a maker fill its handle. |
| latency `L` | For one message: first bit of its request packet in, to first bit of the response packet that carries its first record out. There is no normalization: index 9 counts in full. |
| slack | `LAT_MAX_NS − DEADLINE_GUARD_NS − (zero-wait path budget of the message, §4.2)`. The queueing a message can absorb before it must be shed. |
| envelope | The load and behaviour under which a rate requirement (REQ-LAT-5, REQ-THR-1) holds (§3.1). REQ-LAT-1 has no envelope. |
| probe session | An ordinary `WL-REF` session whose packets the production capture measures (§6.11). |
| dedicated lane | A lane core that serves the accounts of one firm only (01 §14.15). Lanes 0–41 on `REF`. |
| pooled lane | One of the 7 cores of the pool on CCD 7 (lanes 42–48 on `REF`). Any pool core serves any pooled packet (01 §14.15). |
| paced client | A client on a dedicated lane that follows `LANE_PACE` (04 §3.6). |

## 2. Measurement points

### 2.1 M-WIRE: first bit in, first bit out, at the exchange NIC (REF, CONSUMER)

```
  generator / client                                          exchange box (REF)
 ┌──────────────┐  fiber   ┌───────────────────┐  ≤ 2 m   ┌─────────────────────────┐
 │ vyrn-bench   ├─────────►│ passive optical   ├─────────►│ NIC port p (X2541)      │
 │ generator    │◄─────────┤ splitter, 1 per   │◄─────────┤ ef_vi RX, CTPIO TX      │
 └──────────────┘          │ direction         │          └─────────────────────────┘
                           └──────┬───────┬────┘
                         tap "in" │       │ tap "out"   (equal fiber lengths ± 0.2 m)
                                  ▼       ▼
                         ┌──────────────────────────────┐
                         │ capture NIC(s): HW timestamp │  every capture port on one
                         │ per frame, start of frame    │  timebase; error ≤ REQ_CAP_ERR_NS
                         └──────────────────────────────┘
```

- **Hardware.** A passive optical splitter on each fiber of each exchange NIC port, in both
  directions. No SPAN port and no active tap: a SPAN port adds switch queueing and drops frames.
  Every capture port shares one timebase. Error between capture ports ≤ `REQ_CAP_ERR_NS` = 5 ns
  (budget), checked by calibration.
- **First bit.** The timestamp of the first bit of the destination MAC field. A capture NIC that
  stamps the end of frame is corrected by `frame_len_bytes × 0.08 ns` (100 Gb/s serialization).
- **Fiber.** The two tap legs of one port are equal within 0.2 m (~1 ns at ~5 µs per km, DESIGN
  §6). Calibration: loop the client fiber back through the splitter with no NIC; subtract that.
- **Matching.** A request `(session, pkt_seq)` matches responses with the same `session` and
  `echo_pkt`, and each record by `index`. A maker fill (`echo_pkt = 0`) matches through the order
  stream: fill → `StepId` → `StepRecord.src_lane, src_lane_seq` → `PacketRecord` → taker packet.
- **Population and statistics.** A maximum is over every message of the run, so B3, B9, B5 and
  B19 capture every packet on every client port, both directions: at full `WL-REF` that is
  ~310M frames/s on 8 capture ports (computed, §5.2). The report gives the exact max, complete HDR
  histograms at 1 ns (11 §7.1, rule 4) and the identity of every sample above
  `LAT_MAX_NS − DEADLINE_GUARD_NS`. Production (REQ-OPS-2) and long soaks may use probe sessions.

### 2.2 M-TSC: RX completion to TX doorbell, by TSC (AWS; in-box diagnostics everywhere)

- `t0` = TSC read by the lane in the poll iteration that first sees the RX completion.
- `t1` = TSC read right after the store that rings the TX doorbell (DPDK on ENA) or after the last
  CTPIO store (ef_vi).
- TSC to ns: invariant TSC, frequency calibrated against `CLOCK_MONOTONIC_RAW` over 10 s on the
  control core (core 51, 01 §10) at start. The pinned core writes `(t0, t1, session, pkt_seq)` into a per-lane ring
  that the control core drains: ≤ 10 ns per packet (budget), on in production at 11 §8's
  sampling rate. `M-STAGE` stamps stage boundaries the same way (§4.2). It checks stage
  budgets. On `REF` and `CONSUMER` it never passes an end-to-end requirement; on `AWS` it is the
  point of REQ-LAT-8 (01 §14.0, fact 1). On AWS, `rx_ts` is the TSC read at RX completion (01 §14.11).

### 2.3 Other points

| ID | From | To | Clock |
|---|---|---|---|
| `M-FIN` | `PacketRecord.rx_ts` of the message | earliest NIC RX timestamp, at any correct replica, of the vote that completes `Q_BASE` or `Q_CHAIN` valid signatures on its block or a descendant | PTP; box-to-box error ≤ `REQ_PTP_BOX_NS` = 1 µs (budget) |
| `M-FIN-C` | same | first bit of the finality notice for that step at the client's capture point | PTP |
| `M-OUT` | first bit of the last response from the old sequencer | first bit of the first response from the new sequencer | one capture system tapping every box of the home |
| `M-EPO` | first bit of the last response of epoch e at the old home | first bit of the first continuous-trading `Fill` of epoch e+1 at the new home | PTP from GNSS-disciplined grandmasters in each home; error ≤ 1 µs (budget) |
| `M-MD` | first bit of a `Fill` out of the sequencer | first bit of the market-data update that reports it | one capture NIC on both taps (11 B15) |
| `M-INC` | first bit of a forced-path packet out of the client, at its capture point | finality of the book block in which it takes effect | PTP |

## 3. Latency requirements

### 3.1 The envelope

REQ-LAT-1 has no load envelope. Its scope is the ingress contract: it holds for every received
packet (§1) at any load and under any client behaviour. Overload is answered `BUSY`, a session over
its buckets gets `RATE_LIMIT`, a halted book answers `BOOK_HALTED`, and each of these is a first
record within `LAT_MAX_NS`. Packets the edge drops are ingress loss, bounded separately by
REQ-LAT-14 and never counted as answered (01 §14.19 A). REQ-LAT-1's only preconditions are the
target: `REF`, tuned per 06, with B1, B17 and B18 passed on that box.

The rate requirements (REQ-LAT-5, REQ-THR-1) hold under all of these conditions:

1. Workload `WL-REF` (§6) at any rate from 0 to 10⁹ msgs/s, including its bursts (§6.9).
2. Every session within its buckets, and every lane within its allocation (REQ-THR-6).
3. Lane load ≤ `REQ_LANE_MAX_LOAD` (0.60) and BBO-core load ≤ `BBO_MAX_LOAD` in every 1 s window.
4. `BASE` or `CHAIN` mode: the sequencer checks only `tag_seq` in both.
5. For the dedicated bound of REQ-LAT-5 only: the client is paced (04 §3.6).

### 3.2 The core requirement

**REQ-LAT-1. Every message of every received packet gets its first record within 1 µs, as a
maximum.**
- Point: `M-WIRE`. Metric: `L`, with no normalization.
- Bound: max ≤ `LAT_MAX_NS` (1,000 ns) over every message of the run: every message type and
  outcome of §3.3, every `count` 1–10, every index 0–9, `BASE` and `CHAIN`. A shed packet's
  `BUSY` record is a first record and meets the same bound.
- Mechanism: deadline admission (01 §14.1, REQ-LAT-3). It is what makes the bound a maximum.
- Test: B3 (full `WL-REF`, full capture), B9 (every type at 10%, 60% and 100% load), B32. One
  sample above `LAT_MAX_NS` fails the run. A run with zero samples of some (type, index) cell of
  §3.3 is invalid. A run is also invalid unless its counters reconcile: per port, `sent =
  received + policed + wire loss`, and every received packet was answered (01 §14.19 A).

**REQ-LAT-2. Every stage stays inside its row of §4.1.**
- Point: `M-STAGE`. Bound: the max of each stage over the run is ≤ its row. A stage before the
  admission test that runs over its row shows up as `BUSY` (REQ-LAT-5); a stage after it would
  break REQ-LAT-1, so REQ-LAT-3 makes those rows hard. Test: B9, B10, B21, B22.
- Reason: REQ-LAT-1 alone passes a design that sheds everything slow. REQ-LAT-2 and REQ-LAT-5
  together make the fast path real.

### 3.3 Per message type (REF, zero-wait path budgets)

| Message and outcome | First record | Path (§4.2) | `count` = 1 | index 9 of 10 | max |
|---|---|---|---|---|---|
| `New` that crosses: taker fill | `Fill`, liq = 1 | BBO | 835 | 880 | 1,000 |
| `New` IOC with no fill | `Out`, cause IOC | BBO | 835 | 880 | 1,000 |
| `New` FOK not filled | `Reject FOK_UNFILLABLE` | BBO | 835 | 880 | 1,000 |
| `New` STP outcome | `Out` cause STP, or `Reject STP` | BBO | 835 | 880 | 1,000 |
| `New` improve (rests inside the spread) | `Ack` | BBO | 835 | 880 | 1,000 |
| `New` join (rests in lane) | `Ack` | lane + cut | 839 | 965 | 1,000 |
| `Cancel`, `Reduce`; first `CancelAck` of `CancelAll` | `CancelAck` | lane + cut | 839 | 965 | 1,000 |
| `Replace` that rests | per 04 §6.5 | lane + cut | 839 | 965 | 1,000 |
| `Replace` that crosses | `Fill` | BBO | 835 | 880 | 1,000 |
| Reject decided by the lane (`BAD_*`, `RISK_*`, `RATE_LIMIT`, `POST_ONLY_WOULD_CROSS`, `EPOCH_MISMATCH`, `WRONG_LANE`, `AUCTION_PHASE`, `SIDE_MISMATCH`, `BOOK_HALTED`, `ACCOUNT_KILLED`, `BAD_BOOK`) | `Reject` | lane + gate | ≤ 839 | ≤ 965 | 1,000 |
| Reject that needs the cut (`TOO_LATE`, `UNKNOWN_HANDLE`) | `Reject` | lane + cut | 839 | 965 | 1,000 |
| `ResendReq` | first resent packet, or `Reject RESEND_GONE` / redirect (REQ-LAT-10) | lane + gate | ≤ 839 | ≤ 965 | 1,000 |
| Maker fill (per REQ-LAT-4) | `Fill`, index 0xFF | BBO + TX core | — | taker + 16 × k | 1,000 |
| Shed packet (every message) | `Reject BUSY` | lane + cut | 800 | 800 | 1,000 |

All values are ns, budget, worst case (§4.2), for a dedicated lane; the ack is 955 typical (01
§14.17.1). A pooled lane adds `REQ_POOL_TOKEN_NS` = 20 to every row, so a pooled 10-message packet
with an ack-path message at index 9 (985) is always shed; ≤ 9 messages fit (Requests to 01, item
6). The max column is the requirement for every row and both classes. A lane reject is at most
the ack of its index. `BUSY` answers the whole packet and waits for the cut like an ack, because
its `SHED` record is frame-gated (01 §14.5).

### 3.4 Other latency requirements

**REQ-LAT-3. Deadline admission is sound: every stage after the test has a hard bound.**
- Statement: a lane tests each packet at dequeue, and the BBO core tests each forwarded op, as
  01 §14.1 states. `predicted_path_ns` is the sum of the §4.1 rows from the test point to the
  wire, at the packet's worst index. Every stage after the test point has a hard maximum equal to
  its row: lane pass 1 and pass 2, the BBO hop and step, the cut and `LaneCut`, the frame gate
  (stream cores 4 and 7), the TX cores (3, 5 and 0), the lane TX and the NIC TX. None of them may
  queue without a bound. Owner: 05, 06, 07.
- The shed path is short: ~20 ns of lane work, then the logged cut, the gate, lane TX and NIC TX
  (800 ns at zero wait, §4.2). Shedding costs less than serving, so it also bounds the lane's own
  backlog (§4.4). A packet dequeued at lane wait ≤ `REQ_BUSY_WAIT_MAX_NS` (180 ns; dequeue age
  ≤ 500 ns) gets its `BUSY` within `LAT_MAX_NS − DEADLINE_GUARD_NS` (980). An older packet
  is not accepted: it is dropped like a wire loss and counted with `BUSY` in B3.
- Every shed decision is in the order stream (`PacketRecord.flags.SHED` or a `Shed` step), so
  replay never recomputes it (`INV-DET`).
- Point: `M-STAGE` per stage, `M-WIRE` end to end. Bound: per-stage max ≤ row after the test;
  zero late `BUSY` answers. Test: B3, B10, B21, B22, B4 (replay of shed decisions).

**REQ-LAT-4. Maker fills leave within 1 µs of the taker's first bit.**
- A maker fill (`echo_pkt` = 0) is caused by the taker's packet (01 §14.14, §14.17.5). The TX
  cores send it in the step that made it, with no hop through the maker's lane.
- **First steps of a sweep** (about 40 makers at index 9, more at lower indices): maker's first
  bit out ≤ `LAT_MAX_NS` after the taker packet's first bit in.
- **Later continuation steps** (`STEP_FILL_CAP` = 64 records per step): ≤ `LAT_MAX_NS` after the
  start of its own step. The taker's first fill is always within 1 µs. A maker fill is a notice to
  another client, not the response to the maker's own packet, so this exempts no response.
- The taker's packet leaves before any maker packet of its step; the k-th maker packet on one TX
  core leaves ≤ `REQ_MAKER_PKT_NS` × k after it, and never delays a later step's first record.
- Point: `M-WIRE`, matched through the order stream (§2.1). Test: B3, B9, B23 (`WL-ADV-1`).
- Computed: at index 9 each TX core fits ⌊(980 − 880) / 16⌋ = 6 maker packets, 18 on three;
  01's ~40 needs ≤ 7.5 ns per packet (Requests to 01, item 4; Open question 1).

**REQ-LAT-5. `BUSY` has two bounds, one per lane class.**
- **Dedicated, paced lanes (01 §14.17.2):** lane-stage `BUSY` = 0 (§4.4.1); total `BUSY` ≤
  `REQ_BUSY_DED_FULL` (10⁻⁵) of the lane's packets at full book load and ≤ `REQ_BUSY_DED_LOW`
  (10⁻⁸) at ≤ `REQ_POOL_LOW_LOAD` (20%). Only crosses and improves can be shed, at the BBO, TX
  and order-stream stages that every client shares (§4.4.3, §4.4.4). A paced client never queues
  in the lane behind another client or behind its own packets.
- **Pooled lanes: `BUSY` ≤ `REQ_BUSY_POOL_FULL` (10⁻³) of pooled packets at full book load
  (10⁹ msgs/s), and ≤ `REQ_BUSY_POOL_LOW` (10⁻⁶) at ≤ 20% of full book load** (§4.4.2).
- Point: counters per class and stage, checked against the capture, over the run and every 1 s
  window, under §3.1 with bursts. Test: B3 **publishes the curves** (`BUSY` per class and stage at
  10–100% load; dedicated paced and unpaced), B21, B22.
- Reason: `BUSY` is how overload is answered within 1 µs. It is never a normal outcome. Without
  this bound, REQ-LAT-1 would pass by shedding, which is a percentile in disguise. REQ-LAT-1
  itself is unchanged: a hard 1 µs maximum for every accepted packet of either class.

**REQ-LAT-6. REQ-LAT-1 holds at low load and after idle time.**
For `WL-LOW`: 1% of the full rate, and single 1-message probe packets after 1 ms, 100 ms and 1 s
of silence on their lane, every message within `LAT_MAX_NS` and zero `BUSY`. Point: `M-WIRE`.
Test: B33. Reason: busy polling keeps cores hot, but cold caches and power states show only at
low load.

**REQ-LAT-7. Bursts within the envelope keep REQ-LAT-1 and REQ-LAT-5.**
- Statement: a `WL-REF` burst (rate × 2 for 100 µs, §6.9) is part of `WL-REF`. REQ-LAT-1 holds
  inside it, and its shed packets count in REQ-LAT-5. Point: `M-WIRE`, samples tagged by burst
  interval. Test: B21, B9.
- Reason (computed): at × 2 a pool core runs at 0.75, so no backlog builds; the burst raises the
  probability of waiting (§4.4.2). A dedicated lane would run at 1.02 of its capacity, so the
  SDK pacer (04 §3.6) holds the excess at the client: ≤ 23 µs of send delay at the end of a 100 µs
  burst, which is not part of `L`. The lane itself never queues.

**REQ-LAT-8. On AWS, the 1 µs is a maximum inside the instance.**
- Point: `M-TSC`, metric `L` inside the instance. Bound: max ≤ `LAT_MAX_NS` for every message of
  §3.3, and REQ-LAT-5 at `WL-AWS`. Conditions: `AWS`; `WL-AWS`. Test: B16.
- Budget (computed): the index-9 cross path without the NIC (45 + 50 + 10 + 100 + 15 + 60 + 40 =
  320 ns) plus the wrong-lane forward (100 ns, DESIGN §4) = 420 ns.
- The wire belongs to the Nitro card (01 §14.0, fact 1). That is a fact of the platform, not an
  exemption: the full specification, with every number at once, is stated against `REF`.

**REQ-LAT-9. CONSUMER meets REQ-LAT-1 to REQ-LAT-7 at the wire,** under §3.1 with `WL-REF`
scaled to 2.4 × 10⁸ msgs/s and a NIC that passed B1. Replication path B uses the X2522 card
(01 §14.7). Test: B20.

**REQ-LAT-10. Bulk cancels and resends: the first record is within 1 µs, the rest is bounded.**
- `CancelAll`: first `CancelAck` per REQ-LAT-1. Last record max ≤ 1,000 + 12 × n ns for n orders
  canceled, n ≤ 10⁵ (budget: 10 ns per order in the lane, 11 B6, plus 2 ns per record of TX).
- `ResendReq`: first record per REQ-LAT-1, always from the lane. If the range is in the lane's
  hot ring (`RESP_HOT_RING_BYTES`, ~8 s, 01 §14.6), the first record is the first resent packet;
  the rest stream at ≥ 1 packet per 50 ns. If only the recovery service holds it, the first
  record is a redirect record (Requests to 01, item 1) and the recovery service delivers the range
  with max ≤ 1 ms. `RESEND_GONE` only when both have dropped it.
- Point: `M-WIRE`. Test: B9, B23 (`WL-ADV-2`, `WL-ADV-7`).

**REQ-LAT-11. Market data reports a fill within 10 µs at p99, with the same bytes for everyone.**
Market data and drop copy are not responses to a request packet, so REQ-LAT-1 does not apply.
Point: `M-MD`. Bound: p99 ≤ 10 µs (budget, `BLD_MD_LAG_P99_US` in 11). Every subscriber of one
feed receives byte-identical updates. Owner: 10. Test: B15.

**REQ-LAT-12. Drop copy reports every fill exactly once within 50 µs at p99.** Point: fill first
bit out → first bit of the drop-copy record. Owner: 10. Test: B35.

**REQ-LAT-13. There is no cold start.** The first messages after a failover, after an epoch
start and after the opening uncross meet REQ-LAT-1, with zero `BUSY` in the first 100 ms. The
warm standby `vyrn-seq` in F2 (01 §14.4) warms its caches by replay as a follower before it takes
over. Test: B19, B13 (every packet in the first 100 ms).

**REQ-LAT-14. Ingress loss is bounded and reported apart from `BUSY`.** (Draft 0.3, 01 §14.19 A.)
- Statement: under `WL-REF`, with every session within its buckets, the edge policers E2 and E4
  drop ≤ `REQ_INGRESS_LOSS_MAX` (10⁻⁶) of sent request packets (04 Q8). A dequeue-age drop never
  happens. Every resend of a lost packet is a received packet with its own REQ-LAT-1 bound.
- Point: generator send counts, switch policer counters per port and per lane, the lane's
  dequeue-drop counter, NIC RX counters. They are published next to the `BUSY` curves of
  REQ-LAT-5 and never summed with them.
- Test: B3, B21, B32. One dequeue-age drop fails the run.
- Reason: without it, a design could meet REQ-LAT-1 by dropping packets it could not answer.

### 3.5 Physical facts and outcomes

Exactly three facts of physics or mathematics limit what a client sees (01 §14.0). None is an
exemption.

| Fact | What holds |
|---|---|
| **AWS.** The wire belongs to the Nitro card. | The 1 µs is a maximum inside the instance (REQ-LAT-8). 1B msgs/s depends on the instance's packet rate (B16, REQ-THR-11). |
| **Handoff window.** For one WAN one-way, light keeps the order flow from the new home's book. | The new home cannot fill. Every order still gets its first record, an auction `Ack` or a reject, within `LAT_MAX_NS` (REQ-EPO-5). Fills come at the uncross. This is the only window without a 1 µs fill. |
| **Finality needs a timely network** (FLP, partial synchrony). | Every accepted order is final ≤ `FINALITY_MAX_MS` while the metro network meets its delay bound. The book halts when finality lags > `FIN_GATE_BLOCKS`, so no fill is issued that cannot be final in time (REQ-FIN-1, REQ-FIN-5). |

Every other situation is answered within `LAT_MAX_NS` with a defined outcome:

| Situation | First record |
|---|---|
| A session above its buckets | `RATE_LIMIT`. Other sessions keep REQ-LAT-1 and REQ-LAT-5 (REQ-SEC-4). |
| A lane or the BBO core over its deadline | `BUSY` (REQ-LAT-3), counted against REQ-LAT-5. On a dedicated lane a lane-stage `BUSY` comes only from the firm's own unpaced bursts. |
| A packet behind its own session's earlier packet | It is served in `pkt_seq` order; its own index and its session's earlier packets are in its budget. |
| A halted book, or a gate that binds (REQ-FIN-5) | `BOOK_HALTED` (lane row of §3.3). |
| A sequencer crash | A packet that reaches a crashed box is not received (§1). The client resends it by `pkt_seq` after failover (REQ-FIN-7); the resend is a received packet with its own REQ-LAT-1 bound. Every packet the crashed box answered stays final (REQ-FIN-3, REQ-FIN-6). |
| Book-to-client fairness finer than the cut | Passive ops against aggressors in other lanes are ordered with ~`CUT_REFRESH_NS` granularity (DESIGN §3). |

## 4. Latency budget

### 4.1 Canonical budget (01 §14.2, message index 9, the worst case)

| Stage | Owner | Cross fill (ns) | Join or cancel ack (ns) | Check |
|---|---|---|---|---|
| NIC RX: wire → RX completion visible to the lane (ef_vi) | 06 | 320 | 320 | B1 |
| Lane per packet: session, bound address, epoch, `pkt_seq`, `tag_seq` | 04, 05 | 45 | 45 | B6 |
| Lane pass 1 through index 9 (`LANE_PASS1_NS` = 5 per message) | 05 | 50 | 50 | B6 |
| Push to the BBO ring, with the in-packet dependency list | 05 | 10 | — | B8 |
| Lane pass 2: apply through index 9 (`LANE_APPLY_NS` = 9 per message) | 05 | — | 90 | B6 |
| Lane → BBO core hop (one cross-CCD cache line) | 05 | 100 | — | B8 |
| BBO step (`BBO_CROSS_NS`, 01 §14.15) | 05 | 15 | — | B8 |
| Logged cut via `LaneCut` (two cut cores; stream core 4 or 7), worst case | 05, 07 | — | 170 | B7 |
| Lane poll of `LaneCut` (01 §14.17.1) | 05 | — | 20 | B7 |
| Frame gate, `INV-FRAME-FIRST` (stream core 4 or 7; normally open for acks) | 07 | 60 | 10 | B10 |
| TX core (TX-A core 3, TX-B core 5 or TX-C core 0) / lane builds the response | 05, 06 | 40 | 20 | B10 |
| NIC TX: CTPIO write → first bit on the wire | 06 | 240 | 240 | B1 |
| **Total (zero wait)** | | **880** | **965** | |
| **Slack** (`LAT_MAX_NS − DEADLINE_GUARD_NS` = 980 − total) | | **100** | **15** | |

The NIC owns 560 ns of every path, which is `NIC_FLOOR_NS` (B1). The ack is 955 ns typical, with
a 160 ns cut term, and 965 worst (01 §14.17.1); `DEADLINE_GUARD_NS` = 20 puts the shed threshold
at 980. A pooled lane adds `REQ_POOL_TOKEN_NS` = 20 to both columns (900 and 985). There is no
queueing row. Lane wait and BBO wait spend slack, and a message without
enough slack is shed (REQ-LAT-3). `BBO_CROSS_NS` = 15 is both the step's latency row and its
throughput cost.

### 4.2 Budget by index and by count (zero wait, computed)

- Cross at index i: 830 + 5 × (i + 1). Ack at index i of a packet of n: 825 + 5n + 9 × (i + 1).
- Lane reject: ≤ the ack of its index. `BUSY`: 320 + 20 (shed) + 170 (logged cut) + 20 (poll) +
  10 (gate) + 20 (TX) + 240 = 800, so `REQ_BUSY_WAIT_MAX_NS` = 980 − 800 = 180 and the oldest
  dequeue age that can still be answered is 500 ns.
- Pooled lane: + `REQ_POOL_TOKEN_NS` (20) on every path.

| Index i | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
|---|---|---|---|---|---|---|---|---|---|---|
| Cross (any n) | 835 | 840 | 845 | 850 | 855 | 860 | 865 | 870 | 875 | 880 |
| Ack, n = 10 | 884 | 893 | 902 | 911 | 920 | 929 | 938 | 947 | 956 | 965 |
| Slack, cross | 145 | 140 | 135 | 130 | 125 | 120 | 115 | 110 | 105 | 100 |
| Slack, ack, n = 10 | 96 | 87 | 78 | 69 | 60 | 51 | 42 | 33 | 24 | 15 |

An ack in a 1-message packet is 839 (slack 141). Index 0 is 45 ns faster than index 9 for a cross
and 81 ns faster for an ack in the same packet; 01 §14.2 rounds this to ~90. The slack falls by
9 ns per later index, so the SDK puts cancels first: a cancel at index 0 has ~100 ns (01
§14.17.1). Every dedicated cell is ≤ the threshold, so every message of every packet can meet
REQ-LAT-1 when it does not queue. The smallest slacks a pooled packet sees (`WL-REF` sends only
1–2-message packets to the pool, §6.8) are 120 for a cross at index 1 and 107 for an ack at
index 1.

Rows after the admission test are hard maxima (REQ-LAT-3), not p99s. A stage over its row takes
the time from another row with that owner's agreement, recorded in 11's report.

### 4.3 Index term

Two-pass early dispatch (01 §14.2) makes the index cost small: a cross pays 5 ns per earlier
message (pass 1 only), and an ack pays 5 ns per message of its packet plus 9 ns per earlier
message. DESIGN §4's 10 × 30 ns of serial lane time is gone. Per-session order still holds: a
packet of session s is served after every earlier packet of s.

### 4.4 Queueing analysis: REQ-LAT-5 under 01 §14.15

**Why shared single-server lanes fail.** For t below one service time an M/G/1 queue has
P(W > t) ≈ ρ, so a lane shared by many clients at load 0.41 with 15–141 ns of slack sheds ~0.25 of
packets (Lindley simulation, 2 × 10⁶ packets), and no load reduction short of ~10⁻⁵ fixes it.
Hence the two lane classes of 01 §14.15. Unpaced arrivals are Poisson (§6.9). Tails use
Cramér–Lundberg (CL): P(W > t) ≈ ρ·e^(−θt), where θ solves λ(E[e^(θS)] − 1) = θ.

#### 4.4.1 Dedicated lanes: no wait in the lane stage

Only one firm's packets reach a dedicated lane's queue. With `A_{n+1}` the gap at the exchange
NIC between packets n and n+1, `S_n` the lane occupancy of packet n and `W_n` its wait, Lindley
gives `W_{n+1} = max(0, W_n + S_n − A_{n+1})`.

1. `LANE_PACE` (04 §3.6): the SDK sends packet n+1 no earlier than `S_n` +
   `PROTO_PACE_MARGIN_NS` (10) + `PROTO_PACE_JITTER_NS` (25) after packet n.
2. The margin pays for lane background work (fill settlement, control ops, credit refills), run
   in slices ≤ 10 ns (05). The leaf compresses a paced gap by ≤ 25 ns (budget; B3 measures it).
   The jitter sits in the gap, not in the slack, because the smallest dedicated slack is 15 ns.
3. So `A_{n+1} ≥ S_n` at the NIC, and with `W_1 = 0` induction gives `W_n = 0` for every n, at
   any load up to the lane's capacity: **lane-stage `BUSY` = 0**. An unpaced firm delays only
   its own packets.
4. The BBO, TX and stream stages are shared, so a dedicated client's crosses and improves can
   still wait there (01 §14.17.2); §4.4.3–§4.4.4 bound it below 10⁻⁵ (10⁻⁸ at ≤ 20%).

Load (§5.2): 23.1M msgs/s and 2.85M packets/s per dedicated lane, load 0.45 (0.51 with response
building). Pacing moves the firm's own queueing into its SDK, outside `L`: the pacer runs at 0.61,
with a mean delay of ~170 ns (M/D/1) and ≤ 23 µs of backlog after a × 2 burst (REQ-LAT-7).

#### 4.4.2 Pooled lanes: M/M/c with c = 7

The pool serves TK and RT. A core with an empty RX queue steals from a sibling (01 §14.15), so
the pool is 7 servers on one queue; M/M/c is conservative for near-constant service. At full load
λ = 25.8M packets/s (§6.8), S = 45 + 14n + 20 (response) + 20 (token) ≈ 101 ns (n ≈ 1.16), so
a = 2.61 Erlang and ρ = 0.373. P(W > t) = C(c, a)·e^(−(cμ − λ)t), with Erlang C and
cμ − λ = 0.043 per ns. The smallest pooled slacks are 107 (ack) and 120 (cross) (§4.2).

| Book load | λ (pkts/s) | ρ per core | P(wait > 0) | P(W > 107) | P(W > 120) |
|---|---|---|---|---|---|
| 100% | 25.8M | 0.373 | 1.9 × 10⁻² | 1.9 × 10⁻⁴ | 1.1 × 10⁻⁴ |
| 100%, inside a × 2 burst | 51.6M | 0.746 | 0.38 | 5.8 × 10⁻² | 4.6 × 10⁻² |
| 50% | 12.9M | 0.187 | 4.3 × 10⁻⁴ | 1.1 × 10⁻⁶ | 5.0 × 10⁻⁷ |
| 20% | 5.16M | 0.075 | 1.4 × 10⁻⁶ | 1.4 × 10⁻⁹ | 6.3 × 10⁻¹⁰ |

Consequences (computed):

1. **Full load: pooled `BUSY` ≈ 4.2 × 10⁻⁴.** Bursts cover 0.2% of the time and carry 0.4% of the
   pooled packets at 5.8 × 10⁻², which adds 2.3 × 10⁻⁴ to the 1.9 × 10⁻⁴ between bursts. A 1 s
   window with twice the mean number of bursts reaches ~6.5 × 10⁻⁴. Both are ≤ `REQ_BUSY_POOL_FULL`.
2. **≤ 20% load: pooled `BUSY` ≤ 1.4 × 10⁻⁹**, three orders below `REQ_BUSY_POOL_LOW`. The curve
   crosses 10⁻⁶ near 50% load; B3 publishes where it really does.
3. **Pooling closes it:** the same 7 cores as single-server lanes give P(W > 107) = 0.19.
4. **Session order costs no slack:** a packet behind its own session's packet waits ≤ 101 ns for
   the token. Each take is logged as `AcctTake` (01 §14.17.4), so replay is exact.
5. **`BUSY` stays on time:** a shed (20 ns) is cheaper than service. Dequeue age > 500 ns happens
   only if the E4 policer fails. Such a packet is ingress loss (REQ-LAT-14), not `BUSY`, and it
   fails B21 (01 §14.16, §14.19 A).

#### 4.4.3 BBO core

| Service | Rate | Cost (ns) | Load |
|---|---|---|---|
| cross (`BBO_CROSS_NS`) | 10M/s | 15 | 0.150 |
| improve or depletion (`BBO_IMPROVE_NS`) | 22M/s | 8 | 0.176 |
| rescan, in slices ≤ `ARC_STEP_BUDGET_NS` (03 ARC-D14) | 10⁴/s | 400 in all | 0.004 |
| **Total** | | | **0.33** |

By CL, θ = 0.16 per ns: P(W > 100) ≈ 3 × 10⁻⁸ (a cross at index 9). `WL-REF` sends crosses and
improves only at index 0–1 (§6.8), with slack ≥ 140 (dedicated, P ≈ 5 × 10⁻¹¹) or ≥ 120 (pool,
P ≈ 1.2 × 10⁻⁹), far inside every REQ-LAT-5 bound; at 20% load (ρ = 0.07) it is negligible.
**Rescan slicing is required:** unsliced 400 ns rescans give P(W > 100) ≈ 6 × 10⁻². 01 §14.15
gives ~0.21 for this load; the rows sum to 0.33 (Requests to 01, item 5), both below 0.60.

#### 4.4.4 TX and order-stream cores

TX-A, TX-B and TX-C (cores 3, 5, 0; 01 §14.17.3) each send ~16M packets/s at ~14 ns, load
≈ 0.22 (05 measured 0.33 with two). Stream-A (core 4) and stream-B (core 7) each frame ~89M
records/s at ≤ 2.8 ns, load ≤ 0.25, step ≤ 20 ns. These shared single servers are where a
dedicated client's crosses and improves can wait, so REQ-LAT-3 needs a hard bound on each; B3
reports `BUSY` per stage (Open question 2).

## 5. Throughput requirements

### 5.1 Canonical throughput budget (DESIGN §3 and §4, with 01 §14.2 costs)

- Lanes (01 §10, §14.15): 42 dedicated lanes (cores 8–49) and a pool of 7 (cores 56–62), 49 in
  all. Lane work is 45 ns per packet + 14 ns per message (5 pass 1 + 9 apply), + 20 ns per pooled
  packet for the token. At `WL-REF`'s mix the 42 dedicated lanes carry **970M msgs/s** at load
  0.45 and the pool **30M msgs/s** at load 0.37 per core (§5.2). `LANE_NS_PER_MSG` (30, all
  costs amortized) is the ceiling: at 30 ns, 49 lanes at 0.60 carry 0.88B msgs/s, so the
  amortized cost must stay ≤ 26 ns at 1B msgs/s (B2).
- BBO core: 15 ns per cross, 8 ns per improve or depletion. `CROSS_CAP` = 10M crosses/s plus 20M
  improves or depletions/s run at load 0.31.
- So one book takes 1B msgs/s as long as **≤ 1% of messages cross**.
- At ≤ 10 messages per packet, 1B msgs/s is 100M packets/s each way, ~190 Gbps each way, about
  50% of 4 × 100GbE.

### 5.2 Refined budget at full `WL-REF` (REF, computed)

| Quantity | Value | Derivation |
|---|---|---|
| Inbound messages | 1.0 × 10⁹ /s | §6 |
| Accepted messages | ≥ (1 − 2 × 10⁻⁵) × 10⁹ /s | shed packets do not count (REQ-THR-1); pooled `BUSY` 3.9 × 10⁻⁴ of 3% of messages |
| Inbound packets | 145.5M /s | MM bundles 93.0M + MM urgent 26.7M + TK 20.8M + RT 5.0M (§6.8) |
| Mean messages per packet | 6.87 | |
| Ingress, line rate incl. preamble and IFG | 242 Gbps (60.5% of 4 client ports × 100G) | 258 B per 10-message packet, 114–130 B per 1–2-message packet |
| Dedicated lanes (42), 01 §14.2 terms | 18.97 core-s/s = 0.45 per lane | MM: 45 ns × 119.7M packets + 14 ns × 970M messages |
| Dedicated lanes, with response build | 21.36 core-s/s = 0.51 per lane | + 20 ns × 119.7M response packets |
| Per dedicated lane | 23.1M msgs/s, 2.85M packets/s | one firm (§6.3); capacity ~45M msgs/s at load 1.0, so a × 2 burst runs at 1.02 and the pacer holds the excess |
| Pool (7 cores) | 2.61 core-s/s = 0.37 per core | TK + RT: 25.8M packets × (45 + 20 + 20) ns + 30M messages × 14 ns |
| Lane time per message, amortized | 24.0 ns ≤ `LANE_NS_PER_MSG` (30) | (21.36 + 2.61) / 10⁹; B2 checks it |
| BBO core load | 0.330 | 10M × 15 + 20M × 8 + 2M depletions × 8 + 10⁴ rescans × 400 (ns per s) |
| Cut cores (01 §10) | core 1: lanes 0–24 · core 6: lanes 25–48 | `CUT_REFRESH_NS` = 100 |
| Order-stream cores (stream-A core 4, stream-B core 7) | ~89M records/s each | 145.5M `PacketRecord`s + 32M steps, by lane half; ≤ 2.8 ns per record at load 0.25 (computed budget) |
| TX cores (TX-A core 3, TX-B core 5, TX-C core 0; 01 §14.17.3) | ~16M packets/s each | 10M taker fills + 20M improve acks + 18M maker packets over three cores; ~14 ns per packet, load ≈ 0.22 |
| Response records | ~1.03 × 10⁹ /s | one or more per message, plus 20M maker fills |
| Egress packets | 163.5M /s | one per request packet + ~18M maker packets |
| Egress, line rate | ~249 Gbps (62%) | 250 B per 10-record response, ~110 B per small response |
| Order stream | ≤ 25 Gbps per path | on 2 dedicated replication ports on two leaf switches (01 §14.7); 11 B10 limit |
| Capture for B3 (§2.1) | ~310M frames/s | 145.5M in + 163.5M out, on 8 tap ports |
| Data tier ingress | 242 Gbps | the client's second copy |
| Durable log per replica | 23.2 GB/s (≤ 26 GB/s, DESIGN §7) | payloads 20.7 GB/s + order stream 2.5 GB/s |
| Local hot log per replica | 12 h at ≤ 37% mean load | 12 × 30.72 TB = 369 TB = 4.4 h at full load; 01 §14.16 asks ≥ 6 h at peak (Open question 8) |

### 5.3 Requirements

**REQ-THR-1. One book sustains 10⁹ inbound messages per second.**
- Point: generator and NIC counters; latency at `M-WIRE`. Conditions: `REF`, `WL-REF`,
  order-to-trade ≥ 100:1 (crosses ≤ 1%). Test: B3, B9.
- Bound: 1.0 × 10⁹ **accepted** msgs/s for 10 minutes after warm-up (messages of shed packets do
  not count); zero RX drops; lane load ≤ `REQ_LANE_MAX_LOAD` and BBO load ≤ `BBO_MAX_LOAD` in every
  1 s window; every REQ-LAT requirement holds in the same run, REQ-LAT-1 and REQ-LAT-5 included.

**REQ-THR-2. The cross ceiling is `CROSS_CAP`, and the BBO core is protected above it.**
- Statement: the book sustains `CROSS_CAP` crosses/s at BBO load ≤ `BBO_MAX_LOAD`. Above it, lane
  cross buckets (REQ-THR-6) reject crosses with `RATE_LIMIT`, and BBO load stays ≤
  `REQ_BBO_HARD_LOAD` (0.65) in every 1 ms window, for any client behaviour. Test: B3
  (`WL-XSWEEP` records the knee), B24, B23 (`WL-ADV-6`).

**REQ-THR-3. Packet rate.** The sequencer receives ≥ 160M packets/s (`WL-REF` + 10%) across its
4 client ports with zero drops, ≥ 40M packets/s on any one port, and sends ≥ 180M packets/s.
Test: B9, and B1 run at these per-port rates.

**REQ-THR-4. Bandwidth.** At full `WL-REF`, no client port exceeds 70% of line rate on ingress or
75% on egress. The order stream uses the 2 dedicated replication ports (01 §14.7), each ≤ 30% of
line rate. Test: B10, B3.

**REQ-THR-5. Session and account envelopes are token buckets on `rx_ts`.** Each session has the
04 buckets and each account has the 10 §3.8 buckets. The tier defaults are:

| Tier | Typical holder | Session msgs/s (burst) | Session pkts/s (burst) | Account `New`+`Replace`/s (burst) | Account crosses/s (burst) | Max live orders per account |
|---|---|---|---|---|---|---|
| A | market-maker sub-account | 5,000,000 (5,000) | 800,000 (500) | 3,000,000 (5,000) | 100,000 (1,000) | 400,000 |
| B | active taker | 250,000 (1,000) | 200,000 (200) | 200,000 (1,000) | 60,000 (500) | 25,000 |
| C | retail or slow | 2,000 (100) | 1,000 (50) | 1,000 (50) | 200 (20) | 500 |

All values are budgets. 10 §3.8's defaults (1M/s and 100k/s) are the tier B ceiling for
`new_bucket` and the tier A value for `cross_bucket`. Tier A overrides `new_bucket` by config.
Cancels have their own bucket and are always accepted (10 §3.7). The arithmetic is 04's (GCRA on
`rx_ts`), so replicas reproduce every `RATE_LIMIT` reject (04 P10). Test: B24.

**REQ-THR-6. Each lane has an allocation and a cross bucket, by lane class.**
- Admission, dedicated lane: the sum of configured session msg rates ≤ `REQ_LANE_OVERSUB` (1.25)
  × 20M msgs/s; the sum of packet rates ≤ 1.25 × 3M packets/s; every account on it belongs to one
  firm. Pool: the sum over the pool ≤ 1.25 × 26M packets/s and ≤ 7 × `MAX_SESSIONS_PER_LANE`
  sessions. On every lane the sum of max live orders ≤ 2²⁴ (`SLOT_BITS`). `vyrn-admin` refuses a
  session or account that breaks a sum.
- Lane buckets, lane-local state on `rx_ts` (each pool core keeps its own; the core is logged in
  `PacketRecord.lane`): dedicated lane cross 70,000/s (burst 700), improve 410,000/s (4,100);
  pool core cross 1,150,000/s (11,500), improve 680,000/s (6,800). Sums: 10.99M crosses/s
  ≤ 1.1 × `CROSS_CAP`, and 21.98M improves/s.

- Reason: account buckets alone do not bound the sum over accounts. With these lane buckets the
  worst sustained BBO load is 11M × 15 + 22M × 8 ns per s = 0.34 (0.36 with depletions), below
  `REQ_BBO_HARD_LOAD`. Owner: 10 (buckets), 05 (lane). Test: B24.

**REQ-THR-7. Book-group mode.** In a group of up to `K` cold books on one box (01 §12.3, 03):
the sum over the group ≤ 10⁹ msgs/s; each book ≤ `CROSS_CAP` on its own BBO core; every REQ-LAT
requirement holds for each book; the lane envelope (REQ-THR-6) applies to the group's sum. One
book's flow affects another book only through shared lanes. Test: B36.

**REQ-THR-8. Replicas keep up.** A replica replays ≥ 1.0 × 10⁹ msgs/s sustained with per-block
replay lag p99 ≤ 2 ms, and catches up at ≥ 1.2 × 10⁹ msgs/s (`BLD_CATCHUP_RATE`), for both the
Rust and the Vx client. The market-data replica in the sequencer's facility runs inside
REQ-LAT-11. Test: B12.

**REQ-THR-9. The data tier ingests every copy.** The data tier receives the full `WL-REF` copy
stream (242 Gbps) with zero loss at the node, and delivers each payload to every replica with
arrival p99 ≤ 200 µs after the sequencer's `rx_ts` (`BLD_DATA_ARRIVAL_P99_US`). Test: B10.

**REQ-THR-10. Capacity variants keep the SLOs.** REQ-THR-1 and REQ-LAT-1 hold with 3 × 10⁸
resting orders on the book (`WL-DEEP`) and with 200,704 sessions (`MAX_SESSIONS_PER_LANE` × the
49 lanes of the 01 §10 map, `WL-SESS`). Test: B39.

**REQ-THR-11. Per-target throughput.**

| Target | Requirement | Test |
|---|---|---|
| `REF` | 1.0 × 10⁹ msgs/s per book (REQ-THR-1) | B3 |
| `CONSUMER` | 2.4 × 10⁸ msgs/s per book: 11 lanes (`N_LANES_CONSUMER`) × 22M (01 rounds it to ~250M) | B20 |
| `AWS` | min(10⁹, 10 × B16's drop-free packets/s) msgs/s at `count` = 10, with REQ-LAT-8; the sequencer adds no limit below the instance's packet rate | B16 |
| `DEV` | none; `vyrn-sim` correctness only | B4 (build E) |

On AWS, 1B msgs/s needs ≥ 100M drop-free packets/s at `count` = 10. That is a fact of the
instance (01 §14.0, fact 1), measured by B16; `REF` carries the full specification.

## 6. Workload model

Every benchmark names one workload ID from this section. 11 implements the generator
(`vyrn-bench gen`) and keeps its configs in `bench/workloads/` (11 §2). If a number here and a
generator config disagree, this section wins.

### 6.1 Workload IDs

| ID | Definition |
|---|---|
| `WL-REF` | The reference workload, §6.2–§6.11, at a stated rate (default 10⁹ msgs/s). |
| `WL-LANE` | `WL-REF` restricted to the sessions of dedicated lane 0 (11 B2), paced and unpaced. |
| `WL-POOL` | `WL-REF` restricted to the pooled sessions (TK and RT), stepped from 10% to 100% of their full rate (B3 curve, B21). |
| `WL-XSWEEP` | `WL-REF` with the cross share stepped from 0.1% to 3.0% in 0.1-point steps of 60 s. Other types scale down in proportion. |
| `WL-LOW` | `WL-REF` at 10⁷ msgs/s, plus idle probes: single 1-message packets after 1 ms, 100 ms and 1 s of silence on their lane. |
| `WL-DIURNAL` | 24 h at 10% of full rate, except at each epoch start: 10 min at 100% then 50 min at 30%. Mean ≈ 14% (computed). |
| `WL-DEEP` | `WL-REF` with the order-lifetime tail weight (§6.7, row 4) raised until 3 × 10⁸ orders rest. |
| `WL-SESS` | `WL-REF` with RT raised until the pool holds 7 × 4,096 sessions and MM sessions raised until each dedicated lane holds 4,096 (200,704 in all), same total message rate. |
| `WL-AUCTION` | 10³, 10⁵ or 10⁶ orders arriving in an auction phase (11 B14). Prices: §6.5 join distances around the last trade, both sides, with 30% of orders through the reference price. |
| `WL-AWS` | `WL-REF` scaled to 80% of B16's drop-free packet rate. `count` ≤ 10. |
| `WL-ADV-1` … `WL-ADV-9` | Adversarial workloads, §6.12. Each runs on top of `WL-REF` at 60% of full rate. |

### 6.2 Generator structure

```
 seed ─► per-session PRNG streams ─► arrival schedule (open loop, fixed in advance)
                                          │ at each send time:
 vyrn-md feed ─► model book (BBO + depth) ──┤ choose type, side, price, qty, TIF (§6.4–§6.7)
                                          ▼
                              packetize (§6.8) ─► MAC (both tags) ─► send twice (04 §2.4)
 sequencer per-class counters (1 s) ─► controller: corrects type probabilities (§6.10)
```

- **PRNG.** xoshiro256** per session, seeded with SplitMix64(`run_seed` ⊕ (`SessionId` << 1)).
  The report records `run_seed`. **Open loop:** send times are fixed before the run and never
  wait for a response (11 §7.1, rule 3). Content is chosen at send time.
- **Model book.** Each generator keeps the book's BBO and the depth of the best 64 levels per side
  from `vyrn-md`. It is a few µs stale. That staleness is part of the workload: it makes some
  intended joins arrive as crosses and some improves arrive as rejects.
- **Price grid.** Tick ladder per 10 §3.5. The run starts from a book with the mid at tick
  1,000,000, built by 60 s of `WL-REF` warm-up that the measurement discards (11 §7.1, rule 4).

### 6.3 Population

| Class | Who | Sessions | Accounts | Lanes | Share of messages | Rate skew |
|---|---|---|---|---|---|---|
| MM | the top 17 firms by volume, on dedicated lanes. Firm f holds L_f lanes, L = (10, 6, 4, 3, 3, 2, 2, 2, 2, then 1 × 8) = 42; one sub-account per lane | 252 (6 per lane) | 42 | dedicated lanes 0–41, one firm each (01 §14.15) | 97.0% | equal per lane: top firm 23.8% of MM, top 4 firms 54.8% |
| TK | active takers | 4,000 | 4,000 | the pool (lanes 42–48) | 2.5% | Zipf(s = 0.5): top session 0.8% of class TK |
| RT | retail and slow clients | 24,000 | 24,000 | the pool | 0.5% | uniform |
| | **Total** | **28,252** | **28,042** | 6 per dedicated lane; 28,000 in the pool (≤ 7 × 4,096) | | |

Computed consequences: every dedicated lane gets 23.1M msgs/s from one firm, and each MM session
sends 3.85M msgs/s (tier A). The pool gets 30M msgs/s in 25.8M packets/s. The top TK session sends
200k msgs/s. An RT session sends 208 msgs/s.

### 6.4 Message mix

Each message counts in exactly one class. A `Replace` counts as the class of its new price. A
`CancelAll` counts as one cancel.

| Class | Join | Cancel | Reduce | Improve | Cross | Total |
|---|---|---|---|---|---|---|
| MM | 49.00 | 44.20 | 2.00 | 1.55 | 0.25 | 97.00 |
| TK | 0.80 | 0.65 | 0 | 0.40 | 0.65 | 2.50 |
| RT | 0.20 | 0.15 | 0 | 0.05 | 0.10 | 0.50 |
| **All** | **50.00** | **45.00** | **2.00** | **2.00** | **1.00** | **100.00** |

Percent of all messages. So: join 50%, cancel or reduce 47%, improve 2%, cross 1%, and the
order-to-trade ratio is 100:1. 11.5% of join-class messages are `Replace`. That fraction makes the
book stationary (computed): orders added (joins + improves + resting cross residuals ≈ 522.5M/s)
equal orders ended (cancels 450M/s + replaced 57.5M/s + filled ~15M/s).

Flags: MM orders carry STP "cancel newest" (01 §6.2 bits 4–5 = 1). Improves carry post-only.
Others carry neither.

### 6.5 Prices

**Joins.** Distance `d` in ticks behind the own side's best (d = 0 is at the best):

| Probability | `d` |
|---|---|
| 0.40 | 0 |
| 0.20 | 1 |
| 0.30 | 2 + min(G, 7), G ~ Geometric(p = 0.25) on {0, 1, …} |
| 0.09 | ⌊10 × 409.6^U⌋, U ~ Uniform[0, 1): log-uniform on [10, 4,095] |
| 0.01 | 4,096 + ⌊60,000 × U⌋: beyond `TICK_HOT_WINDOW`, into the overflow structure |

Side: buy or sell with probability 0.5. An MM quote bundle (§6.8) has 5 buys and 5 sells. If the
own side is empty, `d` counts from the opposite best minus one tick.

**Improves.** Price = own best + 1 tick toward the other side, when the model spread is ≥ 2 ticks.
Otherwise the generator sends a join at d = 0, and the controller (§6.10) compensates.

**Crosses.** The taker sweeps `k` levels of the model book:

| Probability | `k` |
|---|---|
| 0.80 | 1 |
| 0.12 | 2 |
| 0.06 | uniform on 3–5 |
| 0.019 | uniform on 6–20 |
| 0.001 | uniform on 21–200 (deep sweep) |

Limit = opposite best + (k − 1) ticks, through. Quantity = model depth over the k levels ×
U[0.5, 1.0], at least 1 lot. TIF: IOC 0.70, day 0.25, FOK 0.05. Of the day crosses, 0.4% use
quantity = 1.2 × model depth, so a residual rests through the old touch. That is 0.1% of crosses
(10⁴/s), and each one can trigger a rescan (05).

### 6.6 Quantities

Joins and improves: MM and TK 1 + Geometric(p = 0.2) lots (mean 5); RT 1 + Geometric(p = 0.5)
lots. `Reduce`: `reduce_by` = ⌊qty / 2⌋ of a live order of the session with d ≤ 3, chosen
uniformly. If that order has 1 lot, the generator sends `Cancel` instead.

### 6.7 Order lifetimes

At each join or improve, the generator draws a lifetime `T`. At time of entry + T, if the order
is still live, it ends: by `Cancel` with probability 0.885, by `Replace` to a new join price with
probability 0.115.

| Row | Probability | `T` |
|---|---|---|
| 1 | 0.60 | log-uniform on [5 µs, 100 µs] |
| 2 | 0.30 | log-uniform on [100 µs, 1 ms] |
| 3 | 0.09995 | log-uniform on [1 ms, 100 ms] |
| 4 | 0.00005 | log-uniform on [100 ms, 8 h]; orders alive at an epoch end carry over |

Mean T ≈ 0.117 s (computed). By Little's law ~61M orders rest at full rate, ~1.2M per lane
(computed), within 2²⁴ slots per lane. `WL-DEEP` raises row 4.

### 6.8 Packetization

| Class | Packets | `count` | Carries |
|---|---|---|---|
| MM bundle | quote bundles | 10 | all MM joins, replaces and reduces; 95% of MM cancels |
| MM urgent | urgent | 1 or 2 (p = 0.5 each) | MM crosses, MM improves, 5% of MM cancels (each MM cancel independently, p = 0.05) |
| TK | every message | 1 (p = 0.8) or 2 (p = 0.2) | all TK messages |
| RT | every message | 1 | all RT messages |

Computed packet rates at 10⁹ msgs/s: MM bundle 93.0M/s, MM urgent 26.7M/s, TK 20.8M/s, RT 5.0M/s;
total 145.5M/s. The generator rigs must send ≥ 40M packets/s per SUT port (Interfaces, item 9).

### 6.9 Arrivals and bursts

- MM bundles form a Poisson process at r_s / 10 per session. All other messages form a
  Poisson process at the session's rate; a 2-message packet carries two drawn at one instant.
- **Bursts.** Global burst events form a Poisson process at 20/s. During [t, t + 100 µs] every
  MM and TK session sends at 2 × its rate. Base rates are divided by 1.002 so that the long-run
  mean is the target rate.
- Session rates follow §6.3 and stay within the session's tier buckets (MM = A, TK = B, RT = C).
- **Pacing.** Each MM firm's sends on a dedicated lane pass through one `LANE_PACE` pacer per
  lane (04 §3.6): send time = max(scheduled time, previous send + pace of the previous packet).
  The report gives the pacer delay separately; it is not part of `L`. `WL-LANE` also runs with
  the pacer off, which gives B3's unpaced dedicated curve. Pooled sessions are not paced.

### 6.10 Lane assignment and the mix controller

- MM: firm f's sub-account j on the j-th of its L_f dedicated lanes, firms in rank order from
  lane 0 (10 §1.3). TK and RT: every session is pooled. Its home pool core (its UDP port, 04 §2.2)
  is chosen by sorting sessions by expected cross rate, descending, and assigning each to the
  pool core with the smallest cross rate so far (ties: smaller message rate, then lower
  `LaneId`). Each pool core ends within ±1% of 1.07M crosses/s (computed); stealing evens out the
  rest at run time.
- **Controller.** Once per second, the generator reads the sequencer's per-class counters
  (11 §8) and corrects each class probability with gain 0.5 toward the target mix. A run is valid
  only if, over the measured interval, the realized shares are within ±0.1 point of target for
  crosses and improves, and within ±1 point for joins and cancels.

### 6.11 Probe sessions

The measured population is the probe sessions: sessions 2 and 5 of the 6 on each dedicated lane
(84), and in each (home pool core, class) the two sessions of rank ⌈n/4⌉ and ⌈3n/4⌉ by rate (28).
That is 112 probe sessions. They run their class's
normal behaviour, so the measured messages are real flow, not synthetic pings. Probes cover every
message type and outcome of §3.3 within each 10-minute run (11 B9).

### 6.12 Adversarial workloads

Each runs on `WL-REF` at 60% of full rate. Victims are every session not in the attack, fully captured. Every
run also passes B4 (bit-identical replay) and matches the Vx oracle.

| ID | Attack | Pass |
|---|---|---|
| `WL-ADV-1` | **One-level pile-up.** 50% of all joins go to one tick at the best bid for 60 s, building ~10⁷ orders at one level across all 49 lanes. Then sweeps at the max order quantity (10 §3.4), one per 10 ms. | Victims: REQ-LAT-1 (max ≤ `LAT_MAX_NS`) and `BUSY` within REQ-LAT-5 for their lane class; maker packets per REQ-LAT-4. |
| `WL-ADV-2` | **Cancel storm.** Every MM session sends `CancelAll` within one 10 µs window, then re-quotes. 10 per second. | First `CancelAck` per REQ-LAT-1, last per REQ-LAT-10; no fill of an order after a cut that covered its cancel; victims as `WL-ADV-1`. |
| `WL-ADV-3` | **Deep sweeps.** Crosses over k = 200–5,000 levels, through the overflow structure, 1,000/s. | Victims as `WL-ADV-1`; BBO load ≤ `REQ_BBO_HARD_LOAD` in every 1 ms window. |
| `WL-ADV-4` | **Single-account flood.** One tier-B session sends at 10 × its buckets; its port runs at the switch policer limit. | `RATE_LIMIT` rejects replay bit for bit, each within `LAT_MAX_NS`; victims in the same pool as `WL-ADV-1`. Run again from one dedicated lane: only that firm's own sessions may see `BUSY`. |
| `WL-ADV-5` | **MAC-failure spoofing.** (a) Packets with real `SessionId`s and random tags from unbound addresses, at the attacker port's policer limit. (b) Packets with a victim's bound address sent from another switch port. | (a) No victim session closes; per-packet cost ≤ 8 ns (04 P4); counters match; victims as `WL-ADV-1`. (b) The switch drops 100% (REQ-SEC-3). |
| `WL-ADV-6` | **Rescan storm.** Alternating-side day crosses that leave residuals through the touch, at the lane cross-bucket limit. | BBO load ≤ `REQ_BBO_HARD_LOAD` per 1 ms; `INV-UNCROSSED` in every snapshot; victims as `WL-ADV-1`. |
| `WL-ADV-7` | **Resend and replay storm.** 100 sessions send `ResendReq` for 65,536 packets at once; captured packets are replayed with the resend flag and without it. | Nothing re-executes; resends meet REQ-LAT-10; victims as `WL-ADV-1`. |
| `WL-ADV-8` | **Equivocating client.** Different logical content to the sequencer and to the data tier (04 §2.4). | Session closed by a control record; every other order final ≤ `FINALITY_MAX_MS`; in CHAIN the bond pays (09). |
| `WL-ADV-9` | **Snapshot race.** Joins from many lanes at prices the BBO core has just moved through, at the maximum rate the buckets allow (the slow path of the crossing lemma, 05). | Oracle-equal fills; `INV-UNCROSSED` holds; BBO load ≤ `REQ_BBO_HARD_LOAD`. |

## 7. Finality and durability

### 7.1 Finality

**REQ-FIN-1. Every accepted order is final within 10 ms, as a maximum.**
- Point: `M-FIN`. Bound: max ≤ `FINALITY_MAX_MS` (10 ms) over every accepted order of the run;
  p50 ≤ 4 ms (DESIGN §5: ~3 ms). Test: B11, B26.
- Conditions: `BASE` and `CHAIN`; full `WL-REF`; voting replicas in separate facilities at 0.5 ms
  one-way; healthy, with one voting replica powered off, and across a sequencer crash. In the
  one-down case every quorum needs all remaining voters, and views led by the dead node must time
  out fast (07). The sequencer never votes (01 §14.4).
- Mechanism: the gate (REQ-FIN-5) halts the book before it issues a fill that cannot be final in
  time. After a sequencer crash, the voters finalize the order stream they already hold: every
  response was frame-gated (01 §14.5), so they hold every answered order.
- Fact (01 §14.0, fact 3): finality needs a network that meets its delay bound. While it does
  not, the book halts; it never issues a fill that misses the bound. A byzantine sequencer that
  stalls is replaced by failover, and the orders it delayed are final within
  `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS`.

**REQ-FIN-2. Clients learn finality within 11 ms.** Replicas publish, per block, the finalized
height and its last `StepId`. A client in the home metro receives it by `M-FIN-C` max ≤ 11 ms.
Owner: 07, 10. Test: B11 (client-side tap).

**REQ-FIN-3. A response that reached the wire does not revert, except under the revert
condition.** Statement: every response (fill, ack, reject) whose first bit left the sequencer is in
the final log, because every response is frame-gated (01 §14.5), unless all three of these hold:

1. The sequencer stops (crash, or byzantine omission) before at least one correct replica holds
   the order stream for the whole prefix up to the fill's step s.
2. For every correct replica, some frame of that prefix was lost on both `REPL_PATHS`.
3. No correct replica could repair the missing frame or its payload from another replica, a data
   node or the sequencer before the sequencer stopped.

```
 sequencer: frame(s) ─► path A ─► path B ─► fill(s) ─► wire        (INV-FRAME-FIRST)
 time ─────────┬───────────────────────────────────┬──────────────────────────────►
               t_f                                  t_f + w      w = flight + repair ≈ 1 ms
               │◄─────── exposure window w ────────►│
 revert ⇔ sequencer stops inside w  ∧  the frame is lost on A  ∧  lost on B  (at every correct replica)
```

- Test: B5 compares a full 2 s capture of fills with the replayed final log (≥ 100 kills). B25
  forces each case of the condition and checks that a revert happens only when all three hold.
- The three conditions above are case (a) of 07 §9.6. That list, cases (a)–(e), is the exhaustive
  set of revert causes (01 §14.19 B). Every revert happens before the fill's block is final; none
  happens after.
- In CHAIN mode, one more case exists and is not a revert of the log: a packet whose `tag_com`
  fails at the committee is busted (09 §1, decision 6). The fill stays in the final log, its
  balance effects are reversed at a boundary, and the session bond pays the counterparties
  (REQ-CHN-4). The verdict is final no later than the fill's own block.

**REQ-FIN-4. Expected reverted fills ≤ 10⁻⁶ per year.**
- Budget inputs: frame loss per path ≤ 10⁻⁹, independent between paths; sequencer stops ≤ 1 per
  year; ~3 × 10⁴ steps in one 1 ms window at full load.
- Computed: 1 × 3 × 10⁴ × (10⁻⁹)² ≈ 3 × 10⁻¹⁴ per year. Test: B10 and B32 (24 h of per-path
  frame-loss counters) bound the loss rate; B25 checks the logic.

**REQ-FIN-5. The unfinalized part of the order stream is bounded.**
- `BASE` and `CHAIN`: ≤ `FIN_GATE_BLOCKS` (8 in both modes) blocks, by `INV-CHN-TXGATE` (09 §4.6, 01
  §14.9). When the gap reaches it, the book halts: every packet gets `BOOK_HALTED` within
  `LAT_MAX_NS`, and nothing waits in the NIC rings. Reason: it keeps REQ-FIN-1 a maximum, and it
  turns a dead quorum into a halt, not unbounded risk.
  Test: B26 (kill 2 voters; the halt starts within 8 blocks), B29 (gate never binds when healthy).

**REQ-FIN-6. A sequencer failover costs ≤ 20 ms.**
- Point: `M-OUT`. Bound: max ≤ `FAILOVER_TARGET_MS` (20 ms) over ≥ 50 kills, because 01 §14.0
  fact 3 bounds delayed orders by `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS`.
  Detection starts after `FAILOVER_SILENCE_MS` (2 ms) of silence. Conditions: B3's load on a
  `BASE` cluster; the four kill methods of 11 B5. Test: B19.

**REQ-FIN-7. Orders are processed exactly once across a failover.** A packet is identified by
`(session, pkt_seq)`. After failover, a client resends every packet without a response. The new
sequencer processes a packet that is not in the final log, and for a packet that is, it answers
from the log (04 §5). No packet is processed twice. Test: B19 (client-side check), B28.

**REQ-FIN-8. A byzantine sequencer's phantom fill is detected within finality.** A sequencer can
send a `Fill` that it never logs. A correct client detects it by `M-FIN-C` + 1 ms, by comparing
its fills with the finality feed and the drop copy (REQ-LAT-12). v1 gives no transferable proof:
response tags are MACs, not signatures. Test: B25 (injected phantom fill).

**REQ-FIN-9. Safety and liveness thresholds.** n counts voters only; `vyrn-seq` never votes (01 §14.4).

| Mode | n | Quorum | Liveness tolerates | Safety tolerates | Reason |
|---|---|---|---|---|---|
| `BASE` | 4 (R1 in F1 with `vyrn-seq`, R2–R4) | 3 | 1 crashed or byzantine | 1 byzantine | two quorums share 3 + 3 − 4 = 2 replicas, at least one correct |
| `CHAIN` | 5 | 4 | 1 | 2 byzantine | two quorums share 4 + 4 − 5 = 3 validators |

`CLIENT_SPLIT_BASE` and `CLIENT_SPLIT_CHAIN` add: a bug in one client stops finality and never
finalizes a wrong block. Test: B4, B26 (split-client divergence drill).

### 7.2 Durability, recovery and catch-up

**REQ-FIN-10. A replica votes only for durable data.** A replica signs a vote for a block only
after the block's order stream and every payload it references are written to its local NVMe and
flushed, on drives with power-loss protection. At 23.2 GB/s per replica (§5.2) this needs ≥ 4
NVMe drives per replica (budget); REF has 12 × 30.72 TB (01 §14.7). Test: B26 (power cut of all boxes of the home at once: every
finalized block is readable after restart).

**REQ-FIN-11. A replica catches up within 5 minutes.**
- Engine snapshots every `REQ_SNAPSHOT_PERIOD_S` (600 s) of order-stream time. A returning
  replica loads the latest one, replays the log after it at ≥ 1.2 × 10⁹ msgs/s, then follows.
- Bound: back to live (replay lag ≤ 2 ms) ≤ `REQ_CATCHUP_MIN` (5 min) after it starts, at the
  `WL-DIURNAL` mean load (14%). Computed: 10 min of log is ~1.95 TB (156 s at 100 Gbps) and ~84B
  messages (70 s of replay); closing the lag that builds meanwhile takes ~30 s more.
- Test: B34.

**REQ-FIN-12. Recovery point and recovery time per failure class.**

| Failure | RPO (fills on the wire) | RTO (trading) | Finality | Owner | Test |
|---|---|---|---|---|---|
| One lane core faults | 0 | the sequencer fail-stops after 1 ms of lane silence (01 §10), then as the next row | ≤ `FINALITY_MAX_MS` for answered orders | 03, 05 | B26 |
| Sequencer process or box | 0, except REQ-FIN-3 | ≤ `FAILOVER_TARGET_MS`: the warm standby in F2 takes over, never a voter (01 §14.4) | ≤ `FINALITY_MAX_MS` for answered orders (REQ-FIN-1) | 07 | B5, B19 |
| One voting replica | 0 | 0 | REQ-FIN-1 one-down case | 07 | B11 |
| One data node | 0 | 0 | max ≤ `FINALITY_MAX_MS` | 07 | B26 |
| One replication path | 0 | 0 | unchanged; alarm (REQ-OPS-3) | 07, 03 | B26 |
| Facility F1 (`vyrn-seq` + R1) | 0, except REQ-FIN-3 | ≤ `FAILOVER_TARGET_MS`; R2–R4 are a quorum | REQ-FIN-1 one-down case | 07, 03 | B26 |
| Facility F2 (standby + R2), F3 or F4 | 0 | 0 | REQ-FIN-1 one-down case | 07, 03 | B26 |
| Two voting replicas | 0 | halted within 8 blocks (REQ-FIN-5), `BOOK_HALTED` within 1 µs; restore ≤ 30 min (budget) | stopped | 07 | B26 |
| Divergence between Rust and Vx clients | 0 | halted until fixed | stopped (by design) | 07, 11 | B26 |
| PTP loss on the sequencer | 0 | 0 in holdover; halt if offset > 1 µs for > 1 s (REQ-OPS-10) | unchanged | 06 | B26 |
| WAN loss between homes | 0 | 0 now; the next handoff is extended (REQ-EPO-7) | unchanged | 08 | B27 |
| Whole home metro | finalized fills not yet at a follower home: ≤ finality + WAN one-way to the nearest follower (TYO ~90 ms, LDN ~45 ms, NYC ~45 ms) | manual emergency re-home ≤ 15 min (REQ-OPS-6) | stopped until re-home | 08 | B26 (drill) |

The metro row is a published limit of v1. A fill can be final in its metro and still be lost if
the whole metro is destroyed before the log reaches another home. Closing that gap needs a
cross-home acknowledgement before finality, which adds a WAN one-way latency to finality (Open
question 6).

## 8. Epochs and handoff

### 8.1 Timeline

```
 old home (epoch e)                          new home (epoch e+1)
 ──────────────────┬─────────────────────────────────────────────────────────────────────►
   continuous      T  last step S                                 start: uncross, then continuous
   trading         │◄─ finality of S ─►│◄──── WAN one-way ────►│◄ ≤ 5 ms ►│
                   │   ≤ 10 ms max      │ cert(e, S) + log tail  │ verify,   │
                   │                    │ cross the ocean        │ uncross   │
   auction at the new home collects orders from T ──────────────────────────►│
                   │◄───────────────── handoff window (M-EPO) ─────────────────►│
```

### 8.2 Requirements

**REQ-EPO-1. The home rotates TYO → LDN → NYC every `EPOCH_HOURS`.** Epoch boundaries are
`EPOCH_BOUNDARIES_UTC`. The boundary is the step S in the `HandoffRecord`, not a clock
(`INV-FENCE`). Owner: 08. Test: B13, B28.

**REQ-EPO-2. The handoff window is finality plus one WAN one-way.**
- Point: `M-EPO`. Bound per transition (budget):

  | Transition | WAN one-way (DESIGN §6 estimate) | Nominal window | Pass bound (+ 5 ms slack, 11 B13) |
  |---|---|---|---|
  | TYO → LDN | ~110 ms | ~120 ms | WAN + 15 ms (~125 ms) |
  | LDN → NYC | ~35 ms | ~45 ms | WAN + 15 ms (~50 ms) |
  | NYC → TYO | ~80 ms | ~90 ms | WAN + 15 ms (~95 ms) |

- The pass bound uses the WAN one-way measured in each run by PTP-stamped probes, so a slow WAN
  fails the WAN, not the design. Conditions: 60% of full `WL-REF`; followers caught up
  (REQ-EPO-9). Test: B13 (30 handoffs per pair, every one within the pass bound), B37 (real WAN,
  staging).
- Reason: the new home cannot match against a book it has not received. Light sets the floor.

**REQ-EPO-3. No order is lost or duplicated across a handoff.** Every packet a client sends is in
exactly one of these states: (a) in epoch e's log with its responses; (b) in epoch e+1's auction
or log with its responses; (c) never accepted, and the client knows it because it got no
in-stream response (04 P7) and may resend it to the new home. `(session, pkt_seq)` continues
across the boundary. Test: B28 (clients that send through the boundary at full bucket rate; every
`pkt_seq` is answered once).

**REQ-EPO-4. The handoff cannot fork.** After cert(`HandoffRecord` e, S), no replica accepts an
epoch-e record with step > S (`INV-FENCE`). A frame from the old sequencer after S is rejected
everywhere. Test: B28 (old sequencer kept running after S, with its frames injected).

**REQ-EPO-5. The opening auction resets latency advantages.**
- The new home accepts orders for epoch e+1 from T. Before T it rejects them (`EPOCH_MISMATCH`).
- No order entered during the window gets priority from its arrival time within the window. At
  the clearing price, resting orders from epoch e keep their time priority, and window orders at
  the same price share pro rata with deterministic lot rounding (08 defines it).
- The clearing price maximizes executed quantity, then minimizes imbalance, then is nearest to
  epoch e's last trade price (08 defines the final tie-break).
- `Cancel`, `Reduce` and `Replace` of epoch-e orders sent during the window apply before the
  uncross, in arrival order.
- Auction-only orders (TIF 3) take part only in the auction. IOC and FOK orders take part in the
  uncross, and any remainder is `Out`.
- Every window order gets its first record within `LAT_MAX_NS` (REQ-LAT-1): an `Ack` that it
  joined the auction, or a reject (01 §14.0, fact 2). Its outcome at the uncross comes within 1 ms
  of the start (`BLD_UNCROSS_US_MAX` for 10⁶ orders, 11 B14).
- The uncross is deterministic and equals the Vx oracle's. Test: B14 (time, oracle), B28.
- Reason: the window is ≥ one WAN one-way, so a client in the old home that sends at T still
  reaches the auction. Pro rata inside the window means distance to the new home buys nothing.

**REQ-EPO-6. Resting orders carry over.** The book at S, with its resting orders and their
priorities, is the book of epoch e+1. A session may opt in to "cancel at boundary" (04, 08): its
resting orders are canceled at S as part of epoch e. Test: B28.

**REQ-EPO-7. An epoch is extended when the new home is not ready.**
- At T − `REQ_EPO_READY_LEAD_S` (300 s) the new home reports readiness: every node of its replica
  set is up; followers lag the finalized log by ≤ 1 s; the new sequencer runs the epoch's engine
  version and passed its B1 self-test at start; session keys for e+1 are issued.
- If it is not ready, the old home finalizes an `EpochExtend` record that moves T by
  `REQ_EPO_EXTEND_MIN` (15 min), and checks again. `EpochNotice` reaches every session ≥
  `REQ_EPO_NOTICE_S` (60 s) before the T in force.
- Extension stops at the next scheduled boundary. The schedule then skips the unready home and
  hands to the following one.
- If the new home holds cert(e, S) but its sequencer cannot start, its own replicas fail over
  (REQ-FIN-6). If no node of the new home can start within 1 s, the book stays halted until
  operators finalize a re-home record that names another home (09 `HandoffTimeout`; REQ-OPS-6).
  Test: B27.

**REQ-EPO-8. Clients are told in advance.** `EpochNotice` carries the next epoch, the next home
and seconds to the boundary. The sequencer sends one to every session at T − 60 s and T − 5 s, and
after every change of T. Test: B27.

**REQ-EPO-9. Follower homes keep up.** Each follower home's replicas lag the active home's
finalized log by ≤ WAN one-way + 5 ms at p99, at full `WL-REF`. That needs WAN capacity per
follower home of ≥ 1.25 × the peak log rate: 1.25 × 23.2 GB/s ≈ 230 Gbps at full load (computed).
Test: B37. Owner: 07, 08 (Open question 5).

**REQ-EPO-10. Keys and lanes change only at boundaries.** Session keys for e+1 (`K_seq`, `K_com`,
`K_out`) and the next sequencer's key (`HandoffRecord.next_seq_key`) are issued before T.
Lane moves of accounts happen at boundaries only (10 §1.6). Test: B28.

## 9. Chain mode

`09-chain.md` owns every mechanism here. These are the properties it must have.

**REQ-CHN-1. The committee is 5 operators with quorum 4, split across two clients.**
`N_CHAIN` = 5, `Q_CHAIN` = 4, `F` = 1, `CLIENT_SPLIT_CHAIN` = 3 Rust + 2 Vx. The 5 validator boxes
vote; `vyrn-seq` never votes, and the sequencing operator votes from its validator box (01 §14.4).
No operator runs two committee nodes in one home. Configuration that breaks any of these is refused at load. Test: B31.

**REQ-CHN-2. No packet is forged unless 2 operators are byzantine.** A packet enters the final log
only with a valid `tag_seq` (checked by the sequencer) and a valid `tag_com` (checked by the
other 4). The sequencing operator never holds `K_com` (09 §1, decision 3). A forced-path packet
carries a session-key signature instead (09 §4.5, `ForcedPacket`). Test: B29 (one byzantine
operator with its keys tries every path; nothing it forges finalizes).

**REQ-CHN-3. Latency and throughput are those of BASE.** REQ-LAT-1 to -13 and REQ-THR-1 hold in
CHAIN mode; `tag_com` is checked on validators, off the fast path. Test: B3, B9 in CHAIN.

**REQ-CHN-4. A bad `tag_com` busts the packet, and its bond pays.** Matching is not rewound. The
fills of the bad packet's orders are reversed at the boundary of 09 §4.6, the counterparties are
paid from the session bond, and the session is suspended once `CHN_TAGFAULT_QUORUM` committee
members report it. The bond covers the worst-case bust of one gate window (09 §5.9). Test: B29.

**REQ-CHN-5. Anyone can re-verify the whole log.** `K_com` of each interval is disclosed after its
blocks are final (TESLA-style, 09). A third party with the public archive replays it and gets the
same state commitments, bit for bit. Test: B30.

**REQ-CHN-6. Custody is on an L1 bridge with 4-of-5 signatures.** Balances are chain state. The
Ethereum L1 contract checks 4-of-5 secp256k1 signatures (09 §1, decision 7). Deposits are
credited only after L1 finality (vendor: two Ethereum epochs, about 12.8 min). A withdrawal leaves
only with 4 signatures over a finalized balance root that contains it, after the 60 s batch and
the 1 h challenge period. If the validators stop posting for 14 days, the escape hatch opens
against the last posted root. Test: B30 (L1 testnet).

**REQ-CHN-7. Every validator keeps the full log available.** Each validator stores the full
order stream and data: ≤ 26 GB/s at peak (DESIGN §7), 23.2 GB/s at full `WL-REF` (§5.2). It keeps
12 h on its own NVMe (12 × 30.72 TB; 12 h holds at ≤ 37% mean load, computed), and the archive
node in its facility keeps `REQ_DA_HOT_DAYS` (7 days) hot (01 §14.7). After that, snapshots and a
public archive held by ≥ 2 operators, kept ≥ 7 years (policy). A hot block is served within 1 s,
an archived block within 24 h. Test: B30.

**REQ-CHN-8. State commitments every second.** Every 1 s of order-stream time the committee
certifies 4-of-5 a balance root (sparse Merkle tree) and a resting-order lattice hash over the
net diff (09 §1, decision 8), within `REQ_CHN_COMMIT_LAG_S` (2 s) after the second ends. A
`CommitCert` is posted to L1 at least every 60 s. Test: B30.

**REQ-CHN-9. A forced packet is final within 10 ms, like any order, and the sequencer cannot
censor it.** Under an honest sequencer, a forced-path packet is positioned at the first block
boundary after the block that includes it is notarized (01 §14.9). Bound: max ≤ `FINALITY_MAX_MS`
from send, by `M-INC`. `FIN_GATE_BLOCKS` (8) is only the deadline after which validators treat
its absence as censorship: evidence plus failover, and then it is final within
`FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` (01 §14.0, fact 3). The sequencing operator is never the
Simplex leader (09 §1, decision 4). Test: B29.

**REQ-CHN-10. Equivocation is slashed automatically.** Two valid `seq_sig`s for one
`(book, height)`, a double vote, a fence violation, a double commit vote and bridge equivocation
are evidence (09 §1, decision 9). The slash applies at the first boundary after the evidence is
included. Evidence is accepted for `CHN_EVIDENCE_EPOCHS` (14 days). Each node persists its signing
high-water mark before every signature (09 §2.5), so an honest node never equivocates after a
restart. Test: B30.

**REQ-CHN-11. Sequencer front-running is capped and published.** The sequencing operator rotates
every epoch (e mod 5, 09 §3.1) and is bonded (`CHN_SEQ_BOND`). After each epoch the chain
publishes per-sequencer fill-quality statistics computed from certified data (09 §1, decision
10). Test: B30.

**REQ-CHN-12. The gate never binds in a healthy run.** The gate halts the book (REQ-FIN-5), so it
binds in 0 book blocks at full `WL-REF`, healthy or with one voter down, in BASE and CHAIN. Test:
B29, B11.

## 10. Platform

**REQ-PLT-1 (C-UNIX).** Every binary builds and runs on Linux 6.6+ on x86-64 and aarch64. The DEV
roles (`vyrn-sim`, `vyrn-vx-oracle`, replay) also run on macOS aarch64. No role needs Windows, a
hypervisor feature or a proprietary OS. Test: B4 (builds A–E), B31.

**REQ-PLT-2 (C-NOCHIP).** No box of any role has an FPGA, an ASIC designed for this, a
programmable switch, a SmartNIC or DPU running our logic, or a GPU. Fixed-function features of COTS
parts are allowed: NIC flow steering, RX timestamps, CTPIO, switch ACLs and policers. Nothing is
loaded into a NIC or a switch: no eBPF offload, no P4, no custom firmware. Test: B31 (inventory by
`lspci -nn` and firmware versions against 06's allowlist, on every production box at each epoch
start).

**REQ-PLT-3 (C-COTS).** Every part on every target's bill of materials is orderable from a public
vendor catalog, within the classes of 00 (x86-64 or aarch64 CPUs; Solarflare X2, ConnectX-6/7 or
ENA NICs; merchant switches with PTP; NVMe). Test: B31 (BOM review).

**REQ-PLT-4 (C-ONEBIN).** A release has exactly one artifact per (binary, architecture). `REF`,
`CONSUMER` and `AWS` run byte-identical x86-64 artifacts. Configuration selects the NIC backend
(ef_vi, DPDK, kernel UDP, sim) and the core map. Test: B31 (BLAKE3 of each running binary equals
the release manifest); B3, B16 and B20 run the same artifact.

**REQ-PLT-5. Pinned cores make no syscall and no allocation after `seal()`.** Test: B3 and B32 run
with a seccomp filter, installed on each pinned thread at `seal()`, that kills the process on any
syscall, and with the aborting allocator (`INV-NOALLOC`). Pass: no kill and no abort.

**REQ-PLT-6. Boxes and NICs are qualified before use.** Every NIC model and firmware passes B1:
max echo (RX + TX) ≤ `NIC_FLOOR_NS` (560) over the whole run, with TX ≤ 240, because the TX tail
after the doorbell is not covered by deadline admission. A GPU echo (B-GPU) may reopen C-NOCHIP
only if it passes the same bound (01 §14.7).
Every box passes B18 on every core of its core map and B17 (PHC skew p99 ≤ 25 ns, max ≤ 100 ns),
at commissioning and after any change of firmware, BIOS, microcode or kernel.

**REQ-PLT-7. Replay is identical on every platform.** One log gives the same outputs and state on
every build of B4: x86-64, aarch64, macOS and Vx. Test: B4.

| Target | Must achieve | Not required | Tests |
|---|---|---|---|
| `REF` | the full specification, every number at once: every REQ-LAT at `M-WIRE`; REQ-THR-1; any role | — | B1–B15, B17–B19, B21–B39 |
| `CONSUMER` | REQ-LAT-1 to -7 at `M-WIRE`; 2.4 × 10⁸ msgs/s; any role at that rate | 1B msgs/s | B20 |
| `AWS` | REQ-LAT-8 at `M-TSC`; REQ-THR-11 rate; any role | facts, not exemptions: the wire is Nitro's; the rate is the instance's packet rate (01 §14.0) | B16 |
| `DEV` | bit-identical replay; `vyrn-sim`; Vx oracle; protocol test vectors | latency; throughput | B4 (build E) |

## 11. Security

**REQ-SEC-1. Every packet is authenticated before it acts.** The sequencer checks `tag_seq` before
any message of the packet acts. In CHAIN mode validators check `tag_com` before they vote; in BASE
it is 0. Responses carry a `K_out` tag. Test: B24, B23 (`WL-ADV-5`).

**REQ-SEC-2. The bad-MAC rule of 01 §12.5 and §14.8 holds.** A bad MAC closes the session
(`BAD_MAC`) only when it comes from the bound address and `epoch16` matches the receiver's epoch. From any other address the packet is dropped and counted, with no SipHash, at
≤ 8 ns per packet (04 P4). Test: B23 (`WL-ADV-5`).

**REQ-SEC-3. Source addresses are bound to switch ports.** The edge switch admits only the source
addresses registered to each client port, and polices each port at ≤ 1.2 × the sum of its
sessions' packet buckets (04 §3.4, 06). Test: B23 (`WL-ADV-4`, `WL-ADV-5`b).

**REQ-SEC-4. One client cannot hurt another.** A client at its port's policer limit, with any
content, leaves every victim inside REQ-LAT-1 and REQ-LAT-5 and never closes a victim's session.
Test: B23 (`WL-ADV-4`, `WL-ADV-5`).

**REQ-SEC-5. Replays never execute.** `pkt_seq` is gapless, `epoch16` is checked, and a resend is
answered from retained responses (01 §14.6; `RESEND_GONE` only when both stores dropped it). A captured packet sent again never runs twice. Test: B23
(`WL-ADV-7`), B28.

**REQ-SEC-6. Keys rotate every epoch.** Each session's `K_seq`, `K_com` and `K_out`, and the
sequencer's signing key (`HandoffRecord.next_seq_key`), are per epoch. A leaked epoch key exposes
that epoch only. Test: B28.

**REQ-SEC-7. Keys live only in process memory.** Signing and MAC keys come from the secret manager
at start and stay in `mlock`ed memory. They never appear in config files, logs, metrics or core
dumps, and core dumps are off on every role. Test: B31 (secret scan of configs, logs and metric
exports; core-dump settings).

**REQ-SEC-8. A node signs only for the active home.** A node signs only when the finalized schedule
makes its home active (09 §2.6), and persists its high-water mark before each signature. Test: B30.

**REQ-SEC-9. Privileged actions are finalized records.** Halt, resume, parameter changes, epoch
extension and re-home take effect only as finalized records: two operators through `vyrn-admin` in
BASE, 4 operator keys in CHAIN (09 §2.10). Test: B26, B27.

**REQ-SEC-10. Memory-unsafe code is confined.** `unsafe` Rust appears only in the SPSC rings, the
lane arena and the NIC shim (DESIGN §8). C appears only in `vyrn-nic-shim`. CI fails on any other.
Test: B31.

**REQ-SEC-11. An equivocating client is closed.** Two validly tagged copies of one `pkt_seq` with
different logical content close the session (04 §2.4). Test: B23 (`WL-ADV-8`).

## 12. Operations

**REQ-OPS-1. Metrics without touching the fast path.** Pinned cores write counters to shared
memory only. The control core exports every 1 s: lane and BBO load, cut age, ring depths, RX drops,
MAC failures (bound and unbound), `RATE_LIMIT` counts per bucket, finality lag, frame loss per
replication path, follower lag, PTP offsets, NVMe free space, and `M-TSC` histograms per type.
Names are 11 §8's. Test: B32.

**REQ-OPS-2. Wire latency is watched in production.** Production `REF` keeps the splitters and the
capture rig on every client port. Probe sessions run in production at 1,000 packets/s each. An
alert fires on any sample above `LAT_MAX_NS − DEADLINE_GUARD_NS`, and when the `BUSY` rate over
60 s exceeds its lane class's bound (REQ-LAT-5). Test: B32.

**REQ-OPS-3. Alarms fire within 1 s.** Conditions: lane or BBO load > 0.60 over 1 s; cut age >
`CUT_REFRESH_NS`; any lane-stage `BUSY` on a paced dedicated lane; any class above its REQ-LAT-5 bound; any block's finality > `FINALITY_MAX_MS`; finality lag > 4 blocks; any frame lost on one replication
path; follower lag > WAN one-way + 50 ms; PHC skew > 100 ns; NVMe below 2 days of hot retention;
any replica down. Test: B26.

**REQ-OPS-4. Upgrades happen only at epoch boundaries.** A replica set never mixes engine versions
inside an epoch. The epoch's engine version is certified with the handoff (Requests to 01, item
4). An emergency fix uses a finalized halt, the upgrade, then a finalized resume. Test: B38.

**REQ-OPS-5. A release passes a fixed gate.** B4 on the golden logs and on the last 24 h of
production logs; B1, B3, B9, B21 and B22 on `REF` with every (type, index) cell of §3.3; B20 on
`CONSUMER`. 11 owns the
checklist.

**REQ-OPS-6. Every runbook exists and is drilled.** Runbooks: sequencer failover, replica loss,
data-node loss, facility loss, two-box loss, client-divergence halt, metro loss (emergency
re-home), epoch extension, key compromise, book halt and resume, NIC requalification, PTP failure,
CHAIN slashing response, bridge pause. Each is drilled monthly in staging. The sequencer failover
is drilled quarterly in production, in the lowest-load epoch. Test: B26, B27.

**REQ-OPS-7. Any incident replays on a laptop.** Any production interval replays bit-identically on
`DEV` from the archive within 1 h of the request. Test: B4 (build E).

**REQ-OPS-8. Capacity is reported and enforced.** A daily report gives each lane's allocation
against REQ-THR-6 and each book's cross headroom. Admission refuses over-allocation. Test: B24.

**REQ-OPS-9. Halts are fast.** A finalized halt takes effect at the first block boundary after its
finality. A local emergency halt by the sequencer (PTP or storage alarm) takes effect within 1 ms
and is logged in the order stream. Test: B26.

**REQ-OPS-10. A bad clock halts the book.** The sequencer runs in PTP holdover on loss of sync, and
halts the book if any of its NICs is > 1 µs from the grandmaster for > 1 s. Reason: the level FIFO
orders by RX timestamp across NICs (11 B17). Test: B26.

## 13. Benchmarks

B1–B20 are 11 §7.3 with these criteria, which replace 11's where they differ. No benchmark passes
on a percentile of first-record latency, on a subset of packet sizes, or on normalized latency.

| # | Pass (changed criterion) |
|---|---|
| B1 | NIC echo max (RX + TX) ≤ `NIC_FLOOR_NS` = 560 over the whole run, TX max ≤ 240, at REQ-THR-3's per-port rates |
| B3 | full `WL-REF` at 10⁹ msgs/s, full capture: **max over the whole run ≤ `LAT_MAX_NS`** for every message, every type and every index 0–9, maker fills included (REQ-LAT-1, -4); **dedicated paced `BUSY` = 0 and pooled `BUSY` ≤ 10⁻³** (REQ-LAT-5); the published curve: pooled `BUSY` at 10–100% load (≤ 10⁻⁶ at ≤ 20%), dedicated `BUSY` paced and unpaced, and the rx-gap compression per dedicated lane; 10⁹ accepted msgs/s (REQ-THR-1) |
| B9 | every (type, index) cell of §3.3 at 10%, 60% and 100% load: max ≤ `LAT_MAX_NS`; stage maxima per REQ-LAT-2 |
| B11 | max finality ≤ `FINALITY_MAX_MS` for every accepted order, healthy and one voter down (REQ-FIN-1) |
| B13 | every handoff within REQ-EPO-2's pass bound; every window order acked within `LAT_MAX_NS` |
| B16 | REQ-LAT-8 max at `M-TSC`; REQ-THR-11 rate |

B21–B39 are new. 11 defines them fully.

| # | Name | Workload | Pass |
|---|---|---|---|
| B21 | Lane admission and queueing | `WL-LANE` and `WL-POOL`, with bursts | paced dedicated `BUSY` = 0; pooled `BUSY` within REQ-LAT-5 at each load step; zero late `BUSY`; lane wait max ≤ `REQ_BUSY_WAIT_MAX_NS`; token and steal costs ≤ `REQ_POOL_TOKEN_NS`; lane stage maxima (REQ-LAT-2, -3, -7) |
| B22 | BBO, TX and stream admission and queueing | `WL-REF` | dedicated `BUSY` ≤ `REQ_BUSY_DED_FULL` (≤ `REQ_BUSY_DED_LOW` at ≤ 20%), all from these shared stages; hop, step, gate and TX-core maxima on all three TX cores (REQ-LAT-3); BBO load ≤ 0.60 per 1 s |
| B23 | Adversarial suite | `WL-ADV-1` … `-9` | each row of §6.12 |
| B24 | Rate envelope | `WL-REF` + bucket probes | every bucket of REQ-THR-5 and -6 rejects as the oracle does; admission refuses over-allocation; BBO ≤ 0.65 per 1 ms |
| B25 | Revert condition | `WL-REF` + fault injection | REQ-FIN-3 (revert only when all three conditions hold); REQ-FIN-8 |
| B26 | Failure-class drills | `WL-REF` at 60% | each row of REQ-FIN-12; REQ-FIN-5 pause; REQ-FIN-10 power cut; REQ-OPS-3, -9, -10 |
| B27 | Readiness and extension | `WL-REF` at 60%, 3 homes | REQ-EPO-7, REQ-EPO-8 |
| B28 | Handoff correctness | `WL-REF` + `WL-AUCTION` | REQ-EPO-3 to -6, -10; REQ-FIN-7 |
| B29 | Chain authentication and forced path | `WL-REF`, CHAIN | REQ-CHN-2, -4, -9 (forced max ≤ 10 ms), -12 |
| B30 | Chain commitments, custody, DA, slashing | `WL-REF`, CHAIN, L1 testnet | REQ-CHN-5 to -8, -10, -11 |
| B31 | Platform and supply audit | — | REQ-PLT-1 to -4; REQ-CHN-1; REQ-SEC-7, -10 |
| B32 | 24 h soak | `WL-DIURNAL` | REQ-LAT-1 max over 24 h (probe sessions plus in-box `M-TSC` on every packet); REQ-PLT-5; frame-loss counters; REQ-OPS-1, -2 |
| B33 | Low load and idle | `WL-LOW` | REQ-LAT-6 |
| B34 | Replica catch-up | `WL-DIURNAL` | REQ-FIN-11 |
| B35 | Drop copy | `WL-REF` | REQ-LAT-12: every fill exactly once, p99 ≤ 50 µs |
| B36 | Book group | `WL-REF` split over K books | REQ-THR-7 |
| B37 | WAN follow | `WL-REF`, 3 homes, real WAN | REQ-EPO-2 on the real WAN; REQ-EPO-9 |
| B38 | Upgrade at a boundary | `WL-REF` at 60% | REQ-OPS-4 |
| B39 | Capacity variants | `WL-DEEP`, `WL-SESS` | REQ-THR-10 |

## 14. Non-goals for v1

v1 is fully collateralized spot (01 §12.1). These are out of v1:

- Margin of any kind (v2 adds isolated-margin linear perpetuals; cross-margin is out of scope);
  options; multi-leg orders; implied matching.
- Order types beyond 01 §6.2 (no stop, iceberg, hidden, pegged or good-till-date orders), and
  auctions other than the opening auction at each handoff.
- One book across several boxes. (`CONSUMER` is a smaller target at 2.4 × 10⁸ msgs/s; on AWS the
  wire and the packet rate are facts of the instance, §3.5. Neither is a non-goal of `REF`.)
- FIX or any text protocol on the order-entry path; IPv6 (04 §2.1); per-packet signatures on the
  fast path; ZK proofs of execution.
- Cross-ocean consensus; automatic takeover after the loss of a whole metro.
- Prevention of sequencer front-running (capped and published, REQ-CHN-11); a transferable proof
  of a phantom fill (REQ-FIN-8); fairness finer than the cut between lanes.
- Windows, GPUs, FPGAs or NIC offload of any logic, on any role.

## 15. Traceability matrix

| Requirement | Owner | Test |
|---|---|---|
| REQ-LAT-1 | 05, 06 | B3, B9, B32 |
| REQ-LAT-2 | 05, 06, 07 | B9, B10, B21, B22 |
| REQ-LAT-3 | 05, 06, 07 | B3, B10, B21, B22, B4 |
| REQ-LAT-4 | 05, 04, 03 | B3, B9, B23 |
| REQ-LAT-5 (dedicated: pacing; pooled: M/M/c) | 05, 04, 03 | B3 (curve), B21, B22 |
| REQ-LAT-7 | 05 | B9, B21 |
| REQ-LAT-6, -8, -9 | 06 | B33, B16, B20 |
| REQ-LAT-10 | 04, 05 | B9, B23 |
| REQ-LAT-11, -12 | 10 | B15, B35 |
| REQ-LAT-13 | 07, 08 | B19, B13 |
| REQ-THR-1 | 05 | B3, B9 |
| REQ-THR-2 | 05, 10 | B3, B23, B24 |
| REQ-THR-3, -4 | 06, 03 | B1, B9, B10 |
| REQ-THR-5, -6 (per lane class) | 04, 10, 05 | B24 |
| REQ-THR-7, -10 | 03, 05 | B36, B39 |
| REQ-THR-8, -9 | 07, 11 | B12, B10 |
| REQ-THR-11 | 06 | B3, B16, B20 |
| REQ-FIN-1, -2 | 07 | B11, B26 |
| REQ-FIN-3, -4 | 07 | B5, B10, B25, B32 |
| REQ-FIN-5 | 07, 09 | B26, B29 |
| REQ-FIN-6, -7 | 07, 04 | B19, B28 |
| REQ-FIN-8, -9 | 07, 10 | B25, B4, B26 |
| REQ-FIN-10, -11 | 07 | B26, B34 |
| REQ-FIN-12 | 07, 03, 08 | B26 |
| REQ-EPO-1, -2 | 08 | B13, B37 |
| REQ-EPO-3, -4, -6, -10 | 08, 04 | B28 |
| REQ-EPO-5 | 08 | B14, B28 |
| REQ-EPO-7, -8 | 08 | B27 |
| REQ-EPO-9 | 07, 08 | B37 |
| REQ-CHN-1 | 09 | B31 |
| REQ-CHN-2, -4, -9, -12 | 09 | B29 |
| REQ-CHN-3 | 09, 05 | B3, B9 |
| REQ-CHN-5 to -8, -10, -11 | 09 | B30 |
| REQ-PLT-1 to -4 | 06, 11 | B4, B31 |
| REQ-PLT-5, -7 | 05, 11 | B3, B32, B4 |
| REQ-PLT-6 | 06 | B1 (max ≤ 560 ns), B17, B18 |
| REQ-SEC-1 to -4 | 04, 06 | B23, B24 |
| REQ-SEC-5, -6 | 04, 08 | B23, B28 |
| REQ-SEC-7, -10 | 11 | B31 |
| REQ-SEC-8, -9 | 09, 04 | B30, B26, B27 |
| REQ-SEC-11 | 04, 07 | B23 |
| REQ-OPS-1 to -3 | 11 | B26, B32 |
| REQ-OPS-4, -5, -7 | 11, 08 | B4, B38 |
| REQ-OPS-6 | 11 | B26, B27 |
| REQ-OPS-8 | 10 | B24 |
| REQ-OPS-9, -10 | 08, 06 | B26 |

## Interfaces to other chapters

**Consumes:** 01 (all names, constants, layouts, invariants); DESIGN §2–§9; 04 P4, P7, P8, P10,
§2.4; 09 §1, §2.5, §2.6, §4.6; 10 §3.4, §3.7, §3.8; 11 §7 (B1–B20 and the `BLD_*` values cited).

**Provides:**

| To | What |
|---|---|
| all | `REQ-*` IDs, measurement points (§2), the envelope (§3.1), the three facts (§3.5) |
| 03 | stage owners (§4.1); port load limits (REQ-THR-4); book-group requirement (REQ-THR-7); TX-A/B/C (cores 3, 5, 0) and stream-A/B (cores 4, 7) load budgets (§5.2); control on core 51; the maker-packet limit per step (REQ-LAT-4) |
| 04 | `BUSY` and resend-redirect semantics (REQ-LAT-3, -10); the `LANE_PACE` requirement and its jitter budget (§4.4.1); tier session buckets (REQ-THR-5); cancel-at-boundary option (REQ-EPO-6); auction `Ack` in the window (REQ-EPO-5) |
| 05 | REQ-LAT-3 hard post-admission stages; REQ-LAT-5 per lane class; the pool's token and steal cost (`REQ_POOL_TOKEN_NS`); background slices ≤ `PROTO_PACE_MARGIN_NS`; rescan slicing (§4.4.3); §4.1 lane, BBO and cut rows; lane buckets per class (REQ-THR-6); `REQ_BBO_RESCAN_NS` |
| 06 | §4.1 NIC rows (RX 320, TX 240, B1 as a max); per-port packet rates (REQ-THR-3); REQ-PLT-*; target table (§10) |
| 07 | REQ-FIN-*; the 8-block gate in BASE (REQ-FIN-5); finality across a sequencer crash (REQ-FIN-1); frame-gate row (§4.1); durable-before-vote (REQ-FIN-10); snapshot cadence |
| 08 | REQ-EPO-*; the `EpochExtend` and re-home records; auction semantics (REQ-EPO-5) |
| 09 | REQ-CHN-*. 09's `B-CHN-*` names map onto B29 and B30 here; 11 merges them |
| 10 | tier account buckets (REQ-THR-5); REQ-LAT-11, REQ-LAT-12; capacity report (REQ-OPS-8) |
| 11 | the workloads (§6) replace 11 §7.1's short descriptions; B21–B39; the max criteria of §13 for B1, B3, B9, B11, B13, B16; full capture (~310M frames/s) for B3 and B9; generator rigs ≥ 40M packets/s per SUT port (11 §7.2 says 25M) |

## Local definitions

| Name | Value | Meaning |
|---|---|---|
| `REQ_BUSY_DED_MAX` | 0 | Lane-stage `BUSY` on a paced dedicated lane (REQ-LAT-5, 01 §14.17.2) |
| `REQ_BUSY_DED_FULL`, `REQ_BUSY_DED_LOW` | 10⁻⁵, 10⁻⁸ | Total dedicated `BUSY` (shared BBO, TX and stream stages; crosses and improves only) at full book load and at ≤ `REQ_POOL_LOW_LOAD` |
| `REQ_BUSY_POOL_FULL`, `REQ_BUSY_POOL_LOW` | 10⁻³, 10⁻⁶ | Pooled `BUSY` per pooled packet at full book load, and at ≤ `REQ_POOL_LOW_LOAD` (REQ-LAT-5) |
| `REQ_INGRESS_LOSS_MAX` | 10⁻⁶ | Edge-policer drops per sent packet for sessions within their buckets (REQ-LAT-14) |
| `REQ_POOL_LOW_LOAD` | 0.20 | Book load below which the low bounds of both classes apply |
| `REQ_POOL_TOKEN_NS` | 20 | Account-token CAS inside CCD 7's L3, on every pooled path (01 §14.15) |
| `REQ_BUSY_WAIT_MAX_NS` | 180 | Lane wait at which a `BUSY` still meets the bound: 1,000 − 20 − 800 (REQ-LAT-3; dequeue age 500) |
| `REQ_LANE_MAX_LOAD` | 0.60 | Lane busy fraction in every 1 s window (§3.1) |
| `REQ_MAKER_PKT_NS` | 16 | Extra time per maker packet of a step on one TX core (REQ-LAT-4; 04 §7.1) |
| `REQ_LANE_IMPROVE_RATE` | 410,000/s dedicated, 680,000/s pool core | Lane improve bucket (REQ-THR-6) |
| `REQ_BBO_RESCAN_NS` | 400 | BBO-core time per rescan (budget) |
| `REQ_BBO_HARD_LOAD` | 0.65 | BBO load limit per 1 ms window under any behaviour (REQ-THR-2) |
| `REQ_LANE_OVERSUB` | 1.25 | Lane allocation factor over 20M msgs/s and 3M packets/s (REQ-THR-6) |
| `REQ_LANE_CROSS_RATE` | 70,000/s dedicated, 1,150,000/s pool core; burst 1% of rate | Lane cross bucket; class sums ≤ 1.1 × `CROSS_CAP` (REQ-THR-6) |
| `REQ_SNAPSHOT_PERIOD_S`, `REQ_CATCHUP_MIN` | 600, 5 | Snapshot period; catch-up bound in minutes (REQ-FIN-11) |
| `REQ_EPO_READY_LEAD_S`, `REQ_EPO_EXTEND_MIN`, `REQ_EPO_NOTICE_S` | 300, 15, 60 | Readiness check before T; extension step (min); minimum notice (s) (REQ-EPO-7) |
| `REQ_CHN_COMMIT_LAG_S` | 2 | Commitment lag (REQ-CHN-8) |
| `REQ_DA_HOT_DAYS` | 7 | Hot retention on the facility archive node (REQ-CHN-7) |
| `REQ_CAP_ERR_NS`, `REQ_PTP_BOX_NS` | 5, 1,000 | Capture-port error; box-to-box PTP error (§2) |

All values are budgets. Definitions: received, accepted and shed packet, `L`, slack, envelope,
probe session (§1); measurement points `M-*` (§2); workloads `WL-*` (§6.1).

## Requests to 01

Resolved: the ack sum (§14.17.1), `FINALITY_P99_MS` (§14.9), the REQ-LAT-5 gap (§14.15, §14.17).

1. Add `LANE_MAX_LOAD = 0.60` (11 §7.23 asks the same); this chapter uses `REQ_LANE_MAX_LOAD`.
   Add a resend-redirect record (e.g. `Reject` 25 `RESEND_RECOVERY`) for REQ-LAT-10.
2. **Lane count.** *Resolved by 01:* §5 has `N_LANES_REF` = 49, and §14.3 puts cut B on lanes 25–48 with
   the hasher on core 50, as the §10 map does.
3. **§14.1's last bullet** still says `BUSY` ≤ 1e-6 of all packets at 1B msgs/s. Replace it with
   §14.17.2's per-class bounds, which REQ-LAT-5 uses.
4. **§14.17.5:** ~40 makers at index 9 needs ≤ 7.5 ns per maker packet per TX core; at 04's
   16 ns three TX cores fit 18 (REQ-LAT-4). State the cost or the number.
5. **BBO load.** §14.15 item 2 gives ~0.21 at 10M crosses + 20M improves; with `BBO_IMPROVE_NS` =
   8 the sum is 0.31 (0.33 with depletions and rescans, §4.4.3).
6. **Pooled 10-message packets.** With the 20 ns token the worst pooled ack at index 9 is 985,
   above the 980 threshold, so such a packet is always shed. Hide the CAS under the RX poll, or cap
   pooled packets at 9 messages.
7. **Dequeue age:** with the 170 + 20 ns cut term the oldest answerable age is 500, not §14.16's 520.
8. Add `engine_version: u32` to `HandoffRecord` (REQ-OPS-4), and `EpochExtend { book, epoch,
   new_boundary: Nanos }` to §6.6 or let 08 define it.
9. Promote `REQ_LANE_CROSS_RATE` and `REQ_LANE_IMPROVE_RATE` per lane class, so 05 and 10 share
   one definition. State in §5 that `F` is the liveness bound and CHAIN safety holds with 2
   byzantine validators (REQ-FIN-9).

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | The old Open question 1 (REQ-LAT-5 failed with shared single-server lanes) is resolved by 01 §14.15 and §14.17.2 (§4.4). New: how many maker packets fit behind a taker in the first steps of a sweep: 18 at 16 ns on three TX cores, or ~40 as 01 states? And does the leaf preserve paced gaps within `PROTO_PACE_JITTER_NS` = 25 ns at 60% port load? | 03, 04, 06 | B3 (maker timing, rx-gap histogram per dedicated lane) |
| 2 | TX-A/B/C (~16M packets/s each) and stream-A/B (~89M records/s each) are single servers after the admission test, shared by every client. REQ-LAT-3 needs hard bounds for them: first records before maker packets, and a rate cap. Can 05 and 07 prove them, and keep dedicated `BUSY` ≤ 10⁻⁵? | 05, 07 | B10, B22 |
| 3 | `WL-REF` needs 36.4M packets/s in and 40.9M out per port. B1 tests 25M, and 11's generators send 25M. Does the X2541 sustain it, with echo max ≤ 560 ns? | 06, 11 | B1, B9 |
| 4 | Full capture for B3 is ~310M frames/s on 8 tap ports. Which COTS capture NICs time-stamp every frame at that rate? | 11 | B3 dry run |
| 5 | Followers need ~230 Gbps of WAN per home at full load (REQ-EPO-9). Buy that, or ship state diffs instead of the full log? | 07, 08 | B37 |
| 6 | Metro loss can lose finalized fills (REQ-FIN-12). Accept it, or add a cross-home acknowledgement that costs one WAN one-way in finality? | 07, 08 | B26 drill and a cost study |
| 7 | REQ-FIN-1 as a maximum with one voter down needs a worst-case Simplex view change that fits in 10 ms after the gate's lag, in a 0.5 ms metro. | 07 | B11, B26 |
| 8 | 12 × 30.72 TB holds 12 h only at ≤ 37% mean load and 4.4 h at full load. 01 §14.16 asks ≥ 6 h at sustained peak, which needs ~500 TB at 23.2 GB/s. More drives, or a smaller log? | 07, 06 | B32, B34 |
| 9 | ~61M resting orders exceed L3. Do the per-op budgets hold as maxima with cache misses? | 05 | B6, B39 |
