# 14. The throughput and workload envelope

Draft 0.3, 2026-11-16. Normative where it says "decision"; the numbers are computed from draft 0.2
budgets and have the status of budgets (00). Local names use the prefix `ENV_`. This chapter
follows `01-conventions.md`. 02 still owns every `REQ-*` and `WL-*` ID; this chapter says under
which workload each throughput claim holds and how a result must be reported.

## 0. Decisions in one table

| # | Decision | Reason |
|---|---|---|
| 1 | "1B msgs/s" is a claim about `WL-REF`, not about arbitrary traffic. Every published throughput number names its workload and its regime (§3). | 1B msgs/s needs batching and ≤ 1% crosses (02 §5.1) |
| 2 | Five rates are reported separately, never one: offered, received, admitted, executed, finalized (§1). | A shed or dropped message must not count as capacity |
| 3 | The envelope has six axes (§2). A run states its value on each. | The review's list: packet fill, burstiness, crossing rate, cancels and improves, maker fan-out, active and cold state |
| 4 | A regime outside the reference envelope publishes a ceiling and a shedding curve, not a pass. | §3 |

## 1. Five rates

| Rate | Counts | Measured at |
|---|---|---|
| offered | messages the generator sent | generator counters |
| received | messages in received packets (02 §1): past E1–E4, at the NIC | NIC RX counters minus ingress loss (REQ-LAT-14) |
| admitted | messages of received packets not shed `BUSY` (lane or BBO shed) | lane and BBO counters, the order stream |
| executed | admitted messages whose outcome record left (fill, ack, cancel ack, out, non-`BUSY` reject) | capture at `M-WIRE` |
| finalized | executed messages whose block is final within `FINALITY_MAX_MS` | `DC_FINAL` against the capture |

REQ-THR-1's "accepted" (02 §5.3) is the **admitted** rate. A report lists all five and the
differences between neighbours: ingress loss, `BUSY`, reject outcomes, finality misses.

## 2. The six axes

| Axis | Reference value (`WL-REF`, 02 §6) | Why it matters |
|---|---|---|
| Packet fill `n` (messages per packet) | mean 6.87; 10 for MM bundles | Lane cost is 65 ns per packet + 14 ns per message; port capacity is per packet (§2.1) |
| Arrival burstiness | Poisson; 20 bursts/s of × 2 for 100 µs | Queueing and `BUSY` (02 §4.4) |
| Crossing rate | 1% of messages | `CROSS_CAP` = 10M crosses/s at 15 ns (02 §5.1) |
| Improves and depletions | 2% improves, ~2M depletions/s | BBO load (02 §4.4.3) |
| Maker fan-out | ~18M maker packets/s; ≤ 18 makers behind a taker on three TX cores | TX cores and REQ-LAT-4 (02 open question 1) |
| Active accounts and cold state | 61M resting orders; up to 200,704 sessions (`WL-SESS`) | Cache misses on every per-op budget (02 open question 9) |

### 2.1 The packet-fill ceiling (computed)

Per packet the lane spends 45 ns (MAC, session) + 20 ns (response build), and 14 ns per message
(02 §5.2). On the wire a request packet of `n` messages is ≈ 98 + 16n bytes, preamble and gap
included (02 §5.2: 114 B at n = 1, 258 B at n = 10). With 49 lanes at `REQ_LANE_MAX_LOAD` = 0.60
and 4 × 100GbE client ports:

```
lane bound  = 49 × 0.60 × n / (65 + 14n) ns
port bound  = 4 × 100 Gbps / (8 × (98 + 16n)) × n
```

| n | Lane bound (M msgs/s) | Port bound (M msgs/s) | Ceiling |
|---|---|---|---|
| 1 | 372 | 439 | **372M**, lane-bound |
| 2 | 632 | 769 | 632M |
| 4 | 972 | 1,235 | 972M |
| 6.87 (`WL-REF` mean) | 1,253 | 1,652 | 1,253M |
| 10 | 1,434 | 1,938 | 1,434M |

So **1B msgs/s needs a mean fill of about 4.2 messages per packet** before any other axis binds.
At one message per packet the book's ceiling is ~372M msgs/s, and the 1B/s figure at that fill
would need 1B packets/s, more than twice the ports' 439M packets/s. This holds before the BBO,
TX and stream cores (02 §4.4) are counted, so the true ceilings are lower or equal.

## 3. Regimes

Each regime runs on `REF` and reports §1's five rates, `BUSY` per lane class (REQ-LAT-5), ingress
loss (REQ-LAT-14) and the REQ-LAT-1 maximum, which must hold in every regime because it has no
load envelope.

| Regime | Workload | What is published | Pass |
|---|---|---|---|
| R1 Reference peak | `WL-REF` at 10⁹ msgs/s | the five rates; finality distribution | REQ-THR-1, B3 |
| R2 Small packets | `WL-REF` mix with every packet at n = 1, then n = 2, stepped to saturation | admitted-rate ceiling per n, against §2.1 | REQ-LAT-1 at every step; ceiling within 10% of §2.1's lane bound or explained |
| R3 Adversarial BBO | `WL-ADV-1`, `-3`, `-6`, `-9`; `WL-XSWEEP` | BBO load per 1 ms window and the shedding curve against cross share | REQ-THR-2 (`REQ_BBO_HARD_LOAD`) |
| R4 Cancel storm | `WL-ADV-2` plus cold handles and cancel/fill races | first and last `CancelAck` maxima; cancel correctness | REQ-LAT-10; no fill after a covering cut |
| R5 Faulted operation | `WL-REF` at 60% with one voter down, then a sequencer kill | outage, recovery, finality misses, reverts | REQ-FIN-1 one-down, REQ-FIN-6, 12 §2 |
| R6 Cold state | `WL-DEEP`, `WL-SESS` | per-op stage maxima with cache misses | REQ-THR-10, B39 |

**Decision.** R1 is the only regime that carries the "1B msgs/s" claim. R2–R6 publish curves and
ceilings. A result is never quoted without its regime.

## 4. Disqualification

A run is invalid, not failed, if any of these holds:

1. The five rates in §1 do not reconcile (per port: `sent = received + policed + wire loss`).
2. Any axis of §2 differs from the regime's stated value by more than 5% over a 1 s window.
3. Any (type, index) cell of 02 §3.3 has zero samples (02 REQ-LAT-1).
4. The capture lost frames.

## Interfaces to other chapters

| Chapter | Consumes from 14 | Provides to 14 |
|---|---|---|
| 02 | regime names for B3, B21–B24, B39 reports | `WL-*`, REQ-THR-*, REQ-LAT-14 |
| 05 | §2.1 lane formula | per-op budgets |
| 11 | the report format (§1, §3, §4) | B3, B9, B21–B24, B39 |
| 13 | — | `DAV_TOLERANCE`, a published envelope term |

## Local definitions

| Name | Value | Meaning |
|---|---|---|
| `ENV_PKT_FIXED_NS` | 65 | Lane time per packet: MAC and session 45 + response build 20 (02 §5.2) |
| `ENV_MSG_NS` | 14 | Lane time per message (02 §5.2) |
| `ENV_MIN_FILL_1B` | ≈ 4.2 | Mean messages per packet at which the lane bound reaches 10⁹ msgs/s (computed) |

## Requests to 01

1. State in §14.0 that "1B msgs/s on one book" means R1 of this chapter.

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | How far below §2.1 do the BBO, TX and order-stream cores put the R2 ceiling? | 05, 07 | B3 R2 run |
| 2 | Is R2's packet-rate ceiling the product a small-packet client buys, and should pooled lanes advertise it? | 10 | policy |
| 3 | Does the 65 ns per-packet lane cost hold at n = 1, where MAC work is not amortized? | 05 | B2, B6 |
