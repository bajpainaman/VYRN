# 13. Data availability and the fault model

Draft 0.3, 2026-11-16. Normative where it says "decision"; the rest is analysis on draft 0.2
budgets. Local names use the prefix `DAV_`. This chapter follows `01-conventions.md`. It owns no
mechanism that 07 already owns; it states what 07's mechanisms guarantee, finds where they stop,
and proposes the rules that close the gap.

## 0. The finding in one paragraph

A replica votes only when it holds every payload of the block (07 §6.4 item 3). A payload missing
from the data tier is fetched from the data home, a peer, then the sequencer (07 §5.5). Only the
sequencer has the bytes a client withheld from the data tier, and it serves them at
`REP_SEQ_DATA_MAX_PPS` = 50k packets/s from a 50 ms retention. The reference load is 145.5M
packets/s (02 §5.2), 2,910 times more. Draft 0.2 closes a session whose two copies **differ**
(07 §5.6), but nothing closes a session whose second copy is **absent**. So one client that sends
only to the sequencer can stall every block it touches, and the finality gate (07 §6.8) then halts
the book. This chapter bounds that case and proposes the rule that closes it (§5).

## 1. Fault model

The design tolerates f = 1 Byzantine voter, and a crash or a Byzantine act by the sequencer (07).
For data, the parties and their faults are:

| Party | Crash | Byzantine actions considered |
|---|---|---|
| Client | stops sending (no effect beyond its own orders) | withholds copy 2; sends different copies (equivocation); delays copy 2; sends copy 2 only to some data boxes |
| Data box | stops (07 §5.7) | withholds, corrupts or reorders payloads; drops a session's packets selectively |
| Replica (voter) | f = 1 | withholds repair from peers (07 §10, `REP_A_PEER`) |
| Sequencer | failover (07 §9) | withholds repair (`SeqDataReq`); serves a payload that differs from what it matched |
| Network | path loss (07 §9.6) | none (paths are operator-owned) |

Correlated failures considered: loss of a whole facility (F1, which holds the sequencer and R1);
loss of both replication paths at the sequencer; a data box and a replica in the same facility.

## 2. What draft 0.2 already guarantees

| Case | Mechanism | Outcome | Bound |
|---|---|---|---|
| Copy 2 late by ≤ `REP_DATA_WAIT_US` (300 µs) | join waits | none | — |
| One data box down | 07 §5.7 redirect and resend | finality stalls for the affected blocks | ≤ 3 ms (budget) |
| Copies differ (8-byte hash, `data_root`, or `count`) | 07 §5.6: sequencer's copy is canonical; session closed with evidence | one fetch per misbehaving session | once per session |
| Data box corrupts bytes | the replica hashes every payload itself (07 §5.4) | treated as missing, refetched | as "copy absent" below |
| Data box equivocates to different replicas | same | as above | as above |
| Peer withholds repair | requester moves to the next source | `REP_A_PEER` alarm | not provable (07 §10) |
| Sequencer dead, payload never seen by any data box | seal lists it unavailable; replay excludes it (07 §9.4) | revert case (d) (12 §2) | §4 |

## 3. The repair capacity (computed)

The only source for a payload no data box has is the sequencer's control core.

| Quantity | Value | Source |
|---|---|---|
| Sequencer repair rate | 50,000 packets/s | `REP_SEQ_DATA_MAX_PPS`, 07 §5.5 |
| Sequencer retention | 50 ms | `REP_SEQ_PKT_RETAIN_MS`, 05 |
| Time a vote may stay pending | 4 ms | `REP_VERIFY_WAIT_MS`, 07 §6.4 |
| Wait before fetching | 0.3 ms | `REP_DATA_WAIT_US` |
| **Repair budget per block that still meets the vote deadline** | 50,000 × (4 − 0.3) ms ≈ **185 packets** | computed |
| Packets per 1 ms block at `WL-REF` | 145,500 | 02 §5.2 |
| **Tolerable fraction of packets without a data-tier copy** | 185 / 145,500 ≈ **1.3 × 10⁻³** | computed, across all sessions together |
| Most packets the sequencer can still serve from retention | 50,000 × 0.05 s = **2,500** | computed |

One dedicated-lane firm at `WL-REF` sends 2.85M packets/s (02 §5.2), so 2,850 per block. If it
withholds copy 2 for one block, the sequencer needs 57 ms to serve them. That is past the vote
deadline (the view nullifies) and past retention (the last 350 become unfetchable while the
sequencer lives). Votes on those blocks fail, `lag` grows, and after 8 closed blocks the gate
halts the book (07 §6.8). **One misbehaving firm can halt the book in about 8 ms.** Draft 0.2 has
no rule that stops it, and the halt does not identify the firm.

## 4. Exposure when the sequencer also dies

If the sequencer crashes while payloads are missing from the data tier, those payloads are gone.
The seal lists them unavailable, and every execution of a step that depends on them reverts (case
(d)). The exposure is every packet that was missing at the crash and not yet repaired:

- Honest clients: only packets in flight to a data box inside `REP_DATA_BATCH_US` + one hop. With
  the data home outside F1 (01 §14.16), a sequencer crash does not also lose them, so honest
  exposure is zero for a box crash and ≈ 10 fills/yr for a full F1 loss (07 §5.1).
- A withholding client: up to everything it sent since it stopped sending copy 2, bounded only by
  the finality gate (≤ ~9 ms of fills, 07 §6.8). The reverted fills include its honest
  counterparties' fills.

## 5. Proposed rules (decisions for draft 0.3 review)

1. **DAV-1. Missing copies are attributed per session.** Each voter counts, per session, records
   it had to resolve from the sequencer (source 3) because no data box had them. When the count in
   any window of `DAV_WINDOW_MS` (10 ms) exceeds `DAV_MISS_MAX` (16 packets), the voter signs a
   `DataMissing{session, window, count}`. Q such reports are evidence: the sequencer closes the
   session through the same control op as 07 §5.6. Withholding is not cryptographically provable,
   but Q voters' reports are attributable under f = 1.
2. **DAV-2. Per-session repair quota.** The sequencer serves source-3 requests for one session at
   most `DAV_SESSION_REPAIR_PPS` (2,000 packets/s). A session past it cannot consume the repair
   capacity that other sessions' blocks need. Its own packets then become unavailable at the next
   seal, or the session is closed by DAV-1 first.
3. **DAV-3. Unavailable before halt.** If a block's vote is still pending only on source-3 payloads
   of sessions already reported by DAV-1, the leader may propose those packets unavailable while
   the sequencer lives (07 §9.4's rule, extended), so the gate does not trip for one client's
   behaviour. Their fills revert (case (d)) and the session's bond (CHAIN) or account (BASE) bears
   the cost.
4. **DAV-4. Publish the tolerance.** The service contract states the §3 figure: with DAV-1 to
   DAV-3, misbehaving sessions together may withhold ≤ `DAV_TOLERANCE` of packets per block before
   finality is affected, and no single session can affect another session's finality.

With DAV-1 a withholding firm is closed within 10 ms + one vote round, before the gate's 8 blocks.
That needs checking against 07 §6.6's margins (Open question 1).

## 6. Benchmarks and tests owned here

| ID | What | Pass |
|---|---|---|
| DAV-T1 | `vyrn-sim`: one session withholds copy 2 at 1%, 10%, 100% of its packets | With DAV-1 to DAV-3: the session is closed, the book never halts, no other session's finality exceeds `FINALITY_MAX_MS` |
| DAV-T2 | `vyrn-sim`: withholding plus sequencer crash inside the window | Reverts are exactly case (d) for the withholding session's steps; honest sessions lose nothing outside §4's honest bound |
| DAV-T3 | `vyrn-sim`: a data box corrupts 1% of payloads to one replica | Replica refetches; no vote waits past `REP_VERIFY_WAIT_MS`; `REP_A_PEER` or data-box alarm |
| DAV-T4 | B26 with 10 MM firms withholding in turn on hardware | as DAV-T1 |

## Interfaces to other chapters

| Chapter | Consumes from 13 | Provides to 13 |
|---|---|---|
| 07 | DAV-1 to DAV-3 if accepted: a new evidence type, a quota on `SeqDataReq`, an extended unavailable rule | §5 fetch order, §5.6, §6.4, §6.8, §9.4 |
| 04 | a session-close reason for DAV-1 | the control op of 07 §5.6 |
| 05 | `REP_SEQ_PKT_RETAIN_MS` sizing against §3 | lane packet retention |
| 09 | bond liability for DAV-3 reverts | §5.9 |
| 12 | case (d) bound | lifecycle |
| 14 | `DAV_TOLERANCE` as a published envelope term | the workload envelope |

## Local definitions

| Name | Value | Meaning |
|---|---|---|
| `DAV_REPAIR_PER_BLOCK` | 185 packets | computed: source-3 repairs that fit before `REP_VERIFY_WAIT_MS` |
| `DAV_TOLERANCE` | 1.3 × 10⁻³ | computed: fraction of a block's packets that may lack a data-tier copy |
| `DAV_WINDOW_MS`, `DAV_MISS_MAX` | 10, 16 | proposed: DAV-1 attribution window and threshold |
| `DAV_SESSION_REPAIR_PPS` | 2,000 | proposed: DAV-2 per-session source-3 quota |

## Requests to 01

1. Add DAV-1 to DAV-3 to §14 once accepted, and a 01 §6.5 reject reason for a DAV-1 session close.

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Does DAV-1 close a withholding session before the gate's 8 blocks trip, with 07 §6.6's margins and one voter down? | 07 | `vyrn-sim` DAV-T1 timing |
| 2 | Is 16 packets per 10 ms low enough to stop abuse and high enough that honest packet loss on the data path never triggers it? Needs the measured per-session loss on copy 2. | 07, 06 | B10 per-session loss counters |
| 3 | Should `REP_SEQ_DATA_MAX_PPS` rise? Core 51 also runs control and the finality listener (07 §6.8). | 07, 05 | core-51 load measurement |
| 4 | On AWS (no tap), how are DAV-1 reports checked (10 open question 4)? | 07, 10 | `vyrn-sim` with withheld copies |
