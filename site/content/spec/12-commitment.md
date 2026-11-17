# 12. Execution commitment: what a record promises, and when

Draft 0.3, 2026-11-16. Normative. Local names use the prefix `CMT_`. This chapter follows
`01-conventions.md`; 01 §14.19 B is binding here, and this chapter is its full statement.

A client-visible fill, a durable execution, a final execution and a settled trade are different
commitments. Draft 0.2 described them in four places (DESIGN §0, 04 §7.5, 07 §6.9 and §9.6, 09
§5.9, 10 §8.2) with different words. This chapter is now the single place that says, for each
stage, what can still undo an execution, what evidence authorizes it, and who bears the loss.

## 0. Decisions in one table

| # | Decision | Reason |
|---|---|---|
| 1 | An execution moves through four stages in one order: `EXECUTED` → `DURABLE` → `FINAL` → `SETTLED` (CHAIN adds settlement on chain). No API merges two stages. | 01 §14.13 item 3 |
| 2 | Two mechanisms can undo an execution: a **revert** (the final log does not contain it) and a **bust** (CHAIN only; it stays in the log and compensating transfers reverse it). Nothing else can. | 01 §14.19 B |
| 3 | Both mechanisms end at `FINAL`. A revert is impossible after it. A bust can still execute after it, but only on a verdict that was final no later than the execution itself. | Fate is fixed at finality |
| 4 | `SETTLED` never undoes anything. A settlement failure is a custody incident (09), not a `Bust`. | Draft 0.2's 04 wording is withdrawn |
| 5 | Every way to undo an `EXECUTED` record needs **two independent faults**, a Byzantine sequencer or a misbehaving client, with one named exception: in-box power loss inside a ≤ 100 ns window (revert case (c), §2). | `INV-FRAME-FIRST` (01 §14.5) |

## 1. The four stages

| Stage | Holds when | Time (budget) | Evidence the client holds | Can still undo it |
|---|---|---|---|---|
| `EXECUTED` | The response record left the sequencer. Its order frames were already written to both replication paths (`DUR_PATHS`, 07 §6.9). | ≤ `LAT_MAX_NS` | The record itself | Revert cases (a)–(e); bust |
| `DURABLE` | Q voters hold the frames contiguously (`DUR_QUORUM`, 07 §6.9). | ~0.6 ms | `Attest` level 1; drop-copy `flags.bit2` | Revert cases (d), (e); bust |
| `FINAL` | The block holding the step has a certificate (`INV-QUORUM`). | ≤ `FINALITY_MAX_MS` | `Attest` level 2; `DC_FINAL`; `REP_FinalityCert` (self-verifying) | A bust whose verdict is in this or an earlier final block (CHAIN) |
| `SETTLED` | BASE: the ledger credited the epoch statement. CHAIN: 09's settlement covers the step. | epoch end, or 09's bound | `Attest` level 3; `DC_SETTLED` | Nothing |

Cases (d) and (e) do not depend on how many replicas hold the frames: an unavailable packet or a
truncated Byzantine tail removes the execution even from a durable prefix. Cases (a)–(c) are
losses of the frames themselves, so `DURABLE` closes them.

## 2. Reverts

A revert is defined by the final log: an execution that a client saw is not in it. 07 §9.6 is the
exhaustive list of causes. This chapter adds the evidence and the cost for each.

| Case (07 §9.6) | Faults needed | Evidence that authorizes it | Expected rate (budget, 07 §9.6) | Who bears the loss |
|---|---|---|---|---|
| (a) frame lost on both paths, then sequencer death within `W` | 2 | The seal (07 §9.4): `F* < f(s)` signed by Q voters | ≈ 2 × 10⁻¹⁴ events/yr | nobody: the trade is void (01 §14.19 B item 4) |
| (b) both paths cut at a live sequencer, until the self-fence | 2 | The seal; the sequencer's self-fence record | ≈ 0.19 fills/yr at average load | nobody: the trade is void (01 §14.19 B item 4) |
| (c) in-box power loss while `lead < 0` | 1 power loss inside a ≤ 100 ns window | The seal | ≈ 2 × 10⁻⁴ /yr | nobody: the trade is void (01 §14.19 B item 4) |
| (d) a packet the step depends on is unavailable | client equivocation or withholding, plus a dead sequencer | The seal's unavailable list (07 §9.4) and the voters' missing reports (13 §3) | by design; bounded by 13 §4 | the withholding session, through 13 §5 |
| (e) a tail conflict truncates the prefix | a Byzantine sequencer | `TailConflict` evidence (07 §10) | not a crash case | the sequencer operator (CHAIN: slashed bond, 09) |

**A revert voids the trade (01 §14.19 B item 4).** A reverted execution never happened. No balance
moved and no fee is charged, and the orders involved are wherever the canonical replay puts them.
No one is compensated in cases (a)–(c). In case (d) the misbehaving session keeps its own losses,
and in case (e) the sequencer operator is slashed (CHAIN, 09). A client that acted on a fill before
`FINAL` carries that risk, at the rates above.

**Notification.** Every reverted execution gets a `DC_REVERT` and an `MD_TRADE_BUST` before the
`DC_FINAL` that covers its step (10 §8.2). A client that received the `Fill` and no `DC_REVERT`
by the time that `DC_FINAL` arrives holds a final execution.

**Case (c) is one fault.** Draft 0.2 said every revert needs two. Case (c) needs a power loss inside
a window of at most 100 ns per response, which makes its rate tiny but does not make it two faults.
Decision 5 holds for (a), (b), (d) and (e); (c) is the named exception, and B-REP-2W measures
`P(lead < 0)`. Open question 1 asks whether a TX-side ordering fence can remove it.

## 3. Busts (CHAIN only)

A bust leaves the execution in the final log. Matching replays as it ran (`INV-DET`). At the first
boundary after the block that carries the verdict, lane ops reverse each busted fill's balance
effect and refund both fees (09 §5.9).

- **Cause.** One side's packet failed `tag_com` at the committee. Nothing else busts a fill.
- **Verdict timing.** The exclusion list that names the bad packet is part of the block that holds
  that packet. That block is the fill's own block or an earlier one, so the verdict is final no
  later than the fill (09 §5.9). A fill whose packets passed `tag_com` can never be busted.
- **Execution timing.** The `Bust` record leaves ≤ 9.16 ms after the bad packet was sent (09 §5.9),
  before the `DC_FINAL` that covers the fill's step.
- **Who pays.** The busted session's bond, up to `CHN_BUST_COMP_BPS` of each fill's notional, then
  the insurance fund. Counterparty debt that the reversal creates is settled after
  `CHN_DEBT_GRACE_S` (09 §5.9).
- **Second-order effects stand.** A fill between two other parties that would have gone differently
  is not changed.

## 4. What a client may rely on, stage by stage

| A client that holds | May treat the execution as |
|---|---|
| `EXECUTED` only | Executed and very likely to survive. It may hedge, but it must reconcile against `DC_FINAL`: if the fill reverts, the trade is void and nobody compensates the hedge. |
| `DURABLE` | Lost only through a misbehaving party (cases (d), (e), or a bust). |
| `FINAL` in BASE | Irreversible. |
| `FINAL` in CHAIN | Irreversible, unless a `Bust` names it, and that `Bust` arrives before the `DC_FINAL` (§3). After the `DC_FINAL` with no `Bust`, irreversible. |
| `SETTLED` | Irreversible, and the assets have moved. |

**The question the review asked.** Does an execution visible at 1 µs survive the declared faults
without waiting for a durability acknowledgement? Under this chapter: it survives every single
fault except case (c), and the two-fault and misbehaviour cases have published rates (§2). That is
a stronger promise than "provisional until final", and weaker than "irreversible at 1 µs". VYRN
publishes exactly this table and never the shorter claim.

## 5. Benchmarks and tests owned here

| ID | What | Pass |
|---|---|---|
| CMT-T1 | `vyrn-sim`: every revert case (a)–(e) injected 10⁴ times per night | Reverted executions are exactly those the case covers; each gets `DC_REVERT` before its `DC_FINAL` |
| CMT-T2 | `vyrn-sim`, CHAIN: bad `tag_com` packets into fast counterparties | Every bust verdict is final no later than the fill's block; no fill with good tags is busted; `INV-CHN-NOMINT` holds |
| CMT-T3 | B25 and B5 on hardware | As 02 REQ-FIN-3; no revert outside 07 §9.6 |

## Interfaces to other chapters

| Chapter | Consumes from 12 | Provides to 12 |
|---|---|---|
| 01 | — | §14.19 B, §14.13 item 3 |
| 04 | the stage names for `Attest` levels and `Bust` | §7.5 records |
| 07 | the exhaustive role of §9.6 | §6.9 attestations, §9.4 seal, §9.6 cases |
| 09 | bust semantics and timing | §5.9 |
| 10 | `DC_REVERT` ordering | §8.2 records |
| 13 | case (d) | the withholding bound and its cost |

## Local definitions

| Name | Value | Meaning |
|---|---|---|
| `CMT_STAGES` | 4 | `EXECUTED`, `DURABLE`, `FINAL`, `SETTLED` |

## Requests to 01

1. 04 §7.5 defines level 1 `DURABLE` as "at least `F + 1` replicas hold the records"; 07 §6.9
   defines `DUR_QUORUM` as Q voters. Pick one. This chapter uses 07's (Q), which is the stronger.

Resolved: the case-(c) exception and void reverts are in 01 §14.19 B items 4 and 6.

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Can a TX-side fence or a different frame-gate order make `P(lead < 0)` zero, so case (c) disappears? | 07, 06 | B-REP-2W |
| 2 | Should BASE mode also expose a `Bust`-style compensating reversal for operator error, or stay strictly log-defined? | 10 | policy decision |
