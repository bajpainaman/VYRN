# VYRN Specification

Draft 0.2, 2026-11-13. Repository: github.com/bajpainaman/VYRN. Source of the design: [`../DESIGN.md`](../DESIGN.md).

VYRN is an exchange with one central limit order book per instrument. It meets these
requirements at the same time:

- A fill at most **1 µs** after the order's first bit reaches the exchange NIC.
- **1B inbound messages per second on one book.**
- BFT finality within **10 ms**.
- A book that **moves between continents every 8 hours**.
- An optional **on-chain mode** with 5 validator operators.

## Hard constraints on everything in this specification

| ID | Constraint |
|---|---|
| C-UNIX | Every process runs on a Unix-based computer. Production roles run on Linux, and macOS is supported for development, tests and the reference book. No role needs Windows, a hypervisor feature, or a proprietary OS. |
| C-NOCHIP | No custom or programmable chips: no FPGA, no ASIC designed for this, no programmable switch (P4/Tofino), no SmartNIC or DPU running our logic, no GPU on any path. All logic runs on general-purpose CPUs. |
| C-COTS | Only commercially available parts: x86-64 or aarch64 CPUs, ASIC NICs bought off the shelf (AMD Solarflare X2, NVIDIA ConnectX-6/7, AWS ENA), merchant L2/L3 switches with PTP, NVMe drives. |
| C-ONEBIN | The same binaries run on bare metal, AWS and a consumer box. Configuration selects the NIC backend and the core map. |

## Reading order

| # | File | Contents | Lines (draft 0.2) |
|---|---|---|---|
| 00 | `00-index.md` | This page: constraints, map, master diagram | — |
| 01 | [`01-conventions.md`](01-conventions.md) | **The contract every chapter follows**: glossary, types, constants, byte layouts, invariants, IDs, and the binding draft 0.2 decisions (§14) | 607 |
| 02 | [`02-requirements.md`](02-requirements.md) | Requirements, measurement points, SLOs, budgets, acceptance | 1,360 |
| 03 | [`03-architecture.md`](03-architecture.md) | System, region, box and core diagrams; data flows; sequence diagrams; component catalog | 1,722 |
| 04 | [`04-protocol.md`](04-protocol.md) | Client protocol: sessions, packets, messages, responses, reliability, rate limits | 1,922 |
| 05 | [`05-engine.md`](05-engine.md) | Matching engine: lanes, cut, BBO core, data structures, algorithms, proofs | 2,973 |
| 06 | [`06-platform.md`](06-platform.md) | Unix host platform: hardware, BIOS, kernel, NIC backends, C shim, PTP, AWS, consumer, macOS | 1,886 |
| 07 | [`07-replication.md`](07-replication.md) | Log, ordering frames, data tier, Simplex, finality, storage, failover, replay | 2,162 |
| 08 | [`08-epochs.md`](08-epochs.md) | Follow the sun: schedule, handoff, certificate, opening auction, fencing, failures | 1,498 |
| 09 | [`09-chain.md`](09-chain.md) | On-chain mode: validators, custody, bridge, authentication, commitments, slashing | 2,026 |
| 10 | [`10-accounts-risk-md.md`](10-accounts-risk-md.md) | Accounts, risk, positions, fees, market data, drop copy, surveillance | 1,738 |
| 11 | [`11-build.md`](11-build.md) | Repo, crates, coding rules, Vx client, tests, benchmarks, observability, ops, milestones | 2,381 |

## Master diagram

```
                              ┌───────────────── one home region (the sun's) ─────────────────┐
  clients (colo / cloud)      │                                                                │
  ───────────────────────     │   facility F1                         facilities F2 … Fn       │
  each packet sent twice ─────┼──► ┌─────────────── vyrn-seq──────────────┐                   │
    1. to the sequencer        │   │ NICs ─► 49 lanes ─► BBO core ─► TX ──┼─► fills/acks ─────┼──► clients
    2. to a data node          │   │          ▲   │cut      │              │                   │
                               │   │          └─ cut core   └─► order ────┼──┐                │
                               │   └──────────────────────────── frames ──┘  │ 2 paths        │
                               │                                             ▼                │
                               │   ┌── vyrn-data─┐  payloads   ┌───────vyrn-replica ×(n−1) ──┐ │
                               └──►│ data tier   ├────────────►│ replay engine (same code)    │ │
                                   └─────────────┘             │ Simplex: 1 ms blocks, q votes │ │
                                                               │ state roots · market data     │ │
                                                               └──────────────┬───────────────┘ │
                                   finality ≤ 10 ms ◄──────── certificate ────┘                 │
                                                                                                │
   other homes (followers) ◄──── finalized log over WAN ─────────────────────────────────────────┘
   TYO ──8h──► LDN ──8h──► NYC ──8h──► TYO      handoff = certificate (e, S) + opening auction
```

## Status of numbers

Every number in this specification is one of three kinds, and the text says which:

- **Budget:** a target the design commits to. A benchmark in `11-build.md` checks it.
- **Measured:** a result of one of our benchmarks, with its ID. Draft 0.1 has none.
- **Vendor:** a figure published by a vendor. It is taken as given until our own benchmark
  replaces it.

## Draft 0.2 changelog

The full text of every decision is in [`01-conventions.md`](01-conventions.md) §14, which
overrides any chapter. In short:

- **Hard requirements are not negotiable (§14.0).** 1 µs is a maximum for every accepted packet,
  every message type and every index 0–9. Exactly three facts are stated as facts:
  - AWS wire latency belongs to Nitro.
  - The handoff window is set by light.
  - BFT needs a timely network.
- **Deadline admission (§14.1):** an answer or `BUSY` within 1 µs. The decision is logged, so
  replay stays deterministic.
- **Two-pass lanes with early dispatch (§14.2).**
- **Two cut cores (§14.3).**
- **Lane classes (§14.15, §14.17):** 42 dedicated lanes (a paced client never waits in its lane)
  and one pooled 7-core group. `BUSY` is bounded per class.
- **Cores and steps:** a 15 ns BBO step, three TX cores and two order-stream cores.
- **Replication:** the sequencer never votes, a warm standby keeps the Rust/Vx client split
  through failover, and every response is frame-gated (§14.4, §14.5).
- **Finality gate in both modes (§14.9):** the sequencer halts rather than issue fills that cannot
  be final within 10 ms.
- **Maker fills within 1 µs (§14.14, §14.17.5).**
- **Adopted from onebook (§14.13):** Segment16 FIFOs, immutable queue positions, separate
  attestations, and epoch-settled balance domains.
- **Naming:** crate and binary prefix `vyrn-`, C shim prefix `vyns_` (§14.12).

**Open items** for draft 0.3 are listed in 01 §14.18 (O1–O7), each with an owner and a benchmark.

**Requests to 01 that are already resolved.** Several chapters' "Requests to 01" sections were
written before the last edits to 01 and still ask for these, which 01 now has:

- `N_LANES_REF` = 49
- `BBO_CROSS_NS` = 15
- §14.3 aligned with the core map
- `FINALITY_MAX_MS`
- `FIN_GATE_BLOCKS`
- the `AcctTake` layout
- `PacketRecord.flags`

**Diagrams.** The rename made some ASCII diagram lines up to 2 characters wider. Most were
realigned. A few box headers are still slightly off; they read correctly.
