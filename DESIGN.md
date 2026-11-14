# VYRN

A design answer to the interview question: 1 µs fills, 1B messages/s on **one** book, no FPGA,
BFT finality in 10 ms, a book that follows the sun, and (extra credit) all of it on-chain with
5 validators. It runs on bare metal, AWS, or a consumer box.

## 0. The answer in six lines

1. **One core per book is sequential, and it only sees the BBO.** Price-time priority is only
   sequential where orders cross. Joins and cancels (~97% of a quote-driven book) go to 50 lane
   cores that own accounts. Only messages that change the BBO go to one BBO core.
2. **The cut replaces the sequencer.** No core waits to be sequenced. The BBO core reads every
   lane's counter and logs that vector. That log *is* the total order, and replicas replay it
   bit for bit.
3. **The fill goes out before consensus and does not revert.** The ordering frame leaves the NIC
   on two paths before the fill does. A fill reverts only if the leader dies *and* both paths drop
   the same frame inside the same 0.5 ms.
4. **BFT finalizes the order, not the state.** Simplex runs over 1 ms blocks of ordering metadata
   inside one metro: ~3 ms typical, < 10 ms p99. Fills are a deterministic function of the order,
   so they are final at the same moment.
5. **The book moves by certificate, not by vote.** The same 5 operators run nodes in every home.
   A handoff costs one WAN one-way latency (35–110 ms), and an auction fills that gap. Light sets
   that floor, not the design.
6. **Rust.** One deterministic binary for the leader and every replica.

## 1. Is "the world's fastest exchange" the goal?

Yes. The spec is 1–2 orders of magnitude past the state of the art on every axis at the same time:

| Axis | Best in production | This spec |
|---|---|---|
| Wire-to-wire response | tens of µs (Eurex T7, Nasdaq) | **1 µs** |
| Throughput of one book | one matching thread: LMAX's famous 6M orders/s | **1B msgs/s** |
| Hardware | every sub-µs tick-to-trade record is on an FPGA | **x86 + COTS NIC** |
| On-chain | Hyperliquid: 0.2 s median, ~200k orders/s | **1 µs fill, 10 ms final** |

The question tests three things:

1. Can you find the one sequential thing in a price-time book (the BBO) and parallelize the rest?
2. Can you keep consensus off the fill path without making fills revocable?
3. Can you treat a continental move as a protocol with a physics floor, not as a pause?

The hedged answer fails because it treats the hard requirements as contradictions and negotiates
them away: "per book" becomes "aggregate", "fill" becomes "promise", and "on-chain" becomes
"commitments". Once you see points 1 and 2, the requirements do not contradict each other.

## 2. The spec I build to

| Requirement | Exact meaning |
|---|---|
| 1 µs | From the first bit in at the exchange NIC to the first bit of the response out. Applies to every message type (fill, resting ack, cancel ack), at p99, for traffic within the per-session rate. |
| Ack = fill | The response to a marketable order is its fill. |
| 1B/s per book | Inbound messages on one instrument, sustained, at an order-to-trade ratio of ≥ 100:1. That is what a quote-driven book at this rate looks like. |
| Final ≤ 10 ms | The ordered log up to that fill carries a BFT certificate (n − f signatures). |
| Epoch | The home rotates TYO → LDN → NYC every 8 h. |
| Hardware | No FPGA anywhere: x86, COTS ASIC NICs, commodity switches. |

**Wire format:** fixed 16-byte binary messages. A new order is `type side flags | tick u32 | qty u32 | client_ref u32`.
A cancel is `type | order_handle u32 | qty u32 | client_ref u32`. Each packet holds up to 10
messages plus two 8-byte MACs. At 64 bytes per message (FIX-sized), 1B/s is 0.5 Tbps. At 16 bytes
it is ~190 Gbps.

## 3. The book: one sequential point

### Classify every message by the state it writes

| Message | Writes | Handled by | Design share |
|---|---|---|---|
| Join (passive add at or behind the BBO) | a new order record | its lane | ~50% |
| Cancel / reduce | one field of one existing order | its lane | ~47% |
| Improve (passive, inside the spread) | the BBO | BBO core | ~2% |
| Cross (marketable) | the BBO and the heads of the best levels | BBO core | ~1% |

### Lanes own accounts, and they own those accounts' orders

- There are 50 lane cores. A client sends account A's packets to UDP port `lane(A)`. The NIC flow
  filter puts each packet on that lane's RX queue. Risk is lane-local, so no risk check ever
  crosses cores. A market maker that needs more than one lane splits into sub-accounts, each with
  its own share of the credit limit.
- Each lane keeps a FIFO of its own orders at every price level. **The book's FIFO at a level is
  the merge of the 50 lane FIFOs, ordered by (NIC RX hardware timestamp, lane id).** No core ever
  appends to a shared queue.
- Every field has one writer. The lane writes the order and its cancel tombstone. The BBO core
  writes the filled quantity, in its own array. There is no CAS and no cache line that two cores
  write.

### The cut replaces the sequencer

- Each lane publishes a counter (the last op it applied) in its own cache line, using a release
  store.
- A cut core reads all 50 counters continuously and publishes the vector, called a cut, every
  ~150 ns.
- Each BBO-core step uses the newest cut. Lane ops at or below the cut are ordered before the step,
  and later ops after it. The step ignores FIFO entries and tombstones above the cut, and it logs
  the cut.
- The result is a total order that no core waited for, and that replicas replay exactly.
- For fairness: resting orders keep exact NIC-timestamp time priority among themselves. The
  position of a passive op relative to aggressors has ~150 ns granularity.

### Why joins can stay lane-local (the lemma)

- The BBO core publishes a versioned BBO snapshot, in which bid < ask is always true. A lane
  re-reads the snapshot once per inbound packet and tags each order with the version it used.
- A lane sends an order to the BBO core if the order improves or crosses its snapshot. Joins stay
  local.
- **Lemma:** two joins classified against the same snapshot cannot cross each other, because
  buy ≤ bid < ask ≤ sell. Two joins classified against different snapshots can cross only at a
  price that the BBO core itself moved through since the older snapshot. The cut carries each
  lane's snapshot version, so the BBO core knows that price range exactly. After a step that moves
  the BBO through a live snapshot (a sweep that leaves a resting residual), the BBO core scans the
  lane FIFOs in that range and executes whatever crosses, in cut order. This is the only slow path.
  It lasts until every lane has refreshed its snapshot, which takes one packet (~1 µs).
- A cancel that empties the best level makes the published BBO stale in the safe direction. A
  stale snapshot sends extra orders to the BBO core, never fewer. Matching always scans the merged
  lane FIFOs, so a stale snapshot cannot cause a wrong fill.

### Cancel against fill

The lane acks a cancel only after a published cut includes it. If the BBO core filled the order at
an earlier step, the cancel is rejected as too late. Otherwise the cancel wins, and every later
step sees the tombstone. Each field has one writer and the cut orders the events, so the outcome is
deterministic and replayable. The race does not exist.

### The ceiling, stated once

- **Lane:** 1B msgs/s is ~20 core-seconds of lane work per second, which loads 49 lanes (42
  dedicated + 7 pooled) to ~0.41. §4 explains why queueing, not capacity, is the real limit.
- **BBO core:** a step costs ≤ 15 ns (Segment16 sweep). 10M crosses/s plus 20M improves or
  depletions/s load it to ~0.33.
- **So one book takes 1B msgs/s as long as ≤ 1% of messages cross.** That is the one number to
  publish. If the flow goes past it, charge for crosses, not for messages. Real venues already set
  fees per message type.

## 4. The box

```
  4 × 100GbE (ef_vi, HW RX timestamps)
        │  UDP port = lane = account shard
        ▼
 ┌───────────────────── 50 lane cores ─────────────────────┐
 │ parse 16 B msgs · MAC · lane-local risk · classify       │
 │ own their accounts' orders + per-level FIFOs             │
 │ ack joins/cancels once a published cut includes them     │
 └─────┬─────────────────────────────────────▲──────────────┘
       │ improves + crosses (SPSC per lane)  │ cut + versioned BBO
       ▼                                     │
 ┌── BBO core ──┐◄── cut core (reads 50 lane counters, publishes cut)
 │ merge lane   │
 │ FIFO heads   │── fill ring ──► TX core ──► CTPIO ──► wire
 │ by timestamp │                    └──► ordering frame ×2 ──► replicas
 └──────────────┘    (BBO core, cut core and TX core share one CCD)
```

### Latency budget: a hard maximum of 1 µs, worst case at message index 9 (bare metal)

Draft 0.1 of this section said "≤ 10 messages, because 10 × 30 ns fits". That was wrong: a
lane that processes a packet in one sequential pass lands the last cross at ~1,130 ns. The fix
changes the design and leaves the requirement alone (spec `01` §14):

- **Two passes.** Pass 1 does the MAC, risk and classification for every message (45 ns per
  packet + 5 ns per message) and sends each cross to the BBO core as soon as it is classified. Pass
  2 then applies the joins and cancels (9 ns per message).
- **Deadline admission.** A packet that could no longer be answered within 1 µs gets a fast
  `BUSY` instead of a late answer. The decision is written to the order stream, so replay stays
  deterministic. So 1 µs is a maximum, not a percentile.

| Stage (cross at index 9) | ns |
|---|---|
| Wire → RX completion visible to the lane (ef_vi) | 320 |
| Lane pass 1: MAC + session (45), 10 messages classified (50), push (10) | 105 |
| Lane → BBO core hop (one cross-CCD cache line) | 100 |
| BBO step (cut and best-level heads prefetched; tombstone check) | 100 |
| Frame gate: the order records are on both replication paths | 60 |
| Fill → TX core (same CCD), build the frame | 40 |
| CTPIO write → first bit on the wire | 240 |
| **Total** | **965** (880 with the 15 ns BBO step of the queueing fix below) |

A join or cancel ack at index 9 takes 320 + 45 + 50 + 90 (pass 2) + 160 (logged cut) + 10
(gate) + 20 + 240 = **955 ns**. Index 0 is ~90 ns faster.

The NIC accounts for 560 of these nanoseconds. That is why the first benchmark (§9) is an empty
echo test: if a card's bare RX + TX floor is above 560 ns at p99.99, that card is out.

### Throughput budget, and the queueing that a hard maximum forces

The lane averages ~17 ns per message with the per-packet cost amortized, so 1B msgs/s is ~20
core-seconds per second. Spreading that over 49 lanes is not the whole answer. **A lane is a
queue.** A packet that arrives while its lane is busy waits, and the slack after the fixed path
(35–90 ns) is smaller than one packet's service time (~140 ns). With one shared core per lane,
~23% of packets would miss their deadline at full load. No COTS CPU closes this for lanes that
many clients share; only a pipelined front end that takes one packet per clock does, and that is
the FPGA this design excludes. The fix keeps both hard requirements:

- **Dedicated lanes** (~42 on REF): one firm per core. A firm that spaces its packets at least
  one service time apart never waits in its lane. Its crosses can still wait briefly in the
  stages every client shares (the BBO core, TX and stream cores): `BUSY` ≤ 1e-5 at full load, and
  ≤ 1e-8 at ≤ 20% load. Market makers send most messages, and they are the clients who get these
  lanes.
- **A pooled lane group** (7 cores in one CCD) for everyone else. Any pool core takes the next
  packet, and account state moves under a per-account token in the shared L3. `BUSY` is ≈ 1e-3 at
  a full 1B msgs/s and ≤ 1e-6 at ≤ 20% book load (M/M/7).
- **A 15 ns BBO step** (Segment16 sweep), three TX cores and two order-stream cores, so that no
  single-server core runs above ~0.25 load.

Every accepted packet is still answered within 1 µs, and the book still accepts 1B msgs/s. At up
to 10 messages per packet, the box needs 4 client-facing 100G ports plus 2 replication ports.

### Hardware

| Target | Box | What it hits |
|---|---|---|
| **Reference** (colo, or a bare-metal cloud where you pick the NIC) | 1 socket AMD EPYC 9575F (64 cores, 5 GHz, 256 MB L3), 12 × DDR5, 6 × Solarflare X2541 100GbE (ef_vi + CTPIO; 4 client, 2 replication) | 1 µs at the wire, 1B msgs/s per book |
| **Consumer** | Ryzen 9 9950X3D (16 cores, 5.7 GHz, 128 MB L3) + one 100GbE COTS NIC | 1 µs at the wire, ~250M msgs/s per book (12 lanes) |
| **AWS** | the largest 200 Gbps `.metal` instance, DPDK on ENA, the NIC's NUMA node only | 1 µs from RX completion to TX doorbell, inside the instance |

AWS runs the same binary, but there the wire belongs to the Nitro card. Each traversal of Nitro
costs microseconds, and you can neither remove that time nor measure it. AWS also does not give
one instance a known packet rate. Whether a book on AWS reaches 1B/s depends on that rate, which
B16 measures. The full specification is stated against bare metal. ENA does RSS only, so a packet can land on the
wrong lane. That lane forwards it to its owner over an SPSC ring, which costs +100 ns.

**Box setup:** SMT off, isolated cores, busy polling, 1 GB huge pages, C-states off, NICs and
memory on one NUMA node, no syscalls after start.

**Why a book never spans boxes:** a lane-to-BBO-core hop inside one socket costs ~100 ns. The same
hop between two boxes is ≥ 1 µs, because it crosses two NICs. So a book lives in one coherence
domain, and other boxes hold replicas of it.

## 5. Replication and 10 ms BFT finality

- **Region:** 4 boxes in 4 facilities of one metro (5 in the on-chain version). One box is the
  sequencer and the rest are replicas. All boxes have the same hardware, and the replicas run the
  same engine, replaying cuts instead of reading counters.
- **The log has two parts.** *Data* is the client payloads (~190 Gbps). *Order* is the
  sequencer's per-packet lane and RX timestamp plus the per-step cuts (~20 Gbps after delta
  encoding).
- **Clients send every packet twice:** once to the sequencer and once to the region's data tier,
  which fans the payloads out to the replicas. The sequencer sends only the order, which leaves
  its 200 Gbps for fills and acks. Each ordering entry carries the packet hash, so a client that
  sends two different versions of a packet is caught and its session is killed.
- **The ordering frame leaves before the fill.** For each step, the TX core writes the ordering
  frame to two replication ports, on two switches, before it writes the fill. So a fill cannot be
  on the wire unless its order is already in flight on two paths.
- **Consensus** is Simplex (Commonware's Rust implementation) over 1 ms blocks of order. A replica
  votes for a block once it holds every payload the block references. Time to finality is 1 ms to
  fill the block plus 3 one-way hops inside the metro (~0.5 ms each): **~3 ms typical, < 10 ms
  p99.**
- **What BFT finalizes is the order.** Fills and state follow from it deterministically. Replicas
  compute state roots behind the live book, off the critical path.
- **Sequencer failover:** the replicas detect 2 ms of silence, finalize the longest order prefix
  that they hold, and the next replica becomes the sequencer. That is a ~20 ms outage, and you
  publish the number.
- **Market data** comes from a replica in the same facility. It runs a few µs behind the book and
  is identical for every subscriber.

## 6. Follow the sun

| Handoff | WAN one-way | No-fill window (finality + WAN) |
|---|---|---|
| TYO → LDN | ~110 ms | ~120 ms |
| LDN → NYC | ~35 ms | ~45 ms |
| NYC → TYO | ~80 ms | ~90 ms |

1. All three homes run a full replica set at all times. The homes that are not active follow the
   finalized log over the WAN.
2. At the time T announced for the end of epoch e, the old sequencer stops. Its last step is S.
3. The old region finalizes S, which takes ≤ 10 ms. The certificate is n − f signatures on
   (e, S, log hash).
4. The certificate and the tail of the log reach the new home one WAN one-way later. The new
   sequencer starts at S + 1.
5. Orders that reach the new home between T and that moment are collected into an opening call
   auction, which uncrosses at the start. After that, trading is continuous.
6. **Fencing:** every frame carries its epoch. Replicas reject any epoch-e frame that comes after
   the certificate for (e, S). The boundary is S, not a clock, so clock skew cannot cause a fork.

**The physics floor:** the new home cannot match against a book it has not received yet, and light
in fiber travels ~5 µs per km. So the window cannot be shorter than one WAN one-way latency. The
auction is the fair way to spend that window, because it resets every latency advantage when the
venue moves 6,000 km. No cross-ocean consensus round is needed, because the operators' keys are the
same in every home. The handoff is a certificate, not a vote.

## 7. Extra credit: completely on-chain with 5 validators

The design above already is a chain. These are the changes that make it one:

- **Validators.** There are 5 independent operators, and each runs one node in each home
  (15 nodes in total). The active committee is the 5 nodes in the home where it is daytime:
  n = 5, f = 1, quorum 4. The handoff certificate is 4-of-5 from the same keys.
- **Blocks** are the 1 ms order blocks, and consensus is Simplex. Finality inside one metro is
  ~3–5 ms.
- **The sequencer** is one validator's node per epoch. The role rotates across operators.
- **Custody.** Balances, margin and positions are state in the state machine. Deposits and
  withdrawals go through a bridge with 4-of-5 threshold signatures.
- **Authentication at 100M packets/s.** Per-packet signatures do not work: an Ed25519 verify costs
  tens of µs of CPU, so 100M/s would take thousands of cores per validator. Use this instead:
  - The wallet signs an on-chain transaction that opens a session. The session registers two
    symmetric keys per epoch: `K_seq` for the epoch's sequencer, and `K_com` shared by the other
    four validators.
  - Every packet carries two 8-byte MACs. The sequencer checks MAC(`K_seq`) in ~20 ns; that is the
    1 µs path. The other four check MAC(`K_com`) before they vote.
  - Forging a packet requires both keys, which means the sequencer and one other validator are
    both byzantine. That is 2 > f. All honest validators that verify hold the same `K_com`, so they
    reach the same verdict on every packet, and a client cannot split them.
  - A client that sends a good `K_seq` MAC and a bad `K_com` MAC gets filled and then excluded
    from the block. Its fills, and those of its counterparties, are reverted. Its session bond pays
    the counterparties, and the session is killed.
  - **Public verifiability:** each interval's `K_com` comes from a hash chain committed when the
    session opens, and it is disclosed after the block is final (TESLA-style). Anyone can
    re-verify the whole log afterwards.
- **Data availability.** Every validator stores the full log, ~26 GB/s at sustained peak. At 10%
  average load that is ~230 TB per day. Keep 7 days hot on NVMe, and snapshots plus an archive
  for the rest.
- **Commitments.** The log is hash-chained every block, which costs ~4 cores of BLAKE3. The state
  root is computed every second, over that second's net diff only: orders that are placed and
  cancelled inside the same second never touch it. An incremental lattice hash (the construction
  Solana adopted for account state) makes each change O(1).
- **Verification** is re-execution by all 5 validators. Do not use ZK: nobody can prove 1B order
  operations per second, and re-execution is cheap because matching is cheap.
- **Censorship.** Every validator accepts packets directly from clients and includes them when it
  is the Simplex leader. The state machine places those packets at the block boundary. So the
  sequencer can censor a client for at most ~2 ms.
- **Equivocation.** The sequencer signs each block's order stream, one signature per ms. Two
  signed streams for the same range are proof, and the bond is slashed automatically.
- **Front-running by the sequencer** cannot be detected order by order at 1 µs, and cannot be
  prevented. You cap it instead: rotate the sequencer operator every epoch, bond it, and publish
  each sequencer's per-epoch fill quality for fast accounts.
- **Cost on AWS.** Cross-AZ transfer costs $0.02/GB (both sides together). 26 GB/s into each
  validator is ~$45k per validator per day at peak. That is why the reference deployment is colo.

## 8. Language: Rust

**Rust (chosen).**
- It produces the same machine code as C++ (both use LLVM). It has `#[repr(C, align(64))]`,
  `core::arch` (prefetch, AES-NI, `rdtsc`), and atomics with explicit `Release`/`Acquire`. The
  whole cut protocol is release stores and acquire loads.
- **Determinism is the replication protocol.** The leader and every replica must compute identical
  fills from the same log. Safe Rust has no undefined behaviour, so a fork can only come from code
  you wrote. The hot crate also bans three things:
  - `HashMap` with its random seed, because iteration order differs from process to process
  - floating point in state
  - reading the clock anywhere except on the RX path
- One language covers the engine, consensus, p2p and storage: Commonware (Simplex, p2p, storage)
  is Rust, and Hyperliquid's node is Rust.
- **NIC access.** The ef_vi and DPDK fast paths are inline functions in C headers. Wrap them in a
  ~100-line C shim, compile it with clang, and link with `-C linker-plugin-lto`, so that they
  inline into the Rust lane loop.
- **No allocation after start.** A global allocator that aborts once the engine is sealed turns
  an allocation into a crash in testing instead of a latency spike in production.
- `unsafe` lives in exactly three places: the SPSC rings, the lane FIFO arena, and the NIC shim.

**C (only for the NIC shim).**
- The NIC shim is C because ef_vi and DPDK are C. Their fast paths are inline functions in C
  headers, and C has a stable ABI that clang can inline into Rust with
  `-C linker-plugin-lto`. That is ~100 lines, and it is the only C in the system.
- C is not the engine. It has the same undefined behaviour as C++ (signed overflow, strict
  aliasing, reads of uninitialized memory). It also has nothing that checks the one-writer-per-field
  rule: in Rust, `Send`/`Sync` and borrows enforce it, and in C it is a comment.

**C++ (no).** It is as fast, and ef_vi and DPDK are native to it. It loses on the one property
this design depends on: undefined behaviour. Take a signed overflow or an out-of-bounds read that
the leader's build resolves one way and a replica built with different flags resolves another. In
this design, that is a chain fork. Sanitizers find some of these. In Rust they cannot occur in
safe code. And in C++ the validators' public networking, which is the code attackers reach, is
memory-unsafe.

**OxCaml (no).** Jane Street's extensions (unboxed types, stack allocation, `[@zero_alloc]`
checking, data-race-free modes) make allocation-free OCaml real. But this engine is a cache-line
protocol across 50 cores: explicit alignment, prefetch, acquire/release atomics, PIO writes to a
NIC. And on the OCaml 5 runtime, a minor GC stops every domain. One allocation in any domain (a log
line in the control plane, say) stalls the BBO core. You would be writing C in OCaml syntax and
giving up the ecosystem that makes OCaml worth using.

**Vx, as of v0.0.4 (3a89e3c7, 2026-11-13): the second validator client.**
- **The role.** Run 3 validators on the Rust client and 2 on a Vx client. With a quorum of 4 out
  of 5, neither implementation can finalize on its own. So a miscompile or a bug in either one
  stops finality instead of forking the chain. Halting the book is better than finalizing a wrong
  fill.
- **Why a validator and not the sequencer.** A validator only replays the log. It needs
  throughput and determinism. It does not need the 1 µs path, NIC MMIO, CTPIO, or a clock.
- **What v0.0.4 already gives this role:**
  - OS-thread `tasks`/`spawn`, checked for `Send`/`Sync`
  - `--sanitize=thread`
  - `VX_TASK_SEED`, which makes race tests of the cut protocol repeatable
  - `valid(p, n)` pointer contracts with `vxc --audit`, for the arena and the rings
  - `invariant` on structs, which enforces one writer per field by file
  - `pub fn` export, which lets the Rust harness link the Vx reference book and diff it after
    every message, not only per log
- **Still needed for the validator client, smallest first:**

  | Ask | Filed on vx-lang/Vx (2026-11-13) |
  |---|---|
  | `ptr::copy_nonoverlapping`, `copy`, `write_bytes` | taken on [#2501](https://github.com/vx-lang/Vx/issues/2501) |
  | `hint::prefetch_read` / `prefetch_write` | [#3373](https://github.com/vx-lang/Vx/issues/3373) |
  | `hint::spin_loop` by target | [#3369](https://github.com/vx-lang/Vx/issues/3369) |
  | pin a task to a set of CPUs | [#3370](https://github.com/vx-lang/Vx/issues/3370) |
  | cache-line alignment of a struct | [#3374](https://github.com/vx-lang/Vx/issues/3374) |
  | α for cache-line hops; CCD fleet file and probe | comment on [#353](https://github.com/vx-lang/Vx/issues/353), [#3372](https://github.com/vx-lang/Vx/issues/3372) |
  | sequencer only: `read_volatile`/`write_volatile`; cycle counter | [#3375](https://github.com/vx-lang/Vx/issues/3375), [#3371](https://github.com/vx-lang/Vx/issues/3371) |

- **Needed only for a Vx sequencer (not planned):** `read_volatile`/`write_volatile`, a cycle
  counter, and emitting LLVM bitcode so the NIC shim can inline across languages.
- **One build flag:** on ARM (Graviton), a `Relaxed` load compiles as `Acquire` unless you pass
  `-fweak-relaxed-atomics`. On x86 the two cost the same.

**Vx before v0.0.4 (kept for the record).** Checked against Vx `main` (dc6a4608, 2026-10-26):
- **What Vx already has:** LLVM AOT compilation, ownership with no GC, atomics with explicit
  orderings, `fence`, and `extern` FFI.
- **What the engine needs and Vx `main` lacks:**
  - `read_volatile`/`write_volatile`, which `core/ptr.vx` lists as still missing. CTPIO and
    doorbell writes are MMIO.
  - prefetch and `rdtsc` intrinsics: `core/hint` has only `pause`, and there is no inline asm.
  - a way to pin 50 threads to cores: `spawn on` is sequential by design.
  - memcpy intrinsics.
- **Maturity:** v0.0.3 with no package manager. The write-vx guide itself names "compiles but
  prints the wrong answer" as a class of compiler bug, and in a replicated state machine a
  miscompile is a fork.
- **The real case for Vx:** its idea is the right one for this design. Placement is in the type
  system, and the fleet files price the links between memory domains. But the memory algebra
  prices capacity and bandwidth, and this engine's cost is the ~100 ns latency of a cache-line hop
  between CCDs. A fleet file for the EPYC 9575F that declares CCDs as domains and prices that hop
  in ns would make the lane → BBO-core crossing a compile-time cost. That is a Vx contribution
  worth making.
- **Vx's job now:** the naive reference book (one thread, linear scans, ~150 lines) as a
  Vx-starters project. The Rust engine is diffed against it on every replayed log, and every
  disagreement is either an engine bug or a new FRICTION.md entry.

## 9. Week-one benchmarks (each one passes or fails)

| # | Test | Pass |
|---|---|---|
| 1 | Empty ef_vi echo on an isolated core, wire-to-wire, measured through a passive fiber splitter into a capture NIC with hardware timestamps | ≤ 560 ns at p99.99, or the card is out |
| 2 | One lane on a real message mix | ≤ 30 ns per message |
| 3 | 49 lanes (42 dedicated + 7 pooled) at 1B msgs/s with 1% crosses | MAX ≤ 1 µs wire-to-wire for every message at every index; BUSY per class within spec `01` §14.17; BBO core ≤ ~0.33 busy |
| 4 | Replay the leader's log on a replica built separately | identical fills and state hash, bit for bit |
| 5 | Kill the sequencer mid-run | every fill the sequencer sent is in the final log |

## 10. The grilling, answered

- **"1 µs without an FPGA is impossible."** The NIC must echo in ≤ 560 ns and the engine adds
  ≤ 405 ns even at message index 9. Deadline admission turns overload into a `BUSY` within 1 µs,
  never a late answer. Benchmark 1 settles the NIC in a day.
- **"A hard 1 µs maximum is impossible with queues."** Without admission control it is. Every
  queued system, FPGA exchanges included, has two packets arriving together sometimes. With
  deadline admission, a packet gets either its result or `BUSY` within 1 µs, and that decision is
  logged.
- **"1B/s on one book is one message per nanosecond."** Only if one core touches every message.
  Here the BBO core touches ~3% of them.
- **"Two lanes' quotes cross each other."** See the lemma: against one snapshot they cannot, and
  against different snapshots the BBO core knows the exact range and scans it.
- **"Cancel races fill."** Each field has one writer and the cut orders the events. The outcome
  is logged and deterministic.
- **"Why not hash orders to cores by order id?"** Risk would then cross cores on every message.
  Accounts → lanes keeps risk local.
- **"Why not shard the book across servers?"** A cross-box hop is ≥ 1 µs, which is the whole
  budget. The book stays in one socket, and its replicas run on other boxes.
- **"The leader crashes right after a fill."** The ordering frame was already on two paths. A
  revert requires leader death plus a double drop inside 0.5 ms.
- **"The book pauses when it moves."** For one WAN one-way latency, by physics, and the auction
  makes that window fair.
- **"Why not a GPU?"** A PCIe round trip to a GPU costs microseconds. GPUs are fine off the
  critical path, for example for hashing and archive work.
- **"Fairness between lanes?"** Hardware RX timestamps on every packet, and lane-id tie-breaks
  whose order rotates each epoch.
- **"What breaks first?"** The BBO core, at ~10M crosses/s on one book. Then the NIC packet rate.
