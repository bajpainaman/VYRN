# 11. Build, test, benchmark and run

Draft 0.2, 2026-11-13. Prefix for local names: `BLD_`. This chapter follows `01-conventions.md`.
Where this chapter and 01 disagree, 01 wins and this chapter has a bug. 01 §14 is binding.

This chapter says how VYRN is built, tested, measured, deployed and operated. It defines the
benchmarks `B1`–`B20` and `B-GPU` (01 §8 assigns them here), and registers every benchmark that
other chapters define (§7.25). It defines the milestones `M0`–`M6` and the risk register.

**The hard requirements are maxima (01 §14.0).** Every benchmark that checks REQ-LAT-1 passes on
the maximum over the whole run, for every message type at every message index 0–9. No benchmark in
this chapter exempts a packet size, an index or a type, or swaps a bound for a percentile.

## 0. Scope and the constraints

| Constraint | How this chapter meets it |
|---|---|
| `C-UNIX` | Every build, test and benchmark runs on Linux or macOS. CI has Linux x86-64, Linux aarch64 and macOS aarch64 runners and nothing else. |
| `C-NOCHIP` | No benchmark puts a programmable device in the measured path. The capture rig uses passive optical taps and a COTS NIC with hardware timestamps. The capture NIC observes, and it never forwards. No GPU, FPGA, ASIC, P4 switch or SmartNIC logic is in any build. B-GPU (§7.24) is the only path that may reopen this, and only if RX + TX ≤ `NIC_FLOOR_NS` (01 §14.7). |
| `C-COTS` | Every runner and every rig is built from parts that 01 §10 names, plus passive fiber taps. |
| `C-ONEBIN` | One release artifact per CPU architecture and per binary. A per-box config file selects the NIC backend, the core map, the mode and the engine client (§10.1). No build flag differs between bare metal, AWS and the consumer box. |

Three rules hold for the whole chapter:

1. **A number without a benchmark is a budget.** Every budget in 01 §5 has a benchmark here that
   checks it. Draft 0.2 has no measured numbers.
2. **The test that matters runs on the platform it claims.** Functional correctness is proved on
   DEV (macOS) and Linux alike. Performance is proved only on Linux on the target hardware.
3. **Every pinned-core role is a poll state machine.** This one structural rule makes the same
   code run on a pinned core, in `vyrn-sim`, in replay and in microbenchmarks (§3.1).

## 1. Repository layout

### 1.1 Decision

The repository is one cargo workspace. One `Cargo.lock` pins every Rust dependency, and one
toolchain file pins `rustc`. The C shim and the Vx code live in the same repository, so one
commit fixes every byte of every artifact.

The reason is determinism. `INV-DET` must hold across the sequencer, the Rust replicas and the Vx
replicas. If they came from different repositories, a release would need a version matrix, and a
divergence would need an archaeology session. With one commit hash per release, `vyrn-admin version`
prints one value, and every box in a cluster must print the same one (§10.2).

### 1.2 Tree

```
VYRN/
├── Cargo.toml                 workspace; [workspace.dependencies] with "=x.y.z" pins; profiles
├── Cargo.lock                 committed; every build uses --locked --offline
├── rust-toolchain.toml        pinned rustc, plus rustfmt, clippy, miri, llvm-tools
├── .cargo/config.toml         vendored-source replacement, linker, per-target rustflags
├── .cargo/release.toml        cross-language LTO for release and bench builds (§4.3)
├── clippy.toml                workspace rules (all crates)
├── deny.toml                  cargo-deny: licenses, advisories, bans, duplicate versions
├── UNSAFE.toml                the only modules allowed to contain `unsafe` (§3.2), with owners
├── ASM-GATE.toml              hot symbols and the callees they must not contain (§4.4)
├── CODEOWNERS                 owners for UNSAFE.toml modules, c/, vx/, supply-chain/
├── supply-chain/              cargo-vet: config.toml, audits.toml, imports.lock
├── vendor/                    output of `cargo vendor`, committed
│
├── crates/
│   ├── engine/                crates under INV-DET; they share the strict clippy.toml below
│   │   ├── clippy.toml        bans floats, std::time, RandomState, logging, threads (§3.3)
│   │   ├─vyrn-types/
│   │   ├─vyrn-crypto/
│   │   ├─vyrn-wire/
│   │   ├─vyrn-cut/
│   │   ├─vyrn-risk/
│   │   ├─vyrn-lane/
│   │   ├─vyrn-bbo/
│   │   └─vyrn-engine/
│   ├── vyrn-nic/              Rust side of the NIC; links c/vyrn-nic-shim on Linux
│   ├─vyrn-log/
│   ├─vyrn-data/
│   ├─vyrn-consensus/
│   ├── vyrn-replica/          library + binary vyrn-replica
│   ├─vyrn-epoch/
│   ├─vyrn-chain/
│   ├── vyrn-md/               library + binaries vyrn-md, vyrn-dropcopy (§1.3)
│   ├── vyrn-sim/              library + binary vyrn-sim
│   └── vyrn-bench/            library + binary vyrn-bench
│
├── bin/                       binary-only packages: main.rs + config wiring, no logic
│   ├─vyrn-seq/
│   ├─vyrn-validator/
│   ├── vyrn-data-box/         binary vyrn-data (§1.3)
│   └─vyrn-admin/
│
├── c/
│   └─vyrn-nic-shim/
│       ├── shim.c             100–300 lines (CI gate, §4.5)
│       ├── shim.h             the C ABI that vyrn-nic binds
│       └── vendor/            pinned ef_vi and DPDK headers, one directory per vendor release
│
├── vx/
│   ├── TOOLCHAIN              vxc v0.0.4, commit 3a89e3c7; the hash of the vxc binary
│   ├── build.sh               the only way Vx artifacts are built (§5.4)
│   ├── FRICTION.md            every Vx workaround, each naming its vx-lang/Vx issue (§5.6)
│   ├── abi/pbv.h              C ABI shared by Rust and Vx: structs, rings, entry points
│   ├── vyrn-vx-oracle/        the sequential reference book (§5.2)
│   └── vyrn-vx-client/        the replay-only validator engine (§5.3)
│
├── fuzz/                      cargo-fuzz package (outside the workspace) and corpora (§6.6)
├── tests/
│   ├── golden/                wire, SipHash, BLAKE3, LEB128 vectors; golden responses
│   ├── logs/                  golden order-stream logs with expected output hashes
│   └── seeds.toml           vyrn-sim seeds that once failed; each runs on every commit
├── bench/
│   ├── rigs/                  capture-rig, generator and runner descriptions (§7.2)
│   ├── workloads/             generator configs; each names a 02 workload ID
│   ├── baselines/             per-runner baselines for the perf gate (§9.3)
│   └── reports/               signed benchmark reports, one per run that gates something
├── tools/                     unsafe-audit, asm-gate, lint-engine, shim-gate, repro-build,
│                              perf-gate, sim-swarm, trace-dump
├── deploy/
│   ├── schema/                config schema, versioned with the protocol (§10.1)
│   ├── profiles/              ref.toml, consumer.toml, aws.toml, dev.toml
│   ├── coremaps/              one file per hardware target (01 §10)
│   ├── image/                 reproducible OS image recipe (kernel cmdline per 06)
│   ├── runbooks/              §10.4, one file per runbook
│   ├── dashboards/            dashboard definitions (§8.5)
│   └── alerts/                alert rules (§8.6)
└── spec/                      this specification
```

### 1.3 Crates and binaries

Each crate has one paragraph of responsibility. "Pinned" means the crate's code runs on an
isolated, pinned core after `seal()`.

| Crate | Pinned | Responsibility |
|---|---|---|
| `vyrn-types` | yes | The newtypes of 01 §3, the constants of 01 §5 as `pub const`, `StepKind`, `HomeCode`, `Mode`, and the record structs of 01 §6.6. No logic beyond checked arithmetic on `Qty`, `Tick` and notional (01 §11.4). No dependencies. |
| `vyrn-crypto` | yes | SipHash-2-4 (in-house, §2.4), BLAKE3 wrappers, Ed25519 verify and sign with ZIP-215 rules, the hybrid Ed25519 + ML-DSA scheme of 01 §14.20 (§2.5a), X25519 and the hybrid X25519 + ML-KEM-768 key agreement of 01 §14.20 G, and the `derive_key` contexts of 01 §4. It exposes `#[inline(always)]` MAC check functions for the lane loop. |
| `vyrn-wire` | yes | Parse and build the packets and records of 01 §6.1–6.5, using `zerocopy` so that parsing needs no `unsafe`. It defines the `RxRing` and `TxRing` traits that every NIC backend implements. Every parse returns a `Result` with a 01 §6.5 reason. Nothing in it panics on input bytes. |
| `vyrn-cut` | yes | Every cross-core primitive: the lane counters, the cut publication (two half-cut lines, one per cut core, 01 §14.3), the per-lane order rings (01 §14.5), the versioned BBO snapshot (a seqlock), the SPSC rings (lane → BBO, BBO → lane fill events, BBO → TX-A, TX-B and TX-C), and the pool primitives of 01 §14.15 (per-account `PoolTok` CAS, per-queue steal locks, the sibling-segment `fetch_and`). It is generic over a `Visibility` backend: `Hw` uses atomics, `Sim` delays visibility by a seeded amount so that `vyrn-sim` sees stale cuts and stale snapshots (§6.4). |
| `vyrn-risk` | yes | Lane-local accounts: balances, reservations (01 §12.1), order counts, rate limits, fees, positions. Every check returns a 01 §6.5 reject. |
| `vyrn-lane` | yes | One lane: deadline admission (`BUSY`, 01 §14.1), session table, MAC check, sequence check, risk, the two passes of 01 §14.2 (classify and dispatch with the in-packet dependency list, then apply joins and cancels in index order), `PacketRecord` pre-encoding, the lane FIFO arena, tombstones, `Ack`/`CancelAck` after the cut and the frame gate (`INV-ACK-AFTER-CUT`, `INV-FRAME-FIRST`), and settlement of fill events. Two classes from one code path (01 §14.15): a dedicated lane, and a pool core that takes account tokens and steals from sibling queues. It never decides a fill (`INV-LANE-NOMATCH`). |
| `vyrn-bbo` | yes | The BBO core: steps (cross, improve, depletion, rescan, idle, shed, control, seal, uncross; 01 §14.10), the deadline test on forwarded ops, the merge of lane FIFO heads by (rx_ts, lane id), the filled-quantity array, snapshot publication, and the opening-auction uncross (08). |
| `vyrn-engine` | yes | Joins lane, cut and BBO into one engine, in two modes: **live** (lanes read `RxRing`, the cut core reads counters) and **replay** (lanes read the order stream, the BBO core reads `StepRecord.cut`), per 01 §11.6. It owns `seal()`, the sealing allocator (§3.5) and the core-role table. |
| `vyrn-nic` | yes | NIC backends behind `vyrn-wire`'s traits: `efvi` and `dpdk` (Linux, through the C shim), `kernel_udp` (Linux and macOS, for DEV and tests), `sim` (in-memory, for `vyrn-sim` and benches). It also holds platform calls: affinity, huge pages, `mlockall`, PHC reads, TSC reads (`sys` module). |
| `vyrn-log` | no | Order-stream encoding (LEB128 deltas, 07), block assembly, the hash chain, block storage on NVMe, and log readers for replay. Shared by the sequencer's two order-stream cores (stream-A on core 4, stream-B on core 7, 01 §10) and by replicas. |
| `vyrn-data` | no | The data tier: receives the client copy of each packet, stores it by `PktHash`, fans it out to replicas, answers fetches for missing payloads. |
| `vyrn-consensus` | no | Simplex on Commonware: block proposal from `vyrn-log`, votes, certificates (`INV-QUORUM`), view changes, sequencer-silence detection (`FAILOVER_SILENCE_MS`). It runs on control and consensus threads with tokio. |
| `vyrn-replica` | split | The replica process: receives order frames on two paths, fetches data, runs the replay engine (Rust `vyrn-engine` or Vx `vyrn-vx-client`, chosen by config), computes state roots, votes. The replay engine threads are pinned; the rest are not. |
| `vyrn-epoch` | no | The epoch schedule, the `HandoffRecord`, its certificate, fencing (`INV-FENCE`), the auction phase control (when to collect, when to uncross), and `EpochNotice` generation. |
| `vyrn-chain` | no | Chain mode: session open by wallet signature (Ed25519, secp256k1), `K_seq`/`K_com` registration, TESLA-style key disclosure, the lattice state commitment, bridge, slashing evidence. |
| `vyrn-md` | split | Market data and drop copy from a replica's replay events. The publisher threads are pinned. |
| `vyrn-sim` | no | The deterministic whole-cluster simulator (§6.4), the oracle binding, the invariant checkers. Test-only: no production artifact links it. |
| `vyrn-bench` | split | The benchmark harness: traffic generator, echo server, microbenchmark drivers, histogram export, report signing (§7). |

| Binary | Package | Links |
|---|---|---|
| `vyrn-seq` | `bin/vyrn-seq` | `vyrn-engine` (live), `vyrn-nic`, `vyrn-log`, `vyrn-consensus` (as a proposer; it never votes, 01 §14.4), `vyrn-epoch`, `vyrn-data` (its frame and fetch codec only, for `SeqDataReq`, 07 §5.5). The warm standby in F2 is the same binary. |
| `vyrn-replica` | `crates/vyrn-replica` | `vyrn-engine` (replay), `vyrn-log`, `vyrn-consensus`, `vyrn-epoch`, `libvyrn_vx_client` |
| `vyrn-validator` | `bin/vyrn-validator` | everything in `vyrn-replica`, plus `vyrn-chain`; in observer mode (03 §4.5) also `vyrn-md`'s `SinkStream` and `dropcopy::ring::RingTap`, which write the output ring (10 §8.6 item 6) |
| `vyrn-data` | `bin/vyrn-data-box` | `vyrn-data`, `vyrn-nic`, `vyrn-log`, `vyrn-cut` (the rings between its cores, 07 §5.2), `vyrn-epoch` (the roster codec, to derive `K_fetch`, 08 §9.6). The library `vyrn-data` stays in layer 4. |
| `vyrn-md` | `crates/vyrn-md` | `vyrn-md`, `vyrn-replica` (replay core), `vyrn-nic` |
| `vyrn-dropcopy` | `crates/vyrn-md` | `vyrn-md::dropcopy`, `vyrn-replica` |
| `vyrn-admin` | `bin/vyrn-admin` | config check, deploy, keys, epoch control, trace dump, release verify |
| `vyrn-sim` | `crates/vyrn-sim` | everything, plus `libvyrn_vx_oracle` |
| `vyrn-bench` | `crates/vyrn-bench` | engine crates, `vyrn-nic`, `libvyrn_vx_oracle` (for B12 cross-checks) |

**Why `bin/` exists.** 01 §9 names binaries that have no crate of their own (`vyrn-seq`,
`vyrn-validator`, `vyrn-admin`, `vyrn-dropcopy`). A binary-only package holds `main.rs` and the config
wiring, and nothing else. All logic stays in the named crates, where it is tested. `vyrn-dropcopy`
is a second binary of `vyrn-md`, because drop copy and market data consume the same replay events
(10). This is listed in Requests to 01.
`vyrn-data` has a crate of its own, but its binary lives in `bin/vyrn-data-box` because it
links `vyrn-epoch` to read the roster and derive `K_fetch` (08 §9.6), and the library `vyrn-data`
sits below `vyrn-epoch` in §1.4. The package is `vyrn-data-box`; the binary is still `vyrn-data`.

**Why the engine crates sit under `crates/engine/`.** Clippy reads the nearest `clippy.toml`
walking up from the crate's manifest. One directory gives the eight `INV-DET` crates one strict
rule file, and a crate cannot leave that rule set without moving directories, which shows in
review.

### 1.4 Dependency graph

An arrow means "depends on". The graph is a DAG, and CI checks it: `tools/lint-engine` fails if
an engine crate depends on a crate outside `crates/engine/`, other than the allowlist in §2.2.

```
  An arrow means "depends on". Each crate depends only on crates in the layers above it.

  layer 0   vyrn-types
               ▲
  layer 1   vyrn-crypto · vyrn-cut · vyrn-risk · (all others) ──► vyrn-types
  layer 2   vyrn-wire ──► vyrn-crypto
            vyrn-bbo ───► vyrn-cut
            vyrn-log ───► vyrn-crypto
  layer 3   vyrn-nic (+ C shim) ──► vyrn-wire
            vyrn-lane ──► vyrn-wire, vyrn-cut, vyrn-risk, vyrn-bbo
  layer 4   vyrn-engine ──► vyrn-lane, vyrn-bbo, vyrn-cut, vyrn-wire
            vyrn-consensus ──► vyrn-log, Commonware (consensus, p2p, runtime, cryptography, storage, codec)
            vyrn-data ──► vyrn-log, vyrn-nic, vyrn-cut (the sharded box's hop rings, 07 §5.2)
  layer 5   vyrn-epoch ──► vyrn-consensus
  layer 6   vyrn-replica ──► vyrn-engine, vyrn-consensus, vyrn-epoch, vyrn-data (frame codec,
                             03 F7), libvyrn_vx_client (Vx, C ABI)
  layer 7   vyrn-md ──► vyrn-replica
            vyrn-chain ──► vyrn-replica, vyrn-epoch

  test-only:  vyrn-sim ──► everything above + libvyrn_vx_oracle (Vx, C ABI)
              vyrn-bench ──► engine crates, vyrn-nic, vyrn-log, libvyrn_vx_oracle
```

Rules the graph encodes:

- **The engine never depends on a NIC.** `vyrn-engine` depends on `vyrn-wire`'s ring traits, not on
  `vyrn-nic`. The binary wires a backend in. So `vyrn-sim` and `vyrn-bench` run the same engine with the
  `sim` backend, and a NIC driver bug cannot change matching.
- **Consensus never depends on the engine.** `vyrn-consensus` orders blocks that `vyrn-log` builds. It
  never calls the matching code. This is 07's "BFT finalizes the order, not the state" in the
  module graph.
- **Only `vyrn-replica` sees both engines.** The Rust replay engine and the Vx client are two
  implementations of one trait, `ReplayEngine` (§5.3). Nothing above `vyrn-replica` knows which one
  runs.

## 2. Dependency policy

### 2.1 Decision

A dependency enters the workspace only if it is on the allowlist in §2.2, has a cargo-vet audit,
is vendored, and is pinned to an exact version. The engine crates have almost no dependencies.
Each one we add is code that must produce bit-identical results on the sequencer and on every
replica, so we take as little of it as possible.

### 2.2 Allowlist

Tier E crates may be used by the engine crates (`crates/engine/`). Tier S crates may be used by
the other production crates. Tier T crates may be used only by tests, `vyrn-sim`, `vyrn-bench`, `fuzz/`
and `tools/`.

| Crate | Tier | Used by | Why this one |
|---|---|---|---|
| `blake3` | E | `vyrn-crypto` | The reference implementation of 01 §4's hash. Its SIMD paths give the same bytes on every target; B4 checks it. `derive_key` is part of its API. |
| `zerocopy` | E | `vyrn-wire`, `vyrn-cut` | Safe reinterpretation of `#[repr(C)]` byte layouts with compile-time layout checks. It keeps `unsafe` out of the wire parser. |
| `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek` | S | `vyrn-crypto` (non-hot API), `vyrn-chain` | Ed25519 and X25519 in Rust. Verification uses the ZIP-215 rules (§2.5). |
| `k256` | S | `vyrn-chain` | secp256k1 verify for EVM wallet session opens (01 §4), pure Rust. Chain mode only. |
| `chacha20poly1305` (with `chacha20`, `poly1305`, `aead`, `cipher`, `universal-hash`, `inout`), `sha2` | S | `vyrn-md` (`dropcopy::noise`) | ChaCha20-Poly1305 and SHA-512 for the drop copy's `Noise_NK_25519_ChaChaPoly_SHA512` transport (10 §8.5 item 5), which stays Noise after PQ-12 adds a TLS provider. RustCrypto, pure Rust; both were already in `Cargo.lock` through `commonware-cryptography` and `ed25519-dalek`, so they add no package. Default features off. |
| `sha3` (with `keccak`) | S | `vyrn-chain` | Keccak-256 for the L1-facing EIP-712 digests and withdrawal tree only (01 §14.11). RustCrypto; `keccak` selects the ARMv8 SHA3 instructions at run time and falls back to portable code, so the binary runs on CPUs without them. Default features off. |
| `libcrux-ml-dsa` (with `libcrux-sha3`, `libcrux-intrinsics`, `libcrux-platform`, `libcrux-secrets`, `libcrux-traits`, `libcrux-macros`) | S | `vyrn-crypto` (non-hot API) | ML-DSA-44 and -65 for the hybrid scheme (01 §14.20). Fastest Rust candidate measured: 97 µs sign mean and 30 µs verify for ML-DSA-44, against 107 / 30 for `aws-lc-rs` and 486 / 61 for RustCrypto `ml-dsa`. Arithmetic, NTT and serialization are formally verified with hax and F\* (crate README). `unsafe` sits in its AVX2 path and `libcrux-intrinsics` only; aarch64 uses the portable path. Enabled features: `mldsa44`, `mldsa65`, `simd256` on x86-64. Pinned to an exact 0.0.x version; 01 §14.20 open question PQ-2 decides whether an independent audit must come first. |
| `ml-dsa` (RustCrypto) | T | `vyrn-crypto` tests, `fuzz/` | Pure-Rust, no-`unsafe` second implementation: the differential reference of §2.5a. Never in a production binary: 5× slower to sign. |
| `libcrux-ml-kem` | S | `vyrn-crypto` (non-hot API) | ML-KEM-768 for hybrid key agreement (01 §14.20 G, PQ-6). Measured 17 µs encaps and 17 µs decaps against 79 / 111 for RustCrypto `ml-kem`. It shares `libcrux-sha3`, `-intrinsics`, `-platform`, `-secrets` and `-traits` with `libcrux-ml-dsa`, so it adds one crate. `#![deny(unsafe_code)]` at the root, `unsafe` only in its AVX2 instantiation and dispatch. Enabled feature: `mlkem768` only; `kyber` off. cargo-vet audit as for `libcrux-ml-dsa` (PQ-2). |
| `ml-kem` (RustCrypto) | T | `vyrn-crypto` tests, `fuzz/` | Pure-Rust, no-`unsafe` ML-KEM: the differential reference of §2.5a. Never in a production binary. |
| `rustls` (with `rustls-pki-types`, `rustls-webpki`, `untrusted`) | S | `vyrn-crypto::tls`, the BASE admin channel | TLS 1.3 (04 §4.4). Default features off and `std` on, so no `ring` or `aws-lc-rs`. `#![forbid(unsafe_code)]`. Runs only VYRN's provider (01 §14.20 H). |
| `libcrux-chacha20poly1305`, `libcrux-hmac`, `libcrux-sha2` (with `libcrux-poly1305`, `libcrux-hacl-rs`) | S | `vyrn-crypto::tls` | ChaCha20-Poly1305 and HMAC-SHA-256 (for HKDF) of VYRN's TLS provider. HACL\*-derived, no `unsafe`. |
| `rustls-graviola` | T | `vyrn-crypto` tests | Interop reference: VYRN's provider must complete handshakes with it in both directions. Never in a production binary (a second crypto stack). |
| `commonware-consensus` | S | `vyrn-consensus` | Simplex (DESIGN §5). |
| `commonware-p2p` | S | `vyrn-consensus`, `vyrn-data` (control channel) | Authenticated peer connections between replicas. |
| `commonware-stream` | S | `vyrn-consensus` | The authenticated, encrypted handshake (SAKE over CUPS) that `commonware-p2p` `authenticated::lookup` takes for the voters' Simplex network (07 §3.1). Same release tag as the other `commonware-*` crates. From `E_pq` the voters use `vyrn-crypto::p2p::HybridSake` through its public `Handshake` trait (01 §14.20 H). |
| `commonware-runtime` | S, T | `vyrn-consensus`, `vyrn-sim` | Tokio runtime in production, the `deterministic` runtime in `vyrn-sim` (§6.4). One trait boundary gives both. |
| `commonware-cryptography` | S | `vyrn-consensus` | The signing scheme types that consensus expects. `vyrn-crypto` adapts its Ed25519 keys to it. |
| `commonware-codec`, `commonware-storage` | S | `vyrn-consensus`, `vyrn-log` | Message encoding for consensus, journal storage for blocks. |
| `tokio` | S | control and consensus threads only (§2.3) | The runtime Commonware's production executor uses. |
| `libc` | S | `vyrn-nic::sys` | `sched_setaffinity`, `mmap` with huge pages, `mlockall`, `madvise`, PHC `ioctl`. |
| `cc` | S (build) | `vyrn-nic` build script | Compiles the C shim with clang (§4). |
| `serde`, `toml` | S | config loading in binaries | Config is parsed before `seal()`, on the control thread. |
| `clap` | S | binaries | Command lines. |
| `prometheus-client` | S | metrics export on the control core (§8.4) | Text exposition format. |
| `tracing`, `tracing-subscriber` | S | control and consensus threads only | Logging off the pinned cores (§8.3). |
| `thiserror` | S | non-engine crates | Error types. Engine crates write their error enums by hand. |
| `proptest` | T | tests | Property tests with shrinking (§6.2). |
| `libfuzzer-sys`, `arbitrary` | T | `fuzz/` | Coverage-guided fuzzing (§6.6). |
| `loom` | T | `vyrn-cut` tests | Exhaustive interleaving checks of the rings and the seqlock (§6.1). |
| `rand`, `rand_chacha` | T | `vyrn-sim`, `vyrn-bench` | Seeded randomness. ChaCha8 gives the same stream on every platform. |
| `hdrhistogram` | T, S | `vyrn-bench`, the metrics exporter | Merging and quantiles off the pinned cores. The pinned cores use the fixed-bucket histogram of §8.2. |

**Not allowed anywhere:** `openssl`, `ring`, `aws-lc-rs`, `aws-lc-sys` (one crypto stack, not two), any crate that spawns
threads in a library, any crate that reads environment variables in an engine path, async
runtimes other than tokio, `crossbeam` (the rings are ours and loom-checked), any crate with a
`build.rs` that downloads anything. `deny.toml` lists them under `[bans]`.

### 2.3 No async runtime on pinned cores

Tokio runs only on the control and consensus threads. On `REF` they share core 51 with the OS,
the only core that is not isolated (01 §10, §14.17), plus the threads 07 assigns. A pinned core runs one
`loop { core.poll() }` and nothing else.

The reason: an async executor parks, wakes, and allocates task state. Parking is a syscall,
waking is a cross-core write, and an allocation after `seal()` aborts (§3.5). None of those is
compatible with a 30 ns lane budget.

The boundary between the two worlds is an SPSC ring from `vyrn-cut`. A control thread writes
commands (an epoch notice, a session open from `vyrn-chain`, a key) into a ring, and the pinned core
polls it in its loop. The pinned core never awaits.

`tools/lint-engine` enforces it: no engine crate may name `tokio`, `async fn`, `.await` or
`std::thread`.

### 2.4 SipHash is in-house

`vyrn-crypto::siphash` implements SipHash-2-4 with a 128-bit key and 64-bit output in about 80 lines,
`#[inline(always)]`, with no `unsafe`.

- **Inlining.** The lane checks one MAC per packet (two in chain mode for validators). The packet
  length is a small multiple of 16 bytes. An inlined implementation specialised for 16-byte blocks
  lets LLVM unroll the compression rounds into the lane loop. A third-party crate behind a
  `Hasher` trait processes byte by byte and is not inlined across crates without LTO tuning.
- **Determinism.** The function is a pure function of key and bytes, the same on every target.
  We own the code, so no update upstream can change it.
- **Test.** The 64 reference vectors of the SipHash paper are in `tests/golden/siphash.txt`. A
  unit test checks all of them, and the Vx client's MAC code (if it computes MACs, §5.3) checks
  the same file.
- **Constant time.** The tag comparison uses a branch-free XOR-OR, so the time to reject a forged
  tag does not depend on which byte differs.

### 2.5 Ed25519 verification rules

All validators must agree on whether every signature is valid, or a client's signed session open
could be valid on some validators and invalid on others. That splits the state.

So every Ed25519 verify in VYRN uses the ZIP-215 rules (cofactored equation, non-canonical
encodings accepted as ZIP-215 specifies). `vyrn-crypto::ed25519::verify` is the only verify
function, and both the Rust and the Vx clients call it through the Rust shell (§5.3). A golden
file `tests/golden/ed25519-edge.txt` holds the edge-case vectors (small-order points,
non-canonical `R` and `A`). The same vectors run against Commonware's verification path, and CI
fails if any verdict differs.

### 2.5a Hybrid and ML-DSA verification rules

All validators must also agree on every hybrid verdict (01 §14.20).

- `vyrn-crypto::sig::verify(scheme, key, msg, sig)` is the only verify function for every scheme,
  and both clients call it through the Rust shell, as for Ed25519. It returns valid only if the
  Ed25519 part passes §2.5 and the ML-DSA part passes FIPS 204 `ML-DSA.Verify` with an empty
  context, each over `scheme ‖ msg`. Lengths are exact; a short or long part is invalid, never
  truncated or padded.
- `vyrn-crypto::sig::sign` uses hedged signing with 32 bytes from the OS RNG per attempt, and runs
  `PQ_HEDGE` attempts on the PQ cores named by the caller (01 §5, §10). It never sits behind a
  `poll()` on a hot core (§3.1): the hot core only pushes bytes onto a ring and reads a slot.
- **Golden and differential tests.** `tests/golden/mldsa-acvp/` holds NIST ACVP vectors for
  ML-DSA-44 and -65 (keygen, sign with given randomness, verify), plus `tests/golden/hybrid-edge.txt`:
  one part valid and the other not (both orders), swapped parts, a scheme-0 signature presented as
  scheme 1, wrong scheme byte, wrong lengths. Every vector runs against `libcrux-ml-dsa` and
  against RustCrypto `ml-dsa`; CI fails if any verdict differs (B4 runs them on every target).
- **ML-KEM-768.** `vyrn-crypto::kex` is the only key-agreement entry point. It runs the FIPS 203
  encapsulation-key check on every key before use and derives hybrid material as 01 §14.20 G
  specifies. Decapsulation is deterministic with implicit rejection, so every member that holds a
  key computes the same secret from the same ciphertext (KG3). `tests/golden/mlkem-acvp/` holds NIST
  ACVP vectors for ML-KEM-768 (keygen from seed, encaps with given randomness, decaps, including
  modified ciphertexts), run against `libcrux-ml-kem` and RustCrypto `ml-kem`; CI fails if any
  output differs.
- The ML-DSA and ML-KEM dependencies' `unsafe` is outside our crates, so `tools/unsafe-audit` (§3.2) does not
  count it; `cargo vet` covers it as a dependency (§2.6).

### 2.6 Pinning, vendoring, audit

| Mechanism | Rule |
|---|---|
| Exact pins | Every entry in `[workspace.dependencies]` uses `"=x.y.z"`. A crate's `Cargo.toml` uses `workspace = true` and never names a version. |
| Lockfile | `Cargo.lock` is committed. Every build runs `cargo build --locked --offline`. |
| Vendoring | `cargo vendor` writes `vendor/`, and `.cargo/config.toml` replaces crates.io with it. A build machine never reaches the network. |
| Commonware | Pinned to one release tag (v2026.10.0 at the time of this draft) for all `commonware-*` crates together. A mixed set of Commonware versions is a `deny.toml` error. |
| Audit | `cargo vet` must pass. We import the audits of the organisations in `supply-chain/config.toml`. A crate with no imported audit gets our own `safe-to-deploy` audit, written by one reviewer and checked by a second. |
| Upgrades | One dependency per PR. The PR includes `cargo vet diff` output for the vendored source, and a B4 run (§7.7) when an E-tier crate changes. |
| Advisories | `cargo deny check advisories` runs on every PR and every night against the RustSec database snapshot. A new advisory against a pinned crate opens an incident ticket the same day. |
| Licences | `deny.toml` allows Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0, CC0-1.0. Anything else needs a written exception in `deny.toml`. The vendored C headers (ef_vi, DPDK) are reviewed by hand and listed in `c/vyrn-nic-shim/vendor/LICENSES`. |
| SBOM | Every release ships a CycloneDX SBOM of Rust crates, C headers and the vxc toolchain hash (§9.5). |

## 3. Rust coding rules for hot crates

"Hot crates" are the eight engine crates plus `vyrn-nic`. The rules below apply to them. Rules
marked *(all)* apply to every crate.

### 3.1 The poll rule

Every role that runs on a pinned core is a type that implements one trait:

```rust
pub enum Progress { Idle, Worked }

pub trait Core {
    /// Does a bounded amount of work and returns. Never blocks, never allocates after seal(),
    /// never reads a clock, never makes a syscall.
    fn poll(&mut self) -> Progress;
}
```

The live binary runs `loop { if core.poll() == Progress::Idle { spin_loop() } }` on the pinned
core. `vyrn-sim` calls `poll` on every core of every simulated box from one thread, in an order its
seeded scheduler picks (§6.4). The microbenchmarks call `poll` on a core fed from memory (§7).
Replay calls the same `poll` with the replay inputs. One code path, four drivers.

"Bounded" means each `poll` handles at most one RX batch (≤ 1 packet per lane by default, 08's
auction excepted), at most one step on the BBO core, or one half-cut on each cut core. The bound
is what lets `vyrn-sim` interleave cores at the granularity where they talk to each other.

**The one clock read: deadline admission.** 01 §14.1 has the lane and the BBO core compare
`now_ns − rx_ts` with the deadline. Engine code gets `now_ns` only through a `DeadlineClock` that
the binary injects (`vyrn-nic::sys` TSC with the TSC↔PHC map of 06; virtual time in `vyrn-sim`). Its
only output is a shed bit, which goes into the order stream (`PacketRecord.flags.SHED` or a `Shed`
step). Replay has no `DeadlineClock`: it reads the bit. So the clock decides whether a packet is
answered `BUSY`, never what an applied packet does, and `INV-DET` holds. `tools/lint-engine`
allows `DeadlineClock::now` only in `vyrn-lane::admit` and `vyrn-bbo::admit`.

### 3.2 `unsafe`

**Decision.** Every crate starts with `#![forbid(unsafe_code)]`, except the crates that contain a
module listed in `UNSAFE.toml`. Those crates start with `#![deny(unsafe_code)]` and put
`#[allow(unsafe_code)]` on the listed module only. (`forbid` cannot be relaxed for one module, so
`deny` plus an audited `allow` is the narrowest form Rust offers.)

`UNSAFE.toml` lists exactly these modules:

| Module | Why it needs `unsafe` | Size budget |
|---|---|---|
| `vyrn-cut::ring` | SPSC rings over `MaybeUninit` slots; producer and consumer index lines. | ≤ 250 lines |
| `vyrn-lane::arena` | The lane FIFO arena: slot reuse with generation counters, intrusive links by index. | ≤ 300 lines |
| `vyrn-nic::ffi` | `extern "C"` declarations for `shim.h`, and the safe wrappers around them. | ≤ 200 lines |
| `vyrn-nic::sys` | `libc` calls: affinity, huge-page `mmap`, `mlockall`, `madvise`, PHC `ioctl`; TSC and `cntvct_el0` reads. | ≤ 250 lines |
| `vyrn-engine::alloc` | The sealing `GlobalAlloc` (§3.5). | ≤ 80 lines |
| `vyrn-replica::vx` | `extern "C"` bindings to `libvyrn_vx_client` (§5.3). | ≤ 150 lines |
| `vyrn-sim::oracle` | `extern "C"` bindings to `libvyrn_vx_oracle` (§5.2). Test-only. | ≤ 100 lines |

DESIGN §8 says `unsafe` lives in exactly three places (rings, arena, NIC shim). The real list has
seven, because a global allocator, the system calls and two FFI boundaries cannot be written
without `unsafe` either. The three DESIGN names still hold all the unsafe code that runs in the
lane and BBO loops. The other four are setup code, FFI or test code.

`tools/unsafe-audit` runs in CI. It fails if:

- an `unsafe` token appears outside a listed module,
- a listed module exceeds its line budget,
- an `unsafe` block or `unsafe impl` lacks a `// SAFETY:` comment directly above it
  (`clippy::undocumented_unsafe_blocks` is `deny` as well),
- a listed module exports a `pub unsafe fn`. Each module exposes a safe API, and the unsafety does
  not leave it.

### 3.3 Lint configuration

`clippy` runs with `-D warnings` on every crate. The workspace `clippy.toml` *(all)* sets:

```toml
disallowed-types = [
  { path = "std::collections::HashMap",  reason = "RandomState: iteration order differs per process (01 §11.2)" },
  { path = "std::collections::HashSet",  reason = "RandomState (01 §11.2)" },
  { path = "std::collections::hash_map::RandomState", reason = "01 §11.2" },
]
disallowed-methods = [
  { path = "std::thread::sleep", reason = "use a timer on the control thread" },
]
```

Non-engine crates that need a hash map use `HashMap<K, V, vyrn_crypto::FixedState>` (SipHash-2-4
with a fixed, published key), or a `BTreeMap`. Iteration over either is a function of the keys
only. Engine crates use neither: they index dense IDs into arrays (01 §11.2).

`crates/engine/clippy.toml` adds the engine bans:

```toml
disallowed-types = [
  # the three above, plus:
  { path = "std::time::Instant",    reason = "no clock in the engine (01 §11.3)" },
  { path = "std::time::SystemTime", reason = "01 §11.3" },
  { path = "std::sync::Mutex",      reason = "blocking on a pinned core" },
  { path = "std::sync::RwLock",     reason = "blocking on a pinned core" },
  { path = "std::sync::mpsc::Sender", reason = "allocates; use vyrn-cut rings" },
  { path = "std::thread::JoinHandle", reason = "engine crates never spawn" },
]
disallowed-methods = [
  { path = "std::time::Instant::now",    reason = "01 §11.3" },
  { path = "std::time::SystemTime::now", reason = "01 §11.3" },
  { path = "std::thread::spawn",         reason = "threads are created by the binary" },
  { path = "std::env::var",              reason = "config is passed in, never read" },
  { path = "std::io::stdout",            reason = "no output on pinned cores (§8.3)" },
  { path = "std::io::stderr",            reason = "no output on pinned cores (§8.3)" },
]
disallowed-macros = [
  { path = "std::println",  reason = "§8.3" },
  { path = "std::eprintln", reason = "§8.3" },
  { path = "std::dbg",      reason = "§8.3" },
]
```

Engine crates also set, in `lib.rs`:

```rust
#![deny(clippy::float_arithmetic, clippy::float_cmp, clippy::cast_precision_loss)]
#![deny(clippy::arithmetic_side_effects)]   // every +, -, * on Qty/Tick/notional is checked
#![deny(clippy::indexing_slicing)]          // see §3.7: indexing goes through audited helpers
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::as_conversions)]            // explicit From/TryFrom for every width change
```

Clippy's float lints catch arithmetic, not type use. A struct field of type `f64` with no
arithmetic on it would pass them. So `tools/lint-engine` also parses every engine source file and
fails on any `f32` or `f64` token, any `as f32`/`as f64`, and any float literal. It also fails on
`tokio`, `async`, `.await`, `rand` and `std::thread` (§2.3).

### 3.4 Integer overflow

**Decision.** `overflow-checks = true` in every profile, including `release` and `bench`.

```toml
[profile.release]
opt-level = 3
codegen-units = 1
debug = "line-tables-only"     # symbolised traces from crash dumps (§8.3)
overflow-checks = true
panic = "abort"
incremental = false

[profile.bench]
inherits = "release"
```

01 §11.4 requires every operation on `Qty`, `Tick` and notional to be checked, with overflow as a
defined reject. The engine code does that explicitly with `checked_*` methods, and clippy's
`arithmetic_side_effects` lint forces it. `overflow-checks` is the backstop: an index or counter
computation that someone wrote with `+` becomes a panic (an abort, §3.8), never a wrap that the
sequencer and a replica could resolve differently.

The cost is measured, not assumed. B2 and B6 run once with the release profile and once with
`overflow-checks = false`. If the difference is more than `BLD_OVERFLOW_COST_MAX` (3% of lane
ns/msg), the hot sites get explicit `checked_*` or `wrapping_*` calls with a comment, and the
profile setting stays on.

### 3.5 The sealing allocator (`INV-NOALLOC`)

`vyrn-engine::alloc` defines the global allocator of every production binary:

```rust
pub struct SealingAlloc;

thread_local! {
    static SEALED: Cell<bool> = const { Cell::new(false) };   // const init: no allocation
}

unsafe impl GlobalAlloc for SealingAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if SEALED.with(Cell::get) { sealed_violation(ViolationKind::Alloc, l.size()) }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(l) }
    }
    // dealloc and realloc check SEALED the same way.
}

/// Called by each pinned core as the last step of its setup.
pub fn seal() { SEALED.with(|s| s.set(true)); }
```

- **Per thread.** `seal()` marks the calling thread. Control and consensus threads never seal and
  may allocate. 01 defines `INV-NOALLOC` for pinned cores only.
- **`dealloc` and `realloc` also trip it.** Freeing on a pinned core means an allocation reached it,
  and a free can take an allocator lock.
- **What a violation does** depends on the build. In `release`, `sealed_violation` writes a fixed
  message with the size and the core role to fd 2 using `libc::write` (no formatting, no
  allocation) and calls `abort()`. In `test` and `sim` builds, it increments a per-thread counter
  and records the caller's return address in a fixed array of 64 entries, so that one test run
  reports every allocation site, not only the first. A test that ends with a non-zero counter
  fails.
- **Setup.** Before `seal()`, a core allocates everything it will need: the arena, the rings, the
  session table, the histograms, the trace ring. It then touches every page (so that page faults
  happen now) and calls `seal()`. `vyrn-engine` refuses to start a core whose config would need more
  than its preallocation (for example, more sessions than `MAX_SESSIONS_PER_LANE`).
- **Checked three ways:** the runtime trap above; `vyrn-sim` runs every scenario with the counting
  allocator; and the asm gate (§4.4) fails if a hot symbol calls `__rust_alloc`, `__rust_realloc`
  or `__rust_dealloc`.

### 3.6 Layout of shared lines

Every structure that more than one core touches is `#[repr(C)]` with an explicit alignment, and a
compile-time assertion fixes its size and field offsets.

```rust
/// One lane's published counter. Written by the lane, read by the cut core.
#[repr(C, align(128))]
pub struct LaneCounter {
    pub applied: AtomicU64,          // LaneSeq, release store by the lane
    pub snap_version: AtomicU64,     // the snapshot version the lane last read
    _pad: [u8; 128 - 16],
}
const _: () = assert!(size_of::<LaneCounter>() == 128);
const _: () = assert!(offset_of!(LaneCounter, snap_version) == 8);
```

**Decision.** A line that one core writes and another core reads (counters, ring head and tail,
the snapshot, the cut) is padded and aligned to `BLD_SHARED_ALIGN = 128` bytes on every target.
Bulk data (lane FIFO slots, level arrays) is aligned to `CACHE_LINE` (01 §5).

The reason for 128 on x86-64: the L2 spatial prefetcher on Zen and on Intel cores fetches the
adjacent 64-byte line in pairs. Two single-writer lines that share a 128-byte pair still interfere
through that prefetcher. Apple M-series lines are 128 bytes already. The cost is memory: 50 lane
counters take 6.4 KB instead of 3.2 KB. B7 measures 64 against 128 on `REF` (§7.10). If 64 shows no
difference, this becomes a request to keep `CACHE_LINE` alone. It is listed in Requests to 01.

Other layout rules:

- Wire and log structs (01 §6) are `#[repr(C)]` with `zerocopy` derives, and have assertions on
  `size_of` (16 for every message and record, 16 for headers) and on every field offset in the
  01 tables. A change to 01 §6 that is not mirrored fails to compile.
- Every field that one core writes and other cores read is an atomic with an explicit `Ordering`,
  never `SeqCst`. The orderings are fixed by 05. A `Relaxed` load in a hot loop has a
  `// ORDERING:` comment saying why it is enough.
- No `#[repr(packed)]` anywhere. A packed field cannot be borrowed safely, and the wire layouts of
  01 are already naturally aligned.

### 3.7 Bounds checks

**Decision.** Safe indexing is the default. A hot loop removes bounds checks by construction, never
with `get_unchecked`.

- **Dense IDs index power-of-two arrays through a mask.** For example, a session table of
  `MAX_SESSIONS_PER_LANE` (4096) entries is indexed by `id & (4096 − 1)` after a range check that
  returns `Reject` for a bad ID. LLVM proves the masked index in range and drops the check.
- **Indexing goes through typed helpers.** `clippy::indexing_slicing` is denied in engine crates.
  Engine code indexes with `vyrn_types::Dense<T, N>`, whose `get(id) -> Option<&T>` takes the typed
  ID, and whose `at(id)` masks. Raw `slice[i]` appears only inside `Dense` itself.
- **Iterators over fixed-size arrays** (`for c in cut.iter()`) instead of `0..N_LANES` index loops.
- **`get_unchecked` is forbidden** outside `UNSAFE.toml` modules, and the arena uses it only behind
  a generation check.
- **Verified in the binary.** The asm gate (§4.4) lists the hot symbols (lane packet loop, MAC,
  classify, BBO cross, cut publish). It fails if any of them contains a call to
  `core::panicking::panic_bounds_check` or `core::slice::index::slice_index_fail`.

### 3.8 Panics

**Decision.** `panic = "abort"` in every production profile. A panic anywhere in a production
process ends the process within microseconds.

- **For the sequencer** this is a failover. The NIC stops sending. The replicas see
  `FAILOVER_SILENCE_MS` (2 ms) of silence and promote the warm standby `vyrn-seq` in F2 (01 §14.4),
  with a published outage of `FAILOVER_TARGET_MS`. Every response already on the wire, acks
  included, is safe: `INV-FRAME-FIRST` put its order records on two paths first (01 §14.5). An abort is better than unwinding: unwinding on one pinned core leaves
  the other pinned cores running against state that a half-finished step left behind, and the
  fill TX cores A, B and C could still send. Abort stops all of them at once.
- **For a replica** it costs one vote. The replica restarts from its last snapshot plus the log
  (07). With f = 1 the quorum continues. The sequencer never votes, so its failure never costs one.
- **A panic reachable from client bytes is a P0 security bug.** It is a remote failover trigger.
  Every engine function that takes input from the wire returns a `Result` with a 01 §6.5 reject.
  The fuzz targets (§6.6) treat any panic as a crash.
- **Where `assert!` stays in release:** O(1) checks of named invariants (`INV-UNCROSSED` after a
  step, `INV-CUT-MONO` when a cut is taken, the generation check in the arena). Each one names its
  invariant in the message. O(n) checks are `debug_assert!` and run in `vyrn-sim` and tests.
- **The panic hook** (installed before `seal()`) copies the message into a preallocated crash
  buffer, writes it to fd 2 with `libc::write`, marks the core's trace ring as frozen, and
  returns, after which `abort` runs. The trace rings live in a shared-memory file so that
  `vyrn-admin trace dump` reads them after the process is gone (§8.3).
- **Tests use unwinding.** Cargo builds tests with unwinding regardless of the profile, so proptest
  can catch a panic and shrink the input.

### 3.9 Review rules for `unsafe`

1. A change to any `UNSAFE.toml` module needs two approvals, one of them from that module's owner
   list in `CODEOWNERS`.
2. A change that adds a module to `UNSAFE.toml` needs an issue first, stating why safe Rust cannot
   do it, and approval from two owners of `UNSAFE.toml`.
3. Each `// SAFETY:` comment names the invariant it relies on (for example "slot `i` is owned by
   the producer until `tail` passes it, ring.rs §ownership"), not what the code does.
4. The module's tests run under Miri (rings, arena, allocator). FFI modules cannot run under Miri,
   so their safe wrappers have unit tests against the `sim` backend and run under AddressSanitizer
   on Linux nightly.
5. Rings and the seqlock have loom models (§6.1). A change to their orderings must keep the loom
   tests passing with the loom preemption bound at 3.
6. The reviewer reads the generated assembly of the changed hot function (`cargo asm` output is
   attached to the PR by CI) and confirms that no new call, branch to a panic, or fence appeared.

## 4. The C shim build

### 4.1 Decision

`c/vyrn-nic-shim` is compiled by clang to LLVM bitcode, and linked with the Rust code through
`-C linker-plugin-lto`, so that the ef_vi and DPDK fast paths inline into the Rust lane loop and
the loops of the three TX cores. It is built only for Linux targets. macOS has neither ef_vi nor DPDK, and the
DEV backends (`kernel_udp`, `sim`) are pure Rust.

### 4.2 Toolchain

- **clang's LLVM major version equals rustc's.** Cross-language LTO reads both sides' bitcode in
  one LLVM. A mismatch either fails the link or, worse, silently stops inlining. CI compares the
  `LLVM version` line of `rustc -vV` with `clang --version` and fails on a different major. The
  build image (§9.4) pins both.
- **Linker:** `lld` from the same LLVM release.
- **Vendor headers:** ef_vi and DPDK headers are vendored under `c/vyrn-nic-shim/vendor/<vendor>-<release>/`.
  The shim is compiled against exactly one release of each. Upgrading a header set is a PR that
  runs B1 and B9 on every NIC in 06's list.

### 4.3 Flags

```
clang -std=c11 -O2 -flto=thin -g1
      -march=x86-64-v3            # aarch64: -mcpu=neoverse-n1 ; equal to rustc's target-cpu
      -fno-strict-aliasing -fwrapv -fno-delete-null-pointer-checks
      -ftrivial-auto-var-init=zero
      -fvisibility=hidden -fno-common -ffunction-sections -fdata-sections
      -fno-stack-protector -fno-plt
      -Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wcast-align -Wshadow
      -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wimplicit-fallthrough
      -I vendor/efvi-<rel>/include -I vendor/dpdk-<rel>/include
```

Why the non-obvious ones:

| Flag | Reason |
|---|---|
| `-fno-strict-aliasing -fwrapv -fno-delete-null-pointer-checks` | They remove three classes of C undefined behaviour that DESIGN §8 names as the reason C is not the engine. The shim casts descriptor bytes, so strict aliasing would be a live hazard. |
| `-ftrivial-auto-var-init=zero` | No read of an uninitialised stack variable can differ between two builds. |
| `-fno-stack-protector` | The shim inlines into the Rust lane loop. A canary check on every inlined call costs cycles on the 1 µs path, and the shim has no stack buffers. clang-tidy (§4.5) rejects any array on the shim's stack. |
| `-march` equal to rustc's `target-cpu` | LTO inlines only between functions with compatible target features. A shim built for a newer ISA than the Rust code is not inlined. |

`.cargo/config.toml`, for every build:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "target-cpu=x86-64-v3",
             "-C", "force-frame-pointers=yes"]

[target.aarch64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld", "-C", "target-cpu=neoverse-n1",
             "-C", "force-frame-pointers=yes"]
```

`.cargo/release.toml`, added to release and bench builds with `--config .cargo/release.toml`
(Cargo appends its `rustflags` to the ones above). The aliases in `.cargo/config.toml`
run them from the repository root: `cargo release` is
`cargo build --release --config .cargo/release.toml`, and `cargo bench-release` is
`cargo bench --config .cargo/release.toml`:

```toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "linker-plugin-lto"]

[target.aarch64-unknown-linux-gnu]
rustflags = ["-C", "linker-plugin-lto"]
```

Debug builds skip cross-language LTO because it slows every link, and stable Cargo has no
per-profile `rustflags`. A release build of the shim without `release.toml` would link but not
inline the shim, so `vyrn-nic`'s build script fails it.

Cargo's `lto` setting stays unset in the release profile. The linker plugin runs ThinLTO over the
Rust and C bitcode together, which is the whole-program LTO this build needs.

**One x86-64 binary for every x86 target.** `x86-64-v3` (AVX2, BMI2) runs on the EPYC 9575F, the
Ryzen 9950X3D and every current x86 AWS `.metal` instance. No per-target build exists, because
C-ONEBIN forbids it. The engine is integer code with few vector loops. The cost of `v3` against
`-C target-cpu=native` is measured once per milestone with B2 and B8 and recorded in the report.
If it exceeds `BLD_ISA_COST_MAX` (5%), the question goes to 06 as an open question, not into a
second binary.

**Frame pointers on.** They make `perf` call stacks on the lab runners exact. Their cost is
measured with B2 the same way as overflow checks (§3.4), with the same 3% limit.

### 4.4 Verifying inlining in CI

`tools/asm-gate` runs on every Linux release build. It reads `ASM-GATE.toml`:

```toml
[[symbol]]
name = "vyrn_lane_rx_batch"          # #[no_mangle] #[inline(never)] wrapper: one RX batch of one lane
forbid_calls = ["vyns_*", "ef_*", "rte_*", "__rust_alloc*", "__rust_dealloc", "__rust_realloc",
                "*panic_bounds_check*", "*slice_index_fail*", "*panic_fmt*"]
forbid_indirect_calls = true
max_bytes = 6144

[[symbol]]
name = "vyrn_tx_ctpio_send"
forbid_calls = ["vyns_*", "ef_*", "__rust_alloc*"]
forbid_indirect_calls = true

[[symbol]]
name = "vyrn_bbo_step"
forbid_calls = ["__rust_alloc*", "*panic_bounds_check*", "*panic_fmt*"]
forbid_indirect_calls = true

# also: vyrn_cut_publish (both cut cores), vyrn_siphash_pkt, vyrn_lane_admit (deadline test),
#     vyrn_lane_classify, vyrn_order_drain (stream cores 4 and 7), vyrn_pool_take (token CAS),
#     vyrn_pool_steal, vyrn_dpdk_rx_burst
```

Procedure:

1. Build `vyrn-seq` in the release profile for the target.
2. Run `llvm-objdump -d --no-show-raw-insn --symbolize-operands` on it.
3. For each listed symbol, extract its body and list every `call`/`jmp` to a symbol (x86-64) or
   `bl`/`b` (aarch64), and every indirect call (`call *`, `blr`).
4. Fail if any target matches `forbid_calls`, if an indirect call appears where it is forbidden,
   or if the body exceeds `max_bytes` (a sign that something unexpected was inlined).
5. Attach the extracted bodies to the CI run, so the `unsafe` reviewer (§3.9 rule 6) reads them.

The hot wrappers are `#[no_mangle] #[inline(never)]` so that the gate has a stable name to find.
Each wraps one bounded unit of work (one RX batch, one step), so the call into the wrapper costs
one direct call per batch, not per message. B2 includes that call.

**When a vendor fast path is an indirect call.** If a header implements its fast path through a
function table (an `ops` pointer), no LTO can inline it. The gate reports it. 06 then decides
whether the shim calls the NIC-generation-specific function directly. Until that decision, the
gate allowlists that one indirect call by name, with its measured cost from B1 in the comment.

### 4.5 Other gates on the shim

- **Size:** `tools/shim-gate` counts non-blank, non-comment lines of `shim.c` plus `shim.h`, and
  fails above 300 (01 §9).
- **Static analysis:** `clang-tidy` with `clang-analyzer-*`, `bugprone-*`, `cert-*` on every PR. The
  config also rejects stack arrays, `malloc`, threads and global mutable state.
- **No hidden state:** the shim holds no global variables. Each call takes the vendor handle that
  `vyrn-nic` owns.
- **Tests:** the DPDK path runs in CI against DPDK's software ring device (`net_ring`), which
  needs no hardware. The ef_vi path runs on the lab runners with X2541 cards, nightly, as part of
  B1. An AddressSanitizer + UBSan build of `vyrn-nic` and the shim runs the DPDK test.

## 5. The Vx parts

### 5.1 Decision and boundary

Vx code ships as two **shared libraries with a C ABI**, and Rust binaries host them:

| Artifact | Built from | Linked into | Used for |
|---|---|---|---|
| `libvyrn_vx_oracle.{so,dylib}` | `vx/vyrn-vx-oracle` | `vyrn-sim`, `vyrn-bench`, engine tests | Per-message differential testing (§6.3) |
| `libvyrn_vx_client.{so,dylib}` | `vx/vyrn-vx-client` | `vyrn-replica`, `vyrn-validator` | The replay engine of the Vx validators |

This is how "Rust for every binary" (01 §9) and "Vx for `vyrn-vx-client`" hold together: the Vx
client is the validator's **state machine**, and the Rust binary is its **shell**. The shell does
networking, Simplex, storage, signatures, `PktHash` checks and BLAKE3. The state machine does
everything that decides an output byte: MAC verdicts on `K_seq` tags, sequence checks, risk,
classification, matching from logged cuts, settlement, the auction uncross, and the canonical
state bytes.

**Why shared and not static.** Parts of the Vx runtime are written in Rust
(`stdlib/rust_core`). Linking a Vx static library into a Rust binary would put two copies of
Rust's runtime symbols into one link. A shared library with hidden visibility keeps them apart.
CI runs `nm -D --defined-only` on each library and fails if it exports any symbol outside the
`pbo_*` / `pbv_*` allowlist in `vx/abi/pbv.h`.

**Why the library is pinned by hash.** C-ONEBIN applies to the libraries too. `vx/build.sh`
writes `target/vx/manifest.toml` with the BLAKE3 hash of each library. `vyrn-replica`'s build
script embeds the hash. At start, the process hashes the library file it loaded and refuses to run
if the hash differs. A Vx validator cannot run a library from a different commit than its shell.

**What diversity covers and what it does not.** A bug in the Rust engine or in the Vx client is
caught: the two disagree, no state attestation reaches a quorum, and the book halts (§10.4.5). A
bug in the shared Rust shell (Commonware Simplex, `vyrn-log`, BLAKE3) is not covered by diversity.
Those are covered by the oracle, by `vyrn-sim`, and by B4. This is in the risk register (R7).

### 5.2 `vyrn-vx-oracle`: the sequential reference book

**What it is.** A single-threaded Vx implementation of 05's sequential specification of the book
(Requests to 05: `SEQSPEC`). It takes events one at a time and returns the response records each
event causes. It uses linear scans and sorted vectors. Its only performance target is
`BLD_ORACLE_MIN_RATE` = 1M events/s on DEV, which lets a differential test cover 10⁹ messages in
about 20 minutes.

**What it covers.** All of v1: `New`, `Cancel`, `Reduce`, `Replace` (with 01 §6.2's priority
rule), `CancelAll`, TIF (day, IOC, FOK, auction-only), post-only, STP modes, every reject of
01 §6.5 that the engine can produce, lane-local balances and reservations (01 §12.1), fees, and the
opening auction (08). Priority at a level is the key (rx_ts, lane id) of 01's level FIFO, so the
oracle inserts in key order. It does not append.

**Size.** DESIGN §8 says ~150 lines for the naive book. That holds for price-time matching alone.
With risk, STP, TIF, Replace and the auction, the budget is `BLD_ORACLE_LINES_MAX` = 1,500 lines of
Vx. Simplicity is the point: a reviewer must be able to read the oracle against 05 in a day.

**ABI** (`vx/abi/pbv.h`):

```c
typedef struct pbo_book pbo_book;

typedef struct {                 /* one linearised event, see §6.3 */
    uint8_t  kind;               /* 1 msg, 2 step, 3 auction_open, 4 auction_uncross, 5 epoch_end */
    uint8_t  lane;
    uint8_t  index;              /* message index in its packet, 0..9 */
    uint8_t  step_kind;          /* for kind = 2: Cross, Improve, Depletion, Rescan, Idle */
    uint32_t session;
    uint32_t pkt_seq;
    uint32_t _pad;
    uint64_t rx_ts;              /* Nanos */
    uint64_t step;               /* StepId, for kind = 2 */
    uint8_t  msg[16];            /* 01 §6.2 bytes, for kind = 1 */
} pbo_event;                     /* 56 bytes; static assert on both sides */

typedef struct {
    uint32_t session;
    uint32_t _pad;
    uint64_t step;               /* the step that produced it; 0 for lane-only responses */
    uint8_t  rec[16];            /* 01 §6.4 bytes */
} pbo_record;

pbo_book* pbo_new(const pbo_config* cfg);          /* tick band, accounts, balances, lane map */
uint32_t  pbo_apply(pbo_book* b, const pbo_event* ev, pbo_record* out, uint32_t out_cap);
uint64_t  pbo_state_bytes(const pbo_book* b, uint8_t* out, uint64_t cap);   /* canonical (07) */
void      pbo_free(pbo_book* b);
```

The functions are Vx `pub fn` with C-compatible parameter types. `pbo_apply` returns the number
of records written, or `UINT32_MAX` if `out_cap` was too small, in which case the harness fails
the test.

**The oracle is not trusted either.** `tests/golden/scenarios/` holds scenarios written by people
from the text of 05, 08 and 10: an input event list and the expected records. The engine and the
oracle must both pass every scenario. When the engine and the oracle disagree on a generated
input, the fix starts by writing the scenario that decides it. A disagreement that the scenario
blames on the oracle, and that traces to the Vx compiler rather than to oracle source, becomes a
FRICTION.md entry and an upstream bug report with a minimal reproduction.

### 5.3 `vyrn-vx-client`: the replay-only validator engine

**What it is.** A second, independent implementation of the replay engine of 01 §11.6, in Vx. It
consumes the order stream and data that the Rust shell hands it, runs 50 lane replayers and one
BBO replayer in parallel, produces the response records of every block, and writes the canonical
state bytes at checkpoints. "Replay-only" means it has no live mode: no NIC, no cut core (it reads
`StepRecord.cut`), no clock, no MMIO. That is why it does not need volatile
([vx-lang/Vx#3375](https://github.com/vx-lang/Vx/issues/3375)) or the cycle counter
([#3371](https://github.com/vx-lang/Vx/issues/3371)). Replay reads every shed decision from the
log (`PacketRecord.flags.SHED`, `Shed` steps) and never recomputes it (01 §14.1).

**The shell boundary.** `vyrn-replica` defines one trait and two implementations:

```rust
pub trait ReplayEngine {
    fn load_snapshot(&mut self, snap: &StateSnapshot) -> Result<(), ReplayError>;
    /// Hands the engine the inputs of one block; returns when the block's outputs are complete.
    fn replay_block(&mut self, blk: &BlockInputs) -> Result<BlockOutputs, ReplayError>;
    fn write_state(&self, w: &mut CanonicalStateWriter) -> Result<(), ReplayError>;
}

pub struct RustReplay { /* vyrn-engine in replay mode */ }
pub struct VxReplay   { /* vyrn-replica::vx bindings to libvyrn_vx_client */ }
```

Config key `engine.client = "rust" | "vx"` picks one. Both are always linked, so one binary serves
both kinds of validator (C-ONEBIN), and the operator assignment of 01 §5 (`CLIENT_SPLIT_BASE`,
`CLIENT_SPLIT_CHAIN`) is a config fact that `vyrn-admin config check` verifies across the cluster.

The client's C ABI:

```c
typedef struct pbv_ctx pbv_ctx;

pbv_ctx* pbv_new(const pbv_config* cfg, const pbv_shared* mem);  /* mem: rings and counters that
                                                                     the Rust shell allocated, 128-aligned */
int32_t  pbv_load_snapshot(pbv_ctx* c, const uint8_t* bytes, uint64_t len);
void     pbv_lane_run(pbv_ctx* c, uint8_t lane);    /* loops until mem->stop is set */
void     pbv_bbo_run(pbv_ctx* c);                   /* loops until mem->stop is set */
uint64_t pbv_state_bytes(const pbv_ctx* c, uint8_t* out, uint64_t cap);
void     pbv_free(pbv_ctx* c);
```

The shell writes `PacketRecord`s with their payloads into one input ring per lane and
`StepRecord`s into the BBO ring. The Vx lanes and the Vx BBO replayer talk to each other through
Vx-owned rings inside `pbv_ctx`. Output records go to one Rust-owned output ring per core. The
shell hashes the outputs into the block's output hash, and hashes the state bytes into the state
root, with the one BLAKE3 in `vyrn-crypto`.

**Output hash.** Both clients produce the same bytes for every block, over that block's outputs
only:

```text
out       = BLAKE3("vyrn v1 out" ‖ H(lane 0) ‖ … ‖ H(lane N−1) ‖ H(tx))      // "vyrn v1 out": 11 ASCII bytes
H(lane l) = BLAKE3(each response packet of lane l, in its production order:
                   session u32 ‖ resp_seq u32 ‖ echo_pkt u32 ‖ n u8 ‖ n × record[16])
H(tx)     = BLAKE3(each fill TX packet, in step order:
                   step u64 ‖ session u32 ‖ resp_seq u32 ‖ pkt_seq u32 ‖ lane u8 ‖ n_rec u8 ‖ role u8 ‖
                   n_rec × record[16])
```

Integers are little-endian. `record[16]` is the response record's 16-byte wire form (04). `N` is
the box's lane count, and a lane with no response hashes the empty string. Responses are hashed
per lane because 07 §7.1 `REP_MERGE` fixes each lane's order but not the order across lanes. A
response's `LaneCut` gate is physical (when the frame may leave) and is not hashed. The reference
implementation is `vyrn-replica`'s `output_hash`, `encode_resp` and `encode_tx`.

**What the Vx client implements itself:** SipHash-2-4 (it decides `BAD_MAC` rejects, so it is
part of the state machine; checked against `tests/golden/siphash.txt`), checked arithmetic,
the arena, the lane and BBO replay logic, settlement, the auction uncross and the canonical state
encoding. It shares no engine source with Rust. It shares only the ABI header, the golden files,
and the specification.

**Engine output must reach the vote.** Diversity only turns a bug into a halt if a replica's
engine output affects what it signs. This chapter requires that a replica attests, with its vote
or at its checkpoint, to the output hash of the blocks it has replayed and to the state root, and
stops attesting when its output differs from the quorum's. 07 and 09 own the message format. This
is in Requests to 07 (Interfaces) and an open question.

**Client v1 (M3).** What the first client fixes where the sketch above does not. Each is a
reading recorded with the PR that built it (`vx/abi/pbv.h` holds the exact layout):

- *Input.* The client takes 07's fields only, as `Engine::replay_wire` does: one input-ring slot
  per `PacketRecord` in O-order (`MID` and Advance records included) with its payload and the
  `RouteRecord`s of that packet inside the slot (a route joins the last packet whose range holds
  it), and one step-ring slot per `StepRecord`. The client applies `REP_MERGE` itself and keeps a
  lane record that is not due yet in its ring, so the shell carries nothing across blocks. A block
  is complete when the last step ran and every lane has used its ring up or waits on a later step.
- *Initial state.* `pbv_new` takes the account and session tables beside the config (as
  `pbo_new` does), since `pbv_load_snapshot` has no canonical state to read in v1. The lane
  argument of `pbv_lane_run` is a `uint32_t`.
- *Output rings.* One per lane and one for fill TX packets; each slot holds exactly the bytes the
  output hash takes, so the shell hashes without decoding.
- *Subset.* New (Day, IOC, FOK, post-only, auction-only), Cancel, Reduce, CancelAll, Heartbeat and
  ResendReq (no LaneSeq), `SHED` records (replayed from the record alone, so their slots carry
  no payload, 05 §18 Q17), and Cross, Improve, Shed, Idle, Depletion, Control, Rescan, Uncross and Seal steps.
  Anything else stops with `PBV_E_UNSUPPORTED` rather than guess, so a v1 Vx validator halts on
  it instead of diverging silently; the gap list below is the plan that closes it.
- *Step kinds and payloads (`PBV_ABI_VERSION` 4).* A step slot carries its 07 §3.8 payload:
  `plen` at byte 12 (≤ 32) and the bytes from byte 544. A payload on any other kind, or a
  malformed one, is `PBV_E_BAD_RECORD`. A Control step's Phase command sets the book phase,
  sends every lane a Phase event, and on a return to Continuous makes (B, A) exact at the cut. A
  Band command sends every lane a Band event (the lanes' band is not read in v1, as in
  `vyrn-lane`). Each lane keeps the phase of the last Phase event it applied, as `vyrn-lane`
  does: a book op is `AUCTION_PHASE` while Frozen (05 §2.5 P4), a New is `BOOK_HALTED` while
  Halted, and 04 §6.9 decides the rest. At the BBO a forwarded taker is `BOOK_HALTED` or
  `AUCTION_PHASE` while Halted or Frozen, an IOC or FOK ends `OUT_AUCTION` in an auction, a Day
  order rests without a sweep, and an auction-only order outside an auction is `AUCTION_PHASE`. A resting auction-only order is
  not live outside an uncross (05 §5.1), so no bound or maker search sees it.
  Outside Continuous the published snapshot is the empty book, each version records whether
  it was Continuous, and an envelope over a version that was not is suspect, as in `Bbo::finish`
  and `Bbo::envelope`. Only a Continuous step other than Rescan widens (B, A) to the envelope
  first. **[Reading, 1a]** A Rescan step replays its logged cut and band. Its batch taker is the
  first in-band New of `(prev, cut]` in key order.
- *CancelAll (3a).* A CancelAll takes `PROTO_CANCELALL_TOKENS` = 16 from the `MSG` buckets
  (`RATE_LIMIT` otherwise) and sets the session's `cancel_all`. After that, a Cancel, Reduce or
  Replace of an order whose current version precedes it is `TOO_LATE` with `D_CANCELED`
  (`Lane::resolve`). Any unapplied CancelAll before a forwarded op in its packet is a pass
  barrier (05 §3.7), and so is a Reduce in the op's range. The barrier is applied before the
  push, as `vyrn-lane` does; an in-range Reduce is no longer `PBV_E_UNSUPPORTED`. In the book, a
  CancelAll ends every order of its session on its lane at its key, which is the effect of
  either an `AcctKill` (one session on the account) or per-order tombstones (more than one).
  At B2 the lane sends a `CancelAck` per order still open, in ascending handle order, then the
  summary `CancelAck(PROTO_HANDLE_ALL, count)` (`settle_cancel_all`). **[Reading, 3a]** The
  client stops with `PBV_E_UNSUPPORTED` when a CancelAll enters a cut while a forwarded op of
  its lane with a lower LaneSeq is still queued, or while that lane's taker is continuing. That
  op would join the book after the CancelAll that already ends it. A CancelAll in a Rescan
  batch after the taker's key, or past C\* in an uncross, is `PBV_E_UNSUPPORTED` like a Cancel.
  **[Reading, 3a]** The test harness opens one session per account per lane, so only the
  `AcctKill` path is exercised; the client treats both paths the same. A barrier only changes
  what a forwarded op's dependencies are; `the_vx_client_replays_in_packet_dependencies` (item
  5) is the test a mutant without it fails.
- *In-packet dependencies (5).* The lane's `forward` builds the list as `vyrn-lane` does: every
  earlier unapplied, not explicit Join or Cancel of another order in range of the forwarded op
  becomes explicit, and the op's `resp_seq` advances by 2. Each one is an `OP_DEP` op-log entry
  at its own LaneSeq (its version slot for a Join, its leg for a Cancel); the forwarded entry
  carries a mask of their distances. The BBO applies them in index order before the source, as
  `Bbo::apply_deps`: in a Frozen book every one, and in a Halted book a Join, gets its reason;
  a Join rests (`Ack`), and a Cancel ends the order (`CancelAck` of its open quantity, or
  `TOO_LATE` when none is open). Their records go in the deps packet (`ROLE_DEPS`, the source's
  `resp_seq`; the source's packet takes the next), which stays in dependency index order: a
  maker record of a Join dependency rested in the same step goes after that dependency's
  records while the packet has room, else to its session's maker packet (spec follow-up F8). A
  Shed step gives every dependency `Reject BUSY`. At B1 a refused Join ends its order (a `BUSY`
  one is shed) and a Cancel that took effect ends its order. **[Reading, 5]** As in
  `Bbo::apply_deps`, a dependency's record index is the source's minus its LaneSeq distance
  (spec follow-up F2: `FwdDep` has no message index), not the message's own index.
  A Join dependency that a visible level crosses at the source's cut (item 5b) matches first, at
  that cut, as `Bbo::join_dep` does: a post-only one ends with `Reject POST_ONLY_WOULD_CROSS`;
  otherwise it sweeps with the step's cap (D14), its taker records in the deps packet, and rests
  any open quantity (`Ack`). One that traded or ended ends the step. The next step is a `CONT`
  step of the same source at the same cut: a capped sweep resumes, then the remaining
  dependencies run, their records in a continuation deps packet (`resp_seq` 0), and the
  source's entry checks and first sweep run in the step its dependencies finish in (its packet
  still takes `resp_seq` + 1). **[Reading, 5]** A Cancel dependency whose order's Join is applied
  but past the cut, which the client's book has not seen, stops with `PBV_E_UNSUPPORTED`. None
  of the first 149 swarm seeds reaches it.
- *Rescan batch takers (2).* The batch taker runs as `Bbo::rescan_finish` does. It must be
  live just after its key, or it is skipped with no status event; an auction-only taker is not
  live outside an uncross. A post-only taker that a visible level crosses ends with a batch
  `Reject POST_ONLY_WOULD_CROSS`. Otherwise it sweeps from `min(A, band_lo)` for a buy, or
  `max(B, band_hi)` for a sell, and sees makers at its key (05 §5.2): an order joined in
  `C_{s−1}`, or in the batch before the key. The sweep is capped like a forwarded one: one level
  or `ENG_STEP_FILLS` = 8 fills per step. A taker with open quantity left gets `RESTED_IN_FLIGHT`
  if its sweep was capped and `RESTED_DONE` otherwise. A capped taker resumes in the next step,
  which must be a Rescan with no source at the same cut (`PBV_E_KIND`, `PBV_E_CUT`; its band is
  not read). Its key and `C_{s−1}` are kept, and (B, A) stay as they are until the sweep ends,
  when they are made exact from `(max(B, band_hi), min(A, band_lo))`. Maker fills have TX
  packets as in a forwarded sweep. The taker's own Fill, Out and Reject records are the
  lane's (05 §8.10 rule 4): the lane holds them until the version settles, and holds the
  taker's Ack while it is in flight (rule B), as `vyrn-lane` does. STP that would act in a batch
  sweep is still `PBV_E_UNSUPPORTED` (item 4). **[Reading, 2]** A Cancel or Reduce in a Rescan
  cut that orders after the taker's key stops with `PBV_E_UNSUPPORTED`. The Vx book has
  already applied it, but at the key it is not visible. Live never logs such a cut:
  `Bbo::clamp_after_key` cuts below the first op after the key. For the same reason, on a live
  log key visibility and cut visibility are the same. So the client implements 05 §5.2, but a
  replay test cannot tell the two apart (a mutant that sees the whole cut passes, as does one
  that drops the kept `C_{s−1}` in CONT steps). Two other rules are also unobservable in tests:
  making the bounds exact while the sweep is still capped, and a batch maker past the key
  (searched, not found). **[Reading, 2]** An auction-only batch taker is skipped with no status
  event, as Rust's `Sweep::Skipped`; 1a sent it `RESTED_DONE`.
- *Uncross and Seal (1b).* A Frozen phase step records the frozen cut C\*. The Uncross step
  that opens an uncross takes p\* and Q from its 07 §3.8 payload (#177) and needs a Frozen book
  at C\*, else `PBV_E_MISMATCH`. Each chunk gives at most `ENG_UNCROSS_CHUNK` = 6 `LIQ_AUCTION`
  fills at p\*: buys from the highest level down, then sells from the lowest up, each level in
  key order, visible at C\* (auction-only orders included). No TX packet is made; each lane
  holds the fill record until its order's version settles, as `vyrn-lane` does (05 §8.9). A book
  at C\* that cannot fill Q is `PBV_E_MISMATCH`, as `Engine::replay_wire` makes it. While an
  uncross is open only its chunks run, separated by at most one Idle step each. The chunk that
  fills Q sends every lane an Uncross event, returns to Continuous and makes (B, A) exact. A
  chunk step with a payload is `PBV_E_BAD_RECORD`. After a Seal step no step runs (`PBV_E_KIND`).
  `tests/replay.rs` checks the oracle's price-time allocation by hand. **[Reading, 1b]** A cut
  past C\* that holds a Cancel or Reduce while an uncross is open stops with
  `PBV_E_UNSUPPORTED`: the Vx book has already applied it, but at C\* it is not visible.
  *Auction-only remainders (05 §8.8 item 6, #193).* The chunk that ends the auction sends each
  lane its C\* in the Uncross event. The lane ends every auction-only order with `ins_seq` ≤
  C\*[l] and open > 0 with `Out{cause: AUCTION}` for its open quantity, in session slot order
  (`session_slot`, not the order `VxConfig` lists sessions) and then root creation order. It does this in B2, right after every pending op ≤ C\*[l] has
  settled and before any later one, as `vyrn-lane` does. The BBO keeps C\* (`adead`, vyrn-bbo
  `State::adead`), so no later uncross sees those orders. `tests/replay.rs` checks this with an
  unfilled auction-only sell, a later cancel of it (TOO_LATE), and a second auction in which that
  sell would otherwise fill first. Mutation check: dropping the end or `adead` fails the test.
  Running the end before the pending ops ≤ C\* still passes, because no script yet has such an
  op pending at the uncross.
  An order a Reduce moved past C\\* after the freeze is still ended: the lane takes the version
  in effect at C\\* (`version_at`, through each version's predecessor), outs that version's open
  quantity, releases and kills every leg from the current version back to it, and holds the
  `Out` under that version, so the Reduce then settles `TOO_LATE` (05 §8.10 rule 4.1), as
  `vyrn-lane` does since #202. `tests/replay.rs` drives that script live over `vyrn_cut::Sim`,
  so the lane admits the Reduce before it sees the freeze and the BBO runs the uncross before it
  sees the Reduce. A client that tests the current version fails it. Holding the `Out` under the
  current version, or releasing only its leg, still passes: the `Out` flushes at the uncross
  boundary, before the Reduce settles, and a Reduce keeps its predecessor's leg. Replace (3b)
  makes the second one observable.
- *Gap list (the plan).* What `RustReplay` replays and the Vx client does not yet
  (1, Uncross and Seal, 2, Rescan batch takers that trade, and 5 and 5b, in-packet dependencies
  with crossing Join dependencies, are done). The client fully replays all of the first 149
  sim-swarm seeds, each under its generated fault schedule (3 before 5, 142 after it);
  `vx_golden.rs`'s `the_vx_client_replays_the_swarm_seeds` requires that, with no
  `PBV_E_UNSUPPORTED` allowance, and runs in the CI `vx` job.
  3. Replace (keep and new priority); CancelAll (3a) is done.
  4. STP that triggers (currently `PBV_E_UNSUPPORTED` in a forwarded or batch sweep and the FOK
     dry run).
  6. `engine.client` wiring in `vyrn-validator` (nothing constructs `VxReplay` today).
  7. Then a write-up of what a Vx default (`engine.client = vx`) needs; the default stays `rust`.
- *Pooled lanes (`AcctTake`, 05 §6.9, 07 §7.1).* `pbv_config` byte 48 is the pool mask,
  `pbv_account` byte 6 flags a pool-wide index at byte 44 (`Lane::set_pool_index`), and
  `pbv_session` byte 10 flags a pooled account at byte 12 (`Engine::pool_session`;
  `PBV_ABI_VERSION` 3). STP compares that index across pooled lanes. **[Reading]** The shell
  checks each `AcctTake` sits right before its packet record, as `RustReplay` does, and puts it
  in that record's slot (byte 416) with its predecessor: the highest lower `ver` of the account
  fed so far, and its lane. A pooled record is due once the account's reproduced count reaches
  that predecessor, so the account's takes replay in `ver` order across lane threads; a lane
  waiting on another lane's take reports that lane's wait step, and only while that lane is idle,
  so the BBO's merge never reads it as settled early. A lane in a take wait publishes the take it
  waits for; one whose chain of waiting lanes leads back to itself, every hop still blocked, has
  a cyclic take order no lane can break and stops with `PBV_E_FAULT`. A take carries with its packet because the
  record stays in its ring. **[Reading]** Each pooled record's lane call takes the account's
  next `ver` (gapless from 1, the token's order); a record of a pooled session without a take,
  a take of another account or `ver`, or a take on a record of an unpooled session is
  `PBV_E_FAULT` (Rust's `Mismatch`). A misplaced or repeated `(account, ver)` take
  (`BadRecord`) is refused by the shell before the client sees it. `tests/replay.rs` ports
  vyrn-engine's take cases and compares at every block split.
- *Band reference.* Each packet record that classifies (not Advance, not `SHED`) checks the
  price band against snapshot version `base + snap_lag` (05 §6.5, 07 §7.1, ruling (c), which
  supersedes #137's boundary-only rule). `base` is the version the lane's latest boundary step
  published, and the slot carries `snap_lag` at byte 56 (`PBV_ABI_VERSION` 2). A `MID` boundary
  inside a packet moves `base` for later packets but not the packet's own snapshot, and an
  Advance boundary also raises the lane's snapshot version to `base`, as `vyrn-lane` does. A
  record is due once its `fills_applied` step ran and the BBO has published that version. The
  client looks it up in a ring of `REPLAY_SNAP_HIST` = 4096 versions, and a version the ring no
  longer holds is `NoSnapshot`, which the client reports as `PBV_E_FAULT`. The snapshot is
  Rust's `Bbo` bounds, not the exact book: before each step `band_env` widens (B, A) to the
  envelope of the snapshot versions the cut's ops may hold, `touch`, a resting taker and an
  Idle/Depletion observation move them, and `finish` publishes them as a new version when
  they change. The client keeps the same bounds, version history and per-lane lowest versions.
- *`LOWVER` (07 §3.8, #190; `PBV_ABI_VERSION` 5).* Step slot byte 24 carries the step's
  `lowver` bitmap. For each set bit the BBO takes, at the step's finish, the version lane `l`
  held when it applied its op at `cut[l]`: each op-log entry records the lane's snapshot version
  when pass 2 applies it, which is `Lane::applied_ver` and so `CounterLine.snap_ver` as #190
  publishes it. A source lane then takes its forwarded op's version, as before. A bit past the
  box's lanes is `PBV_E_CUT`, and a bit on a lane whose cut is 0 is `PBV_E_BAD_RECORD`
  (`Engine::step_call`). The client no longer reads lane counters for `lowver`. **[Reading]**
  "The version of the packet holding `cut[l]`" is the version of the lane call that applied the
  op, as `Engine::low_hist` records it, not the op's own packet's when pass 2 runs in a later
  call. The value matters (engine thread, #199): replay resets the band bounds to the envelope
  each step, and those bounds are published and versioned, so a wrong `lowver` gives snapshot
  versions live never had. Under a no-mask mutant, sim-swarm seeds 1–300 fail 10/300 with
  INV-DET `NoSnapshot`; seed 6f with faults `drop 31` is pinned in `tests/seeds.toml`.
  `vyrn-sim/tests/vx_golden.rs` frames that seed's live order stream as 07 (`cluster::run_log`)
  and replays it with `RustReplay` and the Vx client, which must give the same output hash. That
  log has in-packet dependencies (gap item 5); a client that ignores the mask fails it. The scripted `tests/replay.rs` checks still compare LOWVER steps byte for
  byte with `RustReplay`: the band and `snap_lag` scripts at every block boundary, a lane's
  catch-up past the 4095-version window, an evicted version, and the `BadRecord` cases.
- *Capacity.* The op log (`OPLOG_CAP`) and the forwarded queue (`FWDQ_CAP` = 1024 per lane) are
  fixed. A live lane can have up to `ENG_FWD_RING` + the BBO's lane buffer forwarded ops in
  flight, so more than `FWDQ_CAP` forwarded ops due before one step (or an op log full before
  one) is a capacity fault: the client stops with `PBV_E_FAULT` instead of waiting on the BBO,
  which waits on the lane (`tests/replay.rs`, forwarded-queue test).
- *Threads.* `VxReplay` creates the `n + 1` threads (W-04) but does not pin them yet: pinning
  comes with the core map (§10.1), and tests run unpinned. W-03 calls libc `sched_yield`, not
  `vyrn_vx_spin`, because vxc cannot declare a host symbol (W-18 in `vx/FRICTION.md`).
- *CI.* The `vx` job runs `vx/build.sh`, then `tests/replay.rs`, `oracle_scenarios` and
  `vx_golden` with `VYRN_REQUIRE_VX=1` and `VYRN_REQUIRE_VX_ORACLE=1`, so a missing library fails
  them. The other
  jobs build no Vx, so their Vx halves skip. vxc embeds its source and target directories and
  links the distro's LLVM/MLIR 22 statically, so the job runs in `debian:trixie` with
  `HOME=/home/user`, the host kind `vxc_blake3.x86_64-linux` was pinned on. It builds vxc with
  `.agents/setup`'s own `llvm_for_vx` and `vxc_build` (`.github/scripts/vxc.sh`) and caches the
  binary with the files vxc reads at run time (its `stdlib/` and three `.so` files, W-10) by
  `vx/TOOLCHAIN` and `rust-toolchain.toml`. LLVM/MLIR 22 is installed on every run, since vxc
  runs its `llvm-config` and links against it. `vx/build.sh` checks its hash either way.
  A cold run takes about 7.5 min (vxc 4.2 min), within S1's 15. On aarch64 there is no pin, so
  the job is x86-64 only.

**Race testing.** The Vx client's own cross-core protocol is tested with `--sanitize=thread` and
with `VX_TASK_SEED` sweeps in CI (§9.2). The interleavings of the shell-to-client rings are
tested by a Rust nightly ThreadSanitizer build of `vyrn-replica` linked against the TSan build of
the client.

### 5.4 Build

`vx/build.sh` is the only way a Vx artifact is built, in CI and on a laptop:

1. Check that the `vxc` binary on `PATH` hashes to the value in `vx/TOOLCHAIN` (v0.0.4,
   `3a89e3c7`). Refuse otherwise. **[Reading, W-10]** v0.0.4 has no release binary, so the value
   is per host kind (`vxc_blake3.<arch>-<os>`): the hash of `.agents/setup`'s build, made with
   the `rust-toolchain.toml` pin by that name and with the registry, toolchain and rust-src paths
   remapped, and with mlir-sys's and tblgen's build scripts sorted (they list a directory in
   `read_dir` order, which differs between filesystems and so changed vxc's static link order
   between machines). vxc still embeds its source and target dirs, so the host kind includes
   setup's layout under `HOME`. The host kind is not per CPU: two x86_64 orbs with identical CPU
   flags differed only by link order. A pin is recorded only once clean builds on two machines of
   that host kind match, and never for a host kind nobody has built on.
2. Build `vyrn-vx-oracle` and `vyrn-vx-client` as shared libraries for the host target, with
   optimisation on. On aarch64, pass `-fweak-relaxed-atomics` for the client (DESIGN §8: without
   it, `Relaxed` loads compile as `Acquire`; correct either way, slower without it).
3. Run `vxc --audit`. Fail on any unproven `valid(p, n)` contract outside the `unsafe` blocks
   listed in `vx/AUDIT.allow`.
4. Build the TSan variant of the client (`--sanitize=thread`) into `target/vx/tsan/`.
5. Check exported symbols (§5.1).
6. Write `target/vx/manifest.toml`: library paths, BLAKE3 hashes, vxc hash, target triple.

The Rust build runs after it, because `vyrn-replica` embeds the hashes. The exact `vxc` flag
spellings live in `build.sh` and nowhere else, so a vxc release that renames a flag changes one
file.

### 5.5 Schedule tied to the Vx issues

The upstream requests are filed on GitHub (vx-lang/Vx). Each `W-nn` is keyed to one issue.

| `W-nn` | Upstream issue | Needed for | Needed by | Workaround until it lands | Removed when |
|---|---|---|---|---|---|
| `W-01` | `copy`, `copy_nonoverlapping`, `write_bytes`: comment on [#2501](https://github.com/vx-lang/Vx/issues/2501) | copying 16-byte messages and records | M3 (correct replay) | a loop of `read`/`write`; cost measured in B12 | the PR merges and a vxc release includes it |
| `W-02` | `hint::prefetch_*`: [#3373](https://github.com/vx-lang/Vx/issues/3373) | prefetching level heads and arena slots | M4 (1B msgs/s) | `extern` call to a host function `vyrn_vx_prefetch(p)` | same |
| `W-03` | `hint::spin_loop` by target: [#3369](https://github.com/vx-lang/Vx/issues/3369) | lane and BBO replayers waiting on rings and cut counts | M3 | `extern` call to host `vyrn_vx_spin()` (Rust `spin_loop`) | same |
| `W-04` | pin a task to CPUs: [#3370](https://github.com/vx-lang/Vx/issues/3370) | each replayer on its own isolated core | M3 | the Rust shell creates and pins the threads and calls `pbv_lane_run` / `pbv_bbo_run` on them | the client moves to `tasks` with `pin_current`, so that `VX_TASK_SEED` covers its whole protocol |
| `W-05` | struct alignment: [#3374](https://github.com/vx-lang/Vx/issues/3374) | single-writer lines in Vx-owned rings and counters | M3 | shared lines come from the Rust shell (`pbv_shared`, 128-aligned); Vx-owned lines get explicit pad fields and `std::alloc::alloc(bytes, 128)` | same |
| `W-06` | α: comment on [#353](https://github.com/vx-lang/Vx/issues/353), plus [#3372](https://github.com/vx-lang/Vx/issues/3372) (the CCD fleet file and α probe) | making the cross-CCD hop a visible cost in Vx | not blocking | none needed | we contribute the probe and fleet file in M4–M5, using our B7/B8 data as the measurement |
| `W-07` | volatile: [#3375](https://github.com/vx-lang/Vx/issues/3375) | a Vx sequencer only | never (not planned) | none needed | — |
| `W-08` | cycle counter: [#3371](https://github.com/vx-lang/Vx/issues/3371) | a Vx sequencer only | never (not planned) | none needed | — |

**Order of work:** #2501 and #3373 first (small stdlib PRs); #3370 and #3374 wait for a
maintainer's design decision; #3369 and #3372 run as design discussions in parallel.
**Before M2 ends**, test whether `vxc --emit-llvm` output links into the `linker-plugin-lto`
build. If it does, `W-02` and `W-03` inline across languages and cost nothing. That experiment
also shows whether the two-runtime problem of §5.1 appears with bitcode linking.

**Upstream rules.** We do not fork Vx. A missing feature is an upstream issue plus a logged
workaround. Each upstream change is one behaviour per PR. #3369, #3370, #3374 and #3372 change
language, runtime or model policy, so each stays an issue until a maintainer agrees, before it is a
branch. Before every push to vx-lang/Vx, `git log -1 --format=%ae` must show the address that
signed the Vx CLA.

### 5.6 Workaround policy

Every Vx workaround has an ID `W-nn`. The IDs `W-01`–`W-08` are fixed by the table of §5.5, and
each is keyed to its vx-lang/Vx issue number. A workaround with no issue gets the next free number
(`W-09` on) and a new upstream issue before it merges.

- **In the code:** each site carries `// VX-WORKAROUND W-04 (vx-lang/Vx#3370)`.
- **In `vx/FRICTION.md`:** one entry per ID with: the issue link, date opened, what the workaround
  does, every file that has the marker, its measured cost (benchmark ID and number), the condition
  for removal, and its status.
- **In CI:** `tools/vx-friction` fails if a marker has no entry, if a marker's issue number differs
  from its entry's, if an entry lists a file that has no marker, or if an entry whose issue has
  landed upstream (status `landed`) still has markers 60 days after the vxc release that contains
  it.
- **Not only workarounds.** Every oracle or client disagreement traced to the Vx compiler or
  standard library, and every Vx feature we looked for and did not find, gets a FRICTION.md
  entry. FRICTION.md is how VYRN pays Vx back: it is the evidence for each upstream issue.

### 5.7 The 1B msgs/s requirement on the Vx client

The Vx client must replay `≥ 1B msgs/s` on `REF` hardware (B12), the same rate as the Rust
client. The reason is quorum arithmetic:

- **CHAIN:** n = 5, q = 4, split 3 Rust + 2 Vx. Every set of 4 validators contains at least one Vx
  validator. If the Vx client lags, every quorum waits for it, and finality is the Vx client's
  replay lag plus the consensus time.
- **BASE:** n = 4 voting replicas (R1 in F1 beside `vyrn-seq`, R2–R4 in F2–F4), q = 3, split 2
  Rust + 2 Vx. Every set of 3 contains at least one Vx replica. The same holds.
- **Failover.** `vyrn-seq` never votes, and failover promotes the warm standby `vyrn-seq` in F2, never
  a voting replica (01 §14.4). So the split, and this arithmetic, survive every failover (§7.22).

So a slow Vx client is not a slow minority. It sets `FINALITY_MAX_MS` for the whole book. The Vx
client also needs catch-up headroom: after a restart or a stall, it must replay faster than the
book produces. B12 therefore requires 1.0B msgs/s sustained and `BLD_CATCHUP_RATE` = 1.2B msgs/s
from memory (07's B-REP-VX asks the same 1.2×). The kill criterion is R5 in the risk register.

## 6. Testing strategy

Seven layers, from cheapest to most expensive. Each catches a class of bug the layer below
cannot.

```
   layer                      runs on                 catches
   ─────────────────────────  ──────────────────────  ─────────────────────────────────────────
   1 unit + loom + Miri       every PR, all hosts     wrong function, wrong memory ordering, UB
   2 property (proptest)      every PR, all hosts     engine ≠ oracle on small random books
   3 differential per msg     every PR + nightly      engine ≠ oracle on 10⁹-message streams
   4 vyrn-sim                 every PR + swarm        protocol bugs under faults and timing
   5 fuzzing                  every PR + nightly      panics and wrong verdicts on hostile bytes
   6 chaos on hardware        nightly staging         what the simulator does not model
   7 cross-build determinism  nightly + release       compiler, flag and client divergence (B4)
```

### 6.1 Unit tests

- **Every crate** has unit tests next to the code. Engine crates must reach
  `BLD_ENGINE_LINE_COVERAGE` = 90% line coverage and 100% of reject codes in 01 §6.5 that the
  crate can return (a table test per crate lists each code and the input that produces it).
- **Golden vectors** in `tests/golden/`: every layout of 01 §6 (encode, decode, byte offsets),
  SipHash-2-4 (the paper's 64 vectors), BLAKE3 (the official `test_vectors.json`, including
  `derive_key`), LEB128 edge cases (0, 127, 128, `u64::MAX`), Ed25519 edge cases (§2.5). The Vx
  client runs the SipHash and canonical-state vectors too.
- **loom** models for `vyrn-cut::ring`, the snapshot seqlock, the cut publication and the pool
  primitives (token CAS and release, steal lock, sibling-segment `fetch_and` against the BBO
  core's sweep): every interleaving up to a preemption bound of 3, with the real atomics replaced
  by loom's. These are the tests that check the `Release`/`Acquire` pairs of 05.
- **Miri** runs the unit tests of `vyrn-cut::ring`, `vyrn-lane::arena` and `vyrn-engine::alloc` on every
  PR, with `-Zmiri-strict-provenance`. These tests are single-threaded: Miri checks the `unsafe`
  code for undefined behaviour (provenance, aliasing, bounds, uninitialised reads) on one thread,
  and loom (above) checks the cross-thread races. `lint-engine` bans `std::thread` in every
  engine source file, test files included (§2.3), so an engine crate has no threaded Miri test.
  A threaded Miri run of the rings would need a test-only exemption in
  `tools/lint-engine/rules.toml` (`[source] banned_paths`); that is a separate change.

### 6.2 Property tests: engine against oracle

`proptest` generates small worlds and checks the engine against `vyrn-vx-oracle`:

- **World:** 1–6 dedicated lanes plus a pool of 0–4 cores (01 §14.15), 1–64 accounts with each
  class, a tick band of 16–256 ticks, balances near the
  reservation limits, every message type and flag combination of 01 §6.2, every TIF and STP mode,
  auction phases.
- **Driver:** the engine's cores run under `vyrn-sim`'s scheduler with a seed that proptest also
  generates, so the same input runs under many interleavings and stale-snapshot delays.
- **Property:** after every event, the engine's records equal the oracle's (§6.3), and the
  canonical state bytes are equal at the end.
- **Shrinking:** proptest shrinks the message list and the scheduler seed together, so a failure
  ends as a short message list plus one interleaving.
- **Budget:** 2,000 cases per property on each PR (`BLD_PROPTEST_CASES_PR`), 1,000,000 nightly.
  Failures are saved to `proptest-regressions/` and run forever after.

Other properties: wire encode/decode round trips; `Handle` generation reuse never aliases a live
order; the reservation of 01 §12.1 never goes negative; every `Ack` is followed by at most one
terminal record (`Fill` to zero, `CancelAck`, `Out`) for that handle.

### 6.3 Per-message differential testing against `vyrn-vx-oracle`

**Decision.** The harness diffs the engine against the oracle after every message, not once per
log. The oracle is linked through `pub fn` (§5.2), so the check runs in the same process with no
serialisation.

**Linearisation.** The engine's log is a partial order (lanes run in parallel). The harness turns
it into the sequence of events that 05's `SEQSPEC` defines:

```rust
// inputs: PacketRecords per lane (in LaneSeq order), StepRecords (in StepId order)
let mut done = [LaneSeq(0); N];                     // last lane op linearised, per lane
for s in steps {                                    // StepId order
    for l in lane_order(seed) {                     // a seeded permutation of 0..N (see below)
        for op in lane_ops(l, done[l] + 1 ..= s.cut[l]) {
            if op.is_lane_local() { oracle.apply(op.event()) }   // join, cancel, reduce, ...
        }
        done[l] = s.cut[l];
    }
    oracle.apply(Event::step(s));                   // the BBO-bound op of the step, plus its
}                                                   // kind (Cross, Improve, Depletion, Rescan)
```

Five checks come out of this:

1. **Equality.** Each event's oracle records must equal the engine's records attributed to the
   same event (same session, same record bytes, same `StepId` for fills). The first difference
   stops the run and writes a report: seed, `StepId`, lane, `LaneSeq`, the event, both record
   lists, and a diff of both canonical states.
2. **Commutation.** `lane_order(seed)` is a different permutation on each run. Lane-local ops of
   different lanes inside one cut interval must commute (they touch different accounts, and
   joins insert by key). Pool cores are the exception: two of them can touch one pooled account
   in one interval, so the permutation keeps each pooled account's ops in `AcctTake` `ver` order
   (01 §14.17 item 4) and permutes everything else. If two permutations give different oracle
   outputs, the design's lemma (DESIGN §3) is broken, or `is_lane_local` misclassifies an op.
   Each nightly run uses three permutations of the same log.
3. **Two passes equal index order (01 §14.2).** The engine dispatches a packet's BBO-bound ops in
   pass 1 and applies its joins and cancels in pass 2. The oracle applies the packet's messages
   strictly in index order 0 … `count − 1`. For every message, the engine's records must equal the
   oracle's records for that message. A cross at index 9 that the BBO core filled against an
   index-2 join of its own packet (through the in-packet dependency list) must give the same
   fills, STP outcomes and handles as the oracle's sequential order. The generators of §6.2 and
   §6.6 bias packets toward 10 messages with same-packet dependencies at every index pair.
4. **Shed decisions replay.** A packet with `PacketRecord.flags.SHED`, or an op shed by a `Shed`
   step, gets `Reject BUSY` from the oracle and no state change. The harness never recomputes a
   deadline; it reads the decision from the log (01 §14.1).
5. **Pooled accounts in session order.** For every pooled account, the ops in token order equal
   the oracle's per-session `pkt_seq` order, whichever pool core ran each op, and a cancel that
   cleared a sibling core's segment bit gives the oracle's `CancelAck` or `TOO_LATE`.

The harness also validates the log on its own before replay: `INV-CUT-MONO` on each of the two
half-cuts and on the step cut; each step's cut covers its `src_lane_seq`; `rx_ts` is
non-decreasing per lane; `first_lane_seq` values are gapless; `fills_applied` never exceeds the
current step; every pooled packet has its `AcctTake`, and each account's `ver` is gapless.

**Scale.** Per PR: the golden logs in `tests/logs/` (about 10⁷ messages). Nightly: 10⁹ messages
from `vyrn-sim` runs of 02's reference workload, and a 60-second capture of the B3 run on `REF`
(about 6 × 10¹⁰ messages, sharded by block range across the lab's DEV and Linux machines).

### 6.4 `vyrn-sim`: the deterministic simulator

**Decision.** The whole cluster runs in one process, on one OS thread, driven by a seeded
discrete-event loop with virtual time. The same seed gives the same run, byte for byte, on macOS
and on Linux. This is the FoundationDB and TigerBeetle approach, and it is the main test of the
replication, failover and handoff protocols.

```
                  vyrn-sim (one thread, virtual time in Nanos, ChaCha8 seeded per component)
 ┌───────────────────────────────────────────────────────────────────────────────────────────┐
 │  event queue (time, seq) ──► scheduler picks the next runnable item, seeded ties          │
 │                                                                                           │
 │  clients ×k ──► sim network (links: latency dist, loss, dup, reorder, partition)          │
 │     (02 workload)        │                                                                │
 │                          ▼                                                                │
 │  box: vyrn-seq  [vyrn-nic::sim queues, PHC model] ─► dedicated lanes + pool ─► cut A, B   │
 │                  ─► BBO ─► TX-A, TX-B, stream-A, stream-B (core map of 01 §10)            │
 │                  each core = Core::poll() step; vyrn-cut Visibility = Sim (seeded delay)  │
 │  box: vyrn-seq standby (F2)  warm, promoted on failover; never votes                      │
 │  box: vyrn-replica ×n      engine = Rust replay, or Vx client through the C ABI           │
 │  box: vyrn-data ×m         payload store and fan-out                                      │
 │  consensus: vyrn-consensus on commonware-runtime::deterministic, same virtual clock       │
 │  disks: in-memory journal with a fault model; clocks: per-box offset, drift, steps        │
 │                                                                                           │
 │  checkers: invariants after every event; oracle diff per message; liveness after heal     │
 └───────────────────────────────────────────────────────────────────────────────────────────┘
```

**How the real code runs inside it.**

- Every pinned role is a `Core` (§3.1). The scheduler calls `poll()` on one core at a time and
  advances virtual time by a cost from the cost model. The default cost model uses the B6 and B8
  results; the `chaos-timing` model draws costs from a heavy-tailed distribution to provoke races.
- `vyrn-cut`'s `Sim` visibility backend holds every published store (lane counter, cut, snapshot,
  ring tail) in a delay queue for a seeded number of virtual nanoseconds before readers see it.
  That is how stale cuts and stale snapshots, the inputs to the lemma's slow path, happen in the
  simulator. **Ordering model.** One `Sim` serves one simulated box. Publication `k` gets the
  deadline `d_k = max(now + δ_k, d_{k−1})`, with `δ_k` drawn from 0..=`BLD_SIM_VIS_MAX_NS` by a
  seeded SplitMix64, so deadlines never decrease in publication order across every line of the
  box. A reader sees, on each line, the newest publication whose deadline has passed. So the
  visible publications are always a prefix of the box's global publication order: a reader can
  see a stale value, but never a later store without every earlier one, on any line. That is
  one of the executions x86-64 TSO allows (one global store order that keeps each core's program
  order), so it invents no reordering the `REF` hardware could not show. A line holds at most `SIM_PENDING` = 8 publications in flight;
  publishing a ninth makes that line's oldest publication, and every earlier one on every line,
  visible at once. Values are never merged or dropped. Pool read-modify-writes (token CAS, steal
  lock, segment `fetch_and`) are not delayed: an RMW always acts on the newest value. A weaker
  mode with per-line delays would model aarch64; it is not specified (`vis.rs` in
  `crates/engine/vyrn-cut`, tests `sim_visibility_is_a_global_prefix` and
  `sim_full_queue_keeps_cross_line_order`).
- `vyrn-consensus` already runs on Commonware's runtime trait, so the simulator gives it the
  `deterministic` runtime with the simulator's clock and network.
- The Vx client runs in the simulator through `VxReplay` with its threads replaced by
  `pbv_*_step` entry points (a bounded-work variant of `pbv_lane_run`, an M4 deliverable, §11).
  Until then, sim runs use the Rust replay engine and the Vx client is covered
  by §6.3 and B4.
- **Fault points.** Non-engine crates (`vyrn-log`, `vyrn-data`, `vyrn-consensus`, `vyrn-replica`,
  `vyrn-epoch`, `vyrn-chain`) may contain `vyrn_types::fault_point!("name")`, which is `false` in
  production builds and seeded in `vyrn-sim` (FoundationDB's BUGGIFY). Engine crates contain no
  fault points. Their faults are injected only at their boundaries (rings, visibility, NIC queues,
  allocator), so the engine code under test is the production code.

**Determinism of the simulator itself.** No wall clock, no threads, no `HashMap` with a random
seed, no iteration over OS state. Each component draws from its own ChaCha8 stream seeded with
`BLAKE3(seed ‖ component name)`, so adding a component does not shift the others' randomness. CI
runs one seed twice on macOS and twice on Linux and requires all four trace hashes to be equal.

**Swarm testing.** Each seed also picks the configuration: dedicated lanes (1–42) and pool cores
(0–7), mode, enabled fault classes, fault rates, workload intensity, epoch length (compressed to
seconds). One seed in four runs the `REF` map of 01 §10 exactly (42 + 7, two cut, TX and stream
cores each). Most bugs need a specific combination, and a fixed configuration never finds them.

**Fault catalogue.**

| ID | Fault | Layer | What it exercises |
|---|---|---|---|
| SF-01 | Packet loss, duplication, reordering on any link | network | client resend, `ResendReq`, gapless `pkt_seq` |
| SF-02 | Corrupted payload bytes | network | MAC reject, session close rule (01 §12.5) |
| SF-03 | Packet from an unbound source address with a bad MAC | network | drop-and-count, session stays open |
| SF-04 | Client sends two versions of one `pkt_seq` (sequencer gets one, data tier the other) | client | `PktHash` mismatch, session kill (07) |
| SF-05 | Loss of one replication path; then of both paths for a window | network | `INV-FRAME-FIRST`, the revert condition of DESIGN §0 |
| SF-06 | Metro partition isolating one replica; isolating the sequencer | network | Simplex view change, `FAILOVER_SILENCE_MS` |
| SF-07 | WAN delay spikes and partition during a handoff | network | 08 handoff, `INV-FENCE`, auction start |
| SF-08 | Sequencer crash at a random event, including between the order frame and the fill or the ack | process | B5 property in simulation; standby promotion keeps the client split (§7.22) |
| SF-09 | Replica crash and restart from snapshot | process | snapshot + log catch-up, `BLD_CATCHUP_RATE` |
| SF-10 | Data-tier node crash; payload missing at a replica | process | fetch path; vote waits for every payload |
| SF-11 | A lane core stalls for 1 µs – 10 ms | core | cut age, BBO waiting, spare-lane takeover (03) |
| SF-12 | BBO core stalls | core | lane back-pressure, ring-full handling |
| SF-13 | Visibility delay of stores (stale cut, stale snapshot) up to `BLD_SIM_VIS_MAX_NS` | memory | lemma slow path, rescans |
| SF-14 | Ring full on lane → BBO, BBO → lane, BBO → TX | memory | back-pressure is a defined behaviour, never a drop |
| SF-15 | RX queue overflow at a NIC | NIC | drop counter; client resend |
| SF-16 | PHC offset between the sequencer's NICs; PHC step | clock | timestamp merge, fairness metrics; no effect on safety |
| SF-17 | Replica clock offset and drift | clock | timers on order-stream time only (01 §11.3) |
| SF-18 | Disk write lost after fsync returns; torn write; full disk | storage | journal recovery, block storage (07) |
| SF-19 | Byzantine sequencer: two signed streams for one range | byzantine | equivocation proof, slashing (09) |
| SF-20 | Byzantine sequencer: frame that references a payload no client sent | byzantine | vote refusal |
| SF-21 | Byzantine sequencer: order frame with a non-monotone cut | byzantine | replay rejects it; no panic |
| SF-22 | Byzantine replica: votes for a block it does not hold | byzantine | quorum still requires q honest-or-correct votes |
| SF-23 | Client with good `K_seq` MAC and bad `K_com` MAC (chain) | byzantine | exclusion, revert of its fills, bond payout (09) |
| SF-24 | Engine divergence injected into one client (Rust or Vx) | engine | divergence alarm, halt not fork (§10.4.5) |
| SF-25 | Epoch boundary during failover; failover during auction | combined | 07 × 08 interactions |
| SF-26 | Allocation forced on a pinned core | engine | counting allocator reports it (§3.5) |
| SF-27 | Overload: a burst or a slow core pushes packets and forwarded ops past their deadline | core | deadline admission, `BUSY`, `Shed` steps (01 §14.1) |
| SF-28 | One of the two cut cores stalls; the two half-cuts publish at different rates | core | half-cut monotonicity, the clamped step-cut rule (01 §14.3, §14.11) |
| SF-29 | Standby `vyrn-seq` lost, or failover during a failover | process | the split check, a second promotion (01 §14.4) |
| SF-30 | Pool token contention: one pooled account on 1–8 sessions sends to every pool queue at once; a token holder stalls 1 µs – 1 ms | pool | `PoolTok` CAS and release, one writer per account record, `BUSY` of the waiting packets only (10 §1.2) |
| SF-31 | Steal order: empty and full queues mixed, steals racing for one sibling queue, a stolen packet that is not its session's next `pkt_seq` | pool | the steal lock, the next-`pkt_seq` check, no packet applied twice or out of session order |
| SF-32 | Sibling-segment cancels under concurrency: a cancel on core X of an order in core Y's `Segment16` while the BBO core sweeps that segment and Y fills or cancels it | pool | `fetch_and` against the sweep; the result equals the oracle per message (§6.3 check 5) |
| SF-33 | Pool replay: the live run with seeded steals and token takes, replayed with different scheduler seeds; a corrupted, missing or reordered `AcctTake` record | pool | the pooled-lane determinism replay (below); replay rejects a bad `AcctTake` log |
| SF-34 | Paced SDK client on a dedicated lane under every other fault class that does not stall its own lane | client | a paced client never gets lane-stage `BUSY` (§6.10) |
| SF-35 | A sweep longer than `STEP_FILL_CAP` (64) fills | core | the sweep continues in further steps, each with its own deadline (01 §14.15 item 6) |

**Invariants checked continuously.**

| Check | When | How |
|---|---|---|
| `INV-WRITER` | every store, `writer-audit` builds | each shared field records the core that wrote it; a second writer core fails the run. A pooled account's records may change writer only across a `PoolTok` release and take; a write without the token fails the run |
| `INV-DET` | every block | every replica's output hash and state bytes equal the sequencer's |
| `INV-FRAME-FIRST` | every response, acks and rejects included (01 §14.5) | the sim NIC records TX queue order; a response whose op records (every op in its step's cut) and step record are not on both replication queues fails |
| `INV-UNCROSSED` | every snapshot | bid < ask, or one side empty |
| `INV-LANE-NOMATCH` | build time | lanes have no access to the filled-quantity array (type-level) and the audit build confirms no lane writes it |
| `INV-CUT-MONO` | every half-cut and every step cut | each half-cut line (cut core A on core 1: lanes 0–24, B on core 6: lanes 25–48) is pointwise ≥ its previous value; each step's cut is ≥ the previous step's (01 §14.3) |
| Shed logged | every `BUSY` | every shed decision is in the order stream (`PacketRecord.flags.SHED` or a `Shed` step); replay of the log gives the same `BUSY` set, byte for byte, on every replica and the oracle |
| Paced never lane-BUSY | every response to a paced session | a session that the SDK paced by `LANE_PACE` on a dedicated lane never gets a lane-stage `BUSY`; a BBO-core `Shed` of its cross or improve is counted against 01 §14.17 item 2 |
| `AcctTake` order | every pooled packet | every token take is logged as `AcctTake { account, ver, lane }` (01 §14.17 item 4); per account, `ver` is gapless from 1 each epoch; the logged `lane` is the core that ran the work; no pooled account record is written by a core without a matching `AcctTake` |
| Pool determinism | every block with pool lanes | replay that follows the `AcctTake` records, under any scheduler seed, gives the same state and responses as the live run (SF-33) |
| Step fill cap | every step | no step writes more than `STEP_FILL_CAP` (64) fill records, and no maker's `resp_seq` credit (16) is exceeded |
| Two passes = index order | every message | §6.3 check 3, against the oracle, per message |
| Client split | every failover and every config load | voting replicas stay 2 Rust + 2 Vx (BASE) or 3 Rust + 2 Vx (CHAIN); `vyrn-seq` holds no vote |
| `INV-FENCE` | every accepted record | no epoch-e record with step > S after cert(e, S) |
| `INV-NOALLOC` | end of run | counting allocator reports zero on sealed cores |
| `INV-QUORUM` | every finalisation | the certificate has q valid signatures from distinct replicas |
| `INV-ACK-AFTER-CUT` | every `Ack`/`CancelAck` | a published cut (both halves) already covered the op, and the frame gate was open |
| Oracle equality | every message | §6.3 |
| No lost fill or ack | end of run, and at each failover | every `Fill` any client received, and every order any client got an `Ack` for, is in the final log, unless a revert case of 07 §9.6 was injected, in which case the reverted fills are exactly those that case covers (01 §14.19 B); a CHAIN bust leaves the fill in the log |
| Safety of finality | every finalisation | no two finalised blocks at one `Height` |
| Conservation | every block | per asset: Σ balances + Σ reservations + fees = deposits − withdrawals |
| Session sanity | every response | `resp_seq` gapless per session; each handle ends in at most one terminal record |
| Liveness | after faults heal | within `BLD_SIM_HEAL_MS` of virtual time, a block finalises and every live session can trade |

**Pool tests.** Four scenarios target the pool (01 §14.15), each on 10⁴ seeds per night:

1. **Token contention** (SF-30). The pass is one writer per account record at every store, no
   lost or doubled reservation, and `BUSY` only on packets that waited past their deadline.
2. **Steal order** (SF-31). Every pooled session's packets are applied in `pkt_seq` order and
   once, whatever core stole them. A seeded fault inverts steal priority, and the run must fail.
3. **Sibling-segment cancels** (SF-32), checked per message against `vyrn-vx-oracle` (§6.3 check 5).
4. **Pooled-lane determinism replay** (SF-33). The live log of a pool run is replayed by the Rust
   engine, the Vx client and the oracle, each under three scheduler seeds. State roots and every
   response must be equal. The replay reads token order from the `AcctTake` records and never
   re-runs the race. A run with one `AcctTake` dropped or swapped must be rejected, never forked.

**Replaying and shrinking.** `vyrn-sim run --seed <hex> [--scenario <name>]` replays a run exactly.
A failure prints the seed, the first broken check, the event index and the last 10,000 events.
`vyrn-sim shrink --seed <hex>` removes injected faults one at a time (delta debugging over the
fault schedule) while the failure persists, and prints the smallest schedule. Every seed that
ever failed goes into `tests/seeds.toml` and runs on every PR.

**Budgets.** Per PR: 500 seeds × 10 virtual seconds (`BLD_SIM_SEEDS_PR`). Nightly swarm: 10⁶
seeds across the lab's machines. Release: zero failing seeds in the last three nightly swarms.

### 6.5 Linearisability of fills

The §6.3 linearisation is a witness. The linearisability check confirms that the witness agrees
with what clients saw in real time:

1. Every response a client received equals the oracle's output for the same op at its
   linearisation point (§6.3 already checks this).
2. **Real-time order.** If a client received the response to op A before it sent op B, then A is
   linearised before B.
3. **No response before its point.** An op's first response left the sequencer after the cut
   that linearises it was published (`INV-ACK-AFTER-CUT` for acks; the step for fills), and after
   its order records left on both paths (`INV-FRAME-FIRST`, 01 §14.5).

Because the log gives the witness, the check is linear in the history length. It does not search
for a linearisation, as a general checker must. `vyrn-sim` runs it on every seed with exact
virtual times. On hardware it runs on B9 and B3 probe-session captures (§7.2), with capture
timestamps as real time, nightly.

### 6.6 Fuzzing

`cargo-fuzz` (libFuzzer) targets, in `fuzz/`:

| Target | Input | Must hold |
|---|---|---|
| `fz_req_packet` | arbitrary bytes as a request packet | no panic; every reject is a 01 §6.5 code; a packet that parses re-encodes to the same bytes |
| `fz_resp_roundtrip` | arbitrary response records | encode-decode identity |
| `fz_order_stream` | arbitrary bytes as an LEB128 order-stream frame (a byzantine sequencer) | no panic; malformed frames rejected with a reason |
| `fz_engine_ops` | structured op sequences (`arbitrary`) on a 4-lane world | engine equals oracle per message (§6.3); no panic; no allocation after seal |
| `fz_replay_cuts` | valid packets with adversarial `StepRecord`s (non-monotone, out-of-range cuts) | the replay engine rejects the block; Rust and Vx clients reject identically |
| `fz_consensus_msg` | arbitrary bytes as our consensus wrappers | no panic (Commonware's own fuzz crates cover its internals) |
| `fz_handoff` | arbitrary `HandoffRecord` plus certificate | only a valid certificate verifies |
| `fz_session_open` | arbitrary session-open transactions (chain) | no panic; only valid signatures accepted, identically for Ed25519 and secp256k1 paths |
| `fz_hybrid_sig` | arbitrary (scheme, key, message, signature) | no panic; `libcrux-ml-dsa` and RustCrypto `ml-dsa` give the same verdict for every input; a hybrid signature with one invalid part is rejected (§2.5a) |
| `fz_config` | arbitrary TOML | `vyrn-admin config check` never panics |

Per PR: 60 s per target on the corpus. Nightly: 8 h per target on Linux lab machines, with
coverage reports. Minimised corpora are committed. Every crash becomes a unit test before its fix
merges.

### 6.7 Chaos tests on hardware

The simulator models what we thought of. Chaos tests on the staging cluster find the rest.

- **Cluster:** seven `REF` boxes in the lab (the active `vyrn-seq`, the warm standby `vyrn-seq`, and
  five replicas, of which BASE runs four), two data-tier boxes, two leaf switches per path pair,
  and two follower homes on smaller boxes. WAN links between homes use kernel netem delay at the
  DESIGN §6 values (110, 35, 80 ms one-way), because inter-home traffic runs over kernel
  networking.
- **Faults:** `SIGKILL`; power off through the BMC; `sysrq-c` kernel panic; link down on one
  replication path, then both; switch reboot; data-tier box loss; disk fill; PTP grandmaster
  loss and a 1 µs PTP step; WAN partition during a handoff; kill the new sequencer during the
  auction; kill the old sequencer after step S and before the handoff certificate.
- **Schedule:** a seed picks the faults and their times. The seed fixes the schedule, not the
  outcome, because hardware timing is not deterministic.
- **Checks:** the log, the captures and the metrics are collected after each run. `vyrn-sim check`
  runs the same invariant checkers offline over them (the checkers take a log and captures as
  input, not only a live simulation). B5, B13 and B19 are chaos tests with fixed schedules.
- **Cadence:** nightly, 8 h, with load at 60% of B3's rate.

### 6.8 Cross-build determinism

B4 (§7.7) is the test. It replays one log through several builds and requires bit-identical
output. It runs on every release candidate and nightly. A smaller version (the golden logs, three
builds) runs on every PR that touches an engine crate, `vyrn-crypto`, the toolchain file or an
E-tier dependency.

### 6.9 Test matrix per platform

DEV/macOS must run the full functional suite. Linux runs everything, and the performance tests run
only on Linux lab hardware.

| Test | DEV macOS aarch64 | CI Linux x86-64 | CI Linux aarch64 | `REF` lab | `CONSUMER` lab | `AWS` |
|---|---|---|---|---|---|---|
| Unit, golden vectors | ✔ | ✔ | ✔ | — | — | — |
| loom, Miri | ✔ | ✔ | — | — | — | — |
| Property tests vs oracle | ✔ | ✔ | ✔ | — | — | — |
| Differential per message | ✔ | ✔ | ✔ | ✔ (B3 logs) | — | — |
| `vyrn-sim` per-PR seeds | ✔ | ✔ | ✔ | — | — | — |
| `vyrn-sim` swarm | ✔ (lab Macs) | ✔ | ✔ | — | — | — |
| Sim cross-platform trace hash | ✔ | ✔ | ✔ | — | — | — |
| Fuzzing (60 s / 8 h) | 60 s | both | — | — | — | — |
| TSan (Rust nightly + Vx) | ✔ | ✔ | — | — | — | — |
| C shim: DPDK `net_ring`, ASan/UBSan | n/a | ✔ | ✔ | — | — | — |
| C shim: ef_vi on hardware | n/a | — | — | ✔ | ✔ | — |
| Asm gate | n/a (no shim) | ✔ | ✔ | — | — | — |
| B4 determinism | ✔ (one build in the set) | ✔ | ✔ | ✔ | — | — |
| Benchmarks B1–B3, B5–B15, B17–B19, B-GPU | — | — | — | ✔ | — | — |
| B20 | — | — | — | — | ✔ | — |
| B16 | — | — | — | — | — | ✔ |
| Registered benchmarks (§7.25) | — | — | — | per owner | per owner | per owner |
| Chaos tests | — | — | — | staging | — | — |

macOS runs the full functional suite with the `sim` and `kernel_udp` NIC backends. It cannot pin
threads (vx-lang/Vx#3370 returns `Unsupported` there, and Rust's affinity calls do nothing on macOS), so
nothing timed is ever reported from it. The pacing-SDK test (§6.10) runs in `vyrn-sim` on every host
and in B3 on `REF`.

### 6.10 The pacing-SDK test

A paced client on a dedicated lane never waits in the lane stage (01 §14.15 item 1, as refined
by §14.17 item 2). The SDK computes `LANE_PACE` from the published `predicted_path_ns` table
(which includes the bounded settlement drain in front of a packet, 10 §4.2) and leaves at least
`predicted_path_ns` of its previous packet before it sends the next one on its lane. It also puts
a packet's cancels first, where the ack slack is largest (01 §14.17 item 1). The test: **a paced
client never gets a lane-stage `BUSY`**, and its total `BUSY` (BBO-core `Shed`s of its crosses
and improves) stays within the dedicated bound of §7.6.

- **Unit.** For any packet sequence, the pacer's gap is ≥ `predicted_path_ns` of the previous
  packet, and the pacer refuses a table whose version differs from the box's. For any message
  list, the SDK's packet has every `Cancel`, `Reduce` and `CancelAll` before every other message,
  and otherwise keeps the client's order (§6.3 check 3 then shows the results equal the oracle).
- **`vyrn-sim` (SF-34).** Every seed with a dedicated lane runs one SDK client per dedicated lane at
  its highest paced rate, every message type, packets of 1–10 messages with cancels mixed in at
  random indices before the SDK reorders them, while the other lanes and the pool run at full
  load and the BBO core at `BBO_MAX_LOAD`. Pass: zero lane-stage `BUSY` to the SDK's sessions over
  all seeds, and every cancel ack within the cost model's 1 µs. A control client that sends 10%
  faster than `LANE_PACE` must get lane-stage `BUSY` in some seed, or the test does not reach the
  bound and fails.
- **`REF` (B3).** The generators drive every dedicated lane through the SDK. Pass: zero lane-stage
  `BUSY` on every dedicated lane over the whole run, and the total within §7.6's bound.

## 7. Benchmarks

### 7.1 Rules for every benchmark

1. **Pass or fail.** Each benchmark has a threshold tied to a 01 constant or to a `BLD_` budget.
   All criteria must pass. A benchmark without a threshold is a measurement, and this chapter has
   none of those, except the placeholder B-GPU (§7.24).
2. **Hard requirements gate on the maximum.** REQ-LAT-1 (`LAT_MAX_NS`) and REQ-FIN-1 (10 ms)
   pass only if the maximum over the whole run, warm-up excluded, is within the bound, for every
   message type at every message index 0–9. A percentile is never a pass criterion for them. A
   component benchmark (B2, B6–B8) may gate its own budget at a stated percentile, because it
   diagnoses a stage; it never stands in for the end-to-end maximum.
3. **Production build, production config.** The release artifact, the deploy profile of the
   target, observability on at production sampling rates (§8). No benchmark-only build exists.
4. **Open loop.** Generators send on a fixed schedule and never wait for responses. Latency is
   measured on the wire, so coordinated omission cannot hide a stall.
5. **Warm-up and length.** The first 60 s are discarded. A run lasts at least 10 minutes unless
   the entry says otherwise. Percentiles come from complete HDR histograms with 1 ns resolution
   up to 10 µs. The maximum is kept exactly, with the request that produced it, and a sample above
   10 µs is kept in an overflow list, never clipped.
6. **Every packet, not only probes.** A maximum over probes alone covers 0.5% of sessions. So
   every latency benchmark also takes `plt_w2w_ns` (NIC TX stamp − RX stamp, 06) for **every**
   response on the SUT, plus the largest stamp-to-wire offset that the probes show (capture time
   − `plt_w2w_ns` on the same response). The pass uses the larger of the two maxima.
7. **Workloads are 02's.** 02 owns the workload model and its IDs. This chapter names
   `WL-REF` (the reference mix: ~50% joins, ~47% cancels and reduces, ~2% improves, ~1% crosses,
   ≤ 10 messages per packet), `WL-LANE` (WL-REF restricted to one lane's accounts), `WL-XSWEEP`
   (WL-REF with the cross share swept from 0.1% to 3%), `WL-AUCTION` (orders that arrive during an
   auction phase) and `WL-AWS` (WL-REF batched for ENA). If 02 names them differently, 02 wins.
8. **A signed report.** Each run writes a report to `bench/reports/`: commit, artifact hashes,
   config, hardware inventory (BIOS, microcode, NIC firmware, kernel, cmdline), raw histograms,
   verdict. The runner signs it with its Ed25519 key. A number in this specification becomes
   "measured" only by citing such a report.

### 7.2 Rigs

**The optical capture rig** measures wire-to-wire time without touching the system under test
(SUT):

```
  generator boxes                        SUT (vyrn-seq on REF)
  (vyrn-bench gen, ef_vi TX)
   G1..G4 ──── fiber ────► [ passive tap ]────────────► port p RX
                                │ 10% copy
                                ▼
                        capture NIC port A ─┐  one NIC, one PHC:
                                            │  no clock error between A and B
   G1..G4 ◄─── fiber ───── [ passive tap ]◄─┼──────────── port p TX
                                │ 10% copy  │
                                ▼           │
                        capture NIC port B ─┘ ──► capture host: match request ↔ response
                                                   by (session, pkt_seq / echo_pkt)
```

- **Capture NIC:** a COTS 100GbE NIC with hardware timestamps on every received frame
  (06 lists qualifying parts). Both taps go into ports of the same NIC, so both timestamps come
  from one PHC.
- **Calibration:** replace the SUT with a passive coupler of known fiber length. The measured time
  minus the fiber delay (4.9 ns/m, vendor) is the rig offset, which every run subtracts. The rig
  qualifies if the zero-device run has p99 − p1 ≤ `BLD_CAPTURE_ERR_NS` (5 ns).
- **Probe sessions:** a capture host cannot keep up with ~190 Gbps in each direction. So 0.5% of
  sessions (`BLD_PROBE_SHARE`) are probes, spread over all lanes, with their own source IP
  addresses. The capture NIC's hardware filters keep only probe traffic. The other 99.5% of
  traffic is load. Each benchmark that uses the rig collects ≥ 10⁶ probe messages in every cell
  of (message type and outcome) × (message index 0–9) × (packet count 1–10).
- **First bit:** responses are matched to requests by session and `echo_pkt`. Unsolicited maker
  fills are matched through the step that produced them.

**Generators:** four `REF`-class boxes running `vyrn-bench gen` with ef_vi TX, one per SUT port,
each able to send 25M packets/s of 01 §6.1 packets with valid MACs.

**Perf runners:** dedicated lab machines of each target class (§9.3), never shared, never
virtualised, tuned per 06.

### 7.3 Summary

| # | Name | Rig | Pass (all must hold) |
|---|---|---|---|
| B1 | Bare-NIC echo floor | capture | RX + TX p99.99 ≤ `NIC_FLOOR_NS` (560 ns) |
| B2 | One lane, real mix | memory-fed | mean ≤ `LANE_NS_PER_MSG` per message |
| B3 | One book at 1B msgs/s | capture + full box | **max** ≤ `LAT_MAX_NS` for every type at every index 0–9; `BUSY` per class: dedicated paced lane-stage = 0 and total ≤ 1e-5 at full load, ≤ 1e-8 at ≤ 20%; pooled ≈ 1e-3 at full load, ≤ 1e-6 at ≤ 20%; curves published; BBO busy ≤ `BBO_MAX_LOAD` |
| B4 | Cross-build determinism | replay | bit-identical outputs and state, shed decisions included |
| B5 | Kill the sequencer | capture + cluster | every sent fill and every acked order is in the final log |
| B6 | Lane microbench per op | memory-fed | each op ≤ its `BLD_LANE_OP_NS` budget |
| B7 | Cut protocol | in-box | each half-cut's age max ≤ `CUT_REFRESH_NS` |
| B8 | BBO cross / improve | memory-fed | ≤ `BBO_CROSS_NS` (15 ns, 01 §14.15) per cross, ≤ `BBO_IMPROVE_NS` per improve, ≤ `STEP_FILL_CAP` fills per step |
| B9 | End to end, every type | capture + full box | **max** ≤ `LAT_MAX_NS` for every type at every index, every load; `BUSY` per class as B3 |
| B10 | Replication bandwidth | cluster | ≤ `BLD_ORDER_GBPS_MAX` per path, zero loss |
| B11 | Simplex finality | cluster | **max** ≤ `FINALITY_MAX_MS` (10 ms) for every accepted order |
| B12 | Replay throughput, Rust and Vx | replica box | ≥ 1.0B msgs/s sustained, ≥ `BLD_CATCHUP_RATE` |
| B13 | Handoff window | 3 homes | ≤ WAN one-way + `FINALITY_MAX_MS` + `BLD_HANDOFF_SLACK_MS` |
| B14 | Auction uncross | full box | ≤ `BLD_UNCROSS_US_MAX` |
| B15 | Market-data latency | capture + replica | p99 ≤ `BLD_MD_LAG_P99_US` |
| B16 | AWS packet-rate limit | AWS | in-instance **max** ≤ `LAT_MAX_NS` at 80% of the drop-free rate |
| B17 | PHC sync across NICs | splitter | offset p99 ≤ `BLD_PHC_SKEW_P99_NS` |
| B18 | Jitter probe | in-box | no gap > `BLD_JITTER_MAX_NS` |
| B19 | Failover outage | capture + cluster | p99 ≤ `FAILOVER_TARGET_MS`; client split kept after every promotion |
| B20 | Consumer box | capture + `CONSUMER` | B3 and B9 criteria at `BLD_CONSUMER_RATE` |
| B-GPU | GPU-initiated NIC echo (placeholder) | capture | none; it may reopen `C-NOCHIP` only if RX + TX ≤ `NIC_FLOOR_NS` |

### 7.4 B1: bare-NIC echo floor

- **Procedure.** `vyrn-bench echo` on one isolated core: ef_vi RX, swap addresses, CTPIO TX, no
  parsing. Run at 1M packets/s and at 25M packets/s per port, with one-message (48-byte payload)
  and ten-message (192-byte payload) packets.
- **Hardware.** `REF` with each candidate NIC from 06 (X2541 first; ConnectX-6 Dx and -7 with
  their fastest COTS path).
- **Metric.** Wire-in to wire-out per packet (RX + TX), from the capture rig; the RX and TX
  shares from the NIC's own stamps; the maximum.
- **Pass.** RX + TX p99.99 ≤ `NIC_FLOOR_NS` (560 ns) at every rate and size. The RX and TX shares
  are reported against the budgets of 320 and 240 ns (01 §5), and the maximum is reported,
  because B3's maximum must absorb the NIC's tail. A NIC that fails is out of 06's list
  (DESIGN §9).

### 7.5 B2: one lane on the real mix

- **Procedure.** One lane core on CCD 1, its BBO-ring consumer on CCD 0 (so the hop is real). The
  lane reads RX descriptors that `vyrn-nic::sim` preloaded into a huge-page ring. It runs saturated
  for 10 minutes. The lane's `poll` count and the TSC give ns per message.
- **Hardware.** `REF`.
- **Workload.** `WL-LANE`, with the account count and resting-order depth of one lane of WL-REF.
- **Metric.** Mean ns per message; pass-1 and pass-2 service time per 10-message packet.
- **Pass.** Mean ≤ `LANE_NS_PER_MSG` (30 ns); for a 10-message packet, pass 1 p99.99 ≤ 95 ns
  (`LANE_PASS1_NS`: 45 + 10 × 5) and pass 2 p99.99 ≤ 90 ns (`LANE_APPLY_NS`: 10 × 9), the lane
  terms of 01 §14.2's index-9 budget. The maximum is reported; B3 gates it end to end.
  Run twice more, with `overflow-checks` off and frame pointers off, to report their costs
  (§3.4, §4.3).

### 7.6 B3: one book at 1B msgs/s

- **Procedure.** Four generators drive `vyrn-seq` on its four client ports for 10 minutes; the two
  replication ports run to two leaf switches (01 §14.7). The capture rig measures probe sessions,
  and `plt_w2w_ns` covers every response (§7.1 rule 6). The BBO core's busy fraction comes from
  its idle-poll counter (§8.2).
- **Hardware.** `REF` with 6 × X2541 and the 01 §10 core map: cut cores 1 and 6, BBO core 2,
  TX-A, TX-B and TX-C on cores 3, 5 and 0, stream-A and stream-B on cores 4 and 7, hasher on
  core 50, OS and control on core 51 (01 §14.17 item 3), 42 dedicated lanes on cores 8–49, the
  pool on cores 56–62 (CCD 7).
- **Workload.** `WL-REF` at 1.0 × 10⁹ inbound messages/s, 1% crosses, packets of 1–10 messages,
  with accounts placed by `lane_map` (10 §1.3): the top firms on dedicated lanes, every dedicated
  client paced through the SDK (§6.10), the rest pooled and unpaced. Probes put every message
  type and outcome at every index 0–9 in both classes, including 10-message packets whose index-9
  message depends on earlier ones (01 §14.2).
- **Metric.** Wire-to-wire latency to the first record of every message, per (type, outcome,
  index, class); its **maximum** over the whole run; the `BUSY` share of packets per class, and
  for dedicated lanes split into lane-stage and BBO-stage (`Shed`); BBO busy fraction per 1 s
  window; fills per step; RX drops. **The `BUSY` curves:** the run repeats at 10%, 20%, 40%, 60%,
  80% and 100% of 10⁹ msgs/s (`BLD_BUSY_CURVE_LOADS`), and the signed report publishes each
  class's `BUSY` share at each point, the pooled one next to the M/M/c (c = 7) model.
- **Pass, all of:**
  - **max ≤ `LAT_MAX_NS` (1,000 ns) for every message type and outcome at every index 0–9**,
    over the whole run, for every accepted packet (REQ-LAT-1, deadline admission per 01 §14.1).
    One response above 1,000 ns fails the run. There is no percentile criterion for REQ-LAT-1.
  - every `BUSY` response itself ≤ `LAT_MAX_NS`, and `BUSY` per class (02 REQ-LAT-5, 01 §14.17
    item 2). Dedicated paced lanes: lane-stage `BUSY` **= 0** over the whole run, and total
    **≤ 1e-5** at full load (crosses and improves only) and **≤ 1e-8** at ≤ 20% load. Pooled
    lanes: **≈ 1e-3** (at most 1e-3) at full load and **≤ 1e-6** at ≤ 20% load. A packet dropped
    past its BUSY deadline counts as `BUSY` (01 §14.16);
  - BBO busy ≤ `BBO_MAX_LOAD` (0.60) in every 1 s window; no step above `STEP_FILL_CAP` (64)
    fills; zero RX drops;
  - each TX core's busy fraction ≈ 0.22 and ≤ 0.25 (01 §14.17 item 3);
  - the B3 log replays on build A with the same shed decisions, `AcctTake` order and outputs (B4).

  The p50, p99 and p99.9 are reported against 01's index-9 budgets (880 ns cross with the 15 ns
  step, §14.2; ack 955 ns typical and 965 ns worst against the 980 ns shed threshold, §14.17
  item 1), per class and with the SDK's cancels-first order. The `WL-XSWEEP` variant records where the BBO core crosses
  0.60, which checks `CROSS_CAP`; it must meet the same maximum up to `CROSS_CAP`.

### 7.7 B4: cross-build determinism

- **Procedure.** Record the order stream and data of a 60 s B3 run (pre-merge: the golden logs).
  Replay it through every build in the set and compare per-block output hashes and the state root
  at every checkpoint.
- **Build set.**

  | Build | Compiler | Flags | Target |
  |---|---|---|---|
  | A | pinned rustc | release profile | Linux x86-64 (`REF`) |
  | B | pinned rustc | `opt-level=1`, `codegen-units=16`, debug assertions on, no LTO | Linux x86-64 |
  | C | previous pinned rustc (one release back) | release profile | Linux x86-64 |
  | D | pinned rustc | release profile | Linux aarch64 (Graviton) |
  | E | pinned rustc | release profile | macOS aarch64 (DEV) |
  | F | vxc v0.0.4 | `vx/build.sh` | Linux x86-64: `vyrn-vx-client` |
  | G | vxc v0.0.4 | `vx/build.sh` | Linux aarch64: `vyrn-vx-client` |

- **Metric.** The first (height, step, lane) at which any build differs.
- **Pass.** No difference anywhere, for every pair, including the `BUSY` set: every build reads
  the shed decisions from the log and none recomputes them. The sequencer's live output is also
  compared to build A's replay.

### 7.8 B5: kill the sequencer mid-run

- **Procedure.** Run B3's load on a BASE cluster per 01 §14.4: F1 holds `vyrn-seq` and R1, F2 holds
  the warm standby `vyrn-seq` and R2, F3 and F4 hold R3 and R4. The capture host keeps a 2 s ring
  buffer of **all** response packets (not only probes) from the sequencer's TX taps, on four
  capture NICs. At a random time, kill the sequencer by one of: `SIGKILL`, BMC power-off, link
  down on all ports, `sysrq-c`. After the standby is promoted, finalise, and replay the final log.
- **Metric.** The fills, and the orders with an `Ack`, in the 2 s capture that are missing from
  the replayed final log.
- **Pass.** None missing, over ≥ 100 kills spread across the four kill methods (01 §14.5: an
  acked order is never lost).

### 7.9 B6: lane microbenchmark per op

- **Procedure.** As B2, but each run uses one op type only, against a lane state taken from
  WL-REF. `perf_event_open` counters (cycles, instructions, L1/L2/L3 misses) are read before and
  after, on the control core, never inside the loop.
- **Pass.** Each op within its budget:

  | Op | `BLD_LANE_OP_NS` (budget) |
  |---|---|
  | `New` (join, rests in lane) | 30 |
  | `New` (improve or cross, pushed to BBO ring) | 30 |
  | `Cancel`, `Reduce` | 22 |
  | `Replace` | 40 |
  | `Heartbeat`, `CancelAll` (per order canceled) | 8, 10 |
  | MAC check per 10-message packet (`K_seq`) | 20 |
  | Fill-event settlement (per fill) | 15 |
  | Deadline test and `BUSY` answer of a whole packet (01 §14.1) | 20 |
  | Pass 1 per message; per packet (01 §14.2) | 5; 45 |
  | Pass 2 apply per message (01 §14.2) | 9 |
  | Pool core: account-token CAS and release inside CCD 7 (01 §14.15) | 20 |
  | Pool core: steal one packet from a sibling queue (steal lock, `pkt_seq` check) | 25 |

  The WL-REF-weighted sum must equal B2's mean within 10%, or the microbenchmark does not model
  the lane and its result is void.

### 7.10 B7: cut-protocol latency

- **Procedure.** On the full box with B3's load, each lane writes the TSC of each counter store
  into a side array (bench config only, outside the measured lines). Cut core A (core 1, lanes
  0–24) and cut core B (core 6, lanes 25–48) each write the TSC of each half-cut publication.
  The control core (core 51) computes, offline, the age of each lane counter in the half-cut that first
  includes it. The TSC is invariant and synchronised across cores on `REF` (06).
- **Metric.** Age of the newest published half-cut, per cut core; join-ack wait (lane op to the
  logged cut that covers it, via `LaneCut`); half-cut monotonicity.
- **Pass.** Each half-cut's age max ≤ `CUT_REFRESH_NS` (100 ns, a maximum in 01 §5); join-ack
  wait max ≤ `BLD_ACK_WAIT_NS` (170 ns with the ~20 ns `LaneCut` poll, 01 §14.17 item 1); every half-cut pointwise ≥ its previous one.
  A variant runs with `BLD_SHARED_ALIGN` = 64 and records the difference (§3.6).

### 7.11 B8: BBO cross and improve microbenchmark

- **Procedure.** The BBO core on CCD 0 consumes prebuilt lane rings whose lanes are on CCDs 1–7
  (dedicated lanes on cores 8–49, pool cores 56–62), with book states built from WL-REF in
  `Segment16` FIFOs. Variants: best-level orders spread over 1, 8 or 49 lanes; sweeps of 1, 4 or
  16 levels, and one of 200 maker orders; a rescan over 1 and 32 ticks.
- **Metric.** Amortised ns per step at saturation (throughput); p99 time per step (latency);
  fill records per step.
- **Pass.** Single-level cross ≤ `BBO_CROSS_NS` (15 ns, 01 §14.15 item 2) amortised; improve and
  depletion ≤ `BBO_IMPROVE_NS` (8 ns) amortised; step latency p99 ≤ `BLD_STEP_P99_NS` (100 ns,
  DESIGN §4). The 200-maker sweep splits into steps of ≤ `STEP_FILL_CAP` = 64 fill records, each
  admitted against its own deadline. Multi-level and rescan results are recorded per level and
  per tick, and feed `CROSS_CAP`.

### 7.12 B9: end to end, every message type

- **Procedure.** As B3, at 10%, 60% and 100% of 10⁹ msgs/s, with probes for every message type and
  outcome: join → `Ack`, improve → `Ack`, cross → `Fill`, `Cancel` → `CancelAck`, `Reduce`,
  `Replace`, and each reject reachable by a probe, each at every index 0–9 of packets of 1–10
  messages.
- **Pass.** At every load: max ≤ `LAT_MAX_NS` for every type and outcome at every index 0–9,
  over the whole run (REQ-LAT-1, REQ-LAT-2); `BUSY` per class as B3: lane-stage 0 on dedicated
  paced lanes with total ≤ 1e-8 at 10% and ≤ 1e-5 at 100%; on pooled lanes ≤ 1e-6 at 10%,
  ≤ 1e-3 at 100%; both on or below B3's curves at 60%. The join and cancel ack distribution is
  also reported against 01 §14.17 item 1's 965 ns worst-case index-9 budget.

### 7.13 B10: replication bandwidth

- **Procedure.** B3's load on a BASE cluster. Count bytes and frames on both replication paths at
  the two leaf switches, and payload arrivals at each replica.
- **Metric.** Order-stream Gbps per path; frame loss; busy fraction of stream-A (core 4) and
  stream-B (core 7) and of TX-A, TX-B and TX-C (cores 3, 5 and 0); the gap between the records a
  response depends on and the response on the wire (from the capture), for fills and acks;
  payload arrival time at replicas.
- **Pass.** ≤ `BLD_ORDER_GBPS_MAX` (25 Gbps) per path; zero frame loss on each path; each stream
  and TX core busy ≤ 0.25 (01 §14.15 item 3; TX ≈ 0.22 with three cores, §14.17 item 3;
  replacing 07's 0.70 for one core);
  records-before-response holds for every captured response, acks included (`INV-FRAME-FIRST`,
  01 §14.5); payload arrival p99 ≤ `BLD_DATA_ARRIVAL_P99_US` (200 µs) after the sequencer's RX
  timestamp.

### 7.14 B11: Simplex finality

- **Procedure.** BASE (4 voting replicas, `vyrn-seq` and its standby beside them) and CHAIN
  (5 validators) in four or five lab racks with fiber spools that give 0.5 ms one-way between
  racks (the metro of DESIGN §5), at B3's load, for 1 hour. Then again with one replica powered
  off. Both modes run with the finality gate of 01 §14.9 (`FIN_GATE_BLOCKS` = 9).
- **Metric.** Time from a message's RX timestamp to the formation of a certificate over its
  block, as 02 defines the measurement point, for every block; the maximum.
- **Pass.** max ≤ `FINALITY_MAX_MS` (10 ms) for every accepted order, healthy and with one
  replica down (01 §14.0). In either mode, a lag past the gate halts the book and no fill is
  issued that could not be final within 10 ms. Forced packets are final ≤ `CHN_FORCED_FINAL_MS` = 11.5 ms after
  they are sent (01 §14.9), their own bound, not a relaxation of `FINALITY_MAX_MS`. The p50 is reported against DESIGN's ~3 ms.

### 7.15 B12: replay throughput (Rust and Vx)

- **Procedure.** A `REF` replica box replays a recorded 10-minute WL-REF log, (a) from huge-page
  memory, at full speed, (b) from the network as it arrives in a live B3 run. Once with
  `engine.client = "rust"`, once with `"vx"`.
- **Metric.** Messages per second; per-block replay lag (block's last payload arrived → its
  outputs complete); output hash equality with the sequencer.
- **Pass, for each client.** (a) ≥ `BLD_CATCHUP_RATE` (1.2 × 10⁹ msgs/s); (b) keeps up with
  1.0 × 10⁹ msgs/s for 10 minutes with replay lag p99 ≤ `BLD_REPLAY_LAG_P99_MS` (2 ms); outputs
  identical. The Vx run also reports the cost of each active workaround (`W-01`–`W-05`).

### 7.16 B13: handoff window

- **Procedure.** Three homes in staging with WAN delay per §6.7. Compress epochs to 10 minutes.
  Run 30 handoffs per direction pair at 60% of B3's load.
- **Metric.** Window = time from the old home's last step S on the wire to the first continuous
  fill at the new home after the auction. WAN one-way is measured per run with PTP-stamped
  probes.
- **Pass.** Every handoff completes (the book moves every 8 h, 01 §14.0), and the max window over
  all runs ≤ WAN one-way + `FINALITY_MAX_MS` + `BLD_HANDOFF_SLACK_MS` (5 ms), per pair. The window
  is the one stated exception to the 1 µs fill (01 §14.0, item 2). `INV-FENCE` holds in every run.

### 7.17 B14: auction uncross time

- **Procedure.** Load the auction book with 10³, 10⁵ and 10⁶ orders (`WL-AUCTION`) and trigger the
  uncross.
- **Metric.** Time from the uncross start to the last uncross response on the wire; equality with
  the oracle's uncross.
- **Pass.** ≤ `BLD_UNCROSS_US_MAX` (1,000 µs) at 10⁶ orders, and identical to the oracle. 08 has
  fixed this number.

### 7.18 B15: market-data latency

- **Procedure.** B3's load. Tap the sequencer's fill TX and the market-data publisher's TX (a
  replica in the same facility) into the same capture NIC.
- **Metric.** Fill first bit → the first bit of the market-data update that reports it.
- **Pass.** p99 ≤ `BLD_MD_LAG_P99_US` (10 µs). 10 owns the final number.

### 7.19 B16: AWS packet-rate limit

- **Procedure.** Two of the `AWS` target instances in one cluster placement group. A DPDK
  generator steps the packet rate up in 5% steps until ENA drops packets. At each step,
  `vyrn-seq` records in-instance latency (RX completion to TX doorbell, by TSC) for probe packets.
  Run once with RSS spreading and record the wrong-lane forwarding cost.
- **Metric.** Drop-free packets/s per queue and per instance; in-instance latency and its
  maximum; forwarding cost.
- **Pass.** In-instance max ≤ `LAT_MAX_NS` for every type at every index, at 80% of the drop-free
  rate; wrong-lane forwarding ≤ `BLD_FWD_NS` (100 ns, DESIGN §4). The wire belongs to Nitro, so
  the 1 µs is measured inside the instance (01 §14.0, item 1; `rx_ts` is the TSC at RX completion,
  01 §14.11). The result sets the `aws.toml` profile's published rate and batch size (§10.1).

### 7.20 B17: PHC sync across NICs

- **Procedure.** A 1×4 passive splitter sends each frame of one generator port to all four NICs of
  a `REF` box, through equal-length fibers. One frame per ms for 24 hours, with the box's PTP
  configuration from 06.
- **Metric.** Pairwise differences of the four RX timestamps of each frame.
- **Pass.** |offset| p99 ≤ `BLD_PHC_SKEW_P99_NS` (25 ns), max ≤ `BLD_PHC_SKEW_MAX_NS` (100 ns).
  The reason: the level FIFO orders by RX timestamp across NICs, so skew between NICs is
  unfairness between lanes.

### 7.21 B18: jitter probe

- **Procedure.** On each isolated core, a loop reads the TSC back to back for 1 hour and records
  every gap. Run idle, and again with the full process on the other cores at B3's load (control
  core exporting metrics, consensus running).
- **Pass.** On every core: no gap > `BLD_JITTER_MAX_NS` (1,000 ns), and at most
  `BLD_JITTER_GAPS_PER_H` (10) gaps > 250 ns per hour. A core that fails leaves the core map until
  06 explains it.

### 7.22 B19: failover outage

- **Procedure.** As B5, 50 kills in BASE and 50 in CHAIN. The capture measures from the old
  sequencer's last response on the wire to the promoted standby's first response. After each
  promotion, `vyrn-admin config check --cluster` reads the vote set from the finalised config record
  and from each box.
- **Pass.** p99 ≤ `FAILOVER_TARGET_MS` (20 ms), and B5's criterion on every kill. **The client
  split survives every promotion:** the promoted box is the standby `vyrn-seq`, never a voting
  replica; the voters stay 2 Rust + 2 Vx in BASE and 3 Rust + 2 Vx in CHAIN, and `vyrn-seq` holds
  no vote (01 §14.4). The same check runs on every SF-08 and SF-29 seed in `vyrn-sim`.

### 7.23 B20: consumer box

- **Procedure.** B3 and B9 on `CONSUMER` with `N_LANES_CONSUMER` lanes and one 100GbE port.
- **Pass.** B3's and B9's criteria at `BLD_CONSUMER_RATE` = `N_LANES_CONSUMER` × (10⁹ /
  `LANE_NS_PER_MSG`) × `BLD_LANE_MAX_LOAD` = 2.4 × 10⁸ msgs/s. DESIGN's "~250M" is this number
  rounded. `BLD_LANE_MAX_LOAD` (0.60) is the lane load DESIGN §3 uses to get 1B msgs/s from 50
  lanes; 01 has no name for it (Requests to 01). `CONSUMER` uses the X2522 card for replication
  path B (01 §14.7). The latency maximum is the same as on `REF`; only the rate differs.

### 7.24 B-GPU: GPU-initiated NIC echo (placeholder)

- **Purpose.** The only path by which `C-NOCHIP` may be reopened (01 §14.7). Until it runs and
  passes, no GPU is in any build, config or core map.
- **Procedure (draft).** As B1, but a GPU kernel polls the NIC's RX ring and rings its TX doorbell
  directly (GPU-initiated I/O), with no CPU in the path. Same rig, rates, sizes and capture.
- **Pass.** None yet; it does not gate a milestone. It may reopen `C-NOCHIP` only if RX + TX
  p99.99 ≤ `NIC_FLOOR_NS` (560 ns) and the maximum is no worse than B1's on the X2541. Reopening is
  a 01 decision, not this chapter's.

### 7.25 Catalogue of registered benchmarks

Other chapters define these. This chapter registers them as references: the owner chapter holds
the procedure and the pass criterion, and §7.1's rules apply to each. Where an entry checks a hard
requirement, it passes on the maximum (§7.1 rule 2).

| IDs | Owner | What they check |
|---|---|---|
| B21–B39 | 02 §13 | B21 lane queueing; B22 BBO queueing; B23 adversarial suite; B24 rate envelope; B25 revert condition; B26 failure-class drills; B27 readiness and extension; B28 handoff correctness; B29 chain authentication and forced path; B30 chain commitments, custody, DA, slashing; B31 platform and supply audit; B32 24 h soak; B33 low load and idle; B34 replica catch-up; B35 drop copy; B36 book group; B37 WAN follow; B38 upgrade at a boundary; B39 capacity variants |
| B-PQ-1 … B-PQ-3 | 07 | hedged ML-DSA sign tail, verify and ML-KEM-768 decapsulation on `REF`; scheme-1 finality with the gate and stream-core load re-run; the scheme switch at `E_pq` (01 §14.20) |
| B-REP-1 … B-REP-12, B-REP-VX | 07 | fill-to-finality across real facilities; frame lead; path skew; stream-core load (cores 4 and 7); sliced signing; hasher load (core 50, 01 §10); replay speed; promotion time; NVMe; archive and `pbz` ratios; path loss and kill run; Vx replay speed |
| PLT-B-PPS, -SW, -HOP, -MEM, -FREQ, -MIT, -SKEW, -AWS-PPS, -ENA-RSS, -X3D, -INJ, -TSME | 06 | packet rate per port; switch latency; cross-CCD hop; memory; frequency slider; mitigations; cross-NIC PHC skew; AWS packet rate; ENA RSS steering; X3D cache; NIC cache injection; TSME |
| EPO-T1 … EPO-T13 | 08 | handoff tests under kills, partitions, skew, byzantine members and client misbehaviour; they run in `vyrn-sim` and on staging |
| B13, B14 (08's criteria) | 08 | 08 fixes B13's window and B14's pass (1,000 µs at 10⁶ orders); §7.16–§7.17 run them |
| B-ARC-1, B-ARC-2 (B-ARC-3) | 03 | fabric load, cut sweep, padding and PHC skew; lane TX posting at peak. 03 names B-ARC-3 but does not define it yet |
| B-CHN-1 … B-CHN-6 | 09 | validator box capacity; LtHash; chain-gate binding rate; `escapeClaim` gas; front-running detection; archive ratio |
| B-RSK1, B-MD1 | 10 | risk cycles on the B2 mix; `MBO-C` ratio and market-data lag |

A registered benchmark gets a signed report like any other, and a milestone that names it gates
on it. A new chapter-local ID is added to this table in the same change that defines it.

## 8. Observability without touching the hot path

### 8.1 Decision

A pinned core never makes a syscall, never formats a string, never takes a lock and never writes
to a line that another core writes. It records what happened in its own memory: counters,
histograms and a trace ring. The control core (core 51 on `REF`) reads that memory and does all
export, logging and alerting.

```
  pinned core k (lane, cut, BBO, TX)                     control core
  ┌───────────────────────────────────┐                 ┌───────────────────────────────┐
  │ CoreStats   (single writer, 128 B │  Relaxed loads  │ sampler, every 100 ms         │
  │   lines, Relaxed stores)          │ ──────────────► │  diffs counters + buckets     │
  │ Histograms  (fixed buckets)       │                 │  → per-window quantiles       │
  │ TraceRing   (64K × 16 B, shm file)│ ─── on demand ─►│ trace freeze / dump           │
  └───────────────────────────────────┘                 │ exporter → mgmt NIC (kernel)  │
                                                        │ tracing logs → journald       │
  NIC: RX hw timestamp, TX completion timestamp ───────►│ in-box latency of every packet│
                                                        └───────────────────────────────┘
```

### 8.2 Counters and histograms

- **Counters.** Each core owns a `CoreStats` block of `BLD_SHARED_ALIGN`-aligned lines. The core
  increments its own `u64` fields with a plain load-add-store through `AtomicU64::store(Relaxed)`,
  which compiles to an ordinary `mov` on x86-64. Counters only go up. The control core reads them
  with `Relaxed` loads and diffs successive samples.
- **Histograms.** Log-linear, fixed at build time: exact 1 ns buckets to 128 ns, then 16
  sub-buckets per power of two up to 2³⁴ ns, `BLD_HIST_BUCKETS` = 512 buckets of `u64`, 4 KiB per
  histogram. Buckets are cumulative counters, so the sampler needs no handshake with the core.
- **Sample cost.** Each sample makes each sampled line shared, so the owner's next write to it
  misses once. At `BLD_SAMPLE_MS` = 100 ms and ≤ 8 lines per core, that is ≤ 80 misses per second
  per core. B3 runs with the sampler on, so the cost is inside its numbers.
- **Busy fraction without a clock.** The BBO core and the lanes count idle polls. Busy fraction =
  1 − idle_polls × `idle_poll_ns` / window, where `idle_poll_ns` is measured once per box at
  start. This reports `BBO_MAX_LOAD` with no TSC read on the busy path.
- **In-box latency of every packet, from the NIC.** Each TX core asks the NIC for TX completion
  timestamps and matches them to the RX hardware timestamp carried with each response. That gives
  the RX-to-TX latency of every response in production, measured by the NIC's own clock, with no
  timer on the lane. The capture rig (§7.2) remains the reference for wire-to-wire numbers.
- **Sampled stamps.** Where a phase needs a TSC stamp (lane service time, step time, cut age), the
  core stamps 1 in `BLD_TRACE_SAMPLE` (64) units. The stamp API returns `()`, so engine code
  cannot branch on the value, and the clock never reaches state (01 §11.3).

Examples of what each role records:

| Role | Counters | Histograms |
|---|---|---|
| Lane | packets, messages by type, rejects by reason (01 §6.5, `BUSY` included, labelled by class), joins/improves/crosses, snapshot refreshes, idle polls, ring-full events; pool cores also: token takes, CAS retries, steals, sibling `fetch_and`s | packet service time (sampled), join-ack wait (sampled), dequeue age `now − rx_ts` (every packet; it is computed anyway), token wait (pool, sampled) |
| Cut core A, B | half-cuts published, idle polls | half-cut age (sampled) |
| BBO core | steps by kind (`Shed` included), fills, rescans and their tick range, idle polls | step time by kind (sampled), BBO ring occupancy |
| TX-A, TX-B | packets, bytes, CTPIO fallbacks, idle polls | RX→TX in-box latency (every packet, NIC clocks) |
| Stream-A, stream-B | frames per path, records, idle polls | frame lead over the dependent response (sampled) |
| Replica engine | messages replayed, blocks | replay lag per block |

### 8.3 Trace ring and the no-logging rule

- **No logging on pinned cores.** The engine `clippy.toml` bans `println!`, `eprintln!`, `dbg!`,
  stdout and stderr (§3.3), and `tools/lint-engine` bans `tracing` and `log` in engine crates.
  Control and consensus threads log with `tracing` to journald.
- **Trace ring.** Each pinned core owns a ring of `BLD_TRACE_ENTRIES` = 65,536 entries of 16 bytes
  (1 MiB), in a file on a huge-page mount (`/dev/hugepages/vyrn-trace-<pid>-<core>`). The core
  overwrites the oldest entry. Layout:

  ```
  off size field
    0   8  tsc     u64
    8   1  kind    u8     RX_PKT, STEP_BEGIN, STEP_END, CUT, RING_FULL, REJECT, STALL, SEAL, PANIC, ...
    9   1  core    u8
   10   2  arg16   u16    e.g. step kind, reject reason
   12   4  arg32   u32    e.g. low bits of LaneSeq or StepId
  ```

- **What goes in it.** Every reject, ring-full event, stall and seal; sampled packets, steps and
  cuts. Writing an entry is a TSC read plus one 16-byte store to a line only this core writes.
- **Freeze and dump.** `vyrn-admin trace freeze` sets a per-core flag that the core checks once per
  poll; the core then stops writing. The panic hook freezes all rings (§3.8). Because the rings are
  files, `vyrn-admin trace dump` reads them after the process exits. It converts TSC to PTP time
  with the (TSC, PHC) pairs that the control core records each second.

### 8.4 Metrics export

- The exporter is a tokio task on the control core. It serves Prometheus text format on the
  management interface (kernel networking, never a trading NIC), port `BLD_METRICS_PORT` (9464).
- It exports counters as totals, and each histogram as its buckets plus p50, p99, p99.9 and max
  per 1 s window. Labels: `book`, `role`, `core`, `lane`, `home`, `epoch`, `client`.
- NIC statistics come from the control core (driver counters, PHC offset from the PTP daemon).
- Each facility runs a Prometheus pair that scrapes every box each second. A global store keeps
  30 days at 1 s and 2 years at 1 min.

### 8.5 Dashboards

`deploy/dashboards/` defines:

1. **Book:** msgs/s in and out; crosses/s against `CROSS_CAP`; BBO busy against `BBO_MAX_LOAD`;
   `plt_w2w_ns` max and p99 by response type and message index against `LAT_MAX_NS`; the `BUSY`
   share per class, the pooled share plotted on B3's curve at the live book load; rejects by
   reason; RX drops.
2. **Lanes:** a heatmap of per-lane load, service-time p99, ring occupancy and snapshot age; for
   the pool, token waits, CAS retries and steals per core.
3. **Replication:** order-stream Gbps per path; frame loss; payload arrival lag; replica replay lag
   by client (Rust, Vx).
4. **Finality:** time to certificate p50, p99 and max against `FINALITY_MAX_MS`; chain-gate lag (CHAIN); view changes; votes
   per replica; state attestations matched and mismatched.
5. **Epoch:** time to boundary; handoff stages with their times; auction book size; follower lag
   per home.
6. **Platform:** PHC offsets (B17's metric live); TSC jitter counters; CPU frequency; temperature;
   ECC errors.
7. **Chain (CHAIN mode):** bridge queue, `K_com` exclusions, slashing evidence, operator status.

### 8.6 Alerts

| Alert | Condition | Severity | Runbook |
|---|---|---|---|
| `DivergenceDetected` | any replica's output hash or state root differs from the quorum's | page, immediate | §10.4.5 |
| `FinalityMaxBreached` | any block's finality > `FINALITY_MAX_MS` (10 ms, a maximum) | page, immediate | §10.4.6 |
| `SequencerSilent` | no order frames for `FAILOVER_SILENCE_MS` (consensus acts on its own; this tells humans) | page | §10.4.2 |
| `LatencyMaxBreached` | any response with `plt_w2w_ns` > `LAT_MAX_NS` (one sample is enough) | page, immediate | §10.4.6 |
| `BusyDedicated` | any lane-stage `BUSY` to a paced session on a dedicated lane (one is enough), or its total above B3's dedicated curve | page, immediate | §10.4.6 |
| `BusyPooledHigh` | pooled `BUSY` share over 60 s above B3's curve at the measured book load | page | §10.4.6 |
| `BboLoadHigh` | BBO busy > `BBO_MAX_LOAD` for 10 s | page | §10.4.6 |
| `CutAgeHigh` | sampled half-cut age > `CUT_REFRESH_NS` on either cut core | ticket | §10.4.6 |
| `PathLoss` | frame loss on either replication path | page | §10.4.6 |
| `ReplayLagHigh` | replay lag p99 > `BLD_REPLAY_LAG_P99_MS`, by client | page | §10.4.6 |
| `PhcSkewHigh` | PHC offset > `BLD_PHC_SKEW_MAX_NS` | page | §10.4.6 |
| `ProcessAborted` | any production process aborted (panic or `INV-NOALLOC`) | page | §10.4.6 |
| `HandoffSlow` | a handoff stage exceeds its B13 budget | page | §10.4.1 |
| `HotRetentionLow` | replica drives hold < 12 h, an archive node < 7 days, or the sequencer's response ring < `RESP_HOT_RING_BYTES` (01 §14.6, §14.7) | ticket | §10.4.6 |
| `SplitBroken` | the voting set is not 2 Rust + 2 Vx (BASE) or 3 Rust + 2 Vx (CHAIN), or a `vyrn-seq` holds a vote | page | §10.4.2 |
| `BuildMismatch` | boxes in one cluster report different release hashes for one protocol version | ticket | §10.2 |

## 9. CI/CD

### 9.1 Stages

```
 PR opened ─► S1 fast (≤ 15 min) ─► S2 full (≤ 60 min) ─► S3 perf gate (≤ 45 min) ─► merge
                                                                                     │
 main ─► nightly: S4 long (8 h: fuzz, swarm, B1/B3/B5/B9–B11/B19, chaos) ◄───────────┤
      ─► weekly:  S5 cluster (B13, B16, B17, B20)                                    │
 tag  ─► S6 release: reproducible builds ×2 ─► compare ─► sign 2-of-3 ─► publish ◄────┘
```

### 9.2 Pre-merge (S1 and S2)

| Stage | Job | Hosts |
|---|---|---|
| S1 | `cargo fmt --check`; `clang-format --dry-run` on the shim | Linux |
| S1 | `cargo clippy --all-targets -D warnings` (both clippy configs) | Linux, macOS |
| S1 | `tools/unsafe-audit`, `tools/lint-engine`, `tools/shim-gate`, `tools/vx-friction` | Linux |
| S1 | `cargo deny check`, `cargo vet --locked` | Linux |
| S1 | `vx/build.sh`; `cargo build --locked --offline` for Linux x86-64, Linux aarch64, macOS aarch64 | all three |
| S1 | unit tests, golden vectors, 2,000 proptest cases, 500 sim seeds, `tests/seeds.toml` | all three |
| S2 | Miri, loom, Rust nightly TSan + Vx TSan, ASan/UBSan of the shim on `net_ring` | Linux, macOS |
| S2 | fuzz 60 s per target; per-PR differential on the golden logs | Linux |
| S2 | B4 reduced (golden logs, builds A, D, E, F) when an engine crate, `vyrn-crypto`, the toolchain or an E-tier crate changed | Linux, macOS |
| S2 | asm gate (§4.4) on the Linux release builds | Linux |
| S2 | `VX_TASK_SEED` sweep: 200 seeds of the Vx client's own replay test | Linux |

### 9.3 The performance gate (S3)

- **Runners.** Dedicated lab machines: two `REF` and one `CONSUMER`, BIOS and kernel per 06, with
  no other tenant. A runner qualifies when ten repeated runs of B2, B6 and B8 have a median absolute
  deviation ≤ 1% (`BLD_RUNNER_NOISE_MAX`). A runner is requalified after any firmware, BIOS or
  kernel change.
- **What runs per PR.** B2, B6, B7, B8, B12 (from memory, both clients) and B18 (10 minutes), on
  every PR that touches a pinned crate, `vyrn-replica`, `vx/`, the toolchain or the shim.
- **Regression rule.** A metric fails if it breaks its absolute threshold (§7), or if it is worse
  than the median of the last 10 runs on `main` by more than max(2%, 3 × the runner's MAD)
  (`BLD_PERF_REGRESS_MIN` = 2%). Both mean and p99 are compared.
- **Override.** A PR may accept a regression that stays within the absolute threshold. It needs a
  written reason in the PR and approval from two owners of the affected crate. Merging it resets
  the baseline. A threshold breach cannot be overridden.
- **Baselines** live in `bench/baselines/<runner>/` and are updated by the gate itself after each
  merge.

### 9.4 Reproducible builds

- **Build image.** An OCI image pinned by digest holds rustc, clang, lld (same LLVM), vxc
  (hash-checked) and nothing else from the network. `deploy/image/` builds it from pinned sources.
- **Inputs.** `SOURCE_DATE_EPOCH` = the commit time; `--remap-path-prefix` for the source,
  vendor and home paths; `--locked --offline`; `codegen-units = 1`; build-id computed from content.
- **Check.** `tools/repro-build` builds every release artifact twice, on two different machines
  (the CI builder and a separate release builder with a different OS install), and compares
  BLAKE3 hashes of every file. Any difference stops the release.
- **Vx.** The same applies to `libvyrn_vx_*`. If vxc output is not reproducible, that is a
  FRICTION.md entry and an upstream issue, and the release uses the CI builder's library with both
  builders' hashes recorded until it is fixed.
- **Chain mode.** Each operator rebuilds the release from the tag with the same image and
  publishes its hashes. 09 decides how attestations gate activation.

### 9.5 Signing and release artifacts

- **Keys.** Three release keys on hardware tokens, held by three maintainers. A release needs two
  signatures (`BLD_RELEASE_SIGS` = 2 of 3) over the release manifest. The keys are hybrid Ed25519 +
  ML-DSA-65 (scheme 2, 01 §14.20): a release signature is valid only if both parts verify. Why
  ML-DSA-65 here and ML-DSA-44 on the live path: release keys live for years, sign a few times a
  month, and a forged release takes every box; 150 µs more per signature costs nothing. Rotation:
  the old Ed25519 keys sign one last manifest that names the three hybrid keys, and from then on a
  box accepts only hybrid signatures. Every manifest from the switch on carries `pq_anchor`
  (01 §14.20 SG6). **Where the halves live (PQ-7).** Each maintainer's Ed25519 half stays on the
  current hardware token. The ML-DSA-65 half is held on that maintainer's air-gapped Linux
  machine, encrypted at rest under a passphrase only that maintainer knows, and never on a
  networked machine. A release signature is made in two steps: the token signs the Ed25519 part,
  and the air-gapped machine signs the ML-DSA part over the same `scheme ‖ digest`, carried in and
  out on removable media. Both parts are joined on the build machine and checked by
  `vyrn-admin release verify` before publication. The quorum stays 2 of 3. The ML-DSA half moves
  to a hardware token with FIPS 204 firmware once one is chosen, by the rotation rule above.
- **Verification.** `vyrn-admin release verify` checks the signatures and every file hash before a
  bundle can be staged (§10.3). Boxes reject an unsigned bundle.
- **Artifacts** (per architecture: Linux x86-64, Linux aarch64; macOS aarch64 for DEV only):
  - binaries: `vyrn-seq`, `vyrn-replica`, `vyrn-validator`, `vyrn-data`, `vyrn-md`, `vyrn-dropcopy`,
    `vyrn-admin`, `vyrn-sim`, `vyrn-bench`
  - libraries: `libvyrn_vx_client`, `libvyrn_vx_oracle`, with their manifest
  - `manifest.toml`: commit, protocol version, config schema version, file hashes, toolchain hashes
  - SBOM (CycloneDX), provenance of both builds, the signed benchmark reports that gated the
    release, golden logs with their expected output hashes
  - detached signatures

## 10. Deployment and operations

### 10.1 Configuration (C-ONEBIN)

Every box runs a release binary and one signed TOML file. The file selects everything that
differs between bare metal, AWS, the consumer box and DEV. No build flag does.

```toml
schema    = 3                       # config schema version, tied to the protocol version
protocol  = 1
role      = "replica"               # seq | replica | validator | data | md | dropcopy
mode      = "CHAIN"                 # BASE | CHAIN
home      = "LDN"
facility  = "F3"
books     = [7]

[engine]
client    = "vx"                    # rust | vx   (replica and validator only)
dedicated = 42                      # lanes 0–41 (01 §10)
pooled    = 7                       # lanes 42–48, one CCD (01 §14.15)

[nic]
backend   = "efvi"                  # efvi | dpdk | kernel_udp | sim
ports     = ["0000:41:00.0", "0000:41:00.1", "0000:42:00.0", "0000:42:00.1"]

[cores]                             # from deploy/coremaps/ref.toml (01 §10), checked against /sys
roles = { tx_c = 0, cut_a = 1, bbo = 2, tx_a = 3, stream_a = 4, tx_b = 5, cut_b = 6,
          stream_b = 7, hasher = 50, os_control = 51 }   # 01 §14.17 item 3
dedicated = "8-49"                  # one firm per lane (10 §1.3)
pool      = "56-62"                 # CCD 7; must be one CCD
spare     = "52-55,63"              # 52–55: planned lane evacuation only

[keys]                              # handles, never key bytes
vote   = "hsm:slot=2:label=vyrn-vote-e"
p2p    = "hsm:slot=2:label=vyrn-p2p"
```

`vyrn-admin config check` and the binary at start both validate the file, and the binary refuses
to start on any failure: schema and protocol versions match the release; the cores exist, are in
`isolcpus`/`nohz_full` (all but core 51), and sit on the NICs' NUMA node; the pool's cores share
one CCD's L3; the NIC backend is available on this OS;
the huge pages needed for the preallocation exist; the cluster's voting set matches
`CLIENT_SPLIT_BASE` or `CLIENT_SPLIT_CHAIN` (from the cluster file), no `seq` box holds a vote key,
and each home has exactly one standby `seq` box in F2 (01 §14.4); key handles resolve. Keys
come from an HSM or the facility's secret manager, never from the file or the repository.

Profiles in `deploy/profiles/` give the defaults per target: `ref.toml` (ef_vi, 42 dedicated
lanes and a 7-core pool; 6 × X2541 on `seq`, 4 × X2541 and 12 NVMe drives on a replica, 01
§14.7; 3 × dual-port CX-6 Dx and 3 × X2541 on an observer, 01 §14.16), `consumer.toml` (11 lanes,
one client port, the X2522 for replication path B), `aws.toml` (DPDK on ENA, RSS forwarding on, the published
rate and batch size from B16), `dev.toml` (`sim` or `kernel_udp`, no pinning).

**Start sequence** of every binary: load and verify config → verify the release manifest and the
Vx library hash → allocate all memory (huge pages, `mlockall`) → open the NIC backend → create and
pin the threads → each pinned core touches its pages, warms its tables, and calls `seal()` → the
control core reports ready.

### 10.2 Versions

- **Release** = one commit and its artifacts. **Protocol version** = the version of everything
  that decides an output byte: wire, order stream, engine semantics, canonical state.
- Boxes of one cluster may run different releases only if they share a protocol version **and**
  B4 passed between those two releases. Otherwise `vyrn-admin config check` refuses the mix.
- A protocol change activates at an epoch number that a finalised admin record names (07 owns the
  record). Every box must have a release that supports the new version before that epoch starts.

### 10.3 Rollouts only at epoch boundaries

A release reaches the active home only at the start of that home's epoch. Each box has two slots,
A and B. `vyrn-admin deploy stage` writes the signed bundle into the inactive slot; `activate` makes
it the slot that starts next.

```
  epoch:      TYO active        LDN active        NYC active        TYO active
  UTC:        00:00 ─────────── 08:00 ─────────── 16:00 ─────────── 00:00
  LDN boxes:  stage + restart   ◄── runs new ───►
              as followers      release as home
              (replay, shadow)
  NYC boxes:  stage ────────── restart as followers ── runs new as home ──►
  TYO boxes:  (old release)     stage ──────────── restart as followers ── new as home ──►
```

1. **Canary.** One follower replica of the next home restarts on the new release and replays the
   finalised log. Its output hashes must match the active home's for `BLD_CANARY_HOURS` (4 h).
2. **Follower home.** The remaining boxes of the next home restart, one at a time, while they are
   followers. Each must match before the next restarts.
3. **Activation.** At the boundary, the next home becomes active on the new release.
4. **The other homes follow** in their own follower windows. A full rollout takes 24 hours.
5. **Rollback** is the same procedure with the previous bundle, which stays in the other slot.

The active home's boxes are never restarted for a release mid-epoch. A fix that cannot wait is a
halt (§10.4.3), not a hot patch.

### 10.4 Runbooks

Each runbook is a file in `deploy/runbooks/`. These are their steps.

#### 10.4.1 Start of epoch

1. T − 60 min: `vyrn-admin epoch preflight --home <next>`: release hashes equal across the next
   home; follower lag 0; PHC offsets within B17's limits; keys loaded; the new sequencer box passed
   its last B18 run.
2. T − 10 min: confirm `EpochNotice` is going out (04, 08).
3. T: the old sequencer stops at step S. Watch the handoff dashboard: cert(e, S), log tail at the
   new home, auction collection.
4. Auction uncross, then continuous trading. Check the window against B13's budget.
5. T + 15 min: `vyrn-admin epoch report` stores the handoff stage times. A stage over budget opens
   a ticket (`HandoffSlow`).
6. If the certificate does not form within `BLD_HANDOFF_ABORT_MS` (500 ms), follow 08's handoff
   failure procedure; do not start the new sequencer by hand.

#### 10.4.2 Sequencer failover

Consensus promotes the warm standby `vyrn-seq` in F2 on its own (07, 01 §14.4). People confirm and
clean up:

1. Confirm the promoted standby is sending (book dashboard) and record the outage (B19's metric
   live). Confirm `SplitBroken` is silent: the voters are unchanged.
2. Freeze and dump the old sequencer's trace rings if the box is reachable.
3. The home now has no standby. Keep the old box out until it passes `vyrn-admin box qualify` (B1
   smoke, B18 10 minutes, ECC and PHC checks). A second failure before a standby returns is
   SF-29's case: it is a halt (§10.4.3), never a promotion of a voting replica.
4. Root cause within 24 hours. A software cause gets a `vyrn-sim` seed or a chaos test before the
   fix merges.
5. The old box rejoins as the standby `vyrn-seq` at the next epoch boundary, never mid-epoch.

#### 10.4.3 Halt

1. Decide: a halt is required for a divergence (§10.4.5), a suspected wrong fill, a security
   incident on the sequencer, or a defect that a fix cannot wait an epoch for.
2. `vyrn-admin book halt --book <id> --reason <code>` submits the signed halt record (07 owns the
   format; in CHAIN mode it needs the operator signatures 09 defines). Lanes then reject with
   `BOOK_HALTED`.
3. Confirm on the book dashboard that inbound orders get `BOOK_HALTED` and that no fill leaves.
4. Post the notice to clients through the status channel within `BLD_HALT_NOTICE_MIN` (5 min).
5. Resume only by a signed resume record, which can open with a call auction (08).

#### 10.4.4 Key rotation

| Key | Rotates | How |
|---|---|---|
| Sequencer block key | every epoch | `next_seq_key` in the `HandoffRecord` (01 §6.6) |
| Session keys `K_seq`, `K_com` | every epoch | session protocol (04, 09) |
| Replica vote key | every 90 days, or at once on suspicion | below |
| p2p identity | with the vote key | below |
| Release keys | yearly, or on loss of a token | 2 of 3 sign the new key set |

Vote key: (1) generate in the HSM; (2) `vyrn-admin keys propose` submits a signed key-change record;
(3) it takes effect at epoch e + 2, so every home sees it finalised first; (4) confirm votes with
the new key; (5) destroy the old key in the HSM after e + 3. On suspected compromise: halt first
(§10.4.3) if the key's operator could combine it with one more key to reach q.

#### 10.4.5 Client divergence alarm

`DivergenceDetected` fires when any replica's output hash or state root differs from the
quorum's.

1. **One box differs, its client's other boxes agree:** a box fault (memory, disk, a bad binary).
   Take the box out, keep its traces, rebuild it, requalify it. No halt: the quorum still forms.
2. **A whole client differs (all Rust or all Vx):** no state attestation can reach q, by the split
   of 01 §5. The book stops finalising. Confirm the halt (§10.4.3) so that lanes reject instead of
   filling into a log that cannot finalise.
3. `vyrn-admin diverge locate` finds the first (height, step, lane) that differs and extracts that
   block's inputs.
4. Replay the block through `vyrn-vx-oracle` and through both clients offline (`vyrn-sim replay`). The
   oracle and the scenarios of 05 decide which client is wrong.
5. If the Vx client is wrong, the sequencer's fills stand. If the Rust engine is wrong, the
   sequencer's live fills were wrong too, and 07's recovery rule decides which fills stand (open
   question 3).
6. Fix, add the block as a golden log, run B4, release through §10.3, resume.

#### 10.4.6 Incident response

1. **Severity.** SEV1: a halt, a divergence, a suspected wrong fill, a security breach. SEV2:
   latency, finality or failover SLO broken. SEV3: degraded redundancy (one path, one replica).
2. **Roles.** An incident commander, an operator at the keyboard, a scribe, a communications
   owner. In CHAIN mode, each operator runs its own incident and joins a shared bridge channel.
3. **First 5 minutes.** Acknowledge, freeze traces on the affected boxes, open the timeline.
4. **Mitigate** with a runbook. Do not improvise on the active sequencer.
5. **Postmortem** within 5 business days for SEV1 and SEV2. Every SEV1 adds a `vyrn-sim` seed, a
   chaos schedule or a golden log, so the same bug fails a test before it can ship again.

### 10.5 On-call

- **Follow the sun.** Each home has an ops team in its own time zone. The active home's team is
  primary during its epoch, which is its daytime. The next home's team is secondary.
- **Coverage.** Pages are acknowledged within `BLD_PAGE_ACK_MIN` (5 min). SEV1 pulls in an engine
  owner and, from M4 on, a Vx client owner.
- **Drills.** Each runbook is drilled on staging once a quarter. Halt and divergence are drilled
  monthly from M5.
- **CHAIN mode.** Each of the 5 operators runs its own on-call for its own boxes. No operator
  touches another operator's box. Cross-operator coordination uses the bridge channel and signed
  records only.

## 11. Milestones and risks

### 11.1 Milestones

Team sizes and durations are budgets. A milestone ends when every exit benchmark passes in a
signed report on the target hardware, not on a date.

| M | Goal | Deliverables | Exit criteria | Depends on | Team, duration |
|---|---|---|---|---|---|
| M0 | The floor and the oracle | workspace, S1 CI, `vyrn-types`, `vyrn-wire`, `vyrn-crypto`; `vyrn-nic` (efvi, dpdk, sim) and the C shim; `vyrn-bench echo`; the capture rig; `vyrn-vx-oracle` with the 05 scenarios; the #2501 comment and #3373 followed up | **B1** on ≥ 1 NIC; B18 on `REF`; asm gate green on the echo path; oracle passes every scenario | — | 4, 6 weeks |
| M1 | One lane, simulated | `vyrn-cut` (rings with loom), `vyrn-risk`, `vyrn-lane` (deadline admission, two passes), `vyrn-engine` single-lane; `vyrn-sim` with one box and SF-01–03, SF-13–15, SF-27; proptest and differential harnesses; fuzz targets for the wire | **B2**, **B6**; 10⁹ messages diffed clean; 10⁴ sim seeds clean | M0 | 6, 8 weeks |
| M2 | One box at 1B msgs/s | `vyrn-bbo` (with `Shed`, `STEP_FILL_CAP`), two cut cores, TX-A/B/C (cores 3, 5, 0) and stream-A/B (cores 4, 7) with the frame gate, 42 dedicated lanes and the 7-core pool with `AcctTake` logging, the pacing SDK (cancels first), rescans; generators at full rate; Vx-in-Rust embedding smoke test; the `--emit-llvm` experiment (§5.5); #3369, #3370, #3374, #3372 in discussion | **B3** (max per type and index, `BUSY` per class, the pooled curve), **B7**, **B8**, **B9** on `REF`; sim with SF-11–14, SF-27, SF-28, SF-30–35 clean; the four pool tests and the pacing-SDK test (§6.4, §6.10) | M1 | 8, 12 weeks |
| M3 | Replication and finality, BASE | `vyrn-log`, `vyrn-data`, `vyrn-consensus`, `vyrn-replica` (Rust), the warm standby and its promotion, state attestations; `vyrn-vx-client` correct with `W-01`–`W-05` | **B4** (builds A–E), **B5**, **B10**, **B11** BASE, **B12** Rust, **B19** with the split check; Vx client matches on the golden logs | M2 | 10, 12 weeks |
| M4 | Epochs, and the Vx client at speed | `vyrn-epoch`, handoff, opening auction; parallel Vx client; `pbv_*_step` for `vyrn-sim`; upstream issues landed where accepted | **B12** Vx, **B4** with F and G, **B13**, **B14**, **B17** | M3, Vx #2501, #3373, #3369, #3370, #3374 or their workarounds | 10, 12 weeks |
| M5 | BASE in production | `vyrn-md`, `vyrn-dropcopy`, accounts and risk (10), `aws.toml` and `consumer.toml`, dashboards, alerts, runbooks drilled, external security audit | **B15**, **B16**, **B20**; all of B1–B20 and the §7.25 entries that 02 assigns to BASE green in one release; 30-day staging soak without a SEV1 | M4 | 12, 14 weeks |
| M6 | CHAIN in production | `vyrn-chain`, `vyrn-validator`, 5 operators × 3 homes, `K_com` checks, TESLA disclosure, lattice commitment, bridge, slashing; operator rebuilds (§9.4) | **B11** CHAIN, **B3** with two MACs per packet, **B13** with 15 nodes, **B4** across operators' builds; external audit of chain and bridge; 60-day public testnet without a SEV1 | M5 | 14, 16 weeks |

Total: 80 weeks and about 800 person-weeks (budget). Nothing after M0 starts at full size: each
milestone hires for the next one while it runs.

### 11.2 Risk register

| # | Risk | Likelihood | Impact | Mitigation | Kill criterion |
|---|---|---|---|---|---|
| R1 | No COTS NIC meets `NIC_FLOOR_NS` | medium | the 1 µs claim | B1 in week one on every NIC in 06; CTPIO; tuning per 06 | no NIC passes B1 by M0 exit + 4 weeks → latency work stops until one does: 06 tries every remaining COTS path (TPH, PLT-B-INJ; other NIC generations), and B-GPU is run. REQ-LAT-1 is never restated (01 §14.0) |
| R2 | Lane cost > `LANE_NS_PER_MSG` | medium | 1B msgs/s per book | B6 per op; fewer cache lines per op; SipHash inlining | B2 > 40 ns after M1 + 6 weeks → the lane design changes (05, 10: fewer lines per op, work moved off the lane) until B3 passes at 1B; the rate is never lowered (01 §14.0) |
| R3 | BBO core > `BBO_CROSS_NS` (15 ns) | medium | `CROSS_CAP`, the BBO shed tail (01 §14.15 item 2) | B8 variants; `Segment16` sweep; prefetch of level heads; fewer lines per step | B8 cross > 20 ns at M2 exit → the BBO step changes (05) until B3 passes `WL-REF` at 1B; `CROSS_CAP` beyond `WL-REF`'s 1% may be restated, the 1B is not |
| R4 | Cross-CCD hop > 100 ns | low | the 965 ns index-9 budget (01 §14.2) | core map keeps BBO, both cut cores and TX on CCD 0; PLT-B-HOP | B3 max > `LAT_MAX_NS` with every other stage in budget → the core map or the path changes (03, 05, 06); REQ-LAT-1 stays |
| R5 | Vx client below 1B msgs/s, or Vx miscompiles | high | finality for the whole book (§5.7) | Vx #2501, #3373, #3369, #3370, #3374, workarounds, FRICTION.md, oracle and B4 | B12 Vx fails at M4 exit + 8 weeks → 01 decides between more Vx replay cores per box and 5 × Rust (diversity lost and stated so); CHAIN keeps 5 validators and 10 ms either way |
| R6 | Upstream rejects a Vx issue | medium | a permanent workaround | one behaviour per PR; issue before branch; never fork | a rejected issue whose workaround costs > 10% of B12 → R5's kill path |
| R7 | Bug in shared Rust shell (Simplex, `vyrn-log`, BLAKE3) | low | a fork that diversity cannot stop | `vyrn-sim`, Commonware's own tests, B4, audits | — (no kill; it is the residual risk of §5.1) |
| R8 | Determinism breaks across builds | medium | a halt in production | B4 per PR touching engine crates; one toolchain pin | any B4 failure blocks the release; no kill |
| R9 | AWS cannot reach the rate | high | AWS rate | B16; batching; publish the AWS rate separately | the AWS profile's rate is whatever B16 measures; no kill |
| R10 | PHC skew across NICs above budget | medium | fairness across lanes | B17; PPS between NICs (06) | B17 fails → all lanes of one book on NICs sharing one PHC, or one NIC per book (06) |
| R11 | Supply-chain compromise | low | everything | vendoring, cargo-vet, reproducible builds, 2-of-3 signing | — |
| R12 | Simulator misses a real-world fault | medium | an outage | chaos tests nightly; every SEV1 adds a test | — |
| R13 | Hiring the M2–M4 team | medium | schedule | hire one milestone ahead | — |
| R14 | `BUSY` above its class bound at `WL-REF` (any lane-stage `BUSY` on a dedicated paced lane, or its total above 1e-5 at full or 1e-8 at ≤ 20% load; pooled above 1e-3 at full or 1e-6 at ≤ 20% load), or a response above 1 µs after admission (a TX-side tail that the deadline test cannot see) | medium | REQ-LAT-1 as a maximum; REQ-LAT-5 | `predicted_path_ns` from B6/B8 maxima; `DEADLINE_GUARD_NS`; B1's maximum; B18; the pacing SDK; more firms on dedicated lanes | B3 fails any criterion at M2 exit + 6 weeks → the path, the guard or the class split changes (05, 06, 10); the bounds stay |
| R15 | Pool determinism: token order across pool cores not replayable from the log | medium | a fork between sequencer and replicas | `AcctTake` records (01 §14.17 item 4); the `AcctTake` checks of §6.4; SF-33; B4 on pool logs | SF-33 or B4 fails at M2 exit → the pool runs without stealing (each pool core a plain lane) until the cause is fixed |

## Interfaces to other chapters

| Chapter | This chapter consumes | This chapter provides |
|---|---|---|
| 01 | names, types, constants, layouts, invariants, determinism rules, the §10 core map, the §14 decisions (lane classes §14.15, rulings §14.16) | the checks that enforce them (lints, asm gate, sim invariants), B1–B20, B-GPU, the §7.25 catalogue, the per-class `BUSY` curve |
| 02 | the workload model and its IDs; measurement points; SLOs; B21–B39 | the benchmark procedures that measure each SLO, max-based for REQ-LAT-1; the registry of B21–B39 |
| 03 | book groups, component catalogue; B-ARC-* | the crate and binary map of each component (§1.3); `deploy/coremaps/` from 01 §10 |
| 04 | session and resend semantics | fuzz targets and probe sessions for every message type |
| 05 | `SEQSPEC` (the sequential specification the oracle implements); atomic orderings; per-op costs; pool stealing and sibling-segment cancels | the oracle, the differential and commutation checks, B6–B8, the pool tests (§6.4) |
| 06 | qualifying NICs, BIOS and kernel settings, the shim API, PTP setup, `plt_w2w_ns`; PLT-B-* | shim build and gates, B1, B16–B18, B-GPU, the perf runners' qualification |
| 07 | order-stream encoding, standby promotion, state attestation, canonical state, recovery rule; B-REP-* | the `ReplayEngine` boundary, B4, B5, B10–B12, B19 with the split check, the divergence runbook |
| 08 | handoff and auction procedures and budgets; EPO-T1–T13; B13 and B14 criteria | B13, B14, the start-of-epoch runbook, rollouts at boundaries |
| 09 | chain-mode signatures, halt and key records, operator attestations, the chain gate; B-CHN-* | CHAIN gates of M6, operator reproducible builds |
| 10 | market-data and drop-copy design, risk rules, `lane_map` classes, `PoolTok`; B-RSK1, B-MD1 | B15, conservation checks in `vyrn-sim`, `vyrn-md`/`vyrn-dropcopy` packaging, SF-30–33 |

Requirements on other chapters that this chapter depends on:

- **05** publishes `SEQSPEC`: the book as a sequential function of the linearised events of §6.3,
  including how rescans and the lemma's slow path appear as events.
- **07** makes each replica attest to its engine output (block output hash and state root), and
  stop attesting on a mismatch, so that client diversity halts instead of forking (§5.3).
- **05** and **06** publish `predicted_path_ns` per packet shape and lane class (the pool's with
  the token CAS), from B6 and B8 maxima, for the deadline test of 01 §14.1 and for the SDK's
  `LANE_PACE` table (§6.10).
- **01** (or 07) fixes the wire layout of `AcctTake` (01 §14.17 item 4) in the order stream;
  the `AcctTake` checks, SF-33 and B4 on pool logs read it.
- **07** (or 05) defines the canonical state encoding that both clients and the oracle write.
- **06** keeps the shim API small enough for 300 lines and decides the indirect-call case of §4.4.

## Local definitions

Values are budgets unless marked.

| Name | Value | Name | Value |
|---|---|---|---|
| `BLD_SHARED_ALIGN` | 128 B | `BLD_LANE_MAX_LOAD` | 0.60 |
| `BLD_OVERFLOW_COST_MAX` | 3% of B2 | `BLD_ISA_COST_MAX` | 5% of B2/B8 |
| `BLD_ORACLE_MIN_RATE` | 10⁶ events/s on DEV | `BLD_ORACLE_LINES_MAX` | 1,500 lines of Vx |
| `BLD_CATCHUP_RATE` | 1.2 × 10⁹ msgs/s | `BLD_REPLAY_LAG_P99_MS` | 2 ms |
| `BLD_ENGINE_LINE_COVERAGE` | 90% | `BLD_PROPTEST_CASES_PR` | 2,000 |
| `BLD_SIM_SEEDS_PR` | 500 × 10 virtual s | `BLD_SIM_VIS_MAX_NS` | 2,000 ns |
| `BLD_SIM_HEAL_MS` | 100 virtual ms | `BLD_CAPTURE_ERR_NS` | 5 ns (p99 − p1, zero device) |
| `BLD_PROBE_SHARE` | 0.5% of sessions | `BLD_PROBES_PER_CELL` | 10⁶ per (type, index, count) |
| `BLD_LANE_OP_NS` | table in §7.9 | `BLD_ACK_WAIT_NS` | 170 ns maximum (01 §14.17 item 1) |
| `BLD_STEP_P99_NS` | 100 ns | `BLD_ORDER_GBPS_MAX` | 25 Gbps per path |
| `BLD_DATA_ARRIVAL_P99_US` | 200 µs | `BLD_HANDOFF_SLACK_MS` | 5 ms |
| `BLD_UNCROSS_US_MAX` | 1,000 µs at 10⁶ orders | `BLD_MD_LAG_P99_US` | 10 µs |
| `BLD_FWD_NS` | 100 ns | `BLD_PHC_SKEW_P99_NS` | 25 ns |
| `BLD_PHC_SKEW_MAX_NS` | 100 ns | `BLD_JITTER_MAX_NS` | 1,000 ns |
| `BLD_JITTER_GAPS_PER_H` | 10 gaps > 250 ns | `BLD_CONSUMER_RATE` | 2.4 × 10⁸ msgs/s |
| `BLD_HIST_BUCKETS` | 512 | `BLD_SAMPLE_MS` | 100 ms |
| `BLD_TRACE_SAMPLE` | 1 in 64 | `BLD_TRACE_ENTRIES` | 65,536 × 16 B |
| `BLD_METRICS_PORT` | 9464 | `BLD_RUNNER_NOISE_MAX` | 1% MAD |
| `BLD_PERF_REGRESS_MIN` | 2% | `BLD_RELEASE_SIGS` | 2 of 3 |
| `BLD_CANARY_HOURS` | 4 h | `BLD_HANDOFF_ABORT_MS` | 500 ms |
| `BLD_HALT_NOTICE_MIN` | 5 min | `BLD_PAGE_ACK_MIN` | 5 min |
| `BLD_BUSY_CURVE_LOADS` | 10, 20, 40, 60, 80, 100% of 10⁹ msgs/s | `BLD_LANE_OP_NS` (pool) | token 20 ns, steal 25 ns (§7.9) |

| Name | Kind | Meaning |
|---|---|---|
| `Core`, `Progress` | Rust trait, enum | The poll interface of every pinned role (§3.1) |
| `ReplayEngine` | Rust trait | The replay boundary that `RustReplay` and `VxReplay` implement (§5.3) |
| `SealingAlloc`, `seal()` | Rust | The global allocator and the per-thread seal (§3.5) |
| `Visibility` (`Hw`, `Sim`) | Rust trait | `vyrn-cut`'s store-visibility backend (§1.3, §6.4) |
| `pbo_*`, `pbv_*` | C ABI | Oracle and Vx client entry points (`vx/abi/pbv.h`) |
| `W-nn` | ID | A Vx workaround keyed to one vx-lang/Vx issue (§5.5, §5.6) |
| `DeadlineClock` | Rust trait | The injected clock of the deadline test, the engine's one clock read (§3.1) |
| `B-GPU` | ID | The GPU-echo placeholder benchmark (§7.24) |
| `SF-nn` | ID | A `vyrn-sim` fault class (§6.4); SF-30–33 are the pool, SF-34 the pacing SDK, SF-35 the step fill cap |
| `WL-*` | ID | A 02 workload (§7.1) |
| `UNSAFE.toml`, `ASM-GATE.toml`, `vx/FRICTION.md` | files | The unsafe allowlist, the asm gate, the Vx friction log |

## Requests to 01

Accepted in 01 §14.11 and no longer open: the Vx parts ship as shared libraries hosted by Rust
binaries; the seven-module `unsafe` allowlist of §3.2; ZIP-215 Ed25519 verification (§2.5); the ID
prefixes B, WL, SF and M. Resolved elsewhere in 01: `FINALITY_MAX_MS` (§5), `FIN_GATE_BLOCKS`
in both modes (§14.9), and the pool's logged token order (`AcctTake`, §14.17). The rest stay open:

1. **§9, binaries:** add the binary-only packages `bin/vyrn-seq`, `bin/vyrn-validator`,
   `bin/vyrn-admin`, and state that `vyrn-dropcopy` is a second binary of crate `vyrn-md`.
2. **§9, crates:** state that `vyrn-cut` owns every cross-core primitive, including the SPSC rings
   and the per-lane order rings of §14.5 (or add a crate `vyrn-ring` for them).
3. **§5:** add `SHARED_ALIGN = 128` for single-writer lines that cross cores, next to
   `CACHE_LINE` (§3.6), pending B7's 64-versus-128 result.
4. **§5:** add `LANE_MAX_LOAD = 0.60`, the lane load behind DESIGN's 1B msgs/s from 50 lanes;
   with 01 §14.15's ~0.41 at 1B msgs/s, say which of the two budgets B20 should use.
5. **§7, `INV-NOALLOC`:** say that it is per thread, and that a free counts as a violation.
6. **§8:** also register `W-nn` (keyed to vx-lang/Vx issues), `B-GPU`, B21–B39 (02), and the
   chapter-local prefixes `B-REP-*`, `PLT-B-*`, `EPO-T*`, `B-ARC-*`, `B-CHN-*`, `B-RSK*`, `B-MD*`,
   with §7.25 as their registry.
7. **§5 and §10, the lane count:** `N_LANES_REF` = 50, but the §10 core map has 49 lanes (42
   dedicated on cores 8–49, 7 pooled on cores 56–62). Set `N_LANES_REF` = 49 or add a lane; this
   chapter's config and tests use 42 + 7. §14.3 still says lanes 25–49 and the hasher on core 7;
   §14.15 item 3 and §10 put stream-B on core 7 and the hasher on core 50.
8. **§5 and §14.1, the NIC tail:** `NIC_FLOOR_NS` is a p99.99 criterion, but `LAT_MAX_NS` is a
   maximum, and deadline admission sees only the time before the lane dequeues. The TX side after
   the doorbell is not covered. State how the NIC's tail above p99.99 fits the maximum: a B1
   maximum bound, or a share of `DEADLINE_GUARD_NS` (R14).
9. **§8 or §14.1:** name `plt_w2w_ns` (06) as the every-packet measurement of REQ-LAT-1, with
   the capture rig as its calibration (§7.1 rule 6).
10. **§11.3:** add the deadline test as the second permitted clock read, with its output confined
    to the logged shed bit (§3.1).
11. **§5 and §14.15:** `BBO_CROSS_NS` = 40 in §5 against 15 in §14.15 item 2; this chapter gates
    B8 on 15. Name `LANE_PACE` and `STEP_FILL_CAP` in §5, and say which stream core writes the
    `StepRecord`s once the order stream is split in two (§14.5 still names one core 4).
12. **§8:** register `BUSY` per class as B3's metric, with the curves as signed artifacts.
13. **§14.1, §14.15 and §14.17:** `DEADLINE_GUARD_NS` is 30 in §14.1 and 20 in §14.17 item 1;
    §14.15 item 3 still puts control on core 0 with the OS. Align both with §14.17 and the §10
    map (TX-C on core 0, OS and control on core 51). §14.15 item 1's "BUSY = 0 by
    construction" is replaced by §14.17 item 2; say so at §14.15.

## Open questions

1. **ef_vi fast paths through a function table.** If ef_vi's event-queue poll or transmit goes
   through an `ops` pointer, LTO cannot inline it. Owner: 06. Settled by: the asm gate (§4.4) on
   the M0 echo build, and B1 with and without a direct call.
2. **Engine output in the vote.** What exactly a replica signs about its engine output, and when.
   Owner: 07 (09 for CHAIN). Settled by: SF-24 in `vyrn-sim`, which must halt finality and never
   finalise a divergent state.
3. **Which fills stand when the Rust engine is the wrong client.** The sequencer runs the Rust
   engine live, so its fills share the bug. Owner: 07, with product. Settled by: an SF-24 scenario
   with the fault in the Rust engine, run against 07's recovery rule.
4. **Failover onto a Vx box.** Resolved by 01 §14.4: `vyrn-seq` never votes, and failover
   promotes the warm standby in F2, never a voting replica. B19's split check and SF-08/SF-29
   confirm it (§7.22).
5. **The Vx runtime inside a Rust host.** Two runtimes in one process, and Vx code on threads that
   Rust created. This may need a new vx-lang/Vx issue (`W-09`). Owner: 11. Settled by: the M2 embedding smoke
   test and the TSan build of §5.3.
6. **Is vxc output reproducible?** Owner: 11. Settled by: `tools/repro-build` on the Vx libraries
   in M2.
7. **128-byte or 64-byte alignment on x86-64.** Owner: 05 and 01. Settled by: B7's variant.
8. **Who owns the canonical state encoding.** Both clients and the oracle must write it byte for
   byte. Owner: 07 or 05. Settled by: B4 with builds F and G.
9. **`x86-64-v3` against native code generation.** Owner: 06. Settled by: B2 and B8, run both ways
   once per milestone.
10. **Final budget for B15.** 08 has fixed B14 at 1,000 µs at 10⁶ orders. `BLD_MD_LAG_P99_US`
    is still this chapter's placeholder. Owner: 10. Settled by: B15 and B-MD1 in M5.
11. **`predicted_path_ns`.** The deadline test needs a per-packet prediction that is never low.
    Owner: 05, with 06. Settled by: B3, where no admitted packet may exceed `LAT_MAX_NS`, and
    B6/B8 maxima per packet shape.
12. **B-GPU.** Is there a COTS GPU-initiated NIC path to measure at all? Owner: 06. Settled by:
    B-GPU (§7.24), if a candidate exists.
13. **Does the pool meet the M/M/c bound?** Token waits, steal-lock contention and the `PoolRisk`
    token make pool service less regular than M/M/c with c = 7 assumes. Owner: 05, with 10.
    Settled by: B3's pooled curve against the model, and SF-30 in `vyrn-sim` with the B6 costs.
14. **Does `AcctTake` cover every cross-core write in the pool** (settlement of a pooled fill
    event, the `PoolRisk` buckets)? Owner: 05, with 07. Settled by: the `AcctTake` checks and
    SF-33 under `writer-audit` builds, and B4 on a pool log (R15).
15. **Does the pacing SDK hold under the dedicated lane's own background work** (control packets,
    settlement drain, Advance records)? Owner: 05. Settled by: SF-34 and B3's zero lane-stage
    `BUSY` criterion on dedicated lanes.
