# 06. Platform: the Unix host

This chapter specifies the machines and the operating system under every VYRN process: the
parts list per target and per role, the BIOS, the Linux kernel and its tuning, the NIC backends
behind one Rust trait, the C shim, time, memory, AWS, the consumer box, macOS for development,
host security, operating procedures, and the checklist a box passes before it joins a facility.

The engine chapters (05, 07) assume a quiet core, a hardware RX timestamp and a NIC that steers
each packet to the lane that owns it. This chapter is where those assumptions are made true, or
where the text says exactly which target cannot make them true and what it does instead.

## 0. Decisions in one table

| # | Decision | Reason (section) |
|---|---|---|
| P1 | Every `REF` box (sequencer, standby, replica, validator, data node, observer) uses the same board, CPU and memory. Roles differ only in NICs and drives. | The standby `vyrn-seq` takes over on failover (01 §14.4); one spares pool; one BIOS profile (§2.1) |
| P2 | Six cards in the sequencer: four single-port X2541 client cards (each lane has one RX VI on one of them) and two dual-port X2542 replication cards, one per leaf switch. Port a of each is written by stream-A (core 4), port b by stream-B (core 7). | 01 §14.7, §14.15; one CTPIO writer per port with two stream cores; the cards are capacity, the replica set is the redundancy (§2.3) |
| P3 | NPS1, all 12 channels interleaved, L3-as-NUMA off. | Hot state lives in L3; DRAM placement does not change hot latency; one node keeps huge-page accounting simple (§3.1) |
| P4 | SMT off, C-states off, boost on, determinism slider on Performance, fabric P-state fixed. | Frequency becomes a function of the workload, not of silicon or temperature (§3.1) |
| P5 | `isolcpus=managed_irq,domain` + `nohz_full` + `rcu_nocbs` on every core except the housekeeping core `HK` (core 51 on every REF box, core 0 on CONSUMER, `H` on AWS). At most one runnable thread per isolated core, `SCHED_OTHER`. | No tick, no RCU callback, no IRQ, no competitor; no RT throttling (§4) |
| P6 | `mitigations=auto` (the kernel default). | Hot cores make no syscalls, so kernel-entry mitigations cost them nothing; the box runs code that attackers reach (§4.4) |
| P7 | A seccomp filter on every hot thread after `seal()` kills the process on any syscall outside a 9-entry allowlist. | A syscall on a hot core is a bug; fail-stop becomes a bounded failover instead of silent jitter (§5.4) |
| P8 | Five NIC backends behind `vyrn_nic::NicBackend`, dispatched statically: `efvi`, `dpdk`, `afxdp`, `kernel`, `sim`. | C-ONEBIN: one binary per ISA, configuration picks the backend (§6) |
| P9 | IPv4 + UDP only on the fast path, UDP checksum 0, no VLAN tag, no IP options. | CTPIO sends complete frames; the packet MACs already protect integrity (§6.2) |
| P10 | ptp4l on NIC 0 follows the facility grandmaster; phc2sys slaves NICs 1–5 to NIC 0; `vyrn-timemon` measures cross-NIC skew with timestamped probes through the leaf switch. | Level-FIFO order across lanes on different NICs depends on cross-NIC skew, not on absolute time (§8) |
| P11 | A box sequences only in platform state `ELIGIBLE`. Losing the grandmaster is a holdover, not an outage; losing cross-NIC sync or the TSC↔PHC map is. | Fairness and deadline admission depend on the box's own clocks agreeing with each other (§8.4, §8.6) |
| P12 | AWS runs the same x86-64 binary on `c6in.metal`, DPDK on ENA, one NUMA node; `rx_ts` is the TSC at RX completion. | 01 §10, §14.11; ENA gives neither steering nor hardware RX stamps we rely on (§9) |
| P13 | Deadline admission reads `now` in the receiving card's PHC time through a per-card TSC↔PHC line, refreshed every 10 ms from a PTM cross-timestamp. Lanes add the line's error bound to `age`; an error above `DEADLINE_GUARD_NS` = 20 makes the box ineligible. | 01 §14.1 needs `now − rx_ts` in ns on the lane core (§8.4) |
| P14 | A client NIC qualifies on maxima only, over the whole B1 run: RX + TX ≤ `NIC_FLOOR_NS` = 560 ns, TX ≤ 240 ns as a maximum of its own, zero CTPIO fallbacks, and a cross-timestamp error ≤ 10 ns. | Nothing after the TX doorbell can shed a response, so the NIC must be bounded, not ranked by percentile (01 §5, §14.16, §6.3) |
| P15 | The REF core map is 01 §10: CCD 0 holds only the BBO core (2), cuts (1, 6), TX-A/B/C (3, 5, 0) and streams (4, 7); 42 dedicated lanes on 8–49; the hasher on 50; OS, IRQs and control on core 51; spares 52–55 and 63; the pool on CCD 7 (56–62). Every core but 51 is isolated. | 01 §14.15, §14.17; one quiet core per hot thread (§4.9) |
| P16 | The 7 pool cores share 7 ef_vi VIs on one client card. Each VI has a consumer lock; a core with an empty VI steals one frame from a sibling's VI by try-lock. Every lock, token and VI state line lives in CCD 7's L3. | 01 §14.15: the steal path and the token CAS never leave one CCD (§6.3) |

## 1. How this chapter meets the hard constraints

| Constraint | How |
|---|---|
| C-UNIX | Production roles run Linux 6.6+ LTS (§4.1). DEV runs macOS with the `kernel` and `sim` backends, and the full test suite passes there (§11). No hypervisor feature is used: AWS uses `.metal` instances. |
| C-NOCHIP | Every part in §2 is a CPU, an ASIC NIC, a merchant-silicon switch, an NVMe drive or a GNSS time appliance. No FPGA, no P4/Tofino switch, no SmartNIC/DPU program, no GPU. §2.9 lists the excluded parts by name; only the lab benchmark B-GPU (§14.3) can reopen the GPU ban. The integrated GPU of the Ryzen is disabled in the BIOS (§3.2). The AWS Nitro card and the board's BMC run their vendors' firmware, never our logic. The AF_XDP redirect program is eBPF that runs on the host CPU (§6.5). |
| C-COTS | All parts are catalog items. NIC firmware is the vendor's released firmware, pinned by version (§3.3). |
| C-ONEBIN | One `x86_64-unknown-linux-gnu` binary built for `x86-64-v3` (11 §4.3) runs on `REF`, `CONSUMER` and `AWS`. It links every Linux backend. One `aarch64` build exists for Graviton and one for macOS, because an ISA change is a different binary by definition. A TOML file selects the backend, the core map and the time source. |

## 2. Bill of materials

### 2.1 One platform for every REF role

**Decision.** The `REF` sequencer, standby sequencer, replica, validator, data node and observer
share one board, one CPU and one memory configuration.

The reason: failover promotes the home's warm standby `vyrn-seq` within `FAILOVER_TARGET_MS`, never
a voting replica (01 §14.4). The standby is the sequencer's SKU, NICs included, so a failover
does not change the latency bound. Replicas, data nodes and observers could use cheaper CPUs, but
a separate board doubles the spares pool, the BIOS profiles and the validation runs for a saving
of a few thousand dollars per box, and a replica board can be re-carded as a standby.

| Part | Specification | Note |
|---|---|---|
| CPU | 1 × AMD EPYC 9575F: 64 Zen 5 cores, 8 CCDs × 8 cores, 256 MB L3 (vendor), up to 5.0 GHz boost (vendor) | 01 §10 |
| Board | Single-socket SP5. 12 DIMM slots at one DIMM per channel. Eight x16 Gen5 groups wired directly to CPU lanes (no PCIe switch), each usable as a CEM x16 slot or bifurcated to 4 × NVMe x4, plus 2 × M.2 x4 for boot. BMC with Redfish over TLS. UEFI that exposes the AMD CBS options of §3.1. | A PCIe switch adds latency and a failure point between CPU and NIC; §2.3 gives the lane plan per role |
| Memory | 12 × 64 GB DDR5-6400 ECC RDIMM, all 12 channels populated, identical part numbers = 768 GB | Bandwidth needs every channel; one DIMM per channel keeps the trained speed at 6400 MT/s (vendor maximum for 1DPC) |
| Cooling | Sized for the CPU's maximum TDP with every core busy-polling, 35 °C inlet | Busy polling is a 100% load on 63 cores, 24 h a day |
| Boot | 2 × M.2 960 GB enterprise NVMe, software RAID 1 | The OS is replaceable; the log is not on these drives |
| Management | Onboard 1/10GbE port on the management VLAN; BMC port on the out-of-band network | Never on a fast-path NIC (§12) |
| PSU | 2 × redundant, on two facility power feeds | |

### 2.2 Per-role differences on REF

| Role | Process | Fast-path NICs | Log drives | Huge pages (1 GiB) |
|---|---|---|---|---|
| Sequencer and standby | `vyrn-seq` | 4 × X2541 100GbE client (ef_vi + CTPIO); 2 × X2542 2 × 100GbE replication, one card per leaf switch, one port per stream core | none (2 × M.2 boot only) | 640 |
| Replica / validator | `vyrn-replica` / `vyrn-validator` | 4 × X2541 | 12 × 61.44 TB Gen5 TLC NVMe with power-loss protection (PLP) | 640 |
| Data node | `vyrn-data` | 2 × ConnectX-7 2 × 200GbE (DPDK mlx5) | none (payloads are buffered in RAM, then owned by replicas) | 640 |
| Observer (one per facility, 10 §7.1) | `vyrn-replica --observer` + `vyrn-md` | 3 × ConnectX-6 Dx 2 × 100GbE (DPDK mlx5): two take the 4 passive taps on the sequencer's client fibres (RX only), one sends market data on both ports; 3 × X2541 (ef_vi): order frames in on path A and on path B, and a third market-data port (01 §14.16) | 4 × 30.72 TB TLC NVMe, PLP (drop copy and surveillance working set, 10) | 640 |
| Archive node (one per facility) | `vyrn-replica --archive` | 1 × ConnectX-7 2 × 200GbE (`kernel` TCP; 07 owns the transfer) | 24 × 122.88 TB QLC NVMe | 64 |

The archive node is the only box with a different board class: a single-socket SP5 storage chassis
with 24 NVMe bays. Its CPU is any Zen 5 EPYC with ≥ 32 cores. It holds the log segments that are
older than the replica's on-box window (next paragraph), so that 01 §14.7's 7 days are kept inside
the facility. 24 × 122.88 TB is ~2.9 PB (vendor capacity), which is 7 days at up to ~18% average
load; a facility whose measured average is higher adds a second archive node. The archive node
streams continuously: it pulls each block from its voter as soon as the block is final, and it
never waits for a segment to fill (07 §8.4).

Why the replica's log is split from the archive: DESIGN §7 gives ~26 GB/s at sustained peak and
~230 TB per day at 10% average load. Seven days is ~1.6 PB. One single-socket box has 128 PCIe
lanes (vendor), and the replica's four NICs take 64 of them, so no replica can hold a week. The
replica writes to 12 × 61.44 TB Gen5 TLC drives (~737 TB, vendor capacity; ≥ 60 GB/s of write
budget at ~5 GB/s per drive, vendor). That meets 01 §14.16: `PLT_ONBOX_HOT_H_PEAK` ≥ 6 h at
sustained peak (737 TB ÷ 26 GB/s ≈ 7.9 h) and `PLT_ONBOX_HOT_H` = 12 h at ≤ 20% average load
(~225 TB). The 30.72 TB drives of 01 §14.7 (~368 TB) hold only ~3.9 h at sustained peak, which
is why the drive changed (Requests to 01). Retention never blocks replication: the oldest block
goes first, archived or not (07 §8.3). 07 owns the segment format and the retention rule; this
chapter owns the boxes. The recovery service of 01 §14.6, a role on one replica per home, keeps
`RESP_RETAIN_PKTS` per session on these drives: ≤ 3.8 TB at the maximum response size.

### 2.3 PCIe lane plan (REF sequencer, replica, observer)

The EPYC 9575F has 128 Gen5 lanes in four I/O-die quadrants of 32 (vendor). Every device is on
CPU lanes, with no PCIe switch.

```
                 EPYC 9575F I/O die: 4 quadrants × 32 lanes, CCD0-7 over Infinity Fabric
        quadrant P0           quadrant P1           quadrant P2           quadrant P3
        x16     x16           x16     x16           x16     x16           x16     x16
SEQ     NIC0    2×M.2 boot    NIC1    NIC4          NIC2    (empty)       NIC3    NIC5
        client  (x8) +x8 free client  X2542 path A  client                client  X2542 path B
        lanes 0-15            lanes 16-24 a: strm-A lanes 25-40           lanes 41-48 a: strm-A
        TX-A (core 3)         TX-C      b: strm-B   TX-B (core 5)         TX-C,     b: strm-B
        → leaf A              → leaf A  → leaf A    → leaf B              pool 42-48 → leaf B
        used: 6 × 16 + 8 = 104 of 128 lanes
REPLICA NIC0    4×NVMe        NIC1    4×NVMe        NIC2    4×NVMe        NIC3    2×M.2 boot
        path A                data                  path B                data    (x8) +x8 free
        + data                                      + data
        → leaf A              → leaf A              → leaf B              → leaf B
        used: 4 × 16 + 12 × 4 + 8 = 120 of 128 lanes
OBSERVER NIC0   2×M.2 boot    NIC1    NIC3          NIC2    4×NVMe        NIC4    NIC5
        CX-6 Dx (x8) +x8 free CX-6 Dx X2541         CX-6 Dx               X2541   X2541
        taps 0,1              taps 2,3 frames A     MD out a, b           frames B MD out
        RX only               RX only  → leaf A     → leaf A, leaf B      → leaf B → leaf B
        used: 6 × 16 + 16 + 8 = 120 of 128 lanes
```

Rules:

1. Each client NIC is on its own I/O-die quadrant, on CPU lanes, with no PCIe switch. The two
   replication NICs are on two different quadrants. A retimer is allowed only where the board
   requires one for that slot. B1 runs per slot, so a slot whose retimer costs latency fails B1
   and is not used for a NIC.
2. The X2541 is a PCIe Gen3 x16 card (vendor). At ~25M packets/s per direction per client card
   (§6.3) this is ~52 Gbps on the wire per direction, inside Gen3 x16. PLT-B-PPS checks it.
3. Lanes split across client cards in the proportions above. The lane → card map is configuration.
   Clients learn it from 04's session setup as `(ip of card, UDP port)` per lane. Each client port
   has one fill TX core (01 §14.17): TX-A writes NIC0, TX-B NIC2, TX-C NIC1 and NIC3. That gives
   TX-A 16 lanes, TX-B 16 and TX-C 17, of which 7 are the lower-volume pool, so each TX core runs
   near the ≈ 0.22 load of 01 §14.17. TX-A serves only lanes of half A and TX-B only half B; TX-C
   serves both halves, and the frame gate does not care, because every TX core checks both
   halves' release words (07 §4.2). The 7 pool lanes are all on NIC3 (§6.3).
4. Order-stream path A leaves on NIC4 (cabled to leaf A) and path B on NIC5 (cabled to leaf B).
   This meets `REPL_PATHS` = 2 on two switches (01 §14.7). NIC4 and NIC5 are dual-port X2542
   cards (vendor: 2 × 100GbE, PCIe Gen3 x16). Port a of each card is written only by stream-A
   (core 4) and port b only by stream-B (core 7), so each stream core writes its own frames to both
   paths, and each port still has exactly one CTPIO writer (`INV-PLT-7`): no core can make
   another's CTPIO write fall back (§6.3). Each replication port carries ~13 Gbps at peak (07
   §3.13), and client TX load stays at ~52 Gbps per port. Six single-port X2541 cards could not
   do this: two stream cores on one replication port would be two CTPIO writers.
5. On a replica, the data-tier copy of the packets (~190 Gbps at peak, 07) is spread over all four
   ports; NIC0 also takes order-frame path A and NIC2 path B. That is ≤ 70% of 100G per port.
6. The cards are capacity, not redundancy. A failed card or link makes the box unhealthy
   (§13.2), and 07's failover moves the book. There is no lane re-homing inside a box.
7. Observer (01 §14.16). The four tap fibres carry ~52 Gbps each; two of them share one CX-6 Dx
   (PCIe Gen4 x16, vendor), ~104 Gbps per card. Full MBO out is ~208 Gbps (10), spread over
   CX-6 Dx NIC2's two ports and X2541 NIC5, ≤ 70% of each 100G port. Order frames arrive on two
   X2541 ports, one per path, at ~26% each (07 §3.13). The CX-6 Dx cards run the `dpdk` backend
   (§6.4); the taps need hardware RX stamps (§3.3), not CTPIO.

### 2.4 Network in one facility

```
                clients (cross-connects, colo racks)
                    │                         │
             ┌──────┴──────┐  ISL (2×100G) ┌──┴──────────┐
             │   leaf A    │═══════════════│   leaf B    │   merchant silicon,
             │  (PTP BC)   │               │  (PTP BC)   │   cut-through, PTP boundary clock
             └┬───┬───┬──┬─┘               └┬───┬───┬──┬─┘
              │   │   │  └─ GM-1 (primary)  │   │   │  └─ GM-2 (backup)
              │   │   │                     │   │   │
       NIC0 NIC1 NIC4 │              NIC2 NIC3 NIC5 │    vyrn-seq (client 0-3, repl 4-5)
                  │   └─ data nodes, observer   │   └─ data nodes, observer
                  │                             │
       metro path A ──► F2…Fn          metro path B ──► F2…Fn      (07 owns the metro links)
```

Passive optical taps on the sequencer's four client RX fibres feed the observer (10 §7.1). Each
tap's insertion loss must leave the sequencer's optics inside their receive power budget
(PLT-V-4 reads the RX power from the module).

**Switches.** Merchant-silicon L2/L3 switches only. Accepted silicon families: Broadcom
Trident 3/4 and Tomahawk 3/4/5, NVIDIA Spectrum-2/3/4. Example products: Arista 7050X3 and
7060X series, NVIDIA SN3000 and SN4000 series. Requirements:

| Requirement | Value | Check |
|---|---|---|
| Forwarding | Cut-through at 100G → 100G | PLT-B-SW |
| Port-to-port latency | ≤ 800 ns p99 at 50% load (budget) | PLT-B-SW, through a passive splitter |
| PTP | IEEE 1588 boundary clock with hardware timestamps on every 100G port | PLT-V-14 |
| Multicast | IGMP snooping and PIM-SM, for market data | 10 |
| Queues | Strict priority for PTP and `vyrn-timemon` probes (DSCP 46 / PCP 6) | §8.3 |
| Software | The vendor's released NOS; we run no code on the switch | C-NOCHIP |

Switch latency is outside `LAT_MAX_NS`, because REQ-LAT-1 starts at the exchange NIC. It is inside
the order-frame path and the finality budget (07).

### 2.5 PTP grandmaster

**Decision.** Two GNSS-disciplined grandmaster appliances per facility, one on each leaf, from the
Meinberg LANTIME M-series or Microchip TimeProvider 4100 class, with a rubidium or OCXO holdover
oscillator. GM-1 has BMCA `priority1` 100, GM-2 has 110. We configure them and run no logic on
them. Each has its own GNSS antenna feed and a 1PPS output that the lab uses to calibrate.

### 2.6 CONSUMER

| Part | Specification | Note |
|---|---|---|
| CPU | AMD Ryzen 9 9950X3D: 16 Zen 5 cores, 2 CCDs, 128 MB L3, 3D V-cache on one CCD (vendor) | 01 §10 |
| Board | AM5 board with ECC UDIMM support and a CPU-attached x16 slot; a BMC is preferred (server-class AM5, e.g. ASRock Rack B650D4U class) | ECC is not optional for a book |
| Memory | 2 × 64 GB DDR5-5600 ECC UDIMM, both channels, 1DPC = 128 GB | JEDEC speed, no EXPO (§3.2) |
| Client NIC | 1 × X2541 100GbE in the CPU x16 slot | Must pass B1 |
| Second NIC | 1 × X2522 2 × 25GbE in an x4 slot, order-stream path B only (01 §14.7); one port to the second switch | `REPL_PATHS` = 2 needs a second switch path; ~5 Gbps of order stream at ~220M msgs/s. If the slot is chipset-attached, path B sends by DMA, not CTPIO, so the TX core never writes frame bytes across the chipset link; `INV-FRAME-FIRST` orders the writes to the TX queues, and path B's wire time counts against finality only |
| Drives | 2 × 4 TB PCIe Gen5 M.2 on CPU lanes (log), 1 × 1 TB M.2 on chipset lanes (boot) | |
| GPU | None. The integrated GPU is disabled in the BIOS. Console over BMC or serial. | C-NOCHIP |

A ConnectX-6 Dx dual-port 100GbE can replace both NICs (one port per switch path) if it passes B1
on this board with the `dpdk` backend. Until it does, the X2541 + X2522 pair is the BOM.

### 2.7 AWS

| Role | Instance | Storage | Note |
|---|---|---|---|
| Sequencer | `c6in.metal` (x86-64, 200 Gbps rated, vendor) | EBS gp3 boot only | §9.1 |
| Replica / validator | `m6idn.metal` (x86-64, 200 Gbps rated, local NVMe instance store, vendor) | instance store for the hot log; S3 for older segments (07) | §9.1 |
| Data node | `c6in.metal` | EBS boot | |
| Observer + `vyrn-md` | `m6idn.metal` | instance store | No taps and no multicast in a VPC: payloads from the data tier, unicast fan-out (10) |

Every instance has one management ENI on the kernel `ena` driver and one or more data ENIs bound
to `vfio-pci` for DPDK (§9.2). `.metal` is required: `nohz_full` and isolation need a host
kernel that owns the physical cores, and a hypervisor would add exits we cannot see.

### 2.8 DEV

Any Apple M-series Mac with ≥ 32 GB of memory and macOS 14 or later. No NIC requirement. §11
lists what runs.

### 2.9 Excluded parts

| Part | Why excluded |
|---|---|
| Arista 7130 series (Metamako heritage), Cisco Nexus 3550-F (Exablaze heritage) and every other FPGA-based switch or L1 fabric | C-NOCHIP: programmable logic in the forwarding path |
| Tofino / P4-programmable switches | C-NOCHIP |
| NVIDIA BlueField DPUs, AMD Pensando DPUs, Intel IPUs, in any mode | C-NOCHIP: a DPU can run our logic, so it is not on the BOM even as a plain NIC |
| AMD Alveo cards and FPGA-based Solarflare variants (e.g. Alveo UL3524), Napatech and Exablaze capture cards | C-NOCHIP. The B1 capture rig (§14.2) uses ASIC NICs too |
| GPUs of any kind on any role, including GPU-initiated networking (GPUDirect-class RX/TX driven from GPU kernels) | C-NOCHIP; DESIGN §10. Banned until B-GPU (§14.3) passes and 01 changes C-NOCHIP |
| Chipset-attached or PCIe-switch-attached fast-path NICs on REF | Latency and shared uplink |

## 3. BIOS and firmware

Board vendors name these options differently. The names below are AMD's CBS names. Validation
(§14) checks the **effect** from Linux, never the menu text, so a renamed option cannot pass with
the wrong value.

### 3.1 REF (EPYC 9575F)

| Setting | Value | Reason | Check from Linux (PLT-V) |
|---|---|---|---|
| SMT | Disabled | A sibling thread shares the core's L1, L2 and execution ports. 49 lanes need 49 whole cores. SMT off also removes cross-thread side channels. | `/sys/devices/system/cpu/smt/active` = 0; 64 CPUs online |
| Global C-state Control | Disabled | No core or package enters a deep C-state, so no wake-up latency, no L2 flush on an idle spare core that the failover lane then needs | `cpupower idle-info`: only `POLL` and `C1` |
| DF C-states | Disabled | The data fabric never sleeps between bursts, so a cross-CCD line or a PCIe write never pays a fabric wake-up | PLT-B-HOP maximum |
| APBDIS | 1, Fixed SOC P-state = P0 | Fixes the fabric and I/O-die clocks. A fabric frequency change moves every cross-CCD hop and every DMA. | PLT-B-HOP maximum ≤ 1.3 × p50 |
| Core Performance Boost | Enabled | 30 ns per message (`LANE_NS_PER_MSG`) assumes boost clocks | `scaling_cur_freq` > base on hot cores |
| Determinism Control / Slider | Manual / Performance | Frequency becomes a function of the workload only, the same on every box of the replica set. A failover target then has the sequencer's latency. Power determinism gives a few % more clock on good silicon, but that clock varies box to box and with temperature. | PLT-V-10: every hot core within 1% of the fleet median frequency |
| cTDP / PPT | Maximum the part allows | Boost stays available with 63 cores busy | PLT-V-10 |
| NUMA nodes per socket (NPS) | NPS1 | One node, 12 channels interleaved. Hot state (BBO arrays, level heads, rings) lives in L3, so DRAM locality does not change hot latency, and NPS1 gives every CCD the full bandwidth. NPS4 would add per-quadrant huge-page pools with no measured gain. | `numactl -H`: 1 node, ~768 GB |
| ACPI SRAT L3 Cache as NUMA Domain | Disabled | It would expose 8 NUMA nodes whose memory is still interleaved over all channels, so a "node-local" allocation would not be local. `vyrn-seq` reads CCD membership from `/sys/devices/system/cpu/cpuN/cache/index3/id`, which is correct in both modes. The lab may enable it to build the Vx CCD fleet file (11 §5.5); production boxes do not. | 1 node |
| Memory interleave | Channel interleave on, 12-way | Uniform latency and full bandwidth | PLT-B-MEM |
| Memory speed | 6400 MT/s (6000 if the board caps 1DPC at 6000) | Vendor maximum | `dmidecode -t 17`: configured speed on all 12 |
| DRAM power-down | Disabled | No exit latency on a DRAM access | — |
| Patrol scrub | Enabled, vendor default interval | Finds latent ECC errors before a read does; costs negligible bandwidth | EDAC shows the scrubber |
| ECC error handling | OS-first where the board offers it | Firmware-first handling raises SMIs, which stall every core | Quiet probe (§4.11) |
| TSME (memory encryption) | Enabled | Protects session keys and the block-signing key against physical DRAM extraction in a shared colo. Hot state is in L3, where it is plaintext anyway. B3 runs with it on. | `dmesg`: SME/TSME active |
| SEV / SEV-SNP | Disabled | No VMs | — |
| IOMMU | Enabled; ACS enabled | vfio-pci needs IOMMU groups; Linux runs it in passthrough for kernel drivers (§4.2) | `dmesg`: AMD-Vi, `iommu=pt` |
| PCIe ASPM | Disabled (also `pcie_aspm=off`) | An L0s/L1 exit costs microseconds on the first packet after a quiet gap | `lspci -vv`: `LnkCtl: ASPM Disabled` on every NIC and NVMe |
| PCIe speed | Auto | The X2541 trains at Gen3 x16, NVMe at Gen5 x4 | `LnkSta` matches |
| PCIe PTM (Precision Time Measurement) | Enabled on every root port that has a client NIC | The TSC↔PHC cross-timestamp of §8.4 needs it | `lspci -vv`: `PTMControl: Enabled` on root port and NIC |
| SR-IOV | Disabled | ef_vi uses VIs, DPDK uses PFs; VFs add nothing | — |
| Above 4G decoding | Enabled | Large BARs | — |
| Secure Boot | Enabled, our db key enrolled | §12 | `mokutil --sb-state` |
| Watchdog (BIOS) | Disabled; BMC watchdog off | A watchdog reset of a sequencer is an unplanned failover | — |

### 3.2 CONSUMER (Ryzen 9 9950X3D)

| Setting | Value | Reason |
|---|---|---|
| SMT | Disabled | As REF |
| Precision Boost Overdrive | Disabled | PBO raises power limits and clocks by silicon quality and temperature. That makes latency vary by box and by hour. Stock boost is deterministic enough. |
| Curve Optimizer | Off | Same reason; an unstable per-core offset is a silent miscompute risk for a replicated state machine |
| Core Performance Boost | Enabled | |
| Global C-state Control | Disabled | As REF |
| Power Supply Idle Control | Typical Current Idle | Avoids the low-current idle state |
| CPPC / preferred cores | Enabled (no effect) | We pin every thread; scheduler hints are irrelevant |
| Memory | JEDEC DDR5-5600, EXPO off, ECC on | EXPO is an overclock. A memory error in a book is a fork. |
| Integrated GPU | Disabled | C-NOCHIP; removes its interrupts and its share of memory bandwidth |
| PCIe ASPM | Disabled | As REF |
| IOMMU | Enabled, `iommu=pt` | As REF |

### 3.3 Firmware pinning

Every box records five versions in its platform report (§14): BIOS, BMC, each NIC's firmware
(`sfboot`/`sfupdate` for Solarflare, `mlxfwmanager` for ConnectX), each NVMe drive's firmware, and
the PTP grandmaster's firmware. A facility runs one version of each per role. A firmware change is
rolled to one box, which runs the full §14 checklist and B1–B5, before the rest. Firmware changes
happen only in a maintenance window (§13.4).

Solarflare X2541 options set with `sfboot`: PXE boot disabled, SR-IOV disabled, and the
firmware variant under which ef_vi CTPIO and hardware RX/TX timestamps both work. The variant is
not trusted by name: PLT-V-11 opens a VI with `EF_VI_TX_CTPIO | EF_VI_RX_TIMESTAMPS` and sends
and receives one stamped frame. Where a card SKU gates hardware timestamping behind a vendor
licence, the BOM buys the SKU or licence that enables it; a card without it fails PLT-V-11.
ConnectX options set with `mlxconfig`: `REAL_TIME_CLOCK_ENABLE=1` (timestamps in ns of PTP
time), `SRIOV_EN=0`.

## 4. The Linux kernel

### 4.1 Version policy

**Decision.** Production runs one exact kernel version per facility, taken from a kernel.org
long-term branch no older than 6.6. The default in draft 0.1 is the newest 6.12.y that has passed
§14 on every role. A distribution kernel (Debian 13, RHEL 10) is allowed when its config meets the
list below.

The reasons: LTS branches get security fixes for years without feature churn, and 6.6 is the
oldest branch with everything this chapter needs (the `isolcpus` flags, `nohz_full` with the
residual tick offloaded, XDP RX timestamp hints from 6.3, `hugepages=<node>:<count>`).

Required config:

```
CONFIG_NO_HZ_FULL=y          CONFIG_RCU_NOCB_CPU=y        CONFIG_CPU_ISOLATION=y
CONFIG_HUGETLBFS=y           CONFIG_TRANSPARENT_HUGEPAGE=y (set to never at boot)
CONFIG_PTP_1588_CLOCK=y      CONFIG_VFIO_PCI=m            CONFIG_XDP_SOCKETS=y
CONFIG_BPF_SYSCALL=y         CONFIG_BPF_JIT=y             CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_LOCKDOWN_LSM=y  CONFIG_MODULE_SIG_FORCE=y CONFIG_IO_URING=y
CONFIG_PREEMPT_VOLUNTARY=y   (not PREEMPT_RT)             CONFIG_X86_AMD_PSTATE=y
CONFIG_AMD_MEM_ENCRYPT=y     CONFIG_EDAC_AMD64=m          CONFIG_SENSORS_K10TEMP=m
CONFIG_PCIE_PTM=y
```

`PREEMPT_RT` is not used. It shortens the wake-up latency of woken tasks. No hot thread is ever
woken: it never sleeps. RT adds cost to locks on the housekeeping core and nothing to hot cores.

Out-of-tree modules: the Onload/ef_vi kernel driver (`sfc`, `sfc_char`, `sfc_resource`, `onload`
built from the vendored Onload release, 11 §4.2) and nothing else. They are signed with the
facility's module key (§12), because the kernel enforces `MODULE_SIG_FORCE`.

A kernel upgrade follows §3.3: one box, full §14, B1–B5, then the facility, in maintenance windows.

### 4.2 Boot parameters

Every REF box (64 cores; core 51 is housekeeping, 01 §10; one command line for every role, so a
standby or a re-carded replica needs no reboot to sequence):

```
isolcpus=managed_irq,domain,0-50,52-63 nohz_full=0-50,52-63 rcu_nocbs=0-50,52-63 rcu_nocb_poll irqaffinity=51
default_hugepagesz=1G hugepagesz=1G hugepages=640 transparent_hugepage=never
nosmt processor.max_cstate=1 cpufreq.default_governor=performance amd_pstate=active
tsc=reliable clocksource=tsc nosoftlockup nowatchdog nmi_watchdog=0 skew_tick=1
numa_balancing=disable iommu=pt pcie_aspm=off mitigations=auto lockdown=integrity
nvme.poll_queues=8 quiet loglevel=3 console=ttyS0,115200
```

CONSUMER (16 cores; core 0 is housekeeping and control):

```
isolcpus=managed_irq,domain,1-15 nohz_full=1-15 rcu_nocbs=1-15 rcu_nocb_poll irqaffinity=0
default_hugepagesz=1G hugepagesz=1G hugepages=104 transparent_hugepage=never
nosmt processor.max_cstate=1 cpufreq.default_governor=performance amd_pstate=active
tsc=reliable clocksource=tsc nosoftlockup nowatchdog nmi_watchdog=0 skew_tick=1
numa_balancing=disable iommu=pt pcie_aspm=off mitigations=auto lockdown=integrity
nvme.poll_queues=4 quiet loglevel=3
```

AWS: generated by `vyrn-admin gen-cmdline --target aws`, which reads the instance topology and the
ENA devices' NUMA node (§9.3). On `c6in.metal` the result has the form below, where `H` is the
first core of the ENA node, `I` is the rest of that node, and the other node's cores stay
non-isolated for consensus, admin and catch-up work:

```
isolcpus=managed_irq,domain,<I> nohz_full=<I> rcu_nocbs=<I> rcu_nocb_poll irqaffinity=<H>,<other node>
default_hugepagesz=1G hugepagesz=1G hugepages=<ena node>:<N>,<other node>:16
transparent_hugepage=never nosmt intel_idle.max_cstate=1 processor.max_cstate=1
cpufreq.default_governor=performance tsc=reliable clocksource=tsc nosoftlockup nowatchdog
nmi_watchdog=0 skew_tick=1 numa_balancing=disable iommu=pt mitigations=auto lockdown=integrity
```

Every parameter and its reason:

| Parameter | Reason |
|---|---|
| `isolcpus=managed_irq,domain,<I>` | `domain` removes the cores from scheduler load balancing, so only an explicitly pinned thread runs there. `managed_irq` keeps managed interrupts (NVMe and NIC kernel queues) off isolated cores whenever the IRQ's mask contains a housekeeping core. |
| `nohz_full=<I>` | With one runnable task, the core runs with no scheduler tick. Since 4.17 the residual 1 Hz tick is offloaded to housekeeping. It also makes housekeeping the home of unbound kthreads. |
| `rcu_nocbs=<I>` `rcu_nocb_poll` | RCU callbacks of isolated cores run in `rcuo` kthreads on `HK`. Polling means the isolated core never has to wake those kthreads with an IPI. |
| `irqaffinity=<HK>` | The default affinity of every non-managed IRQ is `HK`. On REF, core 0 is the boot CPU and is still isolated (it runs TX-C): the kernel must accept `nohz_full` on the boot CPU while `HK` keeps the timekeeping duty, which PLT-V-5 checks (`/sys/devices/system/cpu/nohz_full` lists core 0; Open question 13). |
| `hugepages=…` 1G | Every hot region is 1 GiB pages: few TLB entries, no page-table walks into DRAM. Reserved at boot because 1 GiB pages cannot be assembled reliably after memory fragments. |
| `transparent_hugepage=never` | No `khugepaged` scanning and no compaction stalls; every huge page is explicit. |
| `nosmt` | Belt and braces with the BIOS setting; on AWS, where the BIOS is not ours, it is the only way to turn SMT off. |
| `processor.max_cstate=1` (`intel_idle.max_cstate=1` on AWS) | Idle cores (`HK` between work, spare cores) use C1 only. Hot cores never idle: they poll. |
| `cpufreq.default_governor=performance` `amd_pstate=active` | The highest performance request from boot, with EPP = performance. |
| `tsc=reliable` `clocksource=tsc` | Zen 5 and Ice Lake have an invariant TSC. `reliable` turns off the clocksource watchdog, which can otherwise demote the TSC to HPET after a long SMI or a false alarm, after which every `clock_gettime` on `HK` becomes a syscall and every TSC map (§8.4) is wrong. |
| `nosoftlockup` `nowatchdog` `nmi_watchdog=0` | The soft-lockup detector and the perf-NMI hard-lockup detector both fire periodically on every CPU. A busy-polling core looks like a lockup to them. |
| `skew_tick=1` | Offsets the ticks of non-isolated cores so that they do not contend on the same locks. |
| `numa_balancing=disable` | Automatic NUMA balancing unmaps pages to sample accesses. On a hot core that is a page fault. |
| `iommu=pt` | Kernel drivers (sfc for ef_vi, mlx5 bifurcated, NVMe) DMA through an identity mapping: no IOTLB misses. vfio-pci devices still get a translated domain, which DPDK fills with 1 GiB IOVA = VA mappings. |
| `pcie_aspm=off` | As §3.1. |
| `mitigations=auto` | §4.4. |
| `lockdown=integrity` | §12. |
| `nvme.poll_queues=8` | Replica log writers use polled I/O queues with no interrupts (§4.7). |
| `quiet loglevel=3` | Console output on the serial port is synchronous and slow; keep it to errors. |

### 4.3 Housekeeping work that must not reach isolated cores

The boot parameters do not cover everything. `vyrn-tune.service` (§4.8) does the rest before any
`vyrn-*` process starts:

1. Writes `HK` (51 on REF, 0 on CONSUMER) or the AWS housekeeping list to
   `/sys/devices/virtual/workqueue/cpumask`, so unbound workqueues run on housekeeping.
2. Sets every writable `/proc/irq/*/smp_affinity_list` to the housekeeping list. A write that
   fails with `EIO` is a managed IRQ; it is checked in step 6 instead.
3. Reduces the kernel netdev queues of every fast-path port to 2 (`ethtool -L <dev> combined 2`)
   and pins their IRQs to `HK`. ef_vi VIs and DPDK queues use no interrupts at all.
4. Writes `0` to `/sys/kernel/mm/ksm/run` and `never` to
   `/sys/kernel/mm/transparent_hugepage/defrag`.
5. Masks `irqbalance.service`, `tuned.service`, `systemd-oomd.service`, `fstrim.timer` and
   `systemd-timesyncd.service`, and stops `chronyd` on boxes where phc2sys owns the system clock.
6. Verifies, and fails the unit if any check fails: no IRQ in `/proc/irq/*/effective_affinity_list`
   names an isolated core, except NVMe queues whose mask is that one core (§4.7); no kthread other
   than the per-CPU bound ones (`ksoftirqd/N`, `migration/N`, `cpuhp/N`, `kworker/N:*`) has an
   isolated core in its affinity.

### 4.4 CPU vulnerability mitigations

**Decision.** `mitigations=auto`, the kernel default. We do not turn mitigations off.

The reasons:

- **They cost the hot path nothing.** Spectre v2, Retbleed, SRSO and similar mitigations act on
  kernel entry, exit and context switches. A hot core makes no syscall, takes no interrupt and
  never context-switches after `seal()` (P7). Its user-mode code runs at the same speed with or
  without them. On Zen 5 the remaining user-visible control, speculative store bypass disable, is
  in `prctl` mode by default and is off for our threads.
- **`HK` pays a little.** Housekeeping, ptp4l and control-plane syscalls get slower by a few
  percent. Nothing on `HK` is on the 1 µs path.
- **The box runs code that attackers reach.** Validators accept packets from the public internet
  (09), and replicas run Commonware's p2p stack. A local privilege escalation after a memory-safety
  bug in a dependency is the threat that mitigations reduce.
- SMT is off, which already removes the cross-thread attacks (MDS, L1TF class) whose mitigations
  are the expensive ones.

PLT-B-MIT runs B3 with `mitigations=auto` and with `mitigations=off` on one lab box. If the cross
p99.99 or the maximum differs by more than 1%, this decision is reopened with that number. The expected difference
is zero.

### 4.5 sysctls

`/etc/sysctl.d/90-vyrn.conf`, applied before any `vyrn-*` process starts and never changed
while one runs (§4.9 rule 5):

```
kernel.numa_balancing = 0            # as numa_balancing=disable
kernel.watchdog = 0                  # soft and hard lockup detectors off
kernel.nmi_watchdog = 0
kernel.sched_autogroup_enabled = 0
kernel.timer_migration = 1           # timers queued on isolated cores migrate to housekeeping
vm.stat_interval = 120               # per-CPU vmstat folding every 120 s, not every 1 s
vm.swappiness = 0                    # and no swap device exists
vm.zone_reclaim_mode = 0
vm.compaction_proactiveness = 0      # no proactive compaction
vm.compact_unevictable_allowed = 0   # compaction never migrates mlocked pages (a migration is a fault)
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2         # only CAP_SYS_PTRACE may attach
kernel.unprivileged_bpf_disabled = 1
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 2
kernel.core_pattern = |/bin/false    # no core dumps: they would contain keys
fs.suid_dumpable = 0
net.core.bpf_jit_harden = 2
```

### 4.6 cpusets and cgroups

cgroup v2, managed by systemd:

```
-.slice
 ├─ init.scope        AllowedCPUs=HK       (REF: 51)
 ├─ system.slice      AllowedCPUs=HK       sshd, journald, ptp4l, phc2sys, vyrn-timemon, vyrn-admin
 ├─ user.slice        AllowedCPUs=HK       operator shells
 └─ vyrn.slice        AllowedCPUs=0-63   vyrn-seq | vyrn-replica | vyrn-data | vyrn-md (one per box)
```

`/etc/systemd/system.conf` sets `CPUAffinity=HK`, so every service starts on `HK` unless its
slice allows more. `vyrn.slice` allows every core, and the process pins each of its threads to
exactly one core with `sched_setaffinity` from its core map. `isolcpus=domain` guarantees that
nothing else is scheduled there. No cpuset partition (`cpuset.cpus.partition=isolated`) is used:
the boot-time isolation already covers it, and `managed_irq` has no cgroup equivalent.

### 4.7 IRQ affinity and the NVMe exception

After `vyrn-tune`, the only interrupts in the system go to `HK`, with one exception that is by
design: an NVMe I/O queue whose managed affinity mask is a single isolated core. Linux creates one
such queue per CPU, and `managed_irq` cannot move an IRQ whose mask has no housekeeping core. The
queue only interrupts when I/O is submitted from that core. Hot cores never submit I/O, so those
IRQ lines stay at zero; the quiet probe (§4.11) and PLT-V-7 check it.

Replica log writers (07) run on WARM cores (§4.9) and use io_uring with `IORING_SETUP_IOPOLL` on
the NVMe poll queues (`nvme.poll_queues`), with `O_DIRECT`. Polled queues have no interrupt line
at all.

### 4.8 systemd units

| Unit | Type | Purpose |
|---|---|---|
| `vyrn-tune.service` | oneshot, `Before=vyrn-time.target vyrn.slice` | §4.3; fails the boot if a check fails |
| `vyrn-ptp4l.service` | simple | ptp4l on NIC 0 (§8.2), `CPUAffinity=HK` |
| `vyrn-phc2sys@nicK.service` | simple, K = 1…5 | NIC K's PHC follows NIC 0's PHC |
| `vyrn-phc2sys-sys.service` | simple | `CLOCK_REALTIME` follows NIC 0's PHC |
| `vyrn-timemon.service` | simple | Cross-NIC skew probe, per-card TSC↔PHC map, time state machine (§8.3, §8.4, §8.6) |
| `vyrn-time.target` | target | Reached when `vyrn-timemon` reports `LOCKED` or `HOLDOVER` |
| `vyrn-admin.service` | notify | Health beacon, drain, platform report (§13) |
| `vyrn-seq.service` / `vyrn-replica.service` / … | notify | The role process |

`vyrn-seq.service`:

```ini
[Unit]
Description=VYRN      sequencer
Requires=vyrn-tune.service vyrn-time.target
After=vyrn-tune.service vyrn-time.target network-online.target

[Service]
Type=notify
User=vyrn
Group=vyrn
Slice=vyrn.slice
ExecStart=/opt/vyrn/bin/vyrn-seq --config /etc/vyrn/seq.toml
# Never restart a sequencer automatically. A restarted sequencer is stale; 07's failover
# has already promoted a replica. vyrn-replica.service uses Restart=on-failure instead.
Restart=no
TimeoutStartSec=900
WatchdogSec=10
LimitMEMLOCK=infinity
LimitCORE=0
LimitNOFILE=65536
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_IPC_LOCK
NoNewPrivileges=yes
RestrictRealtime=yes
OOMScoreAdjust=-1000
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK AF_XDP
SystemCallArchitectures=native
ReadWritePaths=/var/lib/vyrn /run/vyrn /dev/hugepages1G
DevicePolicy=closed
DeviceAllow=/dev/sfc_char rw
DeviceAllow=/dev/onload rw
DeviceAllow=/dev/vfio/vfio rw
DeviceAllow=char-vfio rw
```

`WatchdogSec` is fed by the control thread only. A stalled control thread means the box cannot
take part in epochs or drains, so systemd kills it, which is a failover. `TimeoutStartSec` covers
prefaulting 640 GiB (§5.3). `RestrictRealtime=yes` enforces §4.10.

### 4.9 Core classes and the rules for each

| Class | Cores (REF) | Rules |
|---|---|---|
| HOT | REF: dedicated lanes (8–49), pooled lanes (56–62), cut A and B (1, 6), BBO (2), fill TX A, B and C (3, 5, 0), order-stream A and B (4, 7), order hasher (50) | One thread per core. After `seal()`: no syscall (seccomp-enforced, §5.4), no allocation (`INV-NOALLOC`), no page fault, no blocking lock, no clock read except the RX timestamp path and the `rdtsc` of deadline admission (§8.4). The pool cores alone use two CCD-local try-locks, the account token and the VI consumer lock (§6.3); a failed CAS moves on and never spins. |
| WARM | replica log writers, frame RX and consensus cores (07's replica map); the role's control thread wherever it runs | One thread per core, isolated, except the control thread. Syscalls allowed. No `munmap`, `mprotect`, `madvise(DONTNEED)` or `mremap` of memory the process has mapped (rule 1). Allocation from a preallocated arena only. |
| HOUSE | `HK`: core 51 on REF, core 0 on CONSUMER; the non-ENA node on AWS | Everything else: kernel, sshd, ptp4l, phc2sys, vyrn-timemon, vyrn-admin, journald. On REF and CONSUMER `HK` also runs the role's control thread (admin, epoch, metrics, lane watchdog, finality listener; 01 §10), which keeps the WARM rules. Core 51 is on CCD 6, away from CCD 0's latency cores. |

Rules that apply to the whole box while a role process is `ACTIVE`, because each one sends an IPI
to every core, isolated or not:

1. **No TLB shootdown in the role process.** `munmap`, `mprotect`, `mremap` and
   `madvise(MADV_DONTNEED)` on memory the process has mapped send a flush IPI to every CPU that
   runs a thread of that process, which includes every hot core. The WARM-class allocator never
   returns memory, and a process-wide seccomp rule returns `EPERM` for these calls after `seal()`
   and counts them.
2. **No kernel text patching.** Enabling ftrace, kprobes, a tracepoint, or anything that flips a
   static key calls `text_poke`, which synchronises every CPU with an IPI. `perf` on an isolated
   core also uses NMIs. These tools are for lab boxes and for boxes in `DRAINED`.
3. **No module load or unload and no BPF program load.** Both can purge lazy vmap areas, which
   flushes the kernel TLB on every CPU. The AF_XDP program is loaded before `seal()`.
4. **No MSR read of another core.** `/dev/cpu/N/msr` and `turbostat` run `rdmsr` on core N through
   an IPI. Temperature comes from `k10temp` (read through the SMN, no IPI), and frequency is
   checked at validation time only.
5. **No sysctl or sysfs write that changes kernel behaviour,** including `drop_caches`,
   `compact_memory`, `nr_hugepages` and the `numa_balancing` toggle.
6. **No CPU hotplug and no cpufreq governor change.**

`vyrn-admin` refuses these operations on a box whose role process is `ACTIVE` and logs the attempt.

### 4.10 Why hot cores do not use SCHED_FIFO

**Decision.** Every hot and warm thread runs `SCHED_OTHER` at nice 0, alone on its core.
`RestrictRealtime=yes` forbids anything else.

- **There is nothing to win against.** A real-time policy decides who runs when two threads are
  runnable on one core. `isolcpus=domain` and pinning guarantee there is only ever one.
- **SCHED_FIFO would hurt.** The default RT throttle (`sched_rt_runtime_us` = 950000) takes the
  core away from a 100%-busy FIFO thread for 50 ms of every second. Turning the throttle off
  instead lets a FIFO busy-loop starve the per-CPU kthreads that must run occasionally on every
  core (`ksoftirqd/N`, `migration/N`, the stop machine), which turns a rare 2 µs interruption into
  an RCU stall or a hung CPU-hotplug operation.
- **`SCHED_OTHER` with `nohz_full` stops the tick** once the core has exactly one runnable task.
  A per-CPU kthread that wakes up on a hot core is a gap above `PLT_JITTER_MAX_NS`, which the
  quiet probe fails and the live gap metric reports (§4.11).

### 4.11 The quiet-core probe

A core is quiet when nothing but our thread runs on it. The probe measures that directly.

```rust
/// Runs on one isolated core, pinned, after seal(). Records every gap between two
/// consecutive TSC reads that is longer than PLT_JITTER_FLOOR_NS.
pub fn quiet_probe(core: CoreId, window: Duration, tsc: &TscMap) -> ProbeReport {
    let floor = tsc.ns_to_ticks(PLT_JITTER_FLOOR_NS);
    let end = rdtsc_ordered() + tsc.ns_to_ticks(window.as_nanos() as u64);
    let mut hist = GapHist::new();          // preallocated: log2 buckets from 16 ns to 1 ms
    let mut prev = rdtsc_ordered();          // lfence; rdtsc
    while prev < end {
        let now = rdtsc_ordered();
        let gap = now - prev;
        if gap > floor { hist.record(tsc.ticks_to_ns(gap)); }
        prev = now;
    }
    ProbeReport { core, hist, irq_delta: read_irq_counts_delta(core) }
}
```

The same gap measurement runs inside every production hot loop: each idle `Core::poll` iteration
(one that found no work) compares its TSC with the previous iteration's and records gaps above
`PLT_JITTER_FLOOR_NS` in a per-core histogram that the control core exports. So the probe is also
a live metric (`plt_loop_gap_ns`), and it does not count the core's own work, which the budgets
already price.

Why the thresholds are maxima and not counts: a gap on a hot core after a packet has passed
deadline admission (01 §14.1) makes that packet's response late by the gap. Nothing can shed the
packet afterwards. So every gap must fit inside the guard: `PLT_JITTER_MAX_NS` = 20 ns for gaps, which is all of `DEADLINE_GUARD_NS` = 20 (01 §14.1). The
TSC↔PHC error and the ≤ `PLT_RX_STAMP_CAL_NS` = 10 ns calibration error of the RX stamp against
the first bit (§14.2) are not in the guard; lanes add both to `age` (§8.4).

Pass thresholds per isolated core, over `PLT_JITTER_WINDOW_S` = 600 s (budget):

| Measure | Pass |
|---|---|
| Largest gap | ≤ `PLT_JITTER_MAX_NS` = 20 ns |
| `/proc/interrupts` delta for the core, every line including `LOC` | 0 |
| Context switches of the probe thread (`/proc/<pid>/task/<tid>/status`) | 0 |

The probe runs on all isolated cores at once, with the role process stopped and with
synthetic load on `HK` (ssh, `journalctl -f`, a 1 GB/s `dd` to a boot drive), because
housekeeping load is what leaks. `rtla osnoise` (kernel tools) runs as a second opinion during
validation only: it agrees with the probe or the box fails. A gap that the probe sees but
`/proc/interrupts` does not explain is an SMI or a firmware event, and the box goes back to §3.

## 5. Memory

### 5.1 Huge-page layout

Every hot region is a 1 GiB huge page from one hugetlbfs mount, `/dev/hugepages1G`
(`pagesize=1G`, mode 0770, group `vyrn`). Regions are anonymous `MAP_PRIVATE | MAP_HUGETLB |
MAP_HUGE_1GB` mappings, except the trace rings, which are files on that mount so that
`vyrn-admin trace dump` can read them after a crash (11 §3.8).

Budget layout of a REF sequencer (sizes are reservations; 05 and 04 own the contents):

| Region | Owner (writer) | Per | Pages | Total |
|---|---|---|---|---|
| Lane arena: FIFO slots (2^`SLOT_BITS` × 32 B), level arrays, tombstones | lane L | lane | 1 | 49 |
| Lane state: sessions, accounts, risk, rate limits | lane L | lane | 1 | 49 |
| Response hot ring (`RESP_HOT_RING_BYTES`, 01 §14.6) | lane L | lane | 4 | 196 |
| Pool: shared session table, account tokens, VI consumer locks (§6.3, 05) | pool cores | pool | 1 | 1 |
| Filled-quantity array (49 × 2^24 × 4 B = 3.3 GB) | BBO core | book | 4 | 4 |
| BBO state, snapshot seqlock, step log staging | BBO core | book | 1 | 1 |
| SPSC rings lane → BBO, BBO → lane, BBO → TX A/B/C | producer of each ring | book | 2 | 2 |
| Cut half-lines (cores 1 and 6) and lane counters | cut cores / lanes | book | 1 | 1 |
| NIC packet buffers (RX rings of its lanes, TX fallback buffers) | vyrn-nic, registered per NIC | NIC | 1 | 6 |
| Order-stream staging and frame ring, one per stream core (07 §4.1) | stream-A, stream-B | stream | 3 | 6 |
| Order hasher (core 50): roots and 50 ms of full-hash lists (07 §4.6) | order hasher | book | 1 | 1 |
| Trace rings and histograms | every hot core | book | 2 | 2 |
| Control arena (WARM allocator) | control core | process | 8 | 8 |
| Headroom for 08's auction and 05 rescans | — | book | — | 314 |
| **Total** | | | | **640** |

01 §14.6 settles retention. Per-session retention, `RESP_RETAIN_PKTS` × `MAX_SESSIONS_PER_LANE` ×
49 lanes ≈ 13.2 billion response packets (~527 GB to ~3.7 TB), does not fit in a 768 GB box,
so the sequencer keeps a 4 GiB byte ring per lane: ~8 s of every session's responses at ~0.5 GB/s
per lane (190 Gbps over 49 lanes, budget at full load). The recovery service keeps the per-session
window on a replica's drives (§2.2).

Each hot core touches at most `PLT_TLB_PAGES_MAX` = 16 distinct 1 GiB pages in steady state
(budget), so its working set stays within the L2 TLB's 1 GiB entries. The layout tool checks this
from the core map.

### 5.2 NUMA placement

| Target | Nodes | Rule |
|---|---|---|
| REF | 1 (NPS1) | No placement decisions. Every region is node 0. |
| CONSUMER | 1 | Same. |
| AWS `c6in.metal` | 2 | Every hot thread, every hot region and every bound ENA device are on the ENA node. Regions use `mbind(MPOL_BIND, ena_node)` before first touch, and the huge-page reservation names the node (`hugepages=<node>:<N>`). The other node runs HOUSE and WARM work only. |
| DEV | 1 | n/a |

Cross-node traffic on AWS is a defect: `vyrn-admin` reads `numastat -p` for the role process each
minute and alarms if any hot region has pages on the other node.

### 5.3 Start-up order, prefaulting and `seal()`

```
vyrn-seq start (HK)
  │ 1. parse config, read topology (/sys cpu cache ids, numa nodes, PCI numa_node), check core map
  │ 2. mlockall(MCL_CURRENT | MCL_FUTURE); prctl(PR_SET_THP_DISABLE); prctl(PR_SET_DUMPABLE, 0)
  │ 3. spawn one thread per core-map entry; each pins itself with sched_setaffinity, then:
  ├──► per-core setup (on its own core, in parallel)
  │      a. mmap its regions (1 GiB pages), mbind on AWS
  │      b. touch every 4 KiB of every region with a write of 0  (first touch = fault now)
  │      c. touch its stack to PLT_STACK_TOUCH = 256 KiB
  │      d. open its NIC queues via vyrn-nic (backend open happened once, on HK, before 3)
  │      e. build its structures in the regions; warm its caches by one pass over them
  │      f. report READY
  │ 4. control core: verify VmLck, HugetlbPages, per-thread minflt/majflt baselines
  │ 5. each core: seal() — allocator trap on (11 §3.5), seccomp filter on (§5.4)
  │ 6. sd_notify(READY=1)
  ▼
 steady state: per-thread minflt and majflt must not change (checked every 10 s, §13.2)
```

Prefaulting in parallel on each owner core matters twice: zeroing 640 GiB from one core takes
minutes, and on AWS first touch from the owner places the page on the right node.

The binary is linked with `-Wl,-z,now,-z,relro` (a request to 11 §4.3), so no lazy PLT binding
runs after start, and `mlockall` locks the text pages.

### 5.4 The hot-thread seccomp filter

**Decision.** Every HOT thread installs a seccomp filter as the last step of `seal()`. Any syscall
outside the allowlist kills the whole process (`SECCOMP_RET_KILL_PROCESS`).

Allowlist: `write` with fd = 2 (the abort message), `rt_sigprocmask`, `rt_sigaction`,
`rt_sigreturn`, `tgkill`, `getpid`, `gettid`, `exit`, `exit_group`. These are exactly what
`abort()` and the panic hook (11 §3.8) need.

- A seccomp filter runs only on syscall entry. A thread that makes no syscalls pays nothing.
- A hot thread that makes a syscall has a bug that also breaks the latency SLO. Killing the
  process turns it into a failover with a published outage (`FAILOVER_TARGET_MS`), which is better
  than a sequencer that runs slow without saying so. This matches 11 §3.5 for allocations.
- The `afxdp` backend adds `sendto` on its XSK file descriptor to the allowlist of TX threads
  (§6.5). The `kernel` backend installs no filter: it is never a production sequencer backend.
- WARM threads get a different, process-wide filter: `munmap`, `mprotect`, `mremap` and `madvise`
  with `MADV_DONTNEED`/`MADV_FREE` return `EPERM` and increment `plt_tlb_syscall_denied_total`
  (§4.9 rule 1).

### 5.5 Cache-line size per target

| Target | `CACHE_LINE` (01 §5) | Shared-line pad (11 §3.6 `BLD_SHARED_ALIGN`) |
|---|---|---|
| REF, CONSUMER (Zen 5) | 64 | 128 |
| AWS x86-64 (Ice Lake) | 64 | 128 |
| AWS aarch64 (Graviton) | 64 | 128 |
| DEV (Apple M-series) | 128 | 128 |

`vyrn-nic::sys` reads the line size at start (`sysconf(_SC_LEVEL1_DCACHE_LINESIZE)` on Linux,
`sysctlbyname("hw.cachelinesize")` on macOS) and refuses to start if it is larger than the
compiled `CACHE_LINE`. The 128-byte pad for lines that one core writes and another reads is
11's decision; the reason is the adjacent-line prefetcher on Zen and Intel cores, and 11's B7
settles it.

## 6. NIC backends

### 6.1 The trait

**Decision.** `vyrn-wire` defines the per-queue traits `RxRing` and `TxRing` (11 §1.3), so the
engine never depends on a NIC. `vyrn-nic` defines one backend trait, `NicBackend`, whose associated
types implement them. The binary picks the backend with one `match` at start and runs a
monomorphised engine for it. No `dyn` exists on a hot path.

```rust
// vyrn-wire::ring — what a lane, the cut core or a TX core sees.
pub const RX_BURST: usize = 16;                       // PLT_RX_BURST

/// One received frame. Same layout as `vyns_rx` in shim.h (asserted below).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RxPkt {
    data: NonNull<u8>,     // first byte of the Ethernet frame; valid until released
    pub len: u16,          // frame length without FCS
    pub flags: RxFlags,    // TS | TS_SYNC | BAD_CSUM | TRUNC
    pub buf_id: u32,
    pub rx_ts: Nanos,      // TAI ns; source given by RxRing::ts_source()
}
const _: () = assert!(size_of::<RxPkt>() == 24 && offset_of!(RxPkt, rx_ts) == 16);

pub trait RxRing: Send {
    /// Never blocks. Writes up to RX_BURST frames, returns how many. No allocation, no lock,
    /// no syscall (the `kernel` backend excepted).
    fn poll(&mut self, out: &mut [RxPkt; RX_BURST]) -> usize;
    /// Gives back the oldest `n` frames not yet released, in poll order.
    fn release(&mut self, n: usize);
    /// Borrow a frame's bytes. The borrow ends before the next `release`.
    fn bytes<'a>(&'a self, p: &'a RxPkt) -> &'a [u8];
    fn ts_source(&self) -> TsSource;
    fn counters(&self) -> &NicCounters;                // single writer: the polling thread
}

pub trait TxRing: Send {
    /// Sends one complete frame (headers built by vyrn-wire). The bytes are copied or written to
    /// the NIC before it returns. `Err(Full)` means no descriptor is free; the caller reaps.
    fn send(&mut self, frame: &[u8]) -> Result<(), TxFull>;
    /// Processes TX completions; returns how many. Called every PLT_TX_REAP_EVERY sends.
    fn reap(&mut self) -> usize;
    fn counters(&self) -> &NicCounters;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TsSource { NicPhc, TscAtPoll, Kernel, Virtual }

// vyrn-nic — what the binary sees at start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendKind { Efvi, DpdkMlx5, DpdkEna, AfXdp, Kernel, Sim }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Steering {
    Exact,            // the NIC delivers lane L's packets only to L's queue
    HashThenForward,  // the NIC hashes; a lane forwards foreign packets to their owner (§6.9)
    Socket,           // the kernel delivers by UDP port
}

pub struct Caps {
    pub steering: Steering,
    pub ts: TsSource,
    pub pio_tx: bool,          // CTPIO-class direct write to the wire
    pub max_rx_queues: u16,
    pub latency_class: LatencyClass,   // §6.8
}

pub struct RxBind { pub lane: LaneId, pub port: PortId, pub ip: Ipv4Addr, pub udp_port: u16 }
#[derive(Clone, Copy)]
pub enum TxClass { Fill, OrderStream, Control }

pub trait NicBackend: Sized {
    type Rx: RxRing;
    type Tx: TxRing;
    const KIND: BackendKind;
    /// Cold path. Opens every port in `cfg`; all vendor errors come back as NicError.
    fn open(cfg: &NicConfig) -> Result<Self, NicError>;
    fn caps(&self) -> Caps;
    fn rx_ring(&mut self, bind: &RxBind) -> Result<Self::Rx, NicError>;
    fn tx_ring(&mut self, port: PortId, class: TxClass) -> Result<Self::Tx, NicError>;
    /// The clock behind this port's timestamps, for vyrn-timemon (§8).
    fn port_clock(&self, port: PortId) -> Result<PortClock, NicError>;
}

#[derive(Debug)]
pub enum NicError {
    Driver { backend: BackendKind, port: PortId, rc: i32, msg: ShimMsg },  // ShimMsg: [u8; 160]
    Unsupported { backend: BackendKind, what: &'static str },
    Config { field: &'static str, why: &'static str },
    Topology { why: &'static str },    // e.g. NIC on a different NUMA node than its lanes
}

// bin/vyrn-seq — the only dynamic choice.
pub fn run(cfg: &Config) -> Result<(), SeqError> {
    match cfg.nic.backend {
        #[cfg(target_os = "linux")] BackendKind::Efvi => engine::<efvi::Efvi>(cfg),
        #[cfg(target_os = "linux")] BackendKind::DpdkMlx5 | BackendKind::DpdkEna =>
            engine::<dpdk::Dpdk>(cfg),
        #[cfg(target_os = "linux")] BackendKind::AfXdp => engine::<afxdp::AfXdp>(cfg),
        BackendKind::Kernel => engine::<kernel::KernelUdp>(cfg),
        BackendKind::Sim => engine::<sim::SimNic>(cfg),
        #[allow(unreachable_patterns)]
        other => Err(SeqError::BackendNotBuilt(other)),
    }
}
```

Contract rules that every backend meets and the `sim` backend's tests check:

1. `poll` returns frames of one queue in arrival order. `rx_ts` is non-decreasing within one
   queue: a backend that sees a smaller hardware stamp than the previous one returns the previous
   value and increments `rx_ts_regress`. (A regression means the PHC stepped, which §8.2 forbids;
   the counter is an alarm.) `rx_ts_regress` is not a field of `NicCounters` or of shim.h's
   `vyns_counters`, whose layout is the ring ABI (§7.2). It lives in the per-queue `ExtCounters`
   that `vyrn-nic` keeps beside them, reached through the `ExtCounted` trait that every backend's
   `Rx` and `Tx` types implement (`NicBackend::Rx: RxRing + ExtCounted`,
   `crates/vyrn-nic/src/lib.rs`). It has the same single-writer rule as `NicCounters` and is not
   fatal. A backend built on the shim gets raw stamps from C and clamps them in Rust, so the
   counter stays on the Rust side.
2. Hot-path errors never return as `Err`. They are counters. Two of them are fatal:
   `evq_overflow` (events were lost, so frames may be lost silently) and `fatal_hw`. The lane
   checks `counters().fatal()` once per poll and fail-stops (abort) if it is set.
3. `send` either sends the whole frame or returns `Full`. It never sends part of a frame.
4. A backend opens its devices on `HK` before the hot threads start, and every queue is
   created by its owner thread before `seal()`.

### 6.2 Fast-path frame format

**Decision.** Ethernet II + IPv4 (IHL = 5, no options, DF set) + UDP, no VLAN tag, 42 bytes of
headers (`PLT_FRAME_HDR_BYTES`). UDP checksum 0 on transmit. IPv6 is not on the fast path.

- IPv4 allows a zero UDP checksum, and IPv6 does not. CTPIO writes a complete frame with no
  checksum offload, so a UDP checksum would cost a software pass over every response. The
  packet MACs (01 §4) already authenticate every byte that matters.
- The IPv4 header checksum is computed in software over 20 bytes; the TX core keeps a per-session
  header template and updates only the length and checksum.
- RX parses fixed offsets. A frame with a VLAN tag, IP options, fragmentation or a UDP length that
  disagrees with the frame length is dropped and counted before any MAC check.
- Destination MAC for responses is the source MAC of the request (the leaf's routed port).
  Destination MACs for order frames are resolved at start from the kernel neighbour table over
  netlink, and refreshed by the control core; no ARP runs on a hot core.
- Frame sizes: a request is ≤ 42 + `MAX_REQ_PAYLOAD` = 234 bytes; a response is ≤ 42 + 16 +
  16 × 16 + 8 = 322 bytes. At 10 messages per packet, 1B msgs/s is 100M frames/s in, ~206 Gbps
  on the wire including preamble, IFG and FCS (budget arithmetic: 258 B × 8 × 10^8).

### 6.3 `efvi`: AMD Solarflare X2541 with ef_vi

| Aspect | Specification |
|---|---|
| Devices | X2541 (REF sequencer client ports, replica, observer; CONSUMER); X2542 for the REF sequencer's replication ports (§2.3); X2522 for the CONSUMER path-B port |
| Driver | Onload's `sfc` + `sfc_char` + `sfc_resource` kernel modules; the port keeps its kernel netdev for ARP, PTP and management |
| Objects | One protection domain per port. One VI per lane on its home client port (RX only, 512 RX descriptors, no TX ring). One TX VI per client port for the fill TX core that owns the port (A, B or C, §2.3), and one per replication port for the stream core that owns the port: **one CTPIO writer per port**. `vyrn-timemon` has an RX-only VI per client port; its probes are sent by the port's TX core from an SPSC request ring, in a gap with no response pending (§8.3). All VIs are created without interrupts; event queues are polled. |
| RX path | NIC DMA → host buffer (2 KiB, registered with `ef_memreg_alloc` from the NIC's 1 GiB page) → RX event in the VI's event queue → the lane's `poll` reads events with `ef_eventq_poll`, takes the frame at `buf + ef_vi_receive_prefix_len`, reads the hardware stamp from the prefix with `ef_vi_receive_get_timestamp_with_sync_flags` → `release` refills descriptors in batches of 16 (`ef_vi_receive_init` + one `ef_vi_receive_push` doorbell). No event batching mode. |
| TX path | CTPIO: the TX core writes the frame through the VI's CTPIO aperture with the ef_vi CTPIO-with-copy call, cut-through threshold `PLT_CTPIO_CT_BYTES` = 64. The same call posts a DMA descriptor pointing at a registered fallback copy; the NIC sends the fallback only if CTPIO aborted (for example an underrun when the CPU write stalls). Completions are reaped every `PLT_TX_REAP_EVERY` = 32 sends; each completion says whether the frame left by CTPIO or by fallback, and the shim counts both. |
| Timestamps | RX: hardware, PHC time (TAI), with the "clock in sync" flag. TX: hardware TX timestamps on the fill VIs, returned with completions; `tx_ts − rx_ts` of the request is the per-response wire-to-wire latency, exported as `plt_w2w_ns` (02's measurement point, measured in the box). |
| Steering | One `ef_filter_spec` per lane: `ef_filter_spec_set_ip4_local(UDP, card_ip, PORT_BASE + L)` → `ef_vi_filter_add` on lane L's VI. Exact. Unmatched traffic goes to the kernel netdev, where nftables drops it (§12). |
| Latency class | A: echo RX + TX ≤ `NIC_FLOOR_NS` = 560 ns wire to wire as the **maximum** over the whole B1 run (01 §5; budgets use RX 320 / TX 240); TX ≤ `PLT_TX_MAX_NS` = 240 ns, also a maximum; zero CTPIO fallbacks; TSC↔PHC cross-timestamp error ≤ `PLT_TSC_MAP_ERR_NS` (§8.4). B1 qualifies each card and slot (§14.1 item 12). |
| Packet rate | ≥ 30M frames/s RX per port of 234-byte frames with zero drops for 600 s (budget, PLT-B-PPS): 1.2 × the 25M/s that 1B msgs/s puts on each of 4 client ports. |
| Targets | REF (sequencer, replica, observer), CONSUMER |

**Why the qualification is a maximum.** The lane computes `age = now − rx_ts` when it dequeues a
packet (01 §14.1). Every RX delay after the stamp is inside `age`, so a slow RX costs a `BUSY`
reply, never a late response. The TX side is after the last decision: once a response is written
to CTPIO, nothing can shed it. So B1 bounds the echo as a maximum, and bounds TX on its own as a
maximum too: the admission test predicts the path with the 240 ns TX of 01 §14.2, so a card with
RX + TX ≤ 560 but TX of 260 would still make an admitted packet late. The TX bound is measured
from the CTPIO write to the first bit on an idle port; queueing behind other frames on the same
port is the TX core's budget (Open question 12).

**A CTPIO fallback is a late frame.** The fallback DMA leaves microseconds after the budget, so it
is not a tolerated rate. The design removes the causes. Underrun cannot happen: the TX core builds
the frame in L1 and writes it in one burst of write-combined stores, on a core that takes no
interrupt (§4.11). Contention cannot happen: each port has one CTPIO writer (§2.3 rule 4), and
probes go through that writer. A fallback that still occurs is a fault: it increments
`plt_ctpio_fallback_total`, and one fallback on an `ACTIVE` box makes it ineligible (§13.2).

**The pooled lanes (01 §14.15).** The pool is lanes 42–48 on cores 56–62, CCD 7. Their VIs map
to the cores as follows:

- All 7 pool VIs are on client card NIC3 (§2.3), one VI per pool lane, each with the exact
  filter `PORT_BASE + L` of any lane. A pooled session gets a home pool lane (its UDP port) at
  session open; 10's lane map balances them. One card means one `PhcMap` line for the whole pool
  (§8.4) and no cross-NIC skew between pooled clients.
- An ef_vi VI has one consumer at a time: its event queue read pointer and RX ring are not
  thread-safe. So each pool VI has a **consumer lock**, an `AtomicU32` (owner core or `FREE`) on
  its own 128-byte line. A core takes it with one CAS before it polls and drops it after
  `release` refills the ring. The home core polls its own VI first in every iteration.
- **The steal path.** A pool core whose own VI had no event tries the next sibling VI in a fixed
  ring order, with a try-CAS from `FREE`. On success it takes at most
  `PLT_POOL_STEAL_FRAMES` = 1 frame, so it holds a sibling's VI for one poll. On failure it moves
  on; it never spins.
- **Everything stays in one CCD.** The locks, the account tokens (05), the VIs' `ef_vi` state and
  the RX descriptor rings are allocated in the pool's own 1 GiB page and touched only by cores
  56–62, so every CAS and every line transfer of the steal path is inside CCD 7's L3 (~20 ns,
  01 §14.15). The NIC writes RX events and buffers by DMA, as for any lane. `vyrn-admin` refuses a
  core map that puts a pool lane outside one CCD, or a pool VI on another card.
- Deadline admission is unchanged: the core that dequeues a frame computes `age` from that
  frame's `rx_ts` and NIC3's line, whichever core is the VI's home. The pool's account takes are
  logged as `AcctTake` records (01 §14.17, 07 §3.6), so replay does not depend on which core
  stole what.

### 6.4 `dpdk`: ConnectX via mlx5, ENA via ena

| Aspect | mlx5 (ConnectX-6 Dx, ConnectX-7) | ena (AWS) |
|---|---|---|
| Binding | Bifurcated: the kernel `mlx5_core` netdev stays up; DPDK attaches through rdma-core (loaded with `dlopen`, so the binary runs where rdma-core is absent) | The data ENIs are bound to `vfio-pci` with write-combining enabled for the LLQ BAR (§9.2); the management ENI stays on the kernel `ena` driver |
| EAL | `--in-memory --no-telemetry --huge-dir /dev/hugepages1G -a <pci>` with `--main-lcore <HK>`; every hot thread calls `rte_thread_register()` before `seal()` so that it gets an lcore id and a mempool cache | same |
| RX path | `rte_eth_rx_burst` on the lane's queue; mbuf data in 1 GiB pages; CQE compression off (`rxq_cqe_comp_en=0`), multi-packet RQ off | `rte_eth_rx_burst` on the lane's queue (or on a shared RSS queue, §6.9) |
| TX path | Copy the frame into an mbuf, `rte_eth_tx_burst` of 1. Inline the whole frame into the WQE (`txq_inline_max=384`), multi-packet write off (`txq_mpw_en=0`) | Copy into an mbuf, `rte_eth_tx_burst`. LLQ mode, so the descriptor and the header go to the device by a write-combined MMIO burst |
| Timestamps | Hardware RX stamps in ns of PTP time, because `REAL_TIME_CLOCK_ENABLE=1` (§3.3), read through the mbuf timestamp dynfield | No hardware RX stamp is assumed. The polling core reads the TSC when `rx_burst` returns non-empty and maps it to TAI (§8.4); one TSC per box means no cross-NIC skew |
| Steering | `rte_flow` in isolated mode: pattern `ETH / IPV4 dst = card_ip / UDP dst = PORT_BASE + L`, action `QUEUE L`. Everything else goes to the kernel. Exact. | No `rte_flow`. RSS (Toeplitz over the 5-tuple) to the lanes' queues, then forwarding (§6.9). HashThenForward. |
| Latency class | B: echo p99 ≤ 1,000 ns (budget); never sequences. Class A only after B1 passes every class-A line of §6.3 on that card | C: `rx_ts` (§8.4) → TX doorbell ≤ `LAT_MAX_NS` as a maximum inside the instance, by deadline admission; the wire is Nitro's (01 §14.0, §9.6) |
| Targets | REF data nodes (CX-7), REF observer (CX-6 Dx: taps and market data out, §2.3), CONSUMER option (CX-6 Dx), archive and lab boxes | AWS, every role |

### 6.5 `afxdp`: any Linux NIC

| Aspect | Specification |
|---|---|
| Use | Fallback for a NIC that neither ef_vi nor a DPDK PMD we ship supports, for archive nodes, and for the lab. Never a production sequencer backend: TX needs a syscall. |
| Setup | One XSK per lane bound to queue L in zero-copy mode where the driver supports it (else copy mode, counted). UMEM in the lane's 1 GiB page, 2 KiB frames. `SO_PREFER_BUSY_POLL` with `napi_defer_hard_irqs` and `gro_flush_timeout` on the netdev, so the queue runs without interrupts while it is polled. |
| XDP program | A 6-instruction eBPF program, `bpf_redirect_map(xsks, rx_queue_index, XDP_PASS)`, assembled in Rust in `vyrn-nic::sys` and loaded with the `bpf` syscall before `seal()`. No C and no BPF toolchain. It runs on the host CPU (C-NOCHIP). |
| RX path | Poll the RX ring; frames in UMEM; return them through the fill ring on `release`. |
| TX path | Write a descriptor to the TX ring; when the kernel sets `XDP_RING_NEED_WAKEUP`, kick with `sendto` (the one extra seccomp entry, §5.4). |
| Timestamps | The XDP RX timestamp hint (kernel ≥ 6.3, drivers that implement it, e.g. mlx5, ice) written into the frame's metadata area by the program; otherwise TSC at poll. |
| Steering | `ethtool -N <dev> flow-type udp4 dst-ip <ip> dst-port <PORT_BASE + L> action L`. An XSK receives only from the queue it is bound to, so without ntuple support the backend falls back to HashThenForward. |
| Latency class | D: echo p99 ≤ 5 µs (budget) |
| Targets | Any Linux box; archive nodes; AWS fallback if DPDK on ENA fails validation |

### 6.6 `kernel`: UDP sockets on Linux and macOS

| Aspect | Specification |
|---|---|
| Use | Unit and integration tests on Linux, every network test on macOS, the management plane, small lab books |
| Sockets | One non-blocking UDP socket per lane bound to `PORT_BASE + L`. Linux: `recvmmsg`/`sendmmsg` in a busy loop, `SO_BUSY_POLL`. macOS: `kqueue` with `EVFILT_READ` polled with a zero timeout, then `recvmsg` until `EAGAIN` |
| Timestamps | Linux: `SO_TIMESTAMPING` with `SOF_TIMESTAMPING_RX_HARDWARE` where the NIC provides it, else software stamps. macOS: `clock_gettime_nsec_np(CLOCK_REALTIME)` right after `recvmsg` returns. Source `Kernel`. |
| Steering | By socket port (`Socket`) |
| Latency class | E: ≤ 50 µs p99 on Linux (budget); unbounded on macOS |
| Targets | DEV, CI, tests |

### 6.7 `sim`: in-process

The `sim` backend is a pair of preallocated rings per lane and per TX port, owned by `vyrn-sim`'s
virtual network. `rx_ts` is the simulator's virtual time, so a replay is bit-identical for a seed.
The simulator injects loss, duplication, reordering between queues, delay, CTPIO fallbacks,
`evq_overflow` and `rx_ts` regressions, so that every counter path in §6.1 has a test. It makes no
syscall, needs no privilege and runs identically on Linux and macOS. Its latency class is S
(virtual time; no latency claim).

### 6.8 Backends by target and latency class

| Class | Backend | Meaning (all budgets) | REF | CONSUMER | AWS | DEV |
|---|---|---|---|---|---|---|
| A | `efvi` (X2541) | echo ≤ 560 ns max, TX ≤ 240 ns max; with admission, meets `LAT_MAX_NS` at the wire | seq, replica, observer | seq | — | — |
| B | `dpdk` mlx5 | echo p99 ≤ 1 µs; class A if B1 passes | data, observer taps and MD | CX-6 Dx option | — | — |
| C | `dpdk` ena | `LAT_MAX_NS` max from `rx_ts` to TX doorbell inside the instance | — | — | all roles | — |
| D | `afxdp` | echo p99 ≤ 5 µs | fallback | fallback | fallback | — |
| E | `kernel` | ≤ 50 µs p99 (Linux) | archive, tests | tests | management | yes |
| S | `sim` | virtual time | tests | tests | tests | yes |

`vyrn-seq` refuses to start as a production sequencer unless its backend's class is A, or C with
`target = aws`. The check is on `Caps::latency_class`, so a misconfigured box fails at start, not
at the first SLO report.

### 6.9 Steering, the address map, and forwarding

The address map gives each lane `L` the pair `(ip of its home card, PORT_BASE + L)`. 04 carries
it in session setup. `PORT_BASE` is 04's constant; this chapter assumes a block of
`N_LANES` consecutive ports.

With `Exact` steering, a packet reaches only its lane, or, for a pooled lane, the pool (§6.3). With `HashThenForward` (ENA, AF_XDP without
ntuple), a packet can land on lane `M ≠ L`. Lane `M` sees it in its `poll`, reads the destination
port, and copies the frame (≤ 234 bytes) with its `rx_ts` into the SPSC ring `fwd[M → L]`
(`PLT_FWD_RING_SLOTS` = 1024 entries, 256-byte slots). Lane `L` drains its forward rings once per
poll, after its own queue. The `rx_ts` is the original one, so ordering is unaffected. The cost is
one cross-core copy, ~100 ns (budget, DESIGN §4). A full forward ring drops the frame and counts
it; the client resends (04).

Forward rings exist only on `HashThenForward` targets. With `PLT_N_LANES_AWS` = 24 lanes (§9.3)
that is 24 × 23 = 552 rings. A lane checks each of its 23 inbound rings once per poll at ~2 ns per
empty ring (one cached load of the producer index), ~50 ns per iteration (budget). AWS accepts
that cost. PLT-B-ENA-RSS tests the alternative in §9.5.

## 7. `vyrn-nic-shim`: the C shim

### 7.1 Why C, and only this much

ef_vi and DPDK are C libraries whose fast paths are macros and `static inline` functions in their
headers (`ef_eventq_poll`, `ef_vi_receive_init`, `rte_eth_rx_burst`, `rte_pktmbuf_alloc`). Rust
cannot call a macro, and `bindgen` cannot bind a `static inline` function except by generating a
C wrapper, which is a shim anyway. So the shim exists to turn those headers into real functions
with a stable C ABI. With cross-language LTO those functions inline back into the Rust loop, so
the boundary costs nothing at run time (11 §4.4 verifies it in the binary).

The shim holds no policy. It does not parse packets, build headers, steer, retry or log. It
translates one vendor call sequence into one function and reports what happened. Everything that
decides anything is Rust. Size: `shim.h` is 84 code lines, `shim.c` ≤ 215, total ≤ 300 (11 §4.5).

### 7.2 `c/vyrn-nic-shim/shim.h` in full

```c
/* shim.h: the C ABI between vyrn-nic (Rust) and ef_vi / DPDK. ABI version 1.
 * Rules (06 §7, 11 §4.5): no global state, no malloc, no threads, no stack arrays.
 * Every handle lives in memory that vyrn-nic allocates, sized by vyns_*_size() and aligned to
 * VYNS_HANDLE_ALIGN. Cold calls return vyns_rc and write a NUL-terminated message into the
 * caller's err buffer. Hot calls never return an error: they count, and two counters
 * (evq_overflow, fatal_hw) make vyrn-nic fail-stop. */
#ifndef VYRN_NIC_SHIM_H
#define VYRN_NIC_SHIM_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define VYNS_ABI_VERSION   1u
#define VYNS_HANDLE_ALIGN  128u
#define VYNS_ERR_LEN       160u

typedef int32_t vyns_rc;
#define VYNS_OK              0
#define VYNS_E_ARG          (-1)  /* bad argument; the message names it              */
#define VYNS_E_DRIVER       (-2)  /* vendor call failed; the message has rc and errno */
#define VYNS_E_UNSUPPORTED  (-3)  /* the device or PMD cannot do this                 */
#define VYNS_E_NO_TS        (-4)  /* hardware timestamps asked for but unavailable    */
#define VYNS_E_STATE        (-5)  /* call out of order                                */

#define VYNS_RX_TS         0x0001u  /* ts_ns is a NIC hardware timestamp */
#define VYNS_RX_TS_SYNC    0x0002u  /* the NIC clock reported "in sync"  */
#define VYNS_RX_BAD_CSUM   0x0004u
#define VYNS_RX_TRUNC      0x0008u

typedef struct vyns_rx {            /* 24 bytes; identical to vyrn_wire::RxPkt */
    const uint8_t *data;            /* first byte of the Ethernet frame      */
    uint16_t len;                   /* frame length without FCS              */
    uint16_t flags;                 /* VYNS_RX_*                             */
    uint32_t buf_id;
    uint64_t ts_ns;                 /* PHC time, TAI ns; 0 unless RX_TS      */
} vyns_rx;

/* Single writer: the thread that polls the handle (relaxed load + store, never a locked RMW).
 * vyrn-nic's control thread reads them as AtomicU64. */
typedef struct vyns_counters {
    _Atomic uint64_t rx_pkts, rx_discard, rx_no_ts, rx_trunc;
    _Atomic uint64_t tx_pkts, tx_ctpio, tx_fallback, tx_full;
    _Atomic uint64_t evq_overflow;  /* != 0: events were lost. Fatal.        */
    _Atomic uint64_t fatal_hw;      /* != 0: the device reported an error.   */
} vyns_counters;

uint32_t vyns_abi_version(void);

/* ---- ef_vi: AMD Solarflare X2 ------------------------------------------------------ */
#define VYNS_EFVI_RX_TS   0x1u
#define VYNS_EFVI_TX_TS   0x2u
#define VYNS_EFVI_CTPIO   0x4u

typedef struct vyns_efvi vyns_efvi;           /* opaque; storage owned by vyrn-nic */

typedef struct vyns_efvi_cfg {
    const char *ifname;             /* kernel netdev of the port                  */
    uint32_t flags;                 /* VYNS_EFVI_*                                */
    uint32_t rxq_entries;           /* power of two; 0 = TX-only VI               */
    uint32_t txq_entries;           /* power of two; 0 = RX-only VI               */
    uint32_t evq_entries;           /* >= rxq_entries + txq_entries               */
    uint32_t buf_bytes;             /* per packet buffer: 2048                    */
    uint32_t ctpio_ct_bytes;        /* cut-through threshold: 64                  */
    uint8_t *buf_mem;               /* huge-page memory for buffers, 4 KiB aligned */
    size_t buf_mem_len;             /* >= (rxq_entries + txq_entries) * buf_bytes */
} vyns_efvi_cfg;

size_t   vyns_efvi_size(void);
vyns_rc  vyns_efvi_open(vyns_efvi *h, const vyns_efvi_cfg *cfg, char *err, size_t err_len);
vyns_rc  vyns_efvi_filter_udp(vyns_efvi *h, uint32_t ip_be, uint16_t port_be,
                              char *err, size_t err_len);
vyns_rc  vyns_efvi_close(vyns_efvi *h, char *err, size_t err_len);
uint32_t vyns_efvi_rx_poll(vyns_efvi *h, vyns_rx *out, uint32_t max);              /* hot */
void     vyns_efvi_rx_release(vyns_efvi *h, uint32_t n);                           /* hot */
int32_t  vyns_efvi_tx_ctpio(vyns_efvi *h, const uint8_t *frame, uint32_t len);     /* hot: 0 sent, 1 full */
uint32_t vyns_efvi_tx_reap(vyns_efvi *h, uint64_t *tx_ts_ns, uint32_t max);       /* hot */
const vyns_counters *vyns_efvi_counters(const vyns_efvi *h);

/* ---- DPDK: mlx5, ena ----------------------------------------------------------------- */
#define VYNS_DPDK_RX_TS    0x1u     /* RTE_ETH_RX_OFFLOAD_TIMESTAMP              */
#define VYNS_DPDK_ISOLATE  0x2u     /* rte_flow isolated mode (mlx5)             */
#define VYNS_DPDK_MAX_Q    64u

typedef struct vyns_dpdk vyns_dpdk;

typedef struct vyns_dpdk_cfg {
    uint16_t port_id;
    uint16_t n_rxq, n_txq;          /* each <= VYNS_DPDK_MAX_Q                   */
    uint16_t rxq_entries, txq_entries;
    uint32_t mbufs_per_q;
    uint32_t flags;                 /* VYNS_DPDK_*                               */
    int32_t socket_id;              /* NUMA node of the port                     */
} vyns_dpdk_cfg;

vyns_rc  vyns_dpdk_eal_init(int argc, char **argv, char *err, size_t err_len);
vyns_rc  vyns_dpdk_thread_register(char *err, size_t err_len);
size_t   vyns_dpdk_size(void);
vyns_rc  vyns_dpdk_open(vyns_dpdk *h, const vyns_dpdk_cfg *cfg, char *err, size_t err_len);
vyns_rc  vyns_dpdk_flow_udp(vyns_dpdk *h, uint32_t ip_be, uint16_t port_be, uint16_t queue,
                            char *err, size_t err_len);
vyns_rc  vyns_dpdk_read_clock(vyns_dpdk *h, uint64_t *dev_ns, char *err, size_t err_len);
vyns_rc  vyns_dpdk_close(vyns_dpdk *h, char *err, size_t err_len);
uint32_t vyns_dpdk_rx_poll(vyns_dpdk *h, uint16_t q, vyns_rx *out, uint32_t max);  /* hot */
void     vyns_dpdk_rx_release(vyns_dpdk *h, uint16_t q, uint32_t n);               /* hot */
int32_t  vyns_dpdk_tx(vyns_dpdk *h, uint16_t q, const uint8_t *frame, uint32_t len); /* hot: 0 sent, 1 full */
const vyns_counters *vyns_dpdk_counters(const vyns_dpdk *h, uint16_t q);

#endif /* VYRN_NIC_SHIM_H */
```

### 7.3 What `shim.c` does, function by function

| Function | Vendor calls | Notes |
|---|---|---|
| `vyns_efvi_open` | `ef_driver_open`, `ef_pd_alloc_by_name`, `ef_vi_alloc_from_pd` (flags from cfg), `ef_memreg_alloc` over `buf_mem`, initial `ef_vi_receive_init` × rxq + `ef_vi_receive_push` | Checks `ef_vi_receive_prefix_len`, that RX timestamps are enabled when asked (`VYNS_E_NO_TS` otherwise), and that the VI got CTPIO when asked (`VYNS_E_UNSUPPORTED`). |
| `vyns_efvi_filter_udp` | `ef_filter_spec_init`, `ef_filter_spec_set_ip4_local(IPPROTO_UDP, ip, port)`, `ef_vi_filter_add` | One exact filter. A duplicate filter is `VYNS_E_DRIVER` with the vendor rc. |
| `vyns_efvi_rx_poll` | `ef_eventq_poll`; per RX event `EF_EVENT_RX_RQ_ID`, `EF_EVENT_RX_BYTES`, `ef_vi_receive_get_timestamp_with_sync_flags` | Fills `vyns_rx`, pushes buffer ids into the handle's FIFO. `EF_EVENT_TYPE_RX_DISCARD` → `rx_discard`; `EF_EVENT_TYPE_OFLOW` → `evq_overflow`; any other unexpected type → `fatal_hw`. |
| `vyns_efvi_rx_release` | `ef_vi_receive_init` × n, one `ef_vi_receive_push` | Refill from the FIFO head. |
| `vyns_efvi_tx_ctpio` | the ef_vi CTPIO-with-copy transmit into the next fallback buffer | Returns 1 if no descriptor is free (`tx_full`). |
| `vyns_efvi_tx_reap` | `ef_eventq_poll` on the TX VI; TX events with timestamps | Counts CTPIO against fallback completions; writes TX stamps if asked. |
| `vyns_dpdk_eal_init` | `rte_eal_init` | Called once, on `HK`. |
| `vyns_dpdk_thread_register` | `rte_thread_register` | Gives a non-EAL thread an lcore id, so mempool caches work. |
| `vyns_dpdk_open` | `rte_pktmbuf_pool_create` per queue on `socket_id`, `rte_eth_dev_configure`, `rte_eth_rx_queue_setup`, `rte_eth_tx_queue_setup`, `rte_flow_isolate` if asked, `rte_eth_dev_start`; `rte_mbuf_dyn_rx_timestamp_register` if RX_TS | `VYNS_E_NO_TS` if the PMD does not offer the timestamp offload. |
| `vyns_dpdk_flow_udp` | `rte_flow_validate`, `rte_flow_create` (ETH / IPV4 dst / UDP dst → QUEUE) | `VYNS_E_UNSUPPORTED` on ENA; vyrn-nic then selects `HashThenForward`. |
| `vyns_dpdk_rx_poll` | `rte_eth_rx_burst` | Keeps the mbuf pointers in the queue's FIFO; reads the timestamp dynfield and its flag. |
| `vyns_dpdk_rx_release` | `rte_pktmbuf_free_bulk` | From the queue's FIFO head. |
| `vyns_dpdk_tx` | `rte_pktmbuf_alloc`, copy, `rte_eth_tx_burst(…, 1)` | On 0 sent: free the mbuf, return 1. |

**The ops-table question (11 §4.4).** `ef_eventq_poll` and the ef_vi transmit calls dispatch
through the VI's `ops` table, and `rte_eth_rx_burst`/`rte_eth_tx_burst` dispatch through
`rte_eth_fp_ops`. LTO cannot inline through those pointers. **Decision:** keep the indirect calls.
Calling the generation-specific functions directly would bind the shim to private symbols of one
Onload or DPDK release. The call target never changes after open, so the branch predictor gets it
right every time; its cost is inside B1's measured echo. 11's asm gate allowlists exactly these
four indirect calls by name.

### 7.4 Build and link

11 §4 owns the flags and the CI gates. The platform-relevant points:

```
c/vyrn-nic-shim/shim.c─clang -flto=thin -march=x86-64-v3──► shim.bc ─┐
vendored libciul (ef_vi), built with clang -flto=thin ────► .bc  ────┤
vendored DPDK static libs + mlx5/ena PMDs (meson, clang, b_lto) ──────┤
rustc -C linker-plugin-lto -C target-cpu=x86-64-v3 ───────► .rlib ────┴─► lld + LLVM LTO ─► vyrn-seq
```

- ef_vi's library (libciul) and DPDK are built from the vendored sources with the same clang, so
  that their non-inline functions also take part in LTO. DPDK's PMDs register themselves with
  constructors, so they are linked with `--whole-archive`.
- rdma-core is not linked: the mlx5 PMD is built to `dlopen` it, so the one binary starts on a box
  with no ConnectX and no rdma-core.
- The shim is compiled only for `target_os = "linux"`. On macOS, `vyrn-nic` builds the `kernel` and
  `sim` backends only, and the build script does not look for clang.

### 7.5 Error handling

- **Cold calls** (`open`, `filter`, `flow`, `close`, `eal_init`) return a `vyns_rc` and write a
  message of at most `VYNS_ERR_LEN` bytes: the vendor function's name, its return code, `errno` and
  `strerror` text, and the argument that failed. vyrn-nic turns it into `NicError::Driver`. vyrn-seq
  prints it with the port and the lane and exits non-zero before `READY`. Nothing is retried in
  C.
- **Hot calls** return counts. Errors become counters in `vyns_counters`, and two of them are
  fatal (`evq_overflow`, `fatal_hw`): the Rust caller checks them once per poll and aborts, which
  is a failover (11 §3.8). A hot call never writes to `err`, never touches `errno` and never logs.
- **ABI drift:** vyrn-nic calls `vyns_abi_version()` at start and refuses a mismatch. A compile-time
  assertion in Rust checks `size_of::<RxPkt>() == 24` against the C layout.

## 8. Time

### 8.1 What time is for

The engine reads one clock: the RX timestamp of each packet, which enters the `PacketRecord`
(01 §11.3). It matters in one place: the level FIFO orders lane FIFOs by `(rx_ts, lane id)`. Two
lanes on two different cards stamp with two different PHCs, so **the skew between the PHCs of one
box is a fairness error** in time priority. Determinism does not depend on it, because replicas
replay the logged `rx_ts`. Absolute time (TAI) matters only for reports and market data.

```
        GNSS                                             facility
          │
   GM-1 ──┤ leaf A (PTP BC) ── NIC0 PHC ◄── ptp4l (client, hardware stamps)
   GM-2 ──┘ leaf B (PTP BC)      │
                                 ├──► phc2sys ──► NIC1 PHC
                                 ├──► phc2sys ──► NIC2 PHC
                                 ├──► phc2sys ──► NIC3 PHC
                                 ├──► phc2sys ──► NIC4, NIC5 PHC (replication; rx_ts unused)
                                 └──► phc2sys ──► CLOCK_REALTIME / CLOCK_TAI ──► TAI map (§8.4)
 vyrn-timemon: two-way timestamped probes NIC0 ⇄ NICk through the leaves → measured skew
 vyrn-timemon: PTM cross-timestamp TSC ⇄ PHC of each client card, 100 Hz → TSC↔PHC lines (§8.4)
```

### 8.2 ptp4l and phc2sys

`/etc/vyrn/ptp4l.conf`:

```
[global]
slaveOnly               1
domainNumber            0
network_transport       L2
delay_mechanism         E2E
time_stamping           hardware
logSyncInterval         -4          # 16 Sync/s from the boundary clock
logMinDelayReqInterval  -4
tx_timestamp_timeout    10
clock_servo             pi
first_step_threshold    0.00002     # may step once, at start, by > 20 µs
step_threshold          0.0         # never step afterwards: slew only
summary_interval        0
uds_address             /run/ptp4l
[enp1s0np0]                         # NIC 0's kernel netdev (from the platform config)
```

phc2sys, one instance per sink: `phc2sys -s <nic0> -c <nicK> -O 0 -R 16 -n 0` for K = 1…5 (both
sides are PHCs in TAI, so the offset is 0), and `phc2sys -s <nic0> -c CLOCK_REALTIME -w -R 16`
for the system clock, which also sets the kernel's TAI offset from ptp4l's `currentUtcOffset`.
phc2sys's default step threshold is off, so the NIC PHCs only slew. On the observer, the tap ports
have no TX fibre, so ptp4l runs on the X2541 that takes path A (§2.3 NIC3) and phc2sys slaves the
other five cards to it; a CX-6 Dx netdev that reports the same PHC index as its sibling port gets
no phc2sys of its own (checked as in §14.2).

**No PHC steps while ACTIVE (`INV-PLT-2`).** A step would move `rx_ts` backwards on one card and
reorder that card's lanes against the others. ptp4l and phc2sys may step only before `vyrn-time.target`
is reached. If a step is ever needed later (offset > 1 ms), `vyrn-timemon` declares `UNSYNC` (§8.6)
and the box drains before the step.

### 8.3 Cross-NIC sync: budget and monitoring

| Quantity | Budget |
|---|---|
| Skew between any two client-card PHCs of one box, p99.9 over 1 h | ≤ `PLT_SKEW_BUDGET_NS` = 25 ns |
| Alarm | > `PLT_SKEW_ALARM_NS` = 50 ns for 1 s |
| Box ineligible to sequence | > `PLT_SKEW_INELIGIBLE_NS` = 100 ns for 1 s |
| Sequencing stops (fail-stop) | > `PLT_SKEW_HALT_NS` = 1,000 ns once |
| NIC 0 offset to the grandmaster, p99 over 1 h | ≤ `PLT_GM_OFFSET_NS` = 100 ns |

Why 25 ns: resting orders keep exact time priority among themselves (DESIGN §3). 25 ns is about
one packet time on a 100G port (258 bytes on the wire = 20.6 ns), so two orders on two cards can
be misordered only if they arrive within about one packet time of each other. The cut already
limits passive-against-aggressor order to ~100 ns (`CUT_REFRESH_NS`), so a tighter budget buys
nothing there. PLT-B-SKEW measures what phc2sys achieves on the X2541. Skew is a fairness
budget, not a latency one: deadline admission maps each lane's `now` to its own card's PHC
(§8.4), so skew never enters `age`.

phc2sys measures each PHC through PCIe reads, and its own offset report cannot see a constant
asymmetry in those reads. So the skew is measured independently, on the wire:

- `vyrn-timemon` owns one RX-only ef_vi VI per client port (hardware stamps, a filter on
  `PLT_PROBE_UDP_PORT`). It sends probes through the port's fill TX core, which writes them with
  its own CTPIO VI when no response is pending and returns the TX stamp (§6.3: one writer per port).
- Ten times a second, for every pair (0, k), it sends a probe 0 → k and one k → 0 through the leaf
  switches in the strict-priority queue, with TX stamps `t1`, `t3` and RX stamps `t2`, `t4`.
- `skew(0,k) = ((t2 − t1) − (t4 − t3)) / 2`, as in PTP. Path asymmetry inside a cut-through leaf
  at one port speed is a few ns (budget ≤ 5 ns, PLT-B-SKEW calibrates it once per box with a
  direct cable between two cards).
- It exports `plt_nic_skew_ns{pair}` and feeds §8.6.

If PLT-B-SKEW shows that phc2sys cannot hold 25 ns on the X2541, `vyrn-timemon` becomes the servo:
it steers NIC k's frequency with `clock_adjtime(ADJ_FREQUENCY)` on `/dev/ptpK` from the probe
measurement, and the three NIC phc2sys units are disabled. The probe stays the monitor either way.

### 8.4 `rx_ts` per backend, and the TSC↔PHC map for deadline admission

| Backend | `rx_ts` | `TsSource` | `age` on the lane core |
|---|---|---|---|
| `efvi`, `dpdk` mlx5 | NIC hardware stamp, PHC TAI ns | `NicPhc` | TSC mapped to the card's PHC (below) |
| `afxdp` with the XDP hint | NIC hardware stamp | `NicPhc` | same |
| `dpdk` ena, `afxdp` without hint | TSC at RX completion (below), mapped to TAI for the log | `TscAtPoll` | TSC − TSC: no mapping error |
| `kernel` | socket stamp or clock read after `recv` | `Kernel` | never sequences |
| `sim` | virtual time | `Virtual` | virtual |

**Why a map.** Deadline admission (01 §14.1) needs `age = now − rx_ts` in ns when a lane dequeues
a packet, and the BBO core needs it again for forwarded ops. `rx_ts` is in the PHC time of the card
that received the packet. A hot core cannot read a PHC: an MMIO read is a ~1 µs PCIe round trip.
It reads the TSC and converts.

**The line.** One seqlock line per client card `K`, written only by `vyrn-timemon` on the HOUSE core:

```rust
#[repr(C, align(128))]
pub struct PhcMap {               // one per client card; read by its lanes and by the BBO core
    seq: AtomicU64,               // odd while being written
    tsc0: u64, phc0: Nanos,       // one cross-timestamp: TSC and PHC at the same instant
    mult: u64, shift: u32,        // PHC ns per TSC tick, from the last two cross-timestamps
    err0_ns: u32,                 // error bound at tsc0 (below)
    drift_ns_per_ms: u32,         // growth of the bound with the line's age
}
// On the lane, at dequeue (integer only, ~3 ns with the line in L1):
//   d   = rdtsc() - tsc0
//   now = phc0 + ((d * mult) >> shift)
//   age = now - rx_ts + err0_ns + ticks_to_ms(d) * drift_ns_per_ms
//         + PLT_RX_STAMP_OFFSET_NS + PLT_RX_STAMP_CAL_NS
```

The lane adds the error bound to `age`. A mapping error therefore costs `BUSY` replies and never
a late response, as long as the bound is true. The BBO core reads the line of the op's card from
the static lane → card map. The line changes every 10 ms, so it stays in each reader's cache; the
cost is one cross-CCD miss per reader per refresh.

**Cross-timestamping.** Every `PLT_TSC_MAP_REFRESH_MS` = 10 ms, `vyrn-timemon` calls
`ioctl(PTP_SYS_OFFSET_PRECISE)` on `/dev/ptpK`. The driver's `getcrosststamp` uses PCIe PTM, so the
device time and the system counter (the TSC) are latched at the same instant, with no PCIe read
window in the error. `vyrn-timemon` converts the returned system time back to TSC ticks with the
kernel clocksource's own `mult`/`shift` (exact to 1 ns), sets `mult`/`shift` from the last two
samples, and writes the line. The equivalent where PRECISE is absent, `PTP_SYS_OFFSET_EXTENDED`,
brackets the PHC read between two system reads; its error is half the PCIe read window, ~250–500 ns
on Gen3 (budget), so it cannot qualify a sequencer card. Its only use is the lab cross-check
below. A client NIC whose driver has no PTM cross-timestamp on this platform fails PLT-V-11.

**Error budget** (`PLT_TSC_MAP_ERR_NS` = 10 ns, budget):

| Term | Budget | How it is known |
|---|---|---|
| PTM cross-timestamp | ≤ 4 ns (PTM link-delay asymmetry: vendor) | PLT-B-XTS: every PTM sample lies inside the `PTP_SYS_OFFSET_EXTENDED` bracket and a CTPIO loopback bracket; residual spread over 24 h |
| TSC conversion and `mult`/`shift` rounding | ≤ 1 ns | arithmetic |
| Extrapolation over one 10 ms period at ≤ `PLT_PHC_RATE_STEP_PPB` = 100 ppb of PHC rate change | ≤ 1 ns | ptp4l and phc2sys only slew (§8.2); the residual below measures it |
| Margin | 4 ns | |

**The bound is measured, not assumed.** Each new cross-timestamp is also a check of the previous
line: `residual = phc_observed − phc_predicted(tsc_observed)`. `err0_ns` is the PTM term plus the
largest |residual| of the last 16 refreshes (160 ms), and `drift_ns_per_ms` is the largest
|residual| per ms of line age in that window. So a servo that starts to move the PHC rate widens
the bound at once.

**Refresh and failure.**

| Condition | Action |
|---|---|
| `err0_ns` > `PLT_TSC_MAP_ERR_NS` = 10 ns | alarm `plt_tsc_map_err_ns` |
| `err0_ns` > `DEADLINE_GUARD_NS` = 20 ns, or the line older than `PLT_TSC_MAP_STALE_MS` = 50 ms | the box is **ineligible to sequence** (time state `MAPERR`, §8.6). If it is `ACTIVE`, it requests a planned handover at the next block boundary. Until then the lanes keep adding the growing bound, so responses stay ≤ `LAT_MAX_NS` and the cost is more `BUSY`. |
| A PTM ioctl fails | the line is not written; its age grows and the stale rule applies |

The threshold is the guard because the budgets of 01 §14.2 and §14.17 leave ~15 ns of slack at
message index 9 against the 980 ns shed threshold. A bound above 20 ns turns most worst-case
packets into `BUSY`, which B3 forbids, and means the cross-timestamp itself is no longer
trustworthy.

**`PLT_RX_STAMP_OFFSET_NS`.** The X2541 stamps a frame at its MAC, a fixed time after the first bit
reaches the port. The B1 tap rig measures that offset per card once (§14.2), and the lane adds
it. It also adds the calibration error, ≤ `PLT_RX_STAMP_CAL_NS` = 10 ns, to `age`, because
`DEADLINE_GUARD_NS` = 20 is all gap budget now (01 §14.1, §4.11).

**AWS: `rx_ts` is the TSC at RX completion (01 §14.11).** The ENA has no hardware stamp we rely
on, so the polling core stamps with the TSC. The stamp must not be later than the completion, or
`age` would under-state the time a frame waited in the ring. So `rx_ts` is the TSC of the most
recent poll of that queue that **drained** it (returned fewer than `RX_BURST` frames). Every frame
returned after that poll completed after it, so `rx_ts` ≤ the true completion time. On an idle
queue the stamp is at most one poll iteration early (~50 ns, budget). Under a backlog the stamp
stays old, `age` grows, and admission answers `BUSY`, which is the right answer for a lane that is
behind. `age = rdtsc() − rx_ts` uses one TSC (invariant, synchronised across the cores of the ENA
socket, which holds every hot core, §9.3), so the AWS age has no mapping error at all. The
Nitro card's time before the completion is not ours, as 01 §14.0 states. A forwarded frame (§6.9)
keeps its original stamp.

**The TAI map.** Logs and market data need TAI, not PHC. A second seqlock line `(tsc0, tai0, mult,
shift)` is refreshed at 10 Hz from paired reads of `CLOCK_TAI` and `rdtsc`. It converts
`TscAtPoll` stamps to TAI for the `PacketRecord`; it is never used for admission. A box whose
`rx_ts` source is `TscAtPoll` says so in its health beacon, and 02 reports its fairness bound
separately.

### 8.5 AWS and the consumer box

**AWS.** Time comes from the Amazon Time Sync Service through the ENA PHC on the management ENI
(kernel `ena` driver, PHC enabled), read by chrony with `refclock PHC /dev/ptp0 poll 0 delay
0.000010 prefer` (vendor configuration). chrony owns `CLOCK_REALTIME`; the TSC map follows it.
The ENA PHC's accuracy is the vendor's, in the microsecond range, reported by chrony as the clock
error bound. Since all AWS `rx_ts` come from one TSC (§8.4), that error moves every stamp together
and never reorders two lanes.

**CONSUMER.** In a facility, the X2541 runs ptp4l exactly as NIC 0 on REF, and it has one
TSC↔PHC line (§8.4); the AM5 root port must offer PTM, which PLT-V-11 checks. There is one client
card, so there is no cross-NIC skew: the X2522 carries only order frames, whose `rx_ts` is never
used. In a lab with no grandmaster, the X2541 PHC free-runs from a one-time NTP set
(`phc2sys -s CLOCK_REALTIME -c <nic>` once at boot, then stopped) and the time state is `FREERUN`.

### 8.6 Time state and eligibility

```
             ptp4l s2 and |GM offset| < 100 ns for 60 s and skew < 50 ns
   UNSYNC ──────────────────────────────────────────────────────────────► LOCKED
     ▲  ▲                                                                   │  ▲
     │  │ holdover > PLT_HOLDOVER_MAX_S (300 s)        GM lost / ptp4l ≠ s2 │  │ GM back,
     │  └──────────────────────────── HOLDOVER ◄────────────────────────────┘  │ offset ok
     │                                   └─────────────────────────────────────┘
     │ skew > 100 ns for 1 s (from any state)
   SKEWED ── skew back < 50 ns for 60 s ──► UNSYNC
     │ any client card: map err0 > 20 ns or line > 50 ms old (from any state)
   MAPERR ── every line err0 < 10 ns for 60 s ──► UNSYNC
   FREERUN: lab and standalone CONSUMER only; never in a facility
```

| State | May sequence? | If this box is the active sequencer |
|---|---|---|
| `LOCKED` | yes | — |
| `HOLDOVER` | yes, until `PLT_HOLDOVER_MAX_S` | Nothing changes: the NIC PHCs still follow NIC 0, so cross-NIC skew is intact. Only absolute time drifts. |
| `UNSYNC` | no | Request a planned handover (07) at the next block boundary. |
| `SKEWED` | no | Request a planned handover at the next block boundary. |
| `MAPERR` | no | Request a planned handover at the next block boundary; lanes keep adding the bound (§8.4). |
| skew > `PLT_SKEW_HALT_NS` | no | Fail-stop now. Time priority across cards is wrong by more than a µs; a 20 ms failover is the smaller harm. |
| `FREERUN` | only with `facility = none` | — |

Replicas replay logged `rx_ts` and never read a clock for the engine, so their time state does
not affect replay or voting. Eligibility applies to sequencer-class boxes: it decides whether a
standby may be promoted (01 §14.4, 07) or a box scheduled as the next home's sequencer (08). `vyrn-timemon` publishes the state in the health beacon (§13.2).

## 9. AWS

### 9.1 Instance class

**Decision.** `c6in.metal` for the sequencer, data and market-data roles; `m6idn.metal` for
replicas, which need local NVMe. Both are x86-64, rated 200 Gbps (vendor), and run the `REF`
binary unchanged. `c7gn.metal` (Graviton, 200 Gbps, one socket) is the aarch64 alternative; it
needs the aarch64 build and is not the default.

Rule for any future instance type: the largest `.metal` type rated ≥ 200 Gbps whose ENA devices
can all be bound from one NUMA node. PLT-V-AWS-1 checks `/sys/bus/pci/devices/*/numa_node` for
every ENA. If an instance's network cards sit on two nodes, vyrn-seq binds only the devices of one
node and the box's bandwidth is that node's share. We do not trade one-node placement for
bandwidth: on AWS, 1B msgs/s depends on the instance's packet rate (01 §14.0, B16, §9.4), and
cross-node placement would put a remote hop inside the 1 µs.

### 9.2 DPDK on ENA

- One management ENI stays on the kernel `ena` driver: SSH, chrony with the ENA PHC (§8.5),
  consensus traffic of replicas (07), CloudWatch agent. Every data ENI is bound to `vfio-pci`.
- LLQ needs write-combining on the device's memory BAR. `vfio-pci` is used with write-combining
  enabled (the amzn-drivers project ships the procedure). PLT-V-AWS-2 fails a box whose ENA PMD
  logs that LLQ is disabled, because without LLQ every TX descriptor costs a DMA fetch.
- Queue count per ENI is read from `rte_eth_dev_info_get` at start; lanes are spread over ENIs so
  that each lane owns one RX queue.
- Security groups allow the client and replica flows with rules broad enough that the flows are
  untracked, so connection-tracking allowances never apply (vendor behaviour, checked by
  `conntrack_allowance_exceeded` staying 0).

### 9.3 Core map on `c6in.metal`

One socket's 32 cores (vendor: 64 cores in 2 sockets, SMT off with `nosmt`) on the ENA node:

| Core (offset from `H`) | Use |
|---|---|
| H | HOUSE |
| H+1 | cut core: one, because 24 lanes is within one REF half (25 lanes, 01 §14.3) |
| H+2 | BBO core |
| H+3 | fill TX core: one, because 24 lanes put about a third of REF's response rate on it (01 §14.17 needs three only at REF's rate) |
| H+4 | order-stream core: one stream (07 §4.1), so `need_B` is always 0 |
| H+5 | control (WARM) |
| H+6 | order hasher (07 §4.6) |
| H+7 … H+30 | `PLT_N_LANES_AWS` = 24 lanes |
| H+31 | spare |

The other socket runs consensus, catch-up, admin and metrics (WARM/HOUSE). 24 lanes at the REF
lane budget give ~480M msgs/s of lane compute (budget, before Ice Lake's lower clock); the
packet-rate allowance is the real limit (§9.4).

### 9.4 Packet-rate limits

AWS does not publish a packets-per-second limit per instance. The ENA reports when one is hit:
`pps_allowance_exceeded`, `bw_in_allowance_exceeded`, `bw_out_allowance_exceeded`,
`conntrack_allowance_exceeded`, `linklocal_allowance_exceeded` (vendor counters, read through the
PMD's xstats or the kernel driver's `ethtool -S`). Per-flow bandwidth is limited too: 5 Gbps per
flow outside a cluster placement group, 10 Gbps inside (vendor). Clients therefore spread sessions
over many source ports.

**PLT-B-AWS-PPS** (B16, to be measured): 8 client instances of the same type in one cluster placement
group drive 234-byte UDP frames at the sequencer, stepping the rate by 1M frames/s every 60 s,
while the sequencer echoes 322-byte responses. The result is the highest step with zero loss and
no increment of any allowance counter, in and out separately, repeated in three regions. That
number, times 10 messages per packet, is the AWS book's published ceiling. No target accepts
more than `MAX_MSGS_PER_PKT` messages per packet: a larger packet would raise the ceiling only by
exempting itself from `LAT_MAX_NS`, which 01 §14.0 forbids. The ceiling is stated as the AWS fact
of 01 §14.0, not as an exemption.

### 9.5 RSS and client-chosen source ports

ENA hashes with Toeplitz over the 5-tuple. If the instance lets vyrn-nic set the RSS key and
indirection table (checked at start with `rte_eth_dev_rss_hash_update`), the server can publish
them, and a client can pick, per lane, a source port whose hash lands on that lane's queue. Then
forwarding (§6.9) becomes the rare case instead of the common one. PLT-B-ENA-RSS measures the
mis-steer rate with and without it. The protocol field belongs to 04 (Open questions).

### 9.6 Replicas across AZs, and what AWS cannot do

Facilities map to Availability Zones: each replica in its own AZ, the sequencer and its clients in
one AZ in a cluster placement group. A region with fewer AZs than `N_BASE` (or `N_CHAIN`) has to
put two boxes in one AZ; an outage of that AZ then removes two votes and halts finality (safety
holds, liveness does not). That limit is published per region.

Cross-AZ transfer costs $0.01/GB in each direction (vendor). Each replica receives ~26 GB/s at
sustained peak (DESIGN §7): 26 GB/s × 86,400 s × $0.02 ≈ $45k per replica per day at peak, and
~$4.5k at 10% average load. This is why `REF` is colo.

What AWS cannot do, and what the spec says instead:

| Limit | Consequence |
|---|---|
| The wire is Nitro's | REQ-LAT-1 on AWS is a maximum from `rx_ts` (the TSC at RX completion) to the TX doorbell inside the instance, held by deadline admission; the wire-to-wire time is neither ours nor measurable (01 §14.0). |
| No CTPIO-class TX, no hardware RX stamp we rely on | Class C latency; `TscAtPoll` stamps with no mapping error in `age` (§8.4). |
| No flow steering | `HashThenForward`, +~100 ns per mis-steered packet. |
| Undisclosed PPS allowance | PLT-B-AWS-PPS sets the AWS ceiling. |
| No BIOS access | `nosmt`, kernel C-state limits; frequency is the instance's. |
| No own grandmaster, no multicast | Time Sync PHC; unicast market data. |

## 10. The consumer box

11 lanes and ~220M msgs/s per book: 11 × 33M × 0.6 ≈ 218M (budget). 01 §5 now has 11 lanes, but
01 §10 still says ~250M; the order hasher needs its own core, and the 16 cores hold only 11 lanes
beside it (Requests to 01, item 2). The BBO core has the REF budget, so the cross cap is unchanged; the
lanes are the limit.

Core map. `vyrn-admin` finds the V-cache CCD at start from
`/sys/devices/system/cpu/cpuN/cache/index3/size` (the CCD with the 96 MB L3) and refuses to start
if the map below would put the BBO, cut or TX core on the other CCD. Shown with V-cache on CCD 0:

| Core | CCD | Use |
|---|---|---|
| 0 | 0 (V-cache) | HOUSE + control (`HK`; REF keeps them off CCD 0 on core 51, which CONSUMER cannot spare) |
| 1 | 0 | cut core: one, because 11 lanes is less than one REF half (01 §14.3) |
| 2 | 0 | BBO core |
| 3 | 0 | TX core: fill TX on the X2541, order stream on the X2541 (path A) and the X2522 (path B) |
| 4 | 0 | order hasher (07 §4.6), ~13% loaded at a quarter of REF's packet rate |
| 5–7 | 0 | lanes 0–2 |
| 8–15 | 1 | lanes 3–10 |

The hasher is not merged into core 0, the cut core or the TX core. On core 0, a housekeeping stall
would delay a block's roots and so its finality. On the cut or TX core, a BLAKE3 slice would sit
on the ack or fill path.

Merging the two TX roles keeps `INV-FRAME-FIRST` trivially: one core writes the order frame, then
the fill, in program order. It is also the only CTPIO writer on the X2541 port, as §6.3 needs. At
~220M msgs/s the TX core sends ~22M responses/s plus ~5 Gbps of order frames, inside one core's
budget (PLT-B-X3D checks it).

Why the V-cache CCD: the BBO core reads level heads in every lane's FIFO and the filled-quantity
array, and the cut core reads 11 lane counters. Those lines live in the BBO core's L3 when it is
96 MB. The V-cache CCD clocks a little lower than the other (vendor); PLT-B-X3D runs B3 with the
BBO, cut and TX cores on each CCD and keeps the faster one. BIOS: §3.2 (PBO off). NICs: one X2541
for all client traffic and path A, one X2522 for path B (§2.6).

## 11. macOS for development

**Rule.** `cargo test --workspace` passes on macOS with default features, and no test needs a
Linux feature to run. Tests that need Linux (`efvi`, `dpdk`, `afxdp`, isolation, seccomp, huge
pages) are behind `#[cfg(target_os = "linux")]` in `vyrn-nic` and `vyrn-bench`, and CI runs them on
Linux runners.

| Works on macOS | Does not work on macOS, and what replaces it |
|---|---|
| Every engine, replay, consensus and protocol test, through `vyrn-sim` and the `sim` backend | Core isolation and pinning: macOS has no `isolcpus`, and `thread_policy_set` affinity is a hint that Apple silicon ignores. Threads use `QOS_CLASS_USER_INTERACTIVE` to prefer performance cores. |
| `kernel` backend: real UDP between processes, with kqueue | ef_vi, DPDK, AF_XDP: Linux only. |
| `vyrn-vx-oracle` and `vyrn-vx-client` builds, the oracle diff after every message | 1 GiB huge pages: none; regions are ordinary pages, so DEV latency numbers are never budgets or measurements. |
| `vyrn-replica` replaying recorded logs (B4 against a golden log) | `mlockall`: not used; vyrn-nic uses `mlock` per region and warns if it fails. |
| `vyrn-bench` microbenchmarks, reported as DEV-only | seccomp: none; the allocator trap (11 §3.5) still runs. |
| The sealing allocator, the asm gate's aarch64 mode | PTP and PHCs: none; `rx_ts` is `Kernel` or `Virtual`. |

`CACHE_LINE` is 128 on Apple M-series (§5.5); the shared-line pad is 128 everywhere, so layouts
are identical.

## 12. Host security

| Area | Measure |
|---|---|
| Boot chain | UEFI Secure Boot with the facility's db key; signed kernel and signed modules (`MODULE_SIG_FORCE`, Onload modules signed at build); `lockdown=integrity` (no unsigned kexec, no `/dev/mem`, no MSR writes). TPM 2.0 measured boot; the block-signing key file is sealed to the PCRs of this boot chain (09 owns keys). |
| Image | Read-only root (dm-verity) built from one manifest; `/var/lib/vyrn` and `/var/log` are the only writable mounts. No compiler, no package manager runs in production. |
| Accounts | No passwords. SSH by certificate through a bastion on the management VLAN, with per-person short-lived certs. `root` login disabled. The `vyrn` user owns the role process and has no shell. |
| Network exposure | The management port and the BMC are on separate networks; neither is reachable from client networks. On fast-path netdevs, nftables drops everything the bypass filters do not take, except ARP and PTP (EtherType 0x88F7) from the leaf. Unknown frames to vyrn-timemon's probe port are dropped by its VI filter. |
| Process | §4.8 sandbox; `CAP_IPC_LOCK` only; `PR_SET_DUMPABLE` 0, no core dumps, `MADV_DONTDUMP` on key pages; seccomp (§5.4). |
| Untrusted input | Client bytes are parsed only in Rust (`vyrn-wire`), never in the shim. A panic reachable from client bytes is a P0 bug (11 §3.8). |
| Time | PTP is unauthenticated, so PTP is accepted only on the leaf-facing port, switch ACLs admit PTP only from the boundary clock, and `vyrn-timemon` cross-checks NIC 0 against the second grandmaster's path. A spoofed master can move absolute time but not cross-NIC skew, which the probes measure on the box's own clocks. |
| Firmware | BIOS and BMC admin passwords from the secret manager; signed firmware only; versions pinned (§3.3); IPMI-over-LAN off, Redfish over TLS only. |
| Audit | `auditd` on `HK` with rules for `execve`, key-file access and module loads; journald forwarded off-box. |

## 13. Operating procedures

### 13.1 Boot

```
POWER_ON → FIRMWARE (BIOS effects, §14 items 1–4) → KERNEL (cmdline, sysctls, vyrn-tune)
 → TIME (vyrn-time.target: LOCKED or HOLDOVER) → NIC (open, self-test frame per port)
 → QUIET (60 s quiet probe on all isolated cores) → REPLICA_READY (may replay and vote)
 → ELIGIBLE (may be promoted or scheduled to sequence) → ACTIVE (sequencing) / DRAINING → DRAINED
```

A failed step stops the boot at that state and `vyrn-admin` reports which check failed and its
value. A box enters `ELIGIBLE` only from `REPLICA_READY` with time state `LOCKED` or `HOLDOVER`,
a passing quiet probe, a passing B1-mini (10^6 echoes per client port through the leaf, timed by
the box's own RX and TX hardware stamps: maximum RX + TX ≤ `NIC_FLOOR_NS`, maximum TX ≤
`PLT_TX_MAX_NS`, zero CTPIO fallbacks), every TSC↔PHC line below `PLT_TSC_MAP_ERR_NS`, and a
platform report less than 30 days old (`INV-PLT-5`).

### 13.2 Health checks while running

`vyrn-admin` publishes a signed health beacon every 100 ms on the control plane. 07 uses it to pick
failover targets and 08 to pick the next home's sequencer.

| Check | Period | Alarm | Makes the box ineligible |
|---|---|---|---|
| Time state, skew, GM offset | 100 ms | §8.3 | §8.6 |
| TSC↔PHC line per client card: `err0_ns`, age | 10 ms | > 10 ns | > 20 ns or > 50 ms old (§8.4) |
| `plt_lat_breach_total`: a response to an accepted packet with `tx_ts − rx_ts + PLT_RX_STAMP_OFFSET_NS` > `LAT_MAX_NS` (same card, same PHC, every frame) | every response | any | any; and an incident report |
| `plt_loop_gap_ns` per hot core | 1 s | gap > `PLT_JITTER_MAX_NS` | gap > `PLT_JITTER_MAX_NS` |
| minflt / majflt per hot thread | 10 s | any change | any change |
| NIC counters: drops, `evq_overflow`, `fatal_hw`, `plt_ctpio_fallback_total` | 1 s | any fallback | link down, fatal counters, any fallback |
| `plt_tlb_syscall_denied_total` | 10 s | any change | — |
| Temperature (k10temp), PROCHOT, EDAC corrected errors, MCE (rasdaemon) | 10 s | any corrected error | an uncorrected error or throttling |
| NVMe (replicas): media errors, write latency p99.9, free space | 60 s | p99.9 > 2 ms | media errors |

### 13.3 Drain

1. `vyrn-admin drain` sets `DRAINING` and the beacon says so.
2. If the box is `ACTIVE`, it asks 07 for a planned handover at the next block boundary; the
   home's warm standby `vyrn-seq` takes over (01 §14.4) and this box becomes the standby.
3. If the box is a replica, it keeps voting until the facility has its full replica set healthy
   elsewhere. In base mode a drained replica leaves `N_BASE − 1` = `Q_BASE` votes, so only one box
   per replica set drains at a time and only when the others are healthy.
4. The role process stops; the box is `DRAINED`. §4.9's banned operations are now allowed.

### 13.4 Maintenance windows

A home is active 8 h of 24 (01 §5). Kernel, firmware and BIOS changes happen on a box whose home
is inactive for at least the next 12 h, one box per replica set at a time, each followed by the
§14 checklist and B1–B5 before the box returns to `ELIGIBLE`.

## 14. Validation checklist

### 14.1 Before a box joins a facility

Each line is a PLT-V check; `vyrn-admin validate` runs all of them and signs the platform report.
Thresholds are budgets.

| # | Check | Pass |
|---|---|---|
| 1 | Inventory against the role's BOM (`dmidecode`, `lspci`, `nvme list`) | exact match |
| 2 | Firmware versions (BIOS, BMC, NIC, NVMe) | the facility's pinned set |
| 3 | BIOS effects of §3 (SMT, C-states, NPS1, memory speed and ECC, ASPM, IOMMU, TSME, Secure Boot) | every row of §3.1 or §3.2 |
| 4 | PCIe links and the §2.3 lane plan: each NIC Gen3 x16 (X2541, X2542), Gen4 x16 (CX-6 Dx) or its rated width; each NVMe Gen5 x4; optics RX power with the observer taps fitted | `LnkSta` = `LnkCap`; RX power inside the module's budget |
| 5 | Kernel version, `/proc/cmdline`, required config, sysctls | byte-exact against the generated set |
| 6 | Isolation: IRQ affinities, workqueue mask, kthread affinities (§4.3 step 6); `nohz_full` includes core 0 on REF | no isolated core named; `HK` = 51 is the only housekeeping core |
| 7 | Quiet probe, 600 s, all isolated cores, with housekeeping load | §4.11: largest gap ≤ 20 ns, 0 interrupts, 0 context switches |
| 8 | Memory: STREAM triad over all cores; idle load-to-use latency | ≥ 450 GB/s; ≤ 130 ns |
| 9 | Cross-CCD hop (PLT-B-HOP): one-line ping-pong CCD0 ⇄ CCD1…7; pool CAS ping-pong among cores 56–62 (PLT-B-POOL) | one-way maximum ≤ 100 ns (the hop of 01 §14.2) over 10^9 pings with every other core at full load; pool CAS ≤ 20 ns p99.99 and ≤ `PLT_JITTER_MAX_NS` max (01 §14.15) |
| 10 | Frequency under full busy-poll for 1 h | every hot core within 1% of the fleet median; no throttling |
| 11 | NIC function (PLT-V-11): CTPIO and RX/TX hardware stamps on every port, both ports of each X2542 written at once; PTM `PTP_SYS_OFFSET_PRECISE` on every client card | one stamped frame each way; cross-timestamp succeeds |
| 12 | B1 echo per client port, through the tap rig (§14.2), ≥ 10^9 echoes at the reference workload's frame mix and full port load | **maximum** RX + TX ≤ `NIC_FLOOR_NS` = 560 ns over the whole run; **maximum** TX ≤ `PLT_TX_MAX_NS` = 240 ns; zero CTPIO fallbacks. A single echo over either bound fails the card in that slot |
| 12a | PLT-B-XTS: TSC↔PHC map per client card, 24 h | `err0_ns` ≤ 10 ns throughout; every PTM sample inside both brackets (§8.4) |
| 13 | PLT-B-PPS per port: 30M frames/s of 234 B for 600 s | zero drops |
| 14 | Time: 1 h LOCKED | NIC 0 GM offset p99 ≤ 100 ns; cross-NIC skew p99.9 ≤ 25 ns |
| 15 | NVMe (replica, archive): O_DIRECT sequential write, all log drives, 1 h | ≥ 40 GB/s (replica); write p99.9 ≤ 1 ms; PLP reported |
| 16 | Burn-in: 24 h full load | 0 uncorrected, ≤ 1 corrected ECC error; 0 MCE |
| 17 | B4 on this box: replay the facility's golden log | identical fills and state hash |
| 18 | Security: Secure Boot, lockdown, dm-verity, SSH config, nftables, BMC network | all as §12 |

A box that fails any line does not join. A box re-runs lines 3–7, 10–14 (with 12a) and 17 after
any kernel, BIOS or firmware change, and the whole list after any hardware change.

### 14.2 The B1 tap rig

Passive optical splitters on the box's RX and TX fibres feed a capture box with one dual-port
ConnectX-7 whose two ports share one hardware clock (checked: both netdevs report the same PHC
index). It stamps the first bit of each frame in and out of the device under test. ASIC NICs only
(§2.9).

The rig gives the total, first bit in to first bit out. The box splits it with its own clocks: RX
= the TSC of the poll that saw the frame, mapped to the card's PHC (§8.4), minus `rx_ts`; TX = the
card's TX hardware stamp minus the TSC of the CTPIO write, mapped the same way. The rest of the
total, rig minus (`tx_ts − rx_ts`), is the two MAC stamp offsets; the run fixes
`PLT_RX_STAMP_OFFSET_NS` per card from it, with a calibration error ≤ `PLT_RX_STAMP_CAL_NS`. B1
reports the maximum of each part and of the total, never a percentile alone.

### 14.3 B-GPU: the only path that can reopen the GPU ban

B-GPU is a placeholder lab benchmark (11 assigns its number). It runs a **GPU-initiated NIC
echo**: a GPU kernel polls an RX ring placed in GPU memory and posts the TX descriptor and doorbell
itself, with no CPU on the path, through the B1 tap rig, at the B1 workload.

| Item | Rule |
|---|---|
| Pass | maximum RX + TX ≤ `NIC_FLOOR_NS` = 560 ns over the whole run, with the TX maximum ≤ `PLT_TX_MAX_NS`, the same as a NIC under B1 |
| Effect of a pass | It may reopen `C-NOCHIP` for discussion in 01. It changes nothing by itself. |
| Until 01 changes `C-NOCHIP` | No GPU on any role, any target (§2.9). The benchmark box is a lab box and never joins a facility. |
| Effect of a fail | Recorded with the numbers; the ban stands. |

## Interfaces to other chapters

| Chapter | This chapter consumes | This chapter provides |
|---|---|---|
| 01 | Targets and REF core map (§10), §14.0–§14.17, `CACHE_LINE`, `NIC_FLOOR_NS`, `DEADLINE_GUARD_NS`, `REPL_PATHS`, `N_LANES_*`, `INV-NOALLOC`, `INV-FRAME-FIRST`, determinism rule 3 | Requests below |
| 02 | REQ-PLT-*, REQ-LAT-1's measurement point | `plt_w2w_ns` and `plt_lat_breach_total` from NIC TX − RX stamps (§6.3, §13.2); latency classes (§6.8); the AWS ceiling from PLT-B-AWS-PPS (B16); `TsSource` per target for the fairness bound |
| 04 | `PORT_BASE`; the lane address map in session setup; resend after a dropped frame | IPv4/UDP fast-path frame rules (§6.2); the RSS-key field question (§9.5); no packet over `MAX_MSGS_PER_PKT` on any target (§9.4) |
| 05 | Region contents and sizes; the lane loop's poll order; deadline admission's `predicted_path_ns` | `RxRing`/`TxRing` contracts, `rx_ts` monotonic per queue, the `PhcMap` line and the `age` formula (§8.4), `PLT_TX_MAX_NS`, the gap share of the guard (§4.11), forward rings for `HashThenForward` (§6.9), core classes (§4.9) |
| 07 | Planned-handover and failover APIs; the replica core map; the stream split and the order hasher; segment format and retention; data-node count | Eligibility and the health beacon (§8.6, §13.2); BOM and lane plan for sequencer, replica and archive nodes (§2.2, §2.3); replication NICs 4–5 as dual-port X2542, port a for stream-A and port b for stream-B; 12 × 61.44 TB per replica; the TX-core → client-port map (§2.3); polled NVMe I/O (§4.7) |
| 08 | Next-home sequencer selection | Eligibility of each box (`INV-PLT-5`) |
| 09 | Key custody | TPM-sealed key files, no core dumps, `MADV_DONTDUMP` (§12) |
| 10 | Market-data fan-out; the observer role and its taps; the lane map's pool class | Observer BOM and lane plan, 3 × CX-6 Dx + 3 × X2541 (§2.2, §2.3 rule 7); tap power budget (§2.4); multicast in colo, unicast on AWS; pool lanes on one card (§6.3) |
| 11 | Shim flags and gates (§4), `BLD_SHARED_ALIGN`, sealing allocator, B-numbers | `shim.h` (§7.2), the ops-table decision (§7.3), PLT-B/PLT-V definitions for 11 to number, `-z now` link flag, an `afxdp` module in `UNSAFE.toml` |

## Local definitions

Constants (budgets unless marked):

| Name | Value | Meaning |
|---|---|---|
| `PLT_HUGEPAGES_REF` / `_CONSUMER` | 640 / 104 | 1 GiB pages reserved at boot |
| `PLT_TLB_PAGES_MAX` | 16 | Distinct 1 GiB pages one hot core touches |
| `PLT_TX_MAX_NS` | 240 | Maximum CTPIO write → first bit out on an idle port; B1 checks it as a maximum |
| `PLT_TSC_MAP_ERR_NS` | 10 | TSC↔PHC error budget; alarm above it; ineligible above `DEADLINE_GUARD_NS` |
| `PLT_TSC_MAP_REFRESH_MS` / `_STALE_MS` | 10 / 50 | Cross-timestamp period; line age that makes the box ineligible |
| `PLT_PHC_RATE_STEP_PPB` | 100 | Largest PHC/TSC rate change per refresh inside the budget |
| `PLT_RX_STAMP_OFFSET_NS` | per card, measured | First bit in → the card's RX stamp (§14.2) |
| `PLT_RX_STAMP_CAL_NS` | 10 | Calibration error of that offset; inside the guard |
| `PLT_STACK_TOUCH` | 256 KiB | Stack prefaulted per hot thread |
| `PLT_ONBOX_HOT_H` | 12 | Hours of log kept on a replica's own NVMe at ≤ 20% average load (01 §14.16) |
| `PLT_ONBOX_HOT_H_PEAK` | ≥ 6 (7.9 budget) | Hours kept at sustained peak (737 TB ÷ 26 GB/s) |
| `PLT_POOL_CORES` | 7 | Pool cores, one CCD (cores 56–62 on REF) |
| `PLT_POOL_STEAL_FRAMES` | 1 | Frames a core takes from a sibling's VI per steal |
| `HK` | 51 (REF), 0 (CONSUMER), `H` (AWS) | The housekeeping core |
| `PLT_RX_BURST` | 16 | Frames per `poll` (`vyrn_wire::RX_BURST`) |
| `PLT_TX_REAP_EVERY` | 32 | Sends between TX reaps |
| `PLT_CTPIO_CT_BYTES` | 64 | CTPIO cut-through threshold |
| `PLT_FRAME_HDR_BYTES` | 42 | Ethernet + IPv4 + UDP |
| `PLT_FWD_RING_SLOTS` | 1024 | Slots per forward ring (256 B each) |
| `PLT_N_LANES_AWS` | 24 | Lanes on `c6in.metal` |
| `PLT_N_LANES_CONSUMER` | 11 | Lanes on the 9950X3D beside the order hasher (§10) |
| `PLT_JITTER_FLOOR_NS` | 16 | Smallest gap the probe records |
| `PLT_JITTER_WINDOW_S` | 600 | Quiet-probe window |
| `PLT_JITTER_MAX_NS` | 20 | Largest allowed gap on a hot core, ever; all of `DEADLINE_GUARD_NS` = 20 |
| `PLT_SKEW_BUDGET_NS` | 25 | Cross-NIC PHC skew, p99.9 |
| `PLT_SKEW_ALARM_NS` / `_INELIGIBLE_NS` / `_HALT_NS` | 50 / 100 / 1000 | §8.3 |
| `PLT_GM_OFFSET_NS` | 100 | NIC 0 to grandmaster, p99 |
| `PLT_HOLDOVER_MAX_S` | 300 | Holdover during which a box stays eligible |
| `PLT_PROBE_UDP_PORT` | 319xx, site-configured | `vyrn-timemon` probe port |

Types: `BackendKind`, `Steering`, `Caps`, `LatencyClass` (A, B, C, D, E, S), `TsSource`,
`RxBind`, `TxClass`, `NicError` (§6.1); `PhcMap` (§8.4); `TimeState` (`UNSYNC`, `LOCKED`,
`HOLDOVER`, `SKEWED`, `MAPERR`, `FREERUN`); `PlatformState` (§13.1); `CoreClass` (`HOT`, `WARM`,
`HOUSE`).

Invariants:

| Name | Statement |
|---|---|
| `INV-PLT-1` | After `seal()`, a HOT thread makes no syscall outside §5.4's allowlist, takes no page fault and never blocks. |
| `INV-PLT-2` | No PHC and no system clock is stepped while a role process is `ACTIVE`. |
| `INV-PLT-3` | Every isolated core runs at most one thread of the role process, under `SCHED_OTHER`; a spare core runs none. |
| `INV-PLT-4` | No operation that sends an IPI to every CPU (§4.9 rules 1–6) runs while a role process is `ACTIVE`. |
| `INV-PLT-5` | A box sequences only in `ELIGIBLE` or `ACTIVE`, with time state `LOCKED` or `HOLDOVER` (or `FREERUN` with `facility = none`). |
| `INV-PLT-6` | A lane's `age` is never less than the true age of the packet: it adds the map's error bound and the RX stamp offset (§8.4), and on AWS `rx_ts` is a lower bound on the RX completion. |
| `INV-PLT-7` | Each fast-path TX port has exactly one CTPIO writer core. |
| `INV-PLT-8` | A pool VI has at most one consumer at a time, and every consumer is a core of the pool's CCD. |

Benchmarks and checks defined here (11 assigns B-numbers): PLT-B-PPS (§6.3), PLT-B-SW (§2.4),
PLT-B-HOP and PLT-B-MEM (§14 items 8–9), PLT-B-FREQ (§3.1 slider), PLT-B-MIT (§4.4),
PLT-B-SKEW (§8.3), PLT-B-XTS (§8.4), PLT-B-AWS-PPS (§9.4, B16), PLT-B-ENA-RSS (§9.5),
PLT-B-X3D (§10), PLT-B-POOL (§14 item 9), B-GPU (§14.3), PLT-B-INJ and PLT-B-TSME (Open questions); PLT-V-1…18 and 12a
(§14.1), PLT-V-AWS-1…2 (§9).

## Requests to 01

Resolved by 01 §14 and removed: the AWS `rx_ts` rule (§14.11), the X2522 for CONSUMER path B
(§14.7), response retention (§14.6), the observer box (§14.16), the frame-gate wording (§14.16),
TX ≤ 240 ns as its own maximum (§14.16), `N_LANES_CONSUMER` = 11 (§5) and the guard (§14.1:
`DEADLINE_GUARD_NS` = 20, all gap budget). Open:

1. **§11 rule 3:** "the NIC RX timestamp" becomes "the RX timestamp: the NIC hardware stamp where
   the backend has one, else the TSC of the last poll that drained the queue, mapped to TAI
   (06 §8.4)". This makes 01 §14.11's "TSC at RX completion" a lower bound, so `age` is never
   under-stated (`INV-PLT-6`).
2. **§10 CONSUMER:** ~220M msgs/s, not ~250M, at 11 lanes (06 §10). Add the CONSUMER and AWS core
   maps (06 §10, §9.3) with one cut, one TX and one stream core each, and `N_LANES_AWS` = 24.
3. **§10 REF row and §14.7:** the NIC column becomes per role: sequencer and standby 4 × X2541
   client plus 2 × dual-port X2542 replication, one port per stream core (06 §2.3 rule 4; two
   stream cores on single-port cards would break `INV-PLT-7`); replica 4 × X2541; observer
   3 × CX-6 Dx + 3 × X2541. §14.7's replica drives are already 12 × 61.44 TB (resolved by 01).
4. **§5:** add `PLT_TX_MAX_NS` = 240 as `NIC_TX_MAX_NS`, the name for §14.16's TX maximum.
5. **§14.1:** say that the RX stamp's calibration error (≤ 10 ns) is added to `age` like the
   TSC↔PHC error, now that the guard is gap budget only (06 §4.11, §8.4).
6. **§7:** promote `INV-PLT-2` (no clock step while active) to `INV-NOSTEP`, `INV-PLT-6` (age is
   never under-stated), `INV-PLT-7` (one CTPIO writer per port) and `INV-PLT-8` (one pool VI
   consumer at a time, inside the pool's CCD).
7. **§5:** add `PORT_BASE` (value from 04) and `SKEW_BUDGET_NS` = 25, which 02's fairness
   requirement cites.
8. **§9:** list the `vyrn-nic` backends (`efvi`, `dpdk`, `afxdp`, `kernel`, `sim`) and note that the
   ring traits live in `vyrn-wire` (11 §1.3) while `NicBackend` lives in `vyrn-nic`.
9. **§5 and §14.3:** *Resolved by 01:* §5 has `N_LANES_REF` = 49 (0–48: 42 dedicated, 7 pooled), and
   §14.3 has cut B on lanes 25–48 with the hasher on core 50. 06 uses 49 lanes and the §10 map.
10. **§10:** name the fill TX core → client port map: TX-A NIC0, TX-B NIC2, TX-C NIC1 and NIC3
    (06 §2.3 rule 3). The map's "TX-A lanes 0–24, TX-B lanes 25–48" cannot hold with three TX
    cores and one CTPIO writer per port.

## Open questions

Resolved by 01 §14 and removed: response retention (§14.6) and the replica on-box window with the
archive node (§14.7).

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Does the X2541 meet `NIC_FLOOR_NS` (maximum RX + TX ≤ 560) and TX ≤ 240 as a maximum on the 9575F with `iommu=pt` and TSME on, in every slot? | 06 | B1 per slot |
| 2 | Does ConnectX-6 Dx or ConnectX-7 with `dpdk` reach class A? | 06 | B1 on mlx5 |
| 3 | Can phc2sys hold cross-NIC skew ≤ 25 ns p99.9 on the X2541, or must `vyrn-timemon` servo? | 06 | PLT-B-SKEW, 24 h |
| 4 | Determinism slider: does Performance cost more than 2% of B3's cross maximum against Power? | 06 | PLT-B-FREQ |
| 5 | Do mitigations or TSME change B3's p99.99 or maximum by more than 1%? | 06 | PLT-B-MIT, PLT-B-TSME |
| 6 | Does NIC RX DMA land in L3 on Zen 5 (TPH/cache injection), and does enabling it lower the RX budget of 320 ns? | 06 | PLT-B-INJ: B1 with and without TPH steering tags |
| 7 | What packet rate does AWS allow per instance, in and out? | 06 measures, 02 publishes | PLT-B-AWS-PPS (B16) |
| 8 | Should 04 carry the RSS key so AWS clients pick source ports per lane? | 04 | PLT-B-ENA-RSS mis-steer rate |
| 9 | Does `sfc` implement a PTM `getcrosststamp` on SP5, and does the kernel map PTM time to the TSC on AMD (the x86 path uses Intel's ART)? If not, the X2541 fails PLT-V-11 and the client NIC changes to one that passes B1 and PLT-B-XTS. | 06 | PLT-B-XTS on the REF box |
| 10 | Can a REF box hold 0 interrupts and no gap > 20 ns on every hot core for 600 s (SMIs, residual tick, frequency transitions)? If not, the guard split changes, never the maximum. | 06 | quiet probe, 24 h, on three boards |
| 11 | Data-tier fan-out: how many data nodes per facility, multicast or unicast to replicas? | 07 | data-tier load test at 190 Gbps |
| 12 | Port queueing: a response written behind k frames on its port leaves ~26 ns × k later, outside `PLT_TX_MAX_NS`. Proposed: the TX core keeps a per-port busy-until clock, sends in `rx_ts` order, and admission's `predicted_path_ns` adds the published backlog bound of the lane's card. | 05 with 06 | B3 at full load with adversarial 1-message packets that get 16-record responses |
| 13 | Does Linux 6.6+ accept core 0, the boot CPU, in `nohz_full` and `isolcpus` with core 51 as the only housekeeping core, and stay quiet on core 0 (TX-C) for 600 s? If not, TX-C moves to a spare (52–55) and 01 §10 changes. | 06 | PLT-V-5 and the quiet probe on core 0 |
| 14 | Do both ports of an X2542, written at once by two CTPIO writers, keep zero fallbacks and TX ≤ 240 ns? | 06 | B1 and B-REP-2W on both ports of NIC4 and NIC5 at once |
| 15 | Pool steal path: under B3's full load, how often does a home core find its own VI locked by a stealer, and does that wait stay inside `PLT_JITTER_MAX_NS`? | 06 with 05 | PLT-B-POOL plus B3 per class (01 §14.17 item 2) |
| 16 | The archive node's feed at sustained peak is ≤ 25 Gbps against ~180 Gbps of ingest; past the ≥ 6 h on-box window a sustained peak loses archive coverage. Is a third replica data port or a direct archive subscription needed? | 06 with 07 | archive lag at sustained peak for 8 h (07 B-REP-9) |
