# 08. Epochs: follow the sun

Draft 0.2, 2026-11-13. Normative. `01-conventions.md` wins over this chapter. Source:
`DESIGN.md` §6. Local names use the prefix `EPO_` (constants) and `Epo` (types).

## 0. Scope, decisions and constraints

This chapter specifies how a book moves home every `EPOCH_HOURS`: schedule, handoff per role,
certificate, window and its floor, opening auction, fencing, keys and membership, failures, client
migration and chaos tests. Simplex (07), continuous matching (05), sessions (04) and validator keys
(09) are specified elsewhere.

| # | Decision | Reason (section) |
|---|---|---|
| E1 | Epoch numbers are 8-hour **slots**: epoch e is nominally `[G + 8h·e, G + 8h·(e+1))`, G = genesis (00:00 UTC). `home(e) = [TYO, LDN, NYC][e mod 3]` unless a `HomeOverride` exists (09). | Keys, sequencer rotation and bonds are a pure function of e (09 §3.1). Clients compute the schedule without asking anyone (§2). |
| E2 | The boundary is the log position `(e, S)` in a certificate, never a time. T only triggers the seal. | Clock skew then changes the window length and never the history (§8.3). |
| E3 | The handoff is a certificate: `Q` voting replicas of the old replica set sign one `HandoffRecord`. `vyrn-seq` never votes and never signs (01 §14.4). There is no WAN consensus round. | One WAN one-way is the floor (§6.3). A second crossing would double the window. |
| E4 | The new home is a follower until it holds the certificate. It collects orders from T, answers each within `LAT_MAX_NS` with a queued `Ack`, finalizes their order in window blocks, applies them speculatively when the log tail arrives, and uncrosses an opening auction when the certificate arrives. | W ≤ t_wan + `FINALITY_MAX_MS` + `EPO_WINDOW_SLACK_MS` (3 ms) at any load (§6). |
| E5 | Window orders are collected without matching and uncrossed once: maximum volume, minimum imbalance, nearest the reference, lowest tick. Allocation is price-time. | The auction is the fair use of a window that physics forces (DESIGN §6). |
| E6 | The go/no-go is decided 10 s before T and logged. Without `Q` ready voting replicas and both ready `vyrn-seq` boxes (primary F1, warm standby F2) at the new home, the old home holds the book and retries every 15 min. | A handoff into a home that cannot reach quorum, or that has no standby, can halt the book on one fault. A hold costs nothing (§2.6, §10.2). |
| E7 | After the seal the old home never resumes on its own. If the new home cannot activate, the book halts until it does or until `Q` operators sign a reassignment. | Automatic resumption across a partition is a fork (§10.3). |
| E8 | Sessions survive the boundary (01 §14.8). `SessionId`, `pkt_seq` and `resp_seq` continue; only the keys rotate. Window answers use a separate window stream (§7.11). | The new home deduplicates every resend against the certified state at S, so no order is lost or applied twice (§11). |
| E9 | Membership, lane map, keys and software versions change only at a boundary, and are fixed in the log at least `EPO_CONFIG_LEAD_S` before it. | The certificate then covers the configuration of the next epoch (§9). |
| E10 | Every packet that reaches either home's sequencer gets its first response within `LAT_MAX_NS`, in the window too, and deadline admission and `BUSY` (01 §14.1) apply there unchanged. Only the **fill** of a window order waits for the uncross. | 01 §14.0: the window exempts the fill and nothing else (§7.11). |

How the chapter meets the hard constraints:

| Constraint | How |
|---|---|
| C-UNIX | Every role here is a thread of `vyrn-seq`, `vyrn-replica`, `vyrn-validator` or `vyrn-data` on Linux. `vyrn-sim` runs every protocol in §12 on macOS. |
| C-NOCHIP | The uncross runs on the lane cores and the BBO core. Signatures and hashes run on general-purpose cores. No switch, NIC or GPU runs our logic. |
| C-COTS | The WAN is leased 400G wavelengths with merchant routers. Time comes from GPS-disciplined PTP grandmasters bought off the shelf. |
| C-ONEBIN | The same binaries run in every home. `home`, roster and lane count are configuration. |

## 1. Words used in this chapter

| Term | Meaning |
|---|---|
| `R_e` | The replica set of epoch e: the voting members in `home(e)` only (01 §14.4). BASE: R1 (F1, beside `vyrn-seq`) and R2–R4 (F2–F4), 2 Rust and 2 Vx. CHAIN: the 5 validator boxes, 3 Rust and 2 Vx (`INV-CHN-SPLIT`). |
| sequencer boxes | The two `vyrn-seq` boxes of a home: the primary in F1 and the warm standby in F2. They never vote. `seq_order` lists them (§2.3). |
| old home, new home, third home | `home(e)`, `home(e+1)` and the remaining home, for the boundary between e and e+1. |
| T | The scheduled end of epoch e in TAI nanoseconds: `G + 8h·(e+1)`, or a later time set by a hold (§2.5). |
| window | The time from the last fill of epoch e until every lane of the new home is **live**, that is, it fills each packet on arrival again (§7.10). Symbol W. |
| queued Ack | The window's 1 µs answer: an `Ack` with flag `EPO_ACK_QUEUED`, which says that the message is in the log of e+1 and is resolved at the uncross (§7.11). |
| window block | A block of e+1 that holds only window `PacketRecord`s and no step. `R_{e+1}` finalizes it before the certificate arrives (§7.1). |
| tail | The part of epoch e's log and data that the new home does not yet hold at T. |
| S′ | The last step of epoch e as the new home's speculative replay sees it, before the certificate. |
| activation | The moment the new sequencer has verified the certificate and its state at S. It then uncrosses. |
| carried order | An order that rests in the book at S and therefore enters epoch e+1. |

## 2. The schedule

### 2.1 Boundaries

`EPOCH_BOUNDARIES_UTC` is 00:00 TYO, 08:00 LDN, 16:00 NYC. The boundaries are UTC and fixed.
Daylight saving time moves the local opening hour of LDN and NYC by one hour, and never the
boundary. The reason: a boundary in UTC is a constant that every client, replica and light client
computes with no time-zone table.

```
UTC     00:00         08:00         16:00         00:00
         │── e ≡ 0 ───│── e ≡ 1 ───│── e ≡ 2 ───│── e+3 ...      (e mod 3)
home     TYO           LDN           NYC           TYO
local    09:00 JST     08:00 GMT     11:00 EST     09:00 JST
                       (09:00 BST)   (12:00 EDT)
```

T is stored and compared as TAI nanoseconds (`Nanos`, 01 §3). The conversion from the UTC
boundary uses the TAI − UTC offset in force at genesis plus any announced leap second. A leap
second changes the TAI value of later boundaries; it is published in `EpoConfig` like any other
change (§2.3).

### 2.2 Epoch numbers

Epoch e is the slot that starts nominally at `G + 8h·e`. The numbering never depends on what
happened: a hold makes epoch e longer and e+1 shorter, and a skip leaves an epoch number unused
(§2.5). Reasons: 09 derives the sequencer operator (`e mod 5`), session keys and bonds from e alone,
up to 4 epochs ahead; and a client computes the next epoch, home and T from the clock and `G`
alone, so it needs an `EpochNotice` only for a revision.

`Epoch` is u32 and the wire carries its low 16 bits (`epoch16`): 2^16 slots are 59.8 years
(computed). `epoch16` is only ever tested for equality with the receiver's epoch, so it may wrap.

### 2.3 `EpoConfig`: the configuration of the next epoch

Everything that differs between epochs is fixed in one record in the log of the epoch before.

```rust
struct EpoConfig {            // control record in the log of epoch e (07 control path; CHAIN: tx path, 09)
    epoch: Epoch,             // the epoch it configures, > e
    home: HomeCode,           // home(epoch) after any HomeOverride
    t_start: Nanos,           // nominal start (TAI); T of the epoch before it
    roster_hash: Hash,        // the roster of all three homes: keys and replica addresses (§9.6)
    seq_order: [u8; 2],       // roster indices of home(epoch)'s vyrn-seq boxes: [primary F1, warm standby F2] (01 §14.4)
    lane_map_hash: [Hash; 3], // lane_map(epoch) for each home's class sizes, TYO, LDN, NYC (10 §1.3)
    n_lanes: [u8; 3],         // lane count of each home's boxes, TYO, LDN, NYC: n_ded + n_pool (REF 42 + 7)
    version: u32,             // engine semantics version in force for the epoch (§9.4)
    endpoint_hash: Hash,      // the endpoint table of all three homes (§11.1)
    flags: u16,               // bit0 skip (the epoch is empty), bit1 date roll, bit2 leap second
    sig_scheme: SigScheme,    // scheme of every live key and signature of `epoch` (01 §3, §14.20)
}
```

Rules:

- The `EpoConfig` for e+1 must be final at least `EPO_CONFIG_LEAD_S` (3,600 s) before T. If it is
  not, the replicas carry the previous epoch's configuration forward with `home`, `t_start` and
  `seq_order` recomputed from the schedule. Reason: a missing record must never block a handoff.
  `roster_hash`, `lane_map_hash`, `n_lanes` and `endpoint_hash` cover all three homes, so carrying
  them forward stays right when `home` changes; `home(epoch)`'s part is read at use. The
  recomputed `seq_order` is the schedule's for the carried roster at `home(epoch)` (§9.6).
  A carried `lane_map_hash` names the maps of the previous epoch; replicas apply its entry for
  `home(epoch)`, which was computed for that home's class sizes.
- 10 publishes the full `lane_map(e+1)` with the same lead (10 §1.4, `ACC_MAP_PUBLISH_LEAD_S`).
- The `HandoffRecord` covers `EpoConfig` through `log_hash`, so the certificate certifies the next
  epoch's configuration as well as the final state.
- **`sig_scheme`** follows 01 §14.20 SG1–SG7, the signature form of 04 §12's VR4: it changes only
  here, at a boundary, never decreases, and `roster_hash` of an epoch with `sig_scheme` ≥ 1 names
  hybrid keys only (the roster's `sig_scheme` equals the config's, §9.6). A carried-forward configuration (first rule) keeps the previous
  `sig_scheme`, so a missing record cannot downgrade it. `HandoffCert(e)` is signed under
  `EpoConfig(e).sig_scheme` and certifies `EpoConfig(e+1)`, so the last scheme-0 certificate
  certifies the first hybrid roster.

### 2.4 How T is announced: `EpochNotice`

Every lane sends an `EpochNotice` record (01 §6.4) to each of its sessions at fixed offsets
before T, and once more at the seal.

| When | Trigger (deterministic) | Content |
|---|---|---|
| `EPO_NOTICE_OFFSETS_S` = 3,600, 600, 60, 10, 1 s before T | The lane's first packet with `rx_ts ≥ T − offset` | next epoch, next home, `ceil((T − rx_ts) / 1e9)` s |
| Session open | The open itself (04) | same |
| After a revision (hold, skip, sequencer change) | The lane's first packet after the revising record's step | same, flags bit0 = revised |
| Seal | The lane's first packet with `rx_ts ≥ T` | seconds = 0 |
| After the seal, at the old home | Any packet of the session | seconds = 0, out of stream (§10.7) |

The notices before the seal are in-stream responses. They are a pure function of logged packets,
so replicas reproduce them bit for bit (`INV-DET`). The trigger is a logged `rx_ts` and not a timer,
because timers fire on order-stream time only (01 §11.3). A session that sends nothing gets the
notice in the response to its next heartbeat. 04 requires a heartbeat at least once per second.

`EpochNotice` has three free bytes. This chapter uses byte 1 for the `seq_index` of epoch e+1 and
bytes 2–3 for flags: bit0 revised, bit1 hold, bit2 skip, bit3 date roll, bit4 endpoint table
changed (Requests to 01, item 1).

### 2.5 Holds, skips and overrides

There are three ways the schedule changes. Each is a record in the log, so it is certified.

| Change | Record | Decided | Effect |
|---|---|---|---|
| **Planned skip** of epoch e+1 | `EpoConfig{epoch: e+1, flags.skip}` | ≥ `EPO_CONFIG_LEAD_S` before T | The old home keeps epoch e through slot e+1. The next handoff is from e to e+2 at T + 8 h. |
| **Home override** | `HomeOverride{epoch, home}` (09 §2.10; BASE: admin) | ≥ `EPO_CONFIG_LEAD_S` before T | `home(e+1)` changes. If it equals `home(e)`, the handoff is in-metro (§6.2, last row). |
| **Hold** (unplanned) | `EpoHold{epoch: e, t_new}` | at the go/no-go (§2.6) | T becomes `T + EPO_HOLD_S` (900 s). Epoch e runs on. The target stays e+1. |

A skip keeps the old home instead of handing to the home after the skipped one. The reason: the old
home's staff and replicas are on shift and healthy, and every extra handoff costs one window. A
skipped epoch number is never used; `EpoGo` names the next epoch (§2.6, §5.1).

A hold that would push T past the nominal end of slot e+1 retargets the handoff to e+2 with
`home(e+2)`. The skipped slot e+1 is then unused, as with a planned skip. The reason: epoch e+1's
keys and sequencer belong to a slot that has passed (09 §3.1).

A hold never shortens anything, and T has no upper bound: if no home is ever ready, the old home
keeps the book. That is the only safe default.

### 2.6 Go/no-go

At `T − EPO_GO_LEAD_S` (10 s) the old home decides whether to hand off. The decision is a logged
record, so every replica and the new home see the same decision.

1. From `T − EPO_PREP_LEAD_S` (60 s), every member of `R_{e+1}` and both sequencer boxes of the
   new home send an `EpoReady` every `EPO_READY_PERIOD_MS` (1,000 ms) to every member of `R_e`,
   on both WAN paths (§5.5).
2. At `T − EPO_GO_LEAD_S`, the old sequencer's control core (BASE) or the Simplex leader (CHAIN)
   proposes exactly one of:
   - `EpoGo{next_epoch, seq_index, next_seq_key, ready: [EpoReady; Q], seq_ready: [EpoReady; 2]}`:
     Q fresh, valid `EpoReady` from distinct voting members of `R_{e+1}`, and one from each of the
     two sequencer boxes in `seq_order`.
   - `EpoHold{epoch: e, t_new: T + EPO_HOLD_S}` otherwise.
3. Validity, checked by every voter in `R_e` before it votes for the block:
   - `EpoGo` is valid if its Q + 2 `EpoReady` signatures verify, each is fresher than
     `EPO_READY_FRESH_MS` (3,000 ms) at the proposal's `rx_ts`, and `seq_index` = `seq_order[0]`,
     the F1 box. The F2 box is the standby. A home with one ready sequencer box is held: without a
     standby, one fault right after activation would halt the book (§10.4).
   - `EpoHold` is valid only if the voter itself does not hold Q + 2 fresh `EpoReady` as above.
     A byzantine proposer therefore cannot hold a healthy handoff.
4. If neither record is final by `T − EPO_GO_DEADLINE_S` (5 s), the replicas treat the proposer
   as failed and run 07's failover. The next proposer proposes again with a deadline of `T − 2 s`.
   If that also fails, the result is a hold by default.

```rust
struct EpoReady {
    epoch: Epoch,             // e+1
    member: u8,               // roster index: a voting member of R_{e+1}, or a sequencer box
    follow_height: Height,    // last epoch-e block this node holds, finalized
    lag_ns: u64,              // replay lag: now − local rx of the newest frame not yet replayed
    keys_ready: bool,         // K_seq/K_out derived for all sessions (sequencer boxes only)
    version: u32,             // engine version it runs; must equal EpoConfig.version
    b4_pass: bool,            // replayed the last 3 epochs bit-identically (B4) on this version
    sig: Ed25519Sig,          // by NK(member, home(e+1)), ctx "vyrn      v1 ready"
}
```

A node sends `EpoReady` only if `lag_ns ≤ EPO_READY_LAG_MS` (1 ms), `version` matches,
`b4_pass` holds, and (for a sequencer box) `keys_ready` holds. The lag excludes the WAN one-way,
which is measured separately (B13). Replay runs at 0.6 × live, so a healthy follower lags by less
than one block; 1 ms keeps the lag inside `EPO_WINDOW_SLACK_MS` (§6.2).

## 3. The handoff on one page

```
 old home (TYO)                        WAN 110 ms                        new home (LDN)
 ─────────────────────────────────────────────────────────────────────────────────────────────
 T−60 s                                                      R_{e+1}: EpoReady every 1 s
 T−10 s  EpoGo logged (seq_index, next_seq_key) ◄─────────── Ready set
 T−1 s   EpochNotice(1 s) to every session
 T       lanes stop at rx_ts ≥ T; Seal step S ──► frames ──────────────┐   new seq: Collect starts
         last block closes (partial)          (tail relayed at once)   │   (rx_ts ≥ T, epoch16 = e+1);
                                                                       │   queued Ack ≤ 1 µs per packet
 T+2     block final (typ; max T+10)                                   │   window blocks final from T+2
 T+2.3   replicas at S: state_root, sign       HandoffSig ──────────┐  │
 T+2.4   any Q sigs = cert(e,S); INV-FENCE                          │  │
                                                                    │  ▼
 T+110.5                                       last tail frames arrive
 T+111.1                                       tail replayed: S′ known → Apply (0.7 ms)
 T+112.4                                       ◄────────────────────┘ cert arrives, verified
 T+112.6                                       Uncross step; first auction fill on the wire
 T+112.6+                                      lanes catch up on post-close packets, then live:
                                               continuous trading of epoch e+1
 T+112.6+  old home: followers of e+1; the old seq answers every stray packet within 1 µs
```

The numbers are typical budgets for TYO → LDN at normal window load (10% of peak). §6 gives
every transition, the maximum and the peak-load case.

## 4. State machines

### 4.1 Messages

| Message | From → to | Transport | Content | Section |
|---|---|---|---|---|
| `EpoConfig` | control path → log | consensus | next epoch's configuration | §2.3 |
| `EpoReady` | each of `R_{e+1}` and both new sequencer boxes → all of `R_e` | WAN, 2 paths | readiness | §2.6 |
| `EpoGo` / `EpoHold` | proposer → log | consensus | the go/no-go decision | §2.6 |
| `EpochNotice` | lanes → sessions | response record | next epoch, home, seconds | §2.4 |
| `Seal` step | old sequencer → `R_e` | order stream | `StepRecord{kind: Seal}` | §4.2 |
| `EpoForceSeal` | each of `R_e` → `R_e` | metro | attestation that no seal arrived | §4.3 |
| `HandoffSig` | each of `R_e` → `R_e`, `R_{e+1}`, both new sequencer boxes, third home | metro + WAN, 2 paths | one signature on the record | §5.3 |
| `HandoffCert` | any holder → anyone | any | record + Q signatures | §5.1 |
| `EpoArmed` | each of `R_{e+1}` → both new sequencer boxes | metro | "I verified cert(e, S) and persisted it" | §4.4 |
| window blocks and votes | new sequencer ↔ `R_{e+1}`; standby follows | metro, 2 paths | window `PacketRecord`s, 1 per ms | §7.1 |
| window responses | new lanes → sessions | response packets, window stream | queued `Ack`, `Reject` | §7.11 |
| tail stream | 2 relays in the old home → new and third home | WAN, 2 paths | order frames, block certs, payloads | §5.5 |
| `EpoTailReq` / `EpoTailResp` | new home ↔ old and third home | WAN | missing heights or payload hashes | §5.5 |
| collected `PacketRecord`s | new sequencer → `R_{e+1}` | order stream | window packets, during the window | §7.1 |
| `EpoActivated` | `R_{e+1}` → old and third home | WAN | height and cert of the first e+1 block | §4.4 |

### 4.2 Old sequencer

```
 Active(e) ─T−10 s─► Deciding ─EpoGo final─► Armed(e) ─lane rx_ts ≥ T (or clock ≥ T + slack)─► Sealing
     ▲                  │                                                                     │
     └─ EpoHold final: ─┘                                     all lanes sealed, final cut, rings drained
        T := t_new                                                                            ▼
 Redirect → Follower(e+1), answering strays ◄─cert(e,S) seen─ Sealed(e,S): Seal step, last block signed
```

The old standby follows the same machine as a follower and takes over the seal if the primary
fails before `T − EPO_SEAL_GUARD_MS` (§10.1).

The seal, step by step:

1. **Lane stop.** Each lane applies a packet only if `rx_ts < T`. Its first packet with
   `rx_ts ≥ T` seals the lane: the lane publishes its last `LaneSeq`, sets its `sealed` flag (one
   cache line, lane-written) and answers that packet as in §10.7. A lane that receives nothing
   seals when the control core's PTP time (core 51 on `REF`) passes `T + EPO_SEAL_SLACK_US`
   (5 µs). The slack covers a packet with `rx_ts < T` that is still in the RX ring. The rule is per packet in NIC time, so
   all lanes cut at the same instant to within the PHC skew between NICs (B17).
2. **Final cut.** The cut cores keep publishing ordinary cuts every `CUT_REFRESH_NS` while lanes
   seal, so every op with `rx_ts < T` is acked or filled within `LAT_MAX_NS` as on any other
   packet (`INV-ACK-AFTER-CUT`, 01 §14.1). The seal adds no wait to any response. When every
   `sealed` flag is set, the cut cores publish the final cut `C_f`. It contains every lane's last op.
3. **Drain.** The BBO core executes every improve and cross in its rings. All of them are at or
   below `C_f`, because lanes push nothing after they seal.
4. **Seal step.** The BBO core executes `StepRecord{kind: Seal, cut: C_f}` (01 §14.10). Its id is
   S. The two order-stream cores (stream-A on core 4 for lanes 0–24, stream-B on core 7 for
   lanes 25–48, 01 §10) drain their halves of the lanes to `C_f` and write the frames, the `Seal`
   record included, to both replication queues.
5. **Last block.** The sequencer closes the current block at S, though it is shorter than
   `BLOCK_NS`, and signs it (`seq_sig`). This block is the last of epoch e.

Budget: T to the Seal frame on the wire ≤ `EPO_SEAL_US` (50 µs). The Seal step itself does
nothing to the book. The book at S is the book after the last cross.

### 4.3 Old replicas (`R_e`)

```
 Voting(e) ──Seal frame──► WaitFinal ──block with S final──► Replay to S ──root ready──► Signed
    │                                                                                │
    │ clock ≥ T + EPO_SEAL_GRACE_MS, no Seal frame                                    │ Q sigs seen
    ▼                                                                                ▼
 ForceSeal: 07 failover in seal mode ─► S := last step of the finalized prefix ─► Fenced(e,S)
                                                                                     │ EpoActivated
                                                                                     ▼
                                                                                Follower(e+1)
```

- **Seal by the sequencer.** A replica votes for the last block as for any block (07). When the
  block that contains the `Seal` step is final, the replica finishes its replay to S, computes
  `state_root` and `log_hash`, builds the `HandoffRecord` and signs it (§5.3).
- **Force seal.** If a replica's PTP clock passes `T + EPO_SEAL_GRACE_MS` (5 ms) with no `Seal`
  frame, it sends `EpoForceSeal{e, last_height_held}` and starts 07's failover in **seal mode**:
  the replicas finalize the longest order prefix they hold, as in an ordinary failover, but they
  promote no standby. S is the last step of that prefix. Q `EpoForceSeal` signatures are the
  attestation that 09 slashes as a withheld handoff. One `EpoForceSeal` is sent per book, signed
  with the member's vote key `VK(i, home(e))`:

  ```
  body (14 bytes, little-endian)          msg = derive_key("vyrn      v1 force seal",
  off size field                                          genesis_hash ‖ mode ‖ body)
    0   2  book             BookId        sig = Ed25519_sign(VK(i, home(e)), msg)
    2   4  epoch            e             on the wire: body ‖ index u8 ‖ sig [64]
    6   8  last_height_held highest block height the member holds
   14      end
  ```
- **Failover guard.** A failover of the sequencer that starts before `T − EPO_SEAL_GUARD_MS`
  promotes the old home's standby, which trades until T and seals. One that starts later runs in
  seal mode. `EPO_SEAL_GUARD_MS` = `FAILOVER_TARGET_MS` (20 ms): a promotion that cannot finish
  before T cannot trade, so seal mode is then the shorter outage. Either way the outage is at most
  the published 20 ms, as for any failover.
- **Fence.** From the first moment a replica holds Q valid `HandoffSig` on one record, it applies
  `INV-FENCE`: it rejects every epoch-e frame with a step greater than S and every epoch-e block
  above `last_height` (§8).

### 4.4 New-home replicas (`R_{e+1}`)

```
 Follower(e) ──T−60 s──► Preparing ──T──► Collecting ──cert(e,S) verified, root equal──► Voting(e+1)
     ▲                     sends EpoReady   votes on window     │                          │
     │                                      blocks only         │ root differs             │ opening block
     │                                      (no steps)          ▼                          ▼ final
     │                                                      Faulty: stop voting,       EpoActivated
     └────────────────────────── re-sync from a snapshot ── alarm, re-replay           sent
```

- **Follower(e).** The node replays epoch e's finalized log, plus the speculative tail stream, with
  the same engine as `R_e` (01 §11.6). Its state lags the old home by one WAN one-way.
- **Preparing.** It loads `EpoConfig(e+1)`, checks its version, and sends `EpoReady`.
- **Collecting.** From T it receives the new sequencer's window `PacketRecord`s and, from its data
  tier, the window payloads. It votes on **window blocks** (§7.1) and on nothing else. A window
  block holds only `PacketRecord`s: it fixes the order of window packets, which does not depend on
  epoch e. No block with a step may be final before the history it extends is certified (F4). So
  every queued-acked order is final within `FINALITY_MAX_MS`, in the window too (01 §14.0).
- **Voting(e+1).** After it verifies the certificate (§5.4), it persists `armed(e+1)` in its
  high-water mark, sends `EpoArmed` to both sequencer boxes, and votes on all blocks of e+1. The
  first block with a step is the opening block (§7.1). When it is final, the members send
  `EpoActivated{epoch: e+1, height, finality cert}` to the old and third homes.

### 4.5 New sequencer

```
 Follower(e) ─T−60 s─► Preparing ─T (own PTP)─► Collect ─replay reaches Seal step S′─► Apply(S′)
                       derive keys               lanes queue-ack,        lanes apply window ops
                       warm retention            stream PacketRecords,   against the state at S′
                                                 propose window blocks          │
                                   cert(e,S): S == S′, roots equal ◄────────────┘
                                                 │                          │ S ≠ S′ or root differs
                                                 ▼                          ▼
                          Close window → Uncross → catch-up → Live(e+1)     Undo to the last final
                                                                            block, replay to S, Apply(S)
```

- **Preparing** (from `T − EPO_PREP_LEAD_S`): derive `K_seq(e+1)` and `K_out(e+1)` for every open
  session (§9.1); fill the response retention buffers from the replay (§11.3); install the NIC flow
  filters for `lane_map(e+1)` (06); allocate the collect buffers.
- **Collect** (from T by its own PTP clock): each lane accepts a packet only if its `rx_ts ≥ T`
  and its `epoch16` equals e+1. It runs deadline admission (01 §14.1), the session, bound-address
  and `tag_seq` checks, assigns `LaneSeq`s, pre-encodes the `PacketRecord` into its order ring
  (01 §14.5), appends the packet to its collect buffer and answers it with a queued `Ack` within
  `LAT_MAX_NS` (§7.11). It applies no message (§7.1). The control core proposes one window block
  per `BLOCK_NS`. A packet with `rx_ts < T` gets an out-of-stream `Reject{EPOCH_MISMATCH}`
  (§11.2), also within `LAT_MAX_NS`.
- **Apply(S′)**: when the speculative replay executes the `Seal` step, the box holds the state at
  S′. Lanes apply their collect buffers against it (§7.3). No response that depends on that state
  is sent. Lanes keep collecting and queue-acking new packets while they apply.
- **Activation**: the certificate arrives and verifies, `S == S′`, and the box's own `state_root`
  and `log_hash` at S equal the record's. The lanes close the window and the BBO core uncrosses
  (§7.6). The first auction fill waits for `EpoArmed` from Q members of `R_{e+1}`; that metro hop
  runs in parallel with the uncross and fits its budget. Lanes then catch up and go live (§7.10).
- **Mismatch**: S′ ≠ S happens only when the old sequencer failed or lied in the tail (§10.1,
  §10.5). The speculative replay and Apply keep an undo log from the last finalized block of e on.
  The box undoes to that block, replays the certified log to S and re-applies. Budget
  `EPO_RESPEC_MS` (15 ms): ≤ 10 ms of unfinalized tail at 0.6 × live, plus the backlog's Apply. If
  the root still differs, the box is faulty: it stops, and the standby activates (§10.4).

**Standby (F2).** The new home's standby `vyrn-seq` runs the same machine without client traffic.
It follows the tail, derives `K_seq(e+1, b)` and `K_out(e+1, b)` for its box b and every open
session, receives every window block and payload, and applies the final window blocks against S′.
It receives `HandoffSig` and `EpoArmed` like the primary. So at any moment it can take over within
`FAILOVER_TARGET_MS` and activate from the same certificate and window blocks (§10.4). It never
votes, so a promotion keeps `CLIENT_SPLIT_BASE` and `CLIENT_SPLIT_CHAIN` intact (01 §14.4).

### 4.6 Data tier

| Data tier | Before T | T → activation | After activation |
|---|---|---|---|
| old home | stores client copies, fans them out to `R_e`, streams every payload to the follower homes on both WAN paths | still accepts copies; copies of packets after the seal are never referenced and age out after `EPO_REDIRECT_HOLD_S` | serves `EpoTailReq`; follows the new home |
| new home | follower: receives epoch-e payloads over the WAN and fans them out to `R_{e+1}` and both sequencer boxes | **also** accepts client copies of epoch e+1 and fans them out to `R_{e+1}` and the standby | ordinary data tier of e+1 |
| third home | follower of e | follower of e | follower of e+1 |

The new home's data tier must accept e+1 copies from T. Reason: replicas vote on a window block
only when they hold every payload it references (07), and window blocks are final within
`FINALITY_MAX_MS` of each packet (§7.1). The opening block then waits for no transfer either.

**Keys across the boundary (reading, `vyrn-data`).** A data home holds one key table per epoch it
serves. With one table it checks no `epoch16`, as replicas filter none (07 §5.4). From T the new
home also holds e + 1's keys (`K_seq(e+1, ·)` or `K_com(e+1, ·)`); `epoch16` then picks the
table, and a copy whose `epoch16` is neither e nor e + 1 is dropped and counted before its MAC is
checked, so it raises no `DataBadMac` (F5, P8). Dedupe windows and the ring span both epochs,
because sessions and `pkt_seq` carry over (04 H8): a resend under e + 1 of a packet first sent
under e is a D3 variant. The new home retires e at activation, the old home at
`EPO_REDIRECT_HOLD_S` after the seal; copies already stored age out of the ring. A `DataRedirect`
during the boundary is tagged under e + 1's key (04 H2). The destination set does not split:
both of the new home's roles fan out to `R_{e+1}` and the standby.

### 4.7 Third home

The third home follows e from the old home until it holds cert(e, S), verified as in §5.4, then
follows e+1 from the new home. It relays every `HandoffSig` and the last block certificates of e
to the new home as a second route (§5.5).

### 4.8 Clients

`Active(e, H) → Scheduled(T) → Switching (resend unacked to H′) → Active(e+1, H′)`; see §11. A
client holds the addresses and keys of both sequencer boxes of H′, so a standby promotion needs
no new state (§10.4).

### 4.9 Timeouts and periods

| Name | Value | Who | On expiry |
|---|---|---|---|
| `EPO_CONFIG_LEAD_S` | 3,600 s | control path | late config is not used for e+1 |
| `EPO_PREP_LEAD_S` | 60 s | `R_{e+1}`, both sequencer boxes | start `EpoReady`, key derivation |
| `EPO_READY_PERIOD_MS` | 1,000 ms | `R_{e+1}` | send the next `EpoReady` |
| `EPO_READY_FRESH_MS` | 3,000 ms | `R_e` voters | an older `EpoReady` does not count |
| `EPO_GO_LEAD_S` | 10 s | proposer | propose `EpoGo` or `EpoHold` |
| `EPO_GO_DEADLINE_S` | 5 s | `R_e` | failover of the proposer; hold by default after the second miss |
| `EPO_SEAL_SLACK_US` | 5 µs | old lanes | an idle lane seals |
| `EPO_SEAL_GRACE_MS` | 5 ms | `R_e` | force seal |
| `EPO_SEAL_GUARD_MS` | 20 ms (= `FAILOVER_TARGET_MS`) | `R_e` | a failover becomes a seal-mode failover |
| `EPO_ACTIVATE_ALARM_MS` | 1,500 ms after the seal | old home | page the operators (§10.3) |
| `EPO_HALT_COLLECT_MS` | 250 ms after T | new control core | log `EpoHalt`; lanes answer `BOOK_HALTED` (§10.3) |
| `EPO_REASSIGN_MIN_S` | 60 s | operators | earliest manual reassignment |
| `EPO_REDIRECT_HOLD_S` | 600 s | old data tier | post-seal copies age out; strays are still answered (§10.7) |
| `EPO_HOLD_S` | 900 s | schedule | next handoff attempt |

## 5. The `HandoffRecord` and its certificate

### 5.1 Contents

The record is 01 §6.6's `HandoffRecord`. Its canonical encoding is fixed here (120 bytes,
little-endian):

```
off size field          value
  0   2  book          BookId
  2   1  next_home     HomeCode of epoch e+1 (may equal home(e): §2.5)
  3   1  reserved      0
  4   4  epoch         e
  8   8  last_step     S: the Seal step, or the last step of the seal-mode prefix
 16   8  last_height   height of the last block of e (the block that contains S)
 24  32  state_root    commitment to the full engine state after S (below)
 56  32  log_hash      BLAKE3 of the BlockHeader at last_height (the chain head)
 88  32  next_seq_key  Ed25519 seq key SK of the new sequencer, from the final EpoGo
120      end
```

Under `EpoConfig(e+1).sig_scheme` = 1 (01 §14.20), `next_seq_key` is the 1,344-byte hybrid key
and the record is 1,432 bytes; the layout is otherwise unchanged.

- `state_root` = BLAKE3 `derive_key("vyrn v1 state root", lthash)`, where `lthash` is the
  2,048-byte lattice hash over every state element at S: accounts and balances per lane, sessions
  (keys excluded, `pkt_seq` and `resp_seq` high-water marks included), resting orders with their
  priority keys and filled quantities, rate buckets, the last trade tick, and control state.
  Replicas keep it incrementally, O(1) per change (DESIGN §7). This chapter needs it in BASE mode
  too (Requests to 01, item 3).
- `log_hash` covers every earlier block through `prev`, so it covers `EpoConfig(e+1)`, `EpoGo` and
  every packet and step of e.
- The next epoch is `EpoGo.next_epoch`, which `log_hash` covers. 01 should make it a field
  (Requests to 01, item 2), because a light client then needs only the certificate.

```rust
struct HandoffCert {
    record: HandoffRecord,
    sigs: [(u8, Ed25519Sig); Q],   // (voting-member index in R_e, signature); distinct, ascending
}
// BASE: 120 + 3 × 65 = 315 bytes.  CHAIN: 120 + 4 × 65 = 380 bytes.
// Scheme 1, hybrid signatures of 2,484 B and a 1,344 B next_seq_key:
// BASE: 1,432 + 3 × 2,485 = 8,887 bytes.  CHAIN: 1,432 + 4 × 2,485 = 11,372 bytes.
```

### 5.2 Signature

```
msg = derive_key("vyrn      v1 handoff", genesis_hash ‖ mode ‖ encode(HandoffRecord))
sig = Ed25519_sign(VK(i, home(e)), msg)       // scheme 0
sig = Hybrid_sign(VK(i, home(e)), scheme ‖ msg) // scheme ≥ 1: both parts, 01 §14.20
```

The scheme is `EpoConfig(e).sig_scheme`, the scheme of the epoch that ends. A `HandoffSig` is
signed once per book per 8 h, off any hot loop: the voter runs the ML-DSA part with `PQ_HEDGE` = 8
on its idle replay lanes after replay reached S, ≤ `PQ_SIGN_MAX_US` = 250 µs, inside the 1 ms
`t_sign` of §6.1.

`genesis_hash` and `mode` stop a record from one deployment or mode from verifying in another. The
key is the member's vote key (09 §2.2), because a handoff signature is a consensus statement and
09 slashes it like a vote.

### 5.3 Who signs, and when

A member i of `R_e` signs exactly one `HandoffRecord` per (book, epoch), and only when all of these
hold:

1. It holds a finality certificate (07) for the block at `last_height`, and that block contains S.
2. Its replay has executed S, and its own `state_root` and `log_hash` equal the record's.
3. The finalized log contains `EpoGo` for e+1 and `next_home`, `next_seq_key` equal its fields.
4. It has not signed a `HandoffRecord` for (book, e) before. It persists `(book, e, record hash)`
   and fsyncs before it sends the signature (09 §2.5's high-water rule).

It then sends `HandoffSig{record hash, i, sig}` to every member of `R_e` and of `R_{e+1}`, to both
sequencer boxes of the new home, and to the third home, on both WAN paths. Any node that holds Q signatures on one record holds the
certificate. Nobody needs to aggregate first; the new home aggregates on receipt.

Only voting replicas sign (01 §14.4). In BASE mode Q = `Q_BASE` = 3 of the `N_BASE` = 4 voting
replicas R1–R4. In CHAIN mode Q = `Q_CHAIN` = 4 of the 5 validator boxes. Neither sequencer box
of the old home signs, in either mode, and a promotion of the standby changes no signer. A book
group (01 §12.3) seals all its books at the same T and produces one record per book.

**Uniqueness.** Two certificates for one (book, e) with different contents need two quorums. Any
two quorums intersect in `2Q − n` members: 2 in BASE (3 + 3 − 4) and 3 in CHAIN (4 + 4 − 5). At
least one of them is honest, because `F` = 1, and an honest member signs once (rule 4). So there is
at most one certificate per (book, e).

### 5.4 Verification at the new home

A node of `R_{e+1}` (and the third home) accepts cert(e, S) when every step passes:

| # | Check | Failure means | Action |
|---|---|---|---|
| 1 | Q distinct indices of `R_e`; each signature verifies under `VK(i, home(e))` from the roster of `EpoConfig(e)` | forged or wrong set | drop, count, alarm |
| 2 | `book`, `epoch` match; `next_home` = my home | not for me | drop |
| 3 | `next_seq_key` = the key in the `EpoGo` my replay holds | the tail is missing | fetch tail (§5.5) |
| 4 | `log_hash` = BLAKE3 of the header at `last_height` in my log, and I hold that block's finality cert | the tail is missing | fetch tail |
| 5 | My `state_root` at S = `record.state_root` | my replay is wrong | stop voting, alarm, re-sync from a snapshot (07) |

Checks 1–2 cost Q Ed25519 verifications: ≤ 0.2 ms (budget, at ≤ 50 µs each). Under scheme 1
they add Q ML-DSA-44 verifications at `PQ_VERIFY_US` = 35 µs each, run in parallel on Q idle
lane cores, so the pair costs ≤ 0.24 ms (budget). `t_ver` max (§6.1) becomes 0.25 ms, and every
W max of §6.2 rises by ≤ 0.05 ms, inside `EPO_WINDOW_SLACK_MS`. [Likely] Checks 3–5 compare
hashes the node already holds. A failure of check 5 at a node does not change the certificate:
Q members of `R_e` signed it, so the node, not the certificate, is wrong.

The roster keys of `R_e` come from `EpoConfig(e)`, which cert(e − 1) covered, back to the genesis
record. A node that starts from a snapshot verifies that chain of certificates (07).

### 5.5 The log tail over the WAN

At T the new home lacks only the tail, the last WAN one-way of log and data. The tail moves by
streaming, so the end of an epoch needs no bulk transfer.

| Stream | Source | Paths | Rate at peak (budget) |
|---|---|---|---|
| order frames, unfinalized | 2 relay replicas in the old home, in different facilities, forward each frame on receipt | one relay per WAN path | 20 Gbps (DESIGN §5) |
| block finality certificates and `HandoffSig` | every member of `R_e` | both paths, and via the third home | < 1 Mbps |
| payloads | the old data tier, every payload on both paths | 2 | 190 Gbps |

- Each WAN path carries at least `EPO_WAN_GBPS_MIN` = 250 Gbps from the active home to each follower
  home (budget). Each path carries the whole stream at all times, so one lost packet or one failed
  path never leaves a gap that a pull must fill, and no backlog grows the window.
- Followers replay the unfinalized frames speculatively. They treat state as final only up to the
  last finalized block. The speculative stream lets the new sequencer reach S′ one finality time
  before the certificate arrives (§6.1).
- **Pull.** After the certificate arrives, a node that misses a block or a payload sends
  `EpoTailReq{heights | pkt_hashes}` to the old home and the third home at the same time. The first
  `EpoTailResp` that verifies wins: a block must carry its finality certificate and a payload must
  match its `PktHash`, so a bad answer from one home never blocks a good one from the other.
  `EpoTailReq` is unsigned (the answers authenticate themselves), little-endian:
  `book u16 ‖ epoch u32 ‖ req_id u32 ‖ kind u8 (1 heights, 2 pkt_hashes) ‖ count u16 ‖ count × u64`,
  with 1 ≤ count ≤ `EPO_TAIL_REQ_MAX` (1,024); `EpoTailResp` echoes `req_id`. For TYO → LDN the
  third home (NYC) answers first: a request at T + 110 ms gets its answer at ≈ T + 180 ms from NYC
  (35 ms each way, NYC got the data at T + 80) and at ≈ T + 330 ms from TYO.
- Follow lag at T adds to the window one for one; `EpoReady` caps it at `EPO_READY_LAG_MS` (1 ms,
  §2.6), which `EPO_WINDOW_SLACK_MS` covers. A pull is needed only when both paths lost the same
  data, which is two faults (§10.6).

## 6. Timeline per transition

### 6.1 Components

The certificate and the tail travel in parallel:

```
cert path:  T ─seal─► S ─finality─► final ─root+sign─► cert ─WAN─► new home ─verify─► ready
tail path:  T ─seal─► S ─relay─► WAN ─► new home ─replay tail─► S′ ─apply backlog─► applied
activation = max(cert path, tail path);   W = activation + uncross + catch-up − (last old fill)
```

| Component | Symbol | Typical | Max | Kind |
|---|---|---|---|---|
| T → Seal step on the wire | t_seal | 0.01 ms | 0.05 ms | budget (`EPO_SEAL_US`) |
| last block final at the old home | t_fin | 2 ms | 10 ms | budget (`FINALITY_MAX_MS`) |
| replay to S, state root, `HandoffSig` out | t_sign | 0.3 ms | 1 ms | budget |
| metro hop to the WAN relay | t_relay | 0.5 ms | 0.5 ms | budget (DESIGN §5) |
| WAN one-way | t_wan | 110 / 35 / 80 ms | same | budget (planning figures, B13 measures) |
| replay of the last tail block at the new sequencer | t_tail | 0.6 ms | 0.6 ms | budget (replay at 0.6 × live) |
| certificate verification | t_ver | 0.1 ms | 0.2 ms | budget |
| apply of the window backlog | t_apply | `EPO_APPLY_NS` × backlog per lane | | budget |
| close window and uncross ‖ Q `EpoArmed` (one metro hop), first fill out | t_unx | 0.2 ms | 0.5 ms | budget (`EPO_UNCROSS_FIRST_US`) |
| lanes apply post-close packets, then live (§7.10) | t_catch | 0.005 ms | 0.3 ms; 0.75 at peak | budget (`EPO_CATCHUP_US`) |

The backlog per lane at S′ is the window's message rate per lane times `t_wan`. At 1B msgs/s into
the new home (peak) it is 20M/s × 110 ms = 2.2M messages per lane for TYO → LDN, which applies in
6.6 ms at 3 ns. At normal window load (10% of peak, budget assumption) it is 0.66 ms. The
catch-up backlog is the per-lane rate times t_unx, and it drains at `LANE_NS_PER_MSG` against
the lane's spare capacity: at peak (load 0.6) and t_unx = 0.5 ms, 10k messages × 30 ns / 0.4 =
0.75 ms.

### 6.2 Windows

All values in ms, budgets. "Peak" = the window receives 1B msgs/s.

| Transition | t_wan | Cert path typ / max | Tail path normal / peak | **W typ** | **W max** | W peak, typ fin | W peak, max | **Bound** |
|---|---|---|---|---|---|---|---|---|
| TYO → LDN | 110 | 112.4 / 121.3 | 111.8 / 117.7 | **112.6** | **121.8** | 118.2 | 122.6 | **123** |
| LDN → NYC | 35 | 37.4 / 46.3 | 36.3 / 38.2 | **37.6** | **46.8** | 38.7 | 47.6 | **48** |
| NYC → TYO | 80 | 82.4 / 91.3 | 81.6 / 85.9 | **82.6** | **91.8** | 86.4 | 92.6 | **93** |
| same home (override to home(e)) | 0 | 2.4 / 11.3 | 1.1 / 1.2 | **2.6** | **11.8** | 2.9 | 12.6 | **13** |

**The bound.** W ≤ t_wan + `FINALITY_MAX_MS` + `EPO_WINDOW_SLACK_MS` (3 ms) for every transition,
at every load up to 1B msgs/s, with no fault. The cert path is at most t_wan + `FINALITY_MAX_MS` +
1.3 ms; the tail path at peak is at most t_wan + 7.7 ms, never above the cert path's maximum; uncross
and catch-up add at most 1.25 ms. Open question 1 guards the 3 ns Apply this relies on. This
tightens B13's `BLD_HANDOFF_SLACK_MS` (5 ms) to 3 ms. DESIGN §6 gives ~120, ~45 and ~90; DESIGN
rounds away the signing, verification and uncross. Faults add only the outages of §10, each
bounded by `FAILOVER_TARGET_MS` unless two faults coincide.

### 6.3 The floor: no window shorter than one WAN one-way latency

**Claim.** Let d be the smallest one-way delay of any channel from the old home to the new home.
Any handoff protocol that keeps a single price-time book (no order fills beyond its quantity, and
no fill trades through a better price that the book holds) has a window W ≥ d.

**Proof.** Let t₀ be the last moment at which the old home may still fill (its seal), and suppose
the new home fills an order at t₁ < t₀ + d. Nothing sent from the old home at or after t₀ can have reached the new home by t₁
(causality; d is the fastest channel). So the new home's state at t₁ is the same in any two
executions that differ only in what the old home received at or after t₀. Two such pairs give a
contradiction:

1. **Double fill.** A sell order X of 1 lot at 100 rests in the book. Execution A: at t₀ a buy
   of 1 lot at 100 arrives at the old home and fills against X. Execution B: no buy arrives at the
   old home. At t₁ a buy of 1 lot at 100 arrives at the new home. In B the book must fill it
   against X, or it fails to match a marketable order against a resting one. The new home cannot
   tell A from B, so it fills it in A too. In A, whose last old fill is at t₀, X sells 2 lots out
   of 1.
2. **Trade-through.** The best ask is 100. Execution A: at t₀ the old home receives a sell at 99,
   which rests. Execution B: it does not. At t₁ a buy at 100 arrives at the new home. In B it fills
   at 100. In A the book holds an ask at 99, so a fill at 100 trades through it. The new home cannot
   tell A from B.

So the first fill at the new home is at t₁ ≥ t₀ + d, and W ≥ d. ∎

**What the proof does not allow.** Stopping the old home earlier only moves t₀. Letting both homes
trade at the same time needs a cross-home agreement per fill, which costs ≥ d per fill and breaks
the 1 µs fill. Moving the book in pieces lets an aggressor at one home miss a better price that is
still at the other home, which is case 2.

**Why finality adds to d.** With `F` = 1, the old sequencer may be the faulty node. The new home
must start from a last step that a quorum fixed, or a faulty old sequencer could later show the new
home a different end of epoch e. A quorum decision takes at least one round of votes inside some
metro after the last step. Our design runs that round at the old home before the WAN crossing.
Running it at the new home instead (new-home nodes voting on epoch-e frames) costs the same round
after the crossing. So W ≥ d + one metro round, and our W ≤ d + t_fin + `EPO_WINDOW_SLACK_MS`.
The window costs fills only. Orders still get a 1 µs answer and a final place in the log in it
(§7.11), because neither needs the state at S: the proof above is about fills.

**The light numbers.** Fiber carries light at ~4.9 µs/km (refractive index ~1.47, vendor). Great
circles: TYO–LDN ~9,560 km, LDN–NYC ~5,570 km, NYC–TYO ~10,850 km (computed). The straight-fiber
floors are 47, 27 and 53 ms. Today's cable routes are longer, which gives the planning figures
110, 35 and 80 ms. A straighter route or a radio path lowers d. Nothing lowers it to zero, and no
protocol goes below it.

## 7. The opening auction

### 7.1 Phases and the opening block

```
 T ───────── Collect ──────────┬──── Apply ─────┬─ Close ─┬─ Uncross ─┬─ catch-up ─┬─ Live(e+1)
   lanes queue window packets   S′ known:        cert ok:   step U     post-close   snapshot v_U;
   queued Ack ≤ 1 µs each       lanes apply ops  lanes      = (e+1, 1)  packets as   every packet
   window blocks final ≤ 10 ms  against S′       close                  continuous   fills on arrival
```

- **Collect** needs no state. Each lane checks `epoch16`, `rx_ts ≥ T`, deadline admission and
  `tag_seq`, assigns `LaneSeq`s, copies the packet into its collect buffer, emits its
  `PacketRecord` with `fills_applied = 0`, and answers with a queued `Ack` (§7.11). Cost
  `EPO_COLLECT_NS` (10 ns) per message (budget). While the box still replays the epoch-e tail, a
  lane at peak carries ~60% replay plus ~20% collect. Replay runs in slices of at most
  `EPO_REPLAY_SLICE_NS` (40 ns) between RX polls, so replay never delays an answer by more.
- **Pooled and dedicated lanes behave the same in the window** (01 §14.15). From T until the lane
  is live (§7.10), a pool core serves only its own RX queue: it steals nothing, and every pooled
  account's token stays parked on its pool-queue core (10 §1.2), where `from_state` puts it. So
  Collect, Apply and catch-up are lane-local on every lane, with the same costs and the same
  `LaneSeq` order, and no `AcctTake` is logged in the window. Collect at 10 ns per message leaves
  no queue for stealing to drain. Stealing resumes at the first packet after the lane goes live.
- **Window blocks.** The control core proposes one window block per `BLOCK_NS`:
  `WinBlock{book, epoch: e+1, wheight: u32, prev: Hash, anchor: Hash, order_root, data_root,
  seq_sig}`, with `anchor` = BLAKE3 of the final `EpoGo` record and `wheight` from 1. It holds only
  `PacketRecord`s (and control-session records such as `EpoHalt`, §10.3). `R_{e+1}` finalizes
  window blocks with 07's Simplex in its own instance `(book, e+1, window)`, at metro finality
  (`FINALITY_MAX_MS`). A window block fixes order, not outcome: the outcome is a pure function of
  the final window blocks and cert(e, S), so finalizing it before the certificate is safe (F4).
- **Apply** starts at S′. The box first builds the epoch-(e+1) engine from the state at S′
  (`EpochEngine::from_state`, §7.9): it places each account in its `lane_map(e+1)` class and lane
  (a pooled account on its pool queue, with its token parked there), folds each
  carried order's filled quantity into its remaining quantity, and starts the filled-quantity array
  at zero. Then each lane applies its buffer in `LaneSeq` order (§7.3), in the same slices.
- **Close.** At activation the control core publishes `t_close` = its PTP time + `EPO_SEAL_SLACK_US`.
  A lane includes in the auction exactly the packets with `rx_ts < t_close`, exactly as the old home
  sealed at T (§4.2). Later packets are still queue-acked on arrival and wait in the collect buffer
  for continuous mode (§7.10).
- **Uncross** is step U = (e+1, 1), `StepKind::Uncross` (01 §14.10). Its cut contains every op
  with `rx_ts < t_close`. No step runs in epoch e+1 before U.
- **The opening block** has height `last_height + 1` and `prev = log_hash`. Its `order_root`
  covers the head of the window chain and the `Uncross` step, so it spans the whole window. Its
  window packets are final already, so its vote waits for nothing after U.

### 7.2 What each message does in the window

| Message | 1 µs answer in the window (§7.11) | At U | After the lane is live |
|---|---|---|---|
| `New`, Day | queued `Ack` with `wref` | joins the auction; any rest rests | normal |
| `New`, IOC | `Reject AUCTION_PHASE` (04 §6.9) | — | normal |
| `New`, FOK | `Reject AUCTION_PHASE` | — | normal |
| `New`, auction-only | queued `Ack` | joins; the rest is `Out` cause auction | `Reject AUCTION_PHASE` |
| `New`, post-only | `Reject AUCTION_PHASE` (04 §6.9; a `Replace` to post-only too) | — | normal |
| `Cancel`, `Reduce` | queued `Ack` | applied to a carried order, or to a window order named by `wref`; else `UNKNOWN_HANDLE` | normal |
| `Replace` | queued `Ack` with `wref` | applied as for `Cancel` (04 P9); the new part joins the auction | normal |
| `CancelAll` | queued `Ack` | applied to carried and earlier window orders of the session | normal |
| `Heartbeat` | `EpochNotice` in the window stream (04 §4.8) | nothing | normal |
| `ResendReq` | queued `Ack`, or the responses if the box holds them | answered (§11.3) | normal |

A window `New` gets a window reference `wref` in its queued `Ack`: the lane's collect index of the
message, which `Apply` maps to the handle it allocates. A `Cancel`, `Reduce` or `Replace` in the
window names a window order by setting byte 1 bit 0 and putting its `wref` in the handle field
(Requests to 01, item 10). After U every window order has a handle, which its final record carries.

If `EpoConfig(e+1).flags.date_roll` is set (the boundary into a TYO epoch, 00:00 UTC), Apply first
expires every carried Day order: `Out` cause 4, expired (01 §14.10). Day means the UTC
trading date. In v1 every resting order is Day, so the TYO open starts with the window orders only.

### 7.3 Apply

```rust
fn lane_apply(l: &mut Lane, buf: &CollectBuf, cfg: &AuctionCfg) {
    for pkt in buf.iter_in_lane_seq_order() {
        if pkt.flags.shed { continue; }                  // answered BUSY in Collect (01 §14.1)
        let s = l.session_mut(pkt.session);
        if pkt.pkt_seq <= s.hw_pkt_seq { l.cnt.dup_across_epoch += 1; continue; }   // applied in e
        if pkt.pkt_seq != s.hw_pkt_seq + 1 { l.outcome(pkt, BAD_SEQ); continue; }    // 04 P5
        s.hw_pkt_seq = pkt.pkt_seq;
        if let Err(r) = l.rate_check(s, pkt.rx_ts) { l.outcome(pkt, r); continue; } // 04 §9
        for (i, m) in pkt.msgs().enumerate() {
            let out = match m.kind {
                New => l.auction_new(m, cfg),                // risk (10 §3.1), band, TIF table §7.2
                Cancel | Reduce => l.apply_cancel(m),        // carried, or window by wref; hist −
                Replace => l.apply_replace(m, cfg),
                CancelAll => l.apply_cancel_all(s),
                Heartbeat => Outcome::None,
                ResendReq => l.queue_resend(s, m),
            };
            l.record_outcome(pkt, i, out);                   // final records are built after U
        }
    }
}
```

`auction_new` checks the TIF table (§7.2), the band (§7.5) and risk (10 §3.1–3.2), allocates a
handle in `LaneSeq` order, appends the order to its lane FIFO with its `PrioKey` (§7.4) and adds
its quantity to the lane's histogram. Cost `EPO_APPLY_NS` = 3 ns per message, amortized (budget). It is 10× below `LANE_NS_PER_MSG`
because RX, MAC, parse, classification and the response were done in Collect or come after U.
Carried-order cancels touch the order arena, which the lane prefetches 16 messages ahead. Packets
that arrive during Apply are queue-acked, join the end of the buffer and are applied in turn.

**Speculation is invisible.** Apply against S′ changes only the lanes' internal state. The queued
`Ack` depends only on the packet and the earlier window packets, never on S′. No response that
depends on S′ leaves the box before activation, and activation requires `S = S′` and equal roots
(§4.5).
Replicas of e+1 later replay the same ops against the certified state at S, in the same
`LaneSeq` order, and reach the same state (`INV-DET`).

### 7.4 Priority key

```
PrioKey = rx_ts (64 bits) ‖ entry_rank (8 bits) ‖ entry_lane_seq (56 bits)      as one u128
```

`entry_rank` is the lane's rank in the tie-break order of the epoch in which the order entered
(DESIGN §10: lane-id tie-breaks rotate each epoch; 05 owns the rotation). An order keeps its key
for life, also when its account moves lanes or changes class (10 §1.3). Every carried order has `rx_ts < T` by the
old home's seal rule, and every window order has `rx_ts ≥ T` by the new home's collect rule. So
every carried order has priority over every window order at the same price, whatever the clock
skew between the homes. `entry_lane_seq < 2^56` holds for 69 years of one lane at full rate.

### 7.5 Reference price and band

```
ref = last_trade_tick(e)                    // the last fill price of epoch e
      or bid(S) if no trade ever, or ask(S), or BookSpec.ref_tick (10) if the book is empty
if bid(S) exists: ref = max(ref, bid(S))
if ask(S) exists: ref = min(ref, ask(S))   // bid(S) < ask(S) by INV-UNCROSSED, so this is defined
band = [max(min_tick, ref − EPO_HIST_HALF), min(max_tick, ref + EPO_HIST_HALF)]   // 8,193 ticks
```

The clamp into the carried spread makes every carried order that can execute lie inside the band:
a carried buy is at most bid(S) ≤ ref ≤ band top, and a carried sell is at least ask(S) ≥ ref ≥
band bottom. Carried buys below the band and carried sells above it cannot execute, because the
clearing tick is inside the band. They stay out of the histogram and rest. A window `New` outside
the band is rejected `BAD_TICK`. So no histogram bucket ever aggregates prices outside the band.

### 7.6 The uncross rule

Let `b[t]` and `s[t]` be the total remaining buy and sell quantity at tick t over all lanes,
carried and window orders together, for t in the band.

```
D(t) = Σ_{u ≥ t} b[u]       demand at t: buys willing to pay t or more
S(t) = Σ_{u ≤ t} s[u]       supply at t: sells willing to take t or less
V(t) = min(D(t), S(t))      executable volume
I(t) = D(t) − S(t)          imbalance (signed)
p*   = the tick that maximizes, in order:
       1. V(t)                     maximum executable volume
       2. −|I(t)|                  minimum imbalance
       3. −|t − ref|               nearest the reference
       4. −t                       lowest tick
```

If `max V = 0`, nothing crosses. The book opens with no uncross fills and U only changes the
phase.

**Lemma 1 (the candidates are intervals).** D is non-increasing and S non-decreasing in t. For any
v, `{t : V(t) ≥ v} = {t : D(t) ≥ v} ∩ {t : S(t) ≥ v}` is an intersection of a down-set and an
up-set, an interval. So `C1 = argmax V` is an interval. I is non-increasing, so `{t : |I(t)| ≤ m}`
is an interval for every m, and `C2 = C1 ∩ {|I| ≤ min_{C1} |I|}` is an interval `[a, b]`. ∎

**Lemma 2 (rule 4 never decides).** `C3 = argmin_{t ∈ [a,b]} |t − ref|` is the single tick
`clamp(ref, a, b)`, because ref is a tick. ∎ Rule 4 stays in the code so that the Rust engine, the
Vx client and the oracle cannot disagree on a malformed input.

**Allocation.** Let V = V(p*). Uniform price: every execution is at p*.

- If `I(p*) = 0`: every buy at ≥ p* and every sell at ≤ p* fills in full.
- If `I(p*) > 0` (buys are rationed): every sell at ≤ p* fills in full. Buys fill in price-time
  priority: higher limit first, then lower `PrioKey`, until V is used. The **marginal tick** `p_m`
  is the highest t with `D(t) ≥ V`; buys above `p_m` fill in full, buys below it get nothing, and
  at `p_m` the remaining `q_rem = V − D(p_m + 1)` goes to the orders in key order. The **marginal
  order** is the first order at `p_m` at which the cumulative quantity reaches `q_rem`; it fills
  partly or exactly.
- If `I(p*) < 0`: the mirror image, with sells rationed, `p_m` the lowest t with `S(t) ≥ V`.

**Lemma 3 (the residual book is uncrossed).** Suppose after the uncross a buy at β and a sell at
α ≤ β both have quantity left. Take `I(p*) > 0`. Every sell at ≤ p* filled in full, so α > p*, and
β ≥ α > p*, so the buy is rationed. Price priority means every fill went to buys at ≥ β ≥ α, so
`D(α) ≥ V + (rest of the buy) > V`. The sell at α was not eligible, so `S(α) ≥ S(p*) + (its qty)
> V`. Then `V(α) > V`, which contradicts rule 1. `I(p*) < 0` is the mirror, and for `I(p*) = 0`
every residual buy is below p* and every residual sell above it. ∎ So the snapshot after U
satisfies `INV-UNCROSSED`.

### 7.7 Pseudocode

```rust
struct UncrossRecord {          // written by the BBO core only; read by every lane
    p: Tick, v: u64, imb: i128, // clearing tick, volume, I(p*)
    p_m: Tick,                  // marginal tick on the rationed side (= p if imb == 0)
    marg: PrioKey, marg_qty: Qty, // marginal order and its fill; marg_qty = 0 if imb == 0
    ref_tick: Tick, band_lo: Tick,
}

fn uncross(lanes: &[LaneView; N_LANES], cfg: &AuctionCfg) -> Option<UncrossRecord> {
    // 1. Sum the lanes' histograms over the union of their touched ranges.  O(N_LANES × B)
    let (lo, hi) = lanes.touched_union();
    let (mut b, mut s) = ([0u64; EPO_HIST_TICKS], [0u64; EPO_HIST_TICKS]);
    for l in lanes { for t in lo..=hi { b[t] += l.hist.buy[t]; s[t] += l.hist.sell[t]; } }
    // 2. One pass over the band, rules 1–4 as one lexicographic key.  O(B)
    let d = suffix_sums(&b); let sp = prefix_sums(&s);
    let mut best: Option<(u64, Reverse<u128>, Reverse<u32>, Reverse<Tick>, usize)> = None;
    for t in lo..=hi {
        let v = min(d[t], sp[t]);
        let imb = d[t] as i128 - sp[t] as i128;
        let k = (v, Reverse(imb.unsigned_abs()), Reverse(cfg.tick(t).abs_diff(cfg.ref_tick)),
                 Reverse(cfg.tick(t)), t);
        if best.map_or(true, |bk| k > bk) { best = Some(k); }
    }
    let (v, _, _, _, t) = best?;
    if v == 0 { return None; }
    let imb = d[t] as i128 - sp[t] as i128;
    // 3. Marginal tick and remaining quantity on the rationed side.  O(B)
    let (side, p_m, q_rem) = match imb.signum() {
        0  => return Some(UncrossRecord::balanced(cfg.tick(t), v, cfg)),
        1  => { let m = (t..=hi).rev().find(|&u| d[u] >= v).unwrap();
                (Buy, m, v - if m < hi { d[m + 1] } else { 0 }) }
        _  => { let m = (lo..=t).find(|&u| sp[u] >= v).unwrap();
                (Sell, m, v - if m > lo { sp[m - 1] } else { 0 }) }
    };
    // 4. Marginal order by weighted selection over the lanes' FIFOs at (side, p_m).
    let (marg, marg_qty) = select_marginal(lanes, side, p_m, q_rem);
    Some(UncrossRecord { p: cfg.tick(t), v, imb, p_m: cfg.tick(p_m), marg, marg_qty,
                         ref_tick: cfg.ref_tick, band_lo: cfg.band.lo })
}

/// Finds the order with the smallest key such that the quantity at or below it reaches q_rem.
/// Each lane's FIFO at (side, p_m) is sorted by PrioKey; the lane builds its prefix quantities.
fn select_marginal(lanes: &[LaneView], side: Side, p_m: usize, q_rem: u64) -> (PrioKey, Qty) {
    let (mut lo, mut hi) = ([0u32; N_LANES], lanes.fifo_lens(side, p_m));
    let mut below = 0u64;                                   // qty known to be below every live key
    loop {
        // Pivot: weighted median of each live range's middle key, weight = range length.
        let piv = weighted_median(lanes.iter().map(|l| (l.key_at((lo[l] + hi[l]) / 2), hi[l] - lo[l])));
        // One parallel round: lane l returns r[l] = #keys < piv in its live range, q[l] = their qty.
        let (r, q) = lanes.rank_round(piv, &lo, &hi);
        let q_less = below + q.iter().sum::<u64>();
        let q_piv = piv.qty;
        if q_less < q_rem && q_rem <= q_less + q_piv { return (piv.key, (q_rem - q_less) as Qty); }
        if q_less >= q_rem { for l in 0..N_LANES { hi[l] = lo[l] + r[l]; } }
        else { below = q_less + q_piv;
               for l in 0..N_LANES { lo[l] += r[l] + (l == piv.lane) as u32; } }
    }
}

/// Lane side: the fill of one own order. Pure function of the record; no BBO-core write.
fn auction_fill(o: &Order, u: &UncrossRecord) -> Qty {
    let better_or_at = |t| if o.side == Buy { t >= u.p } else { t <= u.p };
    if !better_or_at(o.tick) { return 0; }
    let rationed = (u.imb > 0 && o.side == Buy) || (u.imb < 0 && o.side == Sell);
    if !rationed { return o.remaining; }
    let beyond = |t| if o.side == Buy { t > u.p_m } else { t < u.p_m };
    if beyond(o.tick) { o.remaining }
    else if o.tick != u.p_m { 0 }
    else if o.key < u.marg { o.remaining } else if o.key == u.marg { u.marg_qty } else { 0 }
}
```

Each round of `select_marginal` discards at least a quarter of the live keys (the weighted median
of medians). So it takes at most `log_{4/3} N + 1` rounds: 49 rounds for N = 10^6 orders at `p_m`.
A round costs ~2 µs (budget): the BBO core writes the pivot line, each lane binary-searches its own
L2-resident array and writes one reply line, and the BBO core reads 49 lines (42 dedicated lanes
and 7 pool cores, 01 §10) and takes a weighted median of 49 pairs.

**Writers.** The BBO core writes only `UncrossRecord`. Each lane computes the fills of its own
orders with `auction_fill`, rewrites their remaining quantities and settles its own balances
(01 §12.2). The filled-quantity array is not written by the uncross. Every field still has one
writer (`INV-WRITER`), and no lane decides a fill by itself: `auction_fill` only reads the BBO core's
decision (`INV-LANE-NOMATCH`).

**Fill records.** Each executed order gets one `Fill` at tick p with `liq = 2` (auction,
01 §14.10). A window order's fill answers its packet (`index` = its message index); a carried
order's fill is unsolicited (`index = 0xFF`). The execution ID is `(U, ordinal)` with
`ordinal = lane_id × 2^32 + k`, where k counts the lane's executed orders in price-then-key order.
Each lane computes its ordinals alone.

**STP** does not apply to the uncross. In a uniform-price auction no buy is paired with a
particular sell, so there is no self-match to prevent. The drop copy flags an account that is on
both sides of one uncross (10).

### 7.8 Scale and time budget

At peak, 1B msgs/s for a 110 ms window is ~110M messages, 2.2M per lane. Sizing:

| Item | Value (budget) |
|---|---|
| Collect buffer per lane | `EPO_COLLECT_MAX_MSGS` = 6M messages (2.7× the TYO → LDN peak), 128 MiB in 1 GB huge pages |
| Histogram per lane | 2 × 8,193 × 8 B = 131 KB, in the lane's 1 MB L2 |
| Sum of 49 histograms | 6.4 MB at worst; typical touched range ±512 ticks is 0.8 MB |

Uncross budget, from activation to the first auction fill on the wire (`EPO_UNCROSS_FIRST_US`):

| Step | Core | Worst case | Typical |
|---|---|---|---|
| lanes close the window, final cut | lanes, cut core | 6 µs | 6 µs |
| sum 49 histograms (cross-CCD reads at ≥ 25 GB/s) | BBO core | 260 µs | 32 µs |
| scan 8,193 ticks, marginal tick | BBO core | 20 µs | 3 µs |
| lanes build prefix arrays at `p_m` | lanes, parallel | 10 µs | 1 µs |
| `select_marginal` (≤ 49 rounds) | BBO core + lanes | 100 µs | 30 µs |
| `UncrossRecord`, `Uncross` frame on both replication queues (`INV-FRAME-FIRST`) | BBO, stream cores A and B | 2 µs | 2 µs |
| first lane computes a fill and writes its response | a lane, TX cores A–C | 3 µs | 3 µs |
| **Total** | | **401 µs ≤ 500** | **77 µs** |

To the last uncross fill at 10^6 executed orders: each lane emits 20k fills at ~15 ns (0.3 ms), and
62.5k response packets of 16 records (17.5 MB) leave 4 × 100GbE in 0.35 ms. Total ≤ 1,000 µs, which
is B14's `BLD_UNCROSS_US_MAX`. This chapter fixes B14's pass at that value.

### 7.9 Interface with 05's auction mode

05 owns the engine. 08 drives it through this interface, which 05 implements in `vyrn-engine`:

```rust
trait EpochEngine {
    /// Build the e+1 engine from the state at S: lane placement by lane_map(e+1), carried orders
    /// with remaining = qty − filled, empty filled-quantity array. Runs before seal().
    fn from_state(state: &StateAtS, map: &LaneMap, n_lanes: u8) -> Self;
    /// Lanes take window ops (§7.3); no classification, no BBO ring traffic.
    fn enter_auction(&mut self, cfg: AuctionCfg);            // band, ref, date_roll
    fn apply_window(&mut self, lane: LaneId, buf: &CollectBuf);
    /// Lanes close at rx_ts ≥ t_close; returns the final cut.
    fn close_window(&mut self, t_close: Nanos) -> Cut;
    /// The Uncross step U: BBO core runs uncross(), publishes UncrossRecord, logs StepRecord.
    fn uncross(&mut self, cut: Cut) -> Option<UncrossRecord>;
    /// Lanes apply auction_fill to their orders, settle, catch up on post-close packets, go live.
    fn resume_continuous(&mut self) -> Snapshot;              // snapshot v_U, INV-UNCROSSED
}
```

The same calls serve any auction inside an epoch (a reopening after `BOOK_HALTED`, 05 and 10),
with the last trade before the halt as the reference.

### 7.10 From auction to continuous trading

1. After U, the BBO core publishes snapshot `v_U` with the residual best bid and ask (Lemma 3).
2. Each lane applies `auction_fill` to its orders, moves residual window orders into its lane
   FIFOs at their ticks (they are already there in auction mode), and sets its phase to
   continuous.
3. **Catch-up.** The lane then processes its post-close packets (`rx_ts ≥ t_close`, already
   queue-acked) as continuous ops in `LaneSeq` order, classified against `v_U` (05), ordered
   after U. A packet that arrives while this queue is not empty is queue-acked within `LAT_MAX_NS`
   and joins its end: a fill sooner would overtake an earlier packet. When the queue is empty the
   lane is **live** and fills each packet on arrival. Catch-up takes at most `EPO_CATCHUP_US`
   (0.75 ms at peak, §6.1). W ends when the last lane is live.
4. **Final records.** The final records of window messages drain at low priority. Each lane builds,
   per session in `(pkt_seq, index)` order: `Fill`, then `Ack` for a resting rest, `Out` for an
   auction-only rest, `Reject` and `CancelAck` as recorded. Uncross fills go first, and leave
   within `BLD_UNCROSS_US_MAX` (§7.8). Continuous responses always go before the drain. A lane
   posts a drain packet only when its port's TX load is below `EPO_DRAIN_LOAD_CAP` (0.80). At peak
   (~110M records, ~1.9 GB) the drain takes ≤ `EPO_DRAIN_MS` (150 ms) in the ~50% of port capacity
   that continuous traffic leaves. Final records take their `resp_seq` at U, before any continuous
   response of the session; the client accepts continuous responses ahead of them and sends no
   `ResendReq` for a gap younger than `EPO_DRAIN_MS`.
5. `LAT_MAX_NS` (REQ-LAT-1) applies to every message at every moment, the window included: each
   window message got its queued `Ack` within it (§7.11). What waits for U is the fill and the
   final record, never the first answer.
6. vyrn-md publishes one `AuctionResult{p, v, imb, ref}` right after U, then the book (10). It
   publishes no indicative price during the window, because the new home has no state at S until
   the last few milliseconds of the window.

### 7.11 The 1 µs answer in the window

The window costs fills only (§6.3). Every packet that reaches a new-home lane gets its first
response within `LAT_MAX_NS`, like any other packet (01 §14.0, E10).

**The queued `Ack`** (Requests to 01, item 8) is `Ack` (0x81) with bytes 2–3 = `EPO_ACK_QUEUED`
(= 1, little-endian u16: bit 0 set, every other bit 0),
`handle` = the `wref` (`New`, `Replace`) or the target handle (`Cancel`, `Reduce`), `tick` = the
message's tick or 0, and the `client_tag`. It states: this message is in the log of e+1 at
(lane, `LaneSeq`), and it is resolved at U. It does not state that a `New` passed risk: balances
are state at S, which the box does not hold yet. Lanes send it under the same gates as any ack:
after a published cut includes the op (`INV-ACK-AFTER-CUT`) and after its `PacketRecord` left on
both replication paths (`INV-FRAME-FIRST`, 01 §14.5). So a queued-acked message is held by
`R_{e+1}`, survives a sequencer crash (§10.4), and is final in a window block within
`FINALITY_MAX_MS` (§7.1).

**The window stream.** The box does not know a session's `resp_seq` at S until the tail arrives,
so window answers use a separate stream: response header flags bit 1 = window, and `resp_seq`
counts the session's window answers from 1 (Requests to 01, item 9). Every window answer is a pure
function of the logged window packets, so replicas reproduce it and the recovery service keeps it
(01 §14.6). A `ResendReq` with byte 1 bit 0 set asks for window answers. Final records after U
use the ordinary stream, continuing from the state at S (F6).

**Budget at message index 9 (REF, as 01 §14.2 with §14.17 item 1):** 320 RX + 45 session and
MAC + 10 × 10 collect + 40 replay slice + 170 logged cut (`LaneCut`, its ~20 ns poll included) +
10 frame gate + 20 response + 240 TX = **945 ns** ≤ 980 ns (`LAT_MAX_NS` − `DEADLINE_GUARD_NS`).
**Deadline admission** (01 §14.1) runs unchanged with the collect path as `predicted_path_ns`. A
late packet gets `Reject BUSY` for each message in the window stream, and is logged with
`PacketRecord.flags.SHED` in its window block; Apply skips it. Collect has no BBO stage, so a
window packet can be shed only at the lane stage. B3's per-class bounds (01 §14.17 item 2: zero
lane-stage `BUSY` on dedicated paced lanes, ≤ 1e-6 at ≤ 20% load on pooled lanes) hold in the
window as everywhere, and pooled and dedicated lanes run the same collect path (§7.1).

**Messages that cannot be queued.** Each gets a definite answer within `LAT_MAX_NS`:

| Case | Why it cannot be queued | 1 µs answer |
|---|---|---|
| late by deadline admission; collect buffer full | 01 §14.1 | `Reject BUSY` per message (detail 1 = full), logged as shed |
| `New` FOK | it needs the book now | `Reject AUCTION_PHASE` |
| `New` IOC | 04 §6.9: IOC is not accepted in any auction phase, so every auction (the opening one and a reopening after a halt, §7.9) answers it the same way | `Reject AUCTION_PHASE`, detail `PROTO_PHASE_AUCTION` (2) |
| `rx_ts < T` | it belongs to epoch e | out-of-stream `Reject EPOCH_MISMATCH` (§11.2) |
| old session of an account that moves lane | it closes at S (§9.2) | out-of-stream `Reject SESSION_CLOSED`, detail `EPO_D_LANE_MOVED` |
| `New` or `Replace` after `EpoHalt` (§10.3) | the book is halted | `Reject BOOK_HALTED` in the window stream |
| a `pkt_seq` already collected | a duplicate in the window | its first answer again, flags bit 0 = resend |
| an unknown `SessionId` | no key exists to verify or to answer it (§9.1) | dropped and counted, as 04 drops it; this cannot happen to a session opened before the cutoff |

**A cancel of a carried order** is queued, not refused. The lane cannot confirm it, because the
order's state at S has not arrived. But the cancel's place in the log is fixed, nothing trades
between S and U, and Apply runs every queued op before the uncross. So a queued cancel of an
order that rests at S always succeeds (`CancelAck`); it is `TOO_LATE` if the order filled in the
tail, and `UNKNOWN_HANDLE` if no such order existed. A `ResendReq` for an epoch-e response that
the retention buffer does not hold yet is queued the same way and served at activation.

## 8. Fencing (`INV-FENCE`)

### 8.1 Epoch tags

| Object | Epoch field | Checked by |
|---|---|---|
| request packet | `epoch16` (01 §6.1) | the receiving lane, before the MAC (§8.2 F5) |
| response packet | `epoch16` (01 §6.3) | the client: selects `K_out(epoch)` |
| order-stream frame | frame header `epoch` (Requests to 01, item 4) | every replica and follower |
| `BlockHeader` | `epoch` (01 §6.6) | every voter |
| vote, `HandoffSig`, `EpoReady` | `epoch` in the signed message | every verifier |

### 8.2 Rules

- **F1** (`INV-FENCE`). After a replica holds cert(e, S), it rejects every epoch-e step above S
  and every epoch-e block above `last_height`. It counts and alarms on each one; a signed one is
  evidence (09).
- **F2.** A member signs one `HandoffRecord` per (book, epoch), persisted before it is sent (§5.3).
- **F3.** A node signs consensus messages of epoch e only if `home(e)` is its home and it is in
  `R_e` (09 §2.6). After it signs the `HandoffRecord` of e, it signs nothing else of epoch e.
- **F4.** A node of `R_{e+1}` votes on no epoch-(e+1) block that holds a step before it has
  verified cert(e, S). Before that it votes only on window blocks, which hold `PacketRecord`s and
  control-session records and no step, and whose `anchor` is the final `EpoGo` (§7.1). It accepts
  epoch-(e+1) frames only from the sequencer box whose key is `next_seq_key`, or from the standby
  after a failover in e+1 (§10.4).
- **F5.** A lane checks `epoch16` first. A packet whose `epoch16` is not the lane's active or
  collecting epoch is not MAC-checked with the lane's key and never closes a session. It gets at
  most one out-of-stream answer (§10.7). Reason: a client on the wrong side of a boundary holds the
  other epoch's key, and closing its session for that would punish a race the client cannot avoid.
  This is 01 §14.8: a bad MAC closes a session only from the bound address **and** with `epoch16`
  equal to the receiver's epoch. After its seal the old home closes no session at all, because the
  sessions' state at S already belongs to e+1 (§10.7).
- **F6.** A response to a packet that does not enter the log is out of stream (`resp_seq = 0`,
  04 P6). Only logged packets consume `resp_seq`, so the new home can continue every session's
  `resp_seq` from the state at S. Window answers use the window stream (§7.11) and consume no
  `resp_seq`.

### 8.3 Why clock skew cannot fork the book

The history of epoch e ends at the certified S, and the history of e+1 starts from it. Clocks only
decide when the seal happens and when collection starts. Take an old-home clock that is off by δ
against the new home's:

- **Old clock late (δ > 0).** The old home seals at true time T + δ. For δ the old home still
  trades and the new home already collects. The collected orders do not execute until cert(e, S),
  and that certificate covers everything the old home did until its seal. The window grows by δ.
- **Old clock early (δ < 0).** The old home seals at T − |δ|. The new home starts at T. For |δ|
  nobody trades. The window grows by |δ|.
- **A packet on both sides.** A client may send one `pkt_seq` to both homes (a resend). If the old
  home applied it before S, the state at S holds `hw_pkt_seq ≥ pkt_seq` and the new home drops its
  copy (§7.3). If not, only the new home applies it. Either way it is applied once.

Two histories never exist: one certificate per (book, e) at most (§5.3), and every e+1 block extends
it (F4). The alarm `EPO_SKEW_ALARM_NS` (1 µs; GPS-disciplined PTP keeps ~100 ns, vendor) protects
fairness and the window length, not safety. vyrn-sim tests skew up to ±10 s (§12).

## 9. Keys and membership at the boundary

### 9.1 Sequencer keys

- **Block signing.** `next_seq_key` is `SK(seq_index, home(e+1))` of the F1 sequencer box (09
  §2.2), of the scheme of `EpoConfig(e+1)`. From `E_pq` on, the replicas accept no scheme-0
  `seq_sig` for e ≥ `E_pq` (01 §14.20 SG2). It is fixed in `EpoGo` and then in the `HandoffRecord`. The replicas of e+1 accept
  `seq_sig` only under this key until a failover in e+1 moves the role to the F2 standby, whose
  `SK` the roster also holds (§10.4).
- **Session keys.** `K_seq(e+1, i)` and `K_out(e+1, i)` come from X25519 between the session's key
  and `XK(i, home(e+1))`, then BLAKE3 `derive_key` with the epoch and i in the input (01 §4; 09
  §5.3; 04 §4). For e+1 ≥ `E_pq` the material also holds the ML-KEM-768 secret that the box
  decapsulates from the session's ciphertext for (e+1, i) (01 §14.20 G, KG1). Clients derive them
  ahead for both sequencer boxes i of the new home. Each box derives its side for every open session
  in Preparing: ~2 × 10^5 sessions at ≤ 25 µs each is 5 s of core time, 0.1 s on 49 lanes (budget).
  From `E_pq`, ≤ 65 µs each with the decapsulation: 13 s of core time, 0.27 s on 49 lanes
  (budget; 17 µs mean and 38 µs p99 measured off `REF`). A session opened in the last 60 s is derived when the
  replay reaches its open record.
- **Open cutoff.** The old home accepts no `OpenSession` after `T − EPO_OPEN_CUTOFF_MS` (500 ms);
  it answers "retry at `home(e+1)`", and the new home serves the open after activation. Reason:
  500 ms > t_wan + `FINALITY_MAX_MS` + `EPO_READY_LAG_MS` on every pair, so every session that can
  send in the window has its open record, and its keys, at the new home before T. No window packet
  then waits unverified. An open is not a 1 µs message (04: ≤ 50 ms); only opens in the last
  500 ms wait for the window.
- **K_com** (CHAIN) is per (e, sequencer) and comes from 09's committee keys. It changes at the
  boundary like `K_seq`. 08 adds nothing.

### 9.2 Lane map

`lane_map(e+1)` is computed by replicas (10 §1.3), fixed in `EpoConfig(e+1)` and published 1 h
ahead. Replicas compute it for each home's class sizes and `EpoConfig(e+1).lane_map_hash` holds
all three hashes (TYO, LDN, NYC), so a carried-forward configuration names a map built for the
home it lands on. It gives each account a class, dedicated or pooled (01 §14.15), and a firm is promoted or
demoted only here, at a boundary. At most `ACC_MAX_MOVES_PER_EPOCH` (1,024) accounts move per
boundary, class changes included. An account that stays pooled keeps its pool queue and does not
move. 04 binds a session to its lane for life, so for a moved account:

1. The client pre-opens a session on the new lane during epoch e, valid from e+1 (04), before the
   open cutoff (§9.1).
2. It trades on the old session until its own T, like every client, and on the new session at H′
   from T. It does not quiesce. A packet still unacked on the old session at T has an answer on
   its way from H: an in-stream response if H applied it before S, or the out-of-stream
   `EPOCH_MISMATCH` if it arrived after the seal. The client resends only the rejected contents, as
   new packets on the new session. So nothing is lost and nothing applies twice, and the account
   loses no trading time beyond the window.
3. The old session closes at S (`SESSION_CLOSED`, detail `EPO_D_LANE_MOVED`). The new home knows
   `lane_map(e+1)`, so it answers a packet on the old session within `LAT_MAX_NS` with that reject
   (§7.11).
4. `from_state` moves the account's balances and resting orders to the new lane. Each order keeps
   its `PrioKey` (§7.4), gets a new handle, and is re-acked on the new session after U with
   `Ack{index: 0xFE}` (Requests to 01, item 5). The client maps `client_tag` to the new handle.

### 9.3 Replica sets

`R_{e+1}` is fixed in `EpoConfig(e+1)` through its roster (§9.6) and changes only at a boundary: in CHAIN by 09's governance
(`NodeCert.valid_from`), in BASE by an admin record. A new box follows for at least one epoch before
it is listed, so it passes `EpoReady`'s lag and B4 checks. A box leaves after its home's last epoch.

### 9.5 Bridge signer table (CHAIN)

The bridge signer table maps an L1 rotation number to its `SignerSet` (09 §6.7: five bridge keys
and five guardian keys). It is a key table like `VK`, `SK` and `XK`, so this chapter owns it and it
changes only at a boundary (E9):

- A governance-approved set with rotation number r + 1 is scheduled for the first boundary after
  its approval and becomes active when that epoch activates; if that epoch is skipped, at the next
  activation.
- Rotation numbers are consecutive from genesis 0. No key is zero, and no key repeats within its
  list (the contract's `_writeSet` check).
- Every activated set stays readable by rotation number, because posts accepted under an earlier
  set stay claimable on L1 (09 §6.7 step 4). L1's own 72 h queue is separate from this table.
- The set in force for epoch e is the one the roster of `EpoConfig(e)` names (§9.6), and it must
  equal the table's set of that rotation number. A carried-forward configuration keeps the set,
  so a rotation activates only at a boundary whose configuration names it.

### 9.4 Software upgrades

| Rule | Statement | Reason |
|---|---|---|
| U1 | A node changes binaries only while its home is a follower. | It has 16 h per day for it, and its replay catches up before its home is active. |
| U2 | A binary implements every engine version from the oldest epoch it may replay to the newest one scheduled. `EpoConfig.version` selects the semantics per epoch. | A replica replays epoch e with e's rules after its binary changed. |
| U3 | A node sends `EpoReady` only if it replayed the last 3 epochs on its new binary bit for bit (B4). | A bad build fails before it votes. |
| U4 | At most one client kind (Rust or Vx) changes binary per boundary. | `CLIENT_SPLIT_BASE` (2 + 2) and `CLIENT_SPLIT_CHAIN` (3 + 2) mean neither kind reaches Q alone, so a bug in the changed kind halts finality and the unchanged kind stays the reference. |
| U5 | A semantic change activates by `EpoConfig.version` at a boundary only after both kinds ship it under U1–U4. | Both implementations then agree before the change counts. |
| U6 | Both sequencer boxes always run Rust (01 §14.4). They change binary under U4 as part of the Rust kind, and the standby changes with the primary. | They never vote, in either mode, so the split counts voters only. Both client kinds' replays check them. |

### 9.6 The roster and `roster_hash`

The roster is every key and replica-plane address of the three homes. `EpoConfig(e)` carries
only its hash; the control path publishes the bytes with the record (BASE: the admin record; CHAIN:
built from the `NodeCert`s in force for e, 09 §2.3, and the bridge signer table, §9.5). One roster
covers all three homes, so a carried-forward `roster_hash` (§2.3) names the right keys whatever
`home(e)` becomes, and a carried `sig_scheme` and a carried roster stay in step (01 §14.20 SG4).

```
Roster {                      // little-endian (01 §3)
    version:    u8,           // 1; a decoder rejects any other value and any trailing byte
    sig_scheme: SigScheme,    // 0 or 1: the scheme of every NK, VK and SK below
    epoch_from: Epoch,        // the first epoch it may configure
    homes:      [Home; 3],    // TYO, LDN, NYC (HomeCode order)
    bridge:     BridgeSet,    // CHAIN only; BASE has no bridge section
}
Home {
    voters:   [Voter; n],     // n = N_BASE or N_CHAIN; voter index = position
    n_seq:    u8,             // BASE ≥ 2; CHAIN = 2 × N_CHAIN: box 2k is operator k's F1 box, 2k + 1 its F2 box
    seq:      [SeqBox; n_seq],// roster index = n + position
    recovery: u8,             // voter index of the recovery service (07 §8.5)
    n_data:   u8,
    data:     [DataBox; n_data],
}
Voter   { client: u8 (0 Rust, 1 Vx), facility: u8 (k for Fk), node_key: [K], vote_key: [K],
          xchg_key: [X] (GXK, 09 §2.4), data_addr: Addr, repl_addr: Addr }
SeqBox  { facility: u8, node_key: [K], seq_key: [K], xchg_key: [X] (XK), client_addr: Addr,
          repl_addr: Addr }
DataBox { facility: u8, addr: Addr }
Addr    { ip: [u8; 16] (IPv6; IPv4 as ::ffff:a.b.c.d), port: u16 }
BridgeSet { rotation_no: u64, bridge_keys: [[u8; 20]; 5], guardian_keys: [[u8; 20]; 5] }   // 09 §6.7

roster_hash = derive_key("vyrn      v1 roster", genesis_hash ‖ mode ‖ Roster)
```

`K` is the `PubKey` length of `sig_scheme` (01 §3: 32 or 1,344 B). `X` is the `KexKey` length of
`sig_scheme` (01 §3, PQ-6(a): X25519, 32 B, or X25519 ‖ ML-KEM-768, 1,216 B). `mode` is one byte, 0 BASE and 1 CHAIN, as in every
`genesis_hash ‖ mode` prefix of this chapter; it also fixes `n` and `Q`, so the roster stores
neither. CHAIN: voter i and boxes 2i and 2i + 1 are operator i's validator box and its F1 and F2
sequencer boxes (09 §1), from `NodeCert(i, home)`, so they share `node_key`; the voter's
`xchg_key` is the `NodeCert`'s GXK and the boxes' is its XK. `node_key` (NK) verifies `EpoReady`
(§2.6), for voters and boxes alike. BASE voters carry a GXK that nothing reads. Client-facing addresses (per-lane
order addresses, the recovery address) are in the endpoint table (§11.1), not here.

**Decode rules.** A node rejects roster bytes, before it uses any key, unless all of these hold:

| # | Rule |
|---|---|
| R1 | `derive_key` of the bytes equals `EpoConfig(e).roster_hash`, checked before decoding |
| R2 | `version` = 1; `sig_scheme` ∈ {0, 1} and equals `EpoConfig(e).sig_scheme`; no trailing byte |
| R3 | `epoch_from` ≤ e |
| R4 | Per home: `client` ∈ {0, 1}, every `facility` ≥ 1, and neither client holds Q voters (`CLIENT_SPLIT`) |
| R5 | Per home: no key repeats among the `vote_key`s and `seq_key`s (07 §13.1). CHAIN: an operator's two boxes (2k, 2k + 1) carry the same `seq_key` and `xchg_key`, from its one `NodeCert`, and different `facility` values; that `seq_key` counts once |
| R6 | Per home: `recovery` names a Rust voter; `n_seq` as above |
| R7 | CHAIN: no bridge or guardian key is zero or repeats within its list, and the set equals the bridge signer table's set of `rotation_no`, activated or scheduled to activate at or before e (§9.5), so `R_{e+1}` is checked before its boundary |
| R8 | `EpoConfig(e).seq_order` names two distinct boxes of `home(e)`: BASE the primary in F1 and the standby in F2; CHAIN an F1 box (even position) as primary and another operator's F2 box (odd position) as standby, in different facilities |

**The schedule's `seq_order`.** BASE: the first box in F1 and the first in F2. CHAIN: the F1 box
of `seq_op(e)` and the F2 box of `next_seq(e, seq_op(e))` (09 §3.1–3.2), roster indices
`n + 2·seq_op(e)` and `n + 2·next_seq + 1`. A published `EpoConfig` names this value; a
carried-forward one recomputes it from the carried roster (§2.3).

**The view.** `REP_Membership(e)` (07 §13.1) is not a separate record: it is `home(e)`'s part of
the roster, with `seq_order` = `[EpoConfig(e).seq_order[0], seq_order[1]]` and then the other
boxes in roster order. `HandoffCert(e − 1)` certifies it through `EpoConfig(e)`.

**Size.** A scheme-0 BASE roster with 2 boxes and 4 data boxes per home is 2,649 B; a scheme-0
CHAIN roster is 6,508 B and a scheme-1 one 177,868 B (computed, `vyrn-epoch` `vectors/roster.txt`).
A node hashes it once per `EpoConfig`, off every hot path: 178 KB of BLAKE3 is ≤ 0.15 ms (budget).

**Vectors.** `crates/vyrn-epoch/vectors/roster.txt` holds the bytes and `roster_hash` of a BASE and
a CHAIN scheme-0 roster, the hash and length of a scheme-1 one, and one reject per rule R1–R8.

## 10. Failure cases

### 10.1 The old sequencer dies before the certificate

| When | Decision | Window effect (budget) |
|---|---|---|
| before `T − EPO_SEAL_GUARD_MS` (20 ms) | Ordinary 07 failover: the old home's F2 standby is promoted, trades until T and seals. No voter changes, so the client split holds. | none; the failover itself is ≤ `FAILOVER_TARGET_MS` |
| after `T − 20 ms`, before its `Seal` frame | Seal-mode failover (§4.3). S is the last step of the longest finalized prefix. A fill reverts only if both replication paths lost its frames, which is two faults (07). | + `FAILOVER_SILENCE_MS` + finality: +2 to +12 ms |
| after its `Seal` frame | Nothing changes. The replicas hold S and certify it. | none |

If the dead sequencer's frames reached the new home but not the old replicas, the new home's S′ is
beyond S. The new sequencer undoes to the last finalized block and re-applies (§4.5):
+`EPO_RESPEC_MS` (15 ms) at worst. That costs time and never correctness, because nothing that
depends on the speculative state was sent. Queued `Ack`s do not depend on it (§7.11).

### 10.2 The new home has fewer than Q healthy replicas, or no standby

Decision: do not hand off. The go/no-go logs `EpoHold`, the old home keeps epoch e, and every
session gets a revised `EpochNotice` (flags bit1). The same holds when either sequencer box of the
new home is not ready (§2.6). The attempt repeats every `EPO_HOLD_S` (900 s), and moves to the
next slot's home when slot e+1 ends (§2.5). A hold costs no window and no fill.

If the new home loses quorum after `EpoGo` is final, the handoff proceeds: the certificate does
not depend on the new home. The book is then certified at S and nobody is active. It stays halted
until `R_{e+1}` has Q healthy members again (restart and follower catch-up, minutes) or until a
reassignment (§10.3). This needs two voter faults after a healthy go/no-go 10 s before, which is
beyond `F`. One voter fault, or one sequencer-box fault (§10.4), leaves the handoff on budget.

### 10.3 A WAN partition during the handoff

| Partition starts | Outcome |
|---|---|
| before the go/no-go | No fresh `EpoReady` reaches the old home: `EpoHold` (§10.2). |
| after `EpoGo`, before the certificate reaches the new home | The certificate and tail take the other path, then the third-home route (§5.5). If all three fail, the book halts at S. |
| after activation | Ordinary follower lag at the old and third homes. No effect on trading. |

The new home keeps queue-acking and finalizing window blocks until `T + EPO_HALT_COLLECT_MS`
(250 ms; the certificate arrives by t_wan + 11.3 ms on the direct path, and by 201 ms on the
slowest third-home route, LDN → TYO → NYC). If no certificate has arrived by then, the control core logs `EpoHalt` in a window
block. From the cut after it, lanes answer `New` and `Replace` with `Reject BOOK_HALTED` within
`LAT_MAX_NS`, and keep queueing `Cancel`, `Reduce` and `CancelAll`, which only reduce risk. When a
path heals, activation proceeds with a longer window and the same uncross rule.

Decision: **no automatic resumption at the old home.** A node of `R_e` cannot tell a dead new home
from a partitioned live one, and a live one activates as soon as it holds the certificate. After
`EPO_REASSIGN_MIN_S` (60 s) after T, operators may reassign epoch e+1 with
`EpoReassign{e+1, home, win_head}`:

1. Each signing operator first fences its own node in the new home through its out-of-band
   management path, so that node can no longer sign for e+1. It then reads the node's persisted
   high-water mark and stops here if the mark shows `armed(e+1)`. It also reads the node's highest
   final window block. If it cannot read the mark, it does not sign.
2. It then signs `EpoReassign` with its operator key (CHAIN: `OIK`, 09 §2.10 tightening; BASE: Q
   admin keys). `win_head` is the highest final window block that any of the Q fenced nodes holds.
3. Q signatures make it valid. The target home fetches the window chain to `win_head` and its
   payloads from the fenced nodes' log stores, then activates e+1 from cert(e, S), the
   reassignment and those window blocks.

```
EpoReassign body (43 bytes, little-endian)   msg = derive_key("vyrn      v1 reassign",
off size field                                              genesis_hash ‖ mode ‖ body)
  0   2  book      BookId                    sig = Ed25519_sign(operator key, msg)
  2   4  epoch     e+1                       valid with Q distinct operator indices, ascending,
  6   1  home      HomeCode of the target     each (index u8, sig [64])
  7   4  wheight   win_head height (0: no final window block)
 11  32  win_hash  win_head block hash (zero when wheight = 0)
 43      end
```

A fill of e+1 at the new home needs Q armed members, and a reassignment needs Q operators whose
members are not armed. Two quorums share an honest operator (§5.3), so exactly one of them can
happen, and no fill sent by the abandoned home can be reverted. Every queued-acked order is in a
final window block, which an honest fenced node of any Q holds (quorum intersection), so
`win_head` covers it: no acked order is lost.

### 10.4 The new sequencer fails

The new home's standby `vyrn-seq` in F2 takes over through 07's failover (SF-25), at any moment from
T on. No voting replica is promoted, so the 2 + 2 (BASE) and 3 + 2 (CHAIN) client splits stay
intact (01 §14.4).

- **During the window, before activation.** `R_{e+1}` detect silence (`FAILOVER_SILENCE_MS`) and
  finalize the longest window prefix they hold. Every queued-acked packet is in it, because its
  record left on both paths before its `Ack` (§7.11). The standby already follows the tail and has
  applied the final window blocks against S′ (§4.5), so it continues collection under its own key
  and activates when the certificate arrives. Window effect: none if the promotion ends before the
  certificate arrives; at most `FAILOVER_TARGET_MS` otherwise.
- **After activation, the `Uncross` frame left on both paths.** Every auction fill sent is in the
  log (`INV-FRAME-FIRST`). The standby replays the opening block and continues.
- **After activation, it did not.** No auction fill was sent. The standby uncrosses from the final
  window blocks and cert(e, S), with the same rule and the same result (`INV-DET`). Packets that
  were never queue-acked are not in the log; their clients resend them.

Clients switch `tag_seq` to `K_seq(e+1, standby)`, which they derived ahead (§9.1), on the failover
notice (04, 07 §9.5). After a promotion the home has no standby until operators restore one (07
§13); 03 places the next standby in F2.

### 10.5 A byzantine old sequencer signs two different final steps

Two signed last blocks with different S cannot both be final: Simplex finalizes one block per
height (07). Members sign a `HandoffRecord` only for the finalized block (§5.3 rule 1), so at most
one certificate exists. The two `seq_sig`s on conflicting headers are equivocation evidence, slashed
automatically in CHAIN mode (09, SF-19). A different tail sent only to the new home yields S′ ≠ S
there and costs the re-replay of §10.1. A sequencer that never seals is force-sealed (§4.3).

### 10.6 Data-tier gaps at the new home

| Gap | Repair | Window effect |
|---|---|---|
| one WAN path loses tail payloads, or fails | none: the other path carries every payload (§5.5) | none |
| both paths lose the same tail payload (two faults) | `EpoTailReq` to the old and third homes at once (§5.5) | check 5 of §5.4 waits for the replay: +70 ms (TYO → LDN via NYC) |
| a window payload missing at the new data tier | `R_{e+1}` fetches it from the new sequencer's collect buffer (07's repair path) | none; metro, within the window block's finality |
| a new-home data node down | clients move to the next data node (04 D4–D5); repair as above | none |

### 10.7 Clients that miss the `EpochNotice`

A client does not need the notice for the default schedule: it computes T from `G` and
`EPOCH_BOUNDARIES_UTC`. The notice matters only for revisions, which vyrn-md and the admin channel
(BASE) or chain state (CHAIN) also publish. A client that still sends to the old home after the
seal gets, from the old sequencer in Redirect state, an out-of-stream response: `EpochNotice`
(seconds 0) and `Reject EPOCH_MISMATCH` for each message (detail = the active epoch). The packet is
MAC-checked with `K_seq(e)`, is never applied, and is answered within `LAT_MAX_NS`, every packet,
to the bound address only. The answer is at most 8 bytes longer than the request, so it cannot
amplify an attack. A bad MAC is dropped and counted and closes nothing (F5). The old box keeps
answering after it rejoins as a follower, between replay slices (§7.1), for as long as it runs:
no packet that reaches a sequencer box goes unanswered.

## 11. Client migration

### 11.1 The endpoint table

At session open the client receives the endpoint table of all three homes in its key bundle
(04 §4.4): per home and per roster index, the order address for each lane, the recovery address,
the data nodes, `XK` and `SK`; plus the port base. Its hash is `EpoConfig.endpoint_hash`. When an
`EpochNotice` has flags bit4 set, the client fetches the new table (admin channel or chain state)
before T.

### 11.2 What the client does

```
 Active(e, H) ── first EpochNotice(e+1, H′, s, seq_index) ──► Scheduled(T)
   prepare: T = now + s (or the schedule), K_seq/K_out(e+1, i) for both sequencer boxes i,
            own lane in lane_map(e+1); if moved: pre-open before the cutoff (§9.1, §9.2)
 Scheduled ── own clock ≥ T, or EpochNotice(0), or Reject EPOCH_MISMATCH from H ──► Switching
   1. stop sending to H
   2. resend every unacked packet to H′ in pkt_seq order: flags bit0 = 1, epoch16 = e+1,
      tag_seq under K_seq(e+1, seq_index), both copies (04 D2), logical content unchanged (04 D3)
   3. then send new packets to H′; each gets a queued Ack within 1 µs of reaching H′ (§7.11)
 Switching ── first response with epoch16 = e+1 (window or ordinary stream) ──► Active(e+1, H′)
   4. after U: ResendReq for any resp_seq gap older than EPO_DRAIN_MS, including late
      responses of epoch e (§11.3); window-stream gaps at any time (byte 1 bit 0)
```

A revised notice (flags bit0) restarts Scheduled with the new T. A packet that reaches H′ with
`rx_ts < T` gets an out-of-stream `Reject EPOCH_MISMATCH`, so switching early gains nothing.

### 11.3 Exactly once across the boundary

- A packet with `pkt_seq ≤ hw_pkt_seq(S)` was applied in epoch e. The new home drops every copy.
  Its responses are in the new sequencer's retention buffer, which the replay filled from
  `T − EPO_PREP_LEAD_S` on (`INV-DET` makes them identical to what the old home sent), and in the
  recovery service (04 P8).
- A packet with `pkt_seq > hw_pkt_seq(S)` was not applied in e (gapless `pkt_seq`). The new home
  applies it once, in the window or after U.
- `resp_seq` continues from the state at S, because only logged packets consume it (F6). Window
  answers have their own stream (§7.11), so the new home never needs `resp_seq(S)` before U.
- A queued-acked packet is in a final window block. No failure loses it (§10.3, §10.4).

So a client never needs the old home after T, and no order is lost or doubled.

### 11.4 Latency the client sees (TYO → LDN, typical, W = 112.6 ms)

| Client in | Last old fill arrives | First new fill arrives | Gap | Queued `Ack` of a send at T arrives | Last send that still joins the auction |
|---|---|---|---|---|---|
| TYO | T | T + 222.6 | 222.6 ms | T + 220 | T + 2.4 |
| LDN | T + 110 | T + 112.6 | 2.6 ms | T + local RTT | T + 112.4 |
| NYC | T + 80 | T + 147.6 | 67.6 ms | T + 70 | T + 77.4 |

Every packet gets its first answer one round trip to H′ plus at most 1 µs after it is sent, in the
window too; the gap is in fills only. The new home's local client sees almost no fill gap: it saw
the old book 110 ms late all along. The old
home's local client pays the window plus the return trip. Every client that reaches the new home
before `t_close` competes in one uncross.

## 12. Testing

### 12.1 Chaos plan in `vyrn-sim`

`vyrn-sim` (11 §6) runs three homes with `N_BASE` or `N_CHAIN` voters and 2 sequencer boxes each,
data tiers, WAN links with the §6 delays and a heavy-tailed jitter, and 10^4 simulated clients
with distances to all homes.
Epochs are compressed to 60 s of virtual time. Each scenario runs over all three transitions.

| ID | Scenario | Fault classes (11) |
|---|---|---|
| EPO-T1 | Clean handoffs, 10%, 60% and 100% window load | — |
| EPO-T2 | Old sequencer killed at a random event in [T − 200 ms, cert] | SF-08, SF-25 |
| EPO-T3 | New sequencer killed at a random event in [T, U + 50 ms]; the standby takes over; also the standby killed first | SF-25 |
| EPO-T4 | 0–4 new-home nodes down at the go/no-go; and after `EpoGo` | SF-09 |
| EPO-T5 | One WAN path cut; both direct paths cut; all three routes cut, then healed | SF-07 |
| EPO-T6 | WAN delay spikes to 5× during the tail | SF-07 |
| EPO-T7 | Clock skew between homes of ±1 µs, ±10 ms, ±10 s; PHC step at T | SF-16, SF-17 |
| EPO-T8 | Byzantine old sequencer: two final blocks, withheld seal, tail sent only to the new home | SF-19, SF-20 |
| EPO-T9 | Byzantine member: signs two `HandoffRecord`s; signs an `EpoHold` while ready | SF-22 |
| EPO-T10 | Data copies of 1% of window packets dropped; tail payloads dropped on one path | SF-10 |
| EPO-T11 | Clients: missed notices, early switch, late switch, resend storms, two contents for one `pkt_seq` | SF-01, SF-04 |
| EPO-T12 | Moved accounts (1,024), promotions and demotions between classes, date roll, skip, hold, home override to the same home | — |
| EPO-T13 | Reassignment after a permanent new-home partition; the certificate arrives during the fencing | SF-07 |
| EPO-T14 | 1 µs in the window: 1B msgs/s into the new home, all message types, cancels of carried orders, moved-account old sessions, collect buffer full, `EpoHalt`; dedicated and pooled lanes at once, with no steal and no `AcctTake` until each lane is live | SF-30, SF-31 |

### 12.2 Pass criteria

Every run must pass all of these. One failure fails the build.

| # | Criterion |
|---|---|
| P1 | No lost order: every message a client sent is, at quiescence, in exactly one epoch's log or answered by an out-of-stream reject that the client then resent. |
| P2 | No duplicate: no `(session, pkt_seq)` is applied in two epochs. |
| P3 | `INV-FENCE`, F1–F6 hold at every node at every event. |
| P4 | One history: every node of every home has the same sequence of `(e, S, log_hash, state_root)`. At most one certificate exists per (book, e). |
| P5 | The auction equals the oracle: `vyrn-vx-oracle` recomputes p*, V, the marginal order and every order's fill from the logged inputs by brute force (every tick, every order), and the engine's results are identical. The residual book is uncrossed. |
| P6 | Every fill sent is in the final log, except a fill whose frames the run dropped on both paths (07). |
| P7 | With no fault injected, the maximum window over seeds is within §6.2's bound (t_wan + `FINALITY_MAX_MS` + `EPO_WINDOW_SLACK_MS`) per transition; with faults, within the effects listed in §10. |
| P8 | No session is closed by a MAC failure that F5 covers. |
| P9 | The Rust and Vx replicas produce identical roots for every block, including the opening block. |
| P10 | Liveness: with ≤ F faults and no partition, every handoff completes or holds as §2.6 says. After a healed partition the book resumes and P1–P9 hold. |
| P11 | Every packet that reaches a sequencer box gets its first response within `LAT_MAX_NS` by the cost model (in `vyrn-sim`) and by B1's wire measurement (on hardware), at both homes, in every phase; every queued-acked message is in a final window block within `FINALITY_MAX_MS`. |
| P12 | No voting replica is ever promoted, and every `HandoffRecord` signer is a voting replica of `R_e`. |

Volume: 10^4 seeds per scenario per night on DEV and CI machines. On hardware, 11 §6.7 runs
EPO-T2, T3, T5, T7 and T14 with netem WAN delay, and B13 and B14 measure §6.2 and §7.8.

## Interfaces to other chapters

| Chapter | 08 consumes | 08 provides |
|---|---|---|
| 01 | §10 core map (two stream cores, three TX cores, control on core 51), §14 decisions: deadline admission, two-pass lanes, frame gating, who votes, sessions, new codes, lane classes (§14.15), `AcctTake` and the ack budget (§14.17) | the queued `Ack`, the window stream and `WinBlock` (Requests to 01, items 8–11); the window rule for pooled lanes (§7.1) |
| 02 | `REQ-EPO-*`, `REQ-FIN-*`, `REQ-LAT-1` IDs | the mechanisms and budgets for them: §6.2 window bound, §7.11 1 µs answer in the window, §11.3 exactly-once, §7 auction determinism |
| 03 | facility layout, the 2 WAN relays per home, the F2 standby `vyrn-seq` | the WAN bandwidth requirement (§5.5), both sequencer boxes in `seq_order` (§2.3) |
| 04 | sessions, keys, `pkt_seq`/`resp_seq`, P5, P6, P8, D2–D5, failover notice, open budget | `EpochNotice` triggers and bytes (§2.4), F5–F6, the window stream and queued `Ack` (§7.11), the open cutoff (§9.1), the client state machine (§11.2), moved accounts without quiesce (§9.2) |
| 05 | lanes, cut, BBO core, `PrioKey` rotation rank, checkpoints and undo of engine state | `EpochEngine` (§7.9), the uncross rule and `UncrossRecord` (§7.6–7.7), the TIF table (§7.2), the Seal procedure (§4.2), catch-up (§7.10) |
| 06 | PTP, TSC↔PHC mapping for deadline admission, NIC flow filters, huge pages | collect buffers and flow filters installed in Preparing |
| 07 | Simplex, finality certs, failover to the standby (also in seal mode), speculative follower replay, payload repair | the seal-mode failover rule (§4.3), F1–F4, window blocks and the opening block (§7.1), `EpoTailReq` (§5.5), standby takeover in the window (§10.4) |
| 09 | `home(e)`, `seq_op(e)`, `HomeOverride`, keys `VK`/`SK`/`XK`, `INV-CHN-SPLIT`, slashing | `HandoffRecord` signing by voters only (§5.2–5.3), `EpoForceSeal` as withheld-handoff evidence, `EpoReassign` with `win_head` (§10.3) |
| 10 | `lane_map(e+1)` with classes, pooled account tokens (10 §1.2), risk checks, `auction_ppm`, `BookSpec.ref_tick`, drop copy | phase/TIF rules (check 5 of 10 §3.1), `AuctionResult`, the date roll, STP rule in the uncross, parked tokens in the window (§7.1) |
| 11 | `vyrn-sim`, SF-01–SF-35, B1, B3 (`BUSY` per class), B13, B14, oracle ABI | EPO-T1–T14, P1–P12, B14 pass = 1,000 µs at 10^6 orders, B13 slack = 3 ms |

## Local definitions

Constants (all budgets). The timeouts and periods are in §4.9.

| Name | Value | Meaning |
|---|---|---|
| `EPO_SEAL_US` | 50 | T to the `Seal` frame on the wire |
| `EPO_WAN_OW_MS` | TYO↔LDN 110, LDN↔NYC 35, NYC↔TYO 80 | planning WAN one-way latencies |
| `EPO_WAN_PATHS` | 2 | independent WAN paths per home pair; each carries the whole stream |
| `EPO_WAN_GBPS_MIN` | 250 | capacity per path from the active home to each follower |
| `EPO_WINDOW_SLACK_MS` | 3 | W ≤ t_wan + `FINALITY_MAX_MS` + this, with no fault, at any load |
| `EPO_READY_LAG_MS` | 1 | maximum replay lag (WAN excluded) for `EpoReady` |
| `EPO_SKEW_ALARM_NS` | 1,000 | clock offset between homes that raises an alarm |
| `EPO_COLLECT_NS` | 10 | lane cost per collected message |
| `EPO_REPLAY_SLICE_NS` | 40 | longest replay or Apply slice between two RX polls of a lane |
| `EPO_ACK_QUEUED` | 1 (bit 0 of `Ack` bytes 2–3, u16 LE) | the queued `Ack` of a window message |
| `EPO_TAIL_REQ_MAX` | 1,024 | items per `EpoTailReq` |
| `EPO_APPLY_NS` | 3 | lane cost per applied window message |
| `EPO_COLLECT_MAX_MSGS` | 6,000,000 | collect buffer per lane; beyond it, `BUSY` |
| `EPO_HIST_HALF` | 4,096 | band half-width in ticks |
| `EPO_HIST_TICKS` | 8,193 | histogram buckets per side |
| `EPO_UNCROSS_FIRST_US` | 500 | activation to the first auction fill |
| `EPO_CATCHUP_US` | 1,000 | U to the moment a lane is live |
| `EPO_DRAIN_LOAD_CAP` | 0.80 | port load above which window final records wait |
| `EPO_DRAIN_MS` | 150 | drain of window final records at peak |
| `EPO_RESPEC_MS` | 15 | undo and re-apply after S′ ≠ S |
| `EPO_OPEN_CUTOFF_MS` | 500 | no `OpenSession` at the old home after T minus this |
| `EPO_NOTICE_OFFSETS_S` | 3,600, 600, 60, 10, 1 | `EpochNotice` offsets |
| `EPO_D_LANE_MOVED` | detail code of `SESSION_CLOSED` | the account moved lane at the boundary |

Types: `EpoConfig`, `Roster` (§9.6), `EpoReady`, `EpoGo`, `EpoHold`, `EpoHalt`, `EpoForceSeal`, `EpoReassign`,
`HandoffSig`, `HandoffCert`, `EpoArmed`, `EpoTailReq`/`EpoTailResp`, `EpoActivated`, `WinBlock`,
`UncrossRecord`, `PrioKey`, `AuctionCfg`, `CollectBuf`, trait `EpochEngine`. Invariants:

| Name | Statement |
|---|---|
| `INV-EPO-1` | No response that depends on the state at S leaves a sequencer box before it has verified cert(e, S) and its own state at S, and holds `EpoArmed` from Q members of `R_{e+1}`. Queued `Ack`s and window-stream rejects depend on no state at S. |
| `INV-EPO-2` | Every carried order has time priority over every window order at the same tick. |
| `INV-EPO-3` | A `(session, pkt_seq)` is applied in at most one epoch. |
| `INV-EPO-4` | The uncross writes only `UncrossRecord`; each order's auction fill is `auction_fill` of it. |
| `INV-EPO-5` | Every packet that reaches a sequencer box of either home gets its first response within `LAT_MAX_NS`, in every phase of the handoff. |
| `INV-EPO-6` | Every queued-acked message is in a final window block within `FINALITY_MAX_MS` of its `Ack`. |
| `INV-EPO-7` | No `vyrn-seq` box votes or signs a `HandoffRecord`; a failover promotes only a standby `vyrn-seq`. |

## Requests to 01

01 §14 resolved the earlier items on `Seal`/`Uncross` (§14.10), `Fill.liq = 2` (§14.10), the
`Out` causes with expired (§14.10), the MAC rule with `epoch16` (§14.8) and sessions that span
epochs (§14.8). These remain:

1. §6.4 `EpochNotice`: byte 1 = `seq_index` of the next epoch; bytes 2–3 = flags (bit0 revised,
   bit1 hold, bit2 skip, bit3 date roll, bit4 endpoint table changed).
2. §6.6 `HandoffRecord`: add `next_epoch: Epoch` at offset 120, and fix the 120-byte encoding and
   the signing context of §5.1–5.2.
3. §4: state that `state_root` in `HandoffRecord` is the lattice hash of the full state in both
   modes, and that `log_hash` is BLAKE3 of the `BlockHeader` at `last_height`.
4. §6.6: every order-stream frame header carries `epoch: Epoch` (`INV-FENCE` needs it per frame).
5. §6.4 `Ack`: `index = 0xFE` marks a re-ack of a carried order with a new handle after a lane
   move.
6. §3: add `PubKey` = `[u8; 32]` (Ed25519), `Ed25519Sig` = `[u8; 64]` and `HomeCode` = u8.
   *`PubKey` and `Ed25519Sig` resolved by 01 §3 and §14.20 (with `Sig` and `SigScheme`).*
   Remaining: `HomeCode`.
7. Promote `EpoConfig` (with `seq_order: [u8; 2]`) to §6.6 (10's Requests to 01, item 5, asks for
   the same record), and `EPO_WAN_OW_MS`, `EPO_HIST_HALF` and `EPO_WINDOW_SLACK_MS` to §5, since
   02, 03 and 11 use them.
8. §6.4 `Ack`: bytes 2–3 = flags; bit 0 = queued (`EPO_ACK_QUEUED`), with `handle` = `wref` for a
   window `New` or `Replace` (§7.11).
9. §6.3: response `flags` bit 1 = window stream; `resp_seq` then counts window answers (§7.11).
10. §6.2: byte 1 bit 0 of `Cancel`, `Reduce` and `Replace` = the handle field holds a `wref`; of
    `ResendReq` = the range is in the window stream.
11. §6.6: add `WinBlock` (§7.1), and state in §14.0 that `FINALITY_MAX_MS` holds for window
    orders through it.
12. §14.5 and §14.15 item 3: with two order-stream cores, name the one that writes `StepRecord`s
    (the `Seal` and `Uncross` records included, §4.2, §7.8), or state that each writes the
    step's record for its half. §14.5 still names a single core 4.
13. §14.15: state that a pool core steals nothing and logs no `AcctTake` from T until its lane
    is live (§7.1), so the window path is the same for both lane classes.
14. §5: *Resolved by 01:* `N_LANES_REF` = 49, which this chapter's lane sums use.

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Does Apply reach 3 ns per message at 2.2M messages per lane? If not, more of Apply moves into Collect (parse, band and TIF checks there, reservations pre-summed per account) until it does. The §6.2 bound is not relaxed. | 05 | a B14 variant: apply 6M collected messages per lane on `REF` |
| 2 | Can 250 Gbps per WAN path per follower home be leased on all three pairs, and what does it cost? | 03 | a 7-day follower-lag measurement on the leased paths (B13 staging) |
| 3 | Does the low-priority drain keep `LAT_MAX_NS` for continuous traffic in the first 150 ms after U at peak? | 04 | B9 run during B13 at 100% window load |
| 4 | Day orders expire at the date roll (§7.2). Should v1 add a GTC TIF so that the book carries across the TYO open? | 10 | `vyrn-sim` replay of recorded flow: book depth at the TYO open under both rules |
| 5 | Price-time allocation rewards a race to arrive at the new home just after T. Is pro-rata at the marginal tick fairer? | 10 | `vyrn-sim` with the client-distance model: fill share by distance under both rules |
| 6 | Is `EPO_HIST_HALF` = 4,096 wide enough? A narrower band speeds the sum. | 05 | replay of historical boundaries: share of window orders rejected `BAD_TICK` |
| 7 | Does the undo log keep S′ ≠ S within `EPO_RESPEC_MS` (15 ms) at peak, and what does it cost the follower replay? | 07 | EPO-T2 window distribution on `REF`, follower replay rate with and without the undo log |
| 8 | Do lanes keep the 945 ns window ack at peak while they replay the tail at 60% load in 40 ns slices? | 05 | B1 variant during B13 at 100% window load, maximum over 10^9 packets |
| 9 | Do `R_{e+1}` voters finalize window blocks within `FINALITY_MAX_MS` while they replay the tail? | 07 | B13 at 100% window load: window-block finality distribution |
| 10 | With no stealing in the window, does a pool core whose queue holds a burst still meet the window ack, and does the first steal after live replay correctly from the parked tokens? | 05 | EPO-T14 with skewed pool queues; 11's pooled-lane determinism replay across a boundary |
