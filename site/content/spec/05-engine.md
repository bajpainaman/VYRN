# 05. Matching engine: lanes, cut, BBO core

Draft 0.2, 2026-11-13. Source: `DESIGN.md` §3 and §4, revised to `01-conventions.md` §14
(binding). Normative names, types, constants, layouts and invariants come from `01`. New names in
this chapter start with `ENG_` and are listed in §16.

`LAT_MAX_NS` is a **maximum** for every accepted packet, every message type and every message
index 0–9 (01 §14.0). This chapter has no percentile budget on any latency path. Where a path
cannot be bounded, the design sheds the work before it is accepted (§6.8), or it splits the work
into bounded steps (§8.5, §8.6, §8.8).

This chapter specifies one book on one sequencer box. It defines:

1. The **sequential specification**: the reference semantics that `vyrn-vx-oracle` implements (§2).
2. The **linearization**: the total order of all ops that the parallel engine produces (§3).
3. The **data structures**, with byte layouts and the writer core of every cache line (§4–§5).
4. The **algorithms** of the lane, the cut core and the BBO core, with budgets (§6–§8).
5. The **proof** that the parallel engine equals the sequential specification (§9).
6. **Replay**, **performance**, **fairness**, **book parameters** and **failures** (§10–§14).

## 0. Decisions in one page

| # | Decision | Reason |
|---|---|---|
| D1 | The sequential specification is "apply every op in the linear order L; every `New` matches on entry". Steps of kind `Rescan`, `Depletion` and `Idle` are no-ops in it. | One simple rule that a 150-line oracle can implement. Everything else is an optimization that must not change the result. |
| D2 | L orders lane ops by the first step whose cut includes them, then by priority key `(prio_ts, rank_e(lane), lane_seq)`. A forwarded op and its in-packet dependencies are ordered at the op's own step (explicit positions). | The cut and the step sources are logged, so L is a function of the order stream. |
| D3 | A step's cut is the two newest half-cuts, clamped below each lane's oldest unexecuted dependency range, and for the source lane also clamped at `q`. It never exceeds what the lanes published. | A forwarded op and its dependencies never enter L before their step, and no step sees an op that its lane has not written. |
| D4 | Every order gets an immutable queue position `(segment, pos)` in its lane FIFO in pass 1, in key order (01 §14.13). Visibility to the BBO core is decided by `ins_seq ≤ cut[lane]`, or by the BBO core's own mark for explicit positions. | The BBO core never writes an order record (`INV-WRITER`). Positions never move. |
| D5 | Slots are copy-on-write. `Reduce` writes a new version slot at the same position; `Replace` that loses priority is a cancel plus a new position. Every lane-written field that the BBO core reads is written once, or is a mask bit whose change is stamped with a `LaneSeq`. | No field changes under a BBO step that uses an older cut. |
| D6 | The BBO core keeps bounds `B ≥ true best bid` and `A ≤ true best ask`. Published snapshots are these bounds. | Cancels only widen the true spread, so the bounds stay valid without the BBO core seeing cancels. This is the "safe direction". |
| D7 | The crossing lemma gives a price band `[lo, hi]` per step from the snapshot versions that the batch's lanes may have used. An empty band proves that the batch cannot cross. A non-empty band triggers a `Rescan` step that processes the band's batch entries in key order. | The slow path is exact and bounded by the band. |
| D8 | IOC and FOK orders are always forwarded. Post-only orders are forwarded when they cross the snapshot. | Their outcome needs a decision that only the BBO core can make. A lane's snapshot is only a routing hint (`INV-ENG-1`). |
| D9 | A lane settles a local op `t` (sends its `Ack` or `CancelAck`, releases reservations) at the first boundary with `t ≤ C_f[lane]`, where `f` is the boundary's `fills_applied`. A boundary can sit between packets or inside one (§6.2). | `f` and the boundary's position are in the `PacketRecord`, and `C_f` is in the `StepRecord`, so settlement is replayable. |
| D10 | Responses for forwarded ops, their dependencies and every maker fill go out from the fill TX cores (A, B, C; 01 §14.17.3) in the step's own packets (01 §14.14). The lane reserves `resp_seq`s ahead. All other responses go out from the lane. | Takers and makers meet `LAT_MAX_NS`. `resp_seq` keeps one writer per number. |
| D11 | Backpressure stalls a core. Lateness is answered by deadline admission: `Reject BUSY` at the lane, or a `Shed` step at the BBO core. Both are logged. | A timing decision is replayable only if it is in the order stream (01 §14.1). |
| D12 | A lane that stalls past `ENG_LANE_DEAD_NS` fail-stops the sequencer. Spare cores (57, 59–63) take lanes only through a cooperative handover. | A wedged writer cannot be fenced inside one coherence domain without killing the process. |
| D13 | The lane processes a packet in two passes. Pass 1 validates, reserves, classifies and pushes each forwarded op at once with its in-packet dependency list. Pass 2 applies the independent joins and cancels (01 §14.2). | A cross at index 9 waits for 9 × 5 ns, not 9 × 14 ns. |
| D14 | Every BBO step is ≤ `ENG_STEP_MAX_NS` = 15 ns: a sweep stops after one level or `ENG_STEP_FILLS` = 8 fills (≤ `STEP_FILL_CAP` = 64) and continues in the next step; a `Rescan` takes a partial cut with warm lines; an uncross runs in chunks under a freeze. | A long step would delay every lane's acks past `LAT_MAX_NS` (§7.7). |
| D15 | Lanes are **dedicated** (one firm per core, lanes 0–41) or **pooled** (a 7-core pool on CCD 7, lanes 42–48) (01 §14.15). Pooled cores share account state under per-account tokens and steal packets; each is still a lane of the cut (§6.9). | A shared single-server lane sheds ~23% at 1B/s; a paced dedicated lane never queues, and a 7-server pool queues far less. |

## 1. Overview

### 1.1 Cores and data flow

```
             CCD 1..7 (lanes 0..48)                                CCD 0
 ┌───────────────────────────────────────────┐        ┌───────────────────────────────────────┐
 │ lane l: dedicated (cores 8–49, lanes 0–41)│        │ core 1: cut core A (lanes 0–24)       │
 │  or pooled (cores 56–62, lanes 42–48)     │        │ core 6: cut core B (lanes 25–48)      │
 │  RX ─► age check ─► MAC, prefetch         │ counter│                                       │
 │  pass 1: parse, risk/resv, classify,      │ line ──┼─► each publishes its half-cut + masks │
 │   positions, PacketRecord ─► OsRing[l]    │        │                                       │
 │   improve/cross/IOC/FOK + deps: FwdRing ──┼────────┼─► core 2: BBO core                    │
 │  pass 2: apply independent joins/cancels, │        │   deadline test, step cut, matches,   │
 │   publish counter after each op           │        │   publishes snapshot                  │
 │  boundary: FillEvents ◄── FillRing[l] ◄───┼────────┼── StepLog ─┬─► cores 3/5: fill TX A/B │
 │   settle at C_f[l], responses ─► TX VI    │snapshot│            │   (taker, deps, makers)  │
 │  reads LaneCut[l] ◄───────────────────────┼─line◄──┼────────────┴─► cores 4/7: stream A/B  │
 │                                           │        │   frames first, then LaneCut[l]       │
 └───────────────────────────────────────────┘        └───────────────────────────────────────┘
```

Every arrow is a single-writer structure. Table 4.1 lists each one with its writer.

### 1.2 Message classes

| Class | Who decides the outcome | Path |
|---|---|---|
| Join (passive, at or behind the lane's snapshot on its side) | sequential semantics; in practice nothing happens at entry | lane only |
| Cancel, Reduce, CancelAll | the cut position of the op | lane only |
| Improve (strictly inside the snapshot spread) | BBO core | FwdRing |
| Cross (at or through the opposite side of the snapshot) | BBO core | FwdRing |
| IOC, FOK (any price) | BBO core | FwdRing |
| Replace to a new tick, or to a larger qty | classified on its new tick and qty | lane or FwdRing |
| Dependency of a forwarded op (an earlier join or cancel of the same packet, §6.6) | BBO core, at the forwarded op's step | FwdRing (with the op) |
| Heartbeat, ResendReq | `04-protocol.md` | lane only, no `LaneSeq` |
| Late packet (§6.8) | the lane: `Reject BUSY`, nothing applied | lane only, no `LaneSeq` |

### 1.3 Two clocks

The engine has two orders of events. Both are functions of the order stream.

- **Book order** L (§3). It orders every op that changes the book. Matching follows it.
- **Lane order.** Each lane applies its ops in `LaneSeq` order and applies fill events at packet
  boundaries given by `PacketRecord.fills_applied`. Ledger checks (risk, reservations) follow it.

A fill changes the book at its step in L. It changes the ledgers of its two accounts at the
next packet boundary of each account's lane whose `fills_applied` reaches that step. Between those
two points the fill is "in flight" and the reservation covers it (§2.6).

## 2. The sequential specification

This section is the reference semantics. `vyrn-vx-oracle` implements it with linear scans. The
parallel engine must produce the same responses and the same state hash (§9, B4).

### 2.1 State

```rust
struct Book {
    phase:  Phase,                    // Continuous | Auction | Halted
    band:   Band,                     // { lo: Tick, hi: Tick }, inclusive (§13.2)
    orders: Vec<Order>,               // all resting orders, any order is fine for the oracle
    accts:  Map<AccountId, Ledger>,   // ordered map (01 §11.2)
    step:   StepId,                   // id of the step being applied
}
struct Order {
    handle: Handle, lane: LaneId, account: AccountId, session: SessionId,
    side: Side, tick: Tick, tif: Tif, post_only: bool, stp: Stp,
    key: PrioKey,                     // (prio_ts, rank_e(lane), lane_seq), §3.2
    total: Qty,                       // filled + open; Reduce lowers it, Replace sets it
    filled: Qty,                      // cumulative over every version of the order
    client_tag: u32,
}
struct Ledger {
    base_free: u64, base_resv: u64,   // base atomic units
    quote_free: u64, quote_resv: u64, // quote atomic units
    open_orders: u32,                 // orders with open > 0 or a pending settle
    fee: FeeTier,                     // { maker_ppm, taker_ppm, auction_ppm: i32 }, 10 §5
}
enum Phase { Continuous, Auction, Frozen, Halted }   // Frozen: auction close, §8.8
```

`open(o) = o.total − o.filled`. An order with `open(o) = 0` is not in `orders`.

### 2.2 Inputs

The oracle consumes the order stream and the data (01 §6.6). From them it builds:

1. For each lane `l`, the ordered list of lane ops `(l, q)` for `q = 1, 2, …`. Op `(l, q)` is
   message `q − first_lane_seq` of the `PacketRecord` with `first_lane_seq ≤ q <
   first_lane_seq + count`. Heartbeats and resend requests do not take a `LaneSeq` (§3.1).
2. For each op its priority key `key(l, q) = (prio_ts, rank_e(l), q)` (§3.2, §12).
3. The list of steps `s = 1, 2, …` with their cuts `C_s` and sources.
4. The linear order L (§3.3).

### 2.3 Ops

Each op is one of these. "Reject" means: no state change except the response.

**`New(o)`** at its position in L, with the ledger as of its lane order (§1.3):

```rust
fn op_new(bk: &mut Book, o: Order, led: &mut Ledger) -> Result<(), Reject> {
    check_wire(o)?;                              // 04: type, flags, reserved bits
    match bk.phase { Halted => return Err(BOOK_HALTED), Frozen => return Err(AUCTION_PHASE), _ => {} }
    if o.tif == AuctionOnly && bk.phase != Auction { return Err(AUCTION_PHASE) }
    if matches!(o.tif, Ioc | Fok) && bk.phase != Continuous { return Err(AUCTION_PHASE) }
    if o.post_only && bk.phase != Continuous { return Err(AUCTION_PHASE) }   // 04 §6.9
    if o.tick < bk.band.lo || o.tick > bk.band.hi { return Err(BAD_TICK) }
    if o.qty < ENG_MIN_QTY || o.qty > ENG_MAX_ORDER_QTY { return Err(BAD_QTY) }
    if led.open_orders >= ENG_MAX_OPEN_PER_ACCT { return Err(RISK_ORDER_COUNT) }
    reserve(led, o.side, o.tick, o.qty)?;        // RISK_CREDIT, §2.6
    led.open_orders += 1;
    match bk.phase {
        Continuous => match_on_entry(bk, o),     // §2.4
        Auction | Halted => rest(bk, o),         // no matching outside Continuous
    }
}
```

The lane-side checks (wire, band, qty, count, reservation) use the lane-order view of the
ledger, the band and the phase (§1.3, §13.2). The book-side part (`match_on_entry` or `rest`)
uses the book at the op's position in L. If the phase seen by the BBO core at the op's step
differs from the phase the lane saw, the BBO core applies §2.5 rule P1.

**`Cancel(h)`**: if `h` names no order of the session's account, reject `UNKNOWN_HANDLE`. If the
order has `open = 0` at the op's position in L, reject `TOO_LATE`. Otherwise remove it, release its
reservation remainder, and answer `CancelAck { canceled: open }`.

**`Reduce(h, r)`**: as `Cancel` for the checks. If `r ≥ open`, remove the order and answer
`CancelAck { canceled: open }`. Otherwise set `total −= r`, keep `key`, release `r` lots of
reservation, and answer `CancelAck { canceled: r }`.

**`Replace(h, tick', qty')`**: reject `SIDE_MISMATCH` if the side bit differs. If `tick' = tick`
and `qty' < total`, it is a `Reduce(h, total − qty')` (01 §6.2). Otherwise: if `open = 0`, reject
`TOO_LATE`. Otherwise remove the old order and enter a new order with the same `Handle`,
`tick'`, `total = qty'`, `filled` carried over, a new key (the replace op's key) and a new queue
position. If `qty' ≤ filled`, the order is finished and the answer is `CancelAck { canceled:
open }` (01 §14.10 has no `Out` cause for it). The new order then runs `match_on_entry` with
`open = qty' − filled`. The reservation is adjusted by §2.6.

**`CancelAll`**: cancel every resting order of the session in the packet's book (04 §6.6), in
ascending handle order, each with its own `CancelAck { handle, canceled: open }`. Then answer the
summary `CancelAck { handle: PROTO_HANDLE_ALL, canceled: n }`, where `n` is the number of orders
canceled. The summary is sent also when `n = 0`. Vector V15 (04 §11) shows the bytes.

**Step `s` of kind `Cross` or `Improve`**: apply the source op's dependencies (§3.7) in index
order, then `New` or `Replace` for the source op. The step kind is `Cross` if the op produced a
fill, else `Improve` (§8.1). A `Cross` step whose sweep reached the per-step cap (§8.5) leaves the
taker **in flight**: not resting, not visible as a maker, reservation held. The next step is then
a continuation (`Cross` with the same source) and resumes `match_on_entry` on the book at its own
point of L. No other source runs between them.

**Step of kind `Shed`**: the source op and its dependencies are answered `Reject BUSY` and
release their reservations. Nothing else changes (01 §14.1).

**Step of kind `Rescan`, `Depletion`, `Idle`**: no-op.

**Step of kind `Control`**: change `phase` (including `Frozen`, §8.8) or `band`. **`Uncross`**:
one chunk of the auction allocation (§8.8). **`Seal`**: the last step of the epoch; nothing
after it is in the epoch's L (08). Halts and phase changes are defined by `08-epochs.md` and
`10-accounts-risk-md.md`.

### 2.4 Matching on entry

```rust
fn match_on_entry(bk: &mut Book, mut t: Order) {
    if t.post_only && crosses(bk, &t) { kill(t, Reject(POST_ONLY_WOULD_CROSS)); return }
    if t.tif == Fok && fillable(bk, &t) < open(&t) { kill(t, Reject(FOK_UNFILLABLE)); return }
    let mut ordinal = 0u32;
    while open(&t) > 0 {
        let Some(m) = best_maker(bk, &t) else { break };    // best price, then smallest key
        if m.account == t.account && t.stp != Stp::None {
            match t.stp {
                CancelNewest => { kill(t, stp_end(&t, m)); return }
                CancelOldest => { remove(bk, m, Out(STP)); continue }
                CancelBoth   => { remove(bk, m, Out(STP)); kill(t, stp_end(&t, m)); return }
            }
        }
        let q = min(open(&t), open(&m));
        fill(bk, &mut t, m, q, m.tick, bk.step, &mut ordinal);  // price = maker's tick
    }
    match t.tif {
        Ioc | Fok if open(&t) > 0 => kill(t, Out(IOC_REST)),
        _ if open(&t) > 0          => rest(bk, t),               // Ack { handle, tick }
        _                          => {}                         // fully filled
    }
}
```

- `best_maker` returns the resting order on the opposite side with the best price that the taker
  can trade with (`tick ≤ t.tick` for a buy, `≥` for a sell), and among those the smallest `key`.
- `crosses(bk, t)` is true when `best_maker` returns `Some`.
- `fillable(bk, t)` walks the same sequence as the loop without changing anything. It counts each
  maker's open qty, skips makers that `CancelOldest` would remove, and stops at the first maker
  that `CancelNewest` or `CancelBoth` would hit. `Stp::None` counts own makers.
- The taker's STP mode governs. The maker's STP mode is not used.
- `stp_end(t, m)` is the taker's end on an STP stop (04 §6.8): `Reject(STP)` with detail =
  `m.handle` when the taker has no fill yet, else `Out(STP)` with qty out = the remaining open
  qty. A `Reject STP` means the order had no effect on the book (04 §7.3).
- `fill` adds `q` to both orders' `filled`, records a fill `(StepId = bk.step, ordinal)`, and
  queues one settlement event per side (§2.6). It removes a maker whose `open` reaches 0.
- A taker gets one `Fill` record per price level and a maker gets one per fill (01 §6.4). The
  taker's `Fill` records for one level are merged: `qty` is the sum over that level.

### 2.5 Phases and the positions of lane decisions

The lane decides admission with its lane-order view of `phase` and `band`. The BBO core decides
matching with the phase at the step. They can differ for an op whose lane had not yet applied a
phase change. The rules are:

- **P1.** The book side uses the phase at the op's position in L. A `New` positioned in `Halted`
  is rejected `BOOK_HALTED` and its reservation is released. A `New` positioned in `Auction` rests
  without matching; an IOC or FOK positioned there gets `Out { cause: AUCTION }`.
- **P2.** An auction-only order is never visible to a step of kind `Cross`, `Improve` or `Rescan`.
  It is visible only to the uncross. After the uncross that follows its entry, its open quantity
  is dead and its lane sends `Out { cause: AUCTION }` (§8.8).
- **P3.** Band checks use the band as of the lane order. A `Replace` or `New` that passed the lane
  band check is matched at any price inside its own limit. The band only limits limits.
- **P4.** In `Frozen` every book op (`New`, `Cancel`, `Reduce`, `Replace`, `CancelAll`) is
  rejected `AUCTION_PHASE` in lane order. A book op that a lane admitted before it applied the
  `Frozen` event, and whose position is after the freeze step, is rejected `AUCTION_PHASE` at its
  settle. The lane tombstones those ops with `tomb_seq = ins_seq` (never visible) before it
  reports its histogram (§8.8). So the book is constant from the freeze cut to the last `Uncross`
  step.

### 2.6 Ledger: reservation, settlement, release

v1 is fully collateralized spot (01 §12.1). All amounts are integers. All arithmetic is checked
(01 §11.4). Overflow is reject `RISK_CREDIT` at entry and is impossible afterwards, because every
later amount is bounded by the reservation.

```rust
// quote atomic units per lot at a tick; book parameter (§13.1)
fn px(t: Tick) -> u64 { t as u64 * QUOTE_PER_TICK_LOT }            // checked
// reservation per lot for a buy at limit t: price plus the maximum fee, rounded up per lot
fn rpl(t: Tick) -> u64 { px(t) + ceil_div(px(t) * ENG_MAX_FEE_PPM as u64, RSK_FEE_DENOM) }
// fee on notional n at rate ppm (10 §5): a charge (ppm ≥ 0) rounds up, a rebate (ppm < 0) down
fn fee(n: u64, ppm: i32) -> i64 {
    if ppm >= 0 { ceil_div(n * ppm as u64, RSK_FEE_DENOM) as i64 }
    else { -((n * ppm.unsigned_abs() as u64 / RSK_FEE_DENOM) as i64) }
}
```

`RSK_FEE_DENOM` = 10^6 (10 §5): rates are parts per million of notional, so 1 bps = 100 ppm.

| Event | Buy order (limit `t`) | Sell order |
|---|---|---|
| Entry | `quote_free −= qty × rpl(t)`; `quote_resv += same`. Reject `RISK_CREDIT` if short. | `base_free −= qty`; `base_resv += qty`. |
| Fill of `q` at tick `f`, `n = q × px(f)` | `quote_resv −= q × rpl(t)`; `quote_free += q × rpl(t) − n`; `base_free += q`; then the fee. | `base_resv −= q`; `quote_free += n`; then the fee. |
| Fee of a maker or auction fill | `quote_free −= fee(n, ppm)` (a rebate adds); `fee_acc[lane] += fee(n, ppm)`. | same |
| Fee of a taker, once per (taker order, step), at the step's `TakerEnd` | `quote_free −= fee(N, taker_ppm)`, where `N` is the sum of `n` over the order's fills in the step; `fee_acc[lane] += same`. | same |
| Order ends with `open = o` | `quote_resv −= o × rpl(t)`; `quote_free += same`. | `base_resv −= o`; `base_free += o`. |

- `ppm` is the maker or auction rate of the account's tier, `taker_ppm` its taker rate. Every
  `|ppm|` is at most `ENG_MAX_FEE_PPM`.
- The taker fee is rounded once per step on the step's total, as 10 §3.3 and §4.4 fix
  (`Settle::taker_end`, `crates/engine/vyrn-risk/src/settle.rs`). Rounding each fill instead
  would charge up to (fills − 1) units more.
- `n + fee ≤ q × rpl(t)` for every fill, summed over the step for the taker: `f ≤ t`,
  `ppm ≤ ENG_MAX_FEE_PPM`, and `ceil(Σx) ≤ Σ ceil(x)`. So a fill never needs more than the lots
  it consumes from the reservation (the release lemma, 10 §3.2).
- Fees are credited to the lane's fee accumulator `fee_acc[lane]` (10 sums them).
- **Replace** of a buy: the lane reserves `max(0, need − resv(o))` at once, where `need = (qty' −
  F) × rpl(tick')` and `F` is the filled qty the lane knows. It never releases at the replace.
  At the settle of the replace op (§7.6), the exact `open` is known and the lane releases
  `resv(o) − open × rpl(tick')`. A fill of the old version that arrives after the replace
  consumes `q × rpl(old tick)`; the "reserve now, release at settle" rule keeps the reservation
  sufficient for both versions.
- **Reduce** releases at its settle. **Cancel** releases at its settle.
- **Rule L1:** a reservation increases only at entry; it decreases only at a fill event or at a
  settle. Both happen at points fixed by the order stream (Lemma 9.12).

### 2.7 Responses

| Op | Responses, in this order |
|---|---|
| `New` resting | `Fill` per level traded (if any), then `Ack { handle, tick }` |
| `New` fully filled | `Fill` per level |
| `New` IOC/STP end | `Fill` per level (if any), then `Out { cause, qty out }` |
| `New` FOK unfillable | `Reject { FOK_UNFILLABLE }` (01 §14.10) |
| `New` rejected | `Reject { reason }` |
| packet late at the lane, or op shed at the BBO core | `Reject { BUSY }` for every affected message |
| `Cancel`, `Reduce`, `CancelAll` | `CancelAck` per order, or `Reject` |
| maker fill | `Fill { index: 0xFF, liq: 0 }` (`liq: 2` in an uncross), unsolicited, `echo_pkt = 0` |
| maker STP removal | `Out { index: 0xFF, cause: STP }`, unsolicited |

Packetization and `resp_seq` are part of the specification, because 01 §7 `INV-DET` covers every
response byte. The rules are in §8.10.

### 2.8 What the oracle exports

```rust
pub fn oracle_new(stream: &OrderStream, data: &DataStore) -> Oracle;
pub fn oracle_step(o: &mut Oracle) -> Option<Vec<ResponsePacket>>;   // one element of L
pub fn oracle_state_hash(o: &Oracle) -> Hash;                        // BLAKE3 of canonical state
```

The canonical state is: every resting order sorted by `(side, tick, key)`, every ledger sorted by
`AccountId`, `phase`, `band`, the last `StepId`, the per-session `resp_seq`. `11-build.md` defines
the byte encoding. `vyrn-sim` diffs `oracle_state_hash` against the engine after every element of L.

## 3. The linearization

### 3.1 Lane ops and `LaneSeq`

- A lane gives one `LaneSeq` to every message that is `New`, `Cancel`, `Reduce`, `Replace` or
  `CancelAll`, including a message that it rejects. Numbers are gapless per lane and start at 1
  each epoch (01 §3).
- `Heartbeat` and `ResendReq` take no `LaneSeq`. They change only session state that `04` owns,
  and they never touch the book.
- The lane assigns `LaneSeq`s in pass 1, in message index order, before it applies anything.
- A packet that fails the MAC or sequence checks of `04` takes no `LaneSeq` and produces no
  `PacketRecord`. It never enters the order stream.
- A packet that deadline admission rejects (§6.8) keeps its `LaneSeq`s (one per counted
  message, as an accepted packet), does not advance the session's `pkt_seq`, and produces a
  `PacketRecord` with `flags.SHED` and its real `pkt_hash`: 07 §3.5 hashes and joins it, so
  `data_root` covers it. The record is needed because the `BUSY` response consumes a
  `resp_seq`, which `LaneCut` gates on those `LaneSeq`s. A resend of the same `pkt_seq` takes
  new `LaneSeq`s.
- `PacketRecord.count` is the number of the packet's messages that take a `LaneSeq`, not the
  header's message count: without a packet-level reject, a `Heartbeat` or `ResendReq` takes none.
  Under a packet-level reject (header, book, packet bucket) or a shed, every message is answered
  and takes one. 07 §3.6's `count` field and `next_lane_seq` follow this count.
- `PacketRecord.first_lane_seq` is the `LaneSeq` of the packet's first message with a number.
  If no message of the packet takes a number, the record carries `count = 0` and
  `first_lane_seq` = the next unused number (`04` decides whether such packets are recorded).

An op is **local** if the lane completes its book part itself (join, cancel, reduce, cancel-all,
a replace whose new version is a join, every reject). An op is **forwarded** if the lane pushes it
to its FwdRing. An op is a **dependency** of forwarded op `(l, q)` if the lane lists it in
`q`'s FwdEntry (§6.6). The BBO core executes a forwarded op, with its dependencies, as the source
of one step, or of one step and its continuations (§8.5).

### 3.2 Priority key

```rust
struct PrioKey { ts: Nanos, rank: u8, seq: LaneSeq }   // compared lexicographically
fn rank_e(e: Epoch, l: LaneId) -> u8 { ((l as u32 + e) % N_LANES as u32) as u8 }
```

- `ts` of a `New` is the packet's `prio_ts` (§6.3): the NIC RX timestamp, raised to the lane's
  previous `prio_ts` if it is smaller. So `prio_ts` is non-decreasing in `LaneSeq` within a lane.
- The key of an op is unique: `(rank, seq)` is unique per op inside an epoch.
- A `Reduce` version keeps the key of the order it reduces. A `Replace` to a new price or a
  larger quantity takes the key of the replace op.
- Within one lane, key order equals `LaneSeq` order. Lemma 9.1 uses this.

### 3.3 Step cuts

Let `K` be the newest cut, read at the start of step `s`: lanes 0–24 from cut core A's newest
half-cut, lanes 25–48 from cut core B's (§7.1). The two halves may come from passes taken at
different times; each half is monotone on its own (`INV-CUT-MONO` per half, 01 §14.3), and
nothing below needs the halves to be simultaneous. Let `h[l]` be the **dependency floor** of
lane `l`'s oldest FwdRing entry that no step has executed yet: its `lane_seq` minus its largest
dependency offset (§6.6), read after `K`, or `∞` if the ring is empty. For a step whose source is
the forwarded op `(src, q)`:

```
C_s[l]   = max(C_{s−1}[l], min(K[l], h[l] − 1))                 for l ≠ src
C_s[src] = max(C_{s−1}[src], min(max(K[src], a), h'[src] − 1, q))
           a  = q − FwdEntry.applied_back: the lane's `applied` when it pushed q
           h' = floor of src's next unexecuted entry
```

`a` lets pass barriers (§6.6), published before the push, enter the source step's batch before
the cut core has read them.

A `Shed` step and a continuation use the source rule. For a step without a source (`Rescan`,
`Depletion`, `Idle`, `Control`, `Uncross`, `Seal`), every lane uses the first line.
`C_0 = [0; N_LANES]`. The BBO core may also
choose any `C_s[l]` between `C_{s−1}[l]` and the value above (a **partial cut**, §8.6); the cut is
logged, so replay does not repeat the choice.

The source op and its dependencies are **explicit**: their position in L is step `s` by
definition, whatever the cut. Pass 2 never applies them; the BBO core decides them and the lane
writes their effects after the step (§6.6, §7.4). `CounterLine.seq` counts them as done, so the
clamp `h − 1` is what keeps them out of earlier cuts.

Three facts follow from the construction. §9 proves them.

- **F1 (monotone).** `C_s ≥ C_{s−1}` pointwise. That is `INV-CUT-MONO`.
- **F2 (explicit ops at their step).** If `(l, x)` is the source or a dependency of step `s`, then
  `C_{s'}[l] < x` for every `s' < s`.
- **F3 (published).** Every op inside `C_s[l]` that is not explicit was applied and published by
  its lane before the step started: `C_s[l] ≤ K[l]`, or `≤ a` for the source, or `≤ C_{s−1}[l]`.
  A lane with `C_s[l] > K[l]` (a **lag lane**, only ever a recent source lane) has published ops
  that the masks may not show yet; the BBO core probes it like a wild lane (Lemma 7.1).

Draft 0.1 raised `C_s[src]` to `q`; with early dispatch that would put ops that pass 2 has not
applied into every later cut. The clamp at `a` and `q` plus explicit positions removes the case.

### 3.4 The position of an op and the linear order L

```
pos(l, x) = s                    if (l, x) is the source or a dependency of step s
          = min { s : C_s[l] ≥ x }  otherwise
B_s       = { (l, x) : pos(l, x) = s, not explicit }     // the batch of step s
L         = B_1 · S_1 · B_2 · S_2 · …      // S_s: the step's dependencies, then its own action
```

While the specification applies `B_s` and `S_s`, `bk.step = s`. So a fill made by a crossing op
inside `B_s` has `StepId s`; the engine makes that fill in its `Rescan` step `s` (§8.6).

Inside `B_s` the ops are sorted by key. If step `s` has a source `(src, q)`, `S_s` applies, in
index order, the lane part and book part of each dependency, then the lane part (the checks and
the reservation) and the book part (`match_on_entry`) of `q`. The lane parts were computed in
pass 1 in lane order; §3.7 shows that this is the same as computing them at `S_s`.

Why sort by key and not by lane: two ops of different lanes in one batch commute unless one of
them crosses (Lemma 9.5). Only a `Rescan` step contains crossing ops, and there the key order
decides who is maker and who is taker. Key order is also lane order within each lane, so L
respects every lane's program order.

### 3.5 Example

```
lane 3 ops:   (3,41) join bid 100   (3,42) cancel (3,17)   (3,43) cross buy 102
lane 7 ops:   (7,90) join ask 103   (7,91) join ask 102
cut core:     K = { 3: 42, 7: 91 }  published before step 12 starts
FwdRing[3]:   (3,43)  → h[3] = 43           FwdRing[7]: empty → h[7] = ∞

step 12 (src = (3,43), Cross, no dependencies):
  C_12[3] = max(C_11[3], min(42, ∞, 43)) = 42,  C_12[7] = max(C_11[7], min(91, ∞)) = 91
  B_12 sorted by key: (3,41) (7,90) (3,42) (7,91)                       (ts order assumed)
  S_12: (3,43) is explicit; the buy at 102 trades with (7,91) at 102 if (7,91) is the best ask
```

The step log records `C_12` and the source. A replica rebuilds `B_12` from the cut and the
`PacketRecord`s, and applies `S_12` from `StepRecord.src_lane` and `src_lane_seq`; the
dependencies are a function of the packet's bytes (§10).

### 3.6 The step's batch cannot hold another lane's explicit op

If `(l, x)` is forwarded or a dependency and `l ≠ src`, then `h[l] ≤ x` until its own step
executes it. So `C_s[l] ≤ h[l] − 1 < x`, and `(l, x)` is not in `B_s`. Each batch holds only
local, independent ops. This is what lets `S_s` treat `(l, x)`'s reserved position as empty
(§5.3) although the lane has already assigned it (D4).

### 3.7 Lemma: a packet's outcome is its index-order outcome

Let packet `P` of lane `l` hold book ops `p_0 … p_{k−1}` with `LaneSeq`s `x_0 < … < x_{k−1}`
(session-only messages and rejects have no book effect and are left out). The **sequential
outcome** of `P` is the result of applying `p_0, …, p_{k−1}` in this order to the book at the
point of L where `P`'s first op stands, each `New` matching on entry. For forwarded op `p_j` let
`D_j` be its dependency list and `I_j = { p_i : i < j, p_i ∉ D_j, p_i not explicit }`.

**Lemma 3.7.** The engine's book, ledgers, fills (with execution IDs) and response records for
the ops of `P` equal its sequential outcome, with every op of a shed `p_j` and its `D_j`
replaced by `Reject BUSY`.

*Proof sketch.* (1) **Lane parts.** Pass 1 runs every check and reservation in index order
against the lane-order ledger. A boundary inside `P` (§6.2) applies fill events at a logged
position, so the order of ledger events is the same in replay. (2) **Ops after `p_j`.** For
`i > j`, `x_i > x_j ≥ h[l]` until step `s_j`, so `pos(p_i) ≥ s_j` and `p_i` follows `S_{s_j}` in
L: program order. (3) **`I_j` may follow `S_{s_j}` in L although it precedes `p_j` in `P`.** By
§6.6 an op of `I_j` is on `p_j`'s own side or outside its price range (an earlier op on
`p_j`'s own handle is on its own side), and it is not a `CancelAll` or an opposite-side `Reduce`
in range (those are pass barriers, applied and published before the push, so they precede
`S_{s_j}` in L). `match_on_entry` of `p_j` reads only opposite-side orders inside its range (the
sweep, the FOK dry run, the post-only test and STP all stay inside it); `replace_ok` reads only
`pred_total`, which pass 1 set from the pending version. So `p_j` and an op of `I_j` touch
disjoint orders, and they commute as in Lemma 9.5; their reservations were taken in index order
in (1). (4) **`D_j` is applied at `S_{s_j}`, in index order, before `p_j`**, with
the conflict cases:

- *Cancel of the account's own opposite-side order `V` in range* (`p_i ∈ D_j`, a `Cancel`). The
  BBO core sets `killed` on `V`'s root before the sweep (§8.5), so `p_j` never meets `V`, which
  is what index order gives. The `CancelAck` carries `open(V)` at `S_{s_j}`: every fill of `V`
  is from a step `< s_j` (later steps see `killed`), as in Lemma 9.11.
- *Own join `W` in range* (`p_i ∈ D_j`, a `New` or new-priority `Replace` that rests). `W` has the
  key `(prio_ts(P), rank_e(l), x_i)`, larger than every older order of lane `l` at its level, and
  its position was assigned in pass 1 behind them. The BBO core inserts `W` as a leaf of lane `l`
  at that key (§5.4), so `p_j` meets `W` exactly where index order puts it among all lanes'
  makers.
- *STP.* Every op of `P` belongs to `p_j`'s account. When `p_j` meets `W` or an older own order,
  §2.4's branch for `p_j.stp` applies: `CancelNewest` kills `p_j`; `CancelOldest` sets `killed`
  on `W`; `CancelBoth` does both; `None` fills `W` as a maker. The BBO core writes only `filled`
  and `killed` (`INV-WRITER`). `W`'s records (`Ack`, then `Fill` or `Out { STP }`) go into the
  step's dependency packet in index order (§8.10), as index order gives.

(5) **Shed.** A `Shed` step applies neither `p_j` nor `D_j`, the lane never writes their
positions or tombstones, and their records are `Reject BUSY`. The ops of `I_j` are already
applied (01 §14.1). Applying `P` in index order with those messages rejected gives the same
result, because by (3) `I_j` never depended on them. (6) **Continuations** of `p_j` (§8.5) run
before any other source, and the batches between them hold only ops of other lanes or later
ops of `l`, which follow `p_j` in program order. ∎

**Corollary (the step-cut rule).** The clamp of §3.3 is exactly what (2) and (4) need: `h` keeps
`D_j` and every later op of `l` out of earlier batches, and `min(K, q)` keeps unapplied ops out of
every cut.

## 4. Shared structures: the writer map

Every structure below is preallocated in 1 GB huge pages before `seal()` (`INV-NOALLOC`). Every
line that two cores touch has one writer (`INV-WRITER`). Sizes and offsets below are the bytes
of each layout. **Padding (11 §3.6, 06 §5.5):** a line that one
core writes and another core reads (`CounterLine`, `SnapshotLine`, `BboFloor`, each `CutPub`
publication and its `newest` word, `LaneCut`, ring index lines, `FwdCons`, `FillCons`,
`FramesOut`, the `RxQueue` lock) is padded and aligned to `BLD_SHARED_ALIGN` = 128 bytes on
every target, so a 64 B layout takes one 128 B line and the bytes past it are padding. Bulk
arrays (`OrderSlot`, `Segment16`, ring entries) are aligned to `CACHE_LINE` (01 §5). `AcctTok`
entries are 16 B, four per line, changed only by CAS and release stores (§6.9).
Field offsets never change. `vyrn-cut` (`SHARED_ALIGN`, `crates/engine/vyrn-cut/src/lib.rs`)
asserts these sizes.

### 4.1 Table

| Structure | Per | Size | Writer | Readers | Lives in | Write rate (budget, at 1B msgs/s) |
|---|---|---|---|---|---|---|
| `OrderSlot` arena | lane | `ENG_SLOT_CAP` × 64 B | lane | BBO | lane's NUMA memory | 1 line per New/Reduce/Replace, 1 per tombstone |
| `Segment16` arena | lane | `ENG_SEG_CAP` × 192 B | lane | BBO | lane | 1 entry (3 stores) per position, 1 mask word per change |
| `SlotAux` arena | lane | `ENG_SLOT_CAP` × 16 B | lane | lane | lane | private |
| level heads (dense window ×2 dirs) | lane, side | 2 × 4096 × 4 B | lane | BBO, cut cores | lane | on empty↔non-empty and head segment reclaim |
| level tails (segment, next pos) | lane, side | 4096 × 8 B | lane | lane | lane | private |
| overflow pages | lane, side | `ENG_OVF_PAGES` × 16.5 KB | lane | BBO (slow path) | lane | far levels only |
| occupancy bitmap | lane, side | 512 B + 8 B summary | lane | cut cores, BBO (slow path) | lane | on empty↔non-empty |
| `AcctKill` | lane | accounts × 16 B | lane | BBO | lane | per `CancelAll` |
| journal | lane | `ENG_JOURNAL` × 16 B | lane | BBO (Rescan only) | lane | 1 entry per independent book op |
| `CounterLine` | lane | 64 B | lane | cut cores, control role | lane | 1 publish per op |
| `FwdRing` | lane | `ENG_FWD_RING` × 64 B | lane | BBO | lane | ~3% of messages, + dependency lines |
| `FwdCons` | lane | 64 B | BBO | lane | CCD 0 | per consumed entry |
| `FillRing` | lane | `ENG_FILL_RING` × 32 B | BBO | lane | CCD 0 | per fill event |
| `FillCons` | lane | 64 B | lane | BBO | lane | per drained batch |
| `OsRing` | lane | `ENG_OS_RING` × 64 B | lane | stream core of its half (4 or 7) | lane | 1 per packet, pre-encoded in pass 1 |
| `MakerSeq` | session | 16 B | lane | fill TX core of its client port (06 §2.3 rule 3) | lane | 1 per 8 TX-core packets of the session |
| `CutPub` ×4, half A / half B | box | 2 × 4 × 8 lines | cut core A / cut core B | BBO | CCD 0 | 1 per ~`CUT_REFRESH_NS` per half |
| occupancy masks, half A / half B | box, side | 2 × 4096 × 4 B | cut core A / cut core B | BBO | CCD 0 | on SET/CLEAR events |
| `BboFloor` | box | 64 B (two half floors) | BBO | cut cores | CCD 0 | 1 per step |
| `SnapshotLine` | box | 64 B | BBO | lanes, TX | CCD 0 | 1 per step |
| `BboSlotState` | lane | `ENG_SLOT_CAP` × 4 B | BBO | BBO | CCD 0 memory | per fill |
| `BboVer` | lane | `ENG_SLOT_CAP` × 1 B | BBO | BBO | CCD 0 memory | per Replace version, per explicit op |
| `Pend` | box | `ENG_PEND_CAP` × 32 B | BBO | BBO | CCD 0 | per explicit op that the lane has not yet written |
| head cache | box, side | 2 KB | BBO | BBO | CCD 0 | private |
| snapshot history | box | `ENG_SNAP_HIST` × 8 B | BBO | BBO | CCD 0 | 1 per version |
| `StepLog` | box | `ENG_STEP_LOG` × 64 B | BBO | stream cores, fill TX cores | CCD 0 | 1–8 lines per step |
| `TxRing` A, B | box | 2 × `ENG_TX_RING` × 64 B | BBO | fill TX core A (core 3) / B (core 5) | CCD 0 | 1+ per forwarded step, 1 per maker session hit |
| `LaneCut` | box | 13 lines with a 16-B atomic store (4 lanes per line; lines of half A and half B disjoint); 49 lines with the seqlock fallback (§4.15) | stream core of the lane's half | lanes | CCD 0 | ≤ 1 per lane per step, after the step's frame |
| `FramesOut` A, B | box | 2 × 64 B | stream core A / B | fill TX cores, other stream core | CCD 0 | per step sent |
| `AuctionCtl` | box | 64 B | BBO | lanes | CCD 0 | per uncross |
| `AuctionHist` | lane | 2 × `ENG_AUCTION_TICKS` × 8 B + 64 B | lane | BBO | lane | per uncross |
| `HandoverCtl` | lane | 64 B | control role (core 51) | lane | CCD 0 | per handover (§14.1) |
| control ring | box | 256 × 64 B | control role (core 51) | BBO | CCD 0 | per halt, phase or band command |

Lane memory is on the box's one NUMA node (`06-platform.md`); "lives in" names the cache that
holds the line in steady state.

### 4.2 Handle and slots

```
Handle (u32):  bits 0..23 = root slot (1 ..= ENG_SLOT_CAP − 1; 0 is null)
               bits 24..31 = generation of that root slot
```

- Slot 0 of every arena is the null slot. It is never allocated.
- A slot's generation increments each time the slot is allocated as a root. A version slot
  (§4.4) is never named by a `Handle`.
- A handle is valid when `slot < ENG_SLOT_CAP`, `aux[slot].state == Root`, the generation
  matches, and `aux[slot].session == session`. Anything else is `UNKNOWN_HANDLE`.

### 4.3 `OrderSlot` (64 B, lane-written, BBO-read)

```
off size field       type     meaning
  0   8  prio_ts     Nanos    merge key part 1 (§3.2)
  8   8  ins_seq     LaneSeq  op that created this version
 16   8  ins_ts      Nanos    KeepPrio: ts of the Reduce op. Other kinds: bytes 16–19 =
                              pred_total (NewPrio: total of the version it replaces), 20–23 = 0
 24   8  tomb_seq    LaneSeq  op that ended this version; 0 = live. Written once.
 32   8  tomb_ts     Nanos    ts of that op; written before tomb_seq
 40   4  next_ver    u32      the KeepPrio version that follows this one; 0 = none. Written once
 44   4  tick        Tick
 48   4  total       Qty      total of the order as of this version (filled + open)
 52   4  acct_ix     u32      lane-local account index (STP compares (lane, acct_ix))
 56   4  root        u32      root slot of the order; equals own index for kind = Original
 60   1  flags       u8       wire flags: side, TIF, post-only, STP (01 §6.2)
 61   1  gen         u8       generation of the root slot
 62   1  kind        u8       0 Original, 1 KeepPrio (Reduce), 2 NewPrio (Replace)
 63   1  tomb_lane   u8       lane whose LaneSeq tomb_seq is (≠ own lane only in a pool, §6.9)
```

For kinds other than `KeepPrio`, the op's ts is `prio_ts`, so `visible_at` (§5.2) uses `prio_ts`
as the insertion ts.

**Write-once rule (`INV-ENG-2`).** The lane writes offsets 0–39 and 44–63 before the slot's
position becomes active (§4.6). It writes `tomb_ts`, then `tomb_seq` with `Release`, at most
once, and `next_ver` at most once (before `tomb_seq` of the same op). No other write happens
while the slot is reachable.

### 4.4 Versions

`Reduce` and `Replace` never change a reachable slot's quantity or tick. They write a new slot.

```
Reduce(h, r) at op q, current version V:
    W = alloc();  W := V with { kind: KeepPrio, ins_seq: q, ins_ts: ts(q), total: V.total − r }
    V.next_ver = W                                     // W keeps V's queue position
    seg.vmask |= bit(pos)                               // the position now has a version chain
    V.tomb_ts = ts(q); V.tomb_seq = q                  // same seq: never both visible

Replace(h, tick', qty') at op q (new priority) = cancel of the old position + a new position:
    W = alloc();  W := { kind: NewPrio, prio_ts: ts(q), ins_seq: q, ins_ts: ts(q),
                         tick: tick', total: qty', root: V.root, gen: V.gen, … }
    W gets the next position at the tail of FIFO(side, tick')          (01 §14.13.2)
    V.tomb_ts = ts(q); V.tomb_seq = q; clear V's position bit (§4.6)
```

The BBO core computes `open = total − filled[root]` for every version, where `filled` lives in
`BboSlotState[root]` (§4.11). Fills of every version add to the same counter. This gives the
FIX semantics of §2.3 (`leaves = qty' − cum_filled`) with no read of lane state that can change.

### 4.5 `SlotAux` (16 B, lane-private)

```
off size field     meaning
  0   4  seg       Segment16 of the order's position (position slot only); free-FIFO link when free
  4   4  client_tag
  8   4  session   SessionId of the owner
 12   1  state     Free | Root | Version | Dead
 13   1  pend      number of unsettled ops that name this order
 14   1  pos       position 0–15 in seg
 15   1  rsv
```

The root's aux also needs the current version and the session list links. They live in a
parallel lane-private array `RootAux { cur: u32, sess_next: u32, sess_prev: u32, resv: u64 }`
(24 B, padded to 32 B), indexed by root slot.

### 4.6 Segment FIFOs and the level directory (01 §14.13)

A lane FIFO at one `(side, tick)` is a chain of `Segment16` blocks. It replaces draft 0.1's
intrusive list of slots: no pointer is chased inside a segment, and an order's queue position
never moves.

```
Segment16 (192 B = 3 lines, CACHE_LINE-aligned, lane-written, BBO-read)
line 0   0  64  slot[16]  u32   position slot (first version) of each position; 0 = unused
line 1  64  64  qty[16]   u32   total of the position slot (write-once with the slot)
line 2 128   4  mask      u32   bits 0–15 active, bits 16–31 pend (one aligned store)
       132   4  gen       u32   segment generation, +1 on every reuse
       136   4  succ      u32   next segment of this FIFO; 0 = end
       140   4  tick      Tick
       144   1  side      u8
       145   1  rsv       u8
       146   2  vmask     u16   positions that need the slot line (NewPrio, Reduce); set once
       148   4  rsv       u32
       152   8  base_ts   Nanos prio_ts of position 0
       160  32  dts[16]   u16   prio_ts − base_ts of each position (key part 1, §3.2)
```

- **Position assignment (pass 1).** The lane keeps a private tail `(seg, next_pos)` per level. A
  `New` or a new-priority `Replace` takes the next position, in `LaneSeq` order, which is key
  order (§3.2). If the segment is full, or `prio_ts − base_ts > u16::MAX`, the lane takes a new
  segment from its free FIFO and links it with `succ`. Positions are assigned to explicit ops
  too, so a position whose op is shed, rejected or never rests stays empty forever.
- **Writing a position.** The lane writes `slot[i]`, `qty[i]`, `dts[i]` and the slot line, then
  sets `active | pend` for `i` in one store to `mask` (`Release`), then publishes the op's
  counter. Independent ops are written in pass 2; explicit ops after their step (§7.4).
- **Cancel = clear one bit.** A cancel writes the version's tombstone (its `LaneSeq`, §4.7), then
  stores `mask` with `active` cleared and `pend` set for `i`. A fill that the lane learns has
  emptied the order, or a BBO kill, clears `active` with no `pend`: the order is dead at every cut.
- **`pend` means "check the slot".** The lane clears `pend` for `i` once `LaneCut[l].cut` covers
  the position's insertion and tombstone (§7.8). A step reads `mask` once and computes
  `cand = active | pend`; for a `pend` bit it compares the slot's `ins_seq` and `tomb_seq` with
  its cut (§5.1). For every other bit, `active` is the answer at every cut that a current or
  later step can use, because that cut is at least `LaneCut[l].cut`.
- **`vmask`** marks positions that need the slot line: a `NewPrio` position slot (its root is
  not `slot[i]`), or an order that was reduced (the BBO core walks `next_ver` to the version
  visible at its cut, §5.1). For every other position `slot[i]` is the root, so
  `qty[i] − filled[slot[i]]` is the open quantity without touching the slot line.

```
Lane l, side S:
  dir[0], dir[1]       two dense directories; CounterLine.dir_sel picks the live one
     .center: Tick     window center c (copied from SnapshotLine.win_center when built)
     .head: [u32; TICK_HOT_WINDOW]       first Segment16 of the level; 0 = empty
  tail: [(u32, u8); TICK_HOT_WINDOW]     lane-private, for the live dir
  ovf:  page_of: [u16; ENG_LADDER_PAGES], pages: [OvfPage; ENG_OVF_PAGES]
        OvfPage { base: Tick, head: [u32; 4096], tail: [u64; 4096], bits: [u64; 64] }

  window(S, c):  bids [c − 3072, c + 1024),  asks [c − 1024, c + 3072)      (4096 ticks each)
  index(t)    :  t − (c − 3072) for bids,    t − (c − 1024) for asks
```

- The head word changes only when the level goes empty → non-empty or when the lane reclaims the
  head segment (§7.8). So the BBO core's cached copy of a head word stays valid for long periods.
- A level outside the window lives in an overflow page. Pages come from a preallocated pool.
  `page_of[t >> 12]` names the page or is `u16::MAX`.
- The lane's logical cap on distinct far pages holding orders is `ENG_FAR_PAGES_MAX` per side. A
  `New` that would exceed it is rejected `BAD_TICK`. The cap is logical, so the reject is replayable.
  Running out of physical pages despite the cap is a fault (§14.3).

### 4.7 Tombstones and `AcctKill`

A tombstone is the pair `(tomb_seq, tomb_ts)` in the version slot. It carries the `LaneSeq` of
the op that wrote it, so the BBO core decides visibility against any cut without asking the lane.

`CancelAll` writes one record, not one tombstone per order:

```
AcctKill (16 B, 4 per line, lane-written, BBO-read; index = acct_ix)
  0  8  kill_seq   LaneSeq of the newest CancelAll of this account; 0 = none
  8  8  kill_ts    its ts
```

A version `V` of account `a` is killed at cut `C` when `kill_seq(a) ≤ C[l]` and
`V.ins_seq < kill_seq(a)`. The lane writes the real tombstones lazily in idle time. Before it
overwrites `kill_seq` with a newer `CancelAll`, it finishes writing the tombstones of the older
one. Then a step whose cut lies between the two still sees the older one's effect through the
tombstones (Lemma 9.4).

`CancelAll` is per session in `04`. The engine implements it per account when the account has
one session, and with per-order tombstones (bounded by `ENG_CANCELALL_EAGER`) when it has more.

### 4.8 Occupancy bitmaps

Per lane and side, a 4096-bit bitmap over the live window (bit = level head ≠ 0) and a 64-bit
summary (bit = word ≠ 0). Lane-written. The cut core reads them to rebuild a lane's column of the
occupancy masks (§7.3). The BBO core reads them only when a lane is "wild" or a level is outside
the window.

### 4.9 Journal (lane-written, BBO-read in `Rescan` only)

```
JEnt (16 B):  0 8 seq LaneSeq | 8 4 tick Tick | 12 3 slot u24 | 15 1 kind u8
kind: 1 New, 2 KeepPrio, 3 NewPrio, 4 Tomb (slot = the ended version), 5 AcctKill (slot = acct_ix)
```

One entry per independent op that changes the book, written in pass 2 before the op's counter
publish (rejects, session ops and explicit ops write none: explicit ops are never batch
entries, §3.6). The ring has
`ENG_JOURNAL` entries. The lane must not overwrite an entry whose `seq > LaneCut[l].cut` (it may
still be in a batch). If the ring is full of such entries, the lane stalls (§14.2).

### 4.10 `CounterLine` (64 B, lane-written, seqlocked)

```
off size field     type      meaning
  0   8  lock      u64       seqlock: odd while the lane writes
  8   8  seq       LaneSeq   every op ≤ seq is applied, or explicit (forwarded or a dependency)
 16   4  snap_ver  u32       snapshot version loaded now (wrapping); every op > seq uses ≥ it
 20   4  f_lo      u32       low 32 bits of fills_applied (wrapping; retires Pend, §8.5)
 24   8  fwd_pend  LaneSeq   dependency floor of the oldest FwdRing entry not seen consumed; 0 = none
 32   4  n_ev      u32       cumulative number of occupancy events
 36   1  dir_sel   u8        live level directory (0 or 1)
 37   1  state     u8        0 Running, 1 Parking, 2 Parked (§14.1)
 38   2  rsv       u16
 40  24  ev[3]     OccEvent  the three newest events, newest last

OccEvent (8 B):  0 4 tick Tick | 4 2 back u16 (seq − event seq, saturating) | 6 2 bits
bits: bit 0 side (0 bid, 1 ask), bit 1 kind (0 SET, 1 CLEAR)
```

The lane publishes after every op: `lock += 1` (odd), fields, `lock += 1` (even, `Release`).
The cut core reads with the usual seqlock retry. `lock` also serves as the watchdog heartbeat:
the lane republishes it at least every `ENG_BEAT_NS` while idle.

### 4.11 BBO-private per-order state

```
BboSlotState[lane][root] : u32     bits 0..30 filled (cumulative over versions), bit 31 killed
```

```
BboVer[lane][slot]     : u8      bit 0: this NewPrio version passed replace_ok (§8.5)
                                 bit 1: explicit, decided at a step ≤ the current one: visible
                                        whatever the cut (§5.1)
```

`killed` is set by a BBO decision that ends an order while its position stays assigned: IOC or
FOK residual, post-only reject, STP removal, a dependency `Cancel` (§3.7), `BOOK_HALTED` at the
step, auction-only after uncross.
`ENG_MAX_ORDER_QTY ≤ 2^31 − 1` keeps `filled` in 31 bits.

### 4.12 Rings

```
FwdEntry (64 B, lane → BBO)                     FillEvent (32 B, BBO → lane)
off size field                                  off size field
  0   8  lane_seq    (written last, Release)      0   8  step      StepId (written last, Release)
  8   8  prio_ts                                  8   4  handle    root slot + gen
 16   4  snap_ver  (u32, wrapping)               12   4  vslot     version slot that traded
 20   4  deadline  latest BBO step start, low    16   4  tick      fill price, or limit for Out
              32 bits of PTP ns (§6.8)           20   4  qty
 24  16  msg   (the 16-B message; byte 2 =      24   1  kind      Fill | Rested | Out | Reject |
              index in bits 0–3 and CROSS in                 Dep | Phase | Band | Uncross
              bit 7, byte 3 = n_dep)
 40   4  handle  root + gen                     25   1  liq       0 maker, 1 taker, 2 auction
 44   4  vslot   version slot written for it    26   2  cause     Out cause / Reject reason
 48   4  session                                28   4  ordinal   fill ordinal in the step
 52   4  resp_seq  first of 1 or 2 reserved
 56   4  pkt_seq   echo_pkt
 60   2  acct_ix
 62   2  applied_back  lane_seq − the lane's `applied` at push (§3.3)

FwdDep (16 B, 4 per line; ceil(n_dep / 4) lines follow their FwdEntry in the ring)
  0  1 back    lane_seq − dep's LaneSeq (1..=9)  |  1 1 kind: 1 Join, 2 Cancel
  2  1 flags   wire flags of the order (side, TIF, post-only, STP)   |  3 1 pos (0–15)
  4  4 tick    the order's tick              |   8 4 qty    total (Join) or 0 (Cancel)
 12  4 slot    Join: its new slot (written in pass 1); Cancel: the position slot it ends
```

- **`CROSS`** (`msg` byte 2, bit 7) is the route the lane classified the op with (§6.5): 1
  `Cross`, 0 `Improve`. Lane risk charges its buckets by that route (10 M8), and the step kind
  does not show it: a `Cross` that ends without a fill (STP, or the book moved after the
  snapshot) steps as `Improve`, and an `Improve` that trades steps as `Cross` (§8.1). The BBO
  core copies the bit into `StepEntry.flags` (§4.15) and decides nothing on it. Wire bytes 2–3
  are 0 (01 §6.2) and the index is 0–9, so bits 4–6 stay 0. An op the lane classifies and then
  rejects is never pushed. Every op it classifies, pushed or not, also logs its route as a
  `RouteRecord` (§10).
- Both rings are SPSC. An entry is new when its first word is greater than the consumer's last
  seen value; `lane_seq` and `step` grow strictly, so no separate producer index exists. The
  consumer skips `ceil(n_dep / 4)` lines after an entry, so dependency lines are never parsed as
  entries. The lane writes them before the entry's `lane_seq` (`Release`).
- The BBO core prefetches the two ring lines after every polled head, so dependency lines arrive
  with their entry in one cross-CCD round trip (§8.4).
- A `Dep` event reports a dependency's outcome to its lane (rested, filled, STP-killed, canceled
  with `open`, or `BUSY`); the lane writes the dependency's position or tombstone from it (§7.4).
- `FwdCons` and `FillCons` hold the consumer index. A producer reads it only when the ring
  looks full.
- One step emits its fill events to a lane as one contiguous run, in ordinal order.
- `Phase`, `Band` and `Uncross` events carry control data in `tick`, `qty` and `cause`
  (§8.8, §13). They go to every lane's ring at the step that makes the change.

### 4.13 `CutPub` half-cuts and occupancy masks (cut-core-written, 01 §14.3)

```
CutPub[h] for half h ∈ {A, B} (ring of 4 per half; h = A: lanes 0–24, B: lanes 25–48):
  line 0:    lock u64 | pub_id u64 | wild u32 (lanes of the half not trusted) | occ_center Tick
             | rsv (bytes 24–63)
  lines 1–7: entry[l] (16 B) = { seq: LaneSeq, snap_ver: u32, f_lo: u32 }   25 entries
newest[h]:   u64 on its own line: the pub_id of the newest publication (Release store)

occA[side][i] : u32   bit l set ⇒ lane l (0–24) may have a non-empty FIFO at window index i
occB[side][i] : u32   bit l − 25 likewise for lanes 25–48
occ(side, i)  = occA[side][i] as u64 | (occB[side][i] as u64) << 25        (BBO core, 2 loads)
BboFloor      : { done_A: u64, done_B: u64 }  written by the BBO core: every step it starts from
                                              now on uses half-cuts ≥ (done_A, done_B)
```

Each cut core is the only writer of its half's lines and its mask array, so no line has two
writers (`INV-WRITER`). The BBO core reads both `newest` publications with their seqlocks. It
reads the masks without a lock: Lemma 7.1 proves that every mask word it can read is conservative
for the cut it uses.

Half B holds 24 lanes (25–48, `N_LANES_REF` = 49, 01 §5, §14.3) in the same 25-entry layout as
half A; its entry 24 is never a lane and stays 0, and occupancy bit 24 of `occB` is never set.
`newest` sits on its own line, apart from the four publications: a reader loads `newest`
(`Acquire`), then that publication, and refuses a publication whose `pub_id` differs (the writer
lapped it). That is `vyrn-cut::PubRing` (`crates/engine/vyrn-cut/src/line.rs`), with
`LANES_PER_HALF` = 25 (`lines.rs`).

### 4.14 `SnapshotLine` (64 B, BBO-written, lane-read)

```
off size field       meaning
  0   8  lock        seqlock
  8   8  version     snapshot version, +1 per change of bid, ask or phase
 16   4  bid         bound B (0 = no bid)
 20   4  ask         bound A (u32::MAX = no ask)
 24   8  done_step   last completed step
 32   4  win_center  window center c for level directories
 36   1  phase       0 Continuous, 1 Auction, 2 Halted, 3 Frozen
 37   1  flags       bit 0: this version is an auction version (envelope rule, §8.6)
 38  26  rsv
```

### 4.15 `StepLog`, `TxRing`, `LaneCut`

```
StepEntry (64-B header + delta lines, BBO → both stream cores and all three fill TX cores):
  0  8 step | 8 1 kind | 9 1 src_lane | 10 1 n_delta | 11 1 n_tx | 12 4 n_fills
  16 8 src_lane_seq (0 = no source) | 24 4 pub_A (low 32) | 28 4 pub_B (low 32)
  32 4 band_lo | 36 4 band_hi (Rescan only) | 40 8 fill_lanes u64
  48 1 flags (bit 0 CONT; bit 1 CROSS: the source's FwdEntry CROSS, steps with a source only)
  49 15 rsv
  then ceil(n_delta / 4) lines of { lane: u8, rsv: [u8;7], seq: LaneSeq } × 4

TxEntry (64-B header + 16-B records, BBO → the fill TX core of the session's lane half):
  0 8 step | 8 4 session | 12 4 resp_seq (0 = take the next number of MakerSeq[session])
  16 4 pkt_seq (0 = unsolicited) | 20 1 lane | 21 1 n_rec | 22 1 role (0 taker, 1 deps, 2 maker)
  23 41 rsv
  then n_rec response records exactly as 01 §6.4

MakerSeq[session] (16 B, lane-written, fill-TX-read; 01 §14.14):
  0 4 base_cur | 4 4 base_next | 8 4 gen | 12 4 rsv      two ranges of 16 numbers each

LaneCut[l] (16 B, 4 per line, stream core of l's half → lane l):  { step: StepId, cut: LaneSeq }
  one 16-B aligned store; the lane reads it with one 16-B aligned load
```

- **Two stream cores, frame gating (01 §14.15.3, §14.16).** Stream core A (core 4) frames the
  `PacketRecord`s of lanes 0–24 and every `StepRecord`; stream core B (core 7) frames lanes
  25–48. Each publishes `FramesOut_A/B = s` once its records for step `s` are in both replication
  TX queues. Step `s` is framed when `min(FramesOut_A, FramesOut_B) ≥ s`; each core writes
  `LaneCut[l] = (s, C_s[l])` for its own lanes only after that. So a lane that reads `LaneCut` for
  `s` knows the gate for its acks is open, and only checks it (~10 ns budget).

- A 16-B aligned SSE/AVX load or store is single-copy atomic on x86-64 CPUs with AVX (vendor:
  Intel SDM vol. 3A §9.1.1; AMD APM vol. 2 §7.3.2). On aarch64 the pair is an `STP`/`LDP` with
  FEAT_LSE2. A target without either uses a per-entry seqlock. `vyrn-cut` uses the seqlock on
  every target, one `LaneCut[l]` per `BLD_SHARED_ALIGN` line, because safe Rust cannot express
  a 16-byte single-copy-atomic store (`LaneCut` in `crates/engine/vyrn-cut/src/lines.rs`).
- Each stream core keeps the full cut and expands the deltas into `StepRecord.cut`
  (01 §6.6). After step `s` is framed, it writes `LaneCut[l]` when `C_s[l]` changed
  or when bit `l` of `StepEntry.fill_lanes` is set (lanes that received fill events in `s`). It
  may skip or batch writes; Lemma 9.12 shows that the output does not depend on the schedule.
- **`MakerSeq`.** The lane fills `base_next` with 16 fresh numbers of the session's `resp_seq`
  whenever it sees (from fill events) that 8 numbers of `base_cur` were used, and bumps `gen`.
  The fill TX core numbers the session's TX-core packets in step order: the `k`-th such packet of
  the session gets number `k mod 16` of the `⌊k / 16⌋`-th range. Both sides count the same
  packets, so the numbers are a function of the step outputs (`INV-DET`), and each number has one
  writer (01 §14.14).

## 5. Visibility and the merged level FIFO

### 5.1 Visibility at a cut

```rust
// V is a version slot of lane l; C is the step's cut. Reads only write-once fields (INV-ENG-2).
fn visible(V: &OrderSlot, l: LaneId, C: &Cut) -> bool {
    (V.ins_seq <= C[l] || bbo_ver[l][V.slot] & EXPLICIT != 0)      // §3.3 explicit positions
        && !(V.tomb_seq != 0 && V.tomb_seq <= C[V.tomb_lane])       // = C[l] outside a pool
        && !killed_by_acct(V, l, C)                  // AcctKill rule, §4.7
}
// The version of position (g, i) visible at C: the position slot, or a KeepPrio successor.
fn version_at(g: &Segment16, i: usize, l: LaneId, C: &Cut) -> Option<&OrderSlot> {
    let mut V = slot(l, g.slot[i]);
    while g.vmask & bit(i) != 0 && V.tomb_seq != 0 && V.tomb_seq <= C[l] && V.next_ver != 0 {
        V = slot(l, V.next_ver);                     // ≤ one hop per Reduce of the order
    }
    visible(V, l, C).then_some(V)
}
fn killed_by_acct(V: &OrderSlot, l: LaneId, C: &Cut) -> bool {
    let k = acct_kill(l, V.acct_ix).kill_seq;        // Acquire
    k != 0 && k <= C[l] && V.ins_seq < k
}
fn live(V: &OrderSlot, l: LaneId, C: &Cut, st: &BboSlotState) -> bool {
    let s = st[l][V.root];
    visible(V, l, C) && s & KILLED == 0 && (V.total as u64) > (s & FILLED_MASK) as u64
        && !(V.flags.tif() == AuctionOnly && step_kind != Uncross)   // §2.5 P2
}
fn open(V: &OrderSlot, l: LaneId, st: &BboSlotState) -> Qty { V.total − filled(st[l][V.root]) }
```

A position whose op has `ins_seq > C[l]` may be written already (an op the cut has not reached).
`visible` hides it. A read that sees `tomb_seq = 0` while the lane is writing a tombstone with
`seq > C[l]` gives the same answer as a read after it, because that tombstone is not in the cut
either. A tombstone with `seq ≤ C[l]` was written before the lane published `seq`, so the BBO
core, which acquired the cut, sees it (Lemma 9.4).

The segment mask is the fast path in front of these checks. A bit that is clear and not `pend`
is dead at every cut ≥ `LaneCut[l].cut`; a bit that is `active` and not `pend` is inserted and
not tombstoned at every such cut; only `pend` bits and `vmask` bits need the slot. An **explicit**
op the lane has not yet written is not in any segment: the BBO core holds it in `Pend` (§8.5)
and merges it as a leaf of its lane.

### 5.2 Visibility at a key (Rescan only)

Inside a `Rescan` batch the ops are ordered by key, not by cut. For a batch entry with key `k`:

```rust
fn visible_at(V: &OrderSlot, l: LaneId, C: &Cut, Cprev: &Cut, k: PrioKey) -> bool {
    let ins  = if V.ins_seq <= Cprev[l] { PrioKey::MIN } else { key(ins_ts(V), l, V.ins_seq) };
    // ins_ts(V) = V.ins_ts if V.kind == KeepPrio, else V.prio_ts (§4.3)
    let tomb = if V.tomb_seq == 0 || V.tomb_seq > C[l] { PrioKey::MAX }
               else if V.tomb_seq <= Cprev[l] { PrioKey::MIN }
               else { key(V.tomb_ts, l, V.tomb_seq) };
    let kill = acct_kill_key(l, V, C, Cprev);         // same three cases for AcctKill
    V.ins_seq <= C[l] && ins < k && !(tomb < k) && !(kill < k)
}
```

An op's effect is visible to every later op in the batch and to none earlier. That is §3.4's
order inside `B_s`.

### 5.3 A lane's head at a level: one segment at a time

```rust
// A cursor names a queue position. It carries the segment generation (ABA check, §7.8).
struct Cursor { seg: u32, gen: u32, pos: u8 }
fn lane_head(l: LaneId, side: Side, t: Tick, C: &Cut, from: Option<Cursor>) -> Option<Cursor> {
    let (mut x, mut p0) = match from {
        Some(c) if seg(l, c.seg).gen == c.gen => (c.seg, c.pos),   // resume inside a segment
        _ => (head_word(l, side, t), 0),                           // reused or new: restart
    };
    while x != 0 {
        let g = seg(l, x);                            // lines 0 and 2 (line 1 when a bit hits)
        let m = g.mask.load(Acquire);
        let mut cand = ((m | m >> 16) & 0xFFFF) as u16 & !((1u16 << p0) - 1);
        while cand != 0 {
            let i = cand.trailing_zeros() as usize;
            let fast = m & (1 << (16 + i)) == 0 && g.vmask & bit(i) == 0;
            if fast { if m & bit(i) != 0 && open_pos(g, i, l) > 0 { return Some(cur(x, g, i)) } }
            else if let Some(V) = version_at(g, i, l, C) {
                if V.ins_seq > C[l] && !explicit(l, V) { return None }     // tail beyond the cut
                if live(V, l, C, st) { return Some(cur(x, g, i)) }
            }
            cand &= cand - 1;
        }
        x = g.succ; p0 = 0;
    }
    None
}
```

The stop rule is exact: positions are assigned in `LaneSeq` order, so every position after one
whose op has `ins_seq > C[l]` (and is not explicit) also has `ins_seq > C[l]`. A `KeepPrio`
version is not a position, so it never stops the walk. `open_pos(g, i, l) = g.qty[i] −
filled(st[l][root])` for a position without a version chain.

### 5.4 The merged level FIFO

The level FIFO at `(side, t)` for cut `C` is the merge of `lane_head` sequences of all lanes by
`(prio_ts, rank_e(l))`. Within one lane, FIFO order is used. It is never stored (01 §1).

```
BBO head cache, one per side, for the touch level T (bid side: T = B; ask side: T = A)
  tick       Tick
  built_pub  (u64, u64)           half-cut ids it was last reconciled with
  present    u64                  lanes whose leaf is non-empty
  leaf[64]   Leaf (32 B)          { cur: Cursor, run: u16 (live positions of cur's segment
                                    at or after cur, as a mask), prio_ts: Nanos, lane: u8,
                                    rank: u8, pend: u8 (leaf comes from Pend), pad }
  node[64]   u8                   loser tree: node[0] = winner lane, node[1..63] = losers
                                  (N_LANES ≤ 64; empty leaves hold key = MAX)
```

- **One leaf per lane, one segment per leaf.** A lane's leaf is its first live position at `T`;
  it caches the segment's live mask `run` from there and its `dts`, so the lane's next position is
  `tzcnt(run)` with key `base_ts + dts[i]`, with no memory access.
- **Pop a run.** The winner `w` stays on top while its next key is below the runner-up's `k2`, so
  one AVX-512 pass over `w`'s segment (§8.5) yields every live position of `w` with key `< k2`, in
  order. Only when the run ends does the tree replay `w`'s path (6 comparisons).
- **New lanes.** Before using the tree, `new = occ(T) & !present`, plus wild and lag lanes and the
  lanes with `Pend` entries at `T`, get a `lane_head` probe. Lanes in `present` need none: new
  positions go behind the head and never move (01 §14.13.2).
- **`Pend` leaves.** An unwritten explicit op that rests is a leaf of its lane at its own key,
  behind the lane's physical positions (§3.7). When the lane writes it, the walk skips that `slot`
  while the `Pend` entry exists, so nothing is counted twice.
- **No stale leaves.** Keys are immutable; a cursor whose segment `gen` changed restarts from the
  lane's head word (§7.8). Deeper levels build a temporary tree the same way (§11.4).

`rank_e(l)` is fixed for the epoch, so trees built in different steps of one epoch agree.

### 5.5 Window re-centering

The window center `c` moves when the touch drifts. Re-centering changes where levels are stored,
never which orders exist, and no output (Lemma 9.14).

```
BBO core:  if |mid(B, A) − c| > ENG_RECENTER_DRIFT, publish SnapshotLine.win_center = c' (mid,
           rounded to a multiple of 64) with the next snapshot.
Lane l:    1. build dir[1 − dir_sel] for c' (copy heads/tails; far levels to or from overflow
              pages; do not clear the old places), in idle slices (~10 µs of lane time)
           2. publish CounterLine.dir_sel = 1 − dir_sel with the next op's publish
           3. after done_step ≥ σ + ENG_QSBR_LAG (σ read at 2), clear the old places
Cut core:  on a dir_sel change, mark the lane wild, rebuild its mask column for c', clear wild.
```

A step reads `dir_sel` after it acquires the cut: if `C[l]` includes an op after the flip, it sees
the new directory; otherwise either directory is correct, because both point into the same
segment chains and nothing a step can reach is retired (§7.8). Between 1 and 3 the lane updates
both places. The collar (§13.2) keeps every cross inside the window within that drift.

## 6. The lane

### 6.1 Main loop

```rust
fn lane_main(l: &mut Lane) -> ! {
    loop {
        let pkt = l.rx.peek_by_ts();                    // smallest rx_ts among 4 VI heads
        if l.boundary_due() { l.boundary(Between) }     // §6.2; Advance record if no packet
        match pkt {
            Some(p) => l.process_packet(p),             // §6.3: admission, passes 1 and 2
            None    => l.idle_work(),                   // §7.8: reclaim, tombstones, beat
        }
    }
}
// Polled between work units of at most ENG_UNIT_NS = 20 ns: before each message of pass 1 and
// pass 2, between 64-B blocks of the MAC, and in idle slices. One 16-B load (an L1 hit while
// LaneCut[l] is unchanged).
fn boundary_due(l: &Lane) -> bool {
    let lc = l.lane_cut.load();                         // (f, c) with c = C_f[l]
    lc.step > l.fills_applied
        && (l.fill_ring.has_through(lc.step) || l.pend.front_seq() <= min(lc.cut, l.applied))
}
```

The lane never waits on another core in this loop except when a ring is full (§14.2). The poll
inside a packet is what bounds "the lane notices `LaneCut`" to `ENG_UNIT_NS` on the ack path: a
lane in the middle of another packet's 185 ns of work still settles within 20 ns (§11.1).

### 6.2 The boundary (the replayable point)

Every `PacketRecord`, including an Advance record, marks one boundary. A boundary sits between
two packets, or **inside** a packet before the pass-1 or pass-2 step of one op. At a boundary
with `f = lc.step` the lane does, in this order:

```
B1  apply every FillEvent with step in (fills_applied, f], in (step, ordinal) order      §7.4
B2  settle every pending op t with t ≤ min(C_f[l], applied), in LaneSeq order            §7.6
B3  send the response packets that B1 and B2 produced (§8.10); set fills_applied = f
```

`applied` is the largest `LaneSeq` whose op and all earlier ones were applied by pass 2 or are
explicit; inside a packet it is the op before the boundary's position. A boundary between packets
precedes B4, the next packet's processing (§6.3). The record written for the boundary carries
`fills_applied = f`. A replica's lane runs the same steps with `f` from the record and `C_f[l]`
from `StepRecord f` (§10). So the lane's ledger, its slots and its responses are the same in both.

**Advance record.** `PacketRecord { lane, count: 0, session: 0, pkt_seq: 0, rx_ts:
last prio_ts, pkt_hash: 0, first_lane_seq: next seq, fills_applied: f, flags }`. It reads no
clock (01 §11.3). `flags.MID` (bit 2) marks a boundary inside the packet whose record precedes it;
`first_lane_seq` is then the op before whose step it runs, and `flags.PASS2` (bit 3) says which pass; an Advance record also has `flags.ADVANCE` (bit 1, 01 §6.6).
The lane writes one only when B1 or B2 has work, so its rate is at most the rate at which
`LaneCut[l]` changes while the lane has pending settles; at full load most boundaries ride on
packets (§11.5).

### 6.3 Processing one packet

```rust
fn process_packet(l: &mut Lane, p: RxPkt) {
    // 0. Pre-pass: read-only. Admission at dequeue (§6.8), MAC, parse, prefetch.
    let cls = l.class_of(&p);                           // (count, Local | Order), §6.8
    if l.late(p.rx_ts, cls, Dequeue) { return l.answer_busy(&p) }        // ~20 ns, no MAC
    let sess = match wire::check_packet(l, &p) {        // 04: session, MAC, pkt_seq, epoch16,
        Ok(s) => s,                                     //     book, bound address, rate limits
        Err(e) => { wire::on_bad_packet(l, &p, e); return }   // takes no LaneSeq
    };
    l.prefetch_packet(&p);                              // handles, accounts, tails (§11.3)
    l.wait_lines(&p);                                   // cold lines arrive here, not in pass 1
    if l.late(p.rx_ts, cls, Commit) { return l.answer_busy(&p) }         // nothing applied yet
    // Commit point. Everything below is applied and logged.
    let prio_ts = max(p.rx_ts, l.last_prio_ts);         // §3.2; rx_ts from the NIC only
    l.last_prio_ts = prio_ts;
    l.os_ring.push(PacketRecord { lane: l.id, count: p.count, session: sess.id,
        pkt_seq: p.pkt_seq, rx_ts: p.rx_ts, pkt_hash: p.hash, first_lane_seq: l.seq + 1,
        fills_applied: l.fills_applied, flags: 0 });    // pre-encoded first (01 §14.5)
    // 1. Pass 1, index order: LaneSeq, checks, reservation, class, position, early dispatch.
    let mut ops = OpList::new();                        // ≤ 10 entries, lane-private
    for (ix, m) in p.msgs().enumerate() {
        if l.boundary_due() { l.boundary(Mid { pass: 1, next: l.seq + 1 }) }    // §6.2
        if m.is_session_only() { wire::session_msg(l, sess, m); continue }       // no LaneSeq
        l.seq += 1;
        let op = l.pass1_msg(sess, ix as u8, m, prio_ts, &mut ops);             // §6.4
        if op.barrier { l.pass2_through(&mut ops, l.seq) }                        // §6.6
        ops.push(op);
    }
    // 2. Pass 2, index order: apply independent ops, publish the counter after each.
    l.pass2_through(&mut ops, l.seq);
    l.flush_immediate(sess);                            // rejects go out now (§8.10)
}
fn pass2_through(l: &mut Lane, ops: &mut OpList, upto: LaneSeq) {
    for op in ops.unapplied_through(upto) {
        if l.boundary_due() { l.boundary(Mid { pass: 2, next: op.seq }) }
        if op.is_independent() { l.pass2_apply(op) }    // §6.4; explicit ops are skipped
        l.applied = op.seq;
        l.publish_counter();                            // §4.10, Release: seq = op.seq
    }
}
```

`pkt_hash` is computed by `04`'s check, which already reads every byte for the MAC. Pass 2 is
wait-free: every slot, position, journal entry, `OsRing` entry and `FwdRing` line it needs was
reserved in pass 1, so pass 2 never waits on another core, and a BBO step never waits on pass 2.

### 6.4 One message: pass 1 and pass 2

```rust
fn pass1_msg(l: &mut Lane, s: &Session, ix: u8, m: Msg, ts: Nanos, ops: &OpList) -> Op {
    let a = &mut l.acct[s.acct_ix];
    let r: Result<Op, Reject> = (|| match m.kind() {
        New => {
            let o = wire::decode_new(m)?;                         // BAD_TYPE, flag checks
            l.admit(a, &o)?;                                      // phase, band, qty, count,
                                                                  //   ACCOUNT_KILLED (10)
            l.reserve(a, &o)?;                                    // §2.6, RISK_CREDIT
            let v = l.alloc_root(s, &o, ts)?;                     // slot index, gen, aux; §7.8
            let pos = l.assign_position(o.side, o.tick, v, ts);   // §4.6, key order
            Ok(Op::join(v, pos, l.classify(&o)))
        }
        Cancel => {
            let r = l.resolve(s, m.handle())?;                    // UNKNOWN_HANDLE, TOO_LATE
            Ok(Op::cancel(r, l.root_aux(r).cur))                  // target side and tick known
        }
        Reduce => { let r = l.resolve(s, m.handle())?; Ok(Op::reduce(r, m.qty()?)) }
        Replace => {
            let r = l.resolve(s, m.handle())?;
            let v = l.root_aux(r).cur;
            if m.side() != slot(v).side() { return Err(SIDE_MISMATCH) }
            if m.tick() == slot(v).tick && m.qty() < slot(v).total {     // a Reduce (01 §6.2)
                return Ok(Op::reduce(r, slot(v).total − m.qty()))
            }
            l.admit_replace(a, &m)?; l.reserve_replace(a, r, &m)?;      // §2.6
            let w = l.alloc_version_slot(v, NewPrio, m.qty(), ts)?;
            let pos = l.assign_position(m.side(), m.tick(), w, ts);
            Ok(Op::replace(r, v, w, pos, l.classify_replace(&m)))
        }
        CancelAll => Ok(Op::cancel_all(s.acct_ix)),
        _ => Err(BAD_TYPE),
    })();
    let mut op = match r { Ok(op) => op, Err(rej) => { l.stage_immediate(s, ix, rej);
                                                       return Op::reject(l.seq) } };
    op.seq = l.seq; op.ix = ix;
    op.barrier = l.is_barrier(&op, ops);                  // §6.6: CancelAll, opposite Reduce
    if op.route == Forward { l.forward(s, ix, m, &mut op, ops) }   // §6.6: push now
    op
}
fn pass2_apply(l: &mut Lane, op: &Op) {                   // only independent ops come here
    match op.kind {
        Join    => { l.write_slot(op.v); l.write_position(op.pos, op.v); l.journal(New, op);
                     l.pend_push(Ack, op) }
        Cancel  => { l.tombstone(op.v); l.clear_bit(op.target_pos); l.journal(Tomb, op);
                     l.pend_push(CancelAck, op) }
        Reduce  => { let w = l.alloc_version(op.v, KeepPrio, op.total_after, op.ts);
                     l.write_version(op.v, w); l.tombstone(op.v); l.journal(KeepPrio, op);
                     l.pend_push(ReduceAck, op) }
        Replace => { l.tombstone(op.v); l.clear_bit(op.old_pos); l.write_slot(op.w);
                     l.write_position(op.pos, op.w); l.journal(NewPrio, op);
                     l.pend_push(ReplaceAck, op) }
        CancelAll => { l.cancel_all(op); l.pend_push(CancelAllAck, op) }
        Reject  => {}
    }
    l.prebuild_response(op);                              // §8.10 rule 3: record and MAC state
}
```

- `resolve` checks the handle (§4.2). It rejects `TOO_LATE` when the lane already knows the
  order is finished (its fill events show `open = 0`, a settle ended it, or an earlier op, of
  this packet or a pending one, ends it). That knowledge is a function of boundaries at logged
  positions, so it is replayable, and it keeps every tombstone write-once. A cancel of an order
  that the BBO core filled but whose events the lane has not applied is answered at settle (§7.6).
- Pass 1 touches only lane-private lines, the account line, the packet's prefetched lines and
  the `FwdRing`, all warm after `wait_lines`: `LANE_PASS1_NS` = 5 per message. Pass 2 writes the
  shared lines: `LANE_APPLY_NS` = 9 per message, including the response pre-build.
- `tombstone(v)` writes `tomb_ts` then `tomb_seq = op.seq` (`Release`), then the mask; the
  journal entry and the mask precede `publish_counter`. `cancel_all` writes `AcctKill { kill_seq,
  kill_ts }` after it has finished the previous `CancelAll`'s tombstones (§4.7).

### 6.5 Classification

```rust
fn classify(l: &Lane, o: &NewOrder) -> Route {
    let s = &l.snap;                                       // (bid, ask, version, phase)
    if s.phase != Continuous { return Local }              // auction and halt: no matching
    if matches!(o.tif, Ioc | Fok) { return Forward }       // D8
    if o.tif == AuctionOnly { unreachable!() }             // rejected by admit in Continuous
    match o.side {
        Buy  => if o.tick >= s.ask { Forward }             // cross (also post-only: D8)
                else if o.tick > s.bid { Forward }         // improve
                else { Local },                            // join: tick ≤ bid
        Sell => if o.tick <= s.bid { Forward }
                else if o.tick < s.ask { Forward }
                else { Local },                            // join: tick ≥ ask
    }
}
```

A `Forward` from the IOC/FOK line or a `// cross` line sets `op.cross`; one from an
`// improve` line leaves it clear. Risk charges by it (10 M8), and the lane logs it for replay
(§4.12, §10).

`bid = 0` means no bid and `ask = u32::MAX` means no ask, so with an empty side every passive
order on that side is an improve. A Halted-phase snapshot never reaches `classify` for a `New`,
because `admit` rejects it with `BOOK_HALTED`.

The lane records `l.snap.version` in `CounterLine.snap_ver` at every refresh. Every later op uses
that version or a newer one. The BBO core needs only this lower bound (§8.6).

### 6.6 Forwarding

```rust
fn forward(l: &mut Lane, s: &Session, ix: u8, m: Msg, op: &mut Op, ops: &mut OpList) {
    let deps = ops.deps_of(op);                            // earlier joins/cancels it depends on
    for d in &deps {                                       // pass 2 will skip them
        ops.mark_explicit(d);
        if d.is_join() { l.write_slot(d.v) }               // root and key for the BBO core
    }
    let n_rs = if deps.is_empty() { 1 } else { 2 };        // deps packet + source packet (D10)
    let rs = s.next_resp_seq; s.next_resp_seq += n_rs;
    l.write_slot(op.v);                                    // the BBO core may read it (§8.5)
    let e = FwdEntry { lane_seq: op.seq, prio_ts: op.ts, snap_ver: l.snap.version as u32,
                       deadline: l.bbo_deadline(op, &deps),            // §6.8
                       msg: m.with_index(ix).with_cross(op.cross).with_ndep(deps.len()),  // §4.12
                       handle: root_handle(op.v),
                       vslot: op.v, session: s.id, resp_seq: rs, pkt_seq: cur_pkt_seq,
                       acct_ix: s.acct_ix as u16,
                       applied_back: (op.seq − l.applied) as u16 };
    while l.fwd_ring.free_lines() < 1 + ceil_div(deps.len(), 4) {
        l.drain_fill_ring_only()                           // §14.2: never block the BBO core
    }
    l.fwd_ring.push_with_deps(e, &deps);                   // FwdDep lines, then lane_seq (Release)
    if l.fwd_pend == 0 { l.fwd_pend = op.seq − deps.max_back() }      // CounterLine.fwd_pend
    l.pend_push(Forwarded, op);
}
```

**The dependency list** of forwarded op `j` (01 §14.2) is every earlier, not yet explicit op of
the same packet that is a resting `New` or new-priority `Replace` (**Join**) on `j`'s opposite
side inside `j`'s price range (`tick ≤ j.tick` for a buy, `≥` for a sell), or a `Cancel`
(**Cancel**) of an order there (`resolve` knows its side and tick in pass 1).

Earlier forwarded ops are not dependencies: they run at earlier steps of the same ring. An
earlier op on `j`'s own handle is not one either: it is on `j`'s side, and pass 1 tracks the
pending version in `OpList`, so `j`'s `pred_total` (§4.3) is already right. A `CancelAll`, and a
`Reduce` or old-priority `Replace` of an opposite-side order in range, are **pass barriers**:
pass 1 runs pass 2 through them before it continues, so a later `j` sees them through the cut.
That delays a later forwarded op by ≤ 81 ns, and its absolute deadline sheds it if that makes it
late; joins after a barrier (the "cancel all, requote" packet) are not delayed.

The source slot and each Join dependency's slot are written before the push, so the `Release` of
`lane_seq` publishes them; their queue positions are written after the step, from its events
(§7.4). `drain_fill_ring_only` buffers events without applying them (applied only at B1).

### 6.7 Lane budget

Budget for one packet of 10 messages at the reference mix (DESIGN §3: 50% joins, 47% cancels or
reduces, 3% forwarded), 01 §14.2. 5 GHz clock (vendor: EPYC 9575F boost).

| Work | When | ns per packet |
|---|---|---|
| RX poll, age check, `04` checks (session, SipHash-2-4 over 176 B, pkt_seq, rate limit), prefetch issue, `PacketRecord` pre-encode | pre-pass (45 per packet of `LANE_PASS1_NS`) | 45 |
| decode, admit, reserve, resolve, classify, position, deps, push (5 per message) | pass 1 | 50 |
| slot and position write, tombstone, journal, response pre-build, counter publish (9 per message) | pass 2 (`LANE_APPLY_NS`) | 90 |
| **packet path** | | **185** |
| boundary B1–B3 (amortized: 0–2 events, 3–8 settles, finalize and send ≤ 1 response packet) | boundary | 25 |
| settling maker fills from events (off the latency path, 01 §14.14), `MakerSeq` refill | boundary | 5 |
| idle work: pend-bit clears, segment reclaim, lazy tombstones (amortized) | idle | 10 |
| **Total** | | **225 = 22.5 per message** |

`LANE_NS_PER_MSG = 30` stays the all-in budget: the table leaves 7.5 ns per message of slack.
The lane's busy fraction at 1B msgs/s (20M msgs/s per lane) is **0.37 on the packet path**
(185 × 2M packets/s) and **0.45 in total** (§11.7).

A cancel whose lines are cold in DRAM costs ~90 ns (vendor DDR5 latency). The pre-pass issues
every prefetch of the packet at once and waits for them before the commit point, so a packet pays
one DRAM latency, not one per cancel, and the wait is measured by the admission check at the
commit point (§6.8). It can cause `BUSY`; it can never make an accepted packet late. B2
(DESIGN §9 #2) measures this table on one lane.

### 6.8 Deadline admission (01 §14.1)

The lane decides at two points whether the packet can still be answered within `LAT_MAX_NS`. No
state has changed at either point.

```rust
const DEADLINE_GUARD_NS: u64 = 20;                        // 01 §14.1
fn late(l: &Lane, rx_ts: Nanos, cls: Class, at: Point) -> bool {
    let now = l.clock.now_ns();                           // TSC → PHC mapping (06), ~3 ns
    let rest = l.cfg.path_ns[cls.count][cls.kind] − if at == Commit { l.cfg.prepass_ns } else { 0 };
    now − rx_ts + rest > LAT_MAX_NS − DEADLINE_GUARD_NS
}
```

- **`predicted_path_ns`** = `path_ns[n][kind]`, a table in the book's configuration (`10`
  `BookSpec`), indexed by message count `n` = 1..=10 and class: `Local` (no `New` or `Replace`,
  read from the message types at dequeue) or `Order`. Each entry is the worst §11.1 path over the
  packet's indices, without NIC RX (the age contains it), rounded up to 5 ns. The ack term uses
  the worst cut arrow of §7.7 (170, with 15 ns steps), plus the 20 ns poll; the cross term uses
  the §11.1 BBO budget, because the BBO core's own test turns BBO-side lateness into a `Shed`:

  | `n` | `Local` = 505 + 14n | `Order` = max(510 + 5n, 505 + 14n) | admitted if `age ≤` |
  |---|---|---|---|
  | 1 | 520 | 520 | 460 |
  | 10 | 645 | 645 | 335 (15 ns above the 320 ns RX budget, §11.8) |

  `11` checks each entry against B3's measured maxima before a configuration is accepted.
- **At dequeue**, a late packet costs ~20 ns: session lookup, bound-address check, one
  `Reject { BUSY }` per message in one response packet, no MAC verification. It does not advance
  `pkt_seq` (the client resends) and cannot change book state; its record is `PacketRecord
  { flags: SHED, pkt_hash: 0 }`. **At the commit point** (after the MAC and the prefetch wait) the
  same test runs without the pre-pass part, so a cold-line wait becomes `BUSY`, never lateness.
- **The BBO core's test.** `FwdEntry.deadline = rx_ts + 980 − 355`, where 355 ns is the §11.1
  path from a step's start to the first bit out (step 15, gate 60, TX 40, NIC TX 240). If `now >
  deadline` when the op would start, the BBO core emits a `Shed` step (§8.1): the op and its
  dependencies get `Reject { BUSY }` from the fill TX core in the op's reserved packet, their lane
  releases their reservations from the `Reject` events, and the packet's independent ops, which
  pass 2 applied, are untouched (01 §14.1).
- **Logging (`INV-DET`).** The `SHED` flag and the `Shed` step are in the order stream; replay
  reads them and never reads a clock (§10, Lemma 9.15).
- **Backlog bound.** The leaf switch polices each lane to `LANE_POLICE_PPS` = 40M packets/s,
  burst `LANE_POLICE_BURST` = 8 (01 §14.1). A 20 ns shed is shorter than the 25 ns policed
  interval, so a lane in overload drains faster than it fills; `04` §3.5 proves that every `BUSY`
  then leaves within `LAT_MAX_NS`.
- **Target.** Dedicated, paced lanes: lane-stage `BUSY = 0`; total `BUSY ≤ 1e-5` at full book
  load (crosses and improves only) and `≤ 1e-8` at ≤ 20% load (01 §14.17.2). Pooled lanes: `BUSY ≤ 1e-3` at full book load
  and `≤ 1e-6` at ≤ 20% book load (01 §14.15.5, B3). §11.8 gives the model.

### 6.9 Dedicated lanes and the pooled lane group (01 §14.15)

**Dedicated lanes** (lanes 0–41, cores 8–49). A lane serves the accounts of one firm only, so
only that firm's packets queue on it. **`LANE_PACE`**: the firm's SDK leaves at least
`path_ns[n][kind]` of the previous packet (§6.8) between two packets to the same lane. Then a
packet finds the lane idle except for at most one work unit of boundary or idle work
(`ENG_UNIT_NS`), and its age at dequeue is its RX time plus ≤ `ENG_UNIT_NS`: lane-stage `BUSY = 0` whenever
`RX + ENG_UNIT_NS ≤ 980 − path` (§11.8 states the margin). Only the firm's own bursts can make it
wait.

**Pooled lanes** (lanes 42–48, cores 56–62, one CCD). Every pool core is a full lane: its own
`LaneSeq`, `CounterLine`, entry in the cut vector, `FwdRing`, `OsRing`, journal, slot arena and
`Segment16` blocks. What the pool shares, in CCD 7's L3:

```
AcctTok[a] (16 B, 4 per line)  { holder: u8 (0xFF = free), rsv: [u8; 3], ver: u32, rsv: u64 }
                               (10 §1.2 and 11 call it PoolTok; this is its one layout)
PoolAcct[a]                    the account's ledger, sessions, RootAux of its orders, AcctKill
RxQueue[c] consumer lock (64 B) { lock: u32, next: u32 }   per pool core's RX VI
```

- **Token.** Before it touches pooled account `a` (pass 1 of a packet of `a`, or B1/B2 work for
  `a`'s orders), core `c` takes `AcctTok[a]` with `CAS(holder: free → c)` (~20 ns inside the L3),
  increments `ver`, and writes `AcctTake { account: a, ver, lane: c }` into its own `OsRing` before the work.
  It releases the token (`Release` store) when the packet or boundary work is done. While `c`
  holds it, `c` is the only writer of every field of `PoolAcct[a]` (`INV-WRITER` per field, in
  time slices that the token orders).
- **Session order.** After taking the token, `c` compares `pkt_seq` with the session's next
  expected value. A packet that is ahead (its predecessor is still in another core's hands) is
  put back at the head of the queue it came from and retried; it never runs out of order.
- **Stealing.** A core whose own RX queue is empty takes the oldest packet (smallest `rx_ts`) from
  a sibling's queue under that queue's consumer lock (CAS on `lock`, ~20 ns). The packet's
  admission age includes the time it waited, so a steal never makes it late.
- **Positions.** A pool core assigns positions for its packets in its **own** `Segment16` blocks
  (§4.6): the order belongs to that lane, and its key carries that lane's rank. A pooled account's
  orders may sit in several pool lanes' FIFOs; the merged level FIFO orders them by key as for
  any lanes.
- **Cancels of a sibling's order.** Core `c` cancels order `o` of account `a` that sits in lane
  `l'`'s segment: it writes `o`'s tombstone with `tomb_seq` = its own `LaneSeq` and `tomb_lane = c`
  (§4.3), then clears the bit with `atomic fetch_and` on `l'`'s segment `mask`. Pool cores always
  update pool segment masks with `fetch_or` / `fetch_and`, never a plain store, so concurrent
  bit changes do not overwrite each other. Each bit has one logical owner at a time: the core that
  holds the order's account token.
- **STP and kills across the pool** compare the pool-wide account index, not the lane.
- **Fill events** of a pooled order go to the `FillRing` of the lane that holds its position;
  that lane applies them under the account's token at its boundary (logged `AcctTake`).

**Lemma 6.1 (pooled lanes keep `INV-WRITER` and `INV-DET`).** (a) Every field has one writer at a
time: lane-private and per-lane shared fields as for any lane; `PoolAcct[a]` and `o`'s
tombstone only under `a`'s token; mask bits through atomic RMW, each bit changed only by the
holder of its order's token (or its owner lane for `pend`, which no other core touches).
(b) Every decision is a function of the log: each lane's ops are ordered by its `LaneSeq`; the
work on one account across lanes is ordered by `AcctTake.ver`, which the lanes log; a step reads
a tombstone against `C[tomb_lane]`, a logged cut. A replica replays each lane in order and holds
a lane at an `AcctTake` until the account's previous `ver` has been replayed (the §10 scheduler),
so it reproduces every token hand-over without timing. Stealing and retries change only which
core and when, both of which the log records. ∎

`AcctTake` is a new record kind in the lane's stream (07 encodes it; §17 R15). 01 §14.15's
argument ("each core's `LaneSeq` logs the order") is not enough for an account whose work runs on
two cores: the cross-core order needs `ver`.

### 6.10 Packet retention for `SeqDataReq`

The sequencer keeps the exact bytes of every packet that has a PacketRecord for
`REP_SEQ_PKT_RETAIN_MS` = 50 ms, so that it can answer `SeqDataReq` (07 §5.5 source 3, 07 §5.6).
The packets kept are the lane verdicts `Accepted` and `Shed`.

- **Placement.** Retention is not on a lane core. After each `ingest`, the RX path hands a
  `Copy` value to the repair thread (control, core 51): `vyrn_engine::retain::Kept {session,
  pkt_seq, pkt_hash, rx_ts, bytes}`. It goes through an SPSC `vyrn_cut::Ring` allocated before
  `seal()`. The push never waits and never allocates. On a full ring the copy is lost and counted
  (`retain_dropped`), and the replica uses another source.
- **Store** (`vyrn_engine::retain::Retain`). A FIFO of fixed slots, sized as peak packet rate ×
  50 ms and overwritten oldest first. It has a 4-way set-associative index over `(session,
  pkt_seq)` with at least eight ways per slot, so a bucket holds a mean of ≤ 0.5 live packets.
  Both are allocated at construction. A lookup returns every retained variant of the key, oldest
  first, whose `rx_ts` is within 50 ms of the newest one put.
  - A packet loses its index entry only when its bucket holds more than four live packets, under
    0.1% at the design load. Such a packet is a miss.
  - The bucket hash is murmur3's `fmix64` of `session << 32 | pkt_seq`, not keyed. A packet shed
    at dequeue (§6.8 test D) is retained without a MAC check, because its `SHED` record is logged
    and the sequencer holds the only copy a replica can fetch. Such a packet must still name an open
    session and a `pkt_seq` inside its V5 window, so a sender cannot aim several keys at one bucket.
    Repeating one key can fill its bucket, but an unchecked packet never takes an index way from an
    `Accepted` (MAC-checked) one; it stays unindexed instead. A shed copy a flood displaces is
    lost: its record cannot be resolved unless another source holds the bytes, which Q17 covers. A record joins only the variant its `pkt_hash` names (07 §5.4).
- **Determinism.** Retention changes no engine state and no output. Replay neither reads it nor
  rebuilds it.

## 7. The cut core, settlement, and physical maintenance

### 7.1 Cut core loop

```rust
fn cut_core(c: &mut CutCore, half: Half) -> ! {          // core 1: A = lanes 0–24; core 6: B
    let lanes = half.lanes();                               // 25 lanes
    loop {
        for l in lanes.clone() { prefetch(&counter[l]) }    // 25 cross-CCD lines in flight
        let floor = bbo_floor.done(half).load(Acquire);
        let pub_id = c.next_pub;
        let out = &mut cutpub[half][pub_id % 4];
        out.begin();                                        // seqlock odd
        for l in lanes.clone() {
            let r = counter[l].read();                      // seqlock retry, ≤ 2 tries typical
            out.entry[l] = (r.seq, r.snap_ver, r.f_lo);
            c.take_events(l, &r, pub_id);                   // §7.2, into this half's occ array
            c.fwd_pend[l] = r.fwd_pend;
            if r.dir_sel != c.dir_sel[l] { c.mark_wild(l); c.dir_sel[l] = r.dir_sel }
        }
        c.apply_safe_clears(floor);                         // §7.2
        out.wild = c.wild; out.occ_center = c.center; out.pub_id = pub_id;
        out.end();                                          // seqlock even, Release
        cutpub[half].newest.store(pub_id, Release);
        c.next_pub += 1;
        c.resync_one_wild_lane();                           // ≤ 16 lines per iteration
    }
}
```

Budget: one iteration ≤ `CUT_REFRESH_NS` = 100 ns per half (01 §14.3). The 25 counter-line reads
overlap and fit in one cross-CCD round trip plus issue time (~70 + 15 ns, vendor-class
core-to-core latency and 24+ outstanding L2 misses per Zen 5 core); the rest is ~8 line stores
into CCD 0's L2 and mask updates. B3 checks the 100 ns.

Each cut core reads lane lines and writes only its own CCD-0 lines (its half's `CutPub` ring,
`occA` or `occB`). It never writes a lane line or the other half's lines. The two cores run
unsynchronized; a step combines whichever two newest publications it reads (§8.3).
`INV-CUT-MONO` holds per half because each half's entries are counter values read in order,
and counters only grow; the step cut is monotone by its `max` (Lemma 9.2).

### 7.2 Occupancy masks with deferred clears

```rust
fn take_events(c: &mut CutCore, l: LaneId, r: &CounterView, pub_id: u64) {
    let n = r.n_ev - c.seen_ev[l];
    if n > 3 { c.mark_wild(l) }                         // events lost; resync from the bitmap
    for e in r.ev.iter().rev().take(min(n, 3)).rev() {  // oldest first
        let i = window_index(c.center, e.side, e.tick); // events outside the window are ignored
        match e.kind {
            Set   => { c.occ[e.side][i] |= c.bit(l); c.held[l].remove_level(e.side, i) }
            Clear => c.held[l].push(Held { side: e.side, i, seq: r.seq - e.back, pub_id }),
        }
    }
    c.seen_ev[l] = r.n_ev;
}
fn apply_safe_clears(c: &mut CutCore, floor: u64) {
    for l in c.lanes() {                                // this half's 25 lanes
        let fp = c.fwd_pend[l];
        c.held[l].drain_where(|h| h.pub_id <= floor && (fp == 0 || h.seq < fp),
                              |h| c.occ[h.side][h.i] &= !c.bit(l));
    }
}
// c.occ is occA (u32, bit l) on core 1 and occB (u32, bit l − 25) on core 6.
```

**Lemma 7.1 (masks are conservative).** Let a step use half-publications `P = (P_A, P_B)` and cut
`C`. If lane `l` has a live order at window index `i` of side `S` at `C`, then bit `l` of
`occ(S, i)` is set when the step reads it, or `l` is wild in its half's publication, or `l` is a
lag lane (`C[l] > P.entry[l].seq`, §3.3), or the order is an unwritten explicit op in `Pend`.

*Proof.* A written order's level became non-empty by a SET event at some seq `x` (the first
position written into an empty level); for an explicit op the lane writes the position, and
emits the SET, before it publishes the `f_lo` that retires the `Pend` entry, so while `Pend`
does not cover it the event is in the counter line. If `l` is not a lag lane, `C[l] ≤
P.entry[l].seq`, so the event was in a counter line that `l`'s cut core read for its half of
`P` or earlier; it was applied at once, unless more than three events arrived between two
reads, which marks `l` wild. A later CLEAR clears the bit only if it was generated at seq `y`
with the level physically empty at `y` (every segment reclaimed, §7.8), `y < fwd_pend` and its
publication `≤` its half's floor. Physical emptiness at `y` means every position assigned before
`y` was dead for every step from then on (§7.8). If the level is non-empty at `C`, the live
order was written after `y`, so its SET came after the CLEAR, and `remove_level` dropped the
CLEAR from `held`, or the SET re-set the bit after the CLEAR. If the CLEAR is applied, the floor
means every step from now on uses a half-publication `≥ P'` with `P'.entry[l].seq ≥ y`, and
`y < fwd_pend ≤ h[l]` lets the clamp of §3.3 reach `y`, so the step's `C[l] ≥ y`, where the level
was empty: no live order exists, and there is nothing to miss. ∎ Draft 0.1 exempted only "the source"; the steps after a
source step had the same gap, which the lag-lane clause closes.

### 7.3 Resync of a wild lane

The cut core reads the lane's occupancy bitmap for each side (8 lines + summary), then the
lane's `CounterLine.seq` again as `y`. It ORs the bitmap into column `l`, and for every column bit
that the bitmap does not have, it pushes a held CLEAR with seq `y`. Then it removes `l` from
`wild`. A level that is empty in the bitmap was empty at some instant before `y` was read, so the
CLEAR at `y` satisfies the condition of Lemma 7.1.

### 7.4 Applying fill events (boundary step B1)

```rust
fn apply_fill_events_through(l: &mut Lane, f: StepId) {
    while let Some(ev) = l.fill_ring.peek() {           // events are in (step, ordinal) order
        if ev.step > f { break }
        let r = l.root(ev.handle);
        match ev.kind {
            Fill   => l.settle_fill(r, &ev),            // §7.5, taker and maker alike
            Rested => l.write_explicit_position(r, &ev),  // the source rests: write its position
            Dep    => l.apply_dependency(r, &ev),       // rested: write position; canceled:
                                                        //   tombstone + clear bit; BUSY: nothing
            Out | Reject => l.end_order(r, ev.qty_out(), &ev),   // releases the remainder
            Phase  => l.phase = ev.phase(),
            Band   => l.band = ev.band(),
            Uncross => l.on_uncross(&ev),               // §8.8
        }
        l.mirror_tx_records(&ev);                       // retention copy of TX-core packets
        l.fill_ring.pop();
    }
    l.fills_applied = f;                                // published as CounterLine.f_lo
}
```

`Rested`, `Dep`, `Out` and `Reject` for a forwarded op are the final status of the op and of its
dependencies from their step. The lane writes an explicit op's position, tombstone and mask bits
here, with the op's own `LaneSeq` as `ins_seq`/`tomb_seq`, and emits the occupancy SET before it
publishes `f_lo` (Lemma 7.1). Every response record of these ops, and every maker `Fill` and maker
`Out { STP }`, was sent by the fill TX core in the step (01 §14.14); the lane only settles the
ledger and mirrors the packets (same `resp_seq`) into the session's retention buffer for resends
(`04`). Mirroring is a function of the events, so the bytes match. None of this work is on a
latency path.

### 7.5 Settling a fill in the ledger

```rust
fn settle_fill(l: &mut Lane, r: RootIx, ev: &FillEvent) {
    let o = &mut l.order[r]; let a = &mut l.acct[o.acct_ix];
    let v = slot(ev.vslot);                             // the version that traded
    let n = ev.qty as u64 * px(ev.tick);
    // Maker and auction fills pay now; a taker fill adds n to the step's taker notional,
    // which TakerEnd charges once (10 §4.4).
    let fee = match ev.liq {
        MAKER   => fee(n, a.fee.maker_ppm),
        AUCTION => fee(n, a.fee.auction_ppm),           // liq = 2, uncross fills (§8.8)
        _       => { l.taker_notional += n; 0 }
    };
    match v.side() {
        Buy => {
            let used = ev.qty as u64 * rpl(v.tick);     // limit of the version that traded
            let paid = n + fee;
            a.quote_resv -= used; a.quote_free += used - paid; a.base_free += ev.qty as u64;
            o.resv -= used;
        }
        Sell => {
            a.base_resv -= ev.qty as u64;
            a.quote_free += n - fee;
            o.resv -= ev.qty as u64;
        }
    }
    l.fee_acc += fee as i128;
    o.filled += ev.qty;
    if o.filled == o.total_cur && o.pend == 0 { l.finish(r) }   // releases o.resv, frees slots
}
```

Every subtraction is checked. A failed check is an engine fault (§14.3), never a reject: §2.6
shows that it cannot happen when the BBO core is correct.

### 7.6 Settling ops (boundary step B2, the ack-after-cut queue)

The pending queue `pend` holds one entry per op that waits for its cut position, in `LaneSeq`
order: `Ack`, `CancelAck`, `ReduceAck`, `ReplaceAck`, `CancelAllAck`, `Forwarded` (also for each
dependency).

```rust
fn settle_through(l: &mut Lane, c: LaneSeq) {          // c = min(C_f[l], applied), §6.2
    while let Some(p) = l.pend.front() {
        if p.seq > c { break }
        let o = &mut l.order[p.root];
        match p.kind {
            Ack => if o.taker_filled(p.seq) < o.total_at(p.seq) {   // it rested at entry
                       l.stage(Ack { handle: o.handle, tick: o.tick, tag: o.tag }) },
            CancelAck => {
                let open = o.total_at(p.seq) - o.filled_before(p.seq);   // fills of versions
                if open == 0 { l.stage(Reject(TOO_LATE)) }               //   ended by p.seq
                else { l.stage(CancelAck { canceled: open }) }
                l.finish_version(p.root, p.seq);                         // release, free
            }
            ReduceAck   => l.settle_reduce(p),         // CancelAck { canceled: min(r, open) }
            ReplaceAck  => l.settle_replace(p),        // TOO_LATE if the old version's open = 0,
                                                       // else Ack { handle, tick' }; true-up resv
            CancelAllAck => l.settle_cancel_all(p),    // CancelAck per order, handle order, then summary
            Forwarded   => {}                          // its status came as events in B1
        }
        if l.phase_frozen_at(p.seq) { l.restage(p, Reject(AUCTION_PHASE)) }   // §2.5 P4
        l.pend.pop();
    }
}
```

**Why `open` is exact here.** A version ended by op `t` can trade only at steps `< pos(t)`
(at `pos(t)` and later its tombstone is inside the cut). `t ≤ C_f[l]` gives `pos(t) ≤ f`. B1 has
applied every event of every step `≤ f`. So the lane holds every fill the version will ever
have. `filled_before(t)` sums the fills whose `vslot` is a version ended at or before `t`; fills
of a newer version (after a `Replace`) do not count.

**Acks wait for the cut (`INV-ACK-AFTER-CUT`).** Every `Ack` and `CancelAck` of a local op is
staged in B2 for `t ≤ C_f[l]`, and `C_f` is a cut that step `f` used and logged. Forwarded ops
and their dependencies get their records from their own step, which positions them (F2).

### 7.7 Latency of a local ack (a maximum)

```
op applied, counter published ─► its cut core reads it          ≤ 100 ns (CUT_REFRESH_NS)
  ─► the BBO core finishes the step in progress                  ≤ ENG_STEP_MAX_NS = 15
  ─► the next step takes that half-cut and finishes              ≤ 15
  ─► order-stream core queues the step's frame, writes LaneCut[l] ≤ 40
  ─► lane polls LaneCut within ENG_UNIT_NS, even inside another packet (§6.1)   ≤ 20
  ─► frame-gate check, B1–B3 with the pre-built response, lane TX doorbell     ≤ 10 + 20
```

Every arrow is bounded by construction: the cut core's pass is fixed work, a BBO step is capped
(D14), a stream core's frame is fixed work per step, and the lane's poll interval is a code property.
The first four arrows are ≤ 160 ns when the BBO core is between steps (the 01 §14.2 term) and
≤ 170 ns in the worst case, when a 15 ns step is in progress and another one takes the cut.
Deadline admission uses the worst case (§6.8). This is why every step kind is capped at 15 ns:
a 70 ns step would make it 280 ns.

### 7.8 Physical maintenance

These actions change memory but never logical state. They run in `idle_work`, in bounded slices
of ≤ `ENG_IDLE_SLICE_NS`.

| Action | Allowed when | Why it is safe |
|---|---|---|
| Clear a position's `pend` bit | the position's `ins_seq` and `tomb_seq` (if any) are `≤ LaneCut[l].cut` | every current and later step's cut is `≥ C_f[l]` (F1), so the bits alone answer it (§4.6) |
| Clear a position's `active` bit after a fill or a BBO kill | its root's `open = 0` or `killed` is known from an event of a step `≤ f` | no step `> f` can see it as live |
| Retire a segment: unlink it from its FIFO (predecessor's `succ`, or the head word) | all 16 positions assigned and none `active` or `pend`, or the level is empty | no current or later step finds a live position in it; a BBO walk that is inside it reads `succ`, which still points forward |
| Clear the level head (level now physically empty) | after its last segment is retired | emits a CLEAR event; Lemma 7.1 |
| Reuse a segment: `gen += 1`, clear masks, then write positions | retired, and `done_step ≥ σ + ENG_QSBR_LAG`, where `σ` was `done_step` at the retire (reader epoch) | a BBO step holds segment references only within one step, except head-cache cursors, which carry `gen` (§5.3) |
| Push a dead slot to the free FIFO; reuse it | at the boundary where it became settled-dead; reuse after its position's segment is retired or the slot is no longer named by any position, and `ENG_QSBR_LAG` steps | the free FIFO's order is a function of boundaries only |
| Write lazy tombstones for a `CancelAll` | any time before the next `CancelAll` of the account | `AcctKill` already hides those orders (§4.7) |
| Trim journal entries | `seq ≤ LaneCut[l].cut` | later batches start above `C_f[l]` |

**Reader epoch and ABA (Lemma 7.2).** `SnapshotLine.done_step` is the BBO core's reader epoch.
A step that starts after `done_step = σ` cannot hold a reference taken before `σ` except a
head-cache cursor. (a) A segment retired at `σ` is reused only after `done_step ≥ σ + 2`, so no
step that could have read it before the retire is still running, and a step that reads it
between the retire and the reuse sees only dead positions and a valid `succ`. (b) A cursor
`(seg, gen, pos)` kept across steps is used only if `seg.gen == gen` both before and after the
BBO core reads the segment (the lane bumps `gen` before it rewrites anything); a reused
segment has `gen + 1` (wrapping at 2^32 reuses of one segment: > 4 × 10^9 retires of one
block, more than an epoch can do, `ENG_SEG_CAP` ≥ 2^18), so the check fails and the BBO core
restarts that lane from its head word. (c) A slot index found in a valid segment names the slot
written for that position, because the slot is not reused while a live segment names it. So
neither a segment nor a slot is read under a stale identity. ∎

**Slot allocation is deterministic.** `alloc_root` and `alloc_version` pop the head of the free
FIFO. The FIFO's order is fixed by the order stream, so slot numbers, and hence `Handle` values
in `Ack` records, match in replay. If the head is not yet physically reusable, the lane spins
on it (latency only). The logical cap `ENG_SLOT_CAP − ENG_FREE_MIN` on live plus pending slots
(reject `RISK_ORDER_COUNT`) keeps the FIFO at least `ENG_FREE_MIN` deep, so the head was freed
at least `ENG_FREE_MIN` frees ago and the spin does not happen in practice.

**Generation wrap.** A root slot's generation repeats after 256 reallocations of that slot.
With a FIFO at least `ENG_FREE_MIN = 2^18` deep, that needs ≥ 2^26 frees on the lane: ≥ 3.3 s
at the lane's peak of 20M ops/s (budget). A handle also must match the session (§4.2), so an
alias can only hit an order of the same session. A client that sends a `Cancel` for a handle more
than 3 s after its terminal response may cancel its own newer order. `04` states this rule.
Aliasing is deterministic, so it never forks replicas.

## 8. The BBO core

### 8.1 Step kinds

| `StepKind` | Source | Book effect (§2) | Emitted when |
|---|---|---|---|
| Code | `StepKind` | Source | Book effect (§2) | Emitted when |
|---|---|---|---|---|
| 1 | `Cross` | forwarded op | dependencies, then `match_on_entry`, ≥ 1 fill; `CONT` flag: a continuation | the op traded |
| 2 | `Improve` | forwarded op | dependencies, then `match_on_entry`, no fill (rests, or is rejected or killed) | the op did not trade |
| 3 | `Rescan` | none | no-op in L; the engine executes the crossing batch entries here | band test fires (§8.6) |
| 4 | `Depletion` | none | no-op | a bound level is found empty and moved (§8.7) |
| 5 | `Idle` | none | no-op | a new half-cut would advance the cut and no ring has an entry |
| 6 | `Shed` | forwarded op | the op and its dependencies: `Reject BUSY` | `now > FwdEntry.deadline` at step start (§6.8) |
| 7 | `Control` | control ring | phase (incl. `Frozen`) or band | §8.8, §13 |
| 8 | `Seal` | control ring | none; ends the epoch's L | 08 asks for the epoch's last step |
| 9 | `Uncross` | control ring | one chunk of the auction allocation; the last chunk sets `Continuous` | §8.8 |

The codes are this chapter's (§17 R11 asks 01 to adopt them; 01 §14.10 names the kinds).
`StepRecord.src_lane_seq = 0` means "no source". A step with a source sets `StepEntry.flags`
bit 1 `CROSS` from its `FwdEntry` (§4.12): the kind is what the step did, `CROSS` is how the lane
routed the op, and the two differ for a Cross that ends without a fill or an Improve that trades.
The record of a `Rescan` carries the band in
`StepEntry.band_lo/hi`; request R2 asks 01 to add it to `StepRecord`.

`Seal` is issued by 08 while the book is `Frozen` or `Halted`, once every lane's counter is in
the cut; its `StepId` is `HandoffRecord.last_step` (`INV-FENCE`), and later book ops get the
phase's reject at once.

### 8.2 Main loop

```rust
fn bbo_main(b: &mut Bbo) -> ! {
    loop {
        let P = (b.read_newest(A), b.read_newest(B));  // two half-cuts, seqlocks, CCD-local
        let heads = b.poll_fwd_rings();                 // §8.4; after P (load order matters)
        b.retire_pend(&P);                              // Pend entries with f_lo ≥ their step
        let ctl = b.control_ring.peek();                // a control command takes precedence
        let src = if b.cont.is_some() { b.cont }        // a continuation runs first (§8.5)
                  else if ctl.is_some() { None } else { b.pick_source(&heads) };
        let C = b.step_cut(&P, &heads, src);            // §3.3, §8.3
        let band = if b.phase == Continuous { b.band_test(&C) } else { Band::EMPTY };
        if !band.is_empty() {
            let Cr = b.partial_rescan_cut(&C, band);     // bounded batch, §8.6
            b.exec_rescan(&Cr, band);                   // one step; b.cut = Cr afterwards
            continue                                    // the source, if any, waits one pass
        }
        if let Some(c) = ctl.filter(|_| src.is_none()) { b.exec_control(c, &C); continue }
        match src {
            Some(e) if b.clock.now_ns_lo32().wrapping_sub(e.deadline) as i32 > 0
                    && !e.is_continuation() => b.exec_shed(e, &C),     // §6.8, Shed
            Some(e) => b.exec_forwarded(e, &C),         // Cross or Improve, or a continuation
            None if C != b.cut => b.exec_idle(&C),      // Idle, or Depletion if a bound is stale
            None => b.idle_work(),                      // §8.11, no step
        }
    }
}
```

Each `exec_*` ends with `b.finish_step()`:

```
1. append the StepEntry (and its delta lines) to StepLog              → order-stream core
2. push this step's FillEvents to each affected lane's FillRing       → lanes (in ordinal order)
3. push the TxEntries: deps packet, source packet, one per maker session → fill TX core
4. if B, A or phase changed: version += 1, record (B, A) in history, write SnapshotLine
5. write SnapshotLine.done_step = s (Release); BboFloor = (P_A.pub_id, P_B.pub_id) (Release)
6. b.cut = C; s += 1
```

Order 1-before-3 lets the fill TX core check `FramesOut ≥ s` before it sends (`INV-FRAME-FIRST`,
01 §14.5). Order 2-before-5 lets a lane that sees `done_step` or `LaneCut` for `s` find every
event of `s` in its ring. A `Shed` step costs the same as an `Improve` and writes one `TxEntry`
(the `BUSY` records) and one `Reject` event per op.

### 8.3 Step cut

```rust
fn step_cut(b: &Bbo, P: &(CutPub, CutPub), heads: &Heads, src: Option<FwdEntry>) -> Cut {
    let mut C = b.cut;                                     // C_{s−1}
    for l in 0..N_LANES {
        let k = P.half(l).entry[l].seq;                    // half A for l < 25, else half B
        let h = heads.floor[l].unwrap_or(u64::MAX);        // dependency floor, §3.3
        C[l] = max(C[l], min(k, h - 1));
    }
    if let Some(e) = src {                                 // the source rule of §3.3
        let l = e.lane;
        let k = max(P.half(l).entry[l].seq, e.lane_seq - e.applied_back as u64);
        C[l] = max(b.cut[l], min(k, heads.next_floor[l].unwrap_or(u64::MAX) - 1, e.lane_seq));
    }
    C
}
```

`heads` must be read after `P` (Acquire on each half's `newest`, then Acquire on each ring head
word). The lane pushes a FwdEntry and marks its dependencies before it publishes any counter past
the dependency floor, so every explicit op with `seq ≤ P.entry[l].seq` is in `heads` and clamps
`C[l]` below itself. The two halves need not be from the same instant: F1–F3 are per lane.

### 8.4 Choosing the source

- `poll_fwd_rings` keeps, per lane, the next ring slot's address. A poll of an unchanged ring is
  an L1 hit (~1 ns). The BBO core polls all 50 in one pass (~50 ns worst, ~25 ns typical with
  the lanes' lines in L1). When a lane writes an entry, the next poll misses and fetches it
  (~70–100 ns cross-CCD, vendor-class); the poll also prefetches the next two ring lines, which
  hold the entry's `FwdDep` lines when it has any, so they arrive in the same round trip.
- `pick_source` takes the ring head with the smallest key `(prio_ts, rank_e(lane), lane_seq)`.
  The BBO core does not wait for a lane that may have an earlier entry in flight: aggressors are
  ordered by arrival at the BBO core among the visible heads, and by key among those. The choice
  is logged in `StepRecord.src_*`, so replay does not repeat it (§10).
- Starvation is impossible: a ring's head is replaced only by entries with larger keys, so every
  head becomes the minimum after finitely many steps.
- A `Control` entry (halt, phase, band, uncross; from core 51) is executed before ring heads, at
  most one per loop pass.

### 8.5 Executing a forwarded op

```rust
fn exec_forwarded(b: &mut Bbo, e: FwdEntry, C: &Cut) {
    let t = b.decode_taker(&e);                            // side, tick, qty, flags, version
    let mut out = StepOut::new(e);
    b.mark_explicit(&e);                                   // BboVer bit 1: source, Join deps
    b.apply_deps(&e, &mut out);                            // §3.7 (4): index order, below
    if b.phase != Continuous { return b.finish_noncontinuous(t, out) }   // §2.5 P1
    if t.kind == NewPrio && !b.replace_ok(&t, C) {         // old version's open was 0 at q
        return b.end(t, &mut out, Reject(TOO_LATE))
    }
    if t.post_only && b.would_cross(&t, C) {
        return b.end(t, &mut out, Reject(POST_ONLY_WOULD_CROSS))
    }
    if t.tif == Fok && b.dry_run_fillable(&t, C) < t.open() {           // no mutation yet
        return b.end(t, &mut out, Reject(FOK_UNFILLABLE))
    }
    b.resume_or_sweep(&mut t, C, &mut out);                // below; may stop at the step cap
    if out.capped { b.cont = Some(e.continuation()); return b.finish_step_with(out.cont()) }
    b.cont = None;
    match (t.tif, t.open()) {
        (_, 0)          => {}                              // fully filled
        (Ioc | Fok, q)  => b.end(t, &mut out, Out(IOC_REST, q)),
        (_, q)          => b.rest(t, &mut out),            // B or A moves to t.tick; Rested;
    }                                                      //   a Pend entry until the lane writes it
    out.kind = if out.n_fills > 0 { Cross } else { Improve };
    b.finish_step_with(out);
}

fn apply_deps(b: &mut Bbo, e: &FwdEntry, out: &mut StepOut) {
    for d in e.deps() {                                    // FwdDep lines, index order
        match d.kind {
            Join   => { b.pend.insert(e.lane, d, e.prio_ts, e.lane_seq − d.back);   // a leaf
                        out.dep_record(d, Ack) }           // W's Ack; fills/STP follow in order
            Cancel => { let o = b.open_of(e.lane, d.slot);                 // at this point of L
                        b.kill(e.lane, d.slot);            // BboSlotState.killed on its root
                        out.dep_record(d, if o == 0 { Reject(TOO_LATE) }
                                          else { CancelAck { canceled: o } }) }
        }
    }
}

fn sweep(b: &mut Bbo, t: &mut Taker, C: &Cut, out: &mut StepOut) {
    let side = t.side.opposite();
    while t.open() > 0 {
        if out.levels == 1 || out.n_fills >= ENG_STEP_FILLS {
            out.capped = true; return                      // D14: continue in the next step
        }
        let lvl = b.bound(side);                           // A for a buy taker, B for a sell
        if lvl == EMPTY || !t.can_trade_at(lvl) { break }
        let tree = b.level_tree(side, lvl, C, t.lane);     // cached for the touch, else built
        let mut level_qty = 0;
        while t.open() > 0 && out.n_fills < ENG_STEP_FILLS {
            let Some(run) = tree.pop_run(C) else { break } // one lane, one segment, keys < k2
            for m in b.segment_run(&run, t, C) {           // AVX-512 pass, below
                if m.lane == t.lane && t.stp != Stp::None && b.acct_of(&m) == t.acct_ix {
                    match t.stp {                          // own maker, incl. a Pend dependency
                        CancelNewest => { b.kill_taker(t, out, STP, &m); return }
                        CancelOldest => { b.kill_maker(&m, out, STP); continue }
                        CancelBoth   => { b.kill_maker(&m, out, STP); b.kill_taker(t, out, STP, &m);
                                          return }
                    }
                }
                let q = min(t.open(), m.open);
                b.filled[m.lane][m.root] += q; t.filled += q; level_qty += q;
                out.maker_fill(&m, lvl, q);                // ordinal += 1, event + maker TxEntry
                if t.open() == 0 || out.n_fills == ENG_STEP_FILLS { break }
            }
            tree.reseat(run.lane, C);                      // next live position of that lane
        }
        if level_qty > 0 { out.taker_fill(t, lvl, level_qty) }   // one taker Fill per level
        out.levels += 1;
        if t.open() > 0 && !out.capped { b.advance_bound(side, lvl, C) }   // next level
    }
}
```

**The segment pass.** `segment_run` turns one leaf's run into makers with no pointer chasing:

```rust
let fill  = _mm512_i32gather_epi32(_mm512_load_epi32(&g.slot), bbo_state(lane), 4);
let open  = _mm512_sub_epi32(_mm512_load_epi32(&g.qty), _mm512_and_epi32(fill, FILLED_MASK));
let live  = _mm512_cmpgt_epi32_mask(open, ZERO) & !_mm512_test_epi32_mask(fill, KILLED)
          & active(g.mask) & !pend(g.mask) & !g.vmask & run.from_mask();
let early = key_lt_mask(_mm512_add_epi64(g.base_ts, widen(g.dts)), rank, run.k2);
// positions live & early, in order; a prefix sum of `open` stops where the taker runs out.
// pend / vmask positions in `early` go through version_at (§5.1) one by one.
```

It reads the segment's three lines once and gathers 16 `filled` words from `BboSlotState`
(BBO-private, L1/L2 near the touch). STP needs a maker's account only when the maker's lane is
the taker's lane: one slot-line read per such position. `Pend` leaves are merged at their keys.

- `bound(side)` is `A` or `B`. `advance_bound` scans `occ` masks from `lvl` away from the
  spread for the next index with any bit set and a live `lane_head` (inline depletion). Outside
  the window it reads overflow pages lane by lane (§11.4).
- `can_trade_at(lvl)`: buy `lvl ≤ t.tick`; sell `lvl ≥ t.tick`.
- `dry_run_fillable` walks a copy of the touch tree (2.1 KB copy) and temporary trees for deeper
  levels, applying the STP skip/stop rules of §2.4, and stops at `t.open()`. It writes nothing.
- `would_cross` is `t.can_trade_at(bound(opposite))` followed by one `pop_live` peek; it is exact
  because the bound level is revalidated (if it is empty, `advance_bound` runs first, read-only).
- `replace_ok`: for a `NewPrio` version, compare `filled[root]` with the old version's total
  (`pred_total`, §4.3). It is checked once per version and cached in `BboVer` (§4.11).
- `rest` sets `B = max(B, t.tick)` for a buy (`A = min(A, t.tick)` for a sell) and emits
  `Rested { qty: open }`. The position was assigned in pass 1 (D4); a `Pend` entry stands in for
  it until the lane writes it at the boundary that applies this step (§7.4).
- `kill_*` sets `killed` in `BboSlotState` and emits the end to the owner's lane; the record
  itself goes out in the step's TX-core packets (§8.10). `kill_maker` emits `Out { cause: STP }`.
  `kill_taker` follows 04 §6.8 and §2.4's `stp_end`: on the op's first step (not a `CONT` step)
  with the taker's open qty unchanged since the sweep began, it emits `Reject { reason: STP,
  detail: m.handle }`. Otherwise (after a fill, on a `CONT` step, or for a `Rescan` batch taker,
  whose order already rested) it emits `Out { cause: STP, qty: open }`.
- **`Pend`** holds `{ lane, side, tick, key, slot, root, qty, step }` per explicit resting op or
  Join dependency (`ENG_PEND_CAP` = 256 entries). `retire_pend` drops an entry when its lane's
  half-cut shows `f_lo ≥ step`: the lane has applied that step's events, so the position,
  its SET event and its mask bits are visible to every later step (Lemma 7.1). At 30M forwarded
  ops/s and a lifetime of ≤ ~400 ns, ~12 entries are live on average.
- **The step cap (D14).** A sweep stops after one level or `ENG_STEP_FILLS` = 8 maker fills,
  well inside `STEP_FILL_CAP` = 64 (01 §14.15.6), so no step exceeds `ENG_STEP_MAX_NS` = 15 ns
  (§8.12). The rest runs as continuation steps (`Cross`, `CONT`) that take precedence over every
  other source; between them the cut may advance (acks keep flowing, §7.7) and the taker is in
  flight (§2.3). A continuation is never shed: it already traded. The cap is a count, so replay
  splits a sweep at the same fills.

### 8.6 The band test and the `Rescan` step

For every lane `l` with `C[l] > C_{s−1}[l]`, the batch ops of `l` were classified against
versions in `[lowver[l], vcur]`, where `lowver[l]` is the `snap_ver` that came with the cut entry
`C_{s−1}[l]` (or the source op's `FwdEntry.snap_ver`, if `C_{s−1}[l]` was set by a source). Then:

```rust
fn band_test(b: &Bbo, C: &Cut) -> Band {
    let (mut hi, mut lo) = (b.B, b.A);                     // bounds of the book at C_{s−1}
    for l in lanes_advanced(C, &b.cut) {
        let (mb, ma) = b.envelope(b.lowver[l], b.vcur);    // max bid, min ask over versions
        hi = max(hi, mb); lo = min(lo, ma);
    }
    if lo <= hi { Band { lo, hi } } else {
        b.B = hi; b.A = lo;                                // widen bounds: still valid, no cross
        Band::EMPTY
    }
}
```

- Outside `Continuous` there is no band test: no step matches (§8.8).
- `envelope` scans the snapshot history when `vcur − lowver ≤ ENG_ENV_SCAN` (usual: 0–2
  versions). Otherwise it uses two monotonic deques over the history (amortized O(1)). If
  `lowver` is older than `ENG_SNAP_HIST` versions, it returns `(TICK_MAX, 0)`: the lane is
  suspect at every price.
- An auction or halt version (flag bit 0) has envelope `(TICK_MAX, 0)`: in those phases lanes
  join at any price, so a batch classified against them is suspect everywhere.
- When the band is empty, the bounds widen to `(max over envelopes, min over envelopes)`.
  Lemma 9.8 shows that they remain bounds of the true book. Widening can only make the next
  snapshot's spread narrower than the true spread: the safe direction.

`lowver[l]` is updated by `finish_step`: it becomes `P.entry[l].snap_ver` when `C[l] =
P.entry[l].seq`, it becomes `e.snap_ver` for the source lane, and it is unchanged when the clamp
held `C[l]` below `P.entry[l].seq` (the older value is still a valid lower bound).

**The `Rescan` step.** It executes `B_s` restricted to the band, in key order:

```rust
fn exec_rescan(b: &mut Bbo, C: &Cut, band: Band) {
    let Cp = b.cut;                                        // C_{s−1}
    let mut ents = KWayMerge::new();                       // by key, across lanes
    for l in lanes_advanced(C, &Cp) {
        ents.add(journal(l).range(Cp[l] + 1 ..= C[l]).filter(|j| band.contains(j.tick)));
    }
    let mut out = StepOut::rescan(band);
    for j in ents {                                        // key order: §3.4 inside B_s
        if !matches!(j.kind, New | NewPrio) { continue }   // tombstones act via visible_at
        let mut t = b.taker_from_slot(j);                  // a join, now treated as a taker
        if !b.live_at(&t, C, &Cp, j.key) { continue }      // ended earlier in the batch
        if t.post_only && b.would_cross_at(&t, C, &Cp, j.key) {
            b.kill(t, &mut out, Reject(POST_ONLY_WOULD_CROSS)); continue
        }
        b.sweep_at(&mut t, C, &Cp, j.key, &mut out);       // sweep with visible_at(…, key)
    }
    b.recompute_bounds_in(band, C);                        // exact top on both sides
    out.kind = Rescan;
    b.finish_step_with(out);
}
```

- Batch entries outside the band cannot cross and cannot be crossed (Lemma 9.6), so the step
  skips them.
- `sweep_at` is `sweep` with two changes: makers must satisfy `visible_at(…, key)` (§5.2), and the
  maker trees are built from `lane_head` walks that also accept batch entries with a smaller key.
  Both work per segment: a leaf is a `(lane, segment)` run, and inside a run the positions are in
  key order, so the k-way merge compares one key per lane and advances inside a segment with
  `tzcnt` on the run mask. A batch entry's position is in its lane's segment chain (independent
  ops are written before their counter publish), so `visible_at` applies to it like any position.
- **Partial cut, warm lines (D14).** A `Rescan` must fit 15 ns, so it may not wait for a
  cross-CCD journal line. When the band test fires, the BBO core first takes an `Idle` step whose
  cut holds the suspect lanes at `C_{s−1}` and prefetches their journal lines; the next step is the
  `Rescan`, with the lines warm. `partial_rescan_cut` keeps the in-band batch entries
  `≤ ENG_RESCAN_MAX` = 1 per step: it lowers
  `C[l]` of the lanes with the most in-band entries, never below `C_{s−1}[l]`, and the next steps
  take the rest. Any cut in that range is a valid step cut (§3.3) and is logged, so the result is
  exact (Lemma 9.7) and replay does not repeat the choice. A stalled lane's large backlog becomes
  a run of short `Rescan` steps instead of one long one.
- A join that `Rescan` fills is the taker: it gets `liq = 1` fill events. A join that it does not
  touch stays as it was: resting, unchanged.
- `exec_rescan` with a non-empty band and no crossing entries is legal and changes nothing but
  the bounds. A band computed wider than necessary therefore never changes the output
  (superset corollary of Lemma 9.7); replay can use any superset of the band.

### 8.7 The `Depletion` step

The bounds `B` and `A` can sit on levels that cancels have emptied. Matching corrects this
inline (`advance_bound`). The idle path corrects it eagerly, so that lanes see a tight snapshot:

```
exec_idle(C):
    if occ(B) has no lane with a live lane_head at C, or occ(A) likewise:
        advance_bound on that side (read-only walk); kind = Depletion
    else kind = Idle
    finish_step()   // publishes a new version if a bound moved
```

A `Depletion` step changes no order. It is logged because it positions the batch `B_s` and
consumes a `StepId`.

### 8.8 Auction mode (engine side; `08-epochs.md` owns the rule)

`08` decides when an auction starts and ends and how the clearing price is chosen; the engine
provides the phase machinery, the histograms and the allocation. Draft 0.1 stalled the BBO core
for tens of µs while lanes built histograms, delaying every ack; draft 0.2 freezes the book and
allocates in 15 ns `Uncross` steps, so every response during an auction keeps the 1 µs bound.

```
Continuous ──Control(Auction)──► Auction ──Control(Frozen)──► Frozen ──Uncross × m──► Continuous
     │                              ▲
     └──Control(Halted)──► Halted ──┘ (Control(Auction); a halt ends by auction)
```

1. **Enter Auction or Halted.** A `Control` step `s_a` sets the phase, publishes a snapshot with
   the auction flag and empty sides, and sends a `Phase` event to every lane. From `s_a` on, no
   step matches. Lanes route every admitted `New` as `Local` (§6.5); IOC/FOK are rejected
   `AUCTION_PHASE`; in Halted every `New` and `Replace` is rejected `BOOK_HALTED`. The book may
   become crossed. `INV-UNCROSSED` still holds, because the published snapshot has empty sides.
2. **Freeze.** `08` asks for the close. A `Control` step `s_f` sets phase `Frozen` with cut
   `C*` = `C_{s_f}` and writes `UncrossReq { step: s_f, cut: C*, lo, hi }` into the box line
   `AuctionCtl` (BBO-written, lane-read), `lo..=hi` = the auction collar (≤ `ENG_AUCTION_TICKS`).
   From the lanes' `Phase` events on, every book op is rejected `AUCTION_PHASE` (§2.5 P4), and
   ops positioned after `s_f` but admitted earlier are rejected at settle and tombstoned at
   their own seq. So the book at every later step until the uncross is the book at `C*`. The BBO
   core keeps running `Idle` steps: acks, cancels' rejects and every other response keep the
   1 µs bound.
3. **Histograms.** Each lane walks its segments in `lo..=hi` in idle slices, sums `open` of every
   order visible at `C*[l]` that is not killed, and writes its `AuctionHist` buffer (lane-written,
   control-core-read): `buy[i], sell[i]: u64` for `i = tick − lo`, then `ready = s_f` (Release).
   Lane cost: ~2 ns per order in the collar (budget), never more than `ENG_IDLE_SLICE_NS` at a time.
4. **Price, off the BBO core.** When all lanes are ready, the control role on core 51 sums the 49
   histograms into cumulative demand `D(p) = Σ_{t ≥ p} buy[t]` and supply `S(p) = Σ_{t ≤ p}
   sell[t]` and calls `08`'s pure function:

   ```rust
   pub fn uncross_price(d: &[u64], s: &[u64], lo: Tick, reference: Tick) -> Option<(Tick, u64)>;
   // returns (clearing tick p*, matched qty Q) or None if nothing crosses
   ```

   It posts `Uncross { p*, Q }` on the control ring. The inputs are lane state at `C*`, so a
   replica's control role computes the same `(p*, Q)` (§10).
5. **Allocate in chunks.** Buys at `tick > p*` and sells at `tick < p*` fill fully. At `p*`, the
   side with more volume fills in merged-FIFO order (key order) until `Q`. The BBO core walks the
   merged segment FIFOs from the best price inward with the same trees as `sweep`, using
   visibility at `C*`, and emits fills at price `p*` with `liq = 2` (01 §14.10; `10` sets the fee
   rule). Each `Uncross` step allocates at most `ENG_UNCROSS_CHUNK` = 6 fills (≤ 15 ns), and the
   BBO core runs the chunks back to back, with `Idle` steps between them when a cut is waiting.
   Fills carry the `StepId` of their chunk; ordinals follow buys-then-sells per merged order
   inside each chunk. Because the book is frozen, splitting the allocation into chunks changes
   nothing but the `StepId`s, which are logged.
6. **Auction-only orders.** After the last chunk `s_u`, every visible auction-only order with
   `open > 0` is dead (§2.5 P2). The `Uncross` event of `s_u` to lane `l` carries `C*[l]`; the lane
   ends each such order with `Out { cause: AUCTION }` at B1.
7. **Continuous again.** `s_u` publishes the exact bounds and sets phase `Continuous`. Lanes that
   classified ops under the auction version are suspect at every price until they refresh
   (§8.6 envelope rule), so any order that crosses the new book is caught by `Rescan`.

`uncross_price` is a pure integer function, part of `INV-DET`. The freeze lasts ~2 ns per collar
order plus ~2.5 ns per fill (budget); 08 bounds it (`ENG_FREEZE_MAX_US`) and tells clients. It is
a market-structure rule, not a latency exemption: every message in it is answered within 1 µs.

### 8.9 Fill events and the step log

| Output of step `s` | Ring | Content |
|---|---|---|
| `StepEntry` | `StepLog` | kind, source, changed cut entries, band, `fill_lanes`, `CONT`, `CROSS` |
| maker `Fill` | `FillRing[maker lane]` | one per fill, `liq = 0` (`2` in an uncross) |
| taker `Fill` | `FillRing[taker lane]` | one per level, `liq = 1` (for the `LaneSeq` source and for Rescan takers) |
| `Rested`/`Out`/`Reject`/`Dep` | `FillRing[taker lane]` | final status of the source op, of each dependency, or of a Rescan taker |
| `Out(STP)` for a maker | `FillRing[maker lane]` | maker removed by STP |
| `Phase`/`Band`/`Uncross` | every `FillRing` | control steps |
| `TxEntry` role 1 | `TxRing` | the dependencies' records in index order (each `Ack`/`CancelAck`, then a Join dependency's own maker `Fill` or `Out(STP)`), on the first reserved `resp_seq` |
| `TxEntry` role 0 | `TxRing` | the source's records: `Fill` per level, then `Ack`/`Out`/`Reject`; a continuation's records on the session's `MakerSeq` |
| `TxEntry` role 2 | `TxRing` | one packet per maker session hit in the step: its `Fill`s (and `Out(STP)`s), numbered from `MakerSeq` (01 §14.14) |

The fill TX core builds each packet from its `TxEntry` and the session's TX state (address,
`K_out`; installed at session open by the control path, `04`). It sends nothing of step `s`
before `FramesOut.step ≥ s` (`INV-FRAME-FIRST`). Auction (`Uncross`) fills are not caused by a
request packet; their lanes send them after B1, like other unsolicited records.

**Fill TX budget per step (01 §14.14, §14.15.3).** Each client port has one fill TX core
(01 §14.17.3, 06 §2.3 rule 3): TX-A (core 3) writes NIC0, TX-B (core 5) NIC2 and TX-C (core 0) NIC1
and NIC3, so a session's packets go out from the TX core of its lane's card. Each reads the step's `TxEntry`s as soon as the
BBO core writes them, and builds and tags its packets (8-way AVX-512 SipHash, ~15 ns for up to 8,
budget) while the stream cores frame the step (the 60 ns gate). After the gate only the CTPIO
writes are serial, per core: `t_tx = 10 + 8k` ns for the source packet and `k` maker packets on
the same core. A step has ≤ 8 maker fills, so `k ≤ 8` on one core in the worst case (all makers
on one card): `t_tx ≤ 74` ns. At index 9 the taker's fill leaves at 880 ns (§11.1) and the last
maker's ≤ 880 + 64 = 944 ns, inside `LAT_MAX_NS − DEADLINE_GUARD_NS`. A continuation step's
makers leave ~15 ns per step later, so at index 9 about five steps (≤ 40 fills) fit; §18 Q15.

### 8.10 Responses and packetization

`INV-DET` covers every response byte, so the grouping of records into packets and the
assignment of `resp_seq` are fixed by these rules. All are functions of lane state at
boundaries and of step outputs.

1. **Forwarded message.** In pass 1 the lane reserves `resp_seq = r` for it, and `r, r + 1` if it
   has dependencies (§6.6). The dependency packet (`r`) and the source packet (`r` or `r + 1`)
   hold exactly their `TxEntry` records, `echo_pkt = pkt_seq`. The fill TX core sends them. A
   `Shed` step sends the same packets with `Reject { BUSY }` records.
2. **TX-core packets without a reservation.** Maker packets and continuation packets of a session
   take the session's next `MakerSeq` number (§4.15), `echo_pkt = 0` for makers and `pkt_seq` for
   a continuation.
3. **Immediate rejects.** In pass 1, all `Reject`s of one request packet's local messages go into
   one packet (`echo_pkt = pkt_seq`), with `resp_seq` taken after the forwarded reservations of
   earlier messages in the packet, in message order. Sent at once. A lane `BUSY` is one such
   packet for the whole request.
4. **Boundary output (B3).** For each session, in this order:
   1. Walk the settles of B2 in `LaneSeq` order. Before each settle `t`, emit the not-yet-emitted
      events of B1 that belong to a version ended by `t`, and the `liq = 1` events of the version
      created by `t` (a Rescan fill of a join), in `(step, ordinal)` order. Then emit `t`'s
      record.
   2. Then emit the remaining events of B1 in `(step, ordinal)` order.
   Records answering one request packet are packed into packets with `echo_pkt = pkt_seq`; other
   unsolicited records that the TX core did not send (auction fills) go into packets with
   `echo_pkt = 0`. A packet holds at most 16 records; `resp_seq` increases in emission order.
   Maker fills and every record the TX core sent are not emitted again (rule 5).
5. **Mirroring.** The lane writes the packets of rules 1 and 2 into the retention buffer, from
   the events of B1, with their `resp_seq`.

Rule 4.1 gives the natural order: a cancel's `CancelAck` follows every fill of the canceled
version; a join's `Ack` precedes every maker fill on it; a `Replace` shows the old version's fills,
then its `Ack`, then the new version's fills.

**Pre-built responses (the 20 ns of B3 on the ack path).** In pass 2 the lane appends each local
op's predicted record (`Ack`, or `CancelAck` with the open quantity known now) to the request's
local response packet, whose first `resp_seq` it reserved in pass 1, and absorbs it into a
SipHash state, checkpointed per record. At B3 a confirmed record costs nothing; the lane
finalizes the tag (~4 ns) and rings the doorbell. A record that changed (a fill of a canceled
order, a `Rescan` fill of a join) is re-absorbed from its checkpoint when its event appears in the
`FillRing`, ≥ 40 ns before `LaneCut` covers the op (§8.2, §4.15). The bytes are rule 4's either way.

### 8.11 Idle work and the prefetch plan

When `bbo_main` finds no source and no new cut, it spends ≤ `ENG_IDLE_SLICE_NS` on, round robin:
revalidating 4 touch leaves per side (segment mask line, `AcctKill` line, head word; changed
lines are refetched), prefetching the three lines of each touch winner's segment and successor,
keeping the trees of the next levels (`B − 1`, `A + 1`) warm at half the rate, and running an
`Idle`/`Depletion` step if a touch tree is empty. Ring lines are prefetched by polling (§8.4).
This is what keeps a cross step at 15 ns (§8.12).

### 8.12 BBO budget

Budgets at 5 GHz, with the prefetch plan in place (no cross-CCD miss on the critical path except
the FwdEntry itself, which is counted in the hop).

| Step | Work | ns |
|---|---|---|
| any (included in every row below) | read two half-cuts (CCD-local), compute cut (SIMD), clock read for the deadline (pipelined), `retire_pend`, band test, `finish_step` (StepEntry, events, TxEntries, snapshot, floor) | 3 |
| Improve, Shed, Depletion | decode, bound compare, `rest` (one `Pend` insert) or one `advance_bound` word scan, event, TxEntry | ~3 |
| Cross, 1 level, ≤ 2 makers in one run | head prefetched by the poll (§11.3), one segment pass (3 lines in L1/L2, 16-lane gather, compare, prefix sum), events, TxEntries | ~15 = `BBO_CROSS_NS` (01 §14.15.2) |
| each extra maker in the run | prefix-sum lane, event, TxEntry when a new session | +1 |
| each extra run (another lane or segment) | tree replay (6 compares), segment pass (prefetched in idle) | +3 |
| dependencies | `FwdDep` lines (arrived with the entry), `Pend` inserts, kills, records | +1 per dependency |
| a continuation step (next level) | `advance_bound`, tree of k lanes from prefetched heads, segment pass | ~15 |
| Rescan (1 entry, lines warmed by the `Idle` step before it) | merge, sweep | ~15 |
| Idle | cut + finish | ~4 |

The caps of §8.5, §8.6 and §8.8 keep every step ≤ `ENG_STEP_MAX_NS` = 15 ns; a step that the
caps allow but would exceed 15 ns is a budget error that B3 reports. At the design mix, 10M
crosses/s × 15 ns + 20M improves/depletions/s × 3 ns + ~1M dependencies × 1 ns ≈ **0.21**
(01 §14.15.2), far below `BBO_MAX_LOAD = 0.60`. The BBO shed tail is then P(wait > 90 ns) ≈ 4e-8
(01 §14.15.2). B3 checks both.

## 9. Equivalence with the sequential specification

**Theorem.** For every order stream, the parallel engine (live or replay) produces the same
responses, the same fills with the same execution IDs `(StepId, ordinal)`, and the same canonical
state as the sequential specification of §2 applied in the order L of §3.4.

The proof is a chain of lemmas. "The book at a point of L" means the sequential specification's
book after applying L up to that point.

### 9.1 L is well defined and respects lane order

**Lemma 9.1.** `pos(l, q)` exists for every op that some step's cut covers, `pos(l, q − 1) ≤
pos(l, q)`, and inside `B_s` the key order restricted to one lane is `LaneSeq` order.

*Proof.* `C_s[l] ≥ q` implies `C_s[l] ≥ q − 1`, so the first such `s` for `q − 1` is not later.
Within one lane, `prio_ts` is non-decreasing in `LaneSeq` (§3.2) and ties are broken by `seq`,
so key order is `LaneSeq` order. A `KeepPrio` version keeps its order's key but is not a batch
element of its own: the batch element is the `Reduce` op, whose key is the op's key. ∎

**Lemma 9.2 (F1, `INV-CUT-MONO`).** `C_s ≥ C_{s−1}` pointwise.

*Proof.* Every entry of the rule of §3.3, the source's included, and every partial cut, is a
`max` with `C_{s−1}[l]`. Each half's entries are monotone on their own (§7.1), but the rule does
not even need that. ∎

**Lemma 9.3 (F2).** The source `(l, q)` of step `s` and each of its dependencies `(l, x)` have
`pos = s`, and no cut before `s` covers any of them.

*Proof.* `pos = s` holds by the definition of §3.4. Before step `s` executes the entry, its
dependency floor `φ ≤ x ≤ q` bounds `h[l] ≤ φ` at every step (ring entries are consumed in order
and this one is unconsumed; an entry not yet pushed has a larger floor than every op before it,
and the lane marks the dependencies before it publishes any counter past `φ`, §8.3), so
`C_{s'}[l] ≤ φ − 1 < x` for `s' < s`. ∎

### 9.2 What a step sees

**Lemma 9.4 (exact view).** During step `s`, for every queue position of lane `l`, the BBO core
finds it live (through the segment mask, `version_at` and `live`, or as a `Pend` leaf) exactly
when the book at `S_s`'s point of L has a live order there: its op is at or before `C_s[l]` in
lane `l`'s order or is explicit at a step `≤ s`, and no op at or before that point ended it.

*Proof.* *Independent ops.* Let `x = V.ins_seq ≤ C_s[l]`. By F3 the lane wrote `V`, the position
(`slot`, `qty`, `dts`, then `mask` with `Release`) and the journal entry before it released a
counter `≥ x` that reached the BBO core through a half-cut, or through the source's FwdEntry
(`a`, §3.3); the BBO core acquired it, so it reads the final values (happens-before is
transitive). If `x > C_s[l]`, `visible` is false whatever the BBO core reads. For a tombstone,
the same argument applies to `tomb_seq ≤ C_s[l]`; a tombstone with `seq > C_s[l]` is either not
seen or seen with `seq > C_s[l]`; both give "live". *The mask.* The lane clears `pend` only when
`LaneCut[l].cut ≥` the position's seqs, and every current or later cut is `≥` that (F1), so a
non-`pend` bit answers the same as the slot check (§4.6). A mask store and the slot writes it
covers are ordered (`Release`); a mask read older than a cancel still shows `active`, which is
correct for a cut below the cancel. *Explicit ops.* The source and its Join dependencies are
`Pend` leaves until the lane writes them; the lane writes them with the `EXPLICIT` mark already
set by the BBO core, so the hand-over is seamless, and the `slot` match prevents double counting
(§5.4). A Cancel dependency sets `killed` at its own step. *Segments.* Lemma 7.2: a segment or
cursor is never read under a stale identity. For `AcctKill`, the lane finishes the old
`CancelAll`'s tombstones before overwriting `kill_seq` (§4.7). `BboSlotState` and `BboVer` have
one writer, the BBO core itself. ∎

**Corollary.** The set of live orders the BBO core sees at step `s` is the book at the end of
`B_s` in L, provided `B_s` contains no crossing op (then every local `New` in `B_s` just rests,
and Lemma 9.6 below shows that this is what L does).

### 9.3 Commutation inside a batch

**Lemma 9.5.** Let `x, y ∈ B_s` be ops of different lanes, and suppose neither trades when
applied in L. Then applying them in either order gives the same book and ledgers.

*Proof.* `x` and `y` touch disjoint ledgers (an account has one lane), disjoint slots, and
disjoint FIFOs (a lane FIFO belongs to one lane). In the book they touch only the level FIFOs,
where each is placed by its key, not by arrival. A cancel or reduce changes only its own order.
Without a trade, nothing else depends on the other. ∎

### 9.4 The crossing lemma

**Lemma 9.6 (crossing).** Let step `s` compute `[lo, hi]` by §8.6 from bounds `(B, A)` with
`B ≥` true best bid and `A ≤` true best ask of the book after `S_{s−1}`, and that book
uncrossed. Apply `B_s` in key order with matching on entry. Then every trade in `B_s` is between
two orders whose ticks lie in `[lo, hi]`. In particular, if `lo > hi`, no op of `B_s` trades.

*Proof.* Every `New` or `NewPrio` op in `B_s` is local (§3.6). A local order was classified in
`Continuous` against a version `v` with `v ∈ [lowver[l], vcur]` (§6.5, the `lowver` rule of §8.6), so a
buy has `tick ≤ b_v ≤ mb_l ≤ hi` and a sell has `tick ≥ a_v ≥ ma_l ≥ lo`. An order classified
under an auction or halt version gives `mb_l = TICK_MAX`, `ma_l = 0`, which only widens the band.
Every resting bid of the pre-batch book has `tick ≤` true best bid `≤ B ≤ hi`; every resting ask
has `tick ≥` true best ask `≥ A ≥ lo`. Cancels and reduces add no order and change no tick.
So at every point of `B_s`, every bid has `tick ≤ hi` and every ask has `tick ≥ lo`. A trade
needs a bid tick `≥` an ask tick: the buy order's limit `p_b` and the sell order's limit `p_s`
satisfy `p_s ≤ p_b` (the maker's tick lies between them). Then `lo ≤ p_s ≤ p_b ≤ hi`. ∎

**Same snapshot (DESIGN's form).** If every op in `B_s` used one version `v` and the pre-batch
bounds equal `(b_v, a_v)`, then `hi = b_v < a_v = lo`, so nothing crosses. The general form
above covers different versions: they can cross only inside `[min a, max b]`, the range the BBO
core moved through since the oldest version in use.

**Lemma 9.7 (Rescan is exact).** If `lo ≤ hi`, then `exec_rescan` produces the same trades,
fills and final book as applying `B_s` in key order with matching on entry.

*Proof.* Split `B_s` into in-band ops `I` and out-of-band ops `O`. By Lemma 9.6 no op of `O`
trades, and no op of `I` trades with an order outside the band. An op of `O` is a join that
rests outside the band, or a cancel or reduce of an order outside the band, so it does not
change any order in the band: it commutes with every op of `I` (Lemma 9.5 extended: the only
interaction is through the band, which `O` does not touch). So L's result is: apply `I` in key
order, then `O`. `exec_rescan` iterates `I`'s journal entries in key order (k-way merge of
per-lane runs, each in `LaneSeq` = key order). For each `New`/`NewPrio` entry with key `k` it
matches against makers that satisfy `visible_at(…, k)`: exactly the orders that exist at `k`'s
point of L (pre-batch orders not ended before `k`, plus batch orders created before `k` and not
ended before `k`). Cancels and reduces are not executed as actions; they act through
`visible_at`, at their key. That is matching on entry at `k`. The `O` ops are already linked and
need no action. ∎

**Corollary (superset bands).** Running `exec_rescan` with any band `⊇ [lo, hi]` gives the same
result, because an extra in-band op either trades in L (then it is in `[lo, hi]`) or does not
(then the sweep finds no maker and leaves it resting). So a replica may use a wider band.

### 9.5 Bounds and the safe direction

**Lemma 9.8 (bounds).** After every step in `Continuous`, `B ≥` true best bid, `A ≤` true best
ask, and `B < A`, where "true" means the book after `S_s`.

*Proof by induction.* Initially both sides are empty. Step `s`:
- *Batch.* If the band is empty, the batch only adds bids `≤ hi` and asks `≥ lo` and removes
  orders, and the BBO core sets `B := hi`, `A := lo` with `hi < lo` (§8.6). If the band is not
  empty, `exec_rescan` recomputes the exact top (`recompute_bounds_in`), and the book is
  uncrossed after it because matching on entry leaves no crossing pair (§2.4).
- *Cross/Improve.* The sweep moves `A` (for a buy) only past levels it found empty or exhausted,
  so `A` stays `≤` true ask; it stops at a level the taker cannot trade at, or with the taker
  filled. A resting residual at `p` sets `B := max(B, p)`; the sweep stopped because the next
  live ask is `> p` (or the side is empty), so `p < A`. A rejected or killed source leaves the
  book and the bounds unchanged.
- *Depletion.* `advance_bound` moves a bound only past levels with no live order at `C_s`.
- *Cancels* inside the batch lower the true bid or raise the true ask, which keeps both
  inequalities.
So the inequalities hold and `B < A`. ∎

**Corollary (`INV-UNCROSSED`).** Every published snapshot is a pair `(B, A)` from Lemma 9.8, or
has empty sides (`Auction`, `Halted`). So `bid < ask` or a side is empty.

**Lemma 9.9 (stale only in the safe direction).** Let a lane classify an order against version
`v`, published by step `s_v` with bounds `(b_v, a_v)`. Suppose no step after `s_v` moved a bound
inward, that is, the only changes since are cancels, fills of resting orders, and joins
classified against `v`. Then (a) if the order crosses the book at its position in L, the lane
forwards it, and (b) if the lane keeps it local, the true best bid stays `≤ b_v` and the true best
ask stays `≥ a_v` after it.

*Proof.* Under the assumption, true bid `≤ b_v` and true ask `≥ a_v` at every point after `s_v`
(cancels and fills only lower the bid and raise the ask; joins against `v` have buy `≤ b_v` and
sell `≥ a_v`). (a) A buy that crosses has `tick ≥` true ask `≥ a_v`, so `classify` forwards it.
(b) A kept buy has `tick ≤ b_v`. ∎

Lemma 9.9 is the DESIGN statement "a stale snapshot sends extra orders to the BBO core, never
fewer". When a step does move a bound inward (an improve or a residual), versions older than that
step are no longer safe on their own; Lemma 9.6 and the `Rescan` step cover that case exactly.

### 9.6 The forwarded step

**Lemma 9.10.** `exec_forwarded` at step `s` produces the same result as `S_s` = matching on
entry of the source op on the book after `B_s`.

*Proof.* By Lemmas 9.4–9.7 the live orders at `C_s` are the book after `B_s` (if the band fired,
a `Rescan` step processed the batch first and the source runs at a later pass). `apply_deps`
applies the dependencies in index order (Lemma 3.7 (4)). The sweep visits levels in price order
from the bound: `advance_bound` misses no non-empty level, because the masks are conservative
(Lemma 7.1), wild and lag lanes are probed, `Pend` leaves are merged, and levels outside the
window are read from the lanes directly. At a level it takes makers in `(prio_ts, rank)` order
across lanes (the tree) and in position order within a lane; positions were assigned in key
order and never move (§4.6), and a run stops at the runner-up's key (§5.4), so the fills are in
key order, which is `best_maker`'s order. The STP, FOK, post-only and IOC branches are the same as
§2.4 line by line; the FOK dry run reads the same sequence without writing. `replace_ok`
implements the `TOO_LATE` rule of `Replace`, because after `pos(q)` only the new version can
change `filled[root]` and it cannot trade before its first check. A continuation resumes the
same loop on the book at its own point of L (§2.3). ∎

**Lemma 9.15 (shed is replayable and in-order).** A `Shed` step's effect is a function of the
log, and equals the sequential outcome with the op and its dependencies rejected `BUSY`.

*Proof.* The decision (`now > deadline`) is the only clock read; its result is the step's kind,
which is logged, and replay reads it (§10). The step applies nothing to the book (§2.3), the lane
writes no position or tombstone for those ops (§7.4), and their reservations are released from
the `Reject` events at a logged boundary. Lemma 3.7 (5) gives the in-order outcome. A lane's
`SHED` record takes no `LaneSeq` and changes only the session's `resp_seq`, which the record
fixes. ∎

### 9.7 Cancel against fill

**Lemma 9.11 (cancel-vs-fill is deterministic).** For a `Cancel` op `t` of order `o`: (a) the
fills of `o`'s ended version are exactly those of steps `< pos(t)`; (b) `pos(t)` is a function of
the logged cuts; (c) the lane's answer is `TOO_LATE` if those fills sum to the version's open
quantity, else `CancelAck { canceled: total − fills }`; (d) live and replay compute the same
answer at the same boundary.

*Proof.* (a) For `s ≥ pos(t)`, `C_s[l] ≥ t`, so the tombstone is visible and `visible` is false
(Lemma 9.4). For `s < pos(t)`, the tombstone is outside the cut. (b) `pos(t)` is defined from
`C_s`, which `StepRecord.cut` carries. (c) is §7.6. (d) The lane answers at the first boundary
with `t ≤ C_f[l]`, `f = fills_applied`; `f` is in the `PacketRecord` and `C_f` in the
`StepRecord`; at that boundary the lane has applied all events of steps `≤ f ≥ pos(t)` (B1), so
by (a) it has all fills of the version. ∎

The same argument covers `Reduce`, `Replace` and `CancelAll` (through `AcctKill`).

### 9.8 Lane determinism and `INV-ACK-AFTER-CUT`

**Lemma 9.12.** The state of lane `l` after each boundary, and the responses it emits there, are
functions of the order stream and the data.

*Proof.* A boundary applies B1 (events of steps `≤ f`), B2 (settles `≤ min(C_f[l], applied)`),
B3 (packing rules of §8.10, a function of B1–B2's output and lane state); then pass 1 and pass 2
of the packet (the data; the routing of each message is read from the log in replay, §10). `f`
and the boundary's position (between packets, or `MID` before a logged op and pass) are logged,
so `applied` is known. Step
outputs are functions of the order stream by induction: step `s` reads lane ops `≤ C_s[l]`, each
processed at a boundary whose `f < s` (the lane applied the events of `f` before it processed and
published the op, and step `s` read the published op after step `f` finished). So the
dependency graph of steps and boundaries is acyclic, and induction along it works. The schedule
of `LaneCut` updates, the timing of B1–B2 and of idle work do not appear in any of these
functions. ∎

**Lemma 9.13 (`INV-ACK-AFTER-CUT`).** Every `Ack` and `CancelAck` is sent after a logged step
cut includes its op.

*Proof.* Local ops: staged in B2 only for `t ≤ C_f[l]`, where `C_f` is step `f`'s cut, and sent
only after `LaneCut` for `f`, which its stream core writes after step `f` is framed (frame gating, §4.15).
Forwarded ops and dependencies: staged in their step's `TxEntry`; the step positions them
(Lemma 9.3) and its record logs the source, from which replay derives the dependencies. The
`StepEntry` is written before the `TxEntry` (§8.2), and the fill TX core sends only after
`FramesOut ≥ s`. ∎

### 9.9 Physical choices do not matter

**Lemma 9.14.** The following never change any output: the window center and re-centering; the
occupancy masks and `wild`; the head cache and its cursors; polling order; prefetching; the
free-FIFO spin; the schedule of `pend`-bit clears, segment retires and reuses, and of `LaneCut`
writes; the `Pend` table's lifetime; the phase offset between the two cut cores; whether a
pre-built response was confirmed; the snapshot values (beyond the routing they cause, which is
logged as step sources and `Rescan` steps).

*Proof.* Each item changes only where the BBO core looks, when, or how fast. Lemmas 9.4, 7.1 and
9.10 show that the BBO core finds the same live orders whatever the masks, cache or window
contain, as long as the masks are conservative. Lemma 9.12 shows that lane outputs do not
depend on schedules. Routing: for any routing, Lemmas 9.6–9.10 prove equality with L, provided
each step's band covers its crossing ops, which §8.6 guarantees for the versions the lanes
actually used. ∎

**Proof of the theorem.** Apply L element by element. A batch `B_s` without crossing ops equals
the engine's state change at `C_s` (Lemmas 9.4, 9.5, 9.6). A batch with crossing ops is executed
by a `Rescan` step (Lemma 9.7). A source step equals `S_s` (Lemma 9.10), a `Shed` step its
`BUSY` outcome (Lemma 9.15), a packet's ops in L give its index-order outcome (Lemma 3.7), and
pooled lanes keep one writer per field and a logged account order (Lemma 6.1).
Ledgers and responses are lane functions of the stream (Lemma 9.12), and cancels resolve
identically (Lemma 9.11). Fill ordinals are assigned in the order the engine executes trades
within a step, which is the order L applies them. ∎

## 10. Replay mode

A replica runs `vyrn-engine` with the same lane, BBO and settlement code. Three inputs change
(01 §11.6):

| Live | Replay |
|---|---|
| NIC RX queues → `process_packet` | `PacketRecord` + data (by `pkt_hash`) → `process_packet`; the record's `rx_ts` is the timestamp |
| deadline admission at the lane | `PacketRecord.flags.SHED`: answer `BUSY`, apply nothing; no clock is read |
| `LaneCut` polls inside a packet | `MID` Advance records: run the boundary before the named op and pass |
| two cut cores → half-cuts | `StepRecord.cut` is the step's cut `C_s`; `step_cut` and partial-cut choices are not repeated |
| `pick_source` over ring heads, band test, the BBO deadline test | `StepRecord.src_*`, `kind` (incl. `Shed`, `CONT`, `CROSS`) and the `Rescan` band (request R2; without it, the band is all ticks, which is correct by the superset corollary of Lemma 9.7) |
| `LaneCut[l]` read by the lane | `PacketRecord.fills_applied = f` and `C_f[l]` from `StepRecord f` |
| snapshot routing in `classify` | an op that a `RouteRecord` names (01 §6.6) takes its route (`cross`); the replayed pass 1 then forwards it or rejects it as live, and a forwarded op is the one a `StepRecord` names as `src = (l, q)`, whose `flags.CROSS` must agree. Every other op is local (`Join`). The step kind never gives the route (§4.12) |
| dependency lists in `FwdEntry` | recomputed from the packet's bytes by the replayed pass 1 (§6.6: a function of the messages and lane state) |
| core 51's `uncross_price` | the replica's control role computes it from its own lanes' histograms at `C*` |
| pool token CAS and stealing (§6.9) | `AcctTake { account, ver, lane }` records: a lane waits at one until the account's previous `ver` is replayed |

**Routes (10 M8).** Lane risk charges a `New` or new-priority `Replace` by its route before it
forwards or rejects it, so replay must give pass 1 the live route, not one derived from the step
kind or the replayed snapshot. The lane writes a `RouteRecord` for every op it classifies `Cross`
or `Improve`, forwarded or rejected by itself (for example by a cross bucket), in pass 1,
into its order ring after the packet's `PacketRecord`. The route travels with its packet: the
`StepRecord` that names a forwarded op can fall in a later block. `StepRecord.flags.CROSS`
repeats a forwarded op's route, and `replay_step` checks it. `vyrn-lane`'s
`Lane::replay_packet(vis, p, clock, mids, routes)` takes the packet's route records as `routes`.

**Scheduler.** The replica schedules lanes and the BBO core as a dataflow:

- Lane `l` may run the boundary of record `r` once steps `≤ r.fills_applied` are done.
- Lane `l` may run pass 1 for op `q` once it has `q`'s packet and route records: the route
  records say which ops are classified, and the replayed pass 1 forwards or rejects them as live.
  Dependencies follow from pass 1.
- The BBO core may run step `s` once every lane has run pass 1 for its source and pass 2 for
  every independent op `≤ C_s[l]`.

Lemma 9.12 shows that this graph is acyclic, so the scheduler never deadlocks. `vyrn-replica`
runs it with the same pinned threads as live or, in `vyrn-sim`, on one thread in a fixed order.
Both give the same bytes.

**Why the output is bit-identical (`INV-DET`).** Every decision of §6–§8 reads only packet
bytes and `rx_ts`; `LaneSeq` positions, `fills_applied`, boundary positions, `SHED`, `AcctTake`
and step cuts, sources and kinds (all in the order stream); state built from those; and book
parameters installed by `Control` steps or at epoch start (§13). No decision reads a clock except
the two logged deadline tests, a random number, a hash-map order, a float, or a ring's fill level
(§14.2). Lemma 9.14 covers the physical choices. Integer overflow is a checked reject or a fault
(§14.3). Replay needs no cut core, masks, snapshot line or TX cores; its BBO core keeps `(B, A)`
for `Rescan` and `advance_bound` and publishes nothing.

**Check.** B4 (DESIGN §9 #4) replays a live log on a separately built replica and compares the
state hash and every fill. `vyrn-sim` also feeds the same stream to `vyrn-vx-oracle` and compares
`oracle_state_hash` after every element of L (§2.8).

## 11. Performance

### 11.1 Latency paths (bare metal `REF`, budget, 01 §14.2)

Message index `i` = 0..9 of a packet of `n` messages; the worst case is `i = n − 1 = 9`.

```
Cross fill (forwarded op that trades), index 9                       index 9   index 0
  NIC RX: first bit in → RX completion visible to the lane (ef_vi)      320       320
  pre-pass: age check, session, MAC, prefetch                            45        45
  pass 1 up to and including message i (5 per message)                   50         5
  push FwdEntry (+ FwdDep lines)                                         10        10
  lane → BBO hop: poll pass + one cross-CCD round trip                  100       100
  BBO step: deadline test, cut, band, deps, segment sweep, events        15        15
  frame gate: stream cores frame the step (TX cores build, MAC)          60        60
  TX core of the taker's half: CTPIO (makers follow, §8.9)               40        40
  NIC TX: CTPIO → first bit on the wire                                 240       240
                                                               total    880       835

Join or cancel ack (local op), index 9 of 10
  NIC RX                                                                320       320
  pre-pass                                                               45        45
  pass 1 of all n messages                                               50        50
  pass 2 up to and including message i (9 per message)                  90         9
  logged cut via LaneCut (cut ≤ 100, BBO step 20, stream core 40)       160       160
  lane notices LaneCut (poll interval ENG_UNIT_NS)                       20        20
  frame gate (already open: LaneCut follows the frame)                   10        10
  B1–B3 with the pre-built response, lane TX doorbell                    20        20
  NIC TX                                                                240       240
                                                               total    955       874
```

Index 0 is 45 ns faster on the cross path and 81 ns faster on the ack path (01 §14.2 says "~90").
The cross path is 01 §14.15's 880 ns. The ack path adds the 20 ns "lane notices" term (the lane's
poll interval, §6.1), which 01 §14.2's 935 ns list leaves out: a lane in the middle of another
packet cannot notice `LaneCut` in zero time.

**What is a maximum and what is not.** Every lane term is a maximum by construction (fixed work,
warm lines after the commit point, the 20 ns poll interval). The BBO-side terms of the cross path
are protected by the BBO core's deadline test: an op that would leave later than `LAT_MAX_NS −
DEADLINE_GUARD_NS` is shed before it trades (§6.8). The ack path has no shed after the commit,
so its maximum is the worst case of §7.7: **965 ns** at index 9 of 10 (the cut term is 170,
not 160, when a 15 ns step is in progress and another one takes the cut). The admission table
(§6.8) uses that worst case, so no accepted packet is late. Each maker fill of the taker's first
step leaves ≤ 64 ns after the taker's (§8.9).

### 11.2 Cross-CCD traffic (budget at 1B msgs/s, 100M packets/s)

| Line | Direction | Transfers/s | GB/s |
|---|---|---|---|
| `FwdEntry` + `FwdDep` lines | lanes → CCD 0 | 30M + ~3M | 2.1 |
| maker segment lines (3 per segment), head words, `AcctKill` (prefetched) | lanes → CCD 0 | ~45M | 2.9 |
| `CounterLine` reads (two cut cores, 25 lanes each) | lanes → CCD 0 | ≤ 250M (1 per lane per 100 ns pass while the lane is busy, ~0.45 of passes) | 16 |
| `MakerSeq` lines | lanes → CCD 0 | ~3M (one per 8 maker packets of a session) | 0.2 |
| journal lines (Rescan only) | lanes → CCD 0 | ≤ 2M | 0.1 |
| `OsRing` (`PacketRecord`, pre-encoded) | lanes → CCD 0 | 100M records, ~50M lines | 3.2 |
| `SnapshotLine` | CCD 0 → lanes | ≤ 100M (one per packet when changed) | 6.4 |
| `LaneCut` lines | CCD 0 → lanes | ≤ 100M | 6.4 |
| `FillEvent`s | CCD 0 → lanes | ~30M events, ~15M lines | 1.0 |
| `FwdCons`/`FillCons` (only when a ring looks full) | both | ~0 | 0 |

Into CCD 0: ~25 GB/s. Out of CCD 0: ~14 GB/s. Vendor figures for one Zen 5 CCD's link to the
I/O die are about 64 GB/s read and 32 GB/s write at FCLK 2 GHz. The two cut cores' 100 ns passes
are the largest item; B3 measures it (§18 Q1). The `SnapshotLine` and `LaneCut`
reads are invalidation-driven: each costs one transfer only if the line changed since the
lane's last read, so idle or slow lanes cost less.

### 11.3 Prefetch plan

| Core | What | When |
|---|---|---|
| lane | the next RX descriptor and payload of each VI | at the top of each loop |
| lane | `SnapshotLine`, `LaneCut[l]` | at the top of each loop, consumed after the RX parse |
| lane | for every message of the packet: the `SlotAux`/`RootAux` and slot line of a `Cancel`/`Reduce`/`Replace` handle, its segment's mask line, the session's account line, the level tail segment | in the pre-pass, all at once; `wait_lines` waits for them before the commit point (§6.3) |
| lane | the free-FIFO head slot and the next free segment | after each allocation |
| cut cores | their 25 `CounterLine`s each | at the start of each pass |
| BBO | touch leaves' segment lines, `AcctKill` lines, next segments, next level's tree | idle slices (§8.11) |
| BBO | the next two ring lines (`FwdDep`), the source lane's head word at the touch, the taker's first target level | when a poll finds a new FwdEntry, before the step starts |
| BBO | `occA`/`occB` words ahead of `advance_bound` | during a sweep, one word ahead |

A `Cancel` whose lines are in DRAM costs ~90 ns (vendor DDR5 latency). The pre-pass issues it
with the other messages' prefetches, so a packet with several cold cancels pays one DRAM latency,
not several, and pays it before the commit point, where the admission check sees it (§6.8).

### 11.4 Sweeps across many levels

Inside the window, `advance_bound` scans `occ(side, ·)` one word pair per 32 levels (L1/L2) and
stops at the first non-zero word with a live head. For each level with `k` lanes present, the
BBO core builds a temporary tree from `k` head segments; with one-level-ahead prefetch the cost
is ~15 ns (§8.12). A level costs one step, so a sweep of `m`
levels is `m` steps of ≤ 15 ns, and acks of every lane keep flowing between them. Outside the
window, it reads each lane's overflow bitmap: ~50 × 70 ns per page touched, which exceeds one
step; the collar keeps every sweep inside the window (§13.2), and a configuration whose collar
does not is rejected by `11`.

### 11.5 Memory

Reference config, 1 GB huge pages, ≈ 8.7 GB: `OrderSlot` arenas 49 × 2^20 × 64 B ≈ 3.2 GB;
`Segment16` arenas 49 × 2^18 × 192 B ≈ 2.4 GB; `SlotAux` + `RootAux` ≈ 2.4 GB; `BboSlotState` +
`BboVer` ≈ 250 MB; directories, tails, bitmaps ≈ 5 MB; overflow pages ≈ 106 MB; journals 49 MB;
rings ≈ 118 MB; session, account and pool tables ≈ 80 MB. A lane's hot set (sessions, accounts,
level arrays, recent slots and segments) is ~3–4 MB, inside its share of the CCD's 32 MB L3
(vendor); the BBO core's is < 2 MB. DRAM bandwidth is dominated by NIC DMA (~24 GB/s each way)
against ~460 GB/s of 12-channel DDR5-4800 (vendor).

### 11.6 Worst-case and adversarial inputs

| Input | Effect | Bound | Mitigation |
|---|---|---|---|
| All liquidity at one level (49 lanes × many orders) | one tree of 49 leaves; runs within a segment | +1 ns per maker in a run, +3 per run; ≤ 8 fills per step | none needed; a cross's cost is linear in makers it hits, which the taker's qty bounds; ≤ 3 maker sessions per step |
| Cancel storm on head orders at the touch | each canceled head costs a mask-line refetch (~70 ns) in the next segment pass | ≤ 1 miss per changed segment per step; idle revalidation removes most before the cross | lane rate limits (`04`); cancels are cheap for lanes, and the BBO core pays per segment, not per order |
| 1000-level sweep | one continuation step per level | ≤ `ENG_BAND_MAX_TICKS` steps of ≤ 15 ns; other sources wait, and are shed if they become late; acks keep flowing | collar caps the levels (§13.2); empty levels cost ~0.1 ns each via masks; the sweep's later maker fills are §18 Q15 |
| One account floods one lane | that lane's budget is used by one account; other lanes unaffected | lane at 100% load; late packets get `BUSY` at ~20 ns each; the leaf-switch policer bounds the backlog (§6.8) | per-session rate limit (`04`); a market maker that needs more spreads over sub-accounts on several lanes (DESIGN §3) |
| One account toggles many levels empty↔non-empty | more than 3 occupancy events per cut pass | lane goes wild; BBO probes that lane's head word at each level it scans | wild costs ≤ 1 line per level per sweep; cut core resyncs in ≤ 16 lines |
| Oscillating BBO (improve, then sweep, repeatedly) | envelopes of lanes with old versions overlap the new bounds; `Rescan` steps | one in-band entry per `Idle` + `Rescan` pair, 2 × 15 ns | each oscillation needs a forwarded op (fee per cross, DESIGN §3); lanes refresh within one packet, so bands close within ~300 ns |
| Stalled lane holds an old `lowver` | that lane's next batch is suspect everywhere | a run of short `Rescan` steps when it resumes (partial cuts, §8.6) | bounded by its batch size; journals give the entries |
| Generation wrap | handle alias after 256 reuses of one slot | ≥ 3.3 s (§7.8) | session check; free-FIFO depth `ENG_FREE_MIN` |
| Huge `CancelAll` (65,536 orders) | O(1) on the critical path (`AcctKill`), lazy tombstones in idle | ~130 µs of idle lane time, ~2 ns per order | the next `CancelAll` of the same account waits for the lazy work; `ENG_CANCELALL_EAGER` caps the multi-session case |
| Many forwarded ops from one lane | FwdRing fills; lane stalls (§14.2) | BBO throughput | `CROSS_CAP`; crosses priced per message type |

### 11.7 The ceiling, tied to the budgets

- Lanes: `49 × (1 / LANE_NS_PER_MSG) × 0.6 ≈ 1.0B msgs/s` is the budget ceiling (42 dedicated +
  7 pooled lanes, 01 §10). At 1B msgs/s spread evenly, each lane takes ~2M packets/s: 185 ns each
  = **0.37** busy on the packet path, 225 ns = **0.45** in total (§6.7); a pool core adds ~20 ns
  of token CAS per packet.
- BBO core: 10M crosses/s × 15 ns + 20M improves or depletions/s × 3 ns ≈ **0.21** (§8.12).
- Fill TX cores: ~30M source and ~20M maker packets/s at ~13 ns each (build 3, SipHash share 2,
  CTPIO 8) split over three cores: **~0.22** each, within 01 §14.15.3's 0.25 (01 §14.17.3).
- Stream cores: ~50M `PacketRecord`s/s and 30M steps/s each, framing and `LaneCut`: 07 owns the
  budget (Q2).
- Cut cores: one 100 ns pass each, back to back: busy 1.0 by design, like a poll loop.
- So one book takes 1B msgs/s while forwarded ops are ≤ 3% and crosses ≤ 1% of messages. The
  consumer box (11 lanes) gives `11 × 33.3M × 0.6 ≈ 220M msgs/s` with the same BBO core.

### 11.8 The `BUSY` rate

`BUSY` happens when a packet's age at dequeue (or at the commit point) exceeds `980 −
path_ns[n][kind]`: 460 ns for one message, 335 ns for ten (§6.8). The age is the actual NIC RX
time plus the lane's queueing wait.

- **A single shared server cannot meet `BUSY ≤ 1e-6`.** A model of Poisson arrivals at 2M
  packets/s and 185 ns service (ρ = 0.37, 4M packets, measured on the model) gives:

  | wait `w` (ns) | 5 | 50 | 150 | 300 | 600 | 1000 |
  |---|---|---|---|---|---|---|
  | P(wait > w) | 0.36 | 0.30 | 0.15 | 0.035 | 2.0e-3 | 4.7e-5 |

  With 5–130 ns of slack, a shared single-core lane would shed 10–36% of packets. This is the
  gap that 01 §14.15 closes with lane classes.
- **Dedicated, paced lanes: lane-stage `BUSY = 0`** (01 §14.17.2). A paced client never queues
  in its lane (§6.9); its packet waits at most one `ENG_UNIT_NS` = 20 ns work unit. For
  ten-message packets this needs `RX ≤ 315 ns` (335 − 20), 5 ns below the 320 ns RX budget;
  one- to eight-message packets have ≥ 20 ns of margin. So lane-stage `BUSY = 0` holds for every
  packet size only if B1 qualifies RX at ≤ 315 ns, or if the work unit for dedicated lanes is
  ≤ 15 ns (§18 Q13). The BBO, TX and stream cores are shared by every client, so a dedicated
  client's BBO-bound op can still be shed there: total `BUSY ≤ 1e-5` at full book load and
  `≤ 1e-8` at ≤ 20% load (01 §14.17.2, B3).
- **Pooled lanes: M/M/c with c = 7.** 01 §14.15.1 gives ≈ 1e-3 at full book load and ≤ 1e-6 at
  ≤ 20% load; the token CAS (~20 ns) and a steal (~20 ns) come out of the same slack. B3
  publishes the measured curve.
- **BBO shed:** at ρ ≈ 0.21 with 15 ns steps, P(wait > 90 ns) ≈ 4e-8 (01 §14.15.2).

## 12. Fairness

### 12.1 Time priority across 4 NICs

- Every packet's `rx_ts` is the NIC's hardware RX timestamp in PTP time (TAI). The four NICs'
  PHCs are disciplined by `06-platform.md` to a common clock with skew ≤ `ENG_PHC_SKEW_NS`
  (budget 20 ns; 06 owns the number and its measurement).
- A lane polls its 4 VIs and always processes the packet with the smallest `rx_ts` among the
  heads that are present. A packet that arrives at the lane later than a packet with a larger
  `rx_ts` (DMA or PCIe reordering) gets `prio_ts = max(rx_ts, last prio_ts)` (§3.2). The clamp
  raises a timestamp by at most the RX-completion skew between VIs (budget ≤ 100 ns, measured by
  B1-style captures). That is the only intra-lane deviation from pure `rx_ts` order.
- Across lanes, resting priority is exactly `(prio_ts, rank_e(lane))`: no core's timing enters.
- **Passive against aggressive** has cut granularity: a join's position relative to a cross is
  decided by whether the step's cut includes it, which depends on the 100 ns cut period
  (`CUT_REFRESH_NS`, per half). The DESIGN states this, and this chapter keeps it. Inside one
  packet the order is the index order (Lemma 3.7).
- **Pooled lanes**: a stolen packet keeps its own `rx_ts`; its `prio_ts` is clamped to the
  thief lane's previous `prio_ts` like any packet of that lane (§3.2), so stealing can delay a
  priority by at most the pool's queueing time, never reorder one session (§6.9).
- **Aggressor against aggressor**: forwarded ops are taken in key order among the FwdRing heads
  that are visible when the BBO core polls (§8.4). Two crosses from different lanes that arrive
  within one hop time (~100 ns) can execute in either order relative to their `rx_ts`.

### 12.2 Tie-break rotation

Equal `prio_ts` across lanes is broken by `rank_e(l) = (l + e) mod N_LANES`. Over `N_LANES`
consecutive epochs every lane holds every rank once. With 3 epochs per day, one full rotation of
49 lanes takes ~16 days. `04` publishes `rank_e` per epoch in the `EpochNotice` data.

### 12.3 What the engine does not promise

- It does not order two packets of one session by anything but `pkt_seq` (they share a lane).
- It does not equalize lanes' load. Account → lane assignment (`10`) is the only balancing tool.

## 13. Book parameters

All parameters are fixed at epoch start from the epoch's configuration (`08`), or changed by a
`Control` step (logged). No parameter changes on a clock.

### 13.1 Tick ladder and quantities

| Parameter | Type | Rule |
|---|---|---|
| `tick_size` | decimal, display only | price = `tick × tick_size` (01 §3) |
| `QUOTE_PER_TICK_LOT` | u64 | quote atomic units for 1 lot at 1 tick; `px(t) = t × QUOTE_PER_TICK_LOT` |
| `lot_size` | u64 | base atomic units per lot |
| `TICK_MIN`, `TICK_MAX` | Tick | `1 ≤ TICK_MIN`, `TICK_MAX ≤ 2^24 − 1` (`ENG_LADDER_PAGES × 4096`); tick 0 is "no bid" |
| `ENG_MIN_QTY` | Qty | 1 lot |
| `ENG_MAX_ORDER_QTY` | Qty | ≤ 2^31 − 1; per book |
| max notional | u64 | `qty × rpl(tick)` must fit in u64; checked at entry, else `BAD_QTY` |

A `New` with `tick ∉ [TICK_MIN, TICK_MAX]` is `BAD_TICK`; `qty ∉ [ENG_MIN_QTY, ENG_MAX_ORDER_QTY]`
is `BAD_QTY`. The ladder is linear in v1. A non-linear ladder (tick size by price band) is
expressed as a linear ladder at the finest tick plus a per-band "allowed tick" bitmap checked at
entry (`BAD_TICK`); v1 does not use it.

### 13.2 Price band (collar)

```
ref      : Tick   the band reference: the last trade tick, or the auction price
half     : u32    ENG_BAND_HALF_TICKS (≤ ENG_BAND_MAX_TICKS / 2)
band     : [ref − half, ref + half] ∩ [TICK_MIN, TICK_MAX]
update   : when a step's last trade tick differs from ref by more than ENG_BAND_HYST ticks,
           the same step sets ref := that tick and emits a Band event to every lane
```

- Lanes check every `New` and `Replace` tick against the band they hold (lane order). That band
  comes from `Band` events applied at boundaries, so the check is replayable.
- The band limits the limit price, so a cross sweeps at most `2 × half` levels. With
  `half ≤ 512` and the window layout of §4.6, every sweep stays inside the window while the center
  is within `ENG_RECENTER_DRIFT = 256` ticks of the mid.
- Resting orders outside a moved band stay in the book; they can trade at their own price.

### 13.3 Halts

- An operator halt arrives on the control ring from core 51 (`vyrn-admin`). The BBO core executes it
  as a `Control` step: phase `Halted`, `Phase` events to every lane.
- In `Halted`: `New` and `Replace` are rejected `BOOK_HALTED` (lane order view); `Cancel`,
  `Reduce`, `CancelAll` work; no step matches; forwarded ops that reach their step are rejected
  `BOOK_HALTED` (§2.5 P1).
- A halt ends with `Control(Phase = Auction)`, a freeze and an uncross (§8.8). The engine has no
  automatic circuit breaker in v1; `10` may add one as a rule that issues `Control` steps from
  logged data.

## 14. Failure inside the box

### 14.1 A lane core stalls

The control role (core 51) watches every lane's `CounterLine.lock`. A lane republishes it at least
every `ENG_BEAT_NS` (budget 1 µs) even when idle.

| Silence | Action |
|---|---|
| < `ENG_LANE_STALL_NS` (20 µs) | count it (`eng_lane_gap{lane}`); every response the gap made late is counted in `eng_late_resp` (§14.5). The BBO core keeps running (§14.4). |
| ≥ `ENG_LANE_STALL_NS` | alert, metric `eng_lane_stall{lane}`; the box keeps running |
| ≥ `ENG_LANE_DEAD_NS` (1 ms) | **fail-stop the sequencer**: the control role tells both stream cores to stop sending frames and all three fill TX cores to stop sending responses. Replicas see silence and fail over after `FAILOVER_SILENCE_MS` (`07`). |

**Why not take over the lane on a spare core.** A wedged thread can resume at any instruction and
write lane memory; inside one process it cannot be fenced except by killing the process, and two
writers would fork the state silently. Fail-stop turns the fault into a 20 ms published outage.
(A pool core's packets are stolen by its siblings while it stalls, but its tokens and segments
cannot be, so the same rule applies to it.)

**Cooperative handover to a spare core (57, 59–63).** The control role can move a healthy lane
(for example on corrected machine-check errors): it sets the lane's handover request; the lane
finishes its packet, writes `CounterLine.state = Parking`, then `Parked` (`Release`), and spins;
the new thread on the spare core, which has already warmed the lane's ~4 MB hot set and polls the
same ef_vi VIs (busy polling needs no re-bind, 06), sets `Running` and continues at the next
boundary. No logical state changes. Packets that wait during the switch (~300 ns, budget) are
admitted or answered `BUSY` by the normal test, so none is late. The control role schedules
handovers in a freeze window (§8.8) when it can.

### 14.2 Rings and buffers that fill

Every policy stalls the producer; none drops or rejects after the order stream has the input.
A lane takes its ring space for the whole packet (`OsRing` entry, journal entries, `FwdRing`
lines for every `New`/`Replace` with its worst dependency count, slots, positions) in the
pre-pass, before the commit point. So a lane stall happens before the commit, where admission
sees it, and never inside pass 1 or pass 2.

| Ring | Producer when full | Can it deadlock? | Logged as |
|---|---|---|---|
| NIC RX queue | the NIC drops (before any `LaneSeq`; the client resends per `04`); the leaf policer keeps this rare (§6.8) | no | NIC drop counter |
| `FwdRing` | lane spins in the pre-pass, copying `FillRing` events into its private buffer (§6.6) | no: the BBO core never waits on the lane while the lane drains | `eng_fwd_full{lane}` |
| `FillRing` | BBO core moves the event to its spill buffer (`ENG_FILL_SPILL` events, BBO-private) and refills the ring as the lane drains | no; spill exhaustion is a fault (§14.3) | `eng_fill_spill{lane}` |
| `OsRing` | lane spins in the pre-pass | no: the order-stream core never waits on a lane | `eng_os_full{lane}` |
| journal | lane spins in the pre-pass until `LaneCut` advances | no: pass 2 of earlier packets never waits | `eng_journal_full{lane}` |
| `StepLog`, `TxRing` | BBO core spins | no: their consumers depend only on NIC TX | `eng_steplog_full` |
| `MakerSeq` range used up | fill TX core holds that session's maker packet until the lane refills | no | `eng_maker_seq_wait` (§18 Q14) |
| free FIFO head or free segment not reusable | lane spins in the pre-pass | no | `eng_slot_spin{lane}` |

A stall changes only timing. The order stream records what happened, and every decision reads
only the order stream (§10), so a stall can never cause a replica to diverge.

### 14.3 Faults

These mean a bug or a hardware fault. Each one fail-stops the sequencer (as in §14.1) and writes a
fault record with the lane, the step and the check that failed:

- a checked subtraction in settlement fails (§7.5);
- a physical pool is empty although its logical cap holds (slots, overflow pages, held clears);
- `B ≥ A` after a step in `Continuous` (`INV-UNCROSSED`);
- a lane FIFO walk exceeds `ENG_SEG_CAP` segments (a cycle);
- the `Pend` table is full (`ENG_PEND_CAP`);
- the `FillRing` spill buffer is full.

Replicas see the same order stream and check the same invariants, so a replica either reproduces
the fault (a deterministic bug: finality halts, which is the intended outcome of `CLIENT_SPLIT`)
or does not (a hardware fault on the sequencer: failover).

### 14.4 The BBO core when a lane counter stops

- The cut core keeps publishing the lane's last `seq`; every step's `C[l]` stays there. No step
  waits.
- The lane's resting orders stay in the book and can be filled; their slots are write-once, so
  the BBO core reads them safely.
- Its unexecuted `FwdRing` entries are executed normally. Its fill events accumulate in
  `FillRing`, then in the spill buffer.
- The lane's own `lowver` stays old; when it resumes, its next batch is suspect everywhere and
  gets a run of short `Rescan` steps (§8.6).
- Its `Pend` entries stay until it resumes and applies their steps; the BBO core keeps merging
  them, so its explicit orders stay visible.
- Other lanes' acks do not depend on the stalled lane: `C_f[l']` advances for every `l' ≠ l`.

### 14.5 Late responses are defects

Every path is bounded by construction (§7.7, §11.1) or shed before acceptance (§6.8). An accepted
packet can be late only if a pinned core stops running (SMI, machine-check, an interrupt on an
isolated core). The TX cores and lanes count `eng_late_resp{core}`; B3 fails on one; 06 delivers
cores with SMIs and interrupts off. This is the fault model of the theorem, not an exemption.

## 15. Interfaces to other chapters

**Consumes:**

| From | What |
|---|---|
| `01` | names, types, constants, wire layouts, invariants, determinism rules |
| `02` | `REQ-LAT-1` (1 µs maximum, 01 §14.0), `REQ-THR-*` (1B msgs/s), measurement points for acks and fills |
| `03` | core map (01 §10: cut cores 1/6, TX cores 3/5/0, stream cores 4/7, control 51, hasher 50), the fill TX cores' `FramesOut` wait, the pool CCD (cores 56–62), book groups (`K`) |
| `04` | packet and session checks (`check_packet`, `session_msg`), `pkt_hash`, rate limits, retention and resend, session TX state for the fill TX core, `CancelAll` scope, the handle-reuse client rule (§7.8), the `BUSY` resend rule and the backlog proof (§3.5) |
| `06` | NIC RX timestamps, TSC↔PHC mapping for the age check, PHC skew bound `ENG_PHC_SKEW_NS`, VI polling for handover, huge pages, isolation with SMIs and interrupts off (§14.5) |
| `07` | `PacketRecord`/`StepRecord` encoding (lanes pre-encode into `OsRing` in pass 1), the order-stream core, frame gating, failover on silence |
| `08` | auction start/stop, the freeze and `ENG_FREEZE_MAX_US`, `uncross_price`, `Seal`, epoch-start parameters, `rank_e` epoch number |
| `10` | account → lane assignment and each account's class (dedicated or pooled, 01 §14.15.4), fee tiers in ppm, `ENG_MAX_FEE_PPM`, auction fee rule, `ACCOUNT_KILLED`, `BookSpec` with the admission table `path_ns` |
| `11` | B2 (lane budget), B3 (BBO and TX load, latency maxima, `BUSY` rate), B4 (replay), the `vyrn-sim` scheduler, the canonical state encoding |

**Provides:**

| To | What |
|---|---|
| `03` | the writer map (§4.1), the cross-CCD traffic plan (§11.2), budgets (§6.7, §8.12, §11.1) |
| `04` | response packetization and `resp_seq` rules (§8.10); which rejects are immediate and which wait for the cut |
| `07` | Advance records (count = 0 `PacketRecord`); `StepEntry` deltas and `fill_lanes`; the `Rescan` band; the dataflow replay scheduler (§10) |
| `08` | `Phase` control steps, `AuctionHist`, uncross allocation (§8.8) |
| `10` | settlement events per fill with `(StepId, ordinal)`, fee accumulators per lane, ledger rules (§2.6) |
| `11` | `vyrn-vx-oracle` interface (§2.8), equivalence lemmas to test (§9), adversarial inputs (§11.6) |
| `vyrn-md`, `vyrn-dropcopy` | fills in L order with execution IDs; book changes per step (from replicas) |

Hard constraints: the engine runs on general-purpose CPU cores only, on Linux (live) and
Linux/macOS (replay, `vyrn-sim`, oracle) (`C-UNIX`); it uses no FPGA, ASIC, SmartNIC logic, P4 or
GPU (`C-NOCHIP`); it needs only cache-coherent shared memory, 16-B aligned atomic loads (or the
seqlock fallback) and COTS NICs through `06`'s backends (`C-COTS`); the same `vyrn-engine` binary
runs live and replay, selected by configuration (`C-ONEBIN`).

## 16. Local definitions

### 16.1 Constants (all budgets unless marked)

| Name | Value | Meaning |
|---|---|---|
| `ENG_SLOT_CAP` | 2^20 (config, ≤ 2^24 = `SLOT_BITS`) | slots per lane arena |
| `ENG_SEG_CAP` | 2^18 (config) | `Segment16` blocks per lane arena |
| `ENG_UNIT_NS` | 20 | maximum lane work between two `LaneCut` polls (§6.1) |
| `ENG_STEP_FILLS` | 8 (≤ `STEP_FILL_CAP` = 64) | maker fills per step; one level per step (§8.5) |
| `ENG_STEP_MAX_NS` | 15 | maximum duration of any BBO step (§8.12) |
| `LANE_PACE` | `path_ns[n][kind]` of the previous packet | minimum gap between a dedicated client's packets (§6.9) |
| `ENG_RESCAN_MAX` | 1 | in-band batch entries per `Rescan` step (§8.6) |
| `ENG_UNCROSS_CHUNK` | 6 | fills per `Uncross` step (§8.8) |
| `ENG_PEND_CAP` | 256 | `Pend` entries (BBO core) |
| `ENG_POOL_CORES` | 7 (cores 56–62, lanes 42–48) | pooled lane group (01 §10) |
| `ENG_FREEZE_MAX_US` | set by `08` | maximum auction freeze |
| `path_ns[n][kind]` | §6.8 table (config, `BookSpec`) | `predicted_path_ns` for deadline admission |
| `ENG_FREE_MIN` | 2^18 | minimum free-FIFO depth; logical cap = `ENG_SLOT_CAP − ENG_FREE_MIN` |
| `ENG_MAX_OPEN_PER_ACCT` | 65_536 | open orders per account (`RISK_ORDER_COUNT`) |
| `ENG_MIN_QTY` | 1 | lots |
| `ENG_MAX_ORDER_QTY` | ≤ 2^31 − 1 (per book) | lots per order |
| `ENG_MAX_FEE_PPM` | set by `10` (`max_fee_ppm`, §5) | maximum fee rate in ppm; sizes reservations |
| `ENG_LADDER_PAGES` | 4096 | 4096-tick pages in the ladder (`TICK_MAX < 2^24`) |
| `ENG_OVF_PAGES` | 64 | overflow pages per lane per side (physical) |
| `ENG_FAR_PAGES_MAX` | 56 | distinct far pages with orders per lane per side (logical cap; `BAD_TICK` beyond). |
| `ENG_RECENTER_DRIFT` | 256 ticks | mid–center distance that triggers re-centering |
| `ENG_QSBR_LAG` | 2 steps | grace period before a slot or directory is reused |
| `ENG_JOURNAL` | 65_536 | journal entries per lane |
| `ENG_FWD_RING` | 1024 | FwdRing entries per lane |
| `ENG_FILL_RING` | 65_536 | FillRing entries per lane |
| `ENG_OS_RING` | 4096 | OsRing entries per lane |
| `ENG_FILL_SPILL` | 2^20 | BBO-private spill events (all lanes) |
| `ENG_STEP_LOG`, `ENG_TX_RING` | 4096 each | entries |
| `ENG_SNAP_HIST` | 4096 | snapshot versions kept for envelopes |
| `ENG_ENV_SCAN` | 8 | version range scanned directly before using deques |
| `ENG_HELD_CLEARS` | 64 | held CLEAR events per lane in the cut core; beyond: wild |
| `ENG_BEAT_NS` | 1_000 | maximum lane heartbeat interval |
| `ENG_LANE_STALL_NS` | 20_000 | stall alert |
| `ENG_LANE_DEAD_NS` | 1_000_000 | stall that fail-stops the sequencer |
| `ENG_IDLE_SLICE_NS` | 20 | maximum idle-work slice on a lane or the BBO core |
| `ENG_PHC_SKEW_NS` | 20 | cross-NIC PHC skew assumed for fairness (06 owns) |
| `ENG_BAND_MAX_TICKS` | 1024 | maximum collar width |
| `ENG_BAND_HALF_TICKS` | ≤ 512 (per book) | collar half-width |
| `ENG_BAND_HYST` | 8 ticks | band reference hysteresis |
| `ENG_AUCTION_TICKS` | 2048 | maximum auction histogram width |
| `ENG_CANCELALL_EAGER` | 1024 | orders tombstoned eagerly by a multi-session `CancelAll` |

### 16.2 Types

`PrioKey`, `Route { Local, Forward }`, `Phase { Continuous, Auction, Frozen, Halted }`,
`Band { lo, hi }`, `OrderSlot` (§4.3), `SlotAux`, `RootAux` (§4.5), `Segment16`, `Cursor`
(§4.6, §5.3), `AcctKill` (§4.7), `JEnt` (§4.9), `CounterLine`, `OccEvent` (§4.10), `BboSlotState`,
`BboVer` (§4.11), `FwdEntry`, `FwdDep`, `FillEvent` (§4.12), `CutPub` half A/B, `BboFloor`
(§4.13), `SnapshotLine` (§4.14), `StepEntry`, `TxEntry`, `MakerSeq`, `LaneCut` (§4.15), `Pend`
(§8.5), `AuctionCtl`, `AuctionHist` (§8.8), Advance record with `MID` (§6.2), `Class` (§6.8),
`AcctTok`, `PoolAcct`, `AcctTake` (§6.9).

`FillEvent.kind`: 1 `Fill`, 2 `Rested`, 3 `Out`, 4 `Reject`, 5 `Phase`, 6 `Band`, 7 `Uncross`,
8 `Dep`. `StepKind` codes: §8.1. `PacketRecord.flags` (u8, 01 §6.6): bit 0 `SHED`, bit 1 `ADVANCE`; this chapter adds bit 2
`MID`, bit 3 `PASS2`.

`Out` causes and new codes are 01 §14.10's: causes 1 `IOC_REST`, 2 `STP`, 3 `AUCTION`, 4
`EXPIRED`; rejects 21 `ACCOUNT_KILLED`, 22 `RESEND_GONE`, 23 `BAD_BOOK`, 24 `BUSY`. Draft 0.1's
`REPLACE_FILLED` is gone (§2.3). The engine emits `EXPIRED` only from a `Control` step that 08 or
10 issue (none in v1).

### 16.3 Invariants

| Name | Statement |
|---|---|
| `INV-ENG-1` | A lane's snapshot affects only routing (local or forwarded). Every observable outcome is decided by the sequential specification. |
| `INV-ENG-2` | Every lane-written field that the BBO core reads is written before its position is active, except the tombstone and `next_ver` (each written once) and the segment `mask` (bits change only as §4.6 states, each change stamped by a `LaneSeq` or dead at every later cut). |
| `INV-ENG-3` | Occupancy masks are conservative for the cut of every step that reads them (Lemma 7.1). |
| `INV-ENG-4` | After every `Continuous` step, `B ≥` true best bid, `A ≤` true best ask, and `B < A` (Lemma 9.8). |
| `INV-ENG-5` | A lane settles a local op `t` at the first boundary with `t ≤ min(C_f[l], applied)`, `f = fills_applied`, and at no other point. |
| `INV-ENG-6` | No logical decision reads a ring's fill level or any timing, except the two deadline tests, whose results are logged (`SHED`, `Shed`); full rings stall the producer before the commit point. |
| `INV-ENG-7` | Queue positions are assigned in pass 1 in key order and never move; only a cancel, a fill or a kill ends one (01 §14.13). |
| `INV-ENG-8` | An explicit op (a source or a dependency) enters L only at its step, and no step's cut covers an op that its lane has not applied or made explicit (F2, F3). |

## 17. Requests to 01

Resolved by 01 §14 and removed: R1 (`Control` step, §14.10), R3 (Advance records, §14.11), R5
(`Out` causes, §14.10, 4 = `EXPIRED`), R6 (`INV-ENG-1`, `-2`, §14.11), R7 (IOC, FOK and post-only
are forwarded, §14.2), R10 (`LaneCut` writer, §14.11; control on core 51, 01 §10, §14.17.3), the `SHED`
flag half of R11 (§6.6 now has `flags`), and R14's step part (15 ns steps, §14.15.2).

| # | Request | Reason |
|---|---|---|
| R2 | Add an optional `band: (Tick, Tick)` to `StepRecord` for `Rescan`. | Replay can rescan exactly the band; without it, all ticks (correct, slower). |
| R4' | In `INV-ACK-AFTER-CUT`, "a published cut" means a step cut logged in a `StepRecord`; define the step cut as in §3.3 (two half-cuts, clamped below each lane's dependency floor, the source at `min(max(K, a), q)`, explicit ops at their step). | Draft 0.1's "raised to `q`" is wrong with early dispatch (§3.3). |
| R8 | State in 01 §6.2/§6.4 that `Replace` keeps the `Handle`, a `Reduce` is answered `CancelAck { canceled }`, a `Replace` `Ack { tick' }`, and a `Replace` to `qty' ≤ filled` `CancelAck { canceled: open }`. | One handle per order; 01 §14.10 has no `REPLACE_FILLED`. |
| R9 | Add `rank_e(l) = (l + e) mod N_LANES` as the tie-break rotation. | `04`, `08`, `vyrn-md` need the same rank. |
| R11 | Add `PacketRecord.flags` bits 2 `MID` and 3 `PASS2`, and the numeric `StepKind` codes of §8.1. | Mid-packet boundaries need a logged position (§6.2). |
| R12 | Add `Phase::Frozen` (every book op rejected `AUCTION_PHASE`). | The freeze keeps an uncross within 1 µs per response (§8.8). |
| R13 | Promote `INV-ENG-7` and `INV-ENG-8`. | 07 and 11 test positions and explicit ops. |
| R14 | Add the 20 ns "lane notices `LaneCut`" term to 01 §14.2's ack path (935 → 955 typical, 965 worst). | A lane inside another packet polls `LaneCut` every `ENG_UNIT_NS` (§6.1). |
| R15 | *Resolved by 01* (§14.17.4): `AcctTake { account, ver, lane }` in the lane record stream (01 §6.6, 07). | 01 §14.15's "each core's `LaneSeq` logs the token order" does not order one account's work across two pool cores; `ver` does (Lemma 6.1). |
| R16 | *Resolved by 01:* §5 has `N_LANES_REF` = 49 (42 + 7) and `BBO_CROSS_NS` = 15, matching §14.15.2. | — |

## 18. Open questions

Settled by 01 §14 and removed: Q3 (`LaneCut` on the stream cores), Q7 (fail-stop on a dead lane),
Q9's `liq` half (`liq = 2`), Q12's percentile form (cold lines are paid before the commit point).

| # | Question | Owner | Settled by |
|---|---|---|---|
| Q1 | Does a half-cut pass over 25 counter lines fit in `CUT_REFRESH_NS = 100`, and do ~25 GB/s into CCD 0 leave margin (§11.2)? | 05 | `vyrn-bench` cut-pass microbenchmark, B3 |
| Q2 | Do the two stream cores take ~50M `PacketRecord`s/s each, 30M steps/s, frame gating and `LaneCut`? | 07 | B3, busy ≤ 0.25 per core |
| Q4 | How often does `Rescan` fire on real quote flow (each in-band entry costs an `Idle` and a `Rescan` step)? | 05 | `vyrn-sim` replay of recorded L3 data |
| Q5 | Is `ENG_PHC_SKEW_NS = 20` achievable across the X2541 NICs in one box? | 06 | PTP skew benchmark with a capture NIC |
| Q6 | Is a 3.3 s minimum handle-reuse interval acceptable, or is a 16-bit generation needed? | 04 | client survey; stale-cancel fuzz in `vyrn-sim` |
| Q8 | 16-B single-copy atomicity on Apple M-series (FEAT_LSE2) for `LaneCut`. | 06 | litmus test; else the seqlock fallback |
| Q9 | Auction fees. | 10 | fee-rule review |
| Q10 | `CancelAll` scope: session or account. | 04 | protocol review |
| Q11 | Book groups: does the lane budget hold for K = 8 cold books per lane? | 03 | B2 with 8 books on one lane |
| Q12' | How often does a cold-line wait in the pre-pass turn a packet into `BUSY`? | 05 | B2 with uniformly old cancel handles |
| Q13 | Dedicated lane-stage `BUSY = 0` for ten-message packets needs RX ≤ 315 ns or a ≤ 15 ns work unit (§11.8). Which? | 01, 06 | B1 RX maxima; B2 work-unit sizes |
| Q14 | `MakerSeq` gives 8 spare numbers, which a market maker hit by many consecutive crosses can use up before its lane refills (`eng_maker_seq_wait`). | 01, 05 | B3 with a market maker at the touch |
| Q15 | 01 §14.14 bounds every maker fill by the taker's first bit. At index 9 about five continuation steps (≤ 40 fills) fit; later steps' maker fills exceed `LAT_MAX_NS`. Cap the fills one taker may take, or re-budget? | 01 | decision; B3 with a 64-maker sweep |
| Q16 | A crash after an ack but before its boundary record leaves loses the boundary's position (01 §14.16 gates on op and step records). Gate on the boundary record too? | 07 | failover test with acks in flight |
| Q17 | Test D (§6.8) sheds before V6, so a packet with a bad MAC still gets a logged `SHED` record whose bytes only the sequencer holds (§6.10). Repeating one key can push those bytes out of retention. The record then stays unresolved and its block's vote waits: DAV-3 (07 §5.5) needs DAV-1's quorum of `DataMissing` (> 16 source-3 resolutions in 10 ms), which one such record does not reach. Check the MAC before logging `SHED`, exempt unchecked `SHED` records from `data_root`, or make an unrepairable `SHED` record unavailable directly? | 05, 07, 13 | decision; `vyrn-sim` shed flood on one key |
