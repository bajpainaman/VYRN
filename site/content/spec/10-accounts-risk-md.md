# 10. Accounts, risk, fees, market data, drop copy, surveillance

Draft 0.2, 2026-11-13. Normative base: [`01-conventions.md`](01-conventions.md), especially §12
and the binding decisions of §14 (two-pass lanes, deadline admission, sessions across epochs,
dedicated and pooled lanes of §14.15, the core map of §10).

This chapter defines who trades (accounts), with what (balances and per-book allocations), under
which limits (pre-trade risk in the lane), how a fill moves money (settlement), what it costs
(fees), and what the world sees afterwards (market data, drop copy, surveillance, statements).
The matching itself is `05-engine.md`. The session protocol and its rate buckets are
`04-protocol.md`. The log and finality are `07-replication.md`.

## 0. Scope, constraints and number labels

- Every risk check and every settlement runs on a lane core, inside `LANE_NS_PER_MSG`. Risk and
  reservation run in pass 1 of the lane (01 §14.2), in index order, inside `LANE_PASS1_NS`
  (5 ns per message). No risk state lives on the BBO core. On a dedicated lane no risk check
  crosses cores. In the pool (01 §14.15) a check crosses cores only inside CCD 7, under the
  account's token (§1.2).
- The 1 µs is a maximum for every accepted packet (01 §14.0). Nothing in this chapter has a
  percentile on the request path. A packet that would miss is answered `BUSY` (01 §14.1), and
  `BUSY` leaves no trace in risk state: no reservation, no rate token, no fee (§3.11).
- Market data, drop copy, surveillance and statements run on replica-class boxes, never on the
  sequencer. They are deterministic functions of the finalized log, so any replica can regenerate
  them byte for byte.
- `C-UNIX`: every process here runs on Linux in production and on macOS under `vyrn-sim`.
  `C-NOCHIP`: market data is encoded on general-purpose cores and replicated by merchant switches;
  no FPGA feed handler, programmable switch or SmartNIC logic. `C-COTS`: market-data taps are
  passive optical splitters; NICs are those of 01 §10. `C-ONEBIN`: `vyrn-md` and `vyrn-dropcopy` are
  the same binaries everywhere; only the distribution backend (multicast or unicast) changes.
- Numbers are **budget**, **measured** or **vendor** (00). Risk limits and fee rates are
  **config** values with a default (Requests to 01, item 1).

## 1. Accounts

### 1.1 Account model

| Kind | Trades | Holds ledger balance | Notes |
|---|---|---|---|
| Standalone | yes | yes | `master == self` |
| Master | no | yes | Owns sub-accounts; holds the limit envelope and the fee tier |
| Sub-account | yes | yes | `master` = its master; its own lane, allocations and limit share |
| Venue fee | no | yes | One per book; its book balance is the sum of the lanes' `fee_acc` (§5.5) |
| Liquidation | v2 only | yes | One per lane per perp book (§6) |

Decisions:

1. **Every trading account is a leaf.** A master never trades. The reason: a master's limits are
   the envelope that its sub-accounts share, and a trading master would need a share of its own.
2. **`AccountId` 0 is reserved** for control ops (§2.4). `0xFFFF_FF00..=0xFFFF_FFFF` are venue
   accounts (fee, liquidation, test). Trading accounts use the rest.
3. **A session belongs to one trading account** (01 §3). A firm with ten sub-accounts opens ten
   sessions, at least one per sub-account.
4. **Accounts are created by a finalized ledger transaction**, never on the 1 µs path. Creation
   assigns a lane for the current epoch (§1.3, rule N), so a new account trades in the epoch it is
   created.

### 1.2 Account state in the lane

The lane holds one `AcctRisk` per account it owns, indexed by a dense lane-local slot. The session
table maps `SessionId → acct_slot`, so no lookup by `AccountId` happens on the hot path. All
records are `#[repr(C, align(64))]` and are written only by the owning lane (`INV-WRITER`).

```rust
#[repr(C, align(64))]
pub struct AcctRisk {                 // 128 bytes: 2 cache lines on x86, 1 on Apple M
    // line 0: read on every New
    pub state: AcctState,             // u8: Active | Killed | Closed
    pub stp_mode: u8,                 // account default STP mode, 01 §6.2 bits 4–5 values
    pub stp_tag: u16,                 // 0 = no STP; else the master's tag for this epoch (§3.6)
    pub _rsv0: u32,
    pub max_open_orders: u32,         // config, default 10_000, hard max RSK_MAX_OPEN_HARD
    pub max_order_qty: Qty,           // config, default Qty::MAX
    pub max_notional: u64,            // quote units per order, config; ≤ RSK_NOTIONAL_HARD_MAX
    pub fee_mul: u64,                 // ceil(max_fee_ppm × 2^64 / RSK_FEE_DENOM) (§3.2)
    pub msg_fee_improve: u32,         // quote units per improve (§5.3)
    pub msg_fee_cross: u32,           // quote units per cross (§5.3)
    pub new_bucket: Bucket,           // 16 B: new-order bucket (§3.8)
    pub _pad0: [u8; 8],
    // line 1: read on crosses, fills and timers
    pub cross_bucket: Bucket,         // 16 B
    pub maker_ppm: i32,               // negative = rebate
    pub taker_ppm: i32,
    pub auction_ppm: i32,
    pub master: AccountId,
    pub account: AccountId,
    pub cod_timeout_ns: u32,          // cancel-on-disconnect, 0 = off (§3.7)
    pub book_mask: u8,                // which book slots of the group this account may trade
    pub _pad: [u8; 23],
}

#[repr(C, align(64))]
pub struct BookBal {                  // 64 bytes per (account, book slot)
    pub quote_free: QuoteAmt,         // u128
    pub quote_resv: QuoteAmt,         // u128
    pub base_free: BaseLots,          // u64
    pub base_resv: BaseLots,          // u64
    pub open_orders: u32,             // live orders of this account in this book
    pub _pad: [u8; 12],
}
```

Budget: `ACC_MAX_ACCOUNTS_PER_LANE = 65_536`, so `AcctRisk` takes 8 MB per lane and `BookBal`
4 MB per lane per book. That does not fit in cache, so the request path never touches it cold.
Only an account with an open session can send a packet, and a lane serves at most
`MAX_SESSIONS_PER_LANE` = 4_096 sessions. So at an account's first session open the lane moves its
records into one of `ACC_HOT_SLOTS = 4_096` slots at the front of the arrays, and back at its last
close (logged ops, 04, so the move replays): 768 KB per lane for one book. The hot region is
pinned in the CCD's L3 with Linux `resctrl` cache allocation (COTS, `C-NOCHIP`; the up to eight
dedicated lanes of a CCD use ≤ 6.3 MB of 32 MB), and prefetched when the lane reads the packet
header. The worst case is an L3 hit (vendor: Zen 5 ~10 ns), hidden behind the per-packet SipHash
(§3.10). Accounts with no open session are touched only by settlement at a boundary (§4.2), where
no response waits on a miss.

**Pooled accounts (01 §14.15).** The pool's accounts have one shared `AcctRisk`/`BookBal` region
for the whole pool (lanes 42–48, cores 56–62 on `REF`, 01 §10), pinned in CCD 7's L3: 7 × 4_096
hot slots, 5.4 MB. Each hot slot has a `PoolTok`, which is 05 §6.9's `AcctTok` (16 B, 4 per
64 B line): `holder: u8` (0xFF = free) and `ver: u32`, the count of the account's takes. One CAS
moves `holder` from free to the core and `ver` to `ver + 1`; the release stores free and keeps
`ver` (`vyrn-cut::PoolTok`, `crates/engine/vyrn-cut/src/pool.rs`). The `ver` of a take is the
`AcctTake.ver` below.
A pool core that dequeues a packet, its own or one it stole (05), takes the account's token with
one CAS inside the CCD (~20 ns, budget) after the deadline test and before pass 1. It keeps the
token while its queue holds more of that account's packets, and releases it with a release store
after pass 2. The holder is the only writer of the account's records (`INV-WRITER` per field,
with one logical owner at a time). Session order holds because the holder checks the session's
next expected `pkt_seq` before pass 1 (04). A cancel of an order that rests in a sibling's
`Segment16` clears its bit with an atomic `fetch_and`, and the holder releases the reservation at
the ack. Replay needs the cross-core order of an account's packets, so each token take is logged
as `AcctTake { account, ver, lane }` (01 §14.17 item 4): `ver` counts the account's takes, and
replay applies the account's work in `ver` order on the logged lane. A packet shed at dequeue
takes no token and logs no `AcctTake` (§3.11).

### 1.3 Lane assignment: `lane_map`

`lane_map: AccountId → (LaneClass, LaneId)` is part of each epoch's configuration. It changes only
at an epoch boundary, and so does an account's class. The reason: a lane owns an account's resting
orders and balances. Moving them mid-epoch is a cross-core state transfer on the hot path. At an
epoch boundary the new sequencer loads all state from the handoff anyway, so a move is free there.

The map gives each account a **class** (01 §14.15 item 4):

- `Dedicated`: the `LaneId` is one of the `n_ded` dedicated lanes (0–41 on `REF`). The lane
  serves the accounts of one firm (a master and its sub-accounts, or one standalone account) and
  nobody else. The top firms by load, which message volume dominates, hold these lanes.
- `Pooled`: every other account. The `LaneId` is the account's **pool queue** (42–48 on `REF`).
  It only steers RX, because any pool core can serve the packet (01 §14.15).

The map publishes both fields, so each client knows its class and its BUSY bound (02 REQ-LAT-5,
01 §14.17 item 2).

**Who computes it.** Every replica computes `lane_map(e+1)` from the finalized log, by the
algorithm below, during epoch `e`. The result is deterministic, so all replicas agree on its hash.
The hash goes into the epoch configuration record that 08 certifies (Requests to 01, item 4). The
sequencer never computes it, so a sequencer cannot place a victim in a slow lane.

**Load metric.** The cost of an account to its lane is measured from the log, not from the live
box's clocks:

```
lane_ns(a, s) = LANE_NS_PER_MSG × msgs(a, s) + RSK_SETTLE_NS × fill_events(a, s)
load(a)       = the 99th percentile over seconds s of lane_ns(a, s), over the last
                ACC_LOAD_WINDOW_EPOCHS epochs that ran in the same home
```

`msgs(a, s)` counts every message of `a`'s sessions in second `s` of order-stream time (rx_ts).
`fill_events(a, s)` counts fill events delivered to `a`'s lane for `a`'s orders. The metric uses
the same home's past epochs, because an account's activity follows its own trading hours. The
percentile uses the integer rule of §9.1.

**Algorithm (deterministic, integer only).** One lane's capacity is `CAP = 10^9` ns/s. The
target is `ACC_LANE_TARGET_PPM = 500_000` (budget, 50% of a lane), so bursts do not queue. A
firm's load `f[m]` is the sum of `load(a)` over its accounts.

**Moves are minimized, because a move closes sessions.** Sessions survive epoch boundaries
(01 §14.8); only an account that changes lane has its sessions closed, and a change of class is
a change of lane for every account of the firm. So the algorithm minimizes moved accounts, not
load spread:

- **Promotion and demotion only at a boundary, with hysteresis.** A free dedicated lane goes to
  the largest pooled firm. When no lane is free, a pooled firm replaces the smallest dedicated
  firms only if it is larger than each of them by `ACC_PROMOTE_RATIO_PPM = 1_250_000` (config,
  1.25×), and no firm involved changed class in the last `ACC_MOVE_COOLDOWN_EPOCHS = 3` epochs of
  the same home. So two firms of similar size never swap back and forth.
- **Inside a class, almost nothing moves.** A dedicated firm keeps its lane ids. Only a firm that
  holds several dedicated lanes rebalances its own accounts, and only on a lane over
  `ACC_LANE_TRIGGER_PPM = 550_000` (budget; the gap to the target is hysteresis), largest account
  first. A pooled account keeps its pool queue for as long as it stays pooled, because stealing
  (01 §14.15) already spreads the pool's load.

```rust
fn next_lane_map(prev: &LaneMap, load: &[(AccountId, u64)], cm: &CoreMap) -> LaneMap {
    let (nd, np) = (cm.n_ded, cm.n_pool);                     // REF: 42 and 7 (01 §10)
    let target = CAP * ACC_LANE_TARGET_PPM / 1_000_000;
    // Rule K (keep): start from the previous map; drop accounts that no longer exist. A firm on
    // a dedicated lane id ≥ nd, or an account on a pool queue outside the pool, is unplaced.
    let mut map = prev.retain_existing().unplace_outside(nd, np);
    let f = firm_loads(&map, load);                            // Σ load(a) per firm
    let mut moves = 0;
    // Rule C (class). Pooled firms in descending load (ties: lower master AccountId).
    for p in map.pooled_firms_desc(&f) {
        let need = ceil_div(f[p], target).max(1);              // dedicated lanes p needs
        let short = need.saturating_sub(map.free_dedicated(nd));
        let ds = map.smallest_dedicated(&f, short);            // fewest small firms freeing `short`
        if ds.lanes() < short { continue; }
        let ok = !cooled(p) && ds.iter().all(|&d| !cooled(d)
                     && f[p] * 1_000_000 > f[d] * ACC_PROMOTE_RATIO_PPM);
        if !ok { continue; }
        let cost = map.accounts(p) + ds.iter().map(|&d| map.accounts(d)).sum::<u32>();
        if moves + cost > ACC_MAX_MOVES_PER_EPOCH { break; }
        for d in ds { map.demote_to_pool(d, np); }             // d's accounts: argmin pool queue
        map.promote(p, need); moves += cost;                   // lowest free lane ids
    }
    // Rule M (move): inside each firm with several dedicated lanes, drain every lane over the
    // trigger to the target into the firm's least loaded lane, largest fitting account first.
    rebalance_within_firms(&mut map, load, &mut moves);
    map
}
// Rule N (new): an account created during epoch e joins its firm's class. In a dedicated firm it
// goes to the firm's least loaded lane; otherwise it goes to the pool queue with the least load,
// from the loads the replicas used for lane_map(e) plus ACC_NEW_ACCOUNT_LOAD per account already
// created this epoch. A new firm is pooled until a boundary promotes it.
```

Rule K keeps every account in place unless its class changes, its lane is over the trigger, or
its lane no longer exists, so almost every session crosses the boundary untouched.
`ACC_MAX_MOVES_PER_EPOCH = 1_024` (config) bounds the state that moves at one handoff and the
sessions closed, class changes included; the epoch report counts promotions, demotions and moves.

**Accounts too big for one lane.** An account with `load(a) > ACC_ACCOUNT_MAX_SHARE_PPM × CAP`
(config, 400_000 = 40% of a lane) is flagged `MUST_SPLIT` in its end-of-epoch statement (§10).
The venue does not split it automatically, because a split divides the firm's capital between
sub-accounts, and that is the firm's decision. Until it splits, its new-order bucket rate is
capped at the 40% share, so it cannot starve the other accounts of its lane or of the pool.

**The map depends on the box.** `lane_map(e+1)` is computed for the class sizes of epoch `e+1`'s
home: `n_ded` dedicated lanes and `n_pool` pool cores, 42 and 7 on `REF` (01 §10). The core map
is identical across a replica set, so a failover inside an epoch never changes them. A home with
fewer dedicated lanes demotes the firms of the missing lanes, so operators keep the three homes on
one core map.

**A moved account takes its state with it.** Balances, reservations and resting orders move with
the account. The new sequencer builds every lane from the certified state (08), so a move is a
different placement of the same state. Resting-order time priority must survive it (Open
questions, item 7).

### 1.4 Distribution to clients

A client learns its lane at session open (04): the response carries `lane: LaneId`, its class,
and the UDP port `port_base + lane`. On bare metal the NIC steers by destination port, so a packet
sent to the wrong port reaches the wrong lane, which rejects it `WRONG_LANE` (detail = the correct
lane). A pooled session's packet on any pool port is served, because every pool core serves the
pool; a pooled packet on a dedicated port, or the reverse, is `WRONG_LANE`. The SDK paces a
dedicated client by `LANE_PACE` (01 §14.15 item 1), so it never queues behind itself, and puts a
packet's cancels first, where the ack slack is largest (01 §14.17 item 1). On
AWS, ENA steers by RSS, so the response also carries a UDP source port that the published RSS key
and indirection table map to the lane; a packet on the wrong queue is rejected `WRONG_LANE` too.
There is no forwarding ring: a forward adds a core hop (~100 ns) to a packet still owed 1 µs.

**Sessions survive the boundary** (01 §14.8, 08): a session keeps its `SessionId`, lane and port
unless its account moves. `lane_map(e+1)` is published, signed by the replica quorum, at least
`ACC_MAP_PUBLISH_LEAD_S = 3_600` s (config) before the boundary, so a client knows an hour ahead.
At the boundary the handoff closes exactly the sessions of moved accounts; their next packet gets
`SESSION_CLOSED` with detail `RSK_D_MOVED | new_lane` (§3.1), and the client opens new sessions to
the new lane. Every other session sends its first packet of epoch `e+1` with no re-open.

### 1.5 Sub-accounts and limit shares

A market maker that needs more than one lane splits into sub-accounts. Each sub-account is an
ordinary trading account with its own allocations and its own share of every limit. All
sub-accounts of a master share its class: a dedicated firm's sub-accounts are spread over the
firm's own dedicated lanes (Rule M, §1.3), and a pooled firm's sub-accounts are all pooled.

- **Limits.** The master holds an envelope `L_master` for each limit (open orders, notional per
  order, new-order rate, cross rate). Each sub-account `i` holds `L_i`. The
  ledger checks `Σ L_i ≤ L_master` when a share changes. A share changes only by a finalized
  control op (§2.4, `CtlSetLimit`), never on the hot path.
- **Capital.** Each sub-account has its own ledger balance and its own per-book allocations.
  Moving capital between sub-accounts is a ledger transfer, finalized in milliseconds.
- **Fee tier.** The tier is computed on the master's total volume (§5.2), so splitting never
  lowers a firm's fees and never raises them.
- **STP.** All sub-accounts of a master share one `stp_tag` (§3.6), so the BBO core prevents a
  self-trade between two sub-accounts even when they sit in different lanes.
- **Kill.** A master kill reaches every sub-account's lane as one control op per lane (§3.7).

## 2. Balances and per-book allocations (escrow)

### 2.1 Units

| Quantity | Type | Unit | Range |
|---|---|---|---|
| Base held in a book | `BaseLots` (u64) | one lot of the book | 0 … 2^64 − 1 |
| Quote held in a book | `QuoteAmt` (u128) | the quote asset's atomic unit | 0 … 2^128 − 1 |
| Order quantity | `Qty` (u32) | lots | 1 … `max_order_qty` |
| Price | `Tick` (u32) | ticks | `BookSpec.min_tick … max_tick` |
| `tick_size` | u64 | quote units per lot per tick | ≥ 1 |
| `lot_size` | u64 | base atomic units per lot | ≥ 1 |

The notional of `q` lots at tick `t` is `q × t × tick_size` quote units, exactly. No float and no
division appear in a notional (01 §11).

Decision: **all fees are charged in quote.** The reason: a buyer then receives exactly `q` lots,
a seller delivers exactly `q` lots, base balances stay whole lots, and a sell reserves exactly
`qty` (01 §12.1).

### 2.2 The ledger

The **ledger** is the replicated record of each account's balance per asset outside every book.
In `CHAIN` mode it is the chain's custody state (09). In `BASE` mode it is a replicated state
machine on the same replica sets, finalized by the same Simplex consensus as a book log with no
matching (07). Deposits and withdrawals touch only the ledger. A book never sees a deposit; it sees
an allocation.

An account's capital in a book is its **allocation** (escrow) for that book. It lives in the
account's lane as a `BookBal`. Allocated capital is either free or reserved by open orders.

### 2.3 The allocation state machine

```
             AllocTx finalized on the ledger
             (ledger.avail −= x, ledger.in_flight += x)
   LEDGER ───────────────────────────────────────────► IN_FLIGHT_IN
     ▲                                                      │ control core injects CtlAllocCredit
     │                                                      │ into the account's lane (a logged op)
     │                                                      ▼
     │                                                 ┌─────────┐ New/fill/cancel move value
     │                                                 │ ESCROW  │ between free and reserved
     │                                                 │ (lane)  │ inside the lane only
     │                                                 └────┬────┘
     │                                                      │ ShrinkTx finalized on the ledger
     │                                                      │ → CtlAllocDebit(mode) into the lane
     │                                                      ▼
     │                                                  SHRINKING ── FREE_ONLY: debit min(x, free)
     │                                                      │      ── CANCEL_SIDE: cancel the side's
     │                                                      │         orders, wait for their acks,
     │                                                      │         then debit min(x, free)
     │                                                      ▼
     │       block holding AllocDebited is final        IN_FLIGHT_OUT  (lane emitted AllocDebited
     └────── (ledger.avail += debited) ◄────────────────  with the amount actually debited)
```

Rules:

1. **Credits are never on the 1 µs path.** An allocation reaches the lane only after the ledger
   finalized it. The lane applies it as one control op, in order with the lane's other ops.
2. **A shrink debits only free balance.** Reserved balance backs live orders. Releasing it would
   let the BBO core fill an order with no money behind it.
3. **Two shrink modes, and no third.** `FREE_ONLY` (the default) debits what is free and leaves
   every order alone. `CANCEL_SIDE` cancels all of the account's orders in that book on the side
   that the asset backs (buys for quote, sells for base), then debits. The venue does not choose
   *which* orders survive a partial shrink. That choice is a trading decision, and the client
   makes it with its own cancels before it shrinks.
4. **The debit can be less than requested.** `AllocDebited` reports the exact amount, the ledger
   credits back exactly that, and the rest of the request is void.
5. **Idempotency.** Every control op carries the control session's gapless `pkt_seq`. The lane
   applies a control packet once. A replay of the same packet is rejected `BAD_SEQ` (04).
6. **Value in flight is counted once.** `IN_FLIGHT_IN` and `IN_FLIGHT_OUT` are ledger fields. The
   ledger conservation check is `avail + in_flight + Σ escrow = deposits − withdrawals − fees`.

### 2.4 Control ops

Control ops enter a lane as packets of the reserved control session `SessionId = 0` (one per
lane). The control core (core 51 on `REF`, beside the OS, 01 §10 and §14.17) builds them from finalized
ledger transactions, and from signed admin commands, and pushes them on the lane's control SPSC
ring. A pooled account's control op goes to its pool queue's ring, and the pool core that applies
it holds the account's token (§1.2). The lane processes a control
packet exactly like a client packet: it gets a `PacketRecord` with a `pkt_hash`, and its payload is
stored in the data tier (07). Control ops are therefore part of the order stream and replay
exactly.

Deadline admission (01 §14.1) never sheds a control packet: its response goes to the control
core and owes no 1 µs. The lane takes a control packet only when its client RX queues are empty,
or after it has waited `RSK_CTL_MAX_WAIT_NS = 100_000` (budget), so control work does not delay
client packets; the order stream records the choice. Each control op is one 16-byte message;
session 0 and codes `0x20…0x2F` and `0xA0…0xAF` are promoted (01 §14.11).

| Code | Name | 0 | 1 | 2–3 | 4–7 | 8–15 |
|---|---|---|---|---|---|---|
| 0x20 | `CtlAllocCredit` | type | asset (0 quote, 1 base) | book | account | amount u64 |
| 0x21 | `CtlAllocDebit` | type | bit0 asset, bit1 mode (0 FREE_ONLY, 1 CANCEL_SIDE) | book | account | amount u64 |
| 0x22 | `CtlSetLimit` | type | limit id (§3.4) | book or 0 | account | value u64 |
| 0x23 | `CtlKillAccount` | type | 1 kill, 0 unkill | 0 | account | admin key id u64 |
| 0x24 | `CtlKillSession` | type | 0 | 0 | session | admin key id u64 |
| 0x25 | `CtlTimerTick` | type | 0 | 0 | 0 | 0 (time = the packet's rx_ts) |
| 0x26 | `CtlSetFees` | type | tier | book | account | maker_ppm i32 (8–11), taker_ppm i32 (12–15) |

Amounts are u64 per op, because a 16-byte message cannot hold an account, a book and a u128.
2^64 µUSD ≈ 1.8 × 10^13 USD; a larger allocation is several ops in one control packet.

`CtlTimerTick` has no time field. The control core sends it through the NIC loopback (06) every
`RSK_TIMER_TICK_NS = 1_000_000` ns (budget), so its time is a NIC RX timestamp (01 §11 rule 3),
and timers (§3.7) fire in an idle lane too.

The lane's response to a control op goes to the control core, not to a client:

| Code | Name | Bytes |
|---|---|---|
| 0xA0 | `AllocCredited` | type, asset, book, account, amount u64 |
| 0xA1 | `AllocDebited` | type, asset, book, account, amount actually debited u64 |
| 0xA2 | `CtlDone` | type, op code, reason u16 (0 = done), account, detail u32, 0 |

**Control rejects.** A control op that fails changes no state and is answered `CtlDone` with a
01 §6.5 reason and detail:

| Op | Failure | Reason | Detail |
|---|---|---|---|
| `CtlAllocCredit` | the free balance would overflow | `BAD_QTY` | `RSK_D_OVERFLOW` |
| `CtlSetLimit` | unknown limit id | `BAD_TYPE` | `PROTO_D_UNKNOWN_TYPE` |
| `CtlSetLimit` | value outside the §3.4 range | `BAD_QTY` | the limit id (1–8) |
| `CtlSetFees` | raises `fee_mul` while the book holds a buy reservation (`quote_resv ≠ 0`, §5.2 rule 2) | `RISK_ORDER_COUNT` | the account's `open_orders` in the book |

The reasons are `vyrn-risk`'s (`ctl.rs`). **Proposed `CtlDone` encoding (no code yet):** bytes
2–3 = the reason u16 (0 = done), bytes 8–11 = the detail u32, bytes 12–15 = 0. `CtlAllocDebit`
never fails: it debits `min(amount, free)` and reports that amount in `AllocDebited`.

Replicas derive the same responses by replay; the ledger acts only on their finalized view.

### 2.5 Credit, debit and shrink in the lane

```rust
fn ctl_alloc_credit(l: &mut Lane, m: &CtlAlloc) -> Result<(), Reject> {
    let bb = l.book_bal_mut(m.account, m.book)?;               // UNKNOWN_HANDLE if not ours
    match m.asset {
        Quote => bb.quote_free = bb.quote_free.checked_add(m.amount as u128).ok_or(BAD_QTY)?,
        Base  => bb.base_free  = bb.base_free.checked_add(m.amount).ok_or(BAD_QTY)?,
    }
    l.ctl_reply(AllocCredited { ..*m });
    Ok(())
}

fn ctl_alloc_debit(l: &mut Lane, m: &CtlAlloc) -> Result<(), Reject> {
    if m.mode != CancelSide { return finish_debit(l, m); }
    // Normal cancel path in idle-time chunks (§3.7); the debit waits until the last CancelAck.
    l.start_side_cancel(m.account, m.book, side_backed_by(m.asset), PendingDebit(*m));
    Ok(())
}

fn finish_debit(l: &mut Lane, m: &CtlAlloc) -> Result<(), Reject> {
    let bb = l.book_bal_mut(m.account, m.book)?;
    let amt = match m.asset {
        Quote => { let d = min(bb.quote_free, m.amount as u128); bb.quote_free -= d; d as u64 }
        Base  => { let d = min(bb.base_free,  m.amount);         bb.base_free  -= d; d }
    };
    l.ctl_reply(AllocDebited { amount: amt, ..*m });
    Ok(())
}
```

`finish_debit` for `CANCEL_SIDE` runs when the last of the side's CancelAcks has been sent. Fills
that the BBO core executed before those cancels took effect settle first, by the normal path. So
the debited amount is the free balance after all of them, which is deterministic.

### 2.6 Moving an allocation between books

A `MoveTx(account, asset, x, from A, to B)` is one ledger transaction with two legs:

1. The ledger finalizes `ShrinkTx(A, x, mode)`. Book A's lane debits `d ≤ x` and emits
   `AllocDebited(d)`.
2. When the block of book A that holds `AllocDebited(d)` is final, the ledger finalizes
   `AllocTx(B, d)`.
3. Book B's lane applies `CtlAllocCredit(d)`.

Latency budget: ≤ 3 × `FINALITY_MAX_MS` + control injection ≈ **35 ms** (budget; a ledger transfer, not an order). It is never
on the 1 µs path, and it does not need to be. A strategy that must move capital faster keeps
headroom in both books.

Books in one book group share lanes (01 §12.3). An allocation move inside a group still uses the
ledger in v1; the router domain (§2.8) is the fast path (Open questions, item 3).

### 2.7 Invariants

| Name | Statement |
|---|---|
| `INV-ACC-1` | For every (account, book): `quote_resv = Σ R_buy(rem_u(o), o.tick)` over the account's live buys in the book, and `base_resv = Σ rem_u(o)` over its live sells (§3.2). |
| `INV-ACC-2` | Per step, over all lanes: `Σ Δbase = 0` and `Σ Δquote + Σ Δfee_acc = 0`. Replicas check both per block, from their replayed lane states. |
| `INV-ACC-3` | No balance field is ever negative. Every subtraction is checked. A failed subtraction in settlement is an engine fault (§4.5), never a reject. |
| `INV-ACC-4` | An account's class and lane (for a pooled account, its pool queue) are constant within an epoch. A pooled account's records are written only by the pool core that holds its token (§1.2). |
| `INV-ACC-5` | A route (§2.8) changes no per-asset total of its lane: what the client loses in book A the router gains in A, and the reverse in B. |

### 2.8 Epoch-settled balance domains and the optional router domain

The per-book allocations of §2.2–§2.6 are the venue's **epoch-settled balance domains**
(01 §14.13 item 5): each book's escrow is its own domain, and value moves between domains only
through the ledger (§2.6, ~35 ms) or at the epoch boundary. A book group may also enable a
**router domain** for routes between its books that cannot wait for the ledger. Its books share
lanes (01 §12.3), so a route is lane-local. A hot book has its own box and no router domain.

- **Router accounts.** One per (group, lane class), from the venue range (§1.1), with a `BookBal`
  in every book of the group, funded by `CtlAllocCredit` like any account. It never trades, never
  moves lane and never changes class. The pooled router is one account in the pool region, taken
  under its token like any pooled account (§1.2). The dedicated router has one shard per
  dedicated lane, so a route stays lane-local and the shard's lane is its only writer
  (`INV-WRITER`); a shard is venue state, not a second firm on the lane. Limits apply per shard.
- **Route op.** A client message `RouteMove { asset, to_book, amount u64, client_tag }` (requested
  code 0x05) in a packet of the source book. Pass 1 applies it in index order, as a reservation:
  client `free(A) −= x`, router `free(A) += x`, router `free(B) −= x`, client `free(B) += x`, one
  lane step, answered within the 1 µs like an `Ack` (requested record 0x88 `Routed`). No BBO hop.
- **Same asset only in v1** (quote to quote, or base to base). A route leaves the router's total
  holding unchanged, so it bears no price risk, only inventory risk: how much sits in which book.
  That is a product setting, not a correctness issue: `router_mode` = Off (default) | Operator |
  Provider(master). The funder sets the inventory per book and earns `router_fee_ppm` (ceil).
- **Risk limits** (per router account and book, `CtlSetLimit`): `router_floor_b` (free inventory
  a route may not take it below), `router_max_route` (per op), `router_net_max_b` (net outflow per
  epoch). For the client, a route counts one `new_bucket` token and needs `free(A) ≥ x + fee`.
  Failures reject `RISK_CREDIT` (detail 3 router inventory, 4 router net limit). Routes are never
  shed by the BBO core; a lane `BUSY` sheds them like any packet (§3.11).
- **Epoch settlement.** The epoch statement (§10) totals each router account per book. Before the
  next epoch starts, the ledger finalizes one `MoveTx` per (router, asset, book) that returns the
  router to its funder's target split, and the lane loads the router with that split.
  Consolidating the dedicated router's shards is the same sweep. So every router imbalance lives
  at most one epoch. A route is a message in the order stream, so replicas reproduce it and check
  `INV-ACC-5`.

## 3. Pre-trade risk in the lane (v1, fully collateralized spot)

### 3.1 Order of checks

A lane runs these checks on every `New`, in this order, in pass 1 (01 §14.2). The first failure
rejects the message, and later checks do not run. The order puts the cheapest and the most
protective checks first. Column **P** marks work done once per packet, after `tag_seq` and before
the first message; column **M** marks the per-message work that must fit `RSK_PASS1_CYCLES`
(§3.10). Hoisting is exact: all messages of a packet share its session, account, snapshot and
`rx_ts`, so a per-packet result equals the per-message result.

| # | Check | 04 §3.3 | P / M | Reject (01 §6.5) | Detail u32 |
|---|---|---|---|---|---|
| 1 | Session open and bound (04) | V7 | P | `SESSION_CLOSED` | 0, or `RSK_D_MOVED \| lane` (§1.4) |
| 2 | `MSG` bucket of the session, then of the account, cost 1, keeping the cancel reserve (04 §9.1) | M1 | M | `RATE_LIMIT` | 2 session, 5 account (04 §9.1) |
| 3 | Account state `Active` | M4 | P | `ACCOUNT_KILLED` (21) | 0 |
| 4 | Snapshot `halted` flag clear | M5 | P | `BOOK_HALTED` | 0 |
| 5 | Phase allows the TIF and post-only (04 §6.9, 08) | M5 | P phase, M 1 compare | `AUCTION_PHASE` | `PROTO_PHASE_*` of the current phase |
| 6 | Account `new_bucket` (§3.8), cost 1 | M1 (10's bucket) | P refill, M 1 decrement | `RATE_LIMIT` | `RSK_BUCKET_NEW` |
| 7 | `1 ≤ qty ≤ max_order_qty` | M6 | M | `BAD_QTY` | `RSK_D_QTY_ZERO` / `RSK_D_QTY_MAX` |
| 8 | `min_tick ≤ tick ≤ max_tick`, then inside the band (§3.5) | M6 | P edges, M 1 compare | `BAD_TICK` | `min_tick` below the range, `max_tick` above it, else the band edge: always the nearest acceptable tick |
| 9 | Notional `≤ max_notional` | M6 | M | `BAD_QTY` | `RSK_D_NOTIONAL` (`RSK_D_OVERFLOW` if it overflows) |
| 10 | `open_orders < max_open_orders`, then a free slot in the lane's pool for the book (§3.4) | M7 | M, packet-local count | `RISK_ORDER_COUNT` | the limit; `RSK_D_LANE_FULL` |
| 11 | Balance covers reservation + message fee of the charged route (§3.2, §5.3) | M7 | M | `RISK_CREDIT` | `RSK_CREDIT_QUOTE` 1, `RSK_CREDIT_BASE` 2: the asset that is short |
| 12 | Post-only that the classification (05) calls a cross | M8 | M (05's cost) | `POST_ONLY_WOULD_CROSS` | best opposite tick of the snapshot |
| 13 | BBO-routed only: `BBO` bucket of the session, then of the account (04 §9.1); then a cross takes `cross_bucket` and the lane cross bucket, an improve the lane improve bucket (§3.8) | M8 | P refill, M 1 decrement | `RATE_LIMIT` | 3, 6 (04 §9.1); `RSK_BUCKET_CROSS`, `_LANE_CROSS`, `_LANE_IMPROVE` |

The order is 04 §3.3's M1–M8, which is the client-visible contract; this table places 10's
checks inside it. `vyrn-risk` implements it (`Risk::check_new`, `crates/engine/vyrn-risk/src/check.rs`).
A `RATE_LIMIT` detail names its bucket by the ids of 04 §9.1, which lists 10's bucket ids too
(the overlap of the two ranges is an open question there). `IOC` and `FOK` are charged as
crosses in checks 11 and 13 whatever the classification (04 §6.2); check 12 uses the
classification. Exposure (`RISK_POSITION`, 04 M7) has no v1 spot limit; it is the v2 perps limit
(§6).

Pass 2 does the rest of the risk work, in index order with the apply: it adds message fees to
`fee_acc`, writes back `open_orders`, and updates statistics. None of that changes a pass-1
decision of the same packet, because pass 1 uses packet-local copies of the counters.

Decisions:

1. **Checks 3–5 consume no `new_bucket` token.** They are per-packet facts and cost nothing per
   message. They come after the `MSG` bucket (check 2), so a message they reject still consumes
   its `MSG` token, as every rejected message does (04 §3.3). Check 2 tests the session bucket,
   then the account bucket, and takes both or neither.
2. **A message rejected by checks 7–13 still consumes its `new_bucket` token**, because it costs
   the lane the same time. Rejects pay no message fee and reserve nothing; the rate limit bounds
   them.
3. **Check 13 takes all its tokens or none.** A cross needs tokens from the session's and the
   account's `BBO` buckets, its account's `cross_bucket` and its lane's bucket; the lane tests
   all of them, then takes all of them. So a lane-level shortage never costs the account a token.
   Because check 11 runs first, an order the balance refuses takes no `BBO` token either.
4. **`BUSY` is outside this table.** A packet shed at dequeue never reaches check 1 (§3.11).

`Cancel`, `Reduce` and `CancelAll` run checks 1 and 2 only, with `keep = 0` (the cancel reserve
is theirs) and never `new_bucket`. `Cancel` and `Reduce` cost 1 `MSG` token, `CancelAll`
`PROTO_CANCELALL_TOKENS` = 16 (04 §9.1). They never fail on risk, halt, band or balance, because
they only reduce risk; their release runs at the ack (§3.9) (`Risk::check_cancel`). `Replace`
runs all checks for the new order (§3.9).

### 3.2 Reservation formulas

A buy of `n` lots at limit tick `t` reserves, in quote:

```
N(n, t)    = n × t × tick_size                                         exact, u128
F(n, t)    = 0                                       if n = 0
           = ((N(n, t) × fee_mul) >> 64) + 1 + n     otherwise          the fee cap
R_buy(n,t) = N(n, t) + F(n, t)
fee_mul    = ceil(max_fee_ppm × 2^64 / RSK_FEE_DENOM),
max_fee_ppm = max(taker_ppm, maker_ppm, auction_ppm, 0)
```

A sell of `n` lots reserves `n` lots of base: `R_sell(n) = n`. A sell needs no quote reservation,
because every fee is taken from the sale's own proceeds (§5.4), and the proceeds always exceed the
fee (`RSK_FEE_PPM_MAX < RSK_FEE_DENOM`).

Why this exact `F`:

- `(N × fee_mul) >> 64 + 1 ≥ ceil(N × max_fee_ppm / RSK_FEE_DENOM)`, because
  `fee_mul / 2^64 ≥ max_fee_ppm / RSK_FEE_DENOM` and `floor(x) + 1 > x`. So `F` covers the fee
  of the whole order at the worst rate, even if the order fills entirely at its limit.
- The `+ n` term pays for rounding: each fill rounds up by < 1 quote unit, and an order has at most
  `n` fills. It costs `n` quote units (1_000 lots in a µUSD book: 0.001 USD).
- A 64 × 64 → 128-bit multiply replaces a u128 division by 10^6. That division is a libcall of
  ~40–80 cycles (vendor: `__udivti3` on x86-64), and the multiply is one `mul` instruction.

**Overflow.** `n × t < 2^64`, because both are u32. `(n × t) × tick_size < 2^128`, because
`tick_size` is u64. So `N` cannot overflow u128. Check 9 bounds `N ≤ max_notional ≤ u64::MAX`, so
`N × fee_mul < 2^128` too. The additions are still `checked_add`, and an overflow is the reject
`BAD_QTY` with `RSK_D_OVERFLOW`, never a wrap (01 §11 rule 4).

**The release lemma.** When a fill of `q` lots settles against a buy with `rem_u` unsettled lots,
the lane releases `rel = R_buy(rem_u, t) − R_buy(rem_u − q, t)` and pays notional and fee out of
it. `rel` always covers them:

```
rel − N(q, t)  = F(rem_u, t) − F(rem_u − q, t)
              ≥ (N(rem_u) − N(rem_u − q)) × fee_mul / 2^64 − 1 + q        (floor difference)
              ≥ N(q, t) × fee_mul / 2^64                                   (q ≥ 1)
              ≥ N(q, p) × rate / RSK_FEE_DENOM                             (p ≤ t, rate ≤ max)
```

`rel − N(q, t)` is an integer, so it is at least the ceiling of the last line, which is the fill's
fee (§5.4). The price improvement `N(q, t) − N(q, p)` also returns to `quote_free`. Summed over an
order's fills, the releases telescope to `R_buy(qty, t)`, so the reservation is released exactly,
with nothing left behind.

### 3.3 Rounding rules

| Amount | Rule | Reason |
|---|---|---|
| Notional | exact | integer product |
| Fee reservation `F` | rounded up (as defined) | must cover the worst case |
| Fee charged | `ceil(N × rate / RSK_FEE_DENOM)`, rate > 0 | the venue never undercharges |
| Rebate paid | `floor(N × |rate| / RSK_FEE_DENOM)`, rate < 0 | the venue never overpays |
| Taker fee | once per (order, step), on the step's total taker notional | one rounding per aggressive action, not per level |
| Maker fee or rebate | once per maker fill | a maker fill is its own execution |
| Band width | `floor` (§3.5) | the band never widens by rounding |

All of these use exact u128 arithmetic at settlement. Only the reservation uses the multiply
bound. Settlement divides by the constant `RSK_FEE_DENOM` with an exact multiply (§4.6).

### 3.4 Per-order and per-account limits

| Limit id | Name | Scope | Default (config) | Hard bound |
|---|---|---|---|---|
| 1 | `max_open_orders` | account, per book | 10_000 | `RSK_MAX_OPEN_HARD = 1_048_576` |
| 2 | `max_order_qty` | account | `Qty::MAX` | `Qty::MAX` |
| 3 | `max_notional` | account, per order | 10^12 quote units | `RSK_NOTIONAL_HARD_MAX = u64::MAX` |
| 4 | `band_bps` | book | 500 (5%) | 10_000 |
| 5 | `new_rate` | account | 1_000_000 /s | lane share (§1.3) |
| 6 | `cross_rate` | account | 100_000 /s | `REQ_LANE_CROSS_RATE` = 220_000 /s (02 REQ-THR-6) |
| 7 | `cod_timeout_ns` | account | 0 (off) | ≥ `RSK_COD_MIN_NS` when on |
| 8 | `stp_mode` | account | 1 (cancel newest) | — |

`CtlSetLimit` accepts these values, and rejects anything else (`ctl::set_limit`,
`crates/engine/vyrn-risk/src/ctl.rs`):

| Limit id | Accepted value (u64) |
|---|---|
| 1 | `0 ..= RSK_MAX_OPEN_HARD` |
| 2 | `0 ..= Qty::MAX` |
| 3 | any |
| 4 | `0 ..= 10_000` |
| 5 | `≥ 1` |
| 6 | `1 ..= REQ_LANE_CROSS_RATE` |
| 7 | `0`, or `≥ RSK_COD_MIN_NS` |
| 8 | `1 ..= 3` |

A rate change (ids 5, 6) keeps the bucket's burst and its current `tat`.

Every limit changes only by `CtlSetLimit`, a finalized control op. A change applies to orders
that arrive after it and never touches resting orders. The reason: a limit change that cancelled
resting orders would be a hidden kill, and kills have their own op.

The lane's 2^24 order slots (`SLOT_BITS`) are split into one pool per book of the group (§4.2).
Admission (02 REQ-THR-6) keeps the sum of `max_open_orders` of a lane's accounts at or below its
pools, and `vyrn-admin` refuses a `CtlSetLimit` that breaks the sum. Closed orders with unsettled
fills (§4.3) still hold a slot for a moment, so a full pool is still a defined reject:
`RISK_ORDER_COUNT` with `RSK_D_LANE_FULL`. B24 must show that it never fires, and surveillance
alarms at 80% use (§9.3).

### 3.5 Price band (collar)

Decision: **the band is relative to the BBO snapshot that the lane already reads for
classification.** The reason: it costs no extra shared read, and its replay is exactly as
replayable as classification, which 05 must make replayable anyway.

```
ref_bid, ref_ask  = snapshot bid and ask (if a side is empty: snapshot.ref_tick, the last
                    trade or auction price, published by the BBO core)
w(ref)            = max(RSK_BAND_MIN_TICKS, (ref × band_mul) >> 32)
band_mul          = floor(band_bps × 2^32 / 10_000)                  computed at config time
buy  accepted iff  tick ≤ ref_ask + w(ref_ask)
sell accepted iff  tick ≥ ref_bid − w(ref_bid)     (saturating at min_tick)
```

The edge is clamped to `[min_tick, max_tick]`. **Empty side with no reference.** When the side
the edge needs is empty and `ref_tick` = 0 (no trade or auction price yet, for example a new
book), no band applies to that side: check 8 tests only `min_tick ≤ tick ≤ max_tick`. The buy
reservation is then bounded by `R_buy(qty, max_tick)`, `max_order_qty` and `max_notional` instead
of by the band (`BookSpec::band_edge`, `crates/engine/vyrn-risk/src/band.rs`). An operator who
wants a collar from the first order opens the book with an auction (08), whose uncross sets
`ref_tick`.

The band limits only the aggressive edge. A buy far below the bid is allowed: it cannot fill
badly, and it reserves less quote, not more. The lane caches `w` per snapshot version, so the
multiply runs at most once per packet. `RSK_BAND_MIN_TICKS = 16` (config) keeps the band usable
in a book with a very low tick index.

The band also bounds the buy reservation: a buy cannot reserve more than
`R_buy(qty, ref_ask + w)`, so a fat-finger price cannot lock an account's whole balance.

### 3.6 Self-trade prevention

STP is decided by the BBO core, because only the BBO core decides fills (`INV-LANE-NOMATCH`).
Risk owns the configuration:

- **`stp_tag: u16`**, one per master, assigned with `lane_map` for the epoch. 0 means no STP.
  The lane writes it into each order's FIFO entry, and into the cross message to the BBO core
  (request to 05). A u16 keeps the FIFO entry small. `ACC_STP_TAGS_MAX = 65_535` masters per
  epoch can use STP.
- **Mode.** Flags bits 4–5 (01 §6.2) select the mode; 0 means "the account's default" (1, cancel
  newest), not "no STP". STP is on by default because self-trades print false volume. An account
  that allows them sets `stp_tag = 0`, and surveillance reports its self-trades (§9.2).
- **Semantics (taker's mode governs).**

| Mode | On a match of taker T with maker M, same `stp_tag` | Fill events |
|---|---|---|
| 1 cancel newest | T's remainder is removed; fills earlier in the step stand | `TakerEnd(cause STP)` to T's lane |
| 2 cancel oldest | M is removed; T continues to the next maker | `StpOut(M)` to M's lane |
| 3 cancel both | both removed | both events |

`StpOut` is written by the BBO core into its own consumed-quantity field, so it needs no lane
write (`INV-WRITER`). M's lane releases M's reservation when it applies the event (§4.4).

### 3.7 Kill switches, halt and cancel-on-disconnect

| Switch | Trigger | Effect | Latency budget |
|---|---|---|---|
| Session kill | client `CancelAll` + close (04), or `CtlKillSession` | session's orders cancelled; further packets `SESSION_CLOSED` | ≤ 1 lane iteration to stop; cancels chunked |
| Account kill | `CtlKillAccount` from an admin key or from the account's risk session (04) | `state = Killed`; every order of the account in this lane cancelled; New/Replace `ACCOUNT_KILLED`; cancels still accepted | ≤ 20 µs from control core to lane (budget) |
| Master kill | one `CtlKillAccount` per sub-account lane | as account kill, in every lane | ≤ 50 µs (budget) |
| Book halt | admin command to the BBO core (05) | snapshot `halted = 1`; lanes reject New/Replace `BOOK_HALTED`; cancels accepted; resting orders stay | one snapshot refresh (≤ 1 packet per lane) |
| Cancel-on-disconnect | no packet from a session for `cod_timeout_ns` of order-stream time | that session's orders cancelled | ≤ timeout + `RSK_TIMER_TICK_NS` |

Decisions:

1. **Cancels are always accepted**, during a halt, after an account kill, and over a rate limit
   (cancels have their own 04 bucket that is never shared with new orders). The reason: a switch
   that blocks risk reduction makes the emergency worse.
2. **Mass cancels are chunked:** `RSK_KILL_CHUNK = 16` orders (≤ 150 ns) per chunk, run only when
   no client packet waits (§2.4). 10_000 orders take ~625 chunks, ≤ 0.3 ms (budget) in the lane's
   ≥ 40% idle time (lane load ≤ 0.60), and the other accounts keep their 1 µs path meanwhile.
3. **Timers run on order-stream time.** The lane's clock is the largest `rx_ts` it has processed,
   including `CtlTimerTick` packets. So cancel-on-disconnect fires at the same op in the live lane
   and in every replica. `RSK_COD_MIN_NS = 1_000_000` (config) because the tick granularity is
   1 ms.
4. **An unkill does not restore orders.** The account starts empty.

### 3.8 Rate limits (risk side)

04 defines the bucket arithmetic (the `Gcra` of 04 §9.1, on `rx_ts` time, with its period
rounding) and the per-session buckets that protect the parser. This chapter defines the
per-account buckets that protect shared resources: the lane and the BBO core. Every bucket here,
account, lane or pool, is that one `Gcra` type (`tat`, `t_ns`, `burst`; 24 bytes), so one
conformance surface covers them all (`crates/engine/vyrn-risk/src/gcra.rs`).

| Bucket | Scope | Counts | Protects | Default (config) |
|---|---|---|---|---|
| `new_bucket` | account | every `New` and `Replace` | the lane's 30 ns/msg | 1M/s, burst 10_000 |
| `cross_bucket` | account | every message the lane classifies as cross | fair share of the lane | 100k/s, burst 1_000 |
| `lane_cross` | dedicated lane, or the pool | every cross of every account in the lane or pool | `CROSS_CAP` | `REQ_LANE_CROSS_RATE` = 220k/s, burst 2_200 (02); the pool: 7 × that |
| `lane_improve` | dedicated lane, or the pool | every improve of every account in the lane or pool | `BBO_IMPROVE_NS` load | 440k/s, burst 4_400 (02); the pool: 7 × that |

The two lane buckets are the hard guard on the BBO core (02 REQ-THR-6): account buckets do not
bound the sum over accounts, but 42 dedicated lane buckets and the pool's buckets cap a book at
10.8M crosses and 21.6M improves per second. At `BBO_CROSS_NS` = 15 (01 §14.15 item 2) that is a
BBO load of ~0.33 (~0.34 with depletions), below `REQ_BBO_HARD_LOAD`. A dedicated lane's buckets
live in its `LaneRisk` line beside `fee_acc` (`INV-WRITER`). **The pool's caps are per pool, not
per pool core:** its two buckets live in one `PoolRisk` line in CCD 7, taken under its own token
like a pooled account (§1.2) and only by BBO-routed ops, while each pool core keeps its own
`fee_acc`. All buckets run on `rx_ts` time with 04's arithmetic, so replicas reproduce every
reject. So the accounts' `cross_rate` may oversubscribe their lane or pool (no single one above
it, §3.4); the cross fee (§5.3) is the soft guard, and surveillance measures the real peak (§9.3).
In a book group the lane and pool buckets apply to the group's sum (REQ-THR-7).

A rate-limited cross is rejected, not downgraded to a join. The reason: changing an order's
meaning in the lane would surprise the client more than a reject.

### 3.9 Pseudocode

```rust
/// Pass 1, once per packet, after tag_seq: checks 1 and 3–5 and the hoisted parts of 6, 8 and 13.
/// Check 2 (04's MSG buckets) runs per message before them and is not shown.
/// Refilling once is exact: every message of the packet has the same rx_ts, so dt = 0 after it.
fn risk_packet(l: &mut Lane, s: SessSlot, snap: &Snap, rx_ts: Nanos) -> Result<PktRisk, Reject> {
    let a = &mut l.acct[l.sess[s].acct_slot];                          // hot slot, prefetched
    if a.state != AcctState::Active { return Err(rej(ACCOUNT_KILLED, 0)); }
    if snap.halted { return Err(rej(BOOK_HALTED, 0)); }
    Ok(PktRisk {
        phase: snap.phase, edges: l.band_cache(snap),                   // §3.5, per version
        new_tok:  a.new_bucket.refill(rx_ts),                           // whole tokens available
        xa_tok:   a.cross_bucket.refill(rx_ts),
        xl_tok:   l.risk.lane_cross.refill(rx_ts),
        il_tok:   l.risk.lane_improve.refill(rx_ts),
        open:     l.bal[a.slot][l.book_slot].open_orders,               // packet-local count
    })
}

/// Pass 1, per New, in index order. Returns the route. Fits RSK_PASS1_CYCLES (§3.10).
fn risk_new(l: &mut Lane, a: &AcctRisk, k: &mut PktRisk, m: &NewMsg, snap: &Snap)
    -> Result<Route, Reject>
{
    phase_check(k.phase, m.tif)?;                                        // 08, one compare
    if k.new_tok == 0 { return Err(rej(RATE_LIMIT, RSK_BUCKET_NEW)); }
    k.new_tok -= 1;                                                      // consumed from here on
    if m.qty.0 == 0 { return Err(rej(BAD_QTY, RSK_D_QTY_ZERO)); }
    if m.qty > a.max_order_qty { return Err(rej(BAD_QTY, RSK_D_QTY_MAX)); }
    let spec = &l.books[m.book_slot];
    k.edges.check(spec, m.side, m.tick)?;                                // one compare per side
    let n = notional(m.qty, m.tick, spec);                               // exact u128
    if n > a.max_notional as u128 { return Err(rej(BAD_QTY, RSK_D_NOTIONAL)); }
    if k.open >= a.max_open_orders { return Err(rej(RISK_ORDER_COUNT, a.max_open_orders)); }
    let route = classify(m, snap);                                       // 05: Join|Improve|Cross
    let charge = if m.tif.is_ioc_or_fok() { Route::Cross } else { route };  // 04 §6.2
    let msg_fee: u128 = a.msg_fee(charge) as u128;                      // 0 for a join
    let bb = &mut l.bal[a.slot][m.book_slot];
    let mut nb = *bb;                                                    // committed below
    match m.side {
        Side::Buy => {
            let r = n.checked_add(fee_cap(n, m.qty, a.fee_mul)).ok_or_else(|| rej(BAD_QTY, RSK_D_OVERFLOW))?;
            let need = r.checked_add(msg_fee).ok_or_else(|| rej(BAD_QTY, RSK_D_OVERFLOW))?;
            if nb.quote_free < need { return Err(rej(RISK_CREDIT, 1)); }
            nb.quote_free -= need;
            nb.quote_resv += r;                       // cannot overflow: r ≤ need ≤ old quote_free
        }
        Side::Sell => {
            if nb.base_free < m.qty.0 as u64 { return Err(rej(RISK_CREDIT, 2)); }
            if nb.quote_free < msg_fee { return Err(rej(RISK_CREDIT, 1)); }
            nb.base_free -= m.qty.0 as u64;
            nb.base_resv += m.qty.0 as u64;
            nb.quote_free -= msg_fee;
        }
    }
    if m.post_only && route == Route::Cross { return Err(rej(POST_ONLY_WOULD_CROSS, snap.opp(m.side))); }
    match charge {                                                       // check 13, all or none
        Route::Join => {}
        Route::Improve => {                       // 04's BBO buckets (ids 3, 6) are tested first
            if k.il_tok == 0 { return Err(rej(RATE_LIMIT, RSK_BUCKET_LANE_IMPROVE)); }
            k.il_tok -= 1;
        }
        Route::Cross => {
            if k.xa_tok == 0 { return Err(rej(RATE_LIMIT, RSK_BUCKET_CROSS)); }
            if k.xl_tok == 0 { return Err(rej(RATE_LIMIT, RSK_BUCKET_LANE_CROSS)); }
            k.xa_tok -= 1; k.xl_tok -= 1;
        }
    }
    *bb = nb;
    k.open += 1;
    l.pass2.push_fee(msg_fee);       // pass 2 adds it to fee_acc and writes back open_orders
    Ok(route)
}
// After pass 1, the lane writes the four buckets' token counts back once (k.*_tok), and the
// session's 04 buckets likewise. A packet shed with BUSY never gets this far (§3.11).

#[inline(always)]
fn fee_cap(n: u128, qty: Qty, fee_mul: u64) -> u128 {
    // n ≤ u64::MAX here (checked by max_notional), so the product fits in u128.
    (((n as u64 as u128) * (fee_mul as u128)) >> 64) + 1 + qty.0 as u128
}

/// Release on CancelAck, Out, StpOut or kill. `filled_final` is final at this point (05).
/// Filled-but-unsettled lots keep their share until their events settle (§4.4).
fn risk_release_open(l: &mut Lane, o: &mut LaneOrder, filled_final: Qty) {
    let open = o.qty - filled_final;                            // lots that will never fill
    let bb = &mut l.bal[o.acct_slot][o.book_slot];
    match o.side {
        Side::Buy  => { let r = r_buy(open, o.tick, &l.books[o.book_slot], l.acct[o.acct_slot].fee_mul);
                        bb.quote_resv -= r; bb.quote_free += r; }          // checked
        Side::Sell => { bb.base_resv -= open as u64; bb.base_free += open as u64; }
    }
    o.closed = true; bb.open_orders -= 1;   // slot freed when settled == filled_final (§4.3)
}
```

**Replace.** A same-tick reduction is a `Reduce` (01 §6.2): no capital, and the removed lots'
reservation returns at its ack. Any other `Replace` reserves the new order in full at entry and
releases the old order's open remainder at the ack, so a quote update needs one order's headroom.
The reason: at entry the lane cannot know how much of the old order the BBO core fills before the
cut includes the replace, and netting would under-reserve whenever that race happens.

**Why reservations are taken at entry and released at the ack.** At entry the lane is the only
writer of the balance, so the check and the debit are one atomic lane step. At the ack, the BBO
core's filled quantity for the order is final (05), so the release is exact. Between the two, the
money is reserved, and that is exactly the interval in which the BBO core may fill the order.

**In-packet dependencies.** Pass 1 pushes each BBO-routed op as soon as it is classified, with
its in-packet dependency list (01 §14.2): the earlier ops of the same packet that touch the
opposite side within its price range, or its own handles. Those earlier ops are mostly joins
that pass 2 has not applied yet. Their reservations are already made, because pass 1 runs risk
in index order: op `j`'s reservation is complete before op `k > j` is classified. So when the BBO
core fills a listed op at its pre-assigned handle as if it rested, the money is behind it. The
lane writes the risk fields of each pre-assigned order record (§4.3) in pass 1, together with the
handle, so a fill event can never find an empty record; fill events are applied only at the next
boundary (`INV-RSK-1`), after pass 2. A listed op counts in `open_orders` from pass 1. An earlier
op that failed a check has no handle and is in no list.

### 3.10 Cycle budget

01 §14.2 fixes the lane's pass-1 cost at `LANE_PASS1_NS` = 5 ns per message plus 45 ns per packet,
and the apply at `LANE_APPLY_NS` = 9 ns per message. Pass 1 per message also carries parse (04),
classification and the BBO-ring push (05). This chapter commits risk and reservation to
**`RSK_PASS1_CYCLES = 16`** of pass 1's 25 cycles per message at 5 GHz (budget, 3.2 ns), and to
`RSK_PKT_NS = 6` ns of the 45 ns per packet.

Per message (`New`, issue cycles in a loop over the packet's messages; the only dependency that
crosses messages is the balance compare-and-subtract, 2 cycles):

| Step | Cycles (budget) | Note |
|---|---|---|
| Phase compare, `new_tok` decrement | 1 | token count hoisted (check 6) |
| Qty range, 2 compares | 1 | |
| Band, 1 compare against the side's edge | 1 | edges hoisted (§3.5) |
| Open orders, compare and increment | 1 | packet-local count |
| Notional: u32×u32→u64, u64×u64→u128 | 2 | 2 `mul` |
| Compare with `max_notional` | 1 | |
| Fee cap: 64×64→128, shift, add | 2 | 1 `mul` |
| Route-dependent fee and tokens, branch-free | 1 | table lookup by route, masked decrements |
| `BookBal`: u128 compare, subtract, add | 3 | line in L1 after the packet's first message |
| Queue the fee for pass 2 | 1 | |
| Reserve | 2 | |
| **Total** | **16** | 3.2 ns at 5 GHz |

Per packet (`RSK_PKT_NS`, ~30 cycles): state, halt and phase, band edges (one `mul` on a new
snapshot version), four bucket refills and their write-back. None depends on the MAC, so they run
beside the SipHash chain and commit only after `tag_seq` passes. On a pool core the account-token
CAS (~20 ns, §1.2) and, for a BBO-routed op, the `PoolRisk` token come on top. They are outside
`RSK_PKT_NS`, and the pool's `predicted_path_ns` (05) includes them, so deadline admission sees
them.

**This is a maximum, not an average.** The production code is branch-free over the 13 checks:
each check sets a bit, the first failure is picked by priority select, and every state update
(tokens, `open`, balance) is masked by "no failure". So every `New` costs the same 16 cycles,
accepted or rejected, and risk causes no branch mispredict. The pseudocode's early returns are
for readability; B-RSK1 checks that both forms agree. The account lines are never a DRAM miss
(§1.2). Pass 2's risk share is ≤ 2 ns of `LANE_APPLY_NS` (fee into
`fee_acc`, one `open_orders` write-back, statistics). `Cancel` and `Reduce` have no per-message
pass-1 risk work beyond 04's type dispatch; their release costs ≤ 4 ns at the ack (§3.9).

### 3.11 `BUSY`: no reservation, no token, no fee

Risk state after a `Reject BUSY` (01 §14.1) is exactly as if the shed op had never arrived:

- **Shed at the lane.** The lane sheds the whole packet at dequeue, before pass 1, and logs
  `PacketRecord.flags.SHED`. No check runs, so the packet makes no reservation, takes no token from
  any bucket (session, account, lane or pool), pays no message fee and changes no counter. A pool
  core sheds before it takes the account token, so a shed never moves a pooled account's state.
  Replay reads the flag and skips the packet the same way.
- **How often (01 §14.17 item 2).** A paced client on a dedicated lane is never shed at the lane
  stage. Its BBO-bound ops share the BBO, TX and stream cores, so its total `BUSY` is ≤ 1e-5 at
  full book load (crosses and improves only) and ≤ 1e-8 at ≤ 20% load. A pooled client is shed
  ≈ 1e-3 of packets at full book load and ≤ 1e-6 at ≤ 20% load (02 REQ-LAT-5). B3 measures every
  class.
- **Shed at the BBO core.** A forwarded op that the BBO core sheds (`StepKind::Shed`) was reserved
  and charged in pass 1. The Shed step writes a `Shed` fill event (kind 6, §4.1) to its lane. At
  that boundary the lane releases the whole reservation, returns the message fee (`quote_free` +,
  `fee_acc` −) and the op's tokens (each bucket capped at its burst), and sends `Reject BUSY`.
  Later ops of the packet that 05 sheds with it, as dependents, get the same release. So `BUSY`
  carries no fee in either case.

Decision: **`BUSY` consumes no rate-limit tokens.** The buckets meter work that the venue admitted.
A shed op got none, and the overload is the venue's, not the client's. Keeping the token would
punish the client twice: a `BUSY` now and a `RATE_LIMIT` on its retry. A refund cannot raise BBO
load above the bucket rate, because the refunded token replaces an op that never ran on the BBO
core. It replays, because the Shed step is in the order stream and the lane applies its event at
a logged boundary (`fills_applied`).

## 4. Settlement on fill events

### 4.1 The BBO → lane fill-event ring

The BBO core writes fill events. Each lane settles its own account's side of each fill
(01 §12.2). There is one SPSC ring per lane, written only by the BBO core and read only by that
lane. In a book group each book's BBO core has its own ring to each lane, and the lane polls them
in book-slot order. A pool core is a lane here too: an event goes to the core whose `Segment16`
holds the order, and that core takes the account's token (§1.2) before it settles.

```
off size field       type      meaning
  0   8  step        StepId    the step that produced the event
  8   2  ordinal     u16       ordinal of the match in the step; 0xFFFF for TakerEnd
 10   1  kind        u8        1 MakerFill, 2 TakerFill, 3 TakerEnd, 4 StpOut, 5 AuctionFill,
                               6 Shed (the op was shed by a Shed step, §3.11)
 11   1  flags       u8        bit0 side of this lane's order (0 buy), bit1 last event of this
                               step for this lane, bits 2–7 = 0
 12   4  handle      Handle    this lane's order
 16   4  tick        Tick      fill tick (0 for TakerEnd, StpOut and Shed)
 20   4  qty         Qty       fill qty; TakerEnd: lots that leave the book; StpOut: lots removed
 24   1  cause       u8        TakerEnd: 0 rested, 1 IOC, 2 FOK, 3 STP, 4 auction-only; else 0
 25   1  book_slot   u8        book within the group
 26   2  n_makers    u16       TakerFill: matches aggregated in this level; else 0
 28   4  reserved    u32       0
```

`RSK_FILL_EVENT_BYTES = 32`, two events per 64-byte line. The ring holds `ENG_FILL_RING` =
65_536 events per lane (05, 2 MB).

Event rules (requests to 05):

1. A `MakerFill` is one maker match. A `TakerFill` aggregates the matches of one taker at one
   price level, with the ordinal of its first match. The taker's response stream also has one
   `Fill` per level (01 §6.4), so the two agree.
2. The events of one taker in one step are contiguous and end with one `TakerEnd`. A `Rescan`
   step that has several aggressors emits each aggressor's group contiguously.
3. **Per-step publication.** The BBO core writes all of one step's events for a lane, then
   publishes that ring's producer index with one release store. A lane therefore never sees part
   of a step. Bit 1 of `flags` marks the last event of the step for this lane, so a lane that
   bounds its drain can stop on a step boundary.
4. If a ring is full, the BBO core never spins: it moves the events to its private spill buffer
   (`ENG_FILL_SPILL`, 05 §14.3) and refills the ring as the lane drains, so no fill waits on a
   lane. Spill use is an alarm (§9.3), and B3 must show it never happens at 60% BBO load.

### 4.2 The lane loop and `fills_applied`

05 §6.1 owns the lane loop. Settlement runs at its boundary step B1: before a packet (or an
Advance record), the lane applies every fill event with step in `(fills_applied, f]`, then settles
the ops that cut `C_f` covers (B2), then processes the packet (B4). The lane picks `f` and logs
it in the `PacketRecord`, so replay never guesses: `f` is the largest step ≤ `lc.step` whose events
in `(fills_applied, f]` number ≤ `RSK_DRAIN_MAX`, but at least one whole step when one is
published (`INV-RSK-1`). Background work (a control packet, §2.4; a mass-cancel chunk, §3.7; one
more boundary for a fill backlog) runs only when no client packet waits (05 idle work).

1. **Bounded B1.** `RSK_DRAIN_MAX = 8` events (budget) × `RSK_SETTLE_NS` = 96 ns is the most that
   B1 adds in front of a packet, unless one step alone gives this lane more events. A step that
   large is a sweep through many of one lane's orders, and `STEP_FILL_CAP` = 64 (01 §14.15
   item 6) bounds it. It delays only that lane, and a packet that it makes late is answered
   `BUSY` (01 §14.1). B3 counts it within its lane class's `BUSY` bound.
2. **Backlog drains in idle time.** With lane load ≤ 0.60 the lane is idle ≥ 40% of the time, and
   settlement is ~1% of a lane (§4.6), so the backlog stays below one event on average.
3. **Acks still advance.** `C_f` is non-decreasing in `f`. A smaller `f` holds back only the acks
   of ops above `C_f`, and only until the next boundary, which follows at once because pending
   events make an Advance record due (05 §6.2).

**Why `fills_applied` makes the reuse of proceeds replayable.** A lane checks a new order against
`quote_free` and `base_free`. Those include the proceeds of every fill the lane has already
settled. Which fills those are depends on timing: when the BBO core published the step relative
to when the packet reached the lane. A replica cannot reproduce that timing. It reproduces the
recorded value instead. Example: step 100 fills A's resting sell on lane 7, and A's next packet P
buys with those proceeds. If lane 7 settled step 100 first, P is accepted and its record says
`fills_applied = 100`; if it polled P first, P is `RISK_CREDIT` and the record says less. The
replica applies exactly the events the record names, so it agrees either way; without the field
it would have to guess, and a wrong guess is a fork.

Replay rule (07 and 05 implement it): before a replica's lane processes the packet of a
`PacketRecord` with `fills_applied = S`, it applies all of its fill events with step ≤ S, and no
event with step > S. This schedule always exists. Step S's cut was read before step S ran, and
lane 7 processed P only after it saw step S's events. So `cut_S[7] < first_lane_seq(P)`. The
dependencies "P after step S" (from `fills_applied`) and "step S after the lane ops at or below
`cut_S`" (from the cut) therefore never form a cycle.

`fills_applied` also orders everything else that a fill changes in the lane: `open_orders`, slot
reuse, and whether a cancel finds an order already closed. One field covers all of it, because
the lane applies fills only between packets (`INV-RSK-1`).

**Book groups.** Each book has its own `StepId` sequence, and `PacketRecord` has one
`fills_applied`. So every piece of lane state that a fill can change is per book: `BookBal`
(with `open_orders`), the slot pool, and `fee_acc`. A packet names one book in its header and
touches only that book's state, so it depends only on that book's fill events, and
`fills_applied` is a step of that book. A control op that spans books (a kill, a timer tick) is
sent as one control packet per book.

### 4.3 Order fields that settlement uses

The lane-private order record (05 owns its layout) must hold, for risk:

| Field | Type | Written by | Use |
|---|---|---|---|
| `acct_slot` | u32 | lane | which `AcctRisk` and `BookBal` |
| `book_slot` | u8 | lane | which book of the group |
| `side`, `tick`, `qty` | | lane | reservation formula; `qty` changes on Reduce |
| `settled` | Qty | lane | lots whose fill events this lane applied; `rem_u = qty − settled` |
| `closed` | bool | lane | the open remainder was released (§3.9) |
| `route` | u2 | lane, pass 1 | Join, Improve or Cross as charged (`IOC`/`FOK` are Cross): which tokens a `Shed` returns (§3.11) |
| `fee_mul` | u64 | lane, pass 1 | the account's `fee_mul` at entry: every release and fee cap of this order uses it, not the current one (§5.2 rule 2) |
| `msg_fee` | u32 | lane, pass 1 | the message fee charged at entry, so a `Shed` returns exactly that amount (§3.11, §5.3) |

`vyrn-risk` keeps these risk fields in `OrderRisk` (`crates/engine/vyrn-risk/src/order.rs`).

The lane frees the order's slot when `closed && settled == filled_final`. Until then a late fill
event can still find the order. Generation bits in `Handle` protect the slot after reuse.

### 4.4 Settlement pseudocode

```rust
fn settle(l: &mut Lane, ev: &FillEvent) {
    let o = l.orders.get_mut(ev.handle).unwrap_or_else(|| engine_fault(EvUnknownHandle, ev));
    let (a, bb, spec, fee_acc) = l.settle_ctx(o);       // AcctRisk, BookBal, BookSpec, i128 acc
    match ev.kind {
        MAKER_FILL | TAKER_FILL | AUCTION_FILL => {
            let q = ev.qty;
            let rem_u = o.qty - o.settled;              // checked; q ≤ rem_u or engine fault
            let n = notional(q, ev.tick, spec);         // exact u128, at the fill tick
            match o.side {
                Side::Buy => {
                    let rel = r_buy(rem_u, o.tick, spec, a.fee_mul)
                            - r_buy(rem_u - q, o.tick, spec, a.fee_mul);
                    bb.quote_resv = sub(bb.quote_resv, rel);       // §3.2 release lemma
                    bb.quote_free = add(bb.quote_free, sub(rel, n));
                    bb.base_free  = add(bb.base_free, q as u64);
                }
                Side::Sell => {
                    bb.base_resv  = sub(bb.base_resv, q as u64);
                    bb.quote_free = add(bb.quote_free, n);
                }
            }
            o.settled += q;
            match ev.kind {
                TAKER_FILL   => l.taker_notional = add(l.taker_notional, n),  // fee at TakerEnd
                MAKER_FILL   => apply_fee(bb, fee_acc, n, a.maker_ppm),
                AUCTION_FILL => apply_fee(bb, fee_acc, n, a.auction_ppm),
                _ => unreachable!(),
            }
            a.stats.on_fill(ev.kind, q, n);                         // statements, §10
            if o.settled == o.qty && !o.closed { l.close_filled(o); } // open_orders −= 1, free slot
        }
        TAKER_END => {
            apply_fee(bb, fee_acc, l.taker_notional, a.taker_ppm);  // one rounding per step
            l.taker_notional = 0;
            if ev.cause != CAUSE_RESTED {
                // IOC/FOK/STP/auction-only remainder leaves the book: filled_final = settled + 0
                risk_release_open(l, o, o.settled);
                l.close_if_settled(o);
            }                                                       // else: rests as a maker
        }
        STP_OUT => {
            // The BBO core removed ev.qty open lots of this resting order (cancel oldest).
            risk_release_open(l, o, o.qty - ev.qty);
            l.close_if_settled(o);
        }
        SHED => {
            // §3.11: as if the op never arrived. Nothing of it was filled.
            risk_release_open(l, o, Qty(0));
            l.refund_msg_fee(bb, fee_acc, a, o.route);              // quote_free +, fee_acc −
            l.refund_tokens(a, o.route);                            // capped at each burst
            l.stage_reject(o, BUSY);
            l.close_if_settled(o);
        }
        _ => engine_fault(EvBadKind, ev),
    }
}

fn apply_fee(bb: &mut BookBal, acc: &mut i128, n: u128, ppm: i32) {
    if ppm >= 0 {
        let fee = ceil_div(n * ppm as u128, RSK_FEE_DENOM);    // n × ppm < 2^64 × 2^14: fits
        bb.quote_free = sub(bb.quote_free, fee);                // covered: §3.2 / §5.4
        *acc = acc.checked_add(fee as i128).unwrap_or_else(|| engine_fault(FeeAccOverflow));
    } else {
        let rebate = (n * ppm.unsigned_abs() as u128) / RSK_FEE_DENOM;   // floor
        bb.quote_free = add(bb.quote_free, rebate);
        *acc = acc.checked_sub(rebate as i128).unwrap_or_else(|| engine_fault(FeeAccOverflow));
    }
}
// add/sub are checked u128/u64 operations whose failure calls engine_fault (§4.5).
```

Maker versus taker, side by side:

| | Buy side receives | Buy side pays | Sell side receives | Sell side pays |
|---|---|---|---|---|
| Taker | `q` lots base | `N(q,p)` + taker fee once per step, from the released reservation | `N(q,p)` − taker fee | `q` lots from `base_resv` |
| Maker | `q` lots base (+ rebate) | `N(q,p)` + maker fee per fill | `N(q,p)` − maker fee (+ rebate) | `q` lots from `base_resv` |
| Auction | `q` lots base | `N(q,p)` + auction fee per fill | `N(q,p)` − auction fee | `q` lots |

A reservation is released in two places only: a fill (its telescoping share) and a close of the
open remainder (`risk_release_open`). So a filled or closed order holds zero (`INV-ACC-1`).

### 4.5 Settlement never rejects

A fill is final when the BBO core writes it. The lane cannot reject it. So settlement has no
failure path for a correct engine:

- Buy: `rel ≥ N(q, p) + fee` by the release lemma (§3.2). For the taker fee, which is charged at
  `TakerEnd`, the sum of the step's `rel − N` already went to `quote_free` with no packet in
  between (`INV-RSK-1`), and it covers `ceil(Σ N × taker_ppm / D)`.
- Sell: `base_resv ≥ q` by `INV-ACC-1`, and `N(q, p) ≥ fee` because `ppm ≤ RSK_FEE_PPM_MAX`.
- Rebates only add.

A failed checked operation in `settle` is therefore an engine bug. `engine_fault` halts the book
(snapshot `halted = 1` via the control core) and keeps the lane serving cancels. A replica that
does not fault at the same op has forked (07). Halting beats a wrong balance.

### 4.6 Settlement budget

`RSK_SETTLE_NS = 12` ns per fill event (budget), because B1 runs in front of a packet (§4.2).
The fee in `apply_fee` is an exact division by the constant `RSK_FEE_DENOM` of a dividend below
2^78 (`n < 2^64`, `ppm < 2^14`). It uses the Granlund–Montgomery constant-divisor method (two
64×64→128 multiplies, a shift and one correction), which is exact for that range, instead of the
`__udivti3` libcall (~40–80 cycles, vendor). With two `r_buy` evaluations the event is ~11
multiplies and ~60 cycles.

At the design point: 10M crosses/s × ~3 matches per cross (assumption, checked by the B3 mix) =
30M maker events + 10M taker groups (≤ 2 events each) ≈ 50M events/s, or 1M per lane = 12 ms/s =
**1.2% of a lane**.

| Name | Statement |
|---|---|
| `INV-RSK-1` | A lane applies fill events only at a boundary (between packets), and only in whole steps. `PacketRecord.fills_applied` is the step of the last event applied before the packet; the lane picks it (§4.2) and replay reads it. |
| `INV-RSK-2` | Every risk decision on a packet is a function of the lane state after applying events with step ≤ `fills_applied`, the packet, its `rx_ts`, and the snapshot that 05 records for it. |

## 5. Fees

### 5.1 What is charged

| Charge | Basis | When | Paid from |
|---|---|---|---|
| Taker fee | notional, `taker_ppm` | once per (taker order, step), at `TakerEnd` | buy: released reservation; sell: proceeds |
| Maker fee or rebate | notional, `maker_ppm` (may be negative) | per maker fill | as above; a rebate credits `quote_free` |
| Auction fee | notional, `auction_ppm` | per auction fill, both sides | as above |
| Message fee | per message class (§5.3) | at lane classification of an accepted `New` or `Replace` | `quote_free` of the order's book |

Every fee is in the book's quote asset, in quote units (§2.1). `RSK_FEE_DENOM = 1_000_000`, so a
rate is in parts per million (1 ppm = 0.01 bp). `RSK_FEE_PPM_MAX = 10_000` (1%) is the hard cap
on any rate.

### 5.2 Maker and taker schedules

The schedule has up to `RSK_FEE_TIERS = 8` tiers per book. A tier is selected by the master
account's trailing 30-day traded notional in that book's quote asset, computed by the replicas at
each epoch boundary from finalized statements (§10). The selected rates go into each account's
`AcctRisk` with the epoch configuration, or by `CtlSetFees`.

Default schedule (config):

| Tier | 30-day notional ≥ (USD equivalent) | taker_ppm | maker_ppm |
|---|---|---|---|
| 0 | 0 | 400 | 100 |
| 1 | 10^7 | 300 | 50 |
| 2 | 10^8 | 250 | 0 |
| 3 | 10^9 | 200 | −20 |
| 4 | 10^10 | 150 | −40 |
| auction | — | 100 both sides | — |

Rules, checked when a schedule is loaded:

1. `−maker_ppm ≤ min over tiers of taker_ppm`. A rebate never exceeds the lowest taker fee, so
   the venue's net fee on every match is ≥ 0. Per step: `ceil(Σ N × t / D) ≥ Σ floor(N × r / D)`
   when `r ≤ t`.
2. Rates change only at an epoch boundary (or by `CtlSetFees`, which applies to orders that
   arrive after it). A resting order's reservation used `fee_mul` from its entry. If a rate rises
   above that `fee_mul`, the release lemma could fail, so `CtlSetFees` may raise `fee_mul` (the
   `max_fee_ppm` multiplier) only while the account holds no buy reservation in the book
   (`quote_resv = 0`), and otherwise the lane rejects the op (`RISK_ORDER_COUNT`, §2.4). Resting
   sells do not block it: the lemma covers buys only, and a sell's fee comes from its proceeds.
   Lowering is always accepted. An epoch boundary re-reserves every resting order (08 loads state,
   and the loader recomputes `quote_resv` with the new `fee_mul`, failing the order's carry-over
   as `Out` if the account cannot cover the difference).
3. Tier volume is the master's total, so sub-accounts share the tier (§1.5).

### 5.3 Message-class fees

Messages differ in cost by ~2× at the BBO core (15 ns against 8 ns, 01 §14.15 item 2) and not at
all at the lane. The fee follows the
BBO core's cost, because the BBO core is the one resource that one book cannot scale
(`CROSS_CAP`, DESIGN §3).

`msg_fee(class) = RSK_MSGFEE_PER_BBO_NS × bbo_ns(class)`, with `bbo_ns` = 0 for lane-only work.

| Class | Fee (config default, quote = µUSD) | Reason |
|---|---|---|
| Join, Cancel, Reduce, CancelAll | 0, always | lane-only work; cancels must never be blocked by a fee |
| Improve | 8 × `RSK_MSGFEE_PER_BBO_NS` = 8 µUSD | uses 8 ns of BBO core |
| Cross | 15 × `RSK_MSGFEE_PER_BBO_NS` = 15 µUSD | uses 15 ns of BBO core (`BBO_CROSS_NS`); charged even if the cross does not fill |

`RSK_MSGFEE_PER_BBO_NS = 1` µUSD per BBO-ns (config). At `CROSS_CAP` this prices the BBO core
at 10M × 15 µUSD = 150 USD/s at full cross load. The operator sets the price per epoch from the
previous epochs' peak cross rate (§9.3): if the peak 1-second cross rate passed 70% of
`CROSS_CAP`, the next epoch's price rises.

Decision: **depletions are free.** A cancel that empties the best level triggers an 8 ns
depletion step. Charging the cancel would block risk reduction, and the depletion cost is
already bounded by the cancel rate limit.

Message fees are debited from `quote_free` at entry (§3.9) and never refunded, also not when the
order is later cancelled; the one exception is a `BUSY` shed, which owes no fee (§3.11). A
`Replace` pays the class of its new order.

### 5.4 Fee rounding

The rules are in §3.3. Worked example, quote = µUSD, `tick_size` = 10 µUSD per lot per tick,
tier 1 (`taker_ppm = 300`, `maker_ppm = 50`), buy 7 lots at limit tick 100_000, filled 3 at
99_998 and 4 at 99_999 in one step:

```
reservation N(7, 100_000) = 7 × 100_000 × 10              = 7_000_000
            fee_mul       = ceil(300 × 2^64 / 10^6)       (max_fee_ppm = 300)
            F             = floor(7_000_000 × fee_mul / 2^64) + 1 + 7 = 2_100 + 8 = 2_108
            R             = 7_002_108
fills       N1 = 3 × 99_998 × 10 = 2_999_940    N2 = 4 × 99_999 × 10 = 3_999_960
taker fee   ceil((2_999_940 + 3_999_960) × 300 / 10^6) = ceil(2_099.97) = 2_100
released    7_002_108 (telescoped);  paid 6_999_900 + 2_100 = 7_002_000
returned to quote_free: 108 = 100 (price improvement) + 8 (unused fee cap: 1 + 7 lots)
```

### 5.5 Fees in BASE and CHAIN mode

| | BASE | CHAIN |
|---|---|---|
| Where fees accrue | lane `fee_acc[book]` (i128), a venue fee account per lane per book | same |
| When they leave the book | at epoch end, the replicas' certified statement totals `Σ fee_acc` and the ledger credits the operator's fee account | at epoch end, a state transition credits the fee pool |
| Who receives them | the operator | the fee pool, split per 09 (validators, the epoch's sequencer operator, insurance) |
| Who sets the schedule | operator config, signed admin command, effective at the next boundary | a governance transaction finalized before the epoch starts (09) |
| Reverted fills (bad `K_com`, DESIGN §7) | n/a | their fees revert with them; the canonical replay excludes the packet (09) |

The lane code is identical in both modes. Only the epoch-end sweep and the schedule's source
differ (`C-ONEBIN`).

## 6. v2 preview: isolated-margin linear perpetuals

v2 adds linear perpetuals with isolated margin: each (account, perp book) is its own margin
account, and losses in one book never touch another. Cross margin stays out of scope (01 §12.1).
Everything stays in the lane, so the v1 single-writer and replay arguments carry over unchanged.

**State per (account, perp book), replacing `BookBal`:** `PerpPos { margin: QuoteAmt, im_resv:
QuoteAmt, cost: i128, pos: i64, funding_idx: i64 }`, 64 bytes, `#[repr(C, align(64))]`.

| v1 spot | v2 perp |
|---|---|
| Buy reserves `R_buy`; sell reserves base | Any order reserves `IM(n, t) = ceil(N(n,t) × im_ppm / D) + F(n,t)` from `margin − im_resv − used_margin`, in pass 1 like v1 |
| Fill moves base and quote | Fill moves `pos` and `cost`; realized PnL on the reducing part moves into `margin` |
| No mark price, no funding | `CtlMark { book, mark_tick }` every `RSK_MARK_PERIOD_MS = 100` (config) from a finalized oracle transaction; `CtlFunding { book, delta_idx }` hourly, applied lazily at the position's next touch |
| No liquidation; `RISK_POSITION` unused | `equity < maintenance` checked on each `CtlMark` and fill; `RISK_POSITION` for an order over the max position; flags bit 6 = reduce-only (requested) |

**Liquidation is an ordinary cross from a liquidation account.** When `equity < MM`, the lane
cancels the account's orders in the book (chunked, §3.7), moves the position and its margin to the
lane's own liquidation account at the mark price (one lane-local change), and that account sends an
IOC cross at `mark ± RSK_LIQ_SLIPPAGE_BPS` through the normal path, risk checks and BBO step. So
liquidation adds no BBO-core path, no step kind, and no wait on another lane. The insurance fund
is the sum of the lanes' liquidation accounts, consolidated at each epoch end. A `CtlMark` sweep
runs in idle-time chunks of `RSK_KILL_CHUNK` positions, like a mass cancel. B2 gains a v2 mix.

## 7. Market data (`vyrn-md`)

### 7.1 Source and placement

Decisions:

1. **Market data is generated by a replica, never by the sequencer.** The sequencer has no cycles
   to spare. More important, a feed derived from the log can only show events that are already
   ordered and on two paths (`INV-FRAME-FIRST`), so the sequencer cannot leak or invent a print.
2. **Each facility runs one non-voting observer box with `vyrn-md`** (01 §14.11). The voting
   replica R1 in the sequencer's facility (01 §14.4) replays and votes at 1B msgs/s, so feed load
   never runs beside a vote. The observer in the sequencer's facility publishes the **A feed**, and
   the next facility's observer in failover order the **B feed**. Both are functions of the log,
   so they are byte-identical, and a subscriber arbitrates by sequence number. After a failover,
   the A role follows the sequencer.
3. **On bare metal the A observer reads the sequencer's inbound fibers through passive optical
   taps** (`C-COTS`, no logic in the path). It then holds every payload at the same moment as the
   sequencer and does not wait for the data tier. It accepts a tapped packet only when its hash
   matches the `PacketRecord.pkt_hash`. On AWS (no taps) the observer takes payloads from the data
   tier, as every replica does.

### 7.2 Feeds

| Feed | Content | Conflation | Rate at the design point (budget) | Wire bandwidth (budget) |
|---|---|---|---|---|
| `MBO` | every order event: add, delete, reduce, exec, step | none | ~1.0B records/s | ~140 Gbps over 5 channels |
| `MBO-C` | `MBO`, varint delta-encoded (§7.5) | none | same | ~60 Gbps (estimate, open question 2) |
| `MBP-10` | aggregated top 10 levels per side | per `MD_MBP_WINDOW_NS = 10_000` of order-stream time | ≤ 2M records/s | ≤ 0.3 Gbps |
| `TOB` | best level per side | price changes: none; quantity-only changes: per `MD_TOB_WINDOW_NS = 1_000` | ~30M records/s | ~4 Gbps |
| `TRADES` | one record per maker match, with execution ID | none | ~30M records/s | ~4 Gbps |
| `STATS` | OHLC, volume, VWAP, trade count, cross rate, status | per second | < 100 records/s | negligible |

Conflation is defined on order-stream time (`rx_ts`), so it is deterministic and the same for
every subscriber.

**Bare metal delivers full `MBO` at 1B msgs/s.** The `REF` observer (01 §14.16) has 4 tap RX
ports and 2 order-stream ports (3 × dual-port ConnectX-6 Dx) and 3 × X2541 for publication, 96
PCIe lanes:
300 Gbps of egress for ~208 Gbps of feeds, 69% of line rate (REQ-THR-4). One core encodes each
channel of each feed (10 cores for `MBO` and `MBO-C`, ≤ 4 ns per record). A subscriber takes full
`MBO` (~35 Gbps per channel) on two 100G ports. Only AWS offers less, as a bandwidth fact (§7.7).

### 7.3 Packet framing

Every `vyrn-md` packet is UDP, little-endian, with a 32-byte header and up to
`MD_MAX_RECS_PER_PKT = 88` records of 16 bytes (1_440 bytes of payload, inside a 1_500-byte MTU).

```
off size field
  0   2  channel    u16       MD_FEED_* code (high byte) | channel index (low byte)
  2   2  count      u16       records in this packet, 0 = heartbeat
  4   2  book       BookId
  6   2  epoch16    u16
  8   8  seq        u64       per channel, starts at 1 each epoch, +1 per packet, gapless
 16   8  ts_base    Nanos     base for ts_delta fields in this packet
 24   8  step_base  StepId    MBO lane channels: watermark (§7.4); other channels: base for
                              step_delta fields and the step open at packet start
```

Packet boundaries are a function of the log, so A and B packetize identically. A packet closes
when (a) it holds 88 records, or (b) it is non-empty at the end of a step interval that added no
record to this channel, or (c) at the end of the first step interval after which its first record
is `MD_FLUSH_NS = 1_000` older than the newest replayed `rx_ts`. Rule (b) flushes at low traffic,
rule (c) at high traffic. A channel with nothing to send emits a header-only heartbeat every
`MD_HEARTBEAT_MS = 1` (on the `CtlTimerTick` boundary).

`ts_base` is chosen so that every `ts_delta` in the packet is in `0 … 65_535`. The encoder closes
the packet early when a record does not fit. `step_delta` works the same way.

### 7.4 MBO structure: lane channels, a step channel, and the merge rule

One core cannot sequence 1B records/s into one stream, and one 100G port cannot carry it. So
`MBO` is split by lane, which is how the engine produces it:

- **Lane channels** `0 … MD_MBO_LANE_CHANNELS − 1` (`= 4`). Channel `k` carries the lane ops
  (adds, deletes and reduces from joins and cancels) of the lanes `L` with `L mod 4 = k`, in lane
  order. ~250M records/s and ~35 Gbps each (budget).
- **Step channel** (index 4). Every step that changes the book: `MD_STEP`, its `MD_EXEC` records,
  the `MD_ADD` of an improve or a resting residual, `MD_DELETE` from STP, and status records.
  ~90M records/s and ~12 Gbps (budget).

Lane ops of different lanes between two steps touch different orders, so their relative order
does not matter for book state. Time priority among them comes from the `(rx_ts, lane)` in each
`MD_ADD`, not from the feed order. Only the position of a lane op relative to steps matters:

```
 lane channel k:  ADD ADD SYNC(T) DEL ADD ... │ header.step_base = W_k (watermark)
 step channel:    STEP(T) EXEC EXEC ... STEP(T+3) EXEC ...

 SYNC(T): the lane-op records after it (up to the next SYNC) are ordered after step T and
          before step T+1. Emitted lazily, only before the first record after a new step.
 W_k:     every record of channel k ordered before step W_k + 1 is in this packet or earlier.

 Subscriber rule: apply step T only when W_k ≥ T − 1 for every k. Before step T, apply every
 pending lane-op record whose SYNC position is < T, in any order across channels.
```

This is exact: a subscriber that follows the rule reconstructs the replica's book after every
step. The watermark bounds the wait: every lane channel flushes at least each `MD_FLUSH_NS`
(rule c) or on a quiet interval (rule b). The step channel alone gives trades and the BBO path.

### 7.5 Record layouts (16 bytes each)

`oid: u32 = (lane << 24) | slot`, unique among live orders in an epoch. The handle's generation
bits are dropped: a slot reappears only after a `MD_DELETE` or a full `MD_EXEC` ends the order.

| Code | Name | 0 | 1 | 2–3 | 4–7 | 8–11 | 12–15 |
|---|---|---|---|---|---|---|---|
| 0x01 | `MD_ADD` | type | bit0 side, bit1 via BBO core, bit2 auction | ts_delta u16 (priority rx_ts) | oid | tick | qty |
| 0x02 | `MD_DELETE` | type | cause (below) | 0 | oid | tick | qty removed |
| 0x03 | `MD_REDUCE` | type | 0 | 0 | oid | tick | qty after |
| 0x0E | `MD_SYNC` | type | 0 | 0 | 0 | step u64 (bytes 8–15) | |
| 0x10 | `MD_STEP` | type | step kind | n_exec u16 | step u64 (bytes 4–11) | | taker oid |
| 0x11 | `MD_EXEC` | type | bit0 aggressor side | ordinal u16 | maker oid | tick | qty |
| 0x12 | `MD_BUST` | type | 0 | ordinal u16 | 0 | step u64 (bytes 8–15) | |
| 0x20 | `MD_STATUS` | type | 0 halted, 1 auction, 2 continuous, 3 closed | 0 | epoch u32 | step u64 (bytes 8–15) | |
| 0x21 | `MD_ATTEST` | type | 2 final, 3 settled | 0 | height low u32 | last step u64 (bytes 8–15) | |
| 0x30 | `MD_LEVEL` | type | bit0 side, bits1–4 level 0–9, bit5 empty | orders u16 (saturating) | tick | qty u64 (bytes 8–15) | |
| 0x40 | `MD_TRADE` | type | bit0 aggressor side, bit1 auction | ts_delta u16 | step_delta u16 (4–5), ordinal u16 (6–7) | tick | qty |
| 0x41 | `MD_TRADE_BUST` | type | 0 | 0 | step_delta u16, ordinal u16 | tick | qty |
| 0x50 | `MD_STAT` | type | stat id | 0 | second of epoch u32 | value u64 (bytes 8–15) | |
| 0x60 | `MD_SNAP_BEGIN` | type | feed | 0 | n records u32 | as-of step u64 (bytes 8–15) | |
| 0x61 | `MD_SNAP_RESUME` | type | channel index | record index u16 | 0 | packet seq u64 (bytes 8–15) | |
| 0x62 | `MD_SNAP_END` | type | 0 | 0 | 0 | first 8 bytes of BLAKE3 of the body | |

`MD_DELETE` causes: 1 cancel, 2 replace, 3 STP, 4 account kill, 5 session kill or
cancel-on-disconnect, 6 allocation shrink, 7 epoch end, 8 halt purge, 9 `MBO-W` window exit. A
`Replace` that loses priority is `MD_DELETE(cause 2)` then `MD_ADD`. `TOB` uses `MD_LEVEL` level 0.
The bust records exist for `CHAIN` busts (DESIGN §7) and for reverts in either mode (07 §9.6,
01 §14.19 B): when the final log, or a final bust verdict, differs from what was published, the
observer busts the execution.

**Four facts, labeled separately** (01 §14.13 item 3). The feed never folds them into one
"confirmed" flag. *Execution* is the `MD_STEP`/`MD_EXEC` itself, and the client's own `Fill` is its
volatile form. *Durability* holds for every record on the feed: the observer publishes only steps
whose frames it has from both replication paths, and `INV-FRAME-FIRST` put them there before any
fill left. *Finality* is an `MD_ATTEST(final)` on the step channel when a block's certificate
arrives: every step ≤ its `last step` is final (≤ 10 ms, 01 §14.9). *Settlement* is an
`MD_ATTEST(settled)`: in `BASE` when the ledger has credited the epoch statement (§10), in
`CHAIN` when 09's settlement covers the step.

`MBO-C` carries the same records in the same channels, with each record encoded as a one-byte
type, then LEB128 varints of `oid − prev_oid`, `tick − touch`, `qty`, and `ts_delta`. Its packets
carry the same header and the same `seq` rule.

### 7.6 Snapshot and incremental recovery

- **Snapshot points are in the log:** after the last step of every block whose height is a
  multiple of `MD_SNAP_EVERY_BLOCKS = 1_000` (once per second). A and B take the same snapshot.
- **The snapshotter is a subscriber.** A separate `vyrn-md` process consumes the incremental feed,
  keeps its own book, pauses at the snapshot point, serializes, and catches up from its buffer.
  So every snapshot exercises the same merge rule that subscribers use.
- **Content:** `MD_SNAP_BEGIN`; the book in level-FIFO order as `MD_ADD` records (ts_delta 0, the
  order is the priority); one `MD_SNAP_RESUME` per channel naming the exact record where
  incremental processing resumes; `MD_SNAP_END`. `MBP-10` and `TOB` snapshots use `MD_LEVEL`.
- **Snapshot channels** run at `MD_SNAP_GBPS = 10` (budget): 10M live orders = 160 MB = ~130 ms
  per cycle. A larger book cycles more slowly; snapshots never throttle the incremental feed.
- **Recovery.** Join the incremental channels and buffer. Read a snapshot. Drop buffered records
  before each channel's resume point. Apply the rest by the merge rule. A gap in one channel is
  repaired from the retransmit service (TCP, by channel and seq range, holding
  `MD_RETX_SECS = 30` s) or by the next snapshot.
- **Epoch start.** Sequence numbers and oids restart each epoch: the book moves home and moved
  accounts' orders get new lanes (§1.3). Each epoch opens with a snapshot after the auction (08).

### 7.7 Distribution

| Environment | Method | Fairness mechanism |
|---|---|---|
| Bare metal | One multicast group per channel per feed; merchant switches replicate (IGMP snooping inside a facility, PIM to cross-connect ports) | One send; the switch replicates; the operator equalizes cross-connect fiber lengths |
| AWS | Unicast fan-out: `vyrn-md` sends to `vyrn-md` relays, each serving ≤ `MD_RELAY_FANOUT = 32` subscribers | Each relay rotates send order per packet: subscriber `i` of `n` gets packet `s` in position `(i + s) mod n` |
| Consumer | Unicast from the observer, same rotation | same |

On AWS a 140 Gbps full-`MBO` stream does not fit one instance (vendor: 200 Gbps per instance,
shared with everything else). That is a bandwidth fact of the platform (01 §14.0), not a
reduction of the design: bare metal ships full `MBO` (§7.2). So on AWS a 1B/s book offers the
tiers, `MBO-C`, and `MBO-W`: a relay-side `MBO` of the orders within `MD_MBO_W_TICKS = 256`
ticks of the touch. The relay keeps the full book and emits a synthetic `MD_ADD` when an order
enters the window and `MD_DELETE(cause 9)` when it leaves, so all subscribers of one window size
get identical bytes.

### 7.8 Latency budget

Measured from the first bit of a step's first fill on the sequencer's wire to the first bit of the
A-feed packet that carries the step's `MD_STEP`, at the observer's NIC:

| Stage | ns (budget) |
|---|---|
| Order frame: sequencer TX → observer RX (one switch hop in the facility) | 1_000 |
| Observer replay of the step and its interval (payload already present via the tap) | 500 |
| Encode, flush rule (c) worst case | 1_000 |
| TX: doorbell → first bit | 300 |
| Reserve for queueing | 2_200 |
| **`MD_LAG_P99_NS`** | **5_000** |

Lane-op records lag the sequencer's ack by the same budget. A participant always sees its own
fill before the public print (≤ 1 µs versus ≤ 5 µs), as on every venue.

**Fairness statement.** All subscribers of a feed get the same bytes, generated once; nobody can
buy an earlier copy, and the sequencer cannot see who subscribes. The only spread is switch
replication skew and fiber length on bare metal (vendor: tens of ns), and the relay rotation on
AWS, which gives every subscriber the same average position.

## 8. Drop copy (`vyrn-dropcopy`)

`vyrn-dropcopy` gives each account (and each master, for all its sub-accounts) a private stream of
executions and order events. It runs on the observers beside `vyrn-md`, from the log alone: the
replayed engine reproduces every response, including its `resp_seq` (`INV-DET`).

### 8.1 Record (48 bytes)

```
off size field
  0   1  type        1 FILL, 2 ACK, 3 CANCEL, 4 OUT, 5 ALLOC, 6 FINAL, 7 REVERT, 8 EOD,
                     9 SETTLED, 10 ROUTE (§2.8)
  1   1  flags       bit0 side, bit1 taker, bit2 durable (always 1, below), bits 3–7 = 0
  2   2  ordinal     u16       DC_FILL: ordinal in the step; else message index in the packet
  4   4  account     AccountId
  8   8  step        StepId    DC_FILL/DC_OUT from a step; else the lane op's LaneSeq
 16   4  session     SessionId
 20   4  resp_seq    u32       the response packet that carried the matching client record
 24   4  handle      Handle
 28   4  tick        Tick
 32   4  qty         Qty
 36   4  client_tag  u32
 40   8  fee         i64       quote units, negative = rebate; a taker's step fee is on its
                               last DC_FILL of the step, 0 on the others
```

The execution ID is `(StepId, ordinal)` (01 §6.4). The taker gets one `DC_FILL` per maker match,
not per level, so both sides of every match carry the same execution ID. `DC_FINAL` reuses `step`
for the last final step and bytes 24–31 for the final block `Height`: every earlier record of the
stream is final. `DC_SETTLED` has the same layout and marks settlement. `DC_REVERT` names a
reverted execution by `(step, ordinal)`.

### 8.2 Four attestations: execution, durability, finality, settlement

01 §14.13 item 3 orders four separate facts, and the drop copy labels each one, never one
"confirmed" flag:

| Fact | Where the client sees it | When (budget) |
|---|---|---|
| Volatile execution | its own `Fill`/`Ack` on the trading session; the `DC_*` record repeats it | ≤ 1 µs |
| Durability | `flags.bit2` of every drop-copy record: the observer sends a record only when it holds the step's frames from both replication paths, which `INV-FRAME-FIRST` guarantees before the `Fill` left | record ≤ 20 µs after the `Fill` (REQ-LAT-12: p99 ≤ 50 µs) |
| Finality | one `DC_FINAL` per block: every step ≤ its last step is final | ≤ `FINALITY_MAX_MS` = 10 ms for every accepted order (01 §14.9), + 1 ms delivery |
| Settlement | `DC_SETTLED`: `BASE` when the ledger credits the epoch statement (§10); `CHAIN` when 09's settlement covers the step | epoch end, or 09's bound |

The stage of a record is therefore (record, newest `DC_FINAL`, newest `DC_SETTLED`), and no record
is ever re-sent to change stage. A fill that the final log excludes gets a `DC_REVERT` before the
`DC_FINAL` that covers its step. That happens for a revert (07 §9.6 cases (a)–(e), in either mode)
and for a `CHAIN` bust (bad `K_com`, 09 §5.9). A busted fill stays in the final log, but its bust
verdict is final no later than its own block, so its `DC_REVERT` still precedes that `DC_FINAL`.
Neither is possible after finality (01 §14.19 B).

### 8.3 Delivery and reconciliation

- TCP with Noise or TLS 1.3, one stream per account or master, a gapless stream sequence, and
  replay from any point of the current and previous epoch (`MD_DC_REPLAY_EPOCHS = 2`, config).
- **Online reconciliation.** `(session, resp_seq, ordinal)` maps every `DC_FILL` to the exact
  client `Fill` record that the trading session received. A client that sees a fill on one stream
  and not the other has found a bug or a lost packet, and knows which.
- **End-of-epoch reconciliation.** `DC_EOD` records carry, per account and book: fill count, total
  base bought and sold, total quote, total fees, message fees, and closing free and reserved
  balances. The last `DC_EOD` carries the BLAKE3 hash of the account's whole canonical drop-copy
  stream for the epoch. That hash is a leaf of the statement tree (§10), so a client can prove
  that its drop copy is the one the quorum signed.

## 9. Surveillance

Surveillance runs on observer replicas and archive boxes, from the finalized log. It never runs on
the sequencer, and it never feeds back into the engine except through finalized control ops.

### 9.1 Sequencer fairness statistics (consumed by 09)

A sequencer can front-run in two ways: stamp a victim's packet late (lie about `rx_ts`), or order
an honest timestamp behind a later one. Neither is provable order by order (DESIGN §7), but both
shift distributions. Every replica computes the metrics below per epoch from the finalized log,
and the quorum-signed epoch report carries them.

Inputs, per packet `P`: `seq_ts(P)` = `PacketRecord.rx_ts`; `dt_ts(P)` = the data node's own NIC
RX timestamp of the client's copy, which the data tier records with the payload (request to 07);
`d(P)` = that data node. Account classes: `FAST` = the top `RSK_SURV_FAST_PPM = 10_000` (1%) of
accounts by cross count in the epoch; `ALL`. Every metric is also split by lane class (dedicated,
pooled), because pooled packets queue and steal by design (01 §14.15), and a sequencer must not
hide a late stamp in the pool's queueing.

**Integer quantile.** `q_p(X)` for `p` in ppm: sort `X` ascending (ties by (session, pkt_seq)) and
take element `floor(p × (|X| − 1) / 10^6)`.

| ID | Metric | Definition |
|---|---|---|
| `FM1` | Timestamp skew | `skew(P) = seq_ts(P) − dt_ts(P)` (i64). `base(a, d) = q_500000` of `skew` over account `a`'s packets via node `d`. `excess(P) = skew(P) − base(a(P), d(P))`. Report `q_990000`, `q_999000` of `excess` per class. |
| `FM2` | Overtakes | Pairs of crosses `(X, Y)`, same side, with `step(Y) < step(X)`, `seq_ts(Y) > seq_ts(X) + RSK_SURV_OVERTAKE_NS`, and `Y` filled at a tick that `X`'s limit reaches (buy: `Y.worst_fill ≤ X.limit`). Report the count per 10^6 crosses, per class of `X`. `FM2-D` is the same with `dt_ts`. |
| `FM3` | IOC fill ratio | `Σ filled / Σ requested` over IOC crosses, per class, in ppm. |
| `FM4` | Taker markout | For `FAST` taker fills: `side × (bid + ask − 2 × fill_tick) × qty` with bid and ask replayed at `rx_ts + 1 ms`, summed, in half-tick-lots (integer, no mid division). |

`RSK_SURV_OVERTAKE_NS = 2_000` (budget) is above the largest lane queueing an honest sequencer can
have: deadline admission sheds every packet older than `LAT_MAX_NS` (01 §14.1). So an honest
sequencer shows `FM2 = 0` exactly, and every count is evidence. `FM2` scans backward from each
`X`, bounded by `RSK_SURV_SCAN_MAX = 4_096` crosses; a scan that hits the bound alerts. Late
stamps show in `FM1`, reordering in `FM2`, both together in `FM2-D`, and trading ahead of informed
flow in `FM3` and `FM4` (`FAST` versus other operators' epochs). 09 sets thresholds and penalties.

### 9.2 Spoofing and layering detection

Detection runs per account on observer replicas with lane-sharded counters, and in full on the
archive. All windows are order-stream time.

| Pattern | Signal (all integer) | Default flag (config) |
|---|---|---|
| Spoofing | In window `W = 1 s`: account places passive orders on side `s` within `D = 10` ticks of the touch with notional ≥ `5 ×` its median order notional; then executes on side `¬s`; then cancels ≥ 90% of those side-`s` orders within `T = 100 ms` of the execution | ≥ 3 occurrences per epoch |
| Layering | ≥ 4 distinct price levels on one side added within 10 ms, each cancelled within `T` after an opposite-side execution by the same master | ≥ 3 per epoch |
| Quote stuffing | account hits its `new_bucket` cap in ≥ 10% of seconds while its fill ratio is < 10^-4 | per epoch |
| Wash trading | executions where maker and taker share a master and `stp_tag = 0` | any |
| Marking the close | share of the account's volume in the last 10 s before an epoch boundary > 5 × its average share | per epoch |

Output is an alert to the operator's compliance queue, with the log range that reproduces it.
There is no automatic action, because these are patterns, not proofs. The operator acts with
ordinary finalized control ops (limits, kill).

### 9.3 Cross-rate monitoring against `CROSS_CAP`

From the `StepRecord` kinds of every block, deterministically:

```
crosses(s)  = number of Cross steps in second s of order-stream time
bbo_ns(s)   = BBO_CROSS_NS × crosses(s) + BBO_IMPROVE_NS × (improves(s) + depletions(s))
model_load  = bbo_ns(s) / 10^9                   (compare with BBO_MAX_LOAD = 0.60)
```

| Level | Condition | Action |
|---|---|---|
| WARN | `crosses(s) ≥ 70% × CROSS_CAP` or `model_load ≥ 0.45` | report the top 20 accounts by cross share |
| ALARM | `crosses(s) ≥ 90% × CROSS_CAP` or `model_load ≥ 0.55`, or any fill-event spill (§4.1 rule 4) | page the operator; next epoch's cross fee rises (§5.3) |
| CRITICAL | live BBO busy fraction (sequencer telemetry, not deterministic) ≥ `BBO_MAX_LOAD` for 100 ms | operator may tighten `cross_rate` limits by control op, or halt |

The model load is deterministic and signed in the epoch report; the live busy fraction is
telemetry for operators only. A gap between them means 01 §5's cost model is wrong, and B3 is
re-run. Lane slot use > 80% (§3.4), dedicated lane load > `ACC_LANE_TARGET_PPM` for a minute, and
a pooled `BUSY` share above B3's published curve at the measured book load also WARN.

### 9.4 The audit trail

The finalized log is the audit trail: every packet, its order, every control op with the admin key
ID that signed it, and a certificate per block. From it `vyrn-sim` rebuilds the state at any step,
every response, every market-data packet and every drop-copy record, so no second copy of events
exists. Off-log records are only admin key registrations (ledger), surveillance alerts with their
dispositions, and telemetry. Timestamps are PTP TAI from the NIC, ≤ 100 ns to UTC (budget, 06),
far inside the tightest regulatory clock rule we target (100 µs for high-frequency trading).

## 10. Reports, statements and retention

**End-of-epoch statement.** After the `HandoffRecord` certificate (08), every replica builds one
statement per account: opening and closing free and reserved balances per book, allocations in
and out, fills (count, base, quote), fees, rebates, message fees, the drop-copy hash (§8.3),
`MUST_SPLIT` (§1.3), next epoch's fee tier, class and lane move, and router totals (§2.8). Statements are leaves of a BLAKE3 Merkle tree in
`AccountId` order; its root `ACC_STMT_ROOT` is in the quorum-signed epoch report, and a client
checks its statement with a Merkle path. The ledger credits fees and in-flight totals from it.

**Venue reports per epoch:** volume and trade count per book, the fairness metrics (§9.1), the
cross-rate profile and peaks (§9.3), `MD_LAG` percentiles from the observers' telemetry, sequencer
failovers, halts, and every admin control op.

**Retention** (config defaults; the longest period that any target jurisdiction requires wins):

| Record | Hot | Archive | Why |
|---|---|---|---|
| Finalized log (order + data) and certificates | 12 h on replica NVMe, 7 days on the facility archive node (01 §14.7) | 7 years | it is the audit trail |
| Market data | `MD_RETX_SECS` in RAM | not stored | regenerated from the log; the archive keeps one BLAKE3 hash per channel per block to prove the regeneration matches |
| Drop copy | 2 epochs replayable | not stored | regenerated from the log, checked against the statement hash |
| Statements and epoch reports | 1 year online | 7 years | small; signed |
| Surveillance alerts and dispositions | 1 year online | 7 years | not derivable from the log |
| Lane maps, fee schedules, risk configs | in the log and epoch configs | 7 years | part of the epoch configuration |

Storing only the log works because market data, drop copy and statements are pure functions of it
(`INV-DET`). It cuts archive volume by the full market-data size (~140 Gbps at peak).

## Interfaces to other chapters

| Chapter | This chapter consumes | This chapter provides |
|---|---|---|
| 02 | `REQ-LAT-1`, `REQ-THR-*` (lane buckets of REQ-THR-6), `REQ-OPS-*` | the lane buckets (§3.8), `MD_LAG_P99_NS`, drop-copy latencies, retention |
| 01 | core map (§10), lane classes (§14.15), observer box (§14.16), `AcctTake` and the `BUSY` bounds (§14.17), `PacketRecord.flags` (§6.6) | the lane map with classes (§1.3), per-pool caps (§3.8), `PoolTok` takes that `AcctTake` logs (§1.2) |
| 03 | book-group size `K`, observer box per facility | the observer role, optical taps, `vyrn-md` and `vyrn-dropcopy` placement, router domain per (group, lane class) (§2.8) |
| 04 | session open, sessions across epochs (01 §14.8), `Bucket` arithmetic, session buckets, `CancelAll`, risk session, the pooled `pkt_seq` check | `lane`, class, port and (AWS) RSS source port in the session-open response (§1.4); account buckets; no tokens for `BUSY` (§3.11); session-resident slots at open/close (§1.2); control session 0 |
| 05 | classification, snapshot (`halted`, `ref_tick`, version), `filled_final` at ack, FIFO entry, step kinds, pool stealing and sibling-segment cancels, `predicted_path_ns` per class | fill-event layout and rules (§4.1, with `Shed`), `stp_tag` in FIFO entries and cross messages, risk fields of pre-assigned order records written in pass 1 (§3.9, §4.3), `RSK_PASS1_CYCLES`, the `f` choice (§4.2), `PoolTok` and `PoolRisk` (§1.2, §3.8) |
| 06 | NIC loopback for `CtlTimerTick`, PTP accuracy, multicast/IGMP, `resctrl` L3 allocation | tick period; observer NICs (§7.2: 3 × dual-port CX-6 Dx + 3 × X2541, replacing 06's 6 × X2541, 01 §14.16); published ENA RSS key (§1.4) |
| 07 | ledger (BASE), control-packet payload storage, replay scheduler, data-tier `dt_ts` | the replay rule for `fills_applied` (§4.2), conservation checks per block (`INV-ACC-2`) |
| 08 | epoch configuration record, state loader, opening auction, session survival | `lane_map(e+1)` with classes, its hash and the moved-account set whose sessions close, promotions and demotions included (§1.3, §1.4), fee tiers, re-reservation at load (§5.2), router rebalancing (§2.8) |
| 09 | custody ledger (CHAIN), fee-pool split, revert mechanics, settlement point, fairness thresholds | fees per epoch, `FM1`–`FM4` per lane class, `ACC_STMT_ROOT`, `DC_SETTLED`/`MD_ATTEST` |
| 11 | B2, B3 (`BUSY` per class), `vyrn-sim` pool tests | new benchmarks: B-MD1 (`MBO-C` ratio, `MD_LAG`), B-RSK1 (risk cycles on the B2 mix); the `lane_map` class property test (Open questions, item 9) |

## Local definitions

| Name | Value | Kind | Meaning |
|---|---|---|---|
| `ACC_MAX_ACCOUNTS_PER_LANE` | 65_536 | budget | `AcctRisk` slots per lane |
| `ACC_LANE_TARGET_PPM`, `ACC_LANE_TRIGGER_PPM` | 500_000, 550_000 | budget | target and trigger lane load for `lane_map` (§1.3) |
| `ACC_HOT_SLOTS`, `ACC_MOVE_COOLDOWN_EPOCHS` | 4_096, 3 | budget, config | session-resident slots (§1.2); move cooldown (§1.3) |
| `ACC_LOAD_WINDOW_EPOCHS`, `ACC_ACCOUNT_MAX_SHARE_PPM`, `ACC_MAX_MOVES_PER_EPOCH`, `ACC_NEW_ACCOUNT_LOAD`, `ACC_MAP_PUBLISH_LEAD_S` | 3, 400_000, 1_024, 10^6 ns/s, 3_600 s | config | `lane_map` inputs (§1.3, §1.4) |
| `ACC_PROMOTE_RATIO_PPM` | 1_250_000 | config | load margin for a pooled firm to displace a dedicated one (§1.3) |
| `LaneClass` | `Dedicated` \| `Pooled` | type | the class field of `lane_map` (§1.3) |
| `PoolTok`, `PoolRisk` | 16 B (05 §6.9 `AcctTok`), 64 B | type | per-account token in the pool region; the pool's `lane_cross`/`lane_improve` buckets under their own token (§1.2, §3.8) |
| `ACC_STP_TAGS_MAX` | 65_535 | budget | STP tags per epoch |
| `ACC_STMT_ROOT` | — | type | Merkle root of the epoch's statements (§10) |
| `QuoteAmt`, `BaseLots` | u128, u64 | type | §2.1 |
| `AcctRisk`, `BookBal`, `PerpPos` | 128, 64, 64 B | type | §1.2, §6 |
| `RSK_PASS1_CYCLES`, `RSK_PKT_NS`, `RSK_SETTLE_NS` | 16 cycles, 6 ns, 12 ns | budget | risk per message in pass 1, per packet, per fill event (§3.10, §4.6) |
| `RSK_FEE_DENOM`, `RSK_FEE_PPM_MAX`, `RSK_FEE_TIERS` | 10^6, 10_000, 8 | const | fee units and bounds (§5) |
| `RSK_MSGFEE_PER_BBO_NS` | 1 µUSD | config | message-fee price (§5.3) |
| `RSK_NOTIONAL_HARD_MAX`, `RSK_MAX_OPEN_HARD` | `u64::MAX`, 1_048_576 | const | hard bounds (§3.4) |
| `RSK_BAND_MIN_TICKS`, `RSK_COD_MIN_NS` | 16, 10^6 ns | config | band floor, minimum cancel-on-disconnect |
| `RSK_TIMER_TICK_NS`, `RSK_KILL_CHUNK`, `RSK_DRAIN_MAX`, `RSK_CTL_MAX_WAIT_NS` | 10^6 ns, 16, 8, 10^5 ns | budget | tick period; work units per chunk and per B1; control-packet wait bound |
| `RSK_FILL_EVENT_BYTES` | 32 | const | §4.1 (ring size is 05's `ENG_FILL_RING`) |
| `RSK_BUCKET_NEW`, `_CROSS`, `_LANE_CROSS`, `_LANE_IMPROVE`; `RSK_D_QTY_ZERO`, `_QTY_MAX`, `_NOTIONAL`, `_OVERFLOW`, `_LANE_FULL`; `RSK_CREDIT_QUOTE`, `_BASE`; `RSK_D_MOVED` | 1–4 (`RATE_LIMIT`, 04 §9.1); 1–4 (`BAD_QTY`), 5 (`RISK_ORDER_COUNT`); 1–2 (`RISK_CREDIT`); 0x100 | const | reject detail codes (§3.1, §1.4) |
| `LaneRisk` | 64 B | type | a dedicated lane's `lane_cross` and `lane_improve` buckets and `fee_acc`; on a pool core, `fee_acc` only (§3.8) |
| `RSK_MARK_PERIOD_MS`, `RSK_LIQ_SLIPPAGE_BPS` | 100, 200 | config | v2 (§6) |
| `RSK_SURV_FAST_PPM`, `RSK_SURV_OVERTAKE_NS`, `RSK_SURV_SCAN_MAX` | 10_000, 2_000, 4_096 | config, budget, budget | fairness metrics (§9.1) |
| `INV-ACC-1…5`, `INV-RSK-1…2` | — | invariant | §2.7, §4.6 |
| `router_mode`, `router_fee_ppm`, `router_floor_b`, `router_max_route`, `router_net_max_b` | Off, 0, —, —, — | config | router domain (§2.8) |
| `MD_MAX_RECS_PER_PKT`, `MD_MBO_LANE_CHANNELS`, `MD_FLUSH_NS`, `MD_HEARTBEAT_MS` | 88, 4, 1_000, 1 | const, budget | framing (§7.3, §7.4) |
| `MD_MBP_WINDOW_NS`, `MD_TOB_WINDOW_NS`, `MD_SNAP_EVERY_BLOCKS`, `MD_RETX_SECS`, `MD_MBO_W_TICKS`, `MD_DC_REPLAY_EPOCHS` | 10_000, 1_000, 1_000, 30, 256, 2 | config | conflation, snapshots, recovery |
| `MD_SNAP_GBPS`, `MD_RELAY_FANOUT`, `MD_LAG_P99_NS` | 10, 32, 5_000 | budget | §7.6–§7.8 |
| `MD_FEED_*` | 1 MBO, 2 MBO-C, 3 MBP-10, 4 TOB, 5 TRADES, 6 STATS, 7 SNAP, 8 MBO-W | const | channel high byte |

## Requests to 01

Resolved by 01 §14: `QuoteAmt`, `BaseLots`, `BookSpec`, the fill-event layout, control session 0
with codes 0x20–0x2F and 0xA0–0xAF, the observer `vyrn-md` box (§14.11) and its NICs (§14.16),
reject 21 `ACCOUNT_KILLED` (§14.10), `FINALITY_MAX_MS` (§5), and the logged order of pooled
token takes (`AcctTake`, §14.17 item 4). Still open:

1. Add a fourth number label, **config**, for defaults of configuration values (00, §13).
2. §12.1: replace "qty × price + max fee" with `R_buy(qty, tick)` from §3.2, so the rounding
   allowance is normative.
3. §7: add `INV-RSK-1`. §6.6: state that `fills_applied` is a step of the packet's own book, that
   the lane picks it (§4.2), and that in a book group all fill-dependent lane state is per book.
   Fill-event kind 6 `Shed` (§3.11) is part of the promoted layout.
4. §6.6: add an `EpochConfig` record (or fields in `HandoffRecord`): `lane_map_hash` (classes
   included), `n_ded`, `n_pool`, `fee_schedule_hash`, `risk_config_hash`, `stp_tag_table_hash`,
   `router_config_hash`.
5. §6.5: define `detail` for `BAD_QTY`, `RATE_LIMIT`, `RISK_CREDIT` and `SESSION_CLOSED` as in
   §3.1 and §1.4, including the lane bucket codes 3 and 4 and `RSK_D_MOVED`.
6. §9: name the BASE-mode ledger (`vyrn-ledger` binary and crate).
7. §6.2: message 0x05 `RouteMove`; §6.4: record 0x88 `Routed` (§2.8). v2: order flag bit 6 =
   reduce-only.
8. §14.2: state that pass 1 is branch-free over risk (§3.10), so `LANE_PASS1_NS` is a maximum.
9. §6.6: add the `AcctTake { account, ver, lane }` layout of §14.17 item 4 to the order-stream
   records, with its place relative to the `PacketRecord` it precedes. Keep `flags` as §6.6 fixes
   them (bit0 SHED, bit1 ADVANCE); `AcctTake` needs no flag bit. State that a `PoolRisk` take
   (§3.8) is logged the same way.
10. §5: `BBO_CROSS_NS` = 40 is superseded by §14.15 item 2 (15). The message fee (§5.3) and the
    lane-bucket load (§3.8) use 15. `N_LANES_REF` = 50 does not match the §10 core map (49 lanes).
11. §14.13 item 5: the router domain is one router account per (group, lane class), the dedicated
    one sharded per lane (§2.8).

## Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Does parse, classification and the BBO-ring push fit the 9 cycles of pass 1 that risk leaves (§3.10) | 05 | B2 with B-RSK1 |
| 2 | `MBO-C` bytes per record at the design mix; is one 100G port enough | 10 | B-MD1 on a recorded B3 stream |
| 3 | A plain allocation move inside a book group still uses the ledger; should it use the router path (§2.8) | 03, 07 | conservation proof plus `vyrn-sim` property test |
| 4 | On AWS (no tap) a client that withholds its data copy stalls every replay, and so `MD_LAG` | 07 | `vyrn-sim` with withheld copies; `MD_LAG` p99 |
| 5 | A sweep that gives one lane more than `RSK_DRAIN_MAX` events in one step (§4.2): is a split of B1 inside a step needed | 05 | B3 `BUSY` count with `WL-XSWEEP` |
| 6 | How a `CHAIN`-mode revert reaches lanes that already settled the reverted fills | 09 | `vyrn-sim` revert scenario; `INV-ACC-2` holds after |
| 7 | Time priority of resting orders whose account changes lane or class at a boundary | 05, 08 | handoff replay test: level FIFO identical before and after |
| 8 | Aggressor grouping of fill events in `Rescan` steps (§4.1 rule 2) | 05 | B4 replay with forced rescans |
| 9 | Whether p99 of 1-second `lane_ns` is the right `lane_map` load metric and class rank, whether `ACC_PROMOTE_RATIO_PPM` stops class churn, and how many sessions both close per boundary | 10 | `vyrn-sim` on recorded flow over 30 epochs: max lane load, promotions, demotions and moves per boundary |
| 10 | Cross-asset routes (USDT book to USDC book) with a priced conversion and its inventory risk | 10, 09 | v2 product design |
| 11 | Does the account-token CAS stay ~20 ns when one pooled account sends on several sessions at once, and how much does the `PoolRisk` token add to pooled crosses | 05 | 11's pool token-contention test, then B3's pooled `BUSY` curve |
| 12 | Does `AcctTake` also order `PoolRisk` takes and settlement of pooled fill events, or do those need their own record (Requests to 01, item 9) | 01, 07 | 11's pooled-lane determinism replay with `AcctTake` checks (B4 on a pool log) |
