# Oracle scenarios

Scenarios written by people from the text of 05, 08 and 10 (spec/11-build.md §5.2). Each is an
event list with the records it must produce. The expected values come from the spec, never from
an implementation. Every book implementation (the Vx oracle, the Rust engine through its
harness) must pass every file. `crates/vyrn-sim/tests/oracle_scenarios.rs` runs them against
`libvyrn_vx_oracle`; another implementation needs only this README and the files.

## Format, version 1

One item per line; `#` starts a comment. Numbers are decimal or `0x` hex, `_` allowed.

| Line | Meaning |
|---|---|
| `book band=LO..HI [qptl=] [max_fee_ppm=] [min_qty=] [max_qty=] [max_open=] [max_orders=] [phase=]` | `pbo_config`. Defaults: qptl 1, fee 0, min 1, max 2^31-1, open 1000, orders 10000, continuous |
| `lane L [rank=R] [first=H]` | `rank_e(L)` (default L) and the first handle the lane gives out (default 0x01000001) |
| `account ID lane=L [base=] [quote=] [maker=] [taker=] [auction=]` | an account; rates in ppm, negative is a rebate |
| `session SID account=ID` | a session |
| `msg LANE SID INDEX [rx=] [seq=] [step=] [reserved=] : OP` | `PBO_EV_MSG` at its position in L |
| `shed LANE SID INDEX [step=] : OP` | a `Shed` step whose source is OP |
| `step KIND` | `rescan`, `depletion`, `idle`, `seal`, or a number |
| `phase P` / `uncross REF [step=]` | a `Control` step / the uncross with reference tick REF |
| `=> SID RECORD`, `=> none`, `=> error event\|full\|cap\|fault` | the expected outcome of the event above |
| `check resting H...` / `check account ID field=v...` / `check phase P` / `check fee_acc L v` | the canonical state bytes |

OP: `new SIDE TIF [post] [stp=N] TICK QTY TAG`, `cancel H TAG`, `reduce H BY TAG`,
`replace SIDE TIF [post] [stp=N] H TICK QTY`, `cancel_all TAG`, `heartbeat`, `raw HEX`.

RECORD (01 §6.4): `ack IDX H TICK TAG`, `fill IDX LIQ H TICK QTY`, `reject IDX REASON DETAIL TAG`,
`cancel_ack IDX H QTY TAG`, `out IDX CAUSE H QTY TAG`, or `vector Vn I`: record I of response
Vn in `tests/golden/vyrn_proto_vectors.out`. `maker` means index 0xFF.

Records compare per session in order. The order across sessions is not compared, because each
client sees only its own stream.

## Spec choices these files fix

- **CancelAll** follows 04 §6.6 and vector V15: one `CancelAck` per live order of the session in
  ascending handle order, then the summary `CancelAck(0xFFFFFFFF, count)`, also for a count of 0.
  05 §2.3 says key order and one `CancelAck(0, 0)` when there are none; 04 is the client contract
  and V15 is a byte vector, so 05 §2.3 should be changed to match.
- **Fee units** are ppm of notional (10 §5, `RSK_FEE_DENOM = 10^6`): ceil for a charge, floor for
  a rebate. 05 §2.6 writes bps over 10^4; 10 owns fees, and ppm expresses every bps rate exactly.
  The fee is per fill, as 05 §2.6 writes it; 10 §3.3 charges the taker once per step on the
  step's total notional, which differs by rounding. That difference is open.
