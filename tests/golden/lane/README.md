# Lane streams

`streams.txt` holds whole runs of the engine's lanes and BBO core (05 §3, §6–§8): every input
in order and every output it produced. Another implementation, such as the Vx oracle behind a
lane harness, replays the inputs and must produce the same output lines. You need only this
README and the file.

**Provenance.** `crates/engine/vyrn-lane/tests/golden.rs` writes and checks the file. The
outputs come from the Rust lane and BBO code, so the file alone is not independent of them.
Each scenario names the test in `crates/engine/vyrn-lane/tests/lane.rs` that asserts its
records from the spec, with values worked out by hand.

## The box

Every scenario starts from the same box:

- 3 lanes, epoch 0, book 7, Continuous, ladder ticks 1..512, `tick_size` 1, band 10 000 bps.
- Lane `l`, session `a` for `a` = 1..15: `SessionId = 1<<20 | l<<12 | a`, lane-local account
  `a`, `K_seq` = 16 zero bytes except byte 0 = `l`, byte 1 = `a` and byte 15 = `0x5a`; BASE
  mode (no `K_com`). Every account has `quote_free = 2^60`, `base_free = 2^40`,
  `max_open_orders = 1000`, and the other 10 §3.4 defaults.
- Handles are `slot | 1 << 24` (generation 1). Slots are given out per lane from 1, in pass 1
  order.
- The lane deadline test uses 05 §6.8's path table and `DEADLINE_GUARD_NS = 20`.
- The BBO core's clock never makes an entry late, except where `step now=N` says.

## Format, version 1

One item per line. `#` starts a comment. Numbers are decimal, or hex with `0x`. Hex strings
are bytes in order.

Inputs are not indented:

| Line | Meaning |
|---|---|
| `scenario NAME` | a fresh box |
| `pkt L SID rx=T now=N [mid=P:Q@S/C]... HEX` | lane `L` receives request bytes `HEX` (04 §3) with `rx_ts = T`; its clock reads `N` during the packet. Each `mid` is a boundary chosen by the caller (05 §6.2): before pass `P` of op `Q`, at `LaneCut = (S, C)`. Without `mid`, boundaries come from `LaneCut` polls |
| `step` / `step now=N` | the cut cores publish, then the BBO core decides one step (clock `N`) and the stream core writes every lane's `LaneCut` |
| `poll L` | lane `L` runs every boundary that is due (05 §6.1 idle polls) |
| `settle` | `step`, then `poll` of every lane in order, repeated until a round does nothing |
| `hold L` | lane `L`'s snapshot line keeps its value, and it runs no idle polls, until its next `pkt` (a lane that has not seen the newest snapshot, 05 §2.5) |

Outputs are indented and follow the input that produced them:

| Line | Meaning |
|---|---|
| `step S kind=K src=L:Q flags=F cut=C0,C1,C2` | a `StepEntry` (05 §8.1): kind code, source (0:0 = none), flags (bit 0 `CONT`), cut |
| `ev L KIND vslot=V h=H tick=T qty=Q liq=X cause=C` | a `FillEvent` to lane `L` (05 §4.12; kinds 1 Fill, 2 Rested, 3 Out, 4 Reject, 8 Dep) |
| `tx SID resp=R echo=E role=X REC...` | a fill TX core packet (05 §8.10 rules 1–2): `resp=0` takes the next `MakerSeq` number |
| `resp L SID resp=R echo=E gate=G REC...` | a lane response packet; `gate` is `none`, `pkt:Q` or `step:S` (05 §8.10) |
| `log L SID pkt=P count=N flags=F first=Q fills_applied=S` | a `PacketRecord` (01 §6.6; flags bit 0 `SHED`, 1 `ADVANCE`, 2 `MID`, 3 `PASS2`) |

`REC` is one 16-byte record (01 §6.4) in hex.

An implementation passes when every output line matches. Within one input, `step` lines and
their `ev`/`tx` lines come first, then `resp` and `log` lines per lane in lane order. Each
lane's lines are in production order. A lane-only implementation reads the `ev` lines as its
fill-ring input and needs to match only the `resp` and `log` lines.
