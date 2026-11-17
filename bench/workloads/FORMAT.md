# Workload configs, generator stream and histogram export

Specified here so that a stranger can write a generator, a reader or a rig without reading
`crates/vyrn-bench`. The numbers behind the workloads are `spec/02-requirements.md` §6; if a
number there and a config here disagree, §6 wins. Everything below is integer-only: no field,
distribution or output depends on floating point.

Reused standards: TOML 1.0 for configs, BLAKE3 for digests, SplitMix64 and xoshiro256** (Vigna and
Blackman, prng.di.unimi.it), HDR-histogram semantics (1 ns resolution), and the VYRN request
packet of `spec/01-conventions.md` §6.1 and `spec/04-protocol.md` §3 for every generated packet.
No new wire format is invented for packets.

## 1. Workload config (`*.toml`, version 1)

| Key | Meaning |
|---|---|
| `version` | `1`. A reader rejects any other value. |
| `id` | The workload ID of 02 §6.1 (`WL-REF`, …). |
| `mode` | `base` or `chain`. `chain` also fills `tag_com`. |
| `book`, `epoch16` | Written into every request header. |
| `rate_msgs_per_s` | Full-rate target over all classes. `gen --rate` overrides it. |
| `lane` | Optional. Keep only the sessions of this lane. Rates stay those of the full population. |
| `[book_model]` | `mid_tick`, `spread_ticks`, `depth_lots`: the fixed BBO the offline generator uses (02 §6.2). |
| `[burst]` | Global bursts (02 §6.9): `rate_per_s`, `window_ns`, `mult_ppm`, `base_scale_ppm`. |
| `[lifetimes]` | `replace_ppm` and `[[lifetimes.row]]` (`ppm`, `lo_ns`, `hi_ns`): 02 §6.7. |
| `[[join_distance]]` | `kind` = `fixed`, `geometric`, `log_uniform`, `uniform`; 02 §6.5. `ppm` sums to 10⁶. |
| `[[cross_levels]]`, `[cross]` | Levels swept, time in force and residual-through-the-touch: 02 §6.5. |
| `[pool]` | `first_lane`, `lanes`: lanes of pooled sessions. |
| `[auction]` | Optional. Every order is `AUCTION_ONLY`; `through_ppm` of them go through the reference. |
| `[[phase]]` | `duration_ns`, `rate_ppm`, optional `cross_scale_ppm`. Phases run back to back. |
| `[[class]]` | `kind` (`mm`, `tk`, `rt`), `placement`, `skew`, `mix`, `qty_p_ppm`, `packets`, and the optional `enabled`, `stp_cancel_newest`, `bursty`, `max_live_orders`. |
| `[extensions]` | The one table a v1 reader ignores. Everything else unknown is an error, so a typo never falls back to a default. |

Probabilities are parts per million, times are ns, rates are msgs/s. A class `mix` is the class's
share of **all** messages in ppm (02 §6.4); a `Replace` counts as a join.

**Versioning.** A new optional key may appear in a later 1.x config only if its absence means
today's behaviour. Anything else bumps `version`. The generator's output for a given config, seed
and version never changes; a change that alters any vector in `vectors.toml` is a new version.

## 2. Randomness

- `run_seed`: a `u64` the report records.
- Each session has its own xoshiro256** stream, seeded by SplitMix64(`run_seed` ⊕ (`SessionId` << 1)):
  the state is the first four SplitMix64 outputs (02 §6.2).
- The burst process has its own stream, seeded by SplitMix64(`run_seed` ⊕ 2⁶³). Bit 63 is never set
  in `SessionId` << 1, so no session shares it.
- Uniform draws below `n` use Lemire's multiply-and-reject (no modulo bias). Exp(1), log-uniform
  and Zipf weights use the integer `log2`/`exp2` of `src/fixed.rs` (Q32, truncating).
- Because streams are per session, the packets of one session do not depend on which other
  sessions are in the run: `lane = N` is exactly the lane-N part of the full run.

## 3. Packets

Each packet is a VYRN request: header (`session`, `pkt_seq` gapless from 1, `count`, `epoch16`,
`book`), 1–10 messages, `tag_seq`, `tag_com`. MAC keys are derived for tests only:
BLAKE3 `derive_key` with the contexts `vyrn-bench v1 gen k_seq` and `vyrn-bench v1 gen k_com`
over `run_seed` (u64 LE) ‖ `SessionId` (u32 LE), first 16 bytes. They protect nothing.

**Handles are placeholders.** The lane assigns the real handle on `Ack`. The generator numbers a
session's orders 1, 2, 3 … in the slot bits (generation 0). A rig sending to a live sequencer
must map handles and recompute the MACs.

## 4. Stream (`VYRN-GEN` v1)

```
header, 68 bytes, little-endian
   0  magic "VYRNGEN\0"
   8  version u16 = 1
  10  header_len u16 = 68
  12  mode u8 (0 base, 1 chain)      13 reserved = 0
  14  book u16        16 epoch16 u16   18 reserved u16 = 0
  20  run_seed u64    28 rate_msgs_per_s u64
  36  BLAKE3 of the config file's bytes, 32 bytes
record, 12 bytes + packet
   0  len u16 (packet bytes)   2  send_ns u64 (ns from the start of the run)
  10  lane u8                  11 class u8 (0 MM, 1 TK, 2 RT)
```

A reader skips to `header_len` before the first record (so later versions can append header
fields) and rejects an unknown `version`. Records are in non-decreasing `send_ns`; ties are
ordered by (`SessionId`, stream). A packet is sent twice on the two paths (04 §2.4); that is the
sender's job.

## 5. Histogram export (`VYRN-HIST` v1)

Per 11 §7.1 rule 5: exact 1 ns buckets up to 10 µs, every sample above 10 µs kept in an overflow
list, the maximum kept with the request that produced it.

```
vyrn-hist 1
name <token>
unit ns
hdr_max_ns 10000
count <n>
max <ns> <session> <pkt_seq> <index>      (absent when count is 0)
b <ns> <count>                            one line per recorded value ≤ 10000, ascending
o <ns> <session> <pkt_seq> <index>        one line per sample above 10000, ascending
```

Among equal maxima the request with the smallest (`session`, `pkt_seq`, `index`) is kept, so the
export does not depend on arrival order. A reader checks that `count` matches the body and that
`max` equals the largest sample. Quantiles are the smallest recorded value with at least q of the
samples at or below it; `vyrn-bench hist <file>` prints them. Signing a report over these files
(11 §7.1 rule 8) is out of scope here: the export is plain text so that any signature scheme can
cover its bytes.

## 6. Conformance

`vectors.toml` lists, for every committed config, a seed, a packet count and the BLAKE3 of the
stream. A stranger's implementation conforms if, for each entry,
`vyrn-bench gen --config <config> --seed <seed> --packets <packets>` produces a stream with that
hash. The same vectors must hold on every build of B4's set. The PRNG vectors are the published
reference outputs (SplitMix64 seed 0 and 1234567; xoshiro256** state {1, 2, 3, 4}); see
`crates/vyrn-bench/src/rng.rs`.

## 7. Not generated yet

- The `vyrn-md` model book: the BBO is the fixed `[book_model]`, so the staleness of 02 §6.2 is
  absent.
- The mix controller (02 §6.10) and the lane pacer (02 §6.9): both need the live sequencer and
  belong to the rig.
- `WL-LOW` idle probes, `WL-ADV-1` … `9`, and the probe-session selection of 02 §6.11.
