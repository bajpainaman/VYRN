//! `e2e-smoke`: a multi-node end-to-end smoke run on one machine, over `kernel_udp`.
//!
//! # Contract
//!
//! **Invocation.** `e2e-smoke [--bin-dir DIR] [--validators K] [--packets P] [--rate R]
//! [--seed S] [--wait-s T] [--seq-cpus L] [--validator-cpus L] [--strict-hashlag] [--finality]
//! [--data] [--dropcopy] [--two-path] [--drop-path-b N] [--keyed] [--data-shards N] [--data-kill]
//! [--kill-voter] [--restart-voter] [--restart-immediate] [--restart-hashlag-us US]`. `DIR` holds `vyrn-seq`, `vyrn-validator`, (with `--data`) `vyrn-data` and (with
//! `--dropcopy`) `vyrn-dropcopy` (default: this binary's directory). Exit 0 when every enabled check passes, 1 when one fails,
//! 2 when the run could not start. Every wait has a deadline of `T` seconds (default 30): the
//! harness never blocks on a child, a socket or a pipe without one, and kills every child it
//! started on any exit path.
//!
//! **Topology.** `K` `vyrn-validator` processes (ephemeral order ports), one `vyrn-seq` DEV box
//! with two dedicated lanes whose `[replication] order` lists every validator and the harness's
//! replay tap, and the harness itself as the client of every session.
//!
//! **Workload.** `vyrn-bench`'s generator over `wl-smoke.toml` (two MM sessions on each of lanes
//! 0 and 1), seed `S`, rate `R`, the first `P` packets. The stream is deterministic in
//! `(config, S, R, P)`. Each packet is re-addressed to its DEV session (generation 1, as
//! `vyrn-seq` opens DEV sessions) and re-MACed with that session's key; its messages are
//! unchanged. Handles in Cancel/Reduce/Replace stay the generator's placeholders, so many of
//! them are rejected: deterministically, which is all replay needs. Packets are paced by the
//! stream's `send_ns`.
//!
//! **Checks**, one `CHECK <name> PASS|FAIL|SKIP <detail>` line each:
//!
//! | name | passes when |
//! |---|---|
//! | `seq` | the box exits 0, `records` equals the packets sent, `seal_violations=0`, at least 2 blocks |
//! | `validators` | each validator reports heights `0..=H` contiguous with the box's `first_step`/`last_step`, every verdict `Valid`, no `FAULT` (R5 for `REP_E_HASHLAG`) |
//! | `replay` | the tap's `OrderCore` readies the same blocks, holding every packet sent exactly once, `DataJoin::check` passes on each, `RustReplay` replays every block, and its responses equal the responses the client received from the box (R1); the tap Nacks its own ORDER holes, at most as many as its socket dropped (R17) |
//! | `replica-out` | with `--data` every validator replays (`[replay]`) and its `out=<hex>` on each `BLOCK` line equals the tap's output hash of that block; one stopped at `REP_E_HASHLAG` is compared on the blocks it printed (R5); SKIP while no validator replays |
//! | `finality` | with `--finality` (default 4 validators, a DEV roster as in `bin/vyrn-validator/tests/committee.rs`, `[consensus]` in every validator and the box): while the box still runs, the box's listener (`FINAL height=<h> ... from=<votes\|cert>`) and every validator that did not stop print `FINAL` through the box's last block. A validator's `OUT_OF_ORDER`, `VOTER_FAULT`, `DATA_FAULT` or `REPLAY_FAULT` line fails `validators`; `REP_E_HASHLAG` follows R5 and R6. SKIP without it |
//! | `dropcopy` | with `--dropcopy` (needs `--data` and `--finality`): an observer (`vyrn-validator`, `role = "observer"`, data destination `n + 1`, in the box's order list on both paths (R12) and every validator's `[consensus] observers`) replays every block into its output ring and finalizes from the validators' certificates; `vyrn-dropcopy` serves the ring over Noise, and one client per session logs in to its account's stream. Each stream's served records, without stage markers, equal an in-process `DropCopy` over the tap's `RustReplay` byte for byte, with gapless seqs, and end in a `DC_FINAL`; every record with a `resp_seq` (acks, cancels, outs, taker fills) names a response packet the client received (10 §8.3), or one replay produced that R1 counts as lost at the client's socket. It prints a DEV timing of those records after their response packets (R9); SKIP without it |
//! | `failover` | with `--data-kill` (R13): the home data box is killed mid-run, the validators reach Q `DataDown`s and REDIRECT, the backup admits a sealed one and redirects every session, and every session moves copy 2; SKIP without it |
//! | `voter-restart` | with `--restart-voter` (R17): the killed victim restarts from its own config and journal without `--fresh` (no `FRESH_JOURNAL` line), and no node reports a `VOTER_FAULT` naming its voter index (unproven: no injected equivocation, R17). `validators`, `replica-out` and `finality` hold it, as `validator-<n−1>r`, to every block and `FINAL` through the end; SKIP without it |
//! | `voter-kill` | with `--kill-voter` (R16): at half the packets, once it has finalized a height, the last validator is killed; its blocks were the box's, and the box finalizes through the block holding the first packet sent after the victim was reaped (cut after it died), with the `n − 1` left. `finality` then needs the box and every running validator through the last block, with Q of the whole committee; SKIP without it |
//! | `data` | with `--data`: the client sends copy 2 of every packet to a `vyrn-data` node (07 §5.1), whose `DATA`/`DATA_HB` frames reach the tap through `vyrn_replica::DataFeed`; the node stores every packet sent (`STATS stored`), `bad_mac`, `events_dropped` and `events_unprinted` are 0 with no `EVENT` line, the feed has no rejected frame and no gap left unrepaired (R14), and that join is the one `replay` reads; SKIP without `--data` |
//!
//! **Readings** (the spec does not settle these; PR body):
//! - R1. The box publishes no output hash. The reference for "replay matches the sequencer" is
//!   what the box put on the wire: every response the client received, per session, sorted by
//!   `(resp_seq, bytes)`. *Ruled (reading of "equal" for loopback UDP in DEV):*
//!   the client's responses must be an in-order, byte-identical subsequence of replay's, and
//!   the shortfall at most `client_sock_drops`, the kernel's receive-drop count for the client's
//!   socket (`/proc/net/udp`, read before it closes); if that count cannot be read, strict
//!   equality. The replay line prints `shortfall=` and `client_sock_drops=` side by side. A
//!   response missing for any other reason, a byte mismatch, or an extra one fails. `dropcopy` takes the same
//!   reading: a drop-copy record whose response packet the client never got passes only if that
//!   response is one of replay's the client is short of. Why: a
//!   client thread starved on a loaded host drops a contiguous burst at its socket, not
//!   vyrn-seq (a 300 ms client stall drops 281, and the shortfall is 281). In the loaded
//!   `--dropcopy` run d-28 the same starvation also stopped validator-0 at `REP_E_HASHLAG`
//!   height 0: it shared CPU 1 with the client, against the validators' 50 ms DEV bound
//!   (`--dev-hashlag-us 50000` then); load, not a fault. The replay side is every `lane_resp` and every fill `tx` with
//!   `resp_seq ≠ 0` (the box does not send `resp_seq` 0 TX packets yet). Fill TX `step`, `lane`
//!   and `role`, which `output_hash` covers, are not on the wire, so the per-block output hash
//!   itself cannot be recomputed from the box's side.
//! - R2. The tap's engine is built the way `vyrn-seq` builds its DEV engine (`EnginePlan`,
//!   `engine_loop`), copied here. A drift between the two shows as a replay failure.
//! - R3. With `--data`, the tap's `DataJoin` is filled only from `vyrn-data`'s frames through
//!   `vyrn_replica::DataFeed` (the tap is destination 0), and gaps by RANGE fetch (R14). Without it, the join gets copy 2 from
//!   the client in process. With `--data` the validators are destinations 1..=n: each reads its
//!   data RX queue, checks `data_root` (vote-rule item 3), fetches gaps from the node, and
//!   replays (`[replay]`, the box's engine and sessions), so `replica-out` runs. Without it they
//!   have no data and no replay.
//! - R4. The validators' `FINAL height=<last_height> view= first= kind= sigs=` and the box's
//!   `FINAL height=<h> view= from=` (#121) are parsed by `height=` only. The committee is a DEV
//!   roster: vote seeds `[i + 1; 32]`, genesis `[0; 32]`, the run's `seq_key` as primary and a
//!   dummy standby, repl and CTRL ports picked below the ephemeral range, `delta_ms = 500`.
//! - R7. `--keyed` (needs `--data --finality`): the box serves only fetches sealed under
//!   `K_fetch` (07 §5.5, 08 §9.6), from the DEV roster: validator 0's X25519 key is
//!   `XCHG_SEED`'s, the box's `BOX_XCHG`'s. The other voters and the `vyrn-seq` entries get
//!   all-zero (low-order) keys, so they get no key: on one host every requester shares
//!   127.0.0.1, and the box refuses two keyed requesters on one IPv4. A relay drops every
//!   `LOSS_EVERY`-th datagram the box sends validator 0, so its RANGE and KEY fetches must be
//!   served (`STATS` `fetch_ring_hit + fetch_log_hit + fetch_resent > 0`) for it to keep up.
//! - R8. `--keyed` also keys the primary `vyrn-seq` box (`SEQ_XCHG`, repl_addr 127.0.0.2) and
//!   gives its `[repair]` `xchg`: with the box still up, `seq-repair` sends a plain KEY fetch of
//!   the last packets sent, one sealed under validator 0's `K_fetch(0, 0, SEQ_TARGET)` and one
//!   under its `K_fetch(1, 0, SEQ_TARGET)`. After R11 moves the box to epoch 1 only the last may
//!   be answered, with the packet's exact bytes (07 §5.5 source 3, 08 §9.6).
//! - R10. `--data-shards N` runs the box on `N` ingest shards (`[shards] n`, 07 §5.2 RSS by
//!   session): `STATS` must report `shards=N` and `hop_full=0`, with every other `data` check
//!   unchanged, so the sharded fan-out keeps one `data_seq` per destination (the feed reports no
//!   gap) and fetches reach the owning shard.
//! - R11. `--keyed`: before the first packet, validator 0 gets `EPOCH 1` on stdin and re-derives
//!   its `K_fetch`, then the data box and the primary `vyrn-seq` box each get `EPOCH 1` and drop
//!   epoch 0's keys. `data` then needs `fetch_unauth = 0`, so every fetch of the run was sealed
//!   under an epoch-1 key, and `seq-repair` (R8) needs the seq box to refuse epoch 0's key.
//! - R12. Path B (07 §3.1). The observer always takes path B (`[nic] order_port_b`, which it
//!   requires) and `vyrn-seq` sends it `PATH_B` copies (`[replication] order_b`); with
//!   `--two-path` every validator does too, and every check above then runs over the deduplicated
//!   two-path stream. `--drop-path-b N` relays the observer's path B and drops its `N`-th
//!   datagram; repair then fills it (R14).
//! - R14. Repair (07 §4.10, sequencer retransmit). Every replica gets `[repair]` with the box's
//!   CTRL port and DEV timers (2 ms, 20 ms). With `--drop-path-b N` the `dropcopy` check requires
//!   that the observer Nacked, gave up no hole, never printed `DURABLE_WAIT`, and that its drop
//!   copy is whole. `--drop-rtx` also drops every retransmit to it: it must print
//!   `ORDER_GAP ... path=B` and `DURABLE_WAIT height=h`, replay exactly blocks `0..h`, and the box
//!   must go past `h`; its drop copy is not compared then (10 §8.2). `--drop-path-a N` relays
//!   validator 0's path A and drops its `N`-th datagram: the `repair` check requires a Nack and no
//!   given-up hole, and `finality` that it finalized through the last block.
//! - R13. `--data-kill` (needs `--keyed`): a backup `vyrn-data` box (`src = 1`, roster data
//!   box 1 with `BOX1_XCHG`, the same destinations) runs beside the home box, and every validator
//!   lists both (`[data] boxes`) with a DEV `silence_us` of `KILL_SILENCE_US`. The client sends
//!   copy 2 of each session's first `FIRST_COPIES` (4) packets to both (07 §5.7 interim
//!   reading, ruled) and the rest to the home box,
//!   which the harness kills after 2/5 of the packets. `failover` needs every running validator's
//!   `DATA_DOWN box=0` at quorum, no `DATA_DOWN box=1` while the backup runs, validator 0's
//!   sealed `REDIRECT_SENT down=0 to=1` (only it holds a `K_fetch`, R7), the backup's
//!   `redirects > 0` and `redirect_unknown = 0`, and a verified `DataRedirect` (DR1, under the
//!   session's `K_seq`) for every session. On its first one per session (DR2) the client moves
//!   copy 2 to the backup and resends its retained bytes from `resend_from` (DR3). `data` checks
//!   the backup's `STATS` without `stored` (the killed box's are gone). R11's `fetch_unauth`
//!   may count the unkeyed validators' plain REDIRECT_BATCHes (kind 5), which a keyed box reads
//!   as bad tags, and nothing else: at most their `FAILOVER redirect_msgs` summed (a plain kind-4
//!   REDIRECT is malformed to a keyed box instead), and `replay` still needs every packet in the tap's join, now fed by both boxes'
//!   frames. The client paces its DR3 resends (20 µs apart): one burst of every retained packet
//!   overflows the backup's ingest socket on a 2-vCPU host. The client keeps each sent packet
//!   for `CLIENT_RETAIN` (100 ms, 04 DR4) and resends only those; `failover` fails if a packet
//!   it sent to the dead home after the kill had expired before its redirect arrived, and prints
//!   the slowest kill-to-redirect time (about 65 ms on a 2-vCPU orb). `KILL_SILENCE_US` (50 ms)
//!   leaves the rest of the window to gossip and REDIRECT: at 100 ms redirects arrive after about
//!   114 ms and the check fails. At 20 ms, before #189, the backup, busy serving every
//!   validator's KEY fetches for the lost packets, went silent long enough to be marked down too
//!   (4 of 4 runs). Since #189 20 ms still fails 3 of 5 runs. *Ruled (DEV only; 07's
//!   `REP_DATA_SILENCE_MS` stays 1 ms):* 50 ms. On an unpinned 2-vCPU host the backup's sender
//!   core was measured going 51.9 ms without a turn (vyrn-seq and vyrn-data busy-polling), and
//!   every validator marked it down 20 ms into that stall while still polling its data queue at
//!   least every 0.8 ms with no full burst: the box really sent nothing, so neither validator
//!   backlog nor receipt timestamps explain it. With the default workloads' four sessions this
//!   is one REDIRECT_BATCH per round; R15 runs 2 000.
//! - R14. The tap repairs its own data gaps, as a replica does (07 §5.5 source 1): a gap its
//!   `DataFeed` reports in box `src`'s `data_seq` is asked for by `Fetch::Range{dst: 0}` at
//!   that box's fetch address, the box resends those `DATA` frames to the tap, and a seq still
//!   missing after `TAP_REASK` (20 ms) is asked for again until the run stops. `data` fails only
//!   on a gap never repaired. Without this a single frame lost to the tap (a UDP receive
//!   overflow while its thread is descheduled on a loaded host) failed `data` and `replay`
//!   (`Missing`) though the box held it. *Reading* (harness): only unkeyed boxes are asked; a
//!   keyed box would count the tap's plain fetch in `fetch_unauth` (R7, R11), and the DEV
//!   roster gives the tap no `K_fetch`, so under `--keyed` a tap gap still fails. `--tap-loss N`
//!   relays the tap's data socket and drops every N-th datagram; `data` then also needs the
//!   relay to have dropped and the tap to have repaired at least one frame.
//! - R15. `--workload tools/e2e-smoke/wl-smoke-many.toml` (WL-SMOKE-MANY) is WL-SMOKE-NOCROSS
//!   with 1 000 MM sessions per lane; with `--packets 8000` about 1 960 of them send. Every
//!   session's DEV entries go into the `vyrn-seq`, data box and `[replay]` configs as for four.
//!   *Reading* (harness): a session's account is `slot mod 15 + 1`, so the sessions of a lane
//!   share its 15 account slots (`NA` = 16, slot 0 unused); a shared account changes which
//!   orders self-trade and which balance binds, not what replay must reproduce. With
//!   `--data-kill` the validators send each round as REDIRECT_BATCHes (about 1 625 sessions in
//!   9 messages), the client must move every session, and `failover` prints the slowest
//!   kill-to-redirect over the sessions that had sent before the kill apart from those that
//!   started later, whose first round comes when a replica first holds one of their blocks
//!   (07 §5.7). Where the time goes, measured at 2 000 sessions on a 2-vCPU orb: detection
//!   50.3 ms, Q DataDowns and every first-round batch sent by 51 ms, all of them at the backup
//!   by 51–55 ms; the backup then sends its per-entry `DataRedirect`s at about 50 per ms (one
//!   shard core, 16 per turn, sharing the CPUs), so the last live session's first redirect
//!   reaches the client at about 82 ms (76.5 ms in CI); the client applies each within 2.6 ms.
//!   *Ruled:* that this passes DR4's design bound on detection plus fan-out is a DEV figure of
//!   a 2-vCPU host (50 ms DEV detection, the backup's sending CPU-bound), not a protocol miss;
//!   07's `REP_DATA_SILENCE_MS` is 1 ms. The backup's
//!   refused redirects are retried since #194 (`redirect_retried`), and `failover` needs
//!   `redirect_dropped` = 0, and `redirect_unknown` = 0. A backup learned a session's address
//!   from one first copy, so one lost to a full shard ring (`hop_full`) or the socket left the
//!   session unmovable. The client now sends four (R13), and since #203 the box holds
//!   redirects while its shard ring has 2 048 or fewer free slots, so ingest wins it.
//!   *Ruled (R15 gates):* `redirect_unknown` = 0, `redirect_dropped` = 0, the box's `hop_full`
//!   = 0 (ingest), every session moves by the deadline, and `replay` (with R1's
//!   shortfall bounded by `client_sock_drops`). DR4 timing does not gate here: CI's R15 step passes `--dr4-dev`, which
//!   prints the slowest kill-to-redirect and the packets expired at the dead home as a DEV
//!   figure. A 2-vCPU host holding 2 000 redirects cannot show the 100 ms bound (on a 2-vCPU
//!   orb on 733ff96: 87–147 ms, the slow runs those with about 2 500 held redirects); 07 §5.7
//!   treats it as a pinned-core figure. The 4-session `--data-kill` step keeps its DR4 gate.
//!   The client opens a `DataRedirect` with the key of the session in its bytes 8..12: trying
//!   every session's key fell behind a burst of 1 600 redirects and moved half the sessions.
//! - R16. `--kill-voter` (needs `--finality`, n ≥ 4): SIGKILL of the last validator after
//!   half the packets, so the committee runs with `f = 1` voter gone for the rest of the run.
//!   Every check then covers the `n − 1` running validators, while Q stays that of the whole
//!   committee (`n − ⌊(n − 1)/3⌋`): with n = 4 every survivor's vote is needed, so any
//!   REP_E_HASHLAG stop leaves no quorum (R6). *Reading* (harness): the victim is the last
//!   validator, not validator 0, which `--keyed` and `--drop-path-a` single out; a crash is
//!   SIGKILL with no stdin EOF, so it prints no `STATS` and is not stopped cleanly. At half the
//!   packets the client pauses until the victim has finalized a height (deadline `T`), so the
//!   victim has voted before it dies: consensus can take seconds to finalize its first height on
//!   a loaded 2-vCPU host, after a 1 500-packet run has ended. The client's schedule then
//!   shifts by the pause, so no burst follows it. Progress after the kill is the barrier block: the harness
//!   reaps the victim, then sends the next packet, and the block holding that packet was cut
//!   after the victim died, so the box finalizing through it proves Q without the victim. The
//!   victim's own `BLOCK` lines cannot bound this (it may vote for a block before printing it),
//!   and the box's `FINAL` lines are not ordered against the kill (another thread reads them).
//!   The victim's lines are read through its reader's EOF mark before they are checked. Not with `--data-kill`, whose DR4 timing the
//!   pause would skew.
//! - R17. `--restart-voter` (needs `--kill-voter`, not `--two-path`): the R16 victim restarts at
//!   3/4 of the packets, or right after it is reaped with `--restart-immediate`, so it replays
//!   its journal in the view it was voting in when it died. It gets the same config, journal
//!   and vote key, and binds the ORDER port it printed before (the box still sends there).
//!   DEV: the restarted validator catches up from frame 1 through the repair backlog, so it lags
//!   from that backlog, not from hashing. `--restart-hashlag-us` gives it alone a harness-only
//!   catch-up bound; every other replica keeps `--dev-hashlag-us` (CI: 20 ms) under
//!   `--strict-hashlag`, and its own `REP_E_HASHLAG` past that bound still fails the run. CI runs
//!   200 ms: on a 2-vCPU orb, 9 immediate-restart runs each on main 68833e1 at 20 ms stopped it
//!   once (height 15), at 100 ms none; 200 ms is twice that (DEV, not a latency result). Known
//!   gap: only the no-`FRESH_JOURNAL` half of the gate is proven. The no-conflicting-vote half has
//!   no injected equivocation, so a `VOTER_FAULT` path that never fires would pass it vacuously;
//!   proving it needs a DEV signing hook in vyrn-validator's voter that signs a second
//!   `Notarize` for another payload in one view.
//! - R18. The tap repairs its own ORDER holes, as a path-A replica does (07 §4.9, §4.10): with
//!   `--finality` (the box's CTRL port) its thread runs `vyrn_replica::Paths` (one path) and
//!   Nacks each hole with R14's DEV timers and 8 tries. Without it the tap keeps arrival order.
//!   Why: on a loaded 2-vCPU host the tap's thread, descheduled, overflowed its socket: 2 of 103
//!   loaded runs failed `replay` with `tap order core: OutOfOrder`, and both times the hole
//!   (8 and 46 frames) equalled the kernel's receive-drop count for that socket. It was a drop,
//!   not a reorder. *Ruled (as R1):* the frames only a retransmit delivered (`tap_repaired`)
//!   may be at most the frames lost to the tap: its socket's kernel drop count (`/proc/net/udp`,
//!   read before it closes), plus, with `--tap-order-loss N`, the relay's drops and its socket's;
//!   without that count, none. A hole given up fails. `--tap-order-loss N` relays the tap's order
//!   socket and drops every N-th datagram, retransmits included; `replay` then also needs the
//!   relay to have dropped and the tap to have repaired at least one frame. The replay line
//!   prints `tap_sock_drops=`, `tap_relay_dropped=`, `tap_repaired=`, `tap_nacks=`, `tap_gaps=`
//!   and `tap_too_old=`.
//! - R6. With more than `n − Q` validators stopped at `REP_E_HASHLAG` (Q = n − ⌊(n − 1)/3⌋),
//!   no quorum is left and the box cannot finalize the rest: DEV timing, a `WARN`. The box must
//!   still have finalized from votes when quorum held for two heights or more, so a broken vote
//!   path fails. `--strict-hashlag` drops the exception.
//! - R5. `REP_E_HASHLAG` (07 §3.7 INV-REP-8) is a 1 ms real-time bound that the validator
//!   measures with user-space receive times and that 07 §7.2 budgets for pinned cores. On an
//!   unpinned DEV machine one preemption between an ORDER frame and its HASH frame trips it, so
//!   by default a validator that stops at it is a `WARN`: its blocks before the fault must still
//!   be the box's. It stays a `WARN` when every validator stops at it (all of them can stop at
//!   one height when the box is preempted between the two frames): the replay tap's order core,
//!   which has no real-time bound, must still ready every height. Any other fault, an `Invalid`
//!   verdict, a stall or a block that differs from the box's fails. `--strict-hashlag` fails a
//!   `REP_E_HASHLAG` stop too and requires one validator to cover every height. The shipped
//!   bound stays 1 ms. `--dev-hashlag-us` (DEV only, needs `--data`) gives the validators
//!   `dev = true` and a larger `[replay] hashlag_us`; CI runs it with `--strict-hashlag`, so every
//!   CI run must cover and finalize every height. The observer gets the voters' bound (or
//!   `--obs-hashlag-us`): with `REP_E_HASHLAG` measured from the kernel's receive stamp (07 §3.7)
//!   the time its order thread spends replaying, feeding the drop copy and finalizing no longer
//!   counts, so it no longer needs the 200 ms it had. CI runs 20 ms: on a loaded 2-vCPU orb (all
//!   validators and the harness on one CPU, two CPU hogs) 40 of 40 runs at 20 ms had no stop, 1 of
//!   10 at 10 ms and 1 of 5 at 2 ms stopped, the latter with every replica at one height, as the
//!   box's sender was preempted between an ORDER frame and its HASH frame (DEV, not a latency
//!   result). Its `REP_E_HASHLAG` still fails the run. `--seq-cpus` and `--validator-cpus` (taskset masks)
//!   keep the box's two polling threads off the validators' cores. Without them all validators
//!   can stop at one height when the box is preempted between an ORDER frame and its HASH frame.
//!
//! - R9. `--dropcopy`'s timing is the receive time of a drop-copy record at its client minus
//!   the receive time of the response packet that carried the same client record (its
//!   `(session, resp_seq)`), both on this host's monotonic clock: REQ-LAT-12's "record after the
//!   `Fill`", over every record that names a response: acks, cancels, outs and the taker's
//!   `DC_FILL`s (a maker's has no `resp_seq`, 10 §8.4 item 4), which `WL-SMOKE` has and
//!   `WL-SMOKE-NOCROSS` does not; the line counts the `DC_FILL`s it includes. `--dropcopy` gates
//!   CI on both workloads. REQ-LAT-12 budgets p99 ≤ 50 µs on REF; this build's observer replays per
//!   block, after the block closes and its payloads arrive, so the number is bounded below by the
//!   block interval. It is a DEV number on a shared machine, printed as one, not a latency result.
//!
//! **Post-only.** A post-only `New` that crosses the lane's snapshot is forwarded, and the BBO
//! core decides it against the true book (03 ARC-D6), so `wl-smoke.toml`, which sends them,
//! replays byte for byte and gates CI alongside `wl-smoke-nocross.toml`.
//!
//! **Build.** Run release binaries: a debug `vyrn-validator` spends more than
//! `REP_HASHLAG_MAX_NS` (1 ms) on ORDER frames often enough to raise `REP_E_HASHLAG` in most
//! runs (R5).
//!
//! DEV timings on shared machines are not latency results; the harness prints only R9's, labeled
//! DEV.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use clap::Parser;
use vyrn_md::dropcopy::{DcConfig, DcRecord, DropCopy, StreamId};
use vyrn_md::{Channel, PacketSink, SinkStream};

mod dropcopy;
use vyrn_bbo::{Bbo, Phase, Record, TxEntry};
use vyrn_bench::config::{Config as WlConfig, Mode};
use vyrn_bench::generator::{GenOptions, Generator, session_keys};
use vyrn_cut::Hw;
use vyrn_data::redirect::Redirect;
use vyrn_engine::{Engine, NoResponses, Rec, Shared, Sink};
use vyrn_lane::{ArenaConfig, Lane, PathTable, RespPkt, SessionSpec};
use vyrn_log::Layout;
use vyrn_replica::{
    BlockInputs, DataFeed, DataJoin, EpochView, OrderCore, ReplayEngine, RustReplay,
};
use vyrn_risk::{AcctRisk, AcctSlot, BookSpec, SessionBuckets};
use vyrn_types::{
    AccountId, BookId, Epoch, Hash, Height, LaneId, PacketFlags, PubKey, SessionId, Tick,
};
use vyrn_wire::{ReqHeader, Request, Response, encode_request};

const WORKLOAD: &str = include_str!("../wl-smoke.toml");
const SEQ_SEED: [u8; 32] = [0x42; 32];
/// `--keyed` (R7): validator 0's X25519 secret and the box's.
const XCHG_SEED: [u8; 32] = [0x5a; 32];
const BOX_XCHG: [u8; 32] = [0x6b; 32];
/// `--keyed` (R8): the primary `vyrn-seq` box's X25519 secret.
const SEQ_XCHG: [u8; 32] = [0x7c; 32];
/// `--data-kill` (R13): the backup data box's X25519 secret.
const BOX1_XCHG: [u8; 32] = [0x8d; 32];
/// `--data-kill` (R13): the validators' DEV `[data] silence_us`, for an unpinned host.
const KILL_SILENCE_US: u64 = 50_000;
/// R13 (07 §5.7 interim reading, ruled): copy 2 of each session's first this many packets also
/// goes to every backup box, so one lost datagram does not cost a backup the session's address.
const FIRST_COPIES: usize = 4;
/// `--data-kill` (R13): the client keeps a sent packet this long (`REP_CLIENT_RETAIN_MS`, 04
/// DR4), then discards it.
const CLIENT_RETAIN: Duration = Duration::from_millis(100);
/// `--keyed` (R7): the relay to validator 0 drops every this-many-th datagram.
const LOSS_EVERY: u64 = 25;
/// R14: the replicas' DEV repair timers, in µs.
const REP_DEV_HOLE_WAIT_US: u64 = 2_000;
const REP_DEV_RETRY_US: u64 = 20_000;

/// R14: a replica's `[repair]`: the box's CTRL port, and the port the box has for it on each
/// path when a relay stands in front of it.
#[derive(Clone, Copy)]
struct Rep {
    nack: SocketAddrV4,
    order_as: Option<u16>,
    order_b_as: Option<u16>,
}

const LANES: usize = 2;
const NA: usize = 16;
const BOOK: u16 = 7;
const QUOTE: u64 = 1_000_000_000_000;
const BASE: u64 = 1_000_000_000;
// The box's DEV engine (bin/vyrn-seq: config.toml shape and `EnginePlan`), R2.
const TICK_MIN: u32 = 1;
const TICK_MAX: u32 = 512;
const WIN_CENTER: u32 = 100;
const SLOT_CAP: u32 = 1024;

#[derive(Parser)]
#[command(about = "Multi-node end-to-end smoke run (vyrn-seq, vyrn-validator, replay tap)")]
struct Cli {
    /// Directory holding vyrn-seq and vyrn-validator (default: this binary's directory).
    #[arg(long)]
    bin_dir: Option<PathBuf>,
    /// Workload config (default: the embedded wl-smoke.toml).
    #[arg(long)]
    workload: Option<PathBuf>,
    /// Validators (default 3, or 4 with --finality: n = 3f + 1 with f = 1).
    #[arg(long)]
    validators: Option<usize>,
    #[arg(long, default_value_t = 1500)]
    packets: u64,
    /// Messages per second (replaces the workload's rate).
    #[arg(long, default_value_t = 2000)]
    rate: u64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Deadline of every wait, in seconds.
    #[arg(long, default_value_t = 30)]
    wait_s: u64,
    /// Require finality lines from every validator (R4).
    #[arg(long)]
    finality: bool,
    /// CPU list for vyrn-seq (taskset -c), so the box's threads do not share cores with the
    /// validators' polling threads (R5).
    #[arg(long)]
    seq_cpus: Option<String>,
    /// CPU list for every vyrn-validator (taskset -c).
    #[arg(long)]
    validator_cpus: Option<String>,
    /// Fail a validator's REP_E_HASHLAG too (pinned rigs); by default it is a WARN (R5).
    #[arg(long)]
    strict_hashlag: bool,
    /// Route payloads through a vyrn-data node.
    #[arg(long)]
    data: bool,
    /// DEV only: the validators' REP_E_HASHLAG bound in µs (`dev = true`, `[replay] hashlag_us`;
    /// needs --data). The spec's bound is 1000; CI sets a larger one with --strict-hashlag (R5).
    #[arg(long, value_name = "US")]
    dev_hashlag_us: Option<u64>,
    /// DEV only, with --dev-hashlag-us: the observer's bound in µs, in place of the voters'
    /// (R5). For measuring how far the bounds go down.
    #[arg(long, value_name = "US", requires = "dev_hashlag_us")]
    obs_hashlag_us: Option<u64>,
    /// DEV only, with --restart-voter and --dev-hashlag-us: the restarted validator's catch-up
    /// bound in µs, in place of the voters' (R17). It replays the repair backlog from frame 1.
    #[arg(long, value_name = "US", requires_all = ["dev_hashlag_us", "restart_voter"])]
    restart_hashlag_us: Option<u64>,
    /// Key the vyrn-data node from the roster and drop some of validator 0's data frames, so
    /// its sealed fetches must be served (R7; needs --data and --finality).
    #[arg(long)]
    keyed: bool,
    /// Add an observer replica and vyrn-dropcopy, and check the drop copy end to end (needs
    /// --data and --finality).
    #[arg(long)]
    dropcopy: bool,
    /// The vyrn-data node's ingest shards (`[shards] n`, R10; needs --data).
    #[arg(long, value_name = "N", default_value_t = 1)]
    data_shards: usize,
    /// Send ORDER frames on path B too (`[replication] order_b`), to every validator's
    /// `order_port_b` (R12). The observer always has path B (it requires it).
    #[arg(long)]
    two_path: bool,
    /// Relay the observer's path B and drop its N-th datagram (needs --dropcopy, R12): the
    /// observer must hold the block that frame belongs to and replay nothing from it on, while
    /// the validators, which still have path A, finish.
    #[arg(long, value_name = "N")]
    drop_path_b: Option<u64>,
    /// Relay the tap's data socket and drop every N-th datagram the data box sends it (R14;
    /// needs --data, not --keyed): the tap must repair its gaps by RANGE fetch, as a replica
    /// does.
    #[arg(long, value_name = "N")]
    tap_loss: Option<u64>,
    /// Relay the tap's order socket and drop every N-th datagram the box sends it (R17; needs
    /// --finality): the tap must Nack its holes, as a replica does.
    #[arg(long, value_name = "N")]
    tap_order_loss: Option<u64>,
    /// With --data-kill, print DR4 timing (slowest kill-to-redirect, packets expired at the
    /// dead home) as a DEV figure instead of gating on it (R15: a 2-vCPU host holding 2 000
    /// redirects cannot show the 100 ms bound).
    #[arg(long)]
    dr4_dev: bool,
    /// With --drop-path-b, also drop every retransmit to the observer's path B (R14): repair
    /// cannot fill the copy, so the observer must report `ORDER_GAP` and hold the block.
    #[arg(long)]
    drop_rtx: bool,
    /// Relay validator 0's path A and drop its N-th datagram (needs --finality, R14): it must
    /// Nack the frame, get it retransmitted and finalize through the last block.
    #[arg(long, value_name = "N")]
    drop_path_a: Option<u64>,
    /// Add a backup data box and kill the home box mid-run: the validators reach Q DataDowns
    /// and REDIRECT, and the client moves copy 2 (R13; needs --keyed).
    #[arg(long)]
    data_kill: bool,
    /// At half the packets, once it has finalized a height, kill the last validator (f = 1,
    /// R16; needs --finality and at least 4 validators): the rest must finalize through the end.
    #[arg(long)]
    kill_voter: bool,
    /// With --kill-voter, restart the victim at 3/4 of the packets from its own journal, without
    /// --fresh (R17): it must rejoin and finalize through the last block, and no node may report
    /// a conflicting vote from it.
    #[arg(long)]
    restart_voter: bool,
    /// With --restart-voter, restart the victim right after the kill instead, in the view it
    /// was leading when it died (R17): its journal is replayed mid-view.
    #[arg(long)]
    restart_immediate: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("e2e-smoke: {e}");
            ExitCode::from(2)
        }
    }
}

/// The kernel's receive-drop count of the UDP socket bound to 127.0.0.1:`port` (Linux
/// `/proc/net/udp`, last column), `None` elsewhere or if not found.
fn udp_drops(port: u16) -> Option<u64> {
    let t = std::fs::read_to_string("/proc/net/udp").ok()?;
    let want = format!("0100007F:{port:04X}");
    t.lines()
        .skip(1)
        .map(str::split_whitespace)
        .find_map(|mut f| {
            (f.nth(1)? == want)
                .then(|| f.last()?.parse().ok())
                .flatten()
        })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ----- the workload -----

struct Sess {
    id: SessionId,
    lane: u8,
    acct: u32,
    k_seq: [u8; 16],
    k_out: [u8; 16],
}

struct Pkt {
    send_ns: u64,
    lane: u8,
    session: SessionId,
    pkt_seq: u32,
    bytes: Vec<u8>,
}

/// The generator's first `n` packets, re-addressed to the DEV sessions (module docs).
fn workload(cli: &Cli) -> Result<(Vec<Sess>, Vec<Pkt>), String> {
    let text = match &cli.workload {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => WORKLOAD.to_owned(),
    };
    let cfg = WlConfig::parse(&text).map_err(|e| e.to_string())?;
    let opts = GenOptions {
        seed: cli.seed,
        rate_override: Some(cli.rate),
    };
    let generator = Generator::new(&cfg, &opts).map_err(|e| e.to_string())?;
    let mut sessions: BTreeMap<u32, Sess> = BTreeMap::new();
    let mut pkts = Vec::new();
    for p in generator.take(usize::try_from(cli.packets).map_err(|e| e.to_string())?) {
        let req = Request::parse(p.bytes()).map_err(|e| format!("generator packet: {e:?}"))?;
        let h = req.header();
        let gen0 = h.session();
        let slot = vyrn_wire::session_slot(gen0);
        let id = vyrn_wire::session_id(slot, p.lane, 1).ok_or("session id")?;
        let s = sessions.entry(id.0).or_insert_with(|| {
            let (k_seq, _) = session_keys(cli.seed, id, Mode::Base);
            let k_out = vyrn_crypto::hash::hash(&k_seq).0;
            Sess {
                id,
                lane: p.lane.0,
                // Account slots 1..NA; with more sessions than that per lane (R15) they share.
                acct: u32::from(slot) % (NA as u32 - 1) + 1,
                k_seq,
                k_out: k_out.first_chunk::<16>().copied().unwrap_or_default(),
            }
        });
        let msgs = req
            .msgs()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("generator message: {e:?}"))?;
        let pkt_seq = h.pkt_seq.get();
        let hdr = ReqHeader::new(id, pkt_seq, 0, BookId(BOOK), false);
        let mut buf = [0u8; vyrn_types::MAX_REQ_PAYLOAD];
        let n = encode_request(&mut buf, hdr, &msgs, &s.k_seq, None).ok_or("re-encode")?;
        pkts.push(Pkt {
            send_ns: p.send_ns,
            lane: p.lane.0,
            session: id,
            pkt_seq,
            bytes: buf.get(..n).unwrap_or_default().to_vec(),
        });
    }
    Ok((sessions.into_values().collect(), pkts))
}

// ----- child processes -----

/// Every line a child prints on stdout, tagged with its node index.
type Lines = Receiver<(usize, String)>;

struct Node {
    name: String,
    child: Child,
    lines: Vec<String>,
}

/// Kills whatever is still running when the harness returns, on every path.
struct Nodes(Vec<Node>);

impl Drop for Nodes {
    fn drop(&mut self) {
        for n in &mut self.0 {
            let _ = n.child.kill();
            let _ = n.child.wait();
        }
    }
}

impl Nodes {
    fn spawn(
        &mut self,
        name: &str,
        cmd: &mut Command,
        tx: &Sender<(usize, String)>,
    ) -> Result<usize, String> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("{name}: {e}"))?;
        let out = child.stdout.take().ok_or("stdout")?;
        let idx = self.0.len();
        let tx = tx.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines() {
                // A read error ends the stream without EOF_MARK: a check that needs the whole
                // output (R16) then fails at its deadline instead of reading a partial one.
                let Ok(l) = l else { return };
                if tx.send((idx, l)).is_err() {
                    return;
                }
            }
            // Clean EOF, ordered after the child's last line: its output is complete (R16).
            let _ = tx.send((idx, EOF_MARK.to_owned()));
        });
        self.0.push(Node {
            name: name.to_owned(),
            child,
            lines: Vec::new(),
        });
        Ok(idx)
    }

    /// Takes lines until `want` holds or `deadline` passes.
    fn wait(
        &mut self,
        rx: &Lines,
        deadline: Instant,
        what: &str,
        mut want: impl FnMut(&[Node]) -> bool,
    ) -> Result<(), String> {
        while !want(&self.0) {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok((i, l)) => {
                    if let Some(n) = self.0.get_mut(i) {
                        n.lines.push(l);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("timed out waiting for {what}"));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!("every child exited before {what}"));
                }
            }
        }
        Ok(())
    }

    /// Takes every line already queued, without waiting.
    fn drain(&mut self, rx: &Lines) {
        while let Ok((i, l)) = rx.try_recv() {
            if let Some(n) = self.0.get_mut(i) {
                n.lines.push(l);
            }
        }
    }

    /// Closes stdin (`--stop-on-stdin-eof`) and waits for the child to exit and its `STATS`.
    fn stop(&mut self, i: usize, rx: &Lines, deadline: Instant) -> Result<bool, String> {
        let n = self.0.get_mut(i).ok_or("node")?;
        drop(n.child.stdin.take());
        let name = n.name.clone();
        self.wait(rx, deadline, &format!("{name} STATS"), |ns| {
            ns.get(i)
                .is_some_and(|n| n.lines.iter().any(|l| l.starts_with("STATS")))
        })?;
        let n = self.0.get_mut(i).ok_or("node")?;
        loop {
            if let Some(st) = n.child.try_wait().map_err(|e| e.to_string())? {
                return Ok(st.success());
            }
            if Instant::now() > deadline {
                return Err(format!("{name} did not exit"));
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
}

/// The line a node's reader adds after the child's stdout reaches EOF (no child prints it).
const EOF_MARK: &str = "\u{0}EOF";

fn line<'a>(n: &'a Node, prefix: &str) -> Option<&'a str> {
    n.lines.iter().find_map(|l| l.strip_prefix(prefix))
}

fn field<'a>(l: &'a str, k: &str) -> Option<&'a str> {
    l.split(' ')
        .find_map(|f| f.strip_prefix(k)?.strip_prefix('='))
}

/// R14 (`--drop-path-b N --drop-rtx`): path B lost one of the observer's frames and every
/// retransmit of it, so repair gives up (`ORDER_GAP ... path=B`) and the observer holds the block
/// it belongs to (`DURABLE_WAIT height=h`), replaying exactly the blocks below it, while the box
/// went past it.
fn durable_hold(n: &Node, dropped: u64, top: Option<u64>) -> Result<String, String> {
    if dropped == 0 {
        return Err("the relay dropped nothing".into());
    }
    if !n
        .lines
        .iter()
        .any(|l| l.starts_with("ORDER_GAP ") && l.ends_with(" path=B"))
    {
        return Err("no ORDER_GAP path=B: repair did not give up on the dropped copy".into());
    }
    let h: u64 = line(n, "DURABLE_WAIT height=")
        .and_then(|v| v.parse().ok())
        .ok_or("no DURABLE_WAIT: the observer did not hold a block")?;
    let replayed: Vec<u64> = blocks(n).iter().map(|b| b.0.0).collect();
    if replayed != (0..h).collect::<Vec<_>>() {
        return Err(format!(
            "held at {h} but replayed {} blocks, last {:?}",
            replayed.len(),
            replayed.last()
        ));
    }
    match top {
        Some(t) if t > h => Ok(format!(
            "path B dropped 1 frame; the observer held block {h} and replayed only 0..{h} of 0..={t}"
        )),
        _ => Err(format!("held at {h}, but the box's last block is {top:?}")),
    }
}

/// R14: a relay dropped one datagram of `who` and repair filled it: it sent a Nack, the box
/// retransmitted, and no hole was given up.
fn repaired(n: &Node, dropped: u64, who: &str) -> Result<String, String> {
    if dropped != 1 {
        return Err(format!("the relay dropped {dropped} datagrams, not 1"));
    }
    let st = line(n, "REPAIR ").ok_or_else(|| format!("{who} printed no REPAIR line"))?;
    let nacks: u64 = field(st, "nacks").and_then(|v| v.parse().ok()).unwrap_or(0);
    if nacks == 0 || field(st, "gaps") != Some("0") {
        return Err(format!("{who}: REPAIR {st}"));
    }
    if n.lines.iter().any(|l| l.starts_with("DURABLE_WAIT ")) {
        return Err(format!("{who} held a block that repair should have filled"));
    }
    Ok(format!("1 datagram dropped and repaired ({nacks} Nacks)"))
}

/// `"a", "b"`: a TOML array's items.
fn quoted(xs: &[String]) -> String {
    xs.iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `(height, first_step, last_step)` and the whole line of every `BLOCK` line.
fn blocks(n: &Node) -> Vec<((u64, u64, u64), &str)> {
    n.lines
        .iter()
        .filter_map(|l| {
            let b = l.strip_prefix("BLOCK ")?;
            let g = |k| field(b, k)?.parse().ok();
            Some(((g("height")?, g("first_step")?, g("last_step")?), b))
        })
        .collect()
}

/// `bin`, under `taskset -c cpus` when a CPU list is given.
fn command(bin: &Path, cpus: Option<&str>) -> Command {
    match cpus {
        Some(c) => {
            let mut cmd = Command::new("taskset");
            cmd.arg("-c").arg(c).arg(bin);
            cmd
        }
        None => Command::new(bin),
    }
}

// ----- the replay tap -----

struct View(PubKey);

impl EpochView for View {
    fn epoch(&self) -> Epoch {
        Epoch(0)
    }
    fn book(&self) -> BookId {
        BookId(BOOK)
    }
    fn seq_key(&self, sender: u8) -> Option<PubKey> {
        (sender == 0).then_some(self.0)
    }
    fn fenced(&self, _: Height) -> bool {
        false
    }
}

/// One sent response as the client saw it, or as replay produced it: session, resp_seq,
/// echo_pkt and the records' 01 §6.4 bytes (R1).
type Resp = (u32, u32, u32, Vec<[u8; 16]>);

#[derive(Default)]
struct Collect(Vec<Resp>);

impl Sink for Collect {
    fn record(&mut self, _: &Rec<'_>) {}
    fn lane_resp(&mut self, _: LaneId, p: &RespPkt) {
        let recs = p.records().iter().map(|r| r.encode()).collect();
        self.0.push((p.session.0, p.resp_seq, p.echo_pkt, recs));
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        if h.resp_seq != 0 {
            let recs = recs.iter().map(|r| r.encode()).collect();
            self.0.push((h.session.0, h.resp_seq, h.pkt_seq, recs));
        }
    }
}

/// `MBO` packets the harness does not read.
struct NoPackets;

impl PacketSink for NoPackets {
    fn emit(&mut self, _: Channel, _: &[u8]) {}
}

type DcRecs = Vec<(StreamId, u64, DcRecord)>;

/// The tap's sink: the responses (R1) and, with `--dropcopy`, an in-process drop copy over
/// `vyrn-md`'s `SinkStream`, as the observer's ring carries it.
struct TapSink {
    resp: Collect,
    dc: Option<SinkStream<NoPackets, DropCopy<DcRecs>>>,
}

impl Sink for TapSink {
    fn record(&mut self, r: &Rec<'_>) {
        if let Some(d) = &mut self.dc {
            d.record(r);
        }
    }
    fn lane_resp(&mut self, l: LaneId, p: &RespPkt) {
        self.resp.lane_resp(l, p);
        if let Some(d) = &mut self.dc {
            d.lane_resp(l, p);
        }
    }
    fn tx(&mut self, h: &TxEntry, recs: &[Record]) {
        self.resp.tx(h, recs);
        if let Some(d) = &mut self.dc {
            d.tx(h, recs);
        }
    }
}

/// A running `vyrn-data` box: its node index and its READY addresses.
struct DataBoxNode {
    idx: usize,
    ingest: SocketAddrV4,
    fetch: SocketAddrV4,
}

/// The tap's data path (R3, R14): its join, filled through `DataFeed` from the data boxes'
/// frames, and what that took.
struct DataTap {
    join: DataJoin,
    frames: usize,
    stored: u64,
    /// Frames the tap asked for again by RANGE fetch and got.
    repaired: u64,
    /// Rejected frames, dropped packets and the gaps never repaired.
    errs: Vec<String>,
}

/// R14: how long a gap's RANGE fetch may go unanswered before the tap asks again.
const TAP_REASK: Duration = Duration::from_millis(20);

/// The tap's data socket until `stop`: every frame goes through a `DataFeed` (destination 0 of
/// `n_boxes` boxes), and when `fetch` names the boxes' fetch addresses (unkeyed boxes, R14) a
/// gap in box `src`'s `data_seq` is fetched from `fetch[src]` by RANGE, re-asked every
/// `TAP_REASK` until its frames arrive, as a replica does (07 §5.5 source 1).
fn data_tap(
    sock: UdpSocket,
    n_boxes: u8,
    fetch: Vec<SocketAddrV4>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<DataTap> {
    std::thread::spawn(move || {
        let mut t = DataTap {
            join: DataJoin::default(),
            frames: 0,
            stored: 0,
            repaired: 0,
            errs: Vec::new(),
        };
        let mut feed = DataFeed::new(BookId(BOOK), n_boxes, 0);
        // (src, data_seq) still missing → when it was last asked for.
        let mut pending: BTreeMap<(u8, u64), Instant> = BTreeMap::new();
        let ask = |src: u8, from: u64, to: u64| {
            if let Some(a) = fetch.get(usize::from(src)) {
                let f = vyrn_data::frame::Fetch::Range { dst: 0, from, to };
                let _ = sock.send_to(&f.encode(), a);
            }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(5)));
        let mut buf = [0u8; 65536];
        while !stop.load(Ordering::Acquire) {
            if let Ok(k) = sock.recv(&mut buf) {
                let b = buf.get(..k).unwrap_or_default();
                t.frames += 1;
                if let Ok(f) = vyrn_data::frame::decode(b)
                    && f.hdr.kind == vyrn_data::frame::Kind::Data
                    && pending.remove(&(f.hdr.src, f.hdr.data_seq)).is_some()
                {
                    t.repaired += 1;
                }
                match feed.on_frame(&mut t.join, b, 0) {
                    Ok(fed) => {
                        t.stored += u64::from(fed.stored);
                        if fed.dropped > 0 {
                            t.errs.push(format!("{} packets dropped", fed.dropped));
                        }
                        if let Some(g) = fed.gap {
                            let now = Instant::now();
                            pending.extend((g.from..=g.to).map(|q| ((g.src, q), now)));
                            for q in g.fetches(256) {
                                if let vyrn_data::frame::Fetch::Range { from, to, .. } = q {
                                    ask(g.src, from, to);
                                }
                            }
                        }
                    }
                    Err(e) => t.errs.push(e.to_string()),
                }
            }
            let now = Instant::now();
            for (&(src, q), at) in pending.iter_mut() {
                if now.duration_since(*at) >= TAP_REASK {
                    ask(src, q, q);
                    *at = now;
                }
            }
        }
        // The runs never repaired, per box.
        let mut run: Option<(u8, u64, u64)> = None;
        for &(src, q) in pending.keys().chain([&(u8::MAX, u64::MAX)]) {
            run = match run {
                Some((s, a, b)) if s == src && b.checked_add(1) == Some(q) => Some((s, a, q)),
                r => {
                    if let Some((s, a, b)) = r {
                        t.errs
                            .push(format!("gap {a}..={b} of box {s} not repaired"));
                    }
                    Some((src, q, q))
                }
            };
        }
        t
    })
}

/// What the tap's order repair did (R17): Nacks sent, holes given up, `NackTooOld`s received,
/// and frames that only a retransmit delivered.
#[derive(Default)]
struct TapRepair {
    nacks: u64,
    gaps: u64,
    too_old: u64,
    repaired: u64,
}

/// The order frames the tap received, until `stop`, in `frame_seq` order. With `nack` (the
/// box's CTRL, and the port the box has for the tap) the tap repairs its holes as a path-A replica does (R17, 07 §4.10); without it
/// the frames stay in arrival order.
fn tap(
    sock: UdpSocket,
    nack: Option<(SocketAddrV4, u16)>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<(Vec<Vec<u8>>, TapRepair)> {
    use vyrn_log::frame::{FrameFlags, FrameHeader};
    use vyrn_log::nack::{Nack, NackTooOld};
    use vyrn_replica::paths::{Ask, Repair};
    std::thread::spawn(move || {
        let mut frames = Vec::new();
        let mut st = TapRepair::default();
        let mut buf = [0u8; 65536];
        let mut paths = nack.map(|_| vyrn_replica::Paths::new(BookId(BOOK), 0, 1).one_path());
        if paths.is_some() {
            // Poll the holes often enough for the DEV hole wait.
            let _ = sock.set_read_timeout(Some(Duration::from_millis(1)));
        }
        let timers = Repair {
            hole_wait_ns: REP_DEV_HOLE_WAIT_US.saturating_mul(1000),
            retry_ns: REP_DEV_RETRY_US.saturating_mul(1000),
            tries: 8,
        };
        let t0 = Instant::now();
        let mut asks = Vec::new();
        while !stop.load(Ordering::Acquire) {
            let got = sock.recv(&mut buf).ok().and_then(|k| buf.get(..k));
            let (Some(ps), Some((to, port))) = (paths.as_mut(), nack) else {
                frames.extend(got.map(<[u8]>::to_vec));
                continue;
            };
            let now = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
            if let Some(f) = got {
                if let Some(t) = NackTooOld::decode(f) {
                    st.too_old = st.too_old.saturating_add(1);
                    ps.too_old(t.path, t.epoch16, t.tenure, t.stream, t.oldest_seq);
                } else {
                    ps.rx_at(vyrn_replica::Path::A, f, now, &mut |d: &[u8], _| {
                        let rtx = FrameHeader::parse(d)
                            .is_ok_and(|(h, _)| h.flags & FrameFlags::RETRANSMIT != 0);
                        st.repaired = st.repaired.saturating_add(u64::from(rtx));
                        frames.push(d.to_vec());
                    });
                }
            }
            asks.clear();
            ps.poll(now, &timers, false, &mut asks);
            for a in &asks {
                match *a {
                    Ask::Nack {
                        path,
                        key,
                        from,
                        to: last,
                    } => {
                        let n = Nack {
                            path,
                            epoch16: key.0,
                            tenure: key.1,
                            stream: key.3,
                            port,
                            from_seq: from,
                            to_seq: last,
                        };
                        st.nacks = st.nacks.saturating_add(1);
                        // UDP: a lost Nack is asked again at the next retry.
                        let _ = sock.send_to(&n.encode(), to);
                    }
                    Ask::Gap { .. } => st.gaps = st.gaps.saturating_add(1),
                }
            }
        }
        (frames, st)
    })
}

/// A UDP relay to `127.0.0.1:port` that drops the datagrams `drop` picks by their 1-based
/// count and bytes, until `stop`: `--keyed` (R7) drops every `LOSS_EVERY`-th,
/// `--drop-path-b`/`--drop-path-a` (R12, R14) one, and `--drop-rtx` also every retransmit.
/// `port` may be set after the relay starts (0 drops), so a node's config can name the relay
/// before the node has bound its own port. Returns its address and, on join, how many it
/// dropped.
fn relay(
    port: Arc<std::sync::atomic::AtomicU16>,
    drop: fn(u64, u64, &[u8]) -> bool,
    arg: u64,
    stop: Arc<AtomicBool>,
) -> Result<(SocketAddr, std::thread::JoinHandle<u64>), String> {
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| e.to_string())?;
    let addr = sock.local_addr().map_err(|e| e.to_string())?;
    let h = std::thread::spawn(move || {
        let (mut n, mut dropped) = (0u64, 0u64);
        let mut buf = [0u8; 65536];
        while !stop.load(Ordering::Acquire) {
            if let Ok(k) = sock.recv(&mut buf) {
                n += 1;
                let b = buf.get(..k).unwrap_or_default();
                let to = port.load(Ordering::Acquire);
                if to == 0 || drop(n, arg, b) {
                    dropped += 1;
                } else {
                    let _ = sock.send_to(b, ("127.0.0.1", to));
                }
            }
        }
        dropped
    });
    Ok((addr, h))
}

/// The responses the client received, with their receive times, until `stop`, unchecked.
/// A `DataRedirect` (04 §7.6) that opens under a session's `K_seq` goes to `redirects` instead
/// (R13, DR1).
fn client(
    sock: UdpSocket,
    stop: Arc<AtomicBool>,
    keys: BTreeMap<u32, [u8; 16]>,
    redirects: Sender<Redirect>,
) -> std::thread::JoinHandle<Vec<(Instant, Vec<u8>)>> {
    std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Acquire) {
            if let Ok(k) = sock.recv(&mut buf) {
                let b = buf.get(..k).unwrap_or_default();
                let r = (k == vyrn_data::redirect::BYTES
                    && b.get(..2) == Some(&vyrn_data::redirect::MAGIC.to_le_bytes()[..]))
                // The session (bytes 8..12) picks its key: one tag check, not one per session
                // (R15's 2 000 sessions would fall behind a burst of redirects).
                .then(|| {
                    let s = b
                        .get(8..12)
                        .and_then(|x| x.try_into().ok())
                        .map(u32::from_le_bytes);
                    keys.get(&s?).and_then(|key| Redirect::open(b, key).ok())
                })
                .flatten();
                match r {
                    Some(r) => {
                        let _ = redirects.send(r);
                    }
                    None => got.push((Instant::now(), b.to_vec())),
                }
            }
        }
        got
    })
}

/// The box's DEV engine (R2), with the sessions open and funded.
fn replay_all(
    sessions: &[Sess],
    data: DataJoin,
    blocks: &[BlockInputs<LANES>],
    dc: Option<&DcConfig>,
) -> Result<(Vec<Hash>, Vec<Resp>, DcRecs), String> {
    let n = u8::try_from(LANES).map_err(|e| e.to_string())?;
    let (tick_min, tick_max) = (Tick(TICK_MIN), Tick(TICK_MAX));
    let book = BookId(BOOK);
    let spec = BookSpec::new(1, tick_min, tick_max, 10_000).ok_or("tick range")?;
    let bbo = Bbo::new(vyrn_bbo::Config {
        n_lanes: n,
        epoch: Epoch(0),
        slot_cap: usize::try_from(SLOT_CAP).map_err(|e| e.to_string())?,
        seg_cap: SLOT_CAP,
        win_center: Tick(WIN_CENTER),
        phase: Phase::Continuous,
        tick_min,
        tick_max,
        band_half: 0,
        band_hyst: 0,
        band_ref: Tick(WIN_CENTER),
        pool: 0,
    });
    let arena = ArenaConfig {
        slot_cap: SLOT_CAP,
        seg_cap: SLOT_CAP,
        tick_min,
        tick_max,
        accounts: u32::try_from(NA).map_err(|e| e.to_string())?,
        journal: SLOT_CAP,
    };
    let lanes: Vec<_> = (0..n)
        .map(|l| vyrn_lane::Config {
            lane: LaneId(l),
            n_lanes: n,
            epoch: Epoch(0),
            book,
            spec,
            path: PathTable::spec(),
            fwd_deadline_ns: vyrn_lane::lane::FWD_DEADLINE_NS,
            phase: Phase::Continuous,
            out_cap: 4096,
        })
        .collect();
    let vis = Hw;
    let mut shared =
        Shared::new(&vis, LANES, arena, &bbo.initial_snapshot()).ok_or("engine shape")?;
    let mut engine: Engine<'_, Hw, NA> =
        Engine::new(&vis, &mut shared, bbo, &lanes, |cfg, aw, ports| {
            let mut acct = AcctRisk::new(AccountId(1), AccountId(1));
            acct.max_open_orders = 1000;
            Lane::<Hw, NA>::new(cfg, aw, ports, acct)
        })
        .ok_or("engine lanes")?;
    for s in sessions {
        let lane = engine.lane_mut(usize::from(s.lane)).ok_or("lane")?;
        let (_, bal) = lane.account_mut(AcctSlot(s.acct)).ok_or("account")?;
        bal.quote_free = u128::from(QUOTE);
        bal.base_free = BASE;
        let ok = lane.open_session(&SessionSpec {
            id: s.id,
            acct: AcctSlot(s.acct),
            k_seq: s.k_seq,
            book,
            buckets: SessionBuckets::default(),
        });
        if !ok {
            return Err(format!("session {:?} did not open", s.id));
        }
    }
    let sink = TapSink {
        resp: Collect::default(),
        dc: dc.map(|c| {
            SinkStream::with_tap(
                book,
                Epoch(0),
                LANES,
                NoPackets,
                DropCopy::new(c, Vec::new()),
            )
        }),
    };
    let mut rep = RustReplay::new(engine, data, NoResponses, sink);
    let mut hashes = Vec::new();
    for b in blocks {
        let h = b.header.height.0;
        rep.payloads_mut()
            .check(b)
            .map_err(|e| format!("height {h}: data join: {e:?}"))?;
        if let (p, TapSink { dc: Some(d), .. }) = rep.payloads_and_sink() {
            d.prepare(b, p);
        }
        let out = rep.replay_block(b).map_err(|e| {
            let steps: Vec<String> = b
                .steps
                .iter()
                .map(|m| {
                    format!(
                        "{}:{:?}:l{}#{}:f{}",
                        m.rec.step.0,
                        m.rec.kind,
                        m.rec.src_lane.0,
                        m.rec.src_lane_seq.0,
                        m.rec.flags
                    )
                })
                .collect();
            format!("{} (block steps {})", e.0, steps.join(" "))
        })?;
        hashes.push(out.output_hash);
        rep.release(b.header.height);
    }
    rep.finish().map_err(|e| e.0)?;
    let sink = rep.into_sink();
    let recs = match sink.dc {
        Some(d) => {
            let (_, dc) = d
                .finish_tap()
                .map_err(|e| format!("in-process drop copy: {e:?}"))?;
            dc.into_out()
                .map_err(|e| format!("in-process drop copy: {e:?}"))?
        }
        None => Vec::new(),
    };
    Ok((hashes, sink.resp.0, recs))
}

// ----- the run -----

struct Report(bool);

impl Report {
    fn check(&mut self, name: &str, r: Result<String, String>) {
        match r {
            Ok(d) => println!("CHECK {name} PASS {d}"),
            Err(d) => {
                self.0 = false;
                println!("CHECK {name} FAIL {d}");
            }
        }
    }
    fn skip(name: &str, why: &str) {
        println!("CHECK {name} SKIP {why}");
    }
}

fn seq_config(
    dir: &Path,
    order: &[String],
    order_b: &[String],
    sessions: &[Sess],
    cons: Option<&Cons>,
    repair: Option<u16>,
) -> Result<PathBuf, String> {
    let mut s = format!(
        r#"schema = 1
protocol = 1
role = "seq"
mode = "BASE"
home = "LDN"
book = {BOOK}

[engine]
dedicated = {LANES}
tick_min = {TICK_MIN}
tick_max = {TICK_MAX}
win_center = {WIN_CENTER}
slot_cap = {SLOT_CAP}

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
port_base = 0

[cores]
engine = 2
stream = 4
seal = "count"

[replication]
order = [{}]
order_b = [{}]
block_ms = 5

[keys]
seq = "env:VYRN_E2E_SEQ_SEED"
"#,
        quoted(order),
        quoted(order_b)
    );
    for x in sessions {
        s.push_str(&format!(
            "\n[[dev_session]]\nlane = {}\nslot = {}\naccount = {}\nk_seq = \"{}\"\nk_out = \"{}\"\nquote = {QUOTE}\nbase = {BASE}\n",
            x.lane,
            vyrn_wire::session_slot(x.id),
            x.acct,
            hex(&x.k_seq),
            hex(&x.k_out)
        ));
    }
    if let Some(c) = cons {
        s.push_str(&format!(
            "\n[consensus]\nctrl = \"{}\"\nroster = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\n",
            c.ctrl,
            c.roster.display(),
            c.roster_hash,
            hex(&[0; 32])
        ));
    }
    // --data: `SeqDataReq` (07 §5.5 source 3) on a picked port the validators' configs name.
    if let Some(port) = repair {
        s.push_str(&format!("\n[repair]\nport = {port}\n"));
        if cons.is_some_and(|c| c.seq_fetch_key.is_some()) {
            s.push_str("xchg = \"env:VYRN_E2E_SEQ_XCHG\"\n");
        }
    }
    let p = dir.join("seq.toml");
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

/// `n` free UDP and TCP ports below the kernel's ephemeral range, for the validators' data queues. Ports
/// the kernel hands out (port 0, as every other node binds) never fall there, so a port picked
/// here and released stays free until its validator binds it, whatever starts in between.
fn data_ports(n: usize) -> Result<Vec<u16>, String> {
    let low: u16 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|r| r.split_whitespace().next()?.parse().ok())
        .unwrap_or(32_768);
    let span = low.saturating_sub(20_000).max(1);
    let start = 20_000 + u16::try_from(std::process::id() % u32::from(span)).unwrap_or(0);
    let ports: Vec<u16> = (0..span)
        .map(|k| 20_000 + (start - 20_000 + k) % span)
        .filter(|&p| {
            UdpSocket::bind(("127.0.0.1", p)).is_ok()
                && std::net::TcpListener::bind(("127.0.0.1", p)).is_ok()
        })
        .take(n)
        .collect();
    if ports.len() < n {
        return Err("no free UDP ports below the ephemeral range for the validators".into());
    }
    Ok(ports)
}

/// A validator's config. With `data = Some((fetch, ports, repair))` (`--data`): its data RX
/// queue on `ports[i]`, the vyrn-data node at `fetch` as box 0 (it is destination `i + 1` there;
/// the tap is 0), the other validators as `[[data.peer]]` (voter `j`, data port) and the box's `[repair]` port as
/// `seq_repair` (07 §5.5 sources 2 and 3), and `[replay]` with the sequencer's engine and
/// sessions, so it prints `out=` per block.
#[allow(clippy::too_many_arguments)] // one flag per harness mode
fn validator_config(
    dir: &Path,
    i: usize,
    data: Option<(&[SocketAddrV4], &[u16], u16)>,
    sessions: &[Sess],
    cons: Option<&Cons>,
    hashlag_us: Option<u64>,
    keyed: bool,
    observer: Option<(&Path, SocketAddrV4)>,
    order_b: bool,
    silence_us: Option<u64>,
    repair: Option<Rep>,
) -> Result<PathBuf, String> {
    let key = hex(&vyrn_crypto::ed25519::public_key(&SEQ_SEED));
    let data_port = data.and_then(|(_, ps, _)| ps.get(i).copied()).unwrap_or(0);
    // The vote key resolves only with [consensus]; without it the handle is read and unused.
    let vote = if cons.is_some() {
        "env:VYRN_E2E_VOTE_SEED".to_owned()
    } else {
        format!("dev:validator-{i}")
    };
    let role = if observer.is_some() {
        "observer"
    } else {
        "validator"
    };
    // DEV: a larger hashlag bound, or keyed fetches to peers whose roster keys are unusable
    // (R8: only validator 0 has a real xchg_key), which only a DEV validator sends unsealed.
    let dev = if hashlag_us.is_some() || keyed || silence_us.is_some() || repair.is_some() {
        "dev = true\n"
    } else {
        ""
    };
    let port_b = if order_b { "order_port_b = 0\n" } else { "" };
    let mut s = format!(
        r#"{dev}schema = 1
protocol = 1
role = "{role}"
mode = "BASE"
book = {BOOK}
epoch = 0
lanes = {LANES}

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
order_port = 0
{port_b}data_port = {data_port}

[membership]
seq_keys = ["{key}"]
"#
    );
    match observer {
        Some((ring, ctrl)) => s.push_str(&format!(
            "\n[observer]\nring = \"{}\"\nring_cap = 16777216\nctrl = \"{ctrl}\"\n",
            ring.display()
        )),
        None => s.push_str(&format!("\n[keys]\nvote = \"{vote}\"\n")),
    }
    if let Some((fetch, ports, repair)) = data {
        let fetch = fetch
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let peers = ports
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(j, p)| format!("\n[[data.peer]]\nvoter = {j}\naddr = \"127.0.0.1:{p}\"\n"))
            .collect::<String>();
        s.push_str(&format!(
            "\n[data]\nboxes = [{fetch}]\nme = {}\n{}{}seq_repair = \"127.0.0.1:{repair}\"\n{peers}\n[replay]\ntick_min = {TICK_MIN}\ntick_max = {TICK_MAX}\nwin_center = {WIN_CENTER}\nslot_cap = {SLOT_CAP}\n",
            i + 1,
            if keyed {
                "xchg = \"env:VYRN_E2E_XCHG\"\n"
            } else {
                ""
            },
            silence_us.map_or_else(String::new, |us| format!("silence_us = {us}\n"))
        ));
        if let Some(us) = hashlag_us {
            s.push_str(&format!("hashlag_us = {us}\n"));
        }
        for x in sessions {
            s.push_str(&format!(
                "\n[[replay.session]]\nlane = {}\nslot = {}\naccount = {}\nk_seq = \"{}\"\nquote = {QUOTE}\nbase = {BASE}\n",
                x.lane,
                vyrn_wire::session_slot(x.id),
                x.acct,
                hex(&x.k_seq)
            ));
        }
    }
    if let Some(c) = cons {
        // Finalize votes and certificates go to the box and, with --dropcopy, the observer.
        let observers = std::iter::once(c.ctrl)
            .chain(c.obs)
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "\n[consensus]\nroster = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\nhome = \"LDN\"\nobservers = [{observers}]\ndelta_ms = 500\nstorage = \"{}\"\n",
            c.roster.display(),
            c.roster_hash,
            hex(&[0; 32]),
            dir.join(format!("journal-{i}")).display(),
        ));
    }
    if let Some(rp) = repair {
        // R14: DEV repair timers (07 §4.9's 5 µs and 50 µs need a pinned host).
        s.push_str(&format!(
            "\n[repair]\nnack = \"{}\"\nhole_wait_us = {REP_DEV_HOLE_WAIT_US}\nretry_us = {REP_DEV_RETRY_US}\n",
            rp.nack
        ));
        if let Some(p) = rp.order_as {
            s.push_str(&format!("order_as = {p}\n"));
        }
        if let Some(p) = rp.order_b_as {
            s.push_str(&format!("order_b_as = {p}\n"));
        }
    }
    let p = dir.join(format!("validator-{i}.toml"));
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

/// The vyrn-data DEV config: destination 0 the tap's data socket, then the validators', and
/// every session's `K_seq`.
/// With `keyed` (R7) also `[roster]`: the box derives every requester's `K_fetch` from it.
fn data_config(
    dir: &Path,
    dests: &[String],
    sessions: &[Sess],
    keyed: Option<&Cons>,
    shards: usize,
    src: u8,
) -> Result<PathBuf, String> {
    let dests = dests
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = format!(
        r#"schema = 1
protocol = 1
role = "data"
mode = "BASE"
home = "LDN"
dev = true
src = {src}
books = [{BOOK}]
dests = [{dests}]

[nic]
backend = "kernel_udp"
ip = "127.0.0.1"
ingest_port = 0
fetch_port = 0

[ring]
slots = 65536

[metrics]
listen = "127.0.0.1:0"

[shards]
n = {shards}
"#
    );
    for x in sessions {
        s.push_str(&format!(
            "\n[[session]]\nid = {}\nkey = \"hex:{}\"\n",
            x.id.0,
            hex(&x.k_seq)
        ));
    }
    if let Some(c) = keyed {
        s.push_str(&format!(
            "\n[roster]\nfile = \"{}\"\nroster_hash = \"{}\"\ngenesis_hash = \"{}\"\nepoch = 0\nbox = {src}\nxchg_secret = \"hex:{}\"\n",
            c.roster.display(),
            c.roster_hash,
            hex(&[0; 32]),
            hex(if src == 0 { &BOX_XCHG } else { &BOX1_XCHG })
        ));
    }
    let p = dir.join(format!("data-{src}.toml"));
    std::fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(p)
}

fn run(cli: &Cli) -> Result<bool, String> {
    // R5's HASHLAG exception needs validators that actually report; zero would pass vacuously.
    let n_val = cli.validators.unwrap_or(if cli.finality { 4 } else { 3 });
    if n_val == 0 {
        return Err("--validators must be at least 1".into());
    }
    if cli.dev_hashlag_us.is_some() && !cli.data {
        return Err(
            "--dev-hashlag-us needs --data: hashlag_us sits in the validators' [replay]".into(),
        );
    }
    if cli.keyed && !(cli.data && cli.finality) {
        return Err("--keyed needs --data and --finality: K_fetch comes from the roster".into());
    }
    if cli.dropcopy && !(cli.data && cli.finality) {
        return Err(
            "--dropcopy needs --data and --finality: the observer replays and finalizes".into(),
        );
    }
    if cli.drop_path_b.is_some_and(|n| n == 0) || (cli.drop_path_b.is_some() && !cli.dropcopy) {
        return Err("--drop-path-b needs --dropcopy and N >= 1".into());
    }
    if cli.tap_loss.is_some_and(|n| n < 2) || (cli.tap_loss.is_some() && (!cli.data || cli.keyed)) {
        return Err("--tap-loss needs --data, no --keyed, and N >= 2 (R14)".into());
    }
    if cli.tap_order_loss.is_some_and(|n| n < 2) || (cli.tap_order_loss.is_some() && !cli.finality)
    {
        return Err("--tap-order-loss needs --finality and N >= 2 (R17)".into());
    }
    if cli.drop_rtx && cli.drop_path_b.is_none() {
        return Err("--drop-rtx needs --drop-path-b".into());
    }
    if cli.drop_path_a.is_some_and(|n| n == 0) || (cli.drop_path_a.is_some() && !cli.finality) {
        return Err(
            "--drop-path-a needs --finality (repair Nacks the box's CTRL) and N >= 1".into(),
        );
    }
    if cli.data_shards == 0 || (cli.data_shards > 1 && !cli.data) {
        return Err("--data-shards needs --data and N >= 1".into());
    }
    if cli.dr4_dev && !cli.data_kill {
        return Err("--dr4-dev needs --data-kill (R15)".into());
    }
    if cli.kill_voter && (!cli.finality || n_val < 4 || cli.data_kill) {
        return Err(
            "--kill-voter needs --finality, at least 4 validators (f >= 1) and no --data-kill (R16)"
                .into(),
        );
    }
    if cli.restart_immediate && !cli.restart_voter {
        return Err("--restart-immediate needs --restart-voter (R17)".into());
    }
    if cli.restart_voter && (!cli.kill_voter || cli.two_path) {
        return Err("--restart-voter needs --kill-voter and no --two-path (R17)".into());
    }
    if cli.data_kill && !cli.keyed {
        return Err("--data-kill needs --keyed: the REDIRECTs it checks are sealed (R13)".into());
    }
    let wait = Duration::from_secs(cli.wait_s);
    let bin_dir = match &cli.bin_dir {
        Some(d) => d.clone(),
        None => std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("binary directory")?
            .to_path_buf(),
    };
    let (sessions, pkts) = workload(cli)?;
    println!(
        "WORKLOAD packets={} sessions={} seed={} rate={}",
        pkts.len(),
        sessions.len(),
        cli.seed,
        cli.rate
    );
    let dir = std::env::temp_dir().join(format!("vyrn-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let (tx, rx) = channel();
    let mut nodes = Nodes(Vec::new());
    let timeout = Some(Duration::from_millis(50));
    let stop_tap = Arc::new(AtomicBool::new(false));
    // With --data, each validator's data port (07 §5.4), picked before vyrn-data starts and
    // outside the ephemeral range, so no node's port-0 bind can take it meanwhile.
    // With --finality also each validator's TCP repl port and the box's CTRL port, from the
    // same range in one pick, so no two picks overlap.
    // With --data also the box's `[repair]` port (07 §5.5 source 3), last of the data picks.
    // With --dropcopy also the observer's data and CTRL ports and vyrn-dropcopy's TCP port.
    let want = if cli.data { n_val + 1 } else { 0 }
        + if cli.finality { n_val + 1 } else { 0 }
        + if cli.dropcopy { 3 } else { 0 };
    let mut picked = data_ports(want)?;
    let val_data: Vec<u16> = if cli.data {
        picked.drain(..n_val).collect()
    } else {
        Vec::new()
    };
    let seq_repair = if cli.data {
        Some(picked.remove(0))
    } else {
        None
    };
    let dc_ports: Vec<u16> = if cli.dropcopy {
        picked.drain(..3).collect()
    } else {
        Vec::new()
    };
    let lo = |p: u16| SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, p);
    let obs_ctrl = dc_ports.get(1).map(|p| lo(*p));
    let cons = if cli.finality {
        let mut c = Cons::new(&dir, &picked, cli.keyed, if cli.data_kill { 2 } else { 1 })?;
        c.obs = obs_ctrl;
        Some(c)
    } else {
        None
    };
    let dc_cfg = cli.dropcopy.then(|| dropcopy::dc_config(&sessions));
    let ring = dir.join("dc.ring");
    // --data: a vyrn-data node takes copy 2 from the client and fans DATA frames out to the
    // tap's data socket and every validator's data port (07 §5.1, §5.2). It starts first, so
    // the validators' configs can name its fetch address; their data ports are picked here.
    let mut relay_h = None;
    let mut tap_relay_h = None;
    let data_node = if cli.data {
        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        sock.set_read_timeout(timeout).map_err(|e| e.to_string())?;
        let mut dests = vec![sock.local_addr().map_err(|e| e.to_string())?.to_string()];
        // R14: the tap's frames go through a lossy relay.
        if let (Some(every), Some(d)) = (cli.tap_loss, dests.first_mut()) {
            let port = sock.local_addr().map_err(|e| e.to_string())?.port();
            let (addr, h) = relay(
                Arc::new(std::sync::atomic::AtomicU16::new(port)),
                |n, every, _| n.is_multiple_of(every),
                every,
                Arc::clone(&stop_tap),
            )?;
            *d = addr.to_string();
            tap_relay_h = Some(h);
        }
        dests.extend(val_data.iter().map(|p| format!("127.0.0.1:{p}")));
        // --keyed (R7): validator 0's frames go through the lossy relay.
        if cli.keyed
            && let (Some(d), Some(&p)) = (dests.get_mut(1), val_data.first())
        {
            let (addr, h) = relay(
                Arc::new(std::sync::atomic::AtomicU16::new(p)),
                |n, every, _| n.is_multiple_of(every),
                LOSS_EVERY,
                Arc::clone(&stop_tap),
            )?;
            *d = addr.to_string();
            relay_h = Some(h);
        }
        // The observer is the last destination (its `[data] me`).
        dests.extend(dc_ports.first().map(|p| format!("127.0.0.1:{p}")));
        let keyed = cons.as_ref().filter(|_| cli.keyed);
        // R13: with --data-kill a backup box (`src = 1`) with the same destinations.
        let mut boxes = Vec::new();
        for src in 0..if cli.data_kill { 2u8 } else { 1 } {
            let cfg = data_config(&dir, &dests, &sessions, keyed, cli.data_shards, src)?;
            let mut c = command(&bin_dir.join("vyrn-data"), cli.seq_cpus.as_deref());
            c.arg("--config").arg(cfg).arg("--stop-on-stdin-eof");
            let name = format!("vyrn-data-{src}");
            let i = nodes.spawn(&name, &mut c, &tx)?;
            nodes.wait(&rx, Instant::now() + wait, &format!("{name} READY"), |ns| {
                ns.get(i)
                    .is_some_and(|n| line(n, "READY vyrn-data ").is_some())
            })?;
            let addr = |k: &str| -> Result<SocketAddrV4, String> {
                nodes
                    .0
                    .get(i)
                    .and_then(|n| line(n, "READY vyrn-data "))
                    .and_then(|l| field(l, k))
                    .ok_or(format!("{name} READY has no {k}="))?
                    .parse()
                    .map_err(|e| format!("{name} {k} address: {e}"))
            };
            boxes.push(DataBoxNode {
                idx: i,
                ingest: addr("ingest")?,
                fetch: addr("fetch")?,
            });
        }
        // Read from now on: the node heartbeats every destination while the validators start,
        // and an unread socket would overflow and drop the first DATA frames.
        // R14: unkeyed boxes take the tap's plain RANGE fetches; a keyed box would count them
        // in fetch_unauth (R7, R11), so under --keyed a tap gap is not repaired.
        let fetch = if cli.keyed {
            Vec::new()
        } else {
            boxes.iter().map(|b| b.fetch).collect()
        };
        let n = u8::try_from(boxes.len()).map_err(|e| e.to_string())?;
        Some((boxes, data_tap(sock, n, fetch, Arc::clone(&stop_tap))))
    } else {
        None
    };
    let box_fetch: Vec<SocketAddrV4> = data_node
        .as_ref()
        .map_or_else(Vec::new, |(bs, _)| bs.iter().map(|b| b.fetch).collect());
    let silence_us = cli.data_kill.then_some(KILL_SILENCE_US);

    // R14: relays in front of validator 0's path A (--drop-path-a) and the observer's path B
    // (--drop-path-b), bound now so the nodes' `[repair]` can name them; their targets are set
    // once the nodes print their ports.
    let stop_relay = Arc::new(AtomicBool::new(false));
    let relay_for = |k: Option<u64>, rtx: bool| -> Result<_, String> {
        let Some(k) = k else { return Ok(None) };
        let port = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let drop: fn(u64, u64, &[u8]) -> bool = if rtx {
            |n, k, b| n == k || b.get(16).is_some_and(|f| f & 2 != 0)
        } else {
            |n, k, _| n == k
        };
        let (addr, h) = relay(Arc::clone(&port), drop, k, Arc::clone(&stop_relay))?;
        Ok(Some((addr, port, h)))
    };
    let relay_a = relay_for(cli.drop_path_a, false)?;
    let relay_b = relay_for(cli.drop_path_b, cli.drop_rtx)?;
    let rep_of = |a: Option<&(SocketAddr, _, _)>, b: Option<&(SocketAddr, _, _)>| {
        cons.as_ref().map(|c| Rep {
            nack: c.ctrl,
            order_as: a.map(|x| x.0.port()),
            order_b_as: b.map(|x| x.0.port()),
        })
    };

    let mut vals: Vec<usize> = (0..n_val)
        .map(|i| {
            let data = data_node
                .as_ref()
                .zip(seq_repair)
                .map(|(_, r)| (&box_fetch[..], &val_data[..], r));
            let keyed = cli.keyed && i == 0;
            let cfg = validator_config(
                &dir,
                i,
                data,
                &sessions,
                cons.as_ref(),
                cli.dev_hashlag_us,
                keyed,
                None,
                cli.two_path,
                silence_us,
                rep_of(relay_a.as_ref().filter(|_| i == 0), None),
            )?;
            let mut c = command(
                &bin_dir.join("vyrn-validator"),
                cli.validator_cpus.as_deref(),
            );
            // A first start: the journal in the run's directory is empty (`--fresh`).
            c.arg("--config")
                .arg(cfg)
                .arg("--stop-on-stdin-eof")
                .arg("--fresh")
                .env("VYRN_E2E_VOTE_SEED", hex(&vote_seed(i)))
                .env("VYRN_E2E_XCHG", hex(&XCHG_SEED));
            nodes.spawn(&format!("validator-{i}"), &mut c, &tx)
        })
        .collect::<Result<_, String>>()?;
    // --dropcopy: the observer, data destination `n_val + 1`, in the box's order list too.
    let obs = match (&data_node, dc_ports.first(), obs_ctrl) {
        (Some(_), Some(port), Some(ctrl)) => {
            // Its data port is `ports[n_val]`; the validators are its `[[data.peer]]`s.
            let ports: Vec<u16> = val_data.iter().copied().chain([*port]).collect();
            let cfg = validator_config(
                &dir,
                n_val,
                Some((&box_fetch[..], &ports[..], seq_repair.ok_or("seq_repair")?)),
                &sessions,
                cons.as_ref(),
                // The observer's DEV bound (R5): the voters' unless --obs-hashlag-us sets it.
                cli.dev_hashlag_us
                    .map(|us| cli.obs_hashlag_us.unwrap_or(us)),
                false,
                Some((&ring, ctrl)),
                true,
                silence_us,
                rep_of(None, relay_b.as_ref()),
            )?;
            let mut c = command(
                &bin_dir.join("vyrn-validator"),
                cli.validator_cpus.as_deref(),
            );
            c.arg("--config").arg(cfg).arg("--stop-on-stdin-eof");
            Some(nodes.spawn("observer", &mut c, &tx)?)
        }
        _ => None,
    };
    let dc_addr = dc_ports.get(2).map(|p| lo(*p));
    if let Some(addr) = dc_addr {
        let cfg = dropcopy::server_config(&dir, addr, &sessions)?;
        let mut c = command(
            &bin_dir.join("vyrn-dropcopy"),
            cli.validator_cpus.as_deref(),
        );
        c.arg("--config").arg(cfg).arg("--ring").arg(&ring);
        nodes.spawn("vyrn-dropcopy", &mut c, &tx)?;
    }
    let deadline = Instant::now() + wait;
    nodes.wait(&rx, deadline, "validators READY", |ns| {
        vals.iter().chain(&obs).all(|&i| {
            ns.get(i)
                .is_some_and(|n| line(n, "READY vyrn-validator order=").is_some())
        })
    })?;
    // A relay in front of a node: the box sends to the relay, which forwards to the node.
    let via = |i: usize,
               prefix: &str,
               r: Option<&(SocketAddr, Arc<std::sync::atomic::AtomicU16>, _)>|
     -> Result<Option<String>, String> {
        let Some(a) = nodes.0.get(i).and_then(|n| line(n, prefix)) else {
            return Ok(None);
        };
        Ok(Some(match r {
            Some((addr, port, _)) => {
                let to: SocketAddrV4 = a.parse().map_err(|e| format!("{prefix}{a}: {e}"))?;
                port.store(to.port(), Ordering::Release);
                addr.to_string()
            }
            None => a.to_owned(),
        }))
    };
    let mut order = Vec::new();
    // Path B (R12): every replica that printed ORDER_B; with --drop-path-b the observer's goes
    // through a relay that drops one datagram (R14: and with --drop-rtx every retransmit).
    let mut order_b = Vec::new();
    for &i in vals.iter().chain(&obs) {
        let ra = relay_a.as_ref().filter(|_| vals.first() == Some(&i));
        order.extend(via(i, "READY vyrn-validator order=", ra)?);
        let rb = relay_b.as_ref().filter(|_| obs == Some(i));
        order_b.extend(via(i, "ORDER_B order=", rb)?);
    }

    let tap_sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let tap_port = tap_sock.local_addr().map_err(|e| e.to_string())?.port();
    tap_sock
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    // R17: --tap-order-loss puts a lossy relay in front of the tap's order socket; the box
    // knows the tap by the relay's address.
    let tap_order_relay = match cli.tap_order_loss {
        Some(every) => Some(relay(
            Arc::new(std::sync::atomic::AtomicU16::new(tap_port)),
            |n, every, _| n.is_multiple_of(every),
            every,
            Arc::clone(&stop_tap),
        )?),
        None => None,
    };
    let tap_as = tap_order_relay.as_ref().map_or(tap_port, |(a, _)| a.port());
    order.push(format!("127.0.0.1:{tap_as}"));
    let cl_sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let cl_port = cl_sock.local_addr().map_err(|e| e.to_string())?.port();
    cl_sock
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    let cl_recv = cl_sock.try_clone().map_err(|e| e.to_string())?;

    let cfg = seq_config(&dir, &order, &order_b, &sessions, cons.as_ref(), seq_repair)?;
    let mut c = command(&bin_dir.join("vyrn-seq"), cli.seq_cpus.as_deref());
    c.arg("--config")
        .arg(cfg)
        .arg("--stop-on-stdin-eof")
        .env("VYRN_E2E_SEQ_SEED", hex(&SEQ_SEED))
        .env("VYRN_E2E_SEQ_XCHG", hex(&SEQ_XCHG));
    let seq = nodes.spawn("vyrn-seq", &mut c, &tx)?;
    // R17: the victim's restart needs a sender for its lines.
    let tx_restart = cli.restart_voter.then(|| tx.clone());
    drop(tx);
    let ready = format!("READY vyrn-seq lanes={LANES} rx=");
    nodes.wait(&rx, Instant::now() + wait, "vyrn-seq READY", |ns| {
        ns.get(seq).is_some_and(|n| line(n, &ready).is_some())
    })?;
    let lane_addrs: Vec<SocketAddrV4> = nodes
        .0
        .get(seq)
        .and_then(|n| line(n, &ready))
        .ok_or("READY")?
        .split(',')
        .map(|a| a.parse().map_err(|e| format!("lane address {a}: {e}")))
        .collect::<Result<_, String>>()?;

    let tap_h = tap(
        tap_sock,
        cons.as_ref().map(|c| (c.ctrl, tap_as)),
        Arc::clone(&stop_tap),
    );
    let stop_cl = Arc::new(AtomicBool::new(false));
    let (redir_tx, redir_rx) = channel();
    let cl_h = client(
        cl_recv,
        Arc::clone(&stop_cl),
        sessions.iter().map(|x| (x.id.0, x.k_seq)).collect(),
        redir_tx,
    );
    let stop_dc = Arc::new(AtomicBool::new(false));
    let dc_clients: Vec<_> = dc_addr.map_or_else(Vec::new, |addr| {
        (0..sessions.len())
            .map(|i| dropcopy::client(addr, i, Arc::clone(&stop_dc), Instant::now() + wait))
            .collect()
    });
    let (data_boxes, data_h) = match data_node {
        Some((bs, h)) => (bs, Some(h)),
        None => (Vec::new(), None),
    };
    let data_idx = data_boxes.first().map(|b| b.idx);
    let data_ingest = data_boxes.first().map(|b| b.ingest);
    let backup = data_boxes.get(1);

    // R11, before any packet: validator 0 moves its K_fetch to epoch 1, then the data box and
    // the vyrn-seq box drop epoch 0, so every fetch of the run must be sealed under the
    // re-derived keys.
    let epoch_step = match (cli.keyed, data_boxes.is_empty(), vals.first()) {
        (true, false, Some(&v)) => {
            let bs: Vec<usize> = data_boxes.iter().map(|b| b.idx).chain([seq]).collect();
            Some(rotate_epoch(&mut nodes, &rx, v, &bs, 1, wait))
        }
        _ => None,
    };

    // Send, paced by send_ns. R13 (--data-kill): copy 2 of each session's first
    // `FIRST_COPIES` packets also goes to the backup box (07 §5.7 interim reading), the home box is killed after `kill_at` packets, and
    // a session's first redirect from it (DR2) moves its copy 2 and resends its retained bytes
    // from `resend_from` (DR3).
    let kill_at = backup.map(|_| pkts.len() * 2 / 5);
    // R16 (--kill-voter): at half the packets the client waits for the victim's first FINAL,
    // kills the last validator and resumes, its schedule shifted by the pause; the killed
    // validator's node index and what the box had finalized then.
    let kill_voter_at = cli.kill_voter.then_some(pkts.len() / 2);
    let mut voter_killed: Option<(usize, Option<u64>)> = None;
    let mut barrier_pkt: Option<(u32, u32)> = None;
    // R17: the restarted victim's node index.
    let restart_at = cli.restart_voter.then_some(if cli.restart_immediate {
        pkts.len() / 2
    } else {
        pkts.len() * 3 / 4
    });
    let mut restarted: Option<usize> = None;
    let mut killed = None;
    let mut moved: BTreeMap<SessionId, Redirect> = BTreeMap::new();
    let mut redirects_heard = 0u64;
    let mut resent = 0u64;
    let mut first_sent: BTreeMap<SessionId, usize> = BTreeMap::new();
    // R13 (04 DR4): each packet's send time; the client resends only what it still retains.
    let mut sent_at: Vec<Instant> = Vec::with_capacity(pkts.len());
    // Packets a redirect asked for that the client had discarded: `lost` were sent to the dead
    // home after the kill, so only a resend reaches a live box; `aged` reached the home box
    // before it died. And each session's kill-to-redirect time, split by whether it had sent
    // before the kill (a session that starts later gets its own rounds, 07 §5.7; R15).
    let (mut lost, mut aged) = (0u64, 0u64);
    let mut latency: Vec<(Duration, bool)> = Vec::new();
    let mut apply = |sent: &[Pkt],
                     at: &[Instant],
                     kill: Option<(usize, Instant)>,
                     moved: &mut BTreeMap<SessionId, Redirect>|
     -> u64 {
        let mut n = 0;
        while let Ok(r) = redir_rx.try_recv() {
            redirects_heard += 1;
            let Some(b) = backup else { continue };
            if r.down != 0 || r.to != 1 || moved.contains_key(&r.session) {
                continue;
            }
            moved.insert(r.session, r);
            let now = Instant::now();
            latency.extend(kill.map(|(ki, t)| {
                let live = sent.iter().take(ki).any(|p| p.session == r.session);
                (now.saturating_duration_since(t), live)
            }));
            for (k, p) in sent
                .iter()
                .enumerate()
                .filter(|(_, p)| p.session == r.session && p.pkt_seq >= r.resend_from)
            {
                if at
                    .get(k)
                    .is_none_or(|t| now.saturating_duration_since(*t) > CLIENT_RETAIN)
                {
                    match kill {
                        Some((ki, _)) if k >= ki => lost += 1,
                        _ => aged += 1,
                    }
                    continue;
                }
                // Paced: an unpaced burst of every retained packet overflows the backup's
                // ingest socket on a small host (R13).
                let _ = cl_sock.send_to(&p.bytes, b.ingest);
                std::thread::park_timeout(Duration::from_micros(20));
                n += 1;
            }
        }
        n
    };
    let mut t0 = Instant::now();
    for (k, p) in pkts.iter().enumerate() {
        let at = t0 + Duration::from_nanos(p.send_ns);
        while let Some(d) = at.checked_duration_since(Instant::now()) {
            std::thread::park_timeout(d);
        }
        if kill_at == Some(k) {
            if let Some(n) = data_idx.and_then(|i| nodes.0.get_mut(i)) {
                n.child
                    .kill()
                    .map_err(|e| format!("kill vyrn-data-0: {e}"))?;
            }
            killed = Some((k, Instant::now()));
        }
        if kill_voter_at == Some(k) {
            let paused = Instant::now();
            let victim = vals.last().copied();
            let up = nodes.wait(&rx, paused + wait, "the victim's first FINAL", |ns| {
                victim
                    .and_then(|i| ns.get(i))
                    .is_some_and(|n| !finals(n).is_empty())
            });
            t0 += paused.elapsed();
            if let (Ok(()), Some(i)) = (up, victim) {
                if let Some(n) = nodes.0.get_mut(i) {
                    n.child
                        .kill()
                        .map_err(|e| format!("kill {}: {e}", n.name))?;
                    // Reaped: the victim is dead before packet `k` is sent, so the block that
                    // holds packet `k` was cut after it died (R16's barrier).
                    n.child
                        .wait()
                        .map_err(|e| format!("reap {}: {e}", n.name))?;
                }
                barrier_pkt = Some((p.session.0, p.pkt_seq));
                vals.retain(|&v| v != i);
                // The baseline: what the box had finalized when the victim died, with every
                // line queued by then taken.
                nodes.drain(&rx);
                let at = nodes.0.get(seq).and_then(|n| finals(n).last().copied());
                voter_killed = Some((i, at));
            }
        }
        // R17: the same config, journal and ports, without --fresh. Its ORDER port was
        // ephemeral; the box sends to the one it printed, so it binds that one again.
        if let (true, Some((i, _)), Some(tx)) =
            (restart_at == Some(k), voter_killed, tx_restart.as_ref())
        {
            let v = n_val - 1;
            let order = nodes
                .0
                .get(i)
                .and_then(|n| line(n, "READY vyrn-validator order="))
                .and_then(|a| a.trim().parse::<SocketAddr>().ok())
                .ok_or("the victim's ORDER address")?;
            let cfg = dir.join(format!("validator-{v}.toml"));
            let text = std::fs::read_to_string(&cfg).map_err(|e| e.to_string())?;
            let mut text = text.replacen(
                "order_port = 0\n",
                &format!("order_port = {}\n", order.port()),
                1,
            );
            // R17: its DEV catch-up bound, harness-only; every other replica keeps its own.
            if let (Some(us), Some(r)) = (cli.dev_hashlag_us, cli.restart_hashlag_us) {
                text = text.replacen(
                    &format!("hashlag_us = {us}\n"),
                    &format!("hashlag_us = {r}\n"),
                    1,
                );
            }
            let again = dir.join(format!("validator-{v}-restart.toml"));
            std::fs::write(&again, text).map_err(|e| e.to_string())?;
            let mut c = command(
                &bin_dir.join("vyrn-validator"),
                cli.validator_cpus.as_deref(),
            );
            c.arg("--config")
                .arg(&again)
                .arg("--stop-on-stdin-eof")
                .env("VYRN_E2E_VOTE_SEED", hex(&vote_seed(v)))
                .env("VYRN_E2E_XCHG", hex(&XCHG_SEED));
            let j = nodes.spawn(&format!("validator-{v}r"), &mut c, tx)?;
            vals.push(j);
            restarted = Some(j);
        }
        resent += apply(
            pkts.get(..k).unwrap_or_default(),
            &sent_at,
            killed,
            &mut moved,
        );
        let dst = lane_addrs.get(usize::from(p.lane)).ok_or("lane address")?;
        cl_sock.send_to(&p.bytes, dst).map_err(|e| e.to_string())?;
        sent_at.push(Instant::now());
        // Copy 2 (07 §5.1): the client sends the same bytes to the data node.
        let home = match (moved.contains_key(&p.session), backup) {
            (true, Some(b)) => Some(b.ingest),
            _ => data_ingest,
        };
        if let Some(d) = home {
            // After the kill a send to the dead box may fail; the redirect resends it.
            let r = cl_sock.send_to(&p.bytes, d);
            if killed.is_none() {
                r.map_err(|e| e.to_string())?;
            }
        }
        if let Some(b) = backup
            && home != Some(b.ingest)
            && {
                let n = first_sent.entry(p.session).or_default();
                *n += 1;
                *n <= FIRST_COPIES
            }
        {
            cl_sock
                .send_to(&p.bytes, b.ingest)
                .map_err(|e| e.to_string())?;
        }
    }
    // R13: every session must move; keep applying redirects until it has (or the deadline).
    let moved_wait = if backup.is_some() {
        let until = Instant::now() + wait;
        while moved.len() < sessions.len() && Instant::now() < until {
            resent += apply(&pkts, &sent_at, killed, &mut moved);
            std::thread::park_timeout(Duration::from_millis(5));
        }
        Some(moved.len())
    } else {
        None
    };
    // Let the box take the last packets before it stops; its stop closes the last block.
    let settle = Instant::now() + Duration::from_millis(300);
    while let Some(d) = settle.checked_duration_since(Instant::now()) {
        std::thread::park_timeout(d);
    }
    // --finality: with the box still up (its listener prints FINAL), wait until the box and
    // every validator that did not stop finalize through the box's last block so far. Every
    // line queued during the run is taken first, so the target is the box's last block
    // before its stop, not an early prefix; the block its stop closes is checked against the
    // validators below.
    nodes.drain(&rx);
    let last = |ns: &[Node]| ns.get(seq).and_then(|n| blocks(n).last().map(|b| b.0.0));
    let fin_wait = if cli.finality {
        nodes.wait(
            &rx,
            Instant::now() + wait,
            "FINAL through the last block",
            |ns| {
                let t = last(ns);
                t.is_some()
                    && ns.get(seq).is_some_and(|n| finals(n).last().copied() >= t)
                    && vals.iter().all(|&i| {
                        ns.get(i)
                            .is_some_and(|n| stopped(n).is_some() || finals(n).last().copied() >= t)
                    })
            },
        )
    } else {
        Ok(())
    };
    let fin_target = last(&nodes.0);
    // R8, with the box still up: its keyed `[repair]` answers a sealed KEY fetch, not a plain one.
    // R11: it has moved to epoch 1, so the epoch-0 key is refused too.
    let seq_repair_probe = cons
        .as_ref()
        .and_then(|c| c.seq_fetch_key)
        .map(|(old, new)| {
            probe_seq_repair(
                nodes.0.get(seq).and_then(|n| line(n, "REPAIR addr=")),
                &old,
                &new,
                &pkts,
            )
        });
    let seq_ok = nodes.stop(seq, &rx, Instant::now() + wait)?;
    // The data node flushes its open frames on stop. R13: the home box was killed, so the
    // backup is the one checked.
    let data_check_idx = backup.map(|b| b.idx).or(data_idx);
    // R13: what each validator printed while the backup still ran (it is marked down after).
    nodes.drain(&rx);
    let before_backup_stop: Vec<usize> = vals
        .iter()
        .map(|&i| nodes.0.get(i).map_or(0, |n| n.lines.len()))
        .collect();
    let data_ok =
        data_check_idx.map(|i| nodes.stop(i, &rx, Instant::now() + wait).unwrap_or(false));
    let seq_node = nodes.0.get(seq).ok_or("seq")?;
    let seq_blocks: Vec<(u64, u64, u64)> = blocks(seq_node).into_iter().map(|b| b.0).collect();
    let stats = line(seq_node, "STATS ").unwrap_or("").to_owned();
    let top = seq_blocks.last().map(|b| b.0);

    // Every validator reaches the box's last block (or its deadline passes, reported below).
    let deadline = Instant::now() + wait;
    let reached = nodes.wait(&rx, deadline, "validators at the last block", |ns| {
        vals.iter().all(|&i| {
            ns.get(i)
                .is_some_and(|n| stopped(n).is_some() || blocks(n).last().map(|b| b.0.0) >= top)
        })
    });
    // --finality: the block the box's stop closed is not in its own FINAL target, so the
    // validators still running finalize through it too, unless HASHLAG stops left no quorum
    // (R6, checked below).
    // Q of the whole committee: R16's killed validator still counts in n.
    let q = n_val - (n_val - 1) / 3;
    let fin_tail = if cli.finality {
        nodes.wait(
            &rx,
            Instant::now() + wait,
            "validator FINAL through the last block",
            |ns| {
                let up: Vec<&Node> = vals.iter().filter_map(|&i| ns.get(i)).collect();
                up.iter().filter(|n| stopped(n).is_none()).count() < q
                    || up
                        .iter()
                        .all(|n| stopped(n).is_some() || finals(n).last().copied() >= top)
            },
        )
    } else {
        Ok(())
    };
    // --dropcopy: the observer replays and finalizes through the last block, then every
    // client stream ends in a DC_FINAL (10 §8.4 item 7); only then does it stop.
    let obs_wait = match obs {
        // R12: the observer holds the block whose frame path B lost; nothing drains.
        Some(o) if cli.drop_rtx => {
            let r = nodes.wait(&rx, Instant::now() + wait, "observer DURABLE_WAIT", |ns| {
                ns.get(o).is_some_and(|n| {
                    stopped(n).is_some() || line(n, "DURABLE_WAIT height=").is_some()
                })
            });
            let ok = nodes.stop(o, &rx, Instant::now() + wait).unwrap_or(false);
            Some(r.map(|()| ok))
        }
        Some(o) => {
            let r = nodes.wait(
                &rx,
                Instant::now() + wait,
                "observer FINAL through the last block",
                |ns| {
                    ns.get(o).is_some_and(|n| {
                        stopped(n).is_some()
                            || (blocks(n).last().map(|b| b.0.0) >= top
                                && finals(n).last().copied() >= top)
                    })
                },
            );
            let ok = nodes.stop(o, &rx, Instant::now() + wait).unwrap_or(false);
            // The ring is complete once the observer stops; give vyrn-dropcopy time to apply
            // it, then wait for every stream to drain (`dropcopy::settled`).
            let since = Instant::now() + Duration::from_millis(300);
            let got: Vec<dropcopy::Got> = dc_clients.iter().map(|c| Arc::clone(&c.0)).collect();
            let until = Instant::now() + wait;
            while r.is_ok() && !dropcopy::settled(&got, since) && Instant::now() < until {
                std::thread::park_timeout(Duration::from_millis(20));
            }
            let r = r.and_then(|()| {
                if dropcopy::settled(&got, since) {
                    Ok(())
                } else {
                    Err("drain timeout: a drop-copy stream did not report every record read".into())
                }
            });
            Some(r.map(|()| ok))
        }
        None => None,
    };
    stop_dc.store(true, Ordering::Release);
    stop_relay.store(true, Ordering::Release);
    let pathb_dropped = relay_b.map(|r| r.2.join().unwrap_or(0));
    let patha_dropped = relay_a.map(|r| r.2.join().unwrap_or(0));
    let mut dc_got = Vec::new();
    let mut dc_errs = Vec::new();
    for (g, h) in dc_clients {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => dc_errs.push(e),
            Err(_) => dc_errs.push("drop-copy client panicked".into()),
        }
        dc_got.push(g);
    }
    let mut val_ok = Vec::new();
    for &i in &vals {
        val_ok.push(nodes.stop(i, &rx, Instant::now() + wait).unwrap_or(false));
    }
    // Read while the client's socket is still open (it closes with its thread).
    let cl_drops = udp_drops(cl_port);
    let cl_drops_s = cl_drops.map_or_else(|| "n/a".to_owned(), |d| d.to_string());
    // R17: the frames lost before the tap's thread read them: its socket's drops, and with
    // --tap-order-loss the relay's socket drops too (the relay's own drops are added below).
    let tap_drops = udp_drops(tap_port).and_then(|d| match &tap_order_relay {
        Some((a, _)) => udp_drops(a.port()).map(|r| d.saturating_add(r)),
        None => Some(d),
    });
    let tap_drops_s = tap_drops.map_or_else(|| "n/a".to_owned(), |d| d.to_string());
    stop_tap.store(true, Ordering::Release);
    stop_cl.store(true, Ordering::Release);
    let (frames, tap_rep) = tap_h.join().map_err(|_| "tap thread")?;
    let tap_order_dropped = match tap_order_relay {
        Some((_, h)) => Some(h.join().map_err(|_| "tap order relay thread")?),
        None => None,
    };
    let mut data_frames = match data_h {
        Some(h) => Some(h.join().map_err(|_| "data tap thread")?),
        None => None,
    };
    let tap_dropped = match tap_relay_h {
        Some(h) => Some(h.join().map_err(|_| "tap relay thread")?),
        None => None,
    };
    let relay_dropped = match relay_h {
        Some(h) => Some(h.join().map_err(|_| "relay thread")?),
        None => None,
    };
    // The tap's join: DATA frames through DataFeed with --data, else copy 2 in process (R3).
    let (mut join, feed_errs, fed_stored) = match data_frames.as_mut() {
        Some(t) => (
            std::mem::take(&mut t.join),
            std::mem::take(&mut t.errs),
            t.stored,
        ),
        None => {
            let mut join = DataJoin::default();
            for p in &pkts {
                join.put(p.session, p.pkt_seq, p.bytes.clone());
            }
            (join, Vec::new(), 0)
        }
    };
    let got = cl_h.join().map_err(|_| "client thread")?;

    let mut rep = Report(true);
    let field_n = |k: &str| field(&stats, k).and_then(|v| v.parse::<u64>().ok());
    rep.check("seq", {
        let records = field_n("records");
        let sv = field_n("seal_violations");
        if !seq_ok {
            Err(format!("exit status not 0: {stats}"))
        } else if records < Some(pkts.len() as u64) {
            // `records` also counts Advance records, so it is at least the packets sent.
            Err(format!(
                "records {records:?} < {} packets sent: {stats}",
                pkts.len()
            ))
        } else if sv != Some(0) {
            Err(stats.clone())
        } else if seq_blocks.len() < 2 {
            Err(format!("{} blocks", seq_blocks.len()))
        } else if seq_blocks.iter().enumerate().any(|(i, b)| b.0 != i as u64) {
            Err("block heights not contiguous from 0".into())
        } else {
            Ok(stats.clone())
        }
    });

    match epoch_step {
        Some(r) => rep.check("epoch", r),
        None => Report::skip("epoch", "off (enable with --keyed, R11)"),
    }

    match seq_repair_probe {
        Some(r) => rep.check("seq-repair", r),
        None => Report::skip("seq-repair", "off (enable with --keyed, R8)"),
    }

    rep.check("validators", {
        let mut errs = Vec::new();
        if let Err(e) = &reached {
            errs.push(e.clone());
        }
        let mut full = 0usize;
        let mut warns = Vec::new();
        for (&i, ok) in vals.iter().zip(&val_ok) {
            let Some(n) = nodes.0.get(i) else { continue };
            let bs = blocks(n);
            let ids: Vec<_> = bs.iter().map(|b| b.0).collect();
            let fault = stopped(n);
            // R5: on an unpinned DEV machine REP_E_HASHLAG is a scheduling alarm. The blocks
            // before it must still be the box's, in order.
            let lag = fault.is_some_and(|f| f.starts_with("FAULT REP_E_HASHLAG "));
            match fault {
                Some(f) if lag && !cli.strict_hashlag => warns.push(format!("{}: {f}", n.name)),
                Some(f) => errs.push(format!("{}: {f}", n.name)),
                None => {}
            }
            let want = if lag && !cli.strict_hashlag {
                seq_blocks.get(..ids.len()).unwrap_or(&seq_blocks)
            } else {
                &seq_blocks[..]
            };
            if ids == seq_blocks {
                full += 1;
            } else if ids != want {
                errs.push(format!(
                    "{}: {} blocks, the box {}; first differs at {:?}",
                    n.name,
                    ids.len(),
                    seq_blocks.len(),
                    ids.iter().zip(&seq_blocks).position(|(a, b)| a != b)
                ));
            }
            if let Some(b) = bs.iter().find(|b| field(b.1, "verdict") != Some("Valid")) {
                errs.push(format!("{}: {}", n.name, b.1));
            }
            if !ok {
                errs.push(format!("{}: did not stop cleanly", n.name));
            }
        }
        // Without --strict-hashlag every stop counted here is a REP_E_HASHLAG WARN (any other
        // stop or stall is already in errs), and the tap still covers every height (R5).
        if full == 0 && cli.strict_hashlag {
            errs.push("no validator reached the last block".into());
        } else if full == 0 && warns.len() == vals.len() {
            println!(
                "WARN every validator stopped at REP_E_HASHLAG; the replay tap covers heights 0..={} (R5)",
                top.unwrap_or(0)
            );
        }
        for w in &warns {
            println!("WARN {w} (R5: a 1 ms bound on an unpinned DEV machine; --strict-hashlag fails it)");
        }
        if errs.is_empty() {
            Ok(format!(
                "{full} of {} validators through heights 0..={}, {} stopped at REP_E_HASHLAG, all Valid",
                vals.len(),
                top.unwrap_or(0),
                warns.len()
            ))
        } else {
            Err(errs.join("; "))
        }
    });

    // The tap: order core, data join, replay.
    let mut out_hashes: Vec<Hash> = Vec::new();
    // R16: the height of the block holding the first packet sent after the victim was reaped.
    let mut barrier: Option<u64> = None;
    let mut dc_inproc = Vec::new();
    let mut resp_times = Vec::new();
    let mut resp_lost: Vec<(u32, u32)> = Vec::new();
    rep.check(
        "replay",
        (|| {
            let mut core: OrderCore<LANES, View> = OrderCore::new(
                Layout::new(u8::try_from(LANES).map_err(|e| e.to_string())?, 1, 0)
                    .map_err(|e| e.to_string())?,
                View(vyrn_crypto::ed25519::public_key(&SEQ_SEED)),
            )
            .map_err(|e| e.to_string())?;
            let mut ready = Vec::new();
            // R17: only frames the tap's own socket dropped may need a retransmit; without
            // that count, none may.
            let rep_s = format!(
                "tap_sock_drops={tap_drops_s} tap_relay_dropped={} tap_repaired={} tap_nacks={} tap_gaps={} tap_too_old={}",
                tap_order_dropped.map_or_else(|| "n/a".to_owned(), |d| d.to_string()),
                tap_rep.repaired, tap_rep.nacks, tap_rep.gaps, tap_rep.too_old
            );
            let allowed = tap_drops
                .unwrap_or(0)
                .saturating_add(tap_order_dropped.unwrap_or(0));
            if tap_rep.repaired > allowed || tap_rep.gaps > 0 {
                return Err(format!("tap order repair beyond the frames lost to it: {rep_s}"));
            }
            if tap_order_dropped.is_some_and(|d| d == 0 || tap_rep.repaired == 0) {
                return Err(format!("--tap-order-loss: the relay dropped or the tap repaired nothing: {rep_s}"));
            }
            let seq_of = |f: &[u8]| {
                vyrn_log::FrameHeader::parse(f)
                    .ok()
                    .map(|(h, _)| (h.tenure, h.stream, h.frame_seq))
            };
            for (i, f) in frames.iter().enumerate() {
                core.on_frame(f, 0).map_err(|e| {
                    let got = seq_of(f);
                    let prev = frames.get(..i).and_then(|p| {
                        p.iter().rev().filter_map(|g| seq_of(g)).find(|x| {
                            got.is_some_and(|(t, s, _)| (x.0, x.1) == (t, s))
                        })
                    });
                    format!(
                        "tap order core: {e:?} at frame {i} of {}: (tenure, stream, frame_seq) {got:?} after {prev:?}, {rep_s}",
                        frames.len()
                    )
                })?;
                while let Some(b) = core.take_ready() {
                    ready.push(b);
                }
            }
            let ids: Vec<_> = ready
                .iter()
                .map(|b| {
                    (
                        b.header.height.0,
                        b.header.first_step.0,
                        b.header.last_step.0,
                    )
                })
                .collect();
            if ids != seq_blocks {
                return Err(format!(
                    "tap readied {} blocks, the box closed {}",
                    ids.len(),
                    seq_blocks.len()
                ));
            }
            // Every packet sent is sequenced exactly once: Advance records do not count, so a
            // lost client packet cannot hide behind them.
            let mut seen: Vec<(u32, u32)> = ready
                .iter()
                .flat_map(|b| &b.lanes)
                .filter_map(|r| match r {
                    vyrn_log::LaneRec::Pkt(p) if p.flags & PacketFlags::ADVANCE == 0 => {
                        Some((p.session.0, p.pkt_seq))
                    }
                    _ => None,
                })
                .collect();
            barrier = barrier_pkt.and_then(|bp| {
                ready.iter().find_map(|b| {
                    b.lanes
                        .iter()
                        .any(|r| matches!(r, vyrn_log::LaneRec::Pkt(p) if (p.session.0, p.pkt_seq) == bp))
                        .then_some(b.header.height.0)
                })
            });
            seen.sort_unstable();
            let mut sent: Vec<(u32, u32)> = pkts.iter().map(|p| (p.session.0, p.pkt_seq)).collect();
            sent.sort_unstable();
            if seen != sent {
                return Err(format!(
                    "blocks hold {} packet records, {} packets were sent",
                    seen.len(),
                    sent.len()
                ));
            }
            let (hashes, mut replayed, recs) = replay_all(
                &sessions,
                std::mem::take(&mut join),
                &ready,
                dc_cfg.as_ref(),
            )?;
            out_hashes = hashes;
            dc_inproc = recs;
            let mut live: Vec<Resp> = Vec::new();
            for (t, g) in &got {
                let r = Response::parse(g).map_err(|e| format!("response: {e:?}"))?;
                let h = r.header();
                let s = sessions
                    .iter()
                    .find(|s| s.id == h.session())
                    .ok_or("response to an unknown session")?;
                if !r.verify(&s.k_out) {
                    return Err(format!("response tag of {:?}", s.id));
                }
                live.push((
                    h.session.get(),
                    h.resp_seq.get(),
                    h.echo_pkt.get(),
                    r.raw_records().to_vec(),
                ));
                resp_times.push((*t, h.session.get(), h.resp_seq.get()));
            }
            live.sort();
            replayed.sort();
            // R1 (ruled, loopback UDP in DEV): the client's responses must be an in-order,
            // byte-identical subsequence of replay's, missing at most the kernel's drop count
            // for the client's socket; without that count, strict equality.
            let mut rest = replayed.iter();
            let subseq = live.iter().all(|a| rest.any(|b| b == a));
            let shortfall = replayed.len().saturating_sub(live.len());
            let lost_ok = cl_drops.is_some_and(|d| shortfall as u64 <= d);
            if subseq && shortfall > 0 && lost_ok {
                println!(
                    "WARN replay shortfall={shortfall} client_sock_drops={cl_drops_s} of {} responses (R1: lost at the client's socket)",
                    replayed.len()
                );
            } else if live != replayed {
                let at = live.iter().zip(&replayed).position(|(a, b)| a != b);
                let show = |v: &[Resp]| {
                    at.and_then(|i| v.get(i)).map(|(s, q, e, rs)| {
                        let rs: Vec<String> = rs.iter().map(|r| hex(r)).collect();
                        format!("session {s:#x} resp_seq {q} echo {e} [{}]", rs.join(" "))
                    })
                };
                return Err(format!(
                    "responses differ: box sent {}, replay produced {} (subsequence {subseq}, shortfall={shortfall} client_sock_drops={cl_drops_s}); first difference at {at:?}: box {:?}, replay {:?}",
                    live.len(),
                    replayed.len(),
                    show(&live),
                    show(&replayed)
                ));
            }
            // R1: the responses the client's socket dropped, which `dropcopy` may not find.
            resp_lost = replayed
                .iter()
                .filter(|r| !live.contains(r))
                .map(|r| (r.0, r.1))
                .collect();
            let digest = |v: &[Resp]| {
                let mut b = Vec::new();
                for (s, q, e, rs) in v {
                    b.extend_from_slice(&s.to_le_bytes());
                    b.extend_from_slice(&q.to_le_bytes());
                    b.extend_from_slice(&e.to_le_bytes());
                    rs.iter().for_each(|r| b.extend_from_slice(r));
                }
                hex(&vyrn_crypto::hash::hash(&b).0)
            };
            Ok(format!(
                "{} blocks replayed, {} responses equal (shortfall={shortfall} client_sock_drops={cl_drops_s}; {rep_s}), responses digest {}, last output_hash {}",
                ready.len(),
                live.len(),
                digest(&live),
                out_hashes.last().map(|h| hex(&h.0)).unwrap_or_default()
            ))
        })(),
    );

    // Validators that replay print out=<hex>; compare per block.
    let replaying: Vec<&Node> = vals
        .iter()
        .filter_map(|&i| nodes.0.get(i))
        .filter(|n| cli.data || blocks(n).iter().any(|b| field(b.1, "out").is_some()))
        .collect();
    // With --data every validator replays, so this check always runs: a validator with no
    // out= at all, or a REPLAY_FAULT, fails it rather than skipping it.
    if replaying.is_empty() {
        Report::skip(
            "replica-out",
            "no validator prints out= (validators replay only with --data)",
        );
    } else {
        rep.check("replica-out", {
            let bad: Vec<String> = replaying
                .iter()
                .filter_map(|n| {
                    let theirs: Vec<Option<&str>> =
                        blocks(n).iter().map(|b| field(b.1, "out")).collect();
                    let ours: Vec<String> = out_hashes.iter().map(|h| hex(&h.0)).collect();
                    // R5: a validator stopped at REP_E_HASHLAG is compared on the blocks it
                    // printed; any other validator must print every block.
                    let lag = n
                        .lines
                        .iter()
                        .any(|l| l.starts_with("FAULT REP_E_HASHLAG "));
                    let first_bad = theirs
                        .iter()
                        .zip(&ours)
                        .position(|(a, b)| *a != Some(b.as_str()));
                    let short = theirs.len() < ours.len() && !lag;
                    if let Some(f) = n.lines.iter().find(|l| l.starts_with("REPLAY_FAULT ")) {
                        return Some(format!("{}: {f}", n.name));
                    }
                    match first_bad {
                        Some(k) => Some(format!(
                            "{} at block {k} ({} vs tap {})",
                            n.name,
                            theirs.get(k).copied().flatten().unwrap_or("-"),
                            ours.get(k).map_or("-", String::as_str)
                        )),
                        None if short || theirs.len() > ours.len() => Some(format!(
                            "{} printed {} of {} blocks",
                            n.name,
                            theirs.len(),
                            ours.len()
                        )),
                        None => None,
                    }
                })
                .collect();
            if bad.is_empty() && replaying.len() == vals.len() {
                let printed: Vec<String> = replaying
                    .iter()
                    .map(|n| format!("{}={}", n.name, blocks(n).len()))
                    .collect();
                Ok(format!(
                    "{} validators match the tap on every block they printed of {} (R5): {}",
                    vals.len(),
                    out_hashes.len(),
                    printed.join(" ")
                ))
            } else {
                Err(format!(
                    "mismatch or missing out=: {bad:?}, {} of {} replaying",
                    replaying.len(),
                    vals.len()
                ))
            }
        });
    }

    if cli.finality {
        rep.check("finality", {
            let n = vals.len();
            let target = fin_target.unwrap_or(0);
            let val_target = top.unwrap_or(0).max(target);
            let seq_final = nodes.0.get(seq).and_then(|x| finals(x).last().copied());
            let mut errs = Vec::new();
            let mut short = Vec::new();
            let mut lagged = 0usize;
            let mut lag_at: Vec<u64> = Vec::new();
            for &i in &vals {
                let Some(v) = nodes.0.get(i) else { continue };
                match stopped(v) {
                    Some(f) if f.starts_with("FAULT REP_E_HASHLAG ") && !cli.strict_hashlag => {
                        lagged += 1;
                        lag_at.extend(field(f, "height").and_then(|h| h.parse::<u64>().ok()));
                    }
                    // Any other stop already fails `validators`.
                    Some(_) => {}
                    None if finals(v).last().copied() < Some(val_target) => short.push(format!(
                        "{} final {:?}",
                        v.name,
                        finals(v).last()
                    )),
                    None => {}
                }
            }
            // R6: more than n − Q validators stopped at REP_E_HASHLAG leaves no quorum; the
            // box cannot finalize the rest, which is DEV timing, not a fault.
            // With R16's victim counted out, it is still only a HASHLAG stop that excuses this.
            let no_quorum = lagged > 0 && n - lagged < q;
            // R6: quorum held below the (n − Q + 1)-th smallest stop height; when that spans at
            // least two heights, the box must still have finalized from votes, so a broken vote
            // path cannot pass.
            lag_at.sort_unstable();
            let quorum_until = lag_at.get(n.saturating_sub(q)).copied().unwrap_or(target);
            // R6: without quorum the survivors cannot finalize the rest either.
            if !no_quorum {
                errs.append(&mut short);
                if seq_final < Some(target) {
                    errs.push(format!("vyrn-seq final {seq_final:?}"));
                }
            }
            if no_quorum && quorum_until >= 2 && seq_final.is_none() {
                errs.push(format!(
                    "vyrn-seq finalized nothing, though Q validators ran through height {quorum_until}"
                ));
            }
            if !no_quorum {
                errs.extend(fin_wait.as_ref().err().cloned());
                errs.extend(fin_tail.as_ref().err().cloned());
            }
            if no_quorum && errs.is_empty() {
                println!(
                    "WARN {lagged} of {n} validators stopped at REP_E_HASHLAG, below Q = {q}; vyrn-seq finalized through {seq_final:?} of {target} (R6)"
                );
            }
            if errs.is_empty() && no_quorum {
                Ok(format!(
                    "no quorum after HASHLAG stops (R6); vyrn-seq finalized through {seq_final:?} while Q validators ran through {quorum_until}"
                ))
            } else if errs.is_empty() {
                Ok(format!(
                    "vyrn-seq through {target} and {} running validators through {val_target} finalized (Q = {q} of {n_val})",
                    n - lagged
                ))
            } else {
                Err(format!("not finalized through {target}: {}", errs.join(", ")))
            }
        });
    } else {
        Report::skip("finality", "off (enable with --finality)");
    }

    // R16: the killed validator had voted (finalized something), printed no fault (R5's HASHLAG
    // WARN aside) through its EOF, and the blocks it printed were the box's, `Valid`, with the
    // tap's `out=`; the box finalized the barrier block, cut after the victim died, so without it
    // (`finality` checks the end).
    match voter_killed {
        Some((i, at)) => rep.check("voter-kill", {
            // Every line the victim printed, through its reader's EOF mark.
            let eof = nodes.wait(&rx, Instant::now() + wait, "the victim's EOF", |ns| {
                ns.get(i)
                    .is_some_and(|n| n.lines.last().is_some_and(|l| l == EOF_MARK))
            });
            let v = nodes.0.get(i).ok_or("killed validator")?;
            let ids: Vec<_> = blocks(v).into_iter().map(|b| b.0).collect();
            let seq_final = nodes.0.get(seq).and_then(|x| finals(x).last().copied());
            let fault = stopped(v)
                .filter(|f| cli.strict_hashlag || !f.starts_with("FAULT REP_E_HASHLAG "));
            let bad_block = blocks(v).into_iter().zip(0..).find(|(b, k)| {
                field(b.1, "verdict") != Some("Valid")
                    || field(b.1, "out").is_some_and(|o| {
                        out_hashes.get(*k).is_none_or(|h| hex(&h.0) != o)
                    })
            });
            if let Err(e) = eof {
                Err(e)
            } else if let Some(f) = fault {
                Err(format!("{}: {f} before the kill", v.name))
            } else if let Some((b, k)) = bad_block {
                Err(format!("{} block {k}: {} (tap out= {:?})", v.name, b.1, out_hashes.get(k).map(|h| hex(&h.0))))
            } else if finals(v).is_empty() {
                Err(format!(
                    "{} finalized nothing before the kill ({} blocks, vyrn-seq final {at:?})",
                    v.name,
                    ids.len()
                ))
            } else if seq_blocks.get(..ids.len()) != Some(&ids[..]) {
                Err(format!("{}: its {} blocks are not the box's", v.name, ids.len()))
            } else if barrier.is_none() || seq_final < barrier {
                // The barrier block holds a packet sent after the victim was reaped, so it was
                // cut after the victim died: it cannot have voted for it or anything after it.
                // (Neither its last BLOCK line, printed after it may already have voted, nor the
                // box's FINAL lines, read on another thread, are ordered against the kill.)
                Err(format!(
                    "vyrn-seq finalized through {seq_final:?}, not through the barrier block {barrier:?}"
                ))
            } else {
                Ok(format!(
                    "{} killed with vyrn-seq final at {at:?}, no fault, its {} blocks the box's and Valid; {} of {n_val} finalized through {seq_final:?}, past the barrier block {barrier:?} cut after the kill (Q = {q})",
                    v.name,
                    ids.len(),
                    vals.len()
                ))
            }
        }),
        None if cli.kill_voter => rep.check(
            "voter-kill",
            Err("the victim finalized nothing by the deadline at half the packets; not killed".into()),
        ),
        None => Report::skip("voter-kill", "off (enable with --kill-voter, R16)"),
    }

    // R17: the restarted victim started from its own journal (no FRESH_JOURNAL: the guard found
    // it non-empty), and no node, the box included, reported a conflicting vote from its index.
    // `validators`, `replica-out` and `finality` hold it to every block and FINAL through the end.
    match restarted {
        Some(j) => rep.check("voter-restart", {
            let v = n_val - 1;
            let me = format!("voter={v}");
            let faults: Vec<String> = nodes
                .0
                .iter()
                .flat_map(|n| {
                    n.lines
                        .iter()
                        .filter(|l| {
                            l.starts_with("VOTER_FAULT ")
                                && l.split_whitespace().any(|w| w == me)
                        })
                        .map(move |l| format!("{}: {l}", n.name))
                })
                .collect();
            let r = nodes.0.get(j).ok_or("restarted validator")?;
            if r.lines.iter().any(|l| l.starts_with("FRESH_JOURNAL ")) {
                Err(format!("{} started with an empty journal", r.name))
            } else if !faults.is_empty() {
                Err(format!("conflicting votes from voter {v}: {}", faults.join("; ")))
            } else {
                Ok(format!(
                    "{} rejoined from its journal: {} blocks, final {:?}, no VOTER_FAULT naming voter {v} on any node",
                    r.name,
                    blocks(r).len(),
                    finals(r).last()
                ))
            }
        }),
        None => Report::skip("voter-restart", "off (enable with --restart-voter, R17)"),
    }
    // R14: validator 0 lost one path A frame and repair filled it (`finality` above checks it
    // still finalized through the last block).
    match (patha_dropped, vals.first().and_then(|&i| nodes.0.get(i))) {
        (Some(d), Some(n)) => rep.check("repair", repaired(n, d, "validator-0")),
        _ => Report::skip("repair", "off (enable with --drop-path-a, R14)"),
    }
    match (obs, obs_wait) {
        (Some(o), Some(w)) => rep.check("dropcopy", {
            let n = nodes.0.get(o).ok_or("observer")?;
            match (w, stopped(n)) {
                (_, Some(f)) => Err(format!("observer: {f}")),
                (Err(e), None) => Err(e),
                (Ok(false), None) => Err("observer did not stop cleanly".into()),
                (Ok(true), None) if cli.drop_rtx => {
                    durable_hold(n, pathb_dropped.unwrap_or(0), top)
                }
                (Ok(true), None) if pathb_dropped.is_some() && !dc_errs.is_empty() => {
                    Err(dc_errs.join("; "))
                }
                // R14: path B lost one frame and repair filled it: the drop copy is whole.
                (Ok(true), None) if let Some(d) = pathb_dropped => repaired(n, d, "observer")
                    .and_then(|r| {
                        dropcopy::check(&dc_got, &resp_times, &dc_inproc, &resp_lost)
                            .map(|c| format!("{r}; {c}"))
                    }),
                (Ok(true), None) if !dc_errs.is_empty() => Err(dc_errs.join("; ")),
                (Ok(true), None) => dropcopy::check(&dc_got, &resp_times, &dc_inproc, &resp_lost),
            }
        }),
        _ => Report::skip("dropcopy", "off (enable with --dropcopy)"),
    }
    match (data_check_idx, data_ok) {
        (Some(i), Some(ok)) => rep.check("data", {
            let n = nodes.0.get(i).ok_or("data node")?;
            let st = line(n, "STATS ").unwrap_or("").to_owned();
            let stored = field(&st, "stored").and_then(|v| v.parse::<u64>().ok());
            let events: Vec<&String> = n.lines.iter().filter(|l| l.starts_with("EVENT")).collect();
            let mut errs = Vec::new();
            if !ok {
                errs.push(format!("vyrn-data did not stop cleanly: {st}"));
            }
            // R13: the backup stores only what reached it; `replay` checks the join holds every
            // packet.
            if backup.is_none() && stored != Some(pkts.len() as u64) {
                errs.push(format!("stored {stored:?} != {} packets sent", pkts.len()));
            }
            // #120: EVENT lines + events_unprinted + events_dropped = bad_mac + copy conflicts.
            // The client sends one byte-identical copy under the right key, so all are 0.
            for k in ["bad_mac", "events_dropped", "events_unprinted"] {
                if field(&st, k) != Some("0") {
                    errs.push(format!("{k} is {:?}, not 0", field(&st, k)));
                }
            }
            if let Some(e) = events.first() {
                errs.push(format!("{} EVENT lines, first {e}", events.len()));
            }
            // R10: the box ran on the asked shards and no hop ring overflowed.
            let shards = cli.data_shards.to_string();
            if field(&st, "shards") != Some(shards.as_str()) || field(&st, "hop_full") != Some("0") {
                errs.push(format!("--data-shards {shards}: STATS shards/hop_full wrong: {st}"));
            }
            // R7: validator 0 lost frames, and only sealed fetches are served. R11: under its
            // epoch-1 keys, so the box refused none of them. R13: the unkeyed validators' plain
            // REDIRECT_BATCHes reach the keyed backup as bad tags; at most those are refused.
            let unkeyed_batches: u64 = if backup.is_some() {
                vals.iter()
                    .skip(1)
                    .filter_map(|&i| nodes.0.get(i).and_then(|n| line(n, "FAILOVER ")))
                    .filter_map(|l| field(l, "redirect_msgs")?.parse::<u64>().ok())
                    .sum()
            } else {
                0
            };
            let unauth = field(&st, "fetch_unauth").and_then(|v| v.parse::<u64>().ok());
            if relay_dropped.is_some() && unauth.is_none_or(|u| u > unkeyed_batches) {
                errs.push(format!(
                    "--keyed: fetch_unauth is {unauth:?}, above the {unkeyed_batches} plain REDIRECT_BATCHes of the unkeyed validators (R11: validator 0's re-derived K_fetch; R13)"
                ));
            }
            if let Some(dropped) = relay_dropped {
                let served: u64 = ["fetch_ring_hit", "fetch_log_hit", "fetch_resent"]
                    .iter()
                    .filter_map(|k| field(&st, k)?.parse::<u64>().ok())
                    .sum();
                if dropped == 0 || served == 0 {
                    errs.push(format!(
                        "--keyed: the relay dropped {dropped} frames and the box served {served} sealed fetches; both must be > 0"
                    ));
                }
            }
            if !feed_errs.is_empty() {
                errs.push(format!("feed: {}", feed_errs.join(", ")));
            }
            let repaired = data_frames.as_ref().map_or(0, |t| t.repaired);
            if let Some(dropped) = tap_dropped
                && (dropped == 0 || repaired == 0)
            {
                errs.push(format!(
                    "--tap-loss: the relay dropped {dropped} frames and the tap repaired {repaired}; both must be > 0 (R14)"
                ));
            }
            if errs.is_empty() {
                Ok(format!(
                    "vyrn-data stored {} packets, {} data frames (DATA and DATA_HB) fed {fed_stored} packets into the replay join, {repaired} frames repaired by RANGE fetch; {st}",
                    pkts.len(),
                    data_frames.as_ref().map_or(0, |t| t.frames)
                ))
            } else {
                Err(errs.join("; "))
            }
        }),
        _ => Report::skip(
            "data",
            "off (enable with --data; without it the tap joins copy 2 in process and validators do not replay, R3)",
        ),
    }

    // R13: the home box died; Q DataDowns, a sealed REDIRECT admitted by the backup, and every
    // session's copy 2 moved (`replay` and `data` then pass on the backup's frames).
    match (moved_wait, backup) {
        (Some(n_moved), Some(b)) => rep.check("failover", {
            let mut errs = Vec::new();
            let mut votes = Vec::new();
            for (&i, &upto) in vals.iter().zip(&before_backup_stop) {
                let Some(n) = nodes.0.get(i) else { continue };
                let live = n.lines.get(..upto).unwrap_or_default();
                if live.iter().any(|l| l.starts_with("DATA_DOWN box=1 ")) {
                    errs.push(format!("{}: marked the live backup down", n.name));
                }
                if stopped(n).is_some() {
                    continue;
                }
                let dd = line(n, "DATA_DOWN box=0 ");
                let g = |k| dd.and_then(|l| field(l, k)).and_then(|v| v.parse::<u64>().ok());
                match (g("votes"), g("quorum")) {
                    (Some(v), Some(q)) if v >= q => votes.push(format!("{}={v}/{q}", n.name)),
                    _ => errs.push(format!("{}: no DATA_DOWN box=0 at quorum", n.name)),
                }
            }
            // Only validator 0 holds a K_fetch (R7), so its REDIRECTs are the sealed ones.
            let v0 = vals.first().and_then(|&i| nodes.0.get(i));
            let v0_fo = v0.and_then(|n| line(n, "FAILOVER ")).unwrap_or("").to_owned();
            let v0_redirects = field(&v0_fo, "redirects").and_then(|v| v.parse::<u64>().ok());
            if !v0.is_some_and(|n| n.lines.iter().any(|l| l.starts_with("REDIRECT_SENT down=0 to=1 "))) {
                errs.push("validator-0 sent no REDIRECT down=0 to=1".into());
            }
            if v0_redirects.unwrap_or(0) == 0 {
                errs.push(format!("validator-0 FAILOVER {v0_fo}"));
            }
            let st = nodes
                .0
                .get(b.idx)
                .and_then(|n| line(n, "STATS "))
                .unwrap_or("")
                .to_owned();
            let admitted = field(&st, "redirects").and_then(|v| v.parse::<u64>().ok());
            // #194: a redirect a full shard ring refused is retried (`redirect_retried`), and
            // dropped only past its queue (`redirect_dropped`), which R15's burst must not reach.
            if field(&st, "redirect_dropped").is_some_and(|v| v != "0") {
                errs.push(format!("backup redirect_dropped={:?}", field(&st, "redirect_dropped")));
            }
            if admitted.unwrap_or(0) == 0 || field(&st, "redirect_unknown") != Some("0") {
                errs.push(format!(
                    "backup redirects={admitted:?} redirect_unknown={:?}: it must admit a sealed REDIRECT and know every session's source",
                    field(&st, "redirect_unknown")
                ));
            }
            if killed.is_none() {
                errs.push("the home box was not killed".into());
            }
            // 04 DR4: a packet sent to the dead home is recovered only by a resend, so its
            // redirect must arrive while the client still retains it.
            let worst_by = |live: bool| {
                latency
                    .iter()
                    .filter(|l| l.1 == live)
                    .map(|l| l.0)
                    .max()
                    .unwrap_or_default()
            };
            let (worst, worst_late) = (worst_by(true), worst_by(false));
            let n_live = latency.iter().filter(|l| l.1).count();
            if lost > 0 && !cli.dr4_dev {
                errs.push(format!(
                    "{lost} packets sent to the dead home had expired (DR4, {} ms) before their redirect; slowest kill-to-redirect {worst:?}",
                    CLIENT_RETAIN.as_millis()
                ));
            }
            if n_moved != sessions.len() {
                errs.push(format!("{n_moved} of {} sessions moved copy 2", sessions.len()));
            }
            let mut from: Vec<String> = moved
                .values()
                .take(8)
                .map(|r| format!("{:#x}@{}", r.session.0, r.resend_from))
                .collect();
            if moved.len() > from.len() {
                from.push(format!("… {} more", moved.len() - from.len()));
            }
            if errs.is_empty() {
                Ok(format!(
                    "home box killed after {} packets; DATA_DOWN {}; validator-0 sent {} sealed REDIRECTs, the backup admitted and sent {}; the client heard {redirects_heard}, moved {n_moved} sessions (resend_from {}) and resent {resent} packets; DR4 ({} ms{}): slowest kill-to-redirect {worst:?} over the {n_live} sessions live at the kill ({worst_late:?} for those that started later), {lost} lost after the kill, {aged} older ones discarded",
                    killed.map_or(0, |k| k.0),
                    votes.join(" "),
                    v0_redirects.unwrap_or(0),
                    admitted.unwrap_or(0),
                    from.join(" "),
                    CLIENT_RETAIN.as_millis(),
                    if cli.dr4_dev { ", DEV figure, not gating" } else { "" }
                ))
            } else {
                Err(errs.join("; "))
            }
        }),
        _ => Report::skip("failover", "off (enable with --data-kill, R13)"),
    }

    let _ = std::io::stdout().flush();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(rep.0)
}

/// The line that stopped or stalled a validator: a sequencer `FAULT`, `OUT_OF_ORDER` (a stall
/// with no repair), `VOTER_FAULT`, `DATA_FAULT` or `REPLAY_FAULT`.
fn stopped(n: &Node) -> Option<&str> {
    const STOP: [&str; 6] = [
        "FAULT ",
        "OUT_OF_ORDER ",
        "VOTER_FAULT ",
        "DATA_FAULT ",
        "REPLAY_FAULT ",
        "FINALITY_FAULT ",
    ];
    n.lines
        .iter()
        .map(String::as_str)
        .find(|l| STOP.iter().any(|p| l.starts_with(p)))
}

fn vote_seed(i: usize) -> [u8; 32] {
    [u8::try_from(i + 1).unwrap_or(u8::MAX); 32]
}

/// The DEV committee of `--finality`: a BASE roster (08 §9.6) of one home, as in
/// `bin/vyrn-validator/tests/committee.rs` (R4): voters `vote_seed(i)` at pre-picked TCP repl
/// ports, this run's `seq_key` as the primary, a dummy standby; and the box's pre-picked CTRL
/// address, which every validator lists as its observer.
struct Cons {
    /// `--keyed` (R8): validator 0's key to the primary `vyrn-seq` box.
    seq_fetch_key: Option<([u8; 16], [u8; 16])>,
    roster: PathBuf,
    roster_hash: String,
    ctrl: SocketAddrV4,
    /// --dropcopy: the observer's CTRL address.
    obs: Option<SocketAddrV4>,
}

impl Cons {
    /// `ports`: `n` TCP repl ports, then the box's CTRL port (`data_ports`).
    /// `keyed` (R7): validator 0 and data box 0 get real X25519 keys, every other entry none.
    /// `boxes` (R13): the data boxes of the home, each with its own key.
    fn new(dir: &Path, ports: &[u16], keyed: bool, boxes: usize) -> Result<Self, String> {
        let (repl, ctrl) = ports.split_at(ports.len().saturating_sub(1));
        let n = repl.len();
        use vyrn_epoch::{Addr, DataBox, Domain, Home, Roster, SeqEntry, Voter};
        let addr = |port: u16| {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..].copy_from_slice(&[127, 0, 0, 1]);
            Addr { ip, port }
        };
        let seq_key = vyrn_crypto::ed25519::public_key(&SEQ_SEED);
        let mut voters = Vec::with_capacity(n);
        for i in 0..n {
            let k = vyrn_crypto::ed25519::public_key(&vote_seed(i)).to_vec();
            voters.push(Voter {
                client: u8::try_from(i % 2).map_err(|e| e.to_string())?,
                facility: u8::try_from(i + 1).map_err(|e| e.to_string())?,
                node_key: k.clone(),
                vote_key: k,
                xchg_key: match (keyed, i) {
                    (true, 0) => vyrn_crypto::x25519::public_key(&XCHG_SEED).to_vec(),
                    (true, _) => vec![0; 32],
                    (false, _) => vec![0x55; 32],
                },
                data_addr: addr(0),
                repl_addr: addr(*repl.get(i).ok_or("repl port")?),
            });
        }
        // R8: the primary box gets a real key, so its `[repair]` serves only sealed fetches. Its
        // repl_addr is 127.0.0.2, so the data box, which keys requesters by IPv4, keeps one
        // keyed requester on 127.0.0.1 (validator 0).
        let mut seq: Vec<SeqEntry> = [seq_key, [0x77; 32]]
            .iter()
            .zip(1u8..)
            .map(|(k, f)| SeqEntry {
                facility: f,
                node_key: k.to_vec(),
                seq_key: k.to_vec(),
                xchg_key: vec![if keyed { 0 } else { 0x66 }; 32],
                client_addr: addr(0),
                repl_addr: addr(0),
            })
            .collect();
        if keyed && let Some(s0) = seq.first_mut() {
            s0.xchg_key = vyrn_crypto::x25519::public_key(&SEQ_XCHG).to_vec();
            s0.repl_addr.ip[12..].copy_from_slice(&[127, 0, 0, 2]);
        }
        let home = Home {
            voters,
            seq,
            recovery: 0,
            data: if keyed {
                [BOX_XCHG, BOX1_XCHG]
                    .iter()
                    .take(boxes)
                    .zip(1u8..)
                    .map(|(x, f)| DataBox {
                        facility: f,
                        addr: addr(0),
                        xchg_key: vyrn_crypto::x25519::public_key(x).to_vec(),
                    })
                    .collect()
            } else {
                Vec::new()
            },
        };
        let r = Roster {
            sig_scheme: 0,
            epoch_from: Epoch(0),
            homes: [home.clone(), home.clone(), home],
            bridge: None,
        };
        let domain = Domain {
            genesis_hash: Hash([0; 32]),
            mode: vyrn_types::Mode::Base,
        };
        let roster = dir.join("roster.hex");
        std::fs::write(&roster, hex(&r.encode())).map_err(|e| e.to_string())?;
        // Validator 0's `K_fetch(e, 0, SEQ_TARGET)` of epochs 0 and 1, which the R8 probe seals
        // with: after R11 moves the box to epoch 1, only the second may be answered.
        let seq_key = |e| {
            r.requester_fetch_key(
                vyrn_epoch::FETCH_CONTEXT,
                &domain,
                Epoch(e),
                vyrn_types::HomeCode::Ldn,
                0,
                vyrn_epoch::SEQ_TARGET,
                &XCHG_SEED,
            )
        };
        let seq_fetch_key = keyed.then(|| Some((seq_key(0)?, seq_key(1)?))).flatten();
        Ok(Self {
            seq_fetch_key,
            roster,
            roster_hash: hex(&r.hash(&domain).0),
            ctrl: SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                *ctrl.first().ok_or("ctrl port")?,
            ),
            obs: None,
        })
    }
}

/// R8: KEY fetches of the last sent packets to the box's keyed `[repair]` at `addr`. The plain
/// form must get no answer; the form sealed under `key` must return the packet's exact bytes.
/// R11: `EPOCH e` to validator `v` (acked `FETCH_EPOCH e`), then to each of `boxes` (acked
/// `FETCH_EPOCHS e,e+1`), so no box drops a key the validator still uses.
fn rotate_epoch(
    nodes: &mut Nodes,
    rx: &Lines,
    v: usize,
    boxes: &[usize],
    e: u32,
    wait: Duration,
) -> Result<String, String> {
    let acks = std::iter::once((v, format!("FETCH_EPOCH {e}"))).chain(
        boxes
            .iter()
            .map(|&b| (b, format!("FETCH_EPOCHS {e},{}", e + 1))),
    );
    for (i, ack) in acks {
        let n = nodes.0.get_mut(i).ok_or("node")?;
        let name = n.name.clone();
        let stdin = n.child.stdin.as_mut().ok_or("stdin")?;
        writeln!(stdin, "EPOCH {e}")
            .and_then(|()| stdin.flush())
            .map_err(|x| format!("{name}: {x}"))?;
        nodes.wait(rx, Instant::now() + wait, &format!("{name} {ack}"), |ns| {
            ns.get(i).is_some_and(|n| n.lines.contains(&ack))
        })?;
    }
    Ok(format!(
        "validator-0 acked FETCH_EPOCH {e}, then vyrn-data and vyrn-seq FETCH_EPOCHS {e},{}; the run's fetches use epoch {e}",
        e + 1
    ))
}

fn probe_seq_repair(
    addr: Option<&str>,
    old: &[u8; 16],
    key: &[u8; 16],
    pkts: &[Pkt],
) -> Result<String, String> {
    use vyrn_data::frame::{Fetch, decode, seal_fetch};
    let addr: SocketAddrV4 = addr
        .ok_or("vyrn-seq printed no REPAIR addr=")?
        .parse()
        .map_err(|e| format!("REPAIR addr: {e}"))?;
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 2048];
    // The box retains 50 ms back from its newest packet (05 §6.10): ask for the last ones sent.
    for p in pkts.iter().rev().take(8) {
        let q = Fetch::Key {
            session: p.session,
            pkt_seq: p.pkt_seq,
        };
        sock.send_to(&q.encode(), addr).map_err(|e| e.to_string())?;
        if sock.recv(&mut buf).is_ok() {
            return Err(format!(
                "the keyed box answered a plain fetch of {:?}",
                (p.session, p.pkt_seq)
            ));
        }
        sock.send_to(&seal_fetch(old, &q), addr)
            .map_err(|e| e.to_string())?;
        if sock.recv(&mut buf).is_ok() {
            return Err(format!(
                "the box answered a fetch of {:?} sealed under epoch 0's key after EPOCH 1 (R11)",
                (p.session, p.pkt_seq)
            ));
        }
        sock.send_to(&seal_fetch(key, &q), addr)
            .map_err(|e| e.to_string())?;
        let n = sock
            .recv(&mut buf)
            .map_err(|e| format!("no answer to a sealed fetch: {e}"))?;
        let f = decode(buf.get(..n).unwrap_or_default()).map_err(|e| format!("{e:?}"))?;
        if f.packets().any(|b| b == p.bytes.as_slice()) {
            return Ok(format!(
                "a plain and an epoch-0 sealed KEY fetch got no answer; the epoch-1 sealed one returned {:?}'s exact bytes",
                (p.session.0, p.pkt_seq)
            ));
        }
    }
    Err("no sealed fetch of the last 8 packets returned their bytes".into())
}

/// Heights of a validator's `FINAL height=<h>` lines, and of the box's (R4).
fn finals(n: &Node) -> Vec<u64> {
    n.lines
        .iter()
        .filter_map(|l| field(l.strip_prefix("FINAL ")?, "height")?.parse().ok())
        .collect()
}
