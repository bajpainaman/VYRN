# Golden vectors

These files let anyone check an implementation of the VYRN client protocol (spec/04-protocol.md,
version 1) or of its crypto, in any language. You don't need this repository's code. Python 3 is
enough to regenerate the protocol files.

| File | What it checks | Source |
|---|---|---|
| `vyrn_proto_vectors.py`, `.out` | 18 request and response packets one `DataRedirect` (V19, 04 §7.6) and one `DataTierStatus` admin frame (V20, 04 §4.4) that a conforming implementation must build byte for byte and accept (04 §11) | the script is the one printed in 04 §11; `.out` is its output |
| `vyrn_reject_vectors.py`, `.out` | 45 validly tagged packets whose layout v1 must refuse, each with its verdict (04 §3.1 V1/V9, §3.3 M2/M3, §6.1, §12 VR1/VR3), and 4 `Reject RATE_LIMIT` records with 10's bucket ids 8–11 (04 §9.1) | written for this repository from those tables |
| `vyrn_admin_vectors.py`, `.out` | 2 BASE-mode admin frames, `OpenSessionReq` and `OpenSessionResp`, that an implementation must build and accept, and 8 it must refuse (04 §4.4) | written for this repository from the §4.4 tables |
| `vyrn_session_vectors.py`, `.out` | 35 packets, one per session state (04 §4.3) and message type, each with the lane's verdict (04 §3.1 V2/V7), and the final in-stream record of the 6 close causes | written for this repository from the 04 §3.1 and §4.3 tables |
| `vyrn_replica_vectors.txt` | 14 order-stream frame sequences and the verdict a replica's order core must reach: the step rules of 07 §3.12 (a cut beyond the decoded lane prefix, a source that is not decoded or is in a `SHED` packet), the `REP_E_HASHLAG` timer at and past 1 ms, also when the late hash itself arrives (07 §3.7), the step merge from the `TenureStart` cuts, a `TenureStart` cut beyond its lane bases, a step missing after both marks (07 §3.8, §3.9), and the header rules (07 §3.10). The file's header gives the format | built with `vyrn-log`'s encoder by `crates/vyrn-replica/tests/conformance.rs` (`VYRN_BLESS=1` rewrites it) |
| `vyrn_data_vectors.py`, `.out` | 5 data frames (07 §5.3) to build and accept and 13 to refuse, 3 fetch requests and 9 refusals, and 5 dedupe-window sequences (07 §5.2 step 3) | written for this repository from the layouts in `crates/vyrn-data/src/lib.rs` |
| `siphash.txt` | SipHash-2-4, 64 lengths (the packet MAC, 01 §4) | [veorq/SipHash](https://github.com/veorq/SipHash) `vectors.h` at `32d0676`, `vectors_sip64` |
| `blake3_test_vectors.json` | BLAKE3 hash, keyed hash and `derive_key` (01 §4) | [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) `test_vectors/test_vectors.json` at `657284b`, byte for byte |
| `ed25519-edge.txt` | Ed25519 edge cases with ZIP-215 verdicts (spec/11-build.md §2.5) | [novifinancial/ed25519-speccheck](https://github.com/novifinancial/ed25519-speccheck) `cases.json` at `6551933`; verdicts from the Zebra row of its README |
| `lane/streams.txt` | 8 whole runs of the lanes and BBO core: every input packet, step and poll, and every step entry, fill event, fill TX packet, response and `PacketRecord` (05 §3, §6–§8). See `lane/README.md` | written by `crates/engine/vyrn-lane/tests/golden.rs`; each scenario's records are asserted from the spec in `crates/engine/vyrn-lane/tests/lane.rs` |

The upstream rows were last compared with those commits on 2026-11-17. The NIC frame vectors
(06 §6.2) live with their backend, in `crates/vyrn-nic/tests/frame_vectors.txt`.

## Check that the files are what the scripts print

Run the scripts from a directory outside the repository with `python3 -I`, so that nothing in
your environment or working directory changes what they import:

```sh
cd /tmp
python3 -I "$REPO/tests/golden/vyrn_proto_vectors.py"  | diff - "$REPO/tests/golden/vyrn_proto_vectors.out"
python3 -I "$REPO/tests/golden/vyrn_reject_vectors.py" | diff - "$REPO/tests/golden/vyrn_reject_vectors.out"
python3 -I "$REPO/tests/golden/vyrn_admin_vectors.py"  | diff - "$REPO/tests/golden/vyrn_admin_vectors.out"
python3 -I "$REPO/tests/golden/vyrn_session_vectors.py" | diff - "$REPO/tests/golden/vyrn_session_vectors.out"
python3 -I "$REPO/tests/golden/vyrn_data_vectors.py"   | diff - "$REPO/tests/golden/vyrn_data_vectors.out"
```

Each command prints nothing when its file matches. CI runs them on every pull request.

## Check an independent implementation

The test keys are `K_seq` = bytes `00..0f`, `K_out` = `10..1f` and `K_com` = `20..2f`. They are
for testing only. Every multi-byte field is little-endian (01 §6).

**Acceptance (`vyrn_proto_vectors.out`).** Each vector is a block:

```text
V1 req  A: New buy Day 5 @ 100000, STP 1 (48 B)
  000: 07 30 10 00 01 00 00 00 01 00 e8 03 01 00 00 00
  ...
  tag_seq=0x8e1382100caea6ce  tag_com=0x0000000000000000
```

The first word is the vector ID, `req` or `resp` gives the direction, and the number in
parentheses is the packet length. Each indented row is a hex offset followed by up to 16 bytes.
The tag line repeats the trailing tags as integers. 04 §11 gives the scenario: the sessions,
handles and epoch behind each packet. An implementation passes when, for every vector, it:

1. builds the same bytes from the scenario's fields and the test keys;
2. parses the bytes back to the same fields, and verifies `tag_seq` with `K_seq` (and `tag_com`
   with `K_com` for V10), a response's `tag` with `K_out`, or V19's `tag` with `K_seq` (V20, an admin frame, has none);
3. holds the `check OK:` lines at the end of the file, such as "V1 with one tag bit flipped fails".

**Refusal (`vyrn_reject_vectors.out`).** Lines starting with `#` describe the vector below them.
Each vector is one line: `<id> <req|resp> <verdict> <hex>`. The tags are valid, so a refusal comes
from the layout alone. The verdicts are:

| Verdict | Meaning |
|---|---|
| `req drop` | Check V1 fails: the receiver drops the packet and sends nothing. |
| `req msgs a,b,…` | The packet is accepted. Each entry is one message, in index order: `ok`, or the `Reject` it gets as `reason/detail`. For example `3/2` is `BAD_TYPE` with `PROTO_D_RESERVED`. A header failure (V9) rejects every message with `3/4`. |
| `resp drop` | The client discards the whole response as a protocol error (VR3). |
| `resp recs a,b,…` | Each entry is one record: `ok`, or `bad`, a protocol error (VR3). A valid `Reject` record is written `reason/detail` instead of `ok`: `9/8` is `RATE_LIMIT` with bucket id 8 (`RSK_BUCKET_NEW`). |

An implementation that accepts any of these packets reads a reserved field that a later version
may give a meaning (VR1, VR2). It would then misread that version's traffic.

**Admin channel (`vyrn_admin_vectors.out`).** Each vector is one line:
`<id> <message> <ok|refuse> <hex>`, where the hex is the whole frame from its `len` field. An
`ok` frame is built from the field values in the comment above it, and a conforming
implementation builds the same bytes and parses them back to those fields. A `refuse` frame has
a nonzero reserved byte, an unknown `type`, or a `len` that does not match the body (04 §4.4);
a receiver refuses it. The keys inside `A02` are test keys only. In this repository,
`bin/vyrn-admin/tests/admin_vectors.rs` checks `vyrn_admin::codec` against them.

**Session state (`vyrn_session_vectors.out`).** `S` lines are
`<id> <state> <message> <verdict>`, for a packet that passes every check except the state ones:
`accept`, `drop` (no response), `oos <REASON> <detail>` (an out-of-stream `Reject`, index 0xFF) or
`reject <REASON> <detail>` (accepted, in-stream `Reject` at index 0). `C` lines are
`<id> close <CAUSE> <hex>`: the 16-byte final record (01 §6.4) the lane emits when the session
enters `CLOSED`. The script's docstring names the one reading it takes (`OPENING` fails V2).
CHAIN `tag_com` is covered by proto vector V10, and the 01 §6.6 records' 07 encoding by the
`blk.frame.*` lines of `vyrn_log_vectors.out`.

**Crypto.** Each of `siphash.txt` and `ed25519-edge.txt` explains its columns in its header
comment. `blake3_test_vectors.json` explains its format in its `_comment` field.

In this repository, `crates/engine/vyrn-wire/tests/vectors.rs` and
`crates/engine/vyrn-crypto/tests/golden.rs` run these checks against `vyrn-wire` and
`vyrn-crypto`.

## Versioning

All vectors are for protocol version 1. The wire has no version field. A session fixes its version
when it opens (04 §12). Vector IDs are stable. A new vector gets the next free ID, and an existing
vector never changes its bytes or its meaning. A later protocol version gets its own files.
