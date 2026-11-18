#!/usr/bin/env python3
"""VYRN 04-protocol v1 reject vectors: bytes a conforming codec must refuse, and the Reject
records it must decode. Standard library only.

Every packet carries a valid tag (K_seq for requests, K_out for responses), so the verdict comes
from the layout checks alone: 04 §3.1 V1 and V9, §3.3 M2 and M3, §6.1 flag combinations, and
§12 VR1 and VR3. S23-S26 are valid Reject records with the RATE_LIMIT ids of 10 §3.8 (04 §9.1).
The expected verdicts below are written from those tables, not computed.

Output, one vector per line after its `#` description:
    <id> req  drop            <hex>   V1 fails: no response, counted only
    <id> req  msgs <v,v,...>  <hex>   accepted; per message, in index order, `ok` or reason/detail
    <id> resp drop            <hex>   the client discards the packet as a protocol error (VR3)
    <id> resp recs <v,v,...>  <hex>   per record, `ok` or `bad` (a protocol error, VR3); a valid
                                      Reject record is written reason/detail instead of `ok`
"""
import struct

MASK = (1 << 64) - 1


def rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & MASK


def siphash24(key: bytes, msg: bytes) -> int:
    """SipHash-2-4, 128-bit key, 64-bit tag; the same function as vyrn_proto_vectors.py."""
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D,
         k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rnd() -> None:
        v[0] = (v[0] + v[1]) & MASK; v[1] = rotl(v[1], 13); v[1] ^= v[0]; v[0] = rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & MASK; v[3] = rotl(v[3], 16); v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & MASK; v[3] = rotl(v[3], 21); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & MASK; v[1] = rotl(v[1], 17); v[1] ^= v[2]; v[2] = rotl(v[2], 32)

    end = len(msg) - len(msg) % 8
    for i in range(0, end, 8):
        m = struct.unpack_from("<Q", msg, i)[0]
        v[3] ^= m; rnd(); rnd(); v[0] ^= m
    b = ((len(msg) & 0xFF) << 56) | int.from_bytes(msg[end:], "little")
    v[3] ^= b; rnd(); rnd(); v[0] ^= b
    v[2] ^= 0xFF
    for _ in range(4):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


if siphash24(bytes(range(16)), bytes(range(15))) != 0xA129CA6149BE45E5:
    raise SystemExit("SipHash-2-4 self-test FAILED")

K_SEQ = bytes(range(0x00, 0x10))   # the test keys of 04 §11
K_OUT = bytes(range(0x10, 0x20))
A, E16, BOOK = 0x00103007, 0x03E8, 1   # session A, epoch 1000, book 1 (04 §11)


def rec(t, b1=0, w=0, a=0, b=0, c=0): return struct.pack("<BBHIII", t, b1, w, a, b, c)


def request(seq, msgs, count=None, flags=0, reserved=0, cut=0, extra=b""):
    n = len(msgs) if count is None else count
    body = struct.pack("<IIBBHHH", A, seq, n, flags, E16, BOOK, reserved) + b"".join(msgs)
    pkt = body + struct.pack("<QQ", siphash24(K_SEQ, body), 0)
    return pkt[:len(pkt) - cut] + extra


def response(seq, recs, count=None, flags=0):
    n = len(recs) if count is None else count
    body = struct.pack("<IIBBHI", A, seq, n, flags, E16, 1) + b"".join(recs)
    return body + struct.pack("<Q", siphash24(K_OUT, body))


H = 0x0100002A                                   # handle: slot 42, generation 1
NEW = rec(0x01, 0x00, 0, 100_000, 5, 0x11111111)  # New buy Day 5 @ 100000
CANCEL = rec(0x02, 0, 0, H, 0, 0x22222222)
HB = rec(0x10)
ACK = rec(0x81, 0, 0, H, 100_000, 0x11111111)
FILL = rec(0x82, 0, 1, H, 100_000, 5)
BAD_TYPE = 3
UNKNOWN, RESERVED, FLAGS, BAD_HDR = 1, 2, 3, 4   # PROTO_D_* of BAD_TYPE (04 §14)


RATE_LIMIT = 9                                   # 01 §6.5
RSK_BUCKETS = [(8, "RSK_BUCKET_NEW"), (9, "RSK_BUCKET_CROSS"),           # 04 §9.1, 10 §3.8
               (10, "RSK_BUCKET_LANE_CROSS"), (11, "RSK_BUCKET_LANE_IMPROVE")]


def rj(detail): return f"{BAD_TYPE}/{detail}"


REQ = [
    ("V1: count 0", request(1, [], count=0), None),
    ("V1: count 11 > MAX_MSGS_PER_PKT, with 11 messages", request(1, [HB] * 11), None),
    ("V1: count 1 but two messages of payload", request(1, [HB, HB], count=1), None),
    ("V1: one byte short", request(1, [HB], cut=1), None),
    ("V1: one byte long", request(1, [HB], extra=b"\x00"), None),
    ("V9: header flags bit 1 (planned v2 extension block)", request(1, [NEW, CANCEL], flags=0x02),
     [rj(BAD_HDR)] * 2),
    ("V9: header reserved bytes 14-15 = 1", request(1, [NEW], reserved=1), [rj(BAD_HDR)]),
    ("V9 before M2: header flags bit 7 and an undefined type", request(1, [rec(0x05)], flags=0x80),
     [rj(BAD_HDR)]),
    ("M2: type 0x05 (order range, undefined)", request(1, [rec(0x05)]), [rj(UNKNOWN)]),
    ("M2: type 0x20 (reserved range)", request(1, [rec(0x20)]), [rj(UNKNOWN)]),
    ("M2: type 0x81 (a response record in a request)", request(1, [ACK]), [rj(UNKNOWN)]),
    ("M2 before M3: undefined type 0x13 with a nonzero flags byte", request(1, [rec(0x13, 0xFF)]),
     [rj(UNKNOWN)]),
    ("M3: New with order flags bit 6 (planned reduce-only)",
     request(1, [rec(0x01, 0x40, 0, 100_000, 5, 1)]), [rj(RESERVED)]),
    ("M3: New with bytes 2-3 nonzero (planned STP group)",
     request(1, [rec(0x01, 0x00, 7, 100_000, 5, 1)]), [rj(RESERVED)]),
    ("M3 before the flag combination: post-only IOC with bit 6",
     request(1, [rec(0x01, 0x4A, 0, 100_000, 5, 1)]), [rj(RESERVED)]),
    ("M3: Cancel with bytes 8-11 nonzero", request(1, [rec(0x02, 0, 0, H, 1, 2)]), [rj(RESERVED)]),
    ("M3: Heartbeat with a nonzero flags byte", request(1, [rec(0x10, 0x01)]), [rj(RESERVED)]),
    ("M3: ResendReq with bytes 12-15 nonzero", request(1, [rec(0x11, 0, 0, 1, 1, 9)]), [rj(RESERVED)]),
    ("M3: CancelAll with bytes 4-7 nonzero", request(1, [rec(0x12, 0, 0, H, 0, 3)]), [rj(RESERVED)]),
    ("M3: Replace with order flags bit 7", request(1, [rec(0x04, 0x80, 0, H, 100_000, 5)]),
     [rj(RESERVED)]),
    ("04 §6.1: New post-only with IOC", request(1, [rec(0x01, 0x0A, 0, 100_000, 5, 1)]), [rj(FLAGS)]),
    ("04 §6.1: Replace post-only with FOK", request(1, [rec(0x04, 0x0C, 0, H, 100_000, 5)]),
     [rj(FLAGS)]),
    ("per message: only index 1 is rejected", request(1, [CANCEL, rec(0x01, 0x80, 0, 1, 1, 1), HB]),
     ["ok", rj(RESERVED), "ok"]),
]

RESP = [
    ("header: count 0", response(1, [], count=0), None),
    ("header: count 17 > 16, with 17 records", response(1, [ACK] * 17), None),
    ("header: flags bit 1 (planned: more records follow)", response(1, [ACK], flags=0x02), None),
    ("header: one record short of count", response(1, [ACK], count=2), None),
    ("type 0x89 (undefined)", response(1, [rec(0x89)]), ["bad"]),
    ("type 0x01 (a request message in a response)", response(1, [NEW]), ["bad"]),
    ("Ack with bytes 2-3 nonzero", response(1, [rec(0x81, 0, 1, H, 100_000, 1)]), ["bad"]),
    ("Ack with index 10 (neither 0-9 nor 0xFF)", response(1, [rec(0x81, 10, 0, H, 100_000, 1)]),
     ["bad"]),
    ("Fill with liq 3", response(1, [rec(0x82, 0, 3, H, 100_000, 5)]), ["bad"]),
    ("Reject with reason 0", response(1, [rec(0x83, 0xFF, 0, 0, 0, 0)]), ["bad"]),
    ("Reject with reason 25 (reserved, not v1)", response(1, [rec(0x83, 0xFF, 25, 0, 0, 0)]),
     ["bad"]),
    ("Reject with bytes 8-11 nonzero", response(1, [rec(0x83, 0xFF, 15, 1000, 1, 0)]), ["bad"]),
    ("CancelAck with bytes 2-3 nonzero", response(1, [rec(0x84, 0, 1, H, 5, 1)]), ["bad"]),
    ("Out with cause 0", response(1, [rec(0x85, 0, 0, H, 1, 1)]), ["bad"]),
    ("Out with cause 9", response(1, [rec(0x85, 0, 9, H, 1, 1)]), ["bad"]),
    ("EpochNotice with byte 1 nonzero", response(1, [rec(0x86, 1, 0, 1001, 0x0102, 3600)]), ["bad"]),
    ("EpochNotice with home-word bytes 10-11 nonzero",
     response(1, [rec(0x86, 0, 0, 1001, 0x00010102, 3600)]), ["bad"]),
    ("Bust with index 0 (must be 0xFF)", response(1, [rec(0x87, 0, 0, H, 100_000, 5)]), ["bad"]),
    ("Attest with level 0", response(1, [rec(0x88, 0, 0, 5, 7, 0)]), ["bad"]),
    ("Attest with level 4", response(1, [rec(0x88, 4, 0, 5, 7, 0)]), ["bad"]),
    ("Attest with bytes 12-15 nonzero", response(1, [rec(0x88, 1, 0, 5, 7, 1)]), ["bad"]),
    ("per record: only index 1 is bad", response(1, [ACK, rec(0x89), FILL]), ["ok", "bad", "ok"]),
] + [
    (f"Reject RATE_LIMIT detail {d}: {name}, a 10 §3.8 bucket (04 §9.1 ids 8-11)",
     response(1, [rec(0x83, 0, RATE_LIMIT, d, 0, 0x11111111)]), [f"{RATE_LIMIT}/{d}"])
    for d, name in RSK_BUCKETS
]

print("# Generated by tests/golden/vyrn_reject_vectors.py; see tests/golden/README.md.")
for prefix, kind, key, vectors in [("R", "req ", "msgs", REQ), ("S", "resp", "recs", RESP)]:
    for i, (what, pkt, want) in enumerate(vectors, 1):
        verdict = "drop" if want is None else f"{key} {','.join(want)}"
        print(f"# {what}")
        print(f"{prefix}{i:02d} {kind} {verdict} {pkt.hex()}")
