#!/usr/bin/env python3
"""VYRN 07-replication sequencer-retransmit vectors: `Nack` and `NackTooOld` (07 §4.10).
Standard library only.

Each datagram is built field by field from the 07 §4.10 layout. Every integer is little-endian.

    Nack (24 B)        type 0x31, path u8 (0 A, 1 B), epoch16 u16, tenure u8, stream u8 (0, 1),
                       port u16 (the requester's ORDER port on `path`), from_seq u64 (>= 1),
                       to_seq u64 (from_seq <= to_seq < from_seq + 1024)
    NackTooOld (16 B)  type 0x32, path u8, epoch16 u16, tenure u8, stream u8, reserved u16 = 0,
                       oldest_seq u64

A receiver refuses a datagram of another length or type, a path or stream above 1, a nonzero
reserved field, or a Nack range outside its bounds. Nothing here imports the Rust code.

Output, one vector per line after its `#` description:
    <id> <message> ok     <hex>   built from the fields in the comment; a receiver accepts it
    <id> <message> refuse <hex>   a receiver refuses it
"""
import json
import struct
import sys

JSON = sys.argv[1:] == ["--json"]          # the same vectors as JSON (tests/golden/README.md)
NACK, TOO_OLD = 0x31, 0x32
SPAN_MAX = 1024


def nack(path, epoch16, tenure, stream, port, from_seq, to_seq, typ=NACK):
    return struct.pack("<BBHBBHQQ", typ, path, epoch16, tenure, stream, port, from_seq, to_seq)


def too_old(path, epoch16, tenure, stream, oldest, reserved=0):
    return struct.pack("<BBHBBHQ", TOO_OLD, path, epoch16, tenure, stream, reserved, oldest)


VECTORS = [
    ("N01", "Nack", "ok", "path A, epoch16 1000, tenure 0, stream 0, port 7400, frames 5..=9",
     nack(0, 1000, 0, 0, 7400, 5, 9)),
    ("N02", "Nack", "ok", "path B, epoch16 0xBEEF, tenure 3, stream 1, port 40001, one frame 2^40",
     nack(1, 0xBEEF, 3, 1, 40001, 1 << 40, 1 << 40)),
    ("N03", "Nack", "ok", "the longest range: 1..=1024",
     nack(0, 1, 0, 1, 9, 1, SPAN_MAX)),
    ("T01", "NackTooOld", "ok", "path A, epoch16 1000, tenure 0, stream 0, oldest_seq 4096",
     too_old(0, 1000, 0, 0, 4096)),
    ("T02", "NackTooOld", "ok", "path B, epoch16 7, tenure 255, stream 1, oldest_seq 2^63",
     too_old(1, 7, 255, 1, 1 << 63)),
    ("R01", "Nack", "refuse", "from_seq 0",
     nack(0, 1, 0, 0, 9, 0, 3)),
    ("R02", "Nack", "refuse", "to_seq below from_seq",
     nack(0, 1, 0, 0, 9, 8, 7)),
    ("R03", "Nack", "refuse", "1025 frames: 1..=1025",
     nack(0, 1, 0, 0, 9, 1, SPAN_MAX + 1)),
    ("R04", "Nack", "refuse", "path 2",
     nack(2, 1, 0, 0, 9, 1, 1)),
    ("R05", "Nack", "refuse", "stream 2",
     nack(0, 1, 0, 2, 9, 1, 1)),
    ("R06", "Nack", "refuse", "23 bytes: N01 without its last byte",
     nack(0, 1000, 0, 0, 7400, 5, 9)[:-1]),
    ("R07", "Nack", "refuse", "N01 with the NackTooOld type",
     nack(0, 1000, 0, 0, 7400, 5, 9, typ=TOO_OLD)),
    ("R08", "NackTooOld", "refuse", "reserved 1",
     too_old(0, 1000, 0, 0, 4096, reserved=1)),
    ("R09", "NackTooOld", "refuse", "17 bytes: T01 and a trailing 0",
     too_old(0, 1000, 0, 0, 4096) + b"\x00"),
    ("R10", "NackTooOld", "refuse", "path 2",
     too_old(2, 1000, 0, 0, 4096)),
]

assert len(nack(0, 0, 0, 0, 0, 1, 1)) == 24 and len(too_old(0, 0, 0, 0, 1)) == 16

if JSON:
    print(json.dumps({
        "source": "tests/golden/vyrn_nack_vectors.py",
        "vectors": [{"id": i, "message": m, "verdict": v, "what": w, "hex": b.hex()}
                    for i, m, v, w, b in VECTORS],
    }, indent=2))
else:
    print("# VYRN 07 §4.10 Nack and NackTooOld vectors (vyrn_nack_vectors.py)")
    for i, m, v, w, b in VECTORS:
        print("# " + w)
        print("%s %s %s %s" % (i, m, v, b.hex()))
