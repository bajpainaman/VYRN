#!/usr/bin/env python3
"""vyrn-log golden vectors (spec/07-replication.md §3, §6.1, §8.2). Pure Python 3, standard library.

Every byte below is written out by hand from the 07 tables, with a comment per field, and
not derived from the Rust encoder. BLAKE3 is a from-scratch implementation that checks itself
against tests/golden/blake3_test_vectors.json first. Run it as

    python3 -I tests/golden/vyrn_log_vectors.py | diff - tests/golden/vyrn_log_vectors.out

The Rust test crates/vyrn-log/tests/golden.rs rebuilds every vector with vyrn-log's encoder,
decodes it back, and compares the result byte for byte with the .out file.
"""
import json
import os
import struct

# ---------------------------------------------------------------- BLAKE3 (hash mode, 32 bytes)
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
M32 = 0xFFFFFFFF
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, x, y):
    s[a] = (s[a] + s[b] + x) & M32; s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32;     s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & M32; s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32;     s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, blen, flags):
    m = list(struct.unpack("<16I", block))
    s = cv[:] + IV[:4] + [counter & M32, counter >> 32, blen, flags]
    for _ in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1]); _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5]); _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9]); _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13]); _g(s, 3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in PERM]
    return [s[i] ^ s[i + 8] for i in range(8)]


def _chunk(data, counter):
    cv = IV[:]
    blocks = [data[i:i + 64] for i in range(0, len(data), 64)] or [b""]
    for i, b in enumerate(blocks):
        f = (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == len(blocks) - 1 else 0)
        if i == len(blocks) - 1:
            return (cv, b.ljust(64, b"\0"), counter, len(b), f)
        cv = _compress(cv, b, counter, 64, f)


def _tree(data, counter):
    if len(data) <= 1024:
        return _chunk(data, counter)
    n = (len(data) + 1023) // 1024
    left = 1 << ((n - 1).bit_length() - 1)   # largest power of two below n
    kids = (_tree(data[:left * 1024], counter), _tree(data[left * 1024:], counter + left))
    return (IV[:], b"".join(struct.pack("<8I", *_compress(*k)) for k in kids), 0, 64, PARENT)


def blake3(data: bytes) -> bytes:
    cv, b, c, l, f = _tree(data, 0)
    return struct.pack("<8I", *_compress(cv, b, c, l, f | ROOT))


with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "blake3_test_vectors.json")) as fh:
    cases = json.load(fh)["cases"]
for case in cases:
    data = bytes(i % 251 for i in range(case["input_len"]))
    if blake3(data).hex() != case["hash"][:64]:
        raise SystemExit(f"BLAKE3 self-test FAILED at input_len {case['input_len']}")
print(f"# BLAKE3 self-test: {len(cases)} official vectors OK")
print()


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def out(name: str, b: bytes) -> None:
    print(f"{name}: {b.hex()}")


# ---------------------------------------------------------------- LEB128 and ZigZag (07 §3.4)
def leb(v: int) -> bytes:
    o = bytearray()
    while True:
        low, v = v & 0x7F, v >> 7
        if v == 0:
            o.append(low)
            return bytes(o)
        o.append(low | 0x80)


def zz(v: int) -> int:
    return (v << 1) if v >= 0 else ((-v) << 1) - 1


assert leb(300) == hx("ac02") and leb(zz(512)) == hx("8008")   # 07 §3.11's own bytes
print("# leb.<decimal>: canonical unsigned LEB128")
for v in [0, 1, 127, 128, 300, 16383, 16384, 4096, 4097, 2**32 - 1, 2**32, 2**63, 2**64 - 1]:
    out(f"leb.{v}", leb(v))
print("# zigzag.<decimal>: LEB128 of ZigZag(i64)")
for v in [0, -1, 1, -2, 2, 512, -100, 700, 2**63 - 1, -2**63]:
    out(f"zigzag.{v}", leb(zz(v)))
print("# leb_bad.<n>: inputs a decoder must reject (overlong, above u64::MAX, unterminated)")
for i, b in enumerate(["8000", "ff00", "8080808080808080808000",
                       "ffffffffffffffffff02", "ffffffffffffffffff7f", "80", ""]):
    print(f"leb_bad.{i}: {b}")
print()

# ---------------------------------------------------------------- 07 §3.11 worked example
# REF layout, substream A. Lane 7: slot 300 bound with the expected pkt_seq, rx_ts +512.
# Step: Cross from lane 7, src op = new cut[7]; half-cut A moves lanes 3, 7, 12 by 2, 10, 1.
out("ex311.sections", hx(
    "07 01"            # LaneRun tag lane 7, k = 1
    " 0a ac02 8008"    # h = count 10; slot 300; zigzag(512)
    " 40 01"           # StepRun, m = 1
    " 50 00 07 00"     # Cross | HOME | SPARSE; gap 0; src 7; zigzag(0)
    " 88100000"        # bitmap of 25 lanes: bits 3, 7, 12
    " 02 0a 01"))      # deltas
# The same step as an Improve whose lane classified it Cross (STP left no fill): the src byte
# carries StepRecord.flags CROSS in bit 7 (07 §3.8), 0x80 | lane 7.
out("ex311.cross_route.sections", hx(
    "07 01 0a ac02 8008"
    " 40 01"
    " 51 00 87 00"     # Improve | HOME | SPARSE; gap 0; src 0x87 = CROSS | lane 7; zigzag(0)
    " 88100000 02 0a 01"))
# RouteRecord (07 §3.6) after lane 7's packet (LaneSeqs 1..10): op 8 was classified Cross and
# rejected by the lane. h = CROSS (bit 7) | back 2 (10 - 8); slot 4098 = LEB 82 20.
out("ex311.route.sections", hx(
    "07 02"            # LaneRun tag lane 7, k = 2
    " 0a ac02 8008"    # the packet record above
    " 82 8220"))       # RouteRecord: h = 0x80 | 2; slot REP_SLOT_ROUTE
# back 10 >= count 10, and a reserved h bit (0x10): both REP_E_COUNT.
out("ex311.bad_route_back.sections", hx("07 02 0a ac02 8008 8a 8220"))
out("ex311.bad_route_bits.sections", hx("07 02 0a ac02 8008 12 8220"))
# MID Advance record (07 §3.6, 05 §6.2) after lane 7's packet (LaneSeqs 1..10, next 11): a
# LaneCut boundary before pass 1 of op 8, at step 1. h = FA_NZ | MID (bit 4); slot 4096 = LEB
# 80 20; rx_ts +0; fills +1; back = 11 - 8 = 3. With PASS2 (bit 7) it runs before pass 2.
out("ex311.mid.sections", hx("07 02 0a ac02 8008 50 8020 00 01 03"))
out("ex311.mid_pass2.sections", hx("07 02 0a ac02 8008 d0 8020 00 01 03"))
# back 0: before a trailing Heartbeat or ResendReq, which takes no LaneSeq (05 §3.1).
out("ex311.mid_end.sections", hx("07 02 0a ac02 8008 50 8020 00 01 00"))
# back 11 > count 10, PASS2 without MID, LSEQ_EXC on an Advance record: all REP_E_COUNT.
out("ex311.bad_mid_back.sections", hx("07 02 0a ac02 8008 50 8020 00 01 0b"))
out("ex311.bad_mid_pass2.sections", hx("07 02 0a ac02 8008 c0 8020 00 01"))
out("ex311.bad_mid_lseq.sections", hx("07 02 0a ac02 8008 70 8020 00 01 03"))
# src byte bit 6 set (0x47): no lane of the half, REP_E_CUT.
out("ex311.bad_src_bit6.sections", hx("07 01 0a ac02 8008 40 01 51 00 47 00 88100000 02 0a 01"))
print()

# ---------------------------------------------------------------- one block on two substreams
# Layout: 4 lanes, 2 substreams (A = lanes 0-1, B = lanes 2-3), lane 3 pooled.
# Tenure: epoch 1000, tenure 0, sender 0, book 1, first_step 1, first_height 100,
# prev_header_hash = 32 x 0x11. Every lane starts at next_lane_seq 1, rx_ts 1_000_000,
# fills_applied 0; every half-cut starts at 0.
PREV = b"\x11" * 32
lane_base = hx("01") + struct.pack("<Q", 1_000_000) + hx("00")
ts = hx("44") + struct.pack("<IBBQQ", 1000, 0, 0, 1, 100) + PREV + lane_base * 2 + hx("00 00")

bind_a = hx("43 00 05") + struct.pack("<I", 0x00301007) + hx("01")  # lane 0 slot 5, next 1
lane0 = hx(
    "00 02"            # LaneRun lane 0, k = 2
    " 03 05 f80a"      # count 3, slot 5, pkt_seq 1 (expected), rx_ts +700
    " 11 05 c701 05")  # count 1 | SEQ_EXC, slot 5, rx_ts -100, pkt_seq 5 (expected 2)
lane1 = hx("01 01 40 8020 00 01")  # lane 1: FA_NZ Advance (slot 4096), rx_ts +0, fills +1
step_a = hx(
    "40 02"
    " 31 00 00 00 04 00"   # Improve | HOME | DENSE; gap 0 (step 1); src 0; zz(4 - 4); +4, +0
    " 96 00 ff 02 0102")   # Control | HOME | SAME | OTHER; gap 0 (step 2); no src; payload
mark_a = hx("42 64 02 01 04")      # height 100; last_step 0 + 2; bounds: lane 0 +4
order_a = bind_a + lane0 + lane1 + step_a + mark_a

bind_b = hx("43 03 00") + struct.pack("<I", 0x00007003) + hx("01")  # lane 3 slot 0, next 1
lane3 = hx(
    "03 02"
    " 00 8120 09 01"   # AcctTake: h 0, slot 4097, account 9, ver 1
    " 02 00 64")       # count 2, slot 0, pkt_seq 1, rx_ts +50
step_b = hx("40 01 a6 01 00 02")   # Control cut-only | DENSE | OTHER; gap 1 (step 2); +0, +2
mark_b = hx("42 64 02 02 02")      # height 100; last_step 2; bounds: lane 3 +2
order_b = bind_b + lane3 + step_b + mark_b

payloads = [f"vyrn-log vector packet {i}".encode() for i in range(3)]  # A0, A1, B0
full = [blake3(p) for p in payloads]
pkt8 = [f[:8] for f in full]       # PktHash: the first 8 bytes, read little-endian


def frame(kind, seq, stream, body, flags=0):
    return struct.pack("<HBBHHQBBHBBH", 0x4250, 1, kind, 1, 1000 & 0xFFFF, seq, flags, 0,
                       len(body), 0, stream, 0) + body


order_root = blake3(blake3(order_a) + blake3(order_b))
data_root = blake3(blake3(full[0] + full[1]) + blake3(full[2]))
signed = struct.pack("<QIHQQ", 100, 1000, 1, 1, 2) + PREV + order_root + data_root
assert len(signed) == 126
header = signed + bytes(64)

out("blk.frame.a1", frame(1, 1, 0, ts + order_a))
out("blk.frame.a1.path_b", frame(1, 1, 0, ts + order_a, flags=1))
out("blk.frame.a2", frame(2, 2, 0, hx("41 00 02") + pkt8[0] + pkt8[1]))
out("blk.frame.a3", frame(3, 3, 0, header))
out("blk.frame.b1", frame(1, 1, 1, ts + order_b))
out("blk.frame.b2", frame(2, 2, 1, hx("41 03 01") + pkt8[2]))
out("blk.frame.b3", frame(4, 3, 1, struct.pack("<QQQ", 2, 100, 1_000_900)))
out("blk.order_a", order_a)
out("blk.order_b", order_b)
for i, p in enumerate(payloads):
    out(f"blk.payload.{i}", p)
out("blk.order_root", order_root)
out("blk.data_root", data_root)
out("blk.header", header)
out("blk.header_hash", blake3(b"vyrn v1 header" + signed))
out("blk.seq_sig_message", b"vyrn      v1 block" + signed)
print()

# ---------------------------------------------------------------- REP_BlockRecord (07 §8.2)
body = order_a + order_b + b"".join(pkt8) + b"".join(payloads)
head = (b"PBBLK001" + struct.pack("<QIBBH", 100, 1000, 0, 0, 0) + header
        + struct.pack("<IIIII", len(order_a) + len(order_b), 24, sum(map(len, payloads)), 0,
                      len(order_a)))
head += bytes(256 - len(head))
rec = bytearray(head + body)
rec += bytes(-len(rec) % 4096)
rec[234:250] = blake3(bytes(rec))[:16]
out("rec.head", bytes(rec[:256]))
print(f"rec.len: {len(rec)}")
out("rec.blake3", blake3(bytes(rec)))
