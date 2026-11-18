#!/usr/bin/env python3
"""VYRN      04-protocol conformance vectors. Pure Python 3, standard library only."""
import struct

MASK = (1 << 64) - 1


def rotl(x: int, b: int) -> int:
    return ((x << b) | (x >> (64 - b))) & MASK


def siphash24(key: bytes, msg: bytes) -> int:
    """SipHash-2-4, 128-bit key, 64-bit tag (as an integer; on the wire it is little-endian)."""
    if len(key) != 16:
        raise ValueError(f"SipHash key must be 16 bytes, got {len(key)}")
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


# Reference vectors from the SipHash paper (key 00..0f, message 00..len-1).
for n, want in [(15, 0xA129CA6149BE45E5), (0, 0x726FDB47DD0E0E31), (8, 0x93F5F5799A932462)]:
    got = siphash24(bytes(range(16)), bytes(range(n)))
    if got != want:
        raise SystemExit(f"SipHash-2-4 self-test FAILED for len {n}: {got:#018x}")
print("siphash24(00..0f, 00..0e) = 0xa129ca6149be45e5  reference vector OK (also len 0, 8)")

K_SEQ = bytes(range(0x00, 0x10))   # test keys only
K_OUT = bytes(range(0x10, 0x20))
K_COM = bytes(range(0x20, 0x30))


def sid(slot, lane, gen): return slot | lane << 12 | gen << 20          # section 4.1
def hdl(slot, gen): return slot | gen << 24                             # 01 section 3
def of(side, tif=0, post=0, stp=0): return side | tif << 1 | post << 3 | stp << 4
def rec(t, b1=0, w=0, a=0, b=0, c=0): return struct.pack("<BBHIII", t, b1, w, a, b, c)


def new(f, tick, qty, tag): return rec(0x01, f, 0, tick, qty, tag)
def cancel(h, tag): return rec(0x02, 0, 0, h, 0, tag)
def reduce(h, by, tag): return rec(0x03, 0, 0, h, by, tag)
def replace(f, h, tick, qty): return rec(0x04, f, 0, h, tick, qty)
def heartbeat(): return rec(0x10)
def resend_req(lo, hi): return rec(0x11, 0, 0, lo, hi, 0)
def cancel_all(tag): return rec(0x12, 0, 0, 0, 0, tag)
def ack(i, h, tick, tag): return rec(0x81, i, 0, h, tick, tag)
def fill(i, liq, h, tick, qty): return rec(0x82, i, liq, h, tick, qty)
def reject(i, why, detail, tag): return rec(0x83, i, why, detail, 0, tag)
def cancel_ack(i, h, qty, tag): return rec(0x84, i, 0, h, qty, tag)
def out(i, cause, h, qty, tag): return rec(0x85, i, cause, h, qty, tag)
def epoch_notice(e, home, secs): return rec(0x86, 0, 0, e, home, secs)


def data_redirect(s, down, to, frm, key):                              # section 7.6
    body = struct.pack("<HBBB3sII", 0x5244, 1, down, to, bytes(3), s, frm)
    return body + struct.pack("<Q", siphash24(key, body))


def request(s, seq, e16, book, msgs, k_com=None, flags=0):
    body = struct.pack("<IIBBHHH", s, seq, len(msgs), flags, e16, book, 0) + b"".join(msgs)
    tag_com = siphash24(k_com, body) if k_com else 0                    # 0 in BASE mode
    return body + struct.pack("<QQ", siphash24(K_SEQ, body), tag_com)


def response(s, rseq, e16, echo, recs, flags=0):
    body = struct.pack("<IIBBHI", s, rseq, len(recs), flags, e16, echo) + b"".join(recs)
    return body + struct.pack("<Q", siphash24(K_OUT, body))


def verify_request(pkt, key):
    n = pkt[8]
    end = 16 + 16 * n
    ok_len = 1 <= n <= 10 and len(pkt) == end + 16
    return ok_len and siphash24(key, pkt[:end]) == struct.unpack_from("<Q", pkt, end)[0]


def dump(name, pkt, req):
    print(f"\n{name} ({len(pkt)} B)")
    for off in range(0, len(pkt), 16):
        print(f"  {off:03x}: " + " ".join(f"{x:02x}" for x in pkt[off:off + 16]))
    tags = struct.unpack_from("<QQ", pkt, len(pkt) - 16) if req else struct.unpack_from("<Q", pkt, len(pkt) - 8)
    print("  " + "  ".join(f"{n}={t:#018x}" for n, t in zip(("tag_seq", "tag_com") if req else ("tag",), tags)))


E, B = 1000, 1                                   # epoch 1000 (epoch16 0x03e8), book 1
A, Bs, C = sid(7, 3, 1), sid(9, 5, 1), sid(2, 0, 4)
A1, A2, A3, A4, B1 = hdl(42, 1), hdl(43, 1), hdl(44, 1), hdl(45, 1), hdl(7, 3)
V = [
    ("V1 req  A: New buy Day 5 @ 100000, STP 1", request(A, 1, E, B, [new(of(0, stp=1), 100_000, 5, 0x11111111)]), True),
    ("V2 resp A: Ack (lane, L-packet)", response(A, 1, E, 1, [ack(0, A1, 100_000, 0x11111111)]), False),
    ("V3 req  A: Cancel A1, Reduce A2 by 2, Replace A3 -> buy 8 @ 100001",
     request(A, 2, E, B, [cancel(A1, 0x22222222), reduce(A2, 2, 0x33333333), replace(of(0, stp=1), A3, 100_001, 8)]), True),
    ("V4 resp A: CancelAck, CancelAck, CancelAck(old) + Ack(new), stored tag 0x44444444",
     response(A, 2, E, 2, [cancel_ack(0, A1, 5, 0x22222222), cancel_ack(1, A2, 2, 0x33333333),
                           cancel_ack(2, A3, 4, 0x44444444), ack(2, A4, 100_001, 0x44444444)]), False),
    ("V5 req  B: New sell IOC 10 @ 100000", request(Bs, 1, E, B, [new(of(1, tif=1), 100_000, 10, 0x55555555)]), True),
    ("V6 resp B: B-packet Fill 8 @ 100001, Fill 1 @ 100000, Out IOC_REMAINDER 1",
     response(Bs, 1, E, 1, [fill(0, 1, B1, 100_001, 8), fill(0, 1, B1, 100_000, 1), out(0, 1, B1, 1, 0x55555555)]), False),
    ("V7 resp A: maker Fill of A4 from the TX core, maker range (echo_pkt 0)", response(A, 3, E, 0, [fill(0xFF, 0, A4, 100_001, 8)]), False),
    ("V8 req  A: Heartbeat", request(A, 3, E, B, [heartbeat()]), True),
    ("V9 resp A: EpochNotice (answer): next 1001, LDN box 1, 3600 s",
     response(A, 4, E, 3, [epoch_notice(E + 1, 2 | 1 << 8, 3600)]), False),
    ("V10 req C: CHAIN mode, New sell post-only 3 @ 100002",
     request(C, 1, E, B, [new(of(1, post=1), 100_002, 3, 0x66666666)], k_com=K_COM), True),
    ("V11 resp A: out-of-stream Reject EPOCH_MISMATCH, detail 1000",
     response(A, 0, E, 4, [reject(0xFF, 15, E, 0)]), False),
    ("V12 req A: ResendReq(1, 1)", request(A, 4, E, B, [resend_req(1, 1)]), True),
    ("V13 resp A: resend of V2 (flags bit0, same resp_seq, new tag)",
     response(A, 1, E, 1, [ack(0, A1, 100_000, 0x11111111)], flags=1), False),
    ("V14 req A: CancelAll", request(A, 5, E, B, [cancel_all(0x77777777)]), True),
    ("V15 resp A: CancelAck x2, summary CancelAck(HANDLE_ALL, 2)",
     response(A, 6, E, 5, [cancel_ack(0, A2, 3, 0x77777777), cancel_ack(0, hdl(46, 1), 6, 0x77777777),
                           cancel_ack(0, 0xFFFFFFFF, 2, 0x77777777)]), False),
    ("V16 req A: New buy IOC 2 @ 100000 (arrives in overload)",
     request(A, 6, E, B, [new(of(0, tif=1), 100_000, 2, 0x88888888)]), True),
    ("V17 resp A: lane shed of V16, in-stream Reject BUSY at index 0, detail = expected 6, client_tag 0",
     response(A, 7, E, 6, [reject(0, 24, 6, 0)]), False),
    ("V18 req A: resend of V16, same pkt_seq and content, bit0 = 1",
     request(A, 6, E, B, [new(of(0, tif=1), 100_000, 2, 0x88888888)], flags=1), True),
    ("V19 redir A: DataRedirect data[0] down -> data[1], resend_from 5, tag under K_seq",
     data_redirect(A, 0, 1, 5, K_SEQ), False),
    ("V20 req A: New sell Day 1 @ 100005 + Heartbeat (arrives in overload)",
     request(A, 7, E, B, [new(of(1), 100_005, 1, 0x99999999), heartbeat()]), True),
    ("V21 resp A: lane shed of V20, BUSY run: one Reject BUSY per message, detail = expected 7",
     response(A, 9, E, 7, [reject(0, 24, 7, 0), reject(1, 24, 7, 0)]), False),
]
for name, pkt, req in V:
    dump(name, pkt, req)

v1, v10 = V[0][1], V[9][1]
bad = bytearray(v1); bad[32] ^= 0x01                                    # one bit of tag_seq
for what, ok in [("V1 verifies with K_SEQ", verify_request(v1, K_SEQ)),
                 ("V1 fails with K_OUT", not verify_request(v1, K_OUT)),
                 ("V1 with one tag bit flipped fails (bound source: close session)",
                  not verify_request(bytes(bad), K_SEQ)),
                 ("V10 tag_com = SipHash(K_COM, bytes 0..32)",
                  struct.unpack_from("<Q", v10, 40)[0] == siphash24(K_COM, v10[:32])),
                 ("V13 tag differs from V2 tag", V[12][1][-8:] != V[1][1][-8:]),
                 ("V17 is in stream (resp_seq 7), echo_pkt 6, Reject BUSY 24 at index 0, detail 6 >= 1, tag 0",
                  struct.unpack_from("<I", V[16][1], 4)[0] == 7 and V[16][1][16:18] == b"\x83\x00"
                  and struct.unpack_from("<HII", V[16][1], 18) == (24, 6, 0)
                  and struct.unpack_from("<I", V[16][1], 12)[0] == 6),
                 ("V18 has V16's logical content (D3) and verifies", V[17][1][16:32] == V[15][1][16:32]
                  and V[17][1][:9] == V[15][1][:9] and verify_request(V[17][1], K_SEQ)),
                 ("V19 tag = SipHash(K_SEQ, bytes 0..16), not K_OUT", struct.unpack_from("<Q", V[18][1], 16)[0]
                  == siphash24(K_SEQ, V[18][1][:16]) != siphash24(K_OUT, V[18][1][:16])),
                 ("V21 answers every message of V20 (count 2, Heartbeat included) with BUSY, detail 7, tag 0",
                  V[20][1][8] == V[19][1][8] == 2 and struct.unpack_from("<I", V[20][1], 12)[0] == 7
                  and all(V[20][1][16 + 16 * i:18 + 16 * i] == bytes([0x83, i])
                          and struct.unpack_from("<HII", V[20][1], 18 + 16 * i) == (24, 7, 0)
                          for i in range(2)))]:
    if not ok:
        raise SystemExit(f"FAILED: {what}")
    print(f"check OK: {what}")
