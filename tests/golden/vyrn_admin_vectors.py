#!/usr/bin/env python3
"""VYRN 04-protocol v1 admin-channel vectors: the BASE-mode session open of 04 §4.4. Standard
library only.

Each frame is built field by field from the §4.4 tables: `len` u32 (the bytes after it), `type`
u16, then the body. Every integer is little-endian (01 §6). A `SocketAddrV4` is the IPv4 address
in network order, then the port u16 little-endian. The verdicts are written from §4.4: a receiver
refuses a frame with a nonzero reserved byte, an unknown `type`, or a `len` that does not match the
body (VR1). Nothing here implements `vyrn-admin`; the bytes come from the spec text alone.

Output, one vector per line after its `#` description:
    <id> <message> ok     <hex>   a conforming implementation builds these bytes and accepts them
    <id> <message> refuse <hex>   a conforming receiver refuses the frame
"""
import ipaddress
import struct

T_OPEN_REQ, T_OPEN_RESP = 0x0001, 0x8001            # 04 §4.4 types
SESSION_A, LANE_A, EPOCH = 0x00103007, 3, 1000      # 04 §11: session A on lane 3, epoch 1000
K_SEQ = bytes(range(0x00, 0x10))                    # 04 §11 test keys, box 0
K_OUT = bytes(range(0x10, 0x20))


def addr(ip: str, port: int) -> bytes:
    return ipaddress.IPv4Address(ip).packed + struct.pack("<H", port)


def frame(typ: int, body: bytes) -> bytes:
    return struct.pack("<IH", 2 + len(body), typ) + body


def open_req(account, cod, rate_tier, src, attest, books, timeout_ms, proto_version=2):
    body = struct.pack("<IHBB", account, proto_version, cod, rate_tier) + src
    body += struct.pack("<BBI", attest, len(books), timeout_ms)
    body += b"".join(struct.pack("<H", b) for b in books)
    assert len(body) == 20 + 2 * len(books)          # 04 §4.4: 20 + 2 × n_books bytes
    return body


def box_keys(index, order, recovery, k_seq, k_out, reserved=0):
    e = struct.pack("<BB", index, reserved) + order + recovery + k_seq + k_out
    assert len(e) == 46                              # 04 §4.4: 46 bytes each
    return e


def key_bundle(epoch, boundary_ts, home, seq_index, next_home, lane_move, failover, data, boxes,
               reserved=b"\x00\x00\x00"):
    assert len(failover) == len(boxes) and len(data) == 8
    kb = struct.pack("<IQBBBBB", epoch, boundary_ts, home, seq_index, next_home, len(boxes),
                     lane_move) + reserved
    assert len(kb) == 20
    return kb + bytes(failover) + b"".join(data) + b"".join(boxes)


def open_resp(session, lane, epoch, active_from_step, limits, bundle, reserved=0, limit_pad=None):
    body = struct.pack("<IBBHIQ", session, lane, reserved, len(limits), epoch, active_from_step)
    for i, (lid, value) in enumerate(limits):
        pad = bytes(7) if limit_pad is None or limit_pad[0] != i else limit_pad[1]
        body += struct.pack("<B", lid) + pad + struct.pack("<Q", value)
    assert len(body) == 20 + 16 * len(limits)
    return body + bundle


# A01: account 7 opens with COD on, tier T1, from 10.0.0.7:40000, Attest records on, books 1 and
# 2, timeout PROTO_TIMEOUT_DEFAULT_MS = 350.
REQ = open_req(7, 1, 1, addr("10.0.0.7", 40000), 1, [1, 2], 350)

# A02: the answer. Session A on lane 3, epoch 1000, active from step 1, limits max_open_orders
# (id 1) = 10_000 and new_rate (id 5) = 1_000_000 (10 §3.4). The key bundle: home 1 (TYO, 01),
# boundary at 8 h of TAI ns, box 0 is the sequencer, failover order 1, 2, 0, next home 2 (LDN),
# no lane move (0xFF), three boxes, data tier 10.0.1.1..8 on port 9000.
DATA = [addr(f"10.0.1.{i}", 9000) for i in range(1, 9)]


def boxes(reserved_at=None):
    out = []
    for i in range(3):
        ks = K_SEQ if i == 0 else bytes(range(0x30 + 0x20 * i, 0x40 + 0x20 * i))
        ko = K_OUT if i == 0 else bytes(range(0x40 + 0x20 * i, 0x50 + 0x20 * i))
        out.append(box_keys(i, addr(f"10.0.2.{i + 1}", 7000), addr(f"10.0.3.{i + 1}", 7001), ks,
                            ko, reserved=1 if reserved_at == i else 0))
    return out


def bundle(**kw):
    bx = kw.pop("boxes", boxes())
    return key_bundle(EPOCH, 28_800_000_000_000, 1, 0, 2, 0xFF, [1, 2, 0], DATA, bx, **kw)


LIMITS = [(1, 10_000), (5, 1_000_000)]
RESP = open_resp(SESSION_A, LANE_A, EPOCH, 1, LIMITS, bundle())
assert len(RESP) == 20 + 16 * 2 + 20 + 3 + 8 * 6 + 3 * 46

VECTORS = [
    ("A01", "OpenSessionReq", "account 7, COD on, tier 1, src 10.0.0.7:40000, attest, books 1 and "
     "2, timeout 350 ms (30 B frame)", frame(T_OPEN_REQ, REQ), "ok"),
    ("A02", "OpenSessionResp", "session 0x00103007 lane 3 epoch 1000 step 1, limits 1=10000 and "
     "5=1000000, a key bundle of 3 boxes", frame(T_OPEN_RESP, RESP), "ok"),
    ("B01", "OpenSessionReq", "n_books 2 but one book: len matches the bytes, not the body",
     frame(T_OPEN_REQ, REQ[:-2]), "refuse"),
    ("B02", "OpenSessionReq", "one trailing byte after the books, counted in len",
     frame(T_OPEN_REQ, REQ + b"\x00"), "refuse"),
    ("B03", "0x0002", "unknown type with an OpenSessionReq body", frame(0x0002, REQ), "refuse"),
    ("B04", "OpenSessionResp", "reserved byte 5 (after lane) = 1",
     frame(T_OPEN_RESP, open_resp(SESSION_A, LANE_A, EPOCH, 1, LIMITS, bundle(), reserved=1)),
     "refuse"),
    ("B05", "OpenSessionResp", "reserved byte 7 of the second limit entry = 1",
     frame(T_OPEN_RESP, open_resp(SESSION_A, LANE_A, EPOCH, 1, LIMITS, bundle(),
                                  limit_pad=(1, bytes(6) + b"\x01"))), "refuse"),
    ("B06", "OpenSessionResp", "key bundle reserved bytes = 00 00 01",
     frame(T_OPEN_RESP, open_resp(SESSION_A, LANE_A, EPOCH, 1, LIMITS,
                                  bundle(reserved=b"\x00\x00\x01"))), "refuse"),
    ("B07", "OpenSessionResp", "reserved byte of BoxKeys 2 = 1",
     frame(T_OPEN_RESP, open_resp(SESSION_A, LANE_A, EPOCH, 1, LIMITS,
                                  bundle(boxes=boxes(reserved_at=2)))), "refuse"),
    ("B08", "OpenSessionReq", "proto_version 1, never released (04 §12)",
     frame(T_OPEN_REQ, open_req(7, 1, 1, addr("10.0.0.7", 40000), 1, [1, 2], 350,
                                proto_version=1)), "refuse"),
]

print("# Generated by tests/golden/vyrn_admin_vectors.py; see tests/golden/README.md.")
for vid, name, what, raw, verdict in VECTORS:
    print(f"# {what}")
    print(f"{vid} {name} {verdict} {raw.hex()}")
