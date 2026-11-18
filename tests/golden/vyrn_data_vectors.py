#!/usr/bin/env python3
"""Golden vectors for the data tier (spec/07-replication.md §5.2-§5.5; crates/vyrn-data docs).

Every byte is written here from the layouts in crates/vyrn-data/src/lib.rs, with no Rust
involved, so any implementation of the data frame, the fetch request and the dedupe window can
check itself against vyrn_data_vectors.out. Every multi-byte field is little-endian.

Line formats (space-separated; '-' for an empty list):
  data_ok   <name> <kind> <book> <epoch16> <data_seq> <src> <pkt,pkt,...> <frame hex>
  data_err  <name> <frame hex> <reason>
  fetch_ok  <name> key <session> <pkt_seq> <hex>
  fetch_ok  <name> range <dst> <from> <to> <hex>
  fetch_ok  <name> block <height> <hex>
  fetch_ok  <name> redirect <session> <resend_from> <down> <to> <hex>
  fetch_err <name> <hex> <reason>
  fetch_auth <name> <key hex> <32-byte fetch hex> <40-byte sealed hex>
  fetch_auth_err <name> <key hex> <hex> <reason>
  redirect  <name> <key hex> <down> <to> <session> <resend_from> <24-byte hex>
  redirect_err <name> <key hex> <hex> <reason>
  dedupe    <name> <pkt_seq,...> <verdict,...>   (verdicts: New Repeat Late; one session)
"""
import struct

DATA_MAGIC = 0x4450
FETCH_MAGIC = 0x4650


def entry(p):
    pad = b"\x00" if len(p) % 2 else b""
    return struct.pack("<H", len(p)) + p + pad


def data_frame(kind, book, epoch16, seq, src, pkts, n_pkts=None, body_len=None, reserved=0,
               magic=DATA_MAGIC, version=1, body=None):
    if body is None:
        body = b"".join(entry(p) for p in pkts)
    n = len(pkts) if n_pkts is None else n_pkts
    bl = len(body) if body_len is None else body_len
    hdr = struct.pack("<HBBHHQBBHI", magic, version, kind, book, epoch16, seq, src, n, bl,
                      reserved)
    assert len(hdr) == 24
    return hdr + body


def fetch(kind, body24, magic=FETCH_MAGIC, version=1, reserved=0):
    b = struct.pack("<HBBI", magic, version, kind, reserved) + body24
    return b


def key(session, pkt_seq):
    return fetch(1, struct.pack("<II", session, pkt_seq) + bytes(16))


def rng(dst, frm, to):
    return fetch(2, bytes([dst]) + bytes(7) + struct.pack("<QQ", frm, to))


def block(h):
    return fetch(3, struct.pack("<Q", h) + bytes(16))


def resend(session, frm, down, to, tail=bytes(14)):
    return fetch(4, struct.pack("<IIBB", session, frm, down, to) + tail)


M64 = (1 << 64) - 1


def rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash24(key, msg):
    """SipHash-2-4 (Aumasson and Bernstein, 2012), written from the paper."""
    k0, k1 = struct.unpack("<QQ", key)
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D, k0 ^ 0x6C7967656E657261,
         k1 ^ 0x7465646279746573]

    def rnd():
        v[0] = (v[0] + v[1]) & M64; v[1] = rotl(v[1], 13); v[1] ^= v[0]; v[0] = rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & M64; v[3] = rotl(v[3], 16); v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & M64; v[3] = rotl(v[3], 21); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & M64; v[1] = rotl(v[1], 17); v[1] ^= v[2]; v[2] = rotl(v[2], 32)

    full = len(msg) - len(msg) % 8
    blocks = [struct.unpack("<Q", msg[i:i + 8])[0] for i in range(0, full, 8)]
    tail = msg[full:] + bytes(7 - len(msg) % 8) + bytes([len(msg) & 0xFF])
    blocks.append(struct.unpack("<Q", tail)[0])
    for m in blocks:
        v[3] ^= m
        rnd(); rnd()
        v[0] ^= m
    v[2] ^= 0xFF
    for _ in range(4):
        rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def seal(b, k):
    return b + struct.pack("<Q", siphash24(k, b))


# The paper's appendix vector: key 00..0f, message 00..0e, tag a129ca6149be45e5.
assert siphash24(bytes(range(16)), bytes(range(15))) == 0xA129CA6149BE45E5


def window(seqs):
    seen, hi, out = set(), 0, []
    for q in seqs:
        if hi >= 256 and q <= hi - 256:
            out.append("Late")
        elif q in seen:
            out.append("Repeat")
        else:
            seen.add(q)
            hi = max(hi, q)
            out.append("New")
    return out


def hx(b):
    return b.hex()


def main():
    print("# " + __doc__.strip().splitlines()[0])
    p1 = bytes(range(48))          # a 1-message request's length
    p2 = bytes(range(100, 133))    # odd length: one pad byte
    p3 = bytes([0xAA] * 192)       # MAX_REQ_PAYLOAD
    ok = [
        ("one_packet", 1, 3, 9, 1, 2, [p1]),
        ("odd_len_pad", 1, 0x0102, 0xFFFF, 0x0123456789ABCDEF, 0, [p2, p1]),
        ("heartbeat", 2, 0, 0, 77, 4, []),
        ("fetch_resp_empty", 3, 0, 0, (5 << 32) | 6, 1, []),
        ("fetch_resp_max", 3, 7, 1, 12, 3, [p3]),
    ]
    for name, kind, book, e16, seq, src, pkts in ok:
        f = data_frame(kind, book, e16, seq, src, pkts)
        pk = ",".join(hx(p) for p in pkts) or "-"
        print(f"data_ok {name} {kind} {book} {e16} {seq} {src} {pk} {hx(f)}")
    good = data_frame(1, 3, 9, 1, 2, [p1])
    err = [
        ("short", good[:23], "Short"),
        ("magic", data_frame(1, 3, 9, 1, 2, [p1], magic=0x4451), "Magic"),
        ("version", data_frame(1, 3, 9, 1, 2, [p1], version=2), "Version"),
        ("kind_0", data_frame(0, 3, 9, 1, 2, [p1]), "Kind"),
        ("kind_4", data_frame(4, 3, 9, 1, 2, [p1]), "Kind"),
        ("reserved", data_frame(1, 3, 9, 1, 2, [p1], reserved=1), "Reserved"),
        ("body_len_long", data_frame(1, 3, 9, 1, 2, [p1], body_len=51), "BodyLen"),
        ("body_len_short", data_frame(1, 3, 9, 1, 2, [p1], body_len=49), "BodyLen"),
        ("n_pkts", data_frame(1, 3, 9, 1, 2, [p1], n_pkts=2), "Count"),
        ("truncated_entry", data_frame(1, 3, 9, 1, 2, [p1],
                                       body=struct.pack("<H", 60) + p1), "Truncated"),
        ("lone_len_byte", data_frame(1, 3, 9, 1, 2, [p1], body=entry(p1) + b"\x01"),
         "Truncated"),
        ("bad_pad", data_frame(1, 3, 9, 1, 2, [p2], body=struct.pack("<H", 33) + p2 + b"\x01"),
         "Pad"),
        ("hb_with_packet", data_frame(2, 0, 0, 1, 2, [p1]), "HbBody"),
    ]
    for name, f, why in err:
        print(f"data_err {name} {hx(f)} {why}")
    print(f"fetch_ok key key 305419896 7 {hx(key(0x12345678, 7))}")
    print(f"fetch_ok range range 2 10 20 {hx(rng(2, 10, 20))}")
    print(f"fetch_ok block block 1099511627776 {hx(block(1 << 40))}")
    print(f"fetch_ok redirect redirect 4294967295 5 0 7 {hx(resend(0xFFFFFFFF, 5, 0, 7))}")
    bad = [
        ("short", key(1, 1)[:31], "Short"),
        ("long", key(1, 1) + b"\x00", "Short"),
        ("magic", fetch(1, struct.pack("<II", 1, 1) + bytes(16), magic=0x4450), "Magic"),
        ("version", fetch(1, struct.pack("<II", 1, 1) + bytes(16), version=0), "Version"),
        ("kind", fetch(9, bytes(24)), "Kind"),
        ("reserved", fetch(1, struct.pack("<II", 1, 1) + bytes(16), reserved=1), "Reserved"),
        ("key_tail", fetch(1, struct.pack("<II", 1, 1) + bytes(15) + b"\x01"), "Reserved"),
        ("range_pad", fetch(2, bytes([1, 1]) + bytes(6) + struct.pack("<QQ", 1, 2)), "Reserved"),
        ("block_tail", fetch(3, struct.pack("<Q", 1) + b"\x01" + bytes(15)), "Reserved"),
        ("redirect_tail", resend(1, 1, 0, 1, tail=bytes(13) + b"\x01"), "Reserved"),
        ("redirect_same", resend(1, 1, 2, 2), "Position"),
        ("redirect_to_8", resend(1, 1, 0, 8), "Position"),
    ]
    for name, b, why in bad:
        print(f"fetch_err {name} {hx(b)} {why}")
    kf = bytes(range(0x40, 0x50))
    for name, b in [("key", key(0x12345678, 7)), ("range", rng(2, 10, 20)),
                    ("block", block(1 << 40)), ("redirect", resend(9, 4, 1, 2))]:
        print(f"fetch_auth {name} {hx(kf)} {hx(b)} {hx(seal(b, kf))}")
    good = seal(key(1, 1), kf)
    for name, b, why in [
        ("bad_tag", good[:39] + bytes([good[39] ^ 1]), "Tag"),
        ("other_key", seal(key(1, 1), bytes(16)), "Tag"),
        ("plain", key(1, 1), "Short"),
        ("tagged_bad_body", seal(fetch(9, bytes(24)), kf), "Kind"),
    ]:
        print(f"fetch_auth_err {name} {hx(kf)} {hx(b)} {why}")
    kr = bytes(range(0x60, 0x70))

    def redirect(down, to, session, frm, key=kr, magic=0x5244, version=1, reserved=b"\x00" * 3):
        body = struct.pack("<HBBB", magic, version, down, to) + reserved + struct.pack(
            "<II", session, frm)
        return seal(body, key)

    for name, args in [("first", (1, 3, 5, 1)), ("wide", (4, 0, 0xFFFFFFFF, 0x80000001))]:
        print(f"redirect {name} {hx(kr)} {' '.join(map(str, args))} {hx(redirect(*args))}")
    good = redirect(1, 2, 7, 9)
    for name, b, why in [
        ("bad_tag", good[:23] + bytes([good[23] ^ 1]), "Tag"),
        ("other_key", redirect(1, 2, 7, 9, key=bytes(16)), "Tag"),
        ("short", good[:23], "Short"),
        ("magic", redirect(1, 2, 7, 9, magic=0x4450), "Magic"),
        ("version", redirect(1, 2, 7, 9, version=2), "Version"),
        ("reserved", redirect(1, 2, 7, 9, reserved=b"\x00\x01\x00"), "Reserved"),
    ]:
        print(f"redirect_err {name} {hx(kr)} {hx(b)} {why}")
    cases = [
        ("in_order", [1, 2, 3, 4]),
        ("repeat_and_reorder", [1, 3, 2, 3, 1, 5, 4]),
        ("word_edges", [64, 1, 63, 65, 128, 129, 65, 64]),
        ("window_edge", [300, 45, 44, 299, 300, 301, 46, 45]),
        ("jump_clears", [1, 2, 1000, 2, 745, 744, 1000]),
    ]
    for name, seqs in cases:
        print(f"dedupe {name} {','.join(map(str, seqs))} {','.join(window(seqs))}")


if __name__ == "__main__":
    main()
