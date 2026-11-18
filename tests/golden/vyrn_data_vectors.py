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
  fetch_err <name> <hex> <reason>
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
    ]
    for name, b, why in bad:
        print(f"fetch_err {name} {hx(b)} {why}")
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
