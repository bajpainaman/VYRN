#!/usr/bin/env python3
"""Writes feed_vectors.txt: vectors for the MBO-C, MBP-10, TOB, TRADES, STATS, MBO-W, SNAP and
retransmit layouts of spec/10-accounts-risk-md.md §7, and the [Guessing] readings that
crates/vyrn-md labels where the spec is silent.

Independent of the Rust code: records are packed with `struct` from the §7.5 table, and each
feed is a direct model of its rules (levels are re-aggregated from the order map at every
evaluation, not kept incrementally). BLAKE3 comes from the `b3sum` CLI.

Usage: python3 -I gen_feed_vectors.py <out dir>
"""

import struct
import subprocess
import sys

BOOK, EPOCH = 7, 0x00010003
EPOCH16 = EPOCH & 0xFFFF
FEED = {"mbo": 1, "mboc": 2, "mbp10": 3, "tob": 4, "trades": 5, "stats": 6, "snap": 7, "mbow": 8}
MAX_RECS, FLUSH_NS = 88, 1_000


def hx(b):
    return b.hex()


def header(feed, idx, count, seq, ts_base, step_base):
    return struct.pack("<HHHHQQQ", (feed << 8) | idx, count, BOOK, EPOCH16, seq, ts_base, step_base)


# --- records (§7.5) ---------------------------------------------------------------------------
def r_level(side, level, l):
    tick, qty, orders = l if l else (0, 0, 0)
    flags = side | (level << 1) | ((1 if orders == 0 else 0) << 5)
    return struct.pack("<BBHIQ", 0x30, flags, min(orders, 0xFFFF), tick, qty)


def r_trade(aggr, auction, dt, ds, ordinal, tick, qty):
    return struct.pack("<BBHHHII", 0x40, aggr | (auction << 1), dt, ds, ordinal, tick, qty)


def r_trade_bust(ds, ordinal, tick, qty):
    return struct.pack("<BBHHHII", 0x41, 0, 0, ds, ordinal, tick, qty)


def r_stat(sid, second, value):
    return struct.pack("<BBHIQ", 0x50, sid, 0, second, value)


def r_add(side, oid, tick, qty, ts_delta=0, flags_extra=0):
    return struct.pack("<BBHIII", 0x01, side | flags_extra, ts_delta, oid, tick, qty)


def b3_8(body):
    out = subprocess.run(["b3sum", "--no-names", "--raw", "-l", "8"], input=body,
                         capture_output=True, check=True).stdout
    assert len(out) == 8
    return out


# --- one channel's packetizer (§7.3 rules a-d) -------------------------------------------------
class Packer:
    def __init__(self, feed, idx=0):
        self.feed, self.idx = feed, idx
        self.recs, self.seq, self.sent, self.added = [], 1, False, False
        self.ts_base = self.step_base = self.opened_at = 0
        self.out = []

    def _open(self, ts_base, step_base, newest):
        self.ts_base, self.step_base, self.opened_at = ts_base, step_base, newest

    def _write(self, rec):
        assert len(rec) == 16
        self.recs.append(rec)
        self.added = True
        if len(self.recs) == MAX_RECS:
            self.close()

    def close(self):
        h = header(self.feed, self.idx, len(self.recs), self.seq, self.ts_base, self.step_base)
        self.out.append(h + b"".join(self.recs))
        self.seq += 1
        self.recs = []
        self.sent = True

    def put(self, rec, newest, step):
        if not self.recs:
            self._open(newest, step, newest)
        self._write(rec)

    def put_delta(self, ts, step, newest, f):
        if self.recs:
            dt, ds = ts - self.ts_base, step - self.step_base
            if 0 <= dt <= 0xFFFF and 0 <= ds <= 0xFFFF:
                self._write(f(dt, ds))
                return
            self.close()
        self._open(ts, step, newest)
        self._write(f(0, 0))

    def end_interval(self, newest):
        if self.recs and (not self.added or newest - self.opened_at >= FLUSH_NS):
            self.close()
        self.added = False

    def tick(self, newest, step):
        if not self.recs and not self.sent:
            self._open(newest, step, newest)
            self.close()
        self.sent = False

    def flush(self):
        if self.recs:
            self.close()

    def finish(self, newest, step):
        if not self.recs:
            self._open(newest, step, newest)
        self.close()


# --- event scripts ----------------------------------------------------------------------------




ENDS_GROUP = lambda kind: kind not in ("exec", "stepop")  # noqa: E731


# Script S1: levels and trades. Kinds: lane/stepop (add|del|reduce ...), step, exec, bust, tick.
S1 = """
100 lane add 0x01000001 0 100 5 100 0 0
200 lane add 0x02000001 0 100 3 200 0 0
300 lane add 0x03000001 1 102 4 300 0 0
400 lane add 0x01000002 1 103 6 400 0 0
500 tick
1500 lane reduce 0x01000001 100 2
2000 step 1 1 2 0x05000001
2000 exec 0 0 0x03000001 102 4
2000 exec 0 1 0x01000002 103 2
2100 lane add 0x02000002 0 101 1 2100 0 0
2200 step 2 9 1 0x05000002
2200 exec 1 0 0x02000002 101 1
2300 bust 1 1 103 2
2400 tick
13000 lane del 0x02000001 1 100 3
80000 step 3 2 0 0x05000003
80000 bust 1 0 102 4
"""




def load(script):
    out = []
    for line in script.strip().splitlines():
        w = line.split()
        ts, kind = int(w[0]), w[1]
        if kind in ("lane", "stepop"):
            out.append((ts, kind, w[2], [int(x, 0) for x in w[3:]]))
        else:
            out.append((ts, kind, None, [int(x, 0) for x in w[2:]]))
    return out


def script_lines(evs):
    lines = []
    for ts, kind, op, a in evs:
        parts = [str(ts), kind] + ([op] if op else []) + [str(x) for x in a]
        lines.append("ev " + " ".join(parts))
    return lines


class Book:
    def __init__(self):
        self.o = {}  # oid -> [side, tick, qty]

    def op(self, op, a):
        if op == "add":
            oid, side, tick, qty = a[0], a[1], a[2], a[3]
            assert oid not in self.o and qty > 0
            self.o[oid] = [side, tick, qty]
        elif op == "del":
            oid, _cause, tick, qty = a
            assert self.o[oid][1:] == [tick, qty]
            del self.o[oid]
        elif op == "reduce":
            oid, tick, after = a
            assert self.o[oid][1] == tick and 0 < after < self.o[oid][2]
            self.o[oid][2] = after

    def exec(self, maker, tick, qty):
        o = self.o[maker]
        assert o[1] == tick and 0 < qty <= o[2]
        o[2] -= qty
        if o[2] == 0:
            del self.o[maker]

    def levels(self, side, n):
        agg = {}
        for s, t, q in self.o.values():
            if s == side:
                q0, c0 = agg.get(t, (0, 0))
                agg[t] = (q0 + q, c0 + 1)
        ticks = sorted(agg, reverse=(side == 0))[:n]
        return [(t, agg[t][0], agg[t][1]) for t in ticks]


def levels_feed(evs, depth, window):
    feed = FEED["mbp10"] if depth == 10 else FEED["tob"]
    pk, book = Packer(feed), Book()
    pub = {0: [None] * depth, 1: [None] * depth}
    state = {"win": 0, "newest": 0, "step": 0}

    def publish(all_, newest, step):
        for side in (0, 1):
            cur = book.levels(side, depth) + [None] * depth
            cur = cur[:depth]
            if depth == 1:
                c, p = cur[0], pub[side][0]
                price = (c[0] if c else None) != (p[0] if p else None)
                if c != p and (price or all_):
                    pk.put(r_level(side, 0, c), newest, step)
                    pub[side][0] = c
                continue
            if all_:
                for i in range(depth):
                    if cur[i] != pub[side][i]:
                        pk.put(r_level(side, i, cur[i]), newest, step)
                        pub[side][i] = cur[i]

    for ts, kind, op, a in evs:
        newest, step = state["newest"], state["step"]
        if ENDS_GROUP(kind):
            w = ts // window
            new = w > state["win"]
            state["win"] = w
            publish(new, newest, step)
        state["newest"] = ts
        if kind == "step":
            pk.end_interval(newest)
            state["step"] = a[0]
        elif kind in ("lane", "stepop"):
            book.op(op, a)
        elif kind == "exec":
            book.exec(a[2], a[3], a[4])
        elif kind == "tick":
            pk.tick(ts, state["step"])
    publish(True, state["newest"], state["step"])
    pk.finish(state["newest"], state["step"])
    return pk.out


def trades_feed(evs):
    pk = Packer(FEED["trades"])
    newest = step = 0
    auction = 0
    for ts, kind, op, a in evs:
        before = newest
        newest = ts
        if kind == "step":
            pk.end_interval(before)
            step = a[0]
            auction = 1 if a[1] == 9 else 0
        elif kind == "exec":
            aggr, ordinal, _maker, tick, qty = a
            pk.put_delta(ts, step, ts,
                         lambda dt, ds: r_trade(aggr, auction, dt, ds, ordinal, tick, qty))
        elif kind == "bust":
            bstep, ordinal, tick, qty = a
            pk.put_delta(ts, bstep, ts, lambda dt, ds: r_trade_bust(ds, ordinal, tick, qty))
        elif kind == "tick":
            pk.tick(ts, step)
    pk.finish(newest, step)
    return pk.out


# Script S2: STATS over two seconds of order-stream time.
T0 = 1_000_000_000
S2 = f"""
{T0} status 2 {EPOCH}
{T0 + 10} lane add 0x01000001 0 100 5 {T0 + 10} 0 0
{T0 + 20} lane add 0x02000001 1 101 10 {T0 + 20} 0 0
{T0 + 30} lane add 0x03000001 1 102 2 {T0 + 30} 0 0
{T0 + 100} step 1 1 2 0x05000001
{T0 + 100} exec 0 0 0x02000001 101 4
{T0 + 100} exec 0 1 0x03000001 102 2
{T0 + 200} step 2 2 0 0x05000002
{T0 + 1_500_000_000} tick
{T0 + 1_600_000_000} step 3 1 1 0x05000003
{T0 + 1_600_000_000} exec 1 0 0x01000001 100 1
{T0 + 1_700_000_000} status 1 {EPOCH}
"""


def stats_feed(evs):
    pk = Packer(FEED["stats"])
    start = evs[0][0]
    st = {"newest": 0, "step": 0, "sec": 0, "status": None}
    cur = {}

    def reset():
        cur.clear()
        cur.update(trades=0, vol=0, notional=0, crosses=0, o=0, h=0, l=0, c=0)

    reset()

    def emit(newest, step):
        sec = st["sec"]
        put = lambda sid, v: pk.put(r_stat(sid, sec, v), newest, step)  # noqa: E731
        if cur["trades"]:
            put(1, cur["o"])
            put(2, cur["h"])
            put(3, cur["l"])
            put(4, cur["c"])
            put(5, cur["vol"])
            put(6, (cur["notional"] << 32) // cur["vol"])
            put(7, cur["trades"])
        put(8, cur["crosses"])
        if st["status"] is not None:
            put(9, st["status"])
        reset()

    for ts, kind, op, a in evs:
        newest, step = st["newest"], st["step"]
        if ENDS_GROUP(kind):
            s = (ts - start) // 1_000_000_000
            if s > st["sec"]:
                emit(newest, step)
                st["sec"] = s
        st["newest"] = ts
        if kind == "step":
            pk.end_interval(newest)
            st["step"] = a[0]
            if a[1] == 1:
                cur["crosses"] += 1
        elif kind == "exec":
            t, q = a[3], a[4]
            if cur["trades"] == 0:
                cur["o"] = cur["h"] = cur["l"] = t
            cur["h"], cur["l"], cur["c"] = max(cur["h"], t), min(cur["l"], t), t
            cur["vol"] += q
            cur["notional"] += t * q
            cur["trades"] += 1
        elif kind == "status":
            st["status"] = a[0]
        elif kind == "tick":
            pk.tick(ts, st["step"])
    emit(st["newest"], st["step"])
    pk.finish(st["newest"], st["step"])
    return pk.out


# Script S3: MBO-W with a window of 2 ticks.
S3 = """
100 lane add 0x01000001 0 100 1 100 0 0
110 lane add 0x02000001 0 97 1 110 0 0
120 lane add 0x03000001 0 99 2 120 0 0
130 lane add 0x01000002 1 105 1 130 0 0
140 lane add 0x02000002 1 110 1 140 0 0
150 lane del 0x01000001 1 100 1
200 step 1 1 1 0x05000001
200 exec 0 0 0x01000002 105 1
300 lane add 0x03000002 0 102 1 300 0 0
400 lane reduce 0x03000001 99 1
500 step 2 9 1 0x05000002
500 exec 1 0 0x03000001 99 1
600 tick
"""


def mbow(evs, width):
    full = {}  # oid -> dict
    out = []
    open_step = 0

    def inside(side, tick):
        ticks = [o["tick"] for o in full.values() if o["side"] == side]
        if not ticks:
            return True
        return tick + width >= max(ticks) if side == 0 else tick <= min(ticks) + width

    def synth(oid, o, enter):
        if enter:
            return ("add", [oid, o["side"], o["tick"], o["qty"], o["prio"], o["bbo"], o["auc"]])
        return ("del", [oid, 9, o["tick"], o["qty"]])

    for ts, kind, op, a in evs:
        by_step = False
        if kind in ("lane", "stepop"):
            by_step = kind == "stepop"
            oid = a[0]
            if op == "add":
                full[oid] = dict(side=a[1], tick=a[2], qty=a[3], prio=a[4], bbo=a[5], auc=a[6],
                                 vis=False)
                full[oid]["vis"] = inside(a[1], a[2])
                show = full[oid]["vis"]
            elif op == "del":
                show = full[oid]["vis"]
                del full[oid]
            else:
                full[oid]["qty"] = a[2]
                show = full[oid]["vis"]
            if show:
                out.append((ts, kind, op, a))
        elif kind == "exec":
            by_step = True
            m = full[a[2]]
            if not m["vis"]:
                out.append((ts, "stepop") + synth(a[2], m, True))
            out.append((ts, kind, None, a))
            m["qty"] -= a[4]
            m["vis"] = True
            if m["qty"] == 0:
                del full[a[2]]
        else:
            if kind == "step":
                open_step = a[0]
            out.append((ts, kind, None, a))
            continue
        kind_out = "stepop" if by_step and open_step > 0 else "lane"
        moved = sorted((o["side"], o["tick"], oid) for oid, o in full.items()
                       if inside(o["side"], o["tick"]) != o["vis"])
        for _s, _t, oid in moved:
            o = full[oid]
            enter = not o["vis"]
            out.append((ts, kind_out) + synth(oid, o, enter))
            o["vis"] = enter
    visible = sorted((oid, o["side"], o["tick"], o["qty"], o["prio"])
                     for oid, o in full.items() if o["vis"])
    return out, visible


# --- MBO-C (crate reading of §7.5) -------------------------------------------------------------
def var(v):
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def zz(d):
    return (d << 1) if d >= 0 else ((-d) << 1) - 1


def mboc(pkt):
    feed_idx, count = struct.unpack_from("<HH", pkt, 0)
    assert feed_idx >> 8 == 1
    out = bytearray(pkt[:32])
    struct.pack_into("<H", out, 0, (2 << 8) | (feed_idx & 0xFF))
    prev_oid = prev_tick = 0
    for i in range(count):
        r = pkt[32 + 16 * i: 48 + 16 * i]
        t = r[0]
        out += r[:2]
        if t in (0x01, 0x02, 0x03, 0x11):
            x16, oid, tick, qty = struct.unpack("<HIII", r[2:])
            out += var(zz(oid - prev_oid)) + var(zz(tick - prev_tick)) + var(qty)
            prev_oid, prev_tick = oid, tick
            if t in (0x01, 0x11):
                out += var(x16)
        elif t == 0x0E:
            out += var(struct.unpack("<Q", r[8:])[0])
        elif t == 0x10:
            n_exec, step, taker = struct.unpack("<HQI", r[2:])
            out += var(n_exec) + var(step) + var(taker)
        elif t == 0x12:
            ordinal, step = struct.unpack_from("<H", r, 2)[0], struct.unpack("<Q", r[8:])[0]
            out += var(ordinal) + var(step)
        elif t in (0x20, 0x21):
            low, step = struct.unpack("<IQ", r[4:])
            out += var(low) + var(step)
        else:
            raise ValueError(t)
    return bytes(out)


def mboc_inputs(mbo_vectors):
    pkts = [bytes.fromhex(l.split()[1]) for l in mbo_vectors.splitlines() if l.startswith("pkt ")]
    recs = [
        struct.pack("<BBHQI", 0x10, 9, 3, 0x0102030405060708, 0xFFFFFFFF),
        struct.pack("<BBHIII", 0x11, 1, 2, 0x05000009, 100, 300),
        struct.pack("<BBHIII", 0x11, 1, 1, 0x02000001, 99, 1),  # negative deltas
        struct.pack("<BBHIQ", 0x12, 0, 1, 0, 2),
        struct.pack("<BBHIQ", 0x20, 2, 0, EPOCH, 7),
        struct.pack("<BBHIQ", 0x21, 3, 0, 0xCAFEBABE, 1 << 63),
        struct.pack("<BBHIII", 0x01, 5, 65535, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ]
    pkts.append(header(1, 4, len(recs), 9, 5000, 3) + b"".join(recs))
    lane = [struct.pack("<B7xQ", 0x0E, 300), struct.pack("<BBHIII", 0x02, 9, 0, 0x01000007, 50, 4)]
    pkts.append(header(1, 3, len(lane), 2, 6000, 299) + b"".join(lane))
    return pkts


# --- snapshots (crate reading of §7.6) ---------------------------------------------------------
def snap_pkts(pk, as_of, now, orders, resume, feed=1):
    recs = [struct.pack("<BBHIQ", 0x60, feed, 0, len(orders) + len(resume), as_of)]
    recs += [r_add(side, oid, tick, qty) for oid, side, tick, qty in orders]
    recs += [struct.pack("<BBHIQ", 0x61, ch, rec, 0, seq) for ch, rec, seq in resume]
    recs.append(struct.pack("<B7x", 0x62) + b3_8(b"".join(recs)))
    for r in recs:
        pk.put(r, now, as_of)
    pk.flush()


def main(out_dir):
    L = ["# Feed vectors (spec/10-accounts-risk-md.md §7.2-§7.7 and the crate's labeled readings).",
         "# Written by gen_feed_vectors.py, an independent model packing bytes with struct.",
         "# Blocks: `case <name> <feed> [param]` ... `endcase`. Inside: `ev` input events (format",
         "# of mbo_vectors.txt, plus `bust <step> <ordinal> <tick> <qty>` and `status <code>",
         "# <epoch>`), `pkt <hex>` expected packets in emission order, `out` expected MBO-W events,",
         "# `order` the expected final book, `in <hex>` an MBO packet (mboc), `snap <as_of> <now>`,",
         "# `sorder <oid> <side> <tick> <qty>`, `resume <ch> <rec> <seq>`, `req <hex> <fields>`.",
         f"# book {BOOK}, epoch {EPOCH:#x} in every case."]

    def case(name, feed, body, param=""):
        L.append(f"case {name} {feed}{(' ' + str(param)) if param != '' else ''}")
        L.extend(body)
        L.append("endcase")

    s1 = load(S1)
    case("levels_s1", "mbp10", script_lines(s1) + [f"pkt {hx(p)}" for p in levels_feed(s1, 10, 10_000)])
    case("levels_s1", "tob", script_lines(s1) + [f"pkt {hx(p)}" for p in levels_feed(s1, 1, 1_000)])
    case("trades_s1", "trades", script_lines(s1) + [f"pkt {hx(p)}" for p in trades_feed(s1)])
    s2 = load(S2)
    case("stats_s2", "stats", script_lines(s2) + [f"pkt {hx(p)}" for p in stats_feed(s2)])
    s3 = load(S3)
    out, vis = mbow(s3, 2)
    body = script_lines(s3) + ["out" + l[2:] for l in script_lines(out)]
    body += [f"order {' '.join(str(x) for x in v)}" for v in vis]
    case("window_s3", "mbow", body, 2)

    with open(f"{out_dir}/mbo_vectors.txt") as f:
        mbo_text = f.read()
    for i, p in enumerate(mboc_inputs(mbo_text)):
        case(f"mboc_{i}", "mboc", [f"in {hx(p)}", f"pkt {hx(mboc(p))}"])

    for name, orders, resume in [
        ("small", [(0x01000005, 0, 101, 3), (0x02000001, 0, 100, 2), (0x03000009, 1, 103, 7)],
         [(0, 0, 4), (1, 2, 9), (2, 0, 1), (3, 1, 3), (4, 5, 12)]),
        ("two_packets", [(0x01000000 + i, i % 2, 100 + (i // 2) * (1 if i % 2 else -1), 1 + i)
                         for i in range(90)],
         [(c, 0, 1) for c in range(5)]),
    ]:
        pk = Packer(FEED["snap"], 1)
        snap_pkts(pk, 42, 7_000, orders, resume)
        body = [f"snap 42 7000"] + [f"sorder {o} {s} {t} {q}" for o, s, t, q in orders]
        body += [f"resume {c} {r} {s}" for c, r, s in resume] + [f"pkt {hx(p)}" for p in pk.out]
        case(f"snap_{name}", "snap", body)

    req = struct.pack("<HHHHQQ", (4 << 8) | 0, BOOK, EPOCH16, 0, 5, 9)
    case("retx_req", "retx", [f"req {hx(req)} {(4 << 8)} {BOOK} {EPOCH16} 5 9"])

    with open(f"{out_dir}/feed_vectors.txt", "w") as f:
        f.write("\n".join(L) + "\n")
    print("ok", sum(1 for l in L if l.startswith("case ")), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
