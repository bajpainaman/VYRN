#!/usr/bin/env python3
"""Writes dc_vectors.txt: drop-copy vectors for spec/10-accounts-risk-md.md §8 (the 48-byte
record, the stream rules of §8.4, the session wire and subscription rule of §8.5).

Independent of the Rust code: records and frames are packed with `struct` from the §8.1 and
§8.5 tables, each stream is a direct model of the §8.4 rules, Ed25519 is the RFC 8032
reference algorithm over hashlib's SHA-512, and BLAKE3 comes from the `b3sum` CLI.

Usage: python3 -I gen_dc_vectors.py <out dir>
"""

import copy
import hashlib
import struct
import subprocess
import sys

BOOK = 7
DENOM = 1_000_000
FILL, ACK, CANCEL, OUT, ALLOC, FINAL, REVERT, EOD, SETTLED, ROUTE = range(1, 11)
SELL, TAKER, DURABLE = 1, 2, 4
CONT, CROSS = 1, 2
MAKER, TAKER_ROLE = 2, 0
OUT_STP = 2


def b3(body):
    return subprocess.run(["b3sum", "--no-names", "--raw"], input=body,
                          capture_output=True, check=True).stdout


# --- Ed25519, RFC 8032 §5.1 -----------------------------------------------------------------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
GY = 4 * pow(5, P - 2, P) % P


def recover_x(y, sign):
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x & 1 != sign:
        x = P - x
    return x


G = (recover_x(GY, 0), GY, 1, recover_x(GY, 0) * GY % P)


def padd(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % P
    B = (a[1] + a[0]) * (b[1] + b[0]) % P
    C = 2 * a[3] * b[3] * D % P
    Dd = 2 * a[2] * b[2] % P
    E, F, Gg, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, Gg * H % P, F * Gg % P, E * H % P)


def pmul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = padd(q, pt)
        pt = padd(pt, pt)
        s >>= 1
    return q


def penc(pt):
    zi = pow(pt[2], P - 2, P)
    x, y = pt[0] * zi % P, pt[1] * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def secret(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def pubkey(seed):
    return penc(pmul(secret(seed)[0], G))


def sign(seed, msg):
    a, prefix = secret(seed)
    A = penc(pmul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    R = penc(pmul(r, G))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % L
    return R + int.to_bytes((r + k * a) % L, 32, "little")


# --- records (§8.1) ---------------------------------------------------------------------------
def rec(kind, flags, ordinal, account, step, session, resp_seq, handle, tick, qty, tag, fee):
    return struct.pack("<BBHIQIIIIIIq", kind, flags | DURABLE, ordinal, account, step, session,
                       resp_seq, handle, tick, qty, tag, fee)


def stage(kind, account, step, height):
    return struct.pack("<BBHIQIIQ", kind, DURABLE, 0, account, step, 0, 0, height) + bytes(16)


def alloc_rec(account, step, asset, debit, amount):
    return struct.pack("<BBHIQIIQ", ALLOC, DURABLE, asset | (2 if debit else 0), account, step,
                       0, 0, amount) + bytes(16)


def route_rec(account, lane_seq, index, session, resp_seq, asset, to_book, amount, tag, fee_):
    return (struct.pack("<BBHIQIIQHBB", ROUTE, DURABLE, index, account, lane_seq, session,
                        resp_seq, amount, to_book, asset, 0)
            + struct.pack("<Iq", tag, fee_))


def revert_rec(b):
    return bytes([REVERT]) + b[1:36] + struct.pack("<I", b[0]) + b[40:]


def eod(account, ordinal, words):
    return struct.pack("<BBHI5Q", EOD, DURABLE, ordinal, account, *[w % 2**64 for w in words])


def eod_hash(account, n, h):
    return struct.pack("<BBHIQ", EOD, DURABLE, 3, account, n) + h


def fee(n, ppm):
    if ppm >= 0:
        return -(-n * ppm // DENOM)
    return -(n * -ppm // DENOM)


# --- the stream model (§8.4) ------------------------------------------------------------------
class Model:
    def __init__(self, tick_size, accts):
        self.ts = tick_size
        self.accts = accts  # acct -> dict(master, sess, tp, mp, mi, mc)
        self.sess = {a["sess"]: k for k, a in accts.items()}
        self.streams = {}
        for k, a in accts.items():
            self.streams[(k, 0)] = self.new_stream()
            if a["master"] is not None:
                self.streams[(a["master"], 1)] = self.new_stream()
        self.orders = {}
        self.released = 0
        self.finals = []
        self.final_step = 0
        self.last_final = None
        self.allocs = []
        self.run = None
        # State after each released step, for a revert (an independent stand-in for the undo log).
        self.snaps = {0: (copy.deepcopy(self.orders), None)}
        self.rel = 0  # release step of the records being emitted
        self.out = []  # (acct, master, seq, bytes)

    @staticmethod
    def new_stream():
        return dict(seq=0, canon=[], pend=[], unsettled=[], fills=0, bb=0, bs=0, qb=0, qs=0,
                    fees=0, msg=0)

    def targets(self, acct):
        t = [(acct, 0)]
        m = self.accts[acct]["master"]
        if m is not None:
            t.append((m, 1))
        if (acct, 1) in self.streams:
            t.append((acct, 1))
        return t

    def push(self, sid, b):
        s = self.streams[sid]
        s["seq"] += 1
        if b[0] not in (FINAL, SETTLED, REVERT):
            s["pend"].append((self.rel, "rec", b))
        self.out.append((sid[0], sid[1], s["seq"], b))

    def emit(self, acct, kind, side, taker, ordinal, step, sess, rs, handle, tick, qty, tag, f):
        b = rec(kind, side | (TAKER if taker else 0), ordinal, acct, step, sess, rs, handle,
                tick, qty, tag, f)
        for sid in self.targets(acct):
            self.push(sid, b)

    def commit(self, sid, upto):
        """Records and message fees released at a step <= upto become canonical."""
        s = self.streams[sid]
        while s["pend"] and s["pend"][0][0] <= upto:
            rel, what, x = s["pend"].pop(0)
            if not s["unsettled"] or s["unsettled"][-1] != rel:
                s["unsettled"].append(rel)
            if what == "msg":
                s["msg"] += x
                continue
            s["canon"].append(x)
            if x[0] == FILL:
                side = x[1] & SELL
                tick, qty = struct.unpack("<II", x[28:36])
                (f,) = struct.unpack("<q", x[40:48])
                s["fills"] += 1
                if side == 0:
                    s["bb"] += qty
                    s["qb"] += qty * tick * self.ts
                else:
                    s["bs"] += qty
                    s["qs"] += qty * tick * self.ts
                s["fees"] += f

    def lane_op(self, lane, seq, sess, rs, msg, r):
        self.rel = self.released + 1
        acct = self.sess.get(sess)
        if r[0] == "ack":
            _, idx, h, tick, tag = r
            side, qty = msg[1], msg[3]
            self.orders[(lane, h)] = dict(acct=acct, sess=sess, side=side, tick=tick, open=qty,
                                          tag=tag)
            out = (ACK, side, idx, h, tick, qty, tag)
        elif r[0] == "cxl":
            _, idx, h, c, tag = r
            o = self.orders[(lane, h)]
            o["open"] -= c
            assert o["open"] >= 0
            if o["open"] == 0:
                del self.orders[(lane, h)]
            out = (CANCEL, o["side"], idx, h, o["tick"], c, tag)
        elif r[0] == "out":
            _, idx, _cause, h, q, tag = r
            if (lane, h) in self.orders:
                o = self.orders.pop((lane, h))
                out = (OUT, o["side"], idx, h, o["tick"], q, tag)
            else:
                # A New the lane took out at once (STP CancelNewest) never rested: its own side
                # and limit tick.
                assert msg[0] == "new"
                out = (OUT, msg[1], idx, h, msg[2], q, tag)
        else:
            return
        if acct is not None:
            kind, side, idx, h, tick, qty, tag = out
            self.emit(acct, kind, side, False, idx, seq, sess, rs, h, tick, qty, tag, 0)

    def step(self, step, kind, flags, src, tx):
        self.released = step
        self.rel = step
        if src is not None:
            self.step_src(step, kind, flags, src, tx)
        self.flush_allocs(step)
        self.flush(False)
        self.snaps[step] = (copy.deepcopy(self.orders), copy.deepcopy(self.run))

    def route(self, acct, *a):
        self.rel = self.released + 1
        for sid in self.targets(acct):
            self.push(sid, route_rec(acct, *a))

    def alloc(self, step, acct, asset, debit, amount):
        self.allocs.append((step, acct, asset, debit, amount))
        self.flush_allocs(self.released)
        # After its block's DC_FINAL went out, an allocation gets that DC_FINAL again.
        if self.last_final is not None:
            self.final_to(*self.last_final)

    def flush_allocs(self, upto):
        while self.allocs and self.allocs[0][0] <= upto:
            step, acct, asset, debit, amount = self.allocs.pop(0)
            self.rel = step
            for sid in self.targets(acct):
                self.push(sid, alloc_rec(acct, step, asset, debit, amount))

    def revert(self, kept):
        assert kept >= self.final_step
        for sid in sorted(self.streams):
            s = self.streams[sid]
            gone = [p for p in s["pend"] if p[0] > kept]
            s["pend"] = [p for p in s["pend"] if p[0] <= kept]
            for _, what, x in gone:
                if what == "rec":
                    self.push(sid, revert_rec(x))
        orders, run = self.snaps[kept]
        self.orders, self.run = copy.deepcopy(orders), copy.deepcopy(run)
        self.snaps = {k: v for k, v in self.snaps.items() if k <= kept}
        self.allocs = [a for a in self.allocs if a[0] <= kept]
        self.finals = [f for f in self.finals if f[1] <= kept]
        self.released = min(self.released, kept)
        self.rel = self.released

    def settled(self, height, last):
        assert last <= self.final_step
        for sid in sorted(self.streams):
            u = self.streams[sid]["unsettled"]
            if u and u[0] <= last:
                while u and u[0] <= last:
                    u.pop(0)
                self.push(sid, stage(SETTLED, sid[0], last, height))

    def step_src(self, step, kind, flags, src, tx):
        slane, sseq, ssess, msg = src
        _, side, limit, qty, tag = msg
        tacct = self.sess.get(ssess)
        if flags & CONT == 0 and kind != "shed" and tacct is not None:
            a = self.accts[tacct]
            f = a["mc"] if flags & CROSS else a["mi"]
            for sid in self.targets(tacct):
                self.streams[sid]["pend"].append((self.rel, "msg", f))
        thdr = next((h for h, _ in tx if h[0] == TAKER_ROLE), None)
        # Record tuples: ("fill", index, liq, handle, tick, qty), ("ack", index, handle, tick,
        # tag), ("out", index, cause, handle, qty, tag), ("rej", index, reason).
        hpos = {"fill": 3, "ack": 2, "out": 3}
        thandle = next((r[hpos[r[0]]] for h, r in tx if h[0] == TAKER_ROLE and r[0] in hpos),
                       None)
        matches = [(h, r) for h, r in tx if h[0] == MAKER and r[0] == "fill"]
        tn = sum(r[5] * r[4] * self.ts for _, r in matches)
        tfee = fee(tn, self.accts[tacct]["tp"]) if tacct is not None else 0
        filled = self.run[1] if self.run and self.run[0] == (slane, sseq) else 0
        k = 0
        for h, r in tx:
            if h[0] != MAKER:
                continue
            _, mlane, msess, mrs = h
            if r[0] == "fill":
                _, _idx, _liq, mh, tick, q = r
                o = self.orders[(mlane, mh)]
                o["open"] -= q
                assert o["open"] >= 0 and o["side"] != side
                if o["open"] == 0:
                    del self.orders[(mlane, mh)]
                filled += q
                last = k + 1 == len(matches)
                if tacct is not None and thandle is not None:
                    self.emit(tacct, FILL, side, True, k, step, ssess, thdr[3], thandle, tick, q,
                              tag, tfee if last else 0)
                if o["acct"] is not None:
                    mp = self.accts[o["acct"]]["mp"]
                    self.emit(o["acct"], FILL, o["side"], False, k, step, o["sess"], mrs, mh,
                              tick, q, o["tag"], fee(q * tick * self.ts, mp))
                k += 1
            elif r[0] == "out" and r[2] == OUT_STP:
                _, idx, _c, mh, q, otag = r
                o = self.orders.pop((mlane, mh))
                if o["acct"] is not None:
                    self.emit(o["acct"], OUT, o["side"], False, idx, step, o["sess"], mrs, mh,
                              o["tick"], q, otag, 0)
        for h, r in tx:
            if h[0] != TAKER_ROLE:
                continue
            if r[0] == "ack":
                _, idx, th, tick, atag = r
                left = qty - filled
                self.orders[(slane, th)] = dict(acct=tacct, sess=ssess, side=side, tick=tick,
                                                open=left, tag=atag)
                if tacct is not None:
                    self.emit(tacct, ACK, side, False, idx, sseq, ssess, h[3], th, tick, left,
                              atag, 0)
            elif r[0] == "out":
                _, idx, _c, th, q, otag = r
                if tacct is not None:
                    self.emit(tacct, OUT, side, True, idx, step, ssess, h[3], th, limit, q, otag,
                              0)
        self.run = ((slane, sseq), filled)

    def rescan_taker(self, step, lane, seq, s, prior, msg, fills, rest, makers):
        """A join a Rescan step swept as a taker (§7.9 item 11, §8.4 item 4): per match, the
        taker's and the maker's DC_FILL at the match's (step, ordinal); the taker's step fee on
        its last one; no message fee (a join, §5.3); then DC_ACK of what rests."""
        self.rel = step
        _, side, _limit, qty, tag = msg
        tacct = self.sess.get(s)
        first_rs = {}
        for rs, r in fills:
            first_rs.setdefault(r[4], rs)
        lvl = {}
        for _, r in fills:
            lvl[r[4]] = lvl.get(r[4], 0) - r[5]
        for _, r, _ in makers:
            lvl[r[4]] = lvl.get(r[4], 0) + r[5]
        assert all(v == 0 for v in lvl.values())
        th = fills[0][1][3]
        tn = sum(r[5] * r[4] * self.ts for _, r, _ in makers)
        tfee = fee(tn, self.accts[tacct]["tp"]) if tacct is not None else 0
        filled = prior
        for i, (hdr, r, k) in enumerate(makers):
            _role, mlane, _msess, mrs = hdr
            _, _idx, _liq, mh, tick, q = r
            o = self.orders[(mlane, mh)]
            o["open"] -= q
            assert o["open"] >= 0 and o["side"] != side
            if o["open"] == 0:
                del self.orders[(mlane, mh)]
            filled += q
            if tacct is not None:
                self.emit(tacct, FILL, side, True, k, step, s, first_rs[tick], th, tick, q, tag,
                          tfee if i + 1 == len(makers) else 0)
            if o["acct"] is not None:
                mp = self.accts[o["acct"]]["mp"]
                self.emit(o["acct"], FILL, o["side"], False, k, step, o["sess"], mrs, mh, tick,
                          q, o["tag"], fee(q * tick * self.ts, mp))
        if rest is not None and rest[1][0] == "ack":
            rs, (_, idx, rh, tick, atag) = rest
            left = qty - filled
            self.orders[(lane, rh)] = dict(acct=tacct, sess=s, side=side, tick=tick, open=left,
                                           tag=atag)
            if tacct is not None:
                self.emit(tacct, ACK, side, False, idx, seq, s, rs, rh, tick, left, atag, 0)

    def final(self, height, last):
        self.finals.append((height, last))
        self.flush(False)

    def flush(self, all_):
        while self.finals and (all_ or self.finals[0][1] <= self.released):
            h, s = self.finals.pop(0)
            self.final_step = max(self.final_step, s)
            self.last_final = (h, s)
            self.final_to(h, s)

    def final_to(self, h, s):
        # DC_FINAL(s) to every stream with a record released at a step <= s that no
        # earlier DC_FINAL covers; those records become canonical.
        for sid in sorted(self.streams):
            p = self.streams[sid]["pend"]
            if p and p[0][0] <= s:
                self.commit(sid, s)
                self.push(sid, stage(FINAL, sid[0], s, h))

    def finish(self, bal):
        self.flush_allocs(2**64)
        self.flush(True)
        for sid in sorted(self.streams):
            self.commit(sid, 2**64)
        self.final_step = max(self.final_step, self.released)
        self.rel = self.released
        for sid in sorted(self.streams):
            acct, master = sid
            members = [a for a, x in self.accts.items()
                       if (a == acct) or (master and x["master"] == acct)]
            b = [sum(bal.get(m, (0, 0, 0, 0))[i] for m in members) for i in range(4)]
            s = self.streams[sid]
            for r in (eod(acct, 0, [s["fills"], s["bb"], s["bs"], s["qb"], s["qs"]]),
                      eod(acct, 1, [s["fees"], s["msg"], 0, 0, 0]),
                      eod(acct, 2, b + [0])):
                self.push(sid, r)
                self.commit(sid, 2**64)
            self.push(sid, eod_hash(acct, len(s["canon"]), b3(b"".join(s["canon"]))))
            self.commit(sid, 2**64)


# --- the scripted cases -----------------------------------------------------------------------
def sess(l, a):
    return (1 << 20) | (l << 12) | a


def h(slot):
    return (1 << 24) | slot


ACCTS = {
    101: dict(master=900, sess=sess(0, 1), tp=400, mp=-20, mi=8, mc=15),
    102: dict(master=900, sess=sess(0, 2), tp=300, mp=50, mi=8, mc=15),
    201: dict(master=None, sess=sess(1, 1), tp=400, mp=-20, mi=8, mc=15),
    301: dict(master=None, sess=sess(2, 1), tp=250, mp=0, mi=8, mc=15),
}

# Each event: ("op", lane, seq, sess, resp_seq, msg, rec) | ("step", id, kind, flags, src, tx)
# | ("final", height, last_step). msg: ("new", side, tick, qty, tag) | ("cancel", handle, tag)
# | ("reduce", handle, by, tag). tx: [((role, lane, sess, resp_seq), rec)].
S01, S02, S11, S21 = sess(0, 1), sess(0, 2), sess(1, 1), sess(2, 1)
CROSS_CASE = [
    ("op", 0, 1, S01, 1, ("new", 1, 105, 2, 11), ("ack", 0, h(1), 105, 11)),
    ("op", 0, 2, S02, 1, ("new", 1, 106, 3, 21), ("ack", 0, h(2), 106, 21)),
    ("op", 0, 3, S02, 1, ("new", 1, 120, 9, 22), ("ack", 1, h(3), 120, 22)),
    ("op", 0, 4, S01, 2, ("new", 0, 90, 1, 12), ("rej", 0, 6)),
    ("step", 1, "cross", CROSS, (1, 1, S11, ("new", 0, 106, 6, 31)), [
        ((TAKER_ROLE, 1, S11, 1), ("fill", 0, 1, h(1), 105, 2)),
        ((TAKER_ROLE, 1, S11, 1), ("fill", 0, 1, h(1), 106, 3)),
        ((TAKER_ROLE, 1, S11, 1), ("ack", 0, h(1), 106, 31)),
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 2)),
        ((MAKER, 0, S02, 0), ("fill", 0xFF, 0, h(2), 106, 3)),
    ]),
    ("final", 1, 1),
    ("op", 1, 2, S11, 2, ("cancel", h(1), 32), ("cxl", 0, h(1), 1, 31)),
    ("op", 0, 5, S02, 2, ("reduce", h(3), 4, 23), ("cxl", 0, h(3), 4, 22)),
    # An IOC sweep over a CONT run: 120 (5 of 102), then 125 (2 of 101); the rest is out.
    ("op", 0, 6, S01, 3, ("new", 1, 125, 2, 13), ("ack", 0, h(4), 125, 13)),
    ("step", 2, "cross", CROSS, (2, 1, S21, ("new", 0, 130, 10, 41)), [
        ((TAKER_ROLE, 2, S21, 1), ("fill", 0, 1, h(1), 120, 5)),
        ((MAKER, 0, S02, 0), ("fill", 0xFF, 0, h(3), 120, 5)),
    ]),
    ("step", 3, "cross", CROSS | CONT, (2, 1, S21, ("new", 0, 130, 10, 41)), [
        ((TAKER_ROLE, 2, S21, 0), ("fill", 0, 1, h(1), 125, 2)),
        ((TAKER_ROLE, 2, S21, 0), ("out", 0, 1, h(1), 3, 41)),
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(4), 125, 2)),
    ]),
    # A shed improve: BUSY, no message fee; an idle step; a lane Out.
    ("step", 4, "shed", 0, (1, 3, S11, ("new", 0, 100, 1, 33)), [
        ((TAKER_ROLE, 1, S11, 3), ("rej", 0, 24)),
    ]),
    ("step", 5, "idle", 0, None, []),
    ("final", 2, 5),
    ("op", 1, 4, S11, 4, ("new", 1, 140, 2, 34), ("ack", 0, h(2), 140, 34)),
    ("op", 1, 5, S11, 5, ("cancel", h(2), 35), ("out", 0, 2, h(2), 2, 34)),
    ("step", 6, "improve", 0, (2, 2, S21, ("new", 0, 99, 4, 42)), [
        ((TAKER_ROLE, 2, S21, 2), ("ack", 0, h(2), 99, 42)),
    ]),
    ("final", 3, 6),
]
LATE_FINAL_CASE = [
    ("op", 0, 1, S01, 1, ("new", 1, 105, 2, 11), ("ack", 0, h(1), 105, 11)),
    ("step", 1, "idle", 0, None, []),
    ("op", 0, 2, S01, 2, ("new", 1, 106, 1, 12), ("ack", 0, h(2), 106, 12)),
    ("step", 2, "idle", 0, None, []),
    ("final", 1, 1),
    ("final", 2, 2),
]
# A tenure is deposed after step 1 is final: steps 2 and 3 (a fill, an ack, an allocation) are
# not in the final log and are reverted; the final log's step 2 fills the same maker again,
# which needs its open quantity back at 5. Settlement comes after the epoch's DC_EOD.
REVERT_CASE = [
    ("op", 0, 1, S01, 1, ("new", 1, 105, 5, 11), ("ack", 0, h(1), 105, 11)),
    ("step", 1, "idle", 0, None, []),
    ("final", 1, 1),
    ("step", 2, "cross", CROSS, (1, 1, S11, ("new", 0, 105, 3, 31)), [
        ((TAKER_ROLE, 1, S11, 1), ("fill", 0, 1, h(1), 105, 3)),
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 3)),
    ]),
    ("op", 0, 2, S02, 1, ("new", 1, 110, 2, 21), ("ack", 0, h(2), 110, 21)),
    ("route", 102, 3, 1, S02, 2, 0, 8, 500, 22, 3),
    ("step", 3, "idle", 0, None, []),
    ("alloc", 3, 101, 0, False, 1000),
    ("revert", 1),
    ("step", 2, "cross", CROSS, (2, 1, S21, ("new", 0, 105, 5, 41)), [
        ((TAKER_ROLE, 2, S21, 1), ("fill", 0, 1, h(1), 105, 5)),
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 5)),
    ]),
    ("alloc", 2, 102, 1, True, 7),
    ("route", 101, 2, 0, S01, 2, 1, 9, 40, 14, -1),
    ("step", 3, "idle", 0, None, []),
    ("final", 2, 2),
]
# A speculative step 2 removes 101's maker by STP and is reverted; the final log's step 2 fills
# it. Block 2's DC_FINAL goes out at step 3, before step 3's allocation for 301, which then gets
# it too. Step 4 is final only by the epoch's end and is settled after DC_EOD.
STP_ALLOC_CASE = [
    ("op", 0, 1, S01, 1, ("new", 1, 105, 5, 11), ("ack", 0, h(1), 105, 11)),
    ("step", 1, "idle", 0, None, []),
    ("final", 1, 1),
    ("step", 2, "cross", CROSS, (0, 2, S01, ("new", 0, 105, 3, 12)), [
        ((TAKER_ROLE, 0, S01, 2), ("ack", 0, h(2), 105, 12)),
        ((MAKER, 0, S01, 0), ("out", 0, OUT_STP, h(1), 5, 11)),
    ]),
    ("revert", 1),
    ("step", 2, "cross", CROSS, (1, 1, S11, ("new", 0, 105, 3, 31)), [
        ((TAKER_ROLE, 1, S11, 1), ("fill", 0, 1, h(1), 105, 3)),
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 3)),
    ]),
    ("final", 2, 3),
    ("step", 3, "idle", 0, None, []),
    ("alloc", 3, 301, 1, False, 250),
    ("op", 0, 2, S02, 1, ("new", 1, 110, 2, 21), ("ack", 0, h(2), 110, 21)),
    ("step", 4, "idle", 0, None, []),
]
# Rescan batch joins swept as takers (05 §8.6, 10 §7.9 item 11). Step 1: 201's buy join at 106
# takes 101's 105 x3 and 102's 106 x2 (two levels), and 1 rests. Steps 2-3: a capped sweep of
# 101's buy join at 110 over 301's 107 x2, then (CONT) 108 x1; 1 rests after step 3. Each
# ("rescan", step, lane, seq, sess, prior, msg, fills [(resp_seq, fill)], rest, makers
# [((role, lane, sess, resp_seq), fill, ordinal)]) comes before its step's release.
RESCAN_CASE = [
    ("op", 0, 1, S01, 1, ("new", 1, 105, 3, 11), ("ack", 0, h(1), 105, 11)),
    ("op", 0, 2, S02, 1, ("new", 1, 106, 2, 21), ("ack", 0, h(2), 106, 21)),
    ("rescan", 1, 1, 1, S11, 0, ("new", 0, 106, 6, 31),
     [(1, ("fill", 0, 1, h(1), 105, 3)), (1, ("fill", 0, 1, h(1), 106, 2))],
     (2, ("ack", 0, h(1), 106, 31)),
     [((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 3), 0),
      ((MAKER, 0, S02, 0), ("fill", 0xFF, 0, h(2), 106, 2), 1)]),
    ("step", 1, "rescan", 0, None, [
        ((MAKER, 0, S01, 0), ("fill", 0xFF, 0, h(1), 105, 3)),
        ((MAKER, 0, S02, 0), ("fill", 0xFF, 0, h(2), 106, 2)),
    ]),
    ("final", 1, 1),
    ("op", 2, 1, S21, 1, ("new", 1, 107, 2, 41), ("ack", 0, h(1), 107, 41)),
    ("op", 2, 2, S21, 2, ("new", 1, 108, 1, 42), ("ack", 0, h(2), 108, 42)),
    ("rescan", 2, 0, 3, S01, 0, ("new", 0, 110, 4, 12),
     [(2, ("fill", 0, 1, h(3), 107, 2))], None,
     [((MAKER, 2, S21, 0), ("fill", 0xFF, 0, h(1), 107, 2), 0)]),
    ("step", 2, "rescan", 0, None, [((MAKER, 2, S21, 0), ("fill", 0xFF, 0, h(1), 107, 2))]),
    ("rescan", 3, 0, 3, S01, 2, ("new", 0, 110, 4, 12),
     [(3, ("fill", 0, 1, h(3), 108, 1))], (4, ("ack", 0, h(3), 110, 12)),
     [((MAKER, 2, S21, 0), ("fill", 0xFF, 0, h(2), 108, 1), 0)]),
    ("step", 3, "rescan", CONT, None, [((MAKER, 2, S21, 0), ("fill", 0xFF, 0, h(2), 108, 1))]),
    ("op", 0, 4, S01, 5, ("cancel", h(3), 13), ("cxl", 0, h(3), 1, 12)),
    ("step", 4, "idle", 0, None, []),
    ("final", 2, 4),
]
# A lane New that would trade with its own account's resting order is taken out at once
# (STP CancelNewest, 05 §2.4) with no Ack: a DC_OUT at its side and limit tick, after the
# packet's other message, a Cancel the lane rejects. The resting order stays.
LANE_STP_CASE = [
    ("op", 1, 1, S11, 1, ("new", 1, 101, 2, 31), ("ack", 0, h(1), 101, 31)),
    ("op", 1, 2, S11, 2, ("cancel", h(8), 32), ("rej", 0, 3)),
    ("op", 1, 3, S11, 2, ("new", 0, 101, 1, 33), ("out", 1, OUT_STP, h(2), 1, 33)),
    ("op", 1, 4, S11, 3, ("cancel", h(1), 34), ("cxl", 0, h(1), 2, 31)),
    ("step", 1, "idle", 0, None, []),
    ("final", 1, 1),
]
BAL = {101: (1000, 20, 7, 0), 102: (5, 0, 3, 1), 201: (77, 0, 0, 0)}


def kind_code(k):
    return {"cross": 1, "improve": 2, "rescan": 3, "shed": 6, "idle": 5}[k]


def fmt_msg(m):
    return " ".join(str(x) for x in m)


def fmt_rec(r):
    return " ".join(str(x) for x in r)


def run_case(lines, name, tick_size, events, bal, post_settled=()):
    m = Model(tick_size, ACCTS)
    lines.append(f"case {name}")
    lines.append(f"tick_size {tick_size}")
    for a, x in sorted(ACCTS.items()):
        mm = x["master"] if x["master"] is not None else "-"
        lines.append(f"acct {a} {mm} {x['sess']:#x} {x['tp']} {x['mp']} {x['mi']} {x['mc']}")
    for ev in events:
        if ev[0] == "op":
            _, lane, seq, s, rs, msg, r = ev
            lines.append(f"op {lane} {seq} {s:#x} {rs} | {fmt_msg(msg)} | {fmt_rec(r)}")
            m.lane_op(lane, seq, s, rs, msg, r)
        elif ev[0] == "step":
            _, sid, kind, flags, src, tx = ev
            if src is None:
                lines.append(f"step {sid} {kind_code(kind)} {flags} -")
            else:
                sl, sq, ss, msg = src
                lines.append(f"step {sid} {kind_code(kind)} {flags} {sl} {sq} {ss:#x} | "
                             f"{fmt_msg(msg)}")
            for (role, lane, s, rs), r in tx:
                lines.append(f"tx {role} {lane} {s:#x} {rs} | {fmt_rec(r)}")
            lines.append("release")
            m.step(sid, kind, flags, src, tx)
        elif ev[0] == "rescan":
            _, step, lane, seq, s, prior, msg, fills, rest, makers = ev
            lines.append(f"rescan {step} {lane} {seq} {s:#x} {prior} | {fmt_msg(msg)}")
            for rs, r in fills:
                lines.append(f"tfill {rs} | {fmt_rec(r)}")
            if rest is not None:
                lines.append(f"trest {rest[0]} | {fmt_rec(rest[1])}")
            for (role, ml, ms, mrs), r, k in makers:
                lines.append(f"tmaker {role} {ml} {ms:#x} {mrs} {k} | {fmt_rec(r)}")
            lines.append("taken")
            m.rescan_taker(step, lane, seq, s, prior, msg, fills, rest, makers)
        elif ev[0] == "alloc":
            _, step, acct, asset, debit, amount = ev
            lines.append(f"alloc {step} {acct} {asset} {int(debit)} {amount}")
            m.alloc(step, acct, asset, debit, amount)
        elif ev[0] == "route":
            lines.append("route " + " ".join(str(x) for x in ev[1:]))
            m.route(*ev[1:])
        elif ev[0] == "revert":
            lines.append(f"revert {ev[1]}")
            m.revert(ev[1])
        else:
            _, height, last = ev
            lines.append(f"final {height} {last}")
            m.final(height, last)
    for a, b in sorted(bal.items()):
        lines.append(f"bal {a} {b[0]} {b[1]} {b[2]} {b[3]}")
    m.finish(bal)
    lines.append("end")
    for height, last in post_settled:
        lines.append(f"settled {height} {last}")
        m.settled(height, last)
    for acct, master, seq, b in m.out:
        lines.append(f"rec {acct} {master} {seq} {b.hex()}")
    lines.append("endcase")
    return m


# --- wire (§8.5) ------------------------------------------------------------------------------
REC, HB, HELLO, ACCEPT, REJECT, END = range(1, 7)
CTX = b"vyrn v1 dropcopy login"


def frame(kind, epoch, seq, body=b""):
    return struct.pack("<BBHIQ", kind, 0, BOOK, epoch, seq) + body.ljust(48, b"\0")


def login_body(master, book, account, epoch, frm, signer, challenge):
    return (b"VDC1" + struct.pack("<BBHIIQII", 1, master, book, account, epoch, frm, signer, 0)
            + challenge)


def login(seed, master, book, account, epoch, frm, signer, challenge):
    body = login_body(master, book, account, epoch, frm, signer, challenge)
    return body + sign(seed, CTX + body)


def main(out_dir):
    lines = [
        "# Drop-copy vectors (spec/10-accounts-risk-md.md §8 and the crate's labeled readings).",
        "# Written by gen_dc_vectors.py, an independent model packing bytes with struct.",
        "# `case` blocks: config (`tick_size`, `acct <id> <master|-> <session> <taker_ppm>",
        "# <maker_ppm> <msg_improve> <msg_cross>`), inputs in release order (`op`, `step` + its",
        "# `tx` lines + `release`, `final`, `bal`; a `rescan` taker's `tfill`, `trest` and",
        "# `tmaker` lines up to `taken`), `end`, then the expected `rec <account>",
        "# <master> <seq> <hex>` in output order. `session` blocks: `store`, `key`, `hello`,",
        "# `login` and the expected frames.",
    ]
    m0 = run_case(lines, "cross", 1_000, CROSS_CASE, BAL)
    m1 = run_case(lines, "quiet", 10, [], {})
    run_case(lines, "late_final", 10, LATE_FINAL_CASE, {})
    run_case(lines, "revert_settle", 100, REVERT_CASE, BAL, post_settled=[(9, 2)])
    run_case(lines, "stp_alloc", 100, STP_ALLOC_CASE, BAL, post_settled=[(3, 4)])
    run_case(lines, "rescan", 100, RESCAN_CASE, BAL)
    run_case(lines, "lane_stp", 100, LANE_STP_CASE, BAL)
    # Sessions over a store of epoch 5 (case cross, ended) and epoch 6 (case quiet, open).
    E0, E1 = 5, 6
    seeds = {101: bytes([1]) * 32, 102: bytes([2]) * 32, 900: bytes([9]) * 32,
             201: bytes([3]) * 32}
    masters = {101: 900, 102: 900}
    store = {E0: {}, E1: {}}
    for e, mm in ((E0, m0), (E1, m1)):
        for acct, master, seq, b in mm.out:
            store[e].setdefault((acct, master), []).append(b)
    for e in (E0, E1):
        for (acct, master), v in sorted(store[e].items()):
            for i, b in enumerate(v):
                lines.append(f"store {e} {acct} {master} {i + 1} {b.hex()}")
    for a, s in sorted(seeds.items()):
        mm = masters.get(a, "-")
        lines.append(f"key {a} {s.hex()} {mm} {pubkey(s).hex()}")

    def may_read(signer, acct, master):
        if master:
            return signer == acct
        return signer == acct or masters.get(acct) == signer

    def session(name, challenge, raw, ok_challenge=None):
        lines.append(f"session {name} {challenge.hex()}")
        lines.append(f"hello {frame(HELLO, E1, 0, challenge).hex()}")
        lines.append(f"login {raw.hex()}")
        # The server's checks, in order.
        why = None
        if raw[0:4] != b"VDC1" or raw[4] != 1 or raw[5] & ~1 or raw[28:32] != bytes(4):
            why = 1
        else:
            master, book, acct, epoch, frm, signer = (raw[5], *struct.unpack(
                "<HIIQI", raw[6:28]))
            ch = raw[32:64]
            if book != BOOK:
                why = 4
            elif signer not in seeds or ch != challenge or not verify_like(signer, raw):
                why = 2
            elif not may_read(signer, acct, master):
                why = 3
            elif epoch not in store:
                why = 5
            elif (acct, master) not in store[epoch]:
                why = 7
            elif frm == 0 or frm > len(store[epoch][(acct, master)]) + 1:
                why = 6
        if why is not None:
            lines.append(f"frame {frame(REJECT, E1, 0, struct.pack('<H', why)).hex()}")
        else:
            v = store[epoch][(acct, master)]
            lines.append(f"frame {frame(ACCEPT, epoch, frm, struct.pack('<Q', len(v))).hex()}")
            e, nxt = epoch, frm
            while True:
                v = store[e].get((acct, master), [])
                while nxt <= len(v):
                    lines.append(f"frame {frame(REC, e, nxt, v[nxt - 1]).hex()}")
                    nxt += 1
                if e == E0:
                    lines.append(f"frame {frame(END, e, nxt - 1).hex()}")
                    e, nxt = E1, 1
                    continue
                break
        lines.append("endsession")

    def verify_like(signer, raw):
        # Ed25519 is deterministic (RFC 8032), so a login verifies iff it is the signer's own
        # signature of these bytes.
        return raw[64:] == sign(seeds[signer], CTX + raw[:64])

    ch = bytes(range(32))
    lg = lambda seed, *a: login(seed, *a)  # noqa: E731
    session("own", ch, lg(seeds[101], 0, BOOK, 101, E0, 1, 101, ch))
    session("resume_mid", ch, lg(seeds[101], 0, BOOK, 101, E0, 4, 101, ch))
    session("master_stream", ch, lg(seeds[900], 1, BOOK, 900, E0, 3, 900, ch))
    session("master_reads_sub", ch, lg(seeds[900], 0, BOOK, 102, E0, 9, 900, ch))
    session("current_epoch", ch, lg(seeds[201], 0, BOOK, 201, E1, 1, 201, ch))
    session("at_end", ch, lg(seeds[201], 0, BOOK, 201, E1, 5, 201, ch))
    session("sub_reads_master", ch, lg(seeds[101], 1, BOOK, 900, E0, 1, 101, ch))
    session("sibling", ch, lg(seeds[102], 0, BOOK, 101, E0, 1, 102, ch))
    session("forged", ch, lg(seeds[102], 0, BOOK, 101, E0, 1, 101, ch))
    session("replayed", ch, lg(seeds[101], 0, BOOK, 101, E0, 1, 101, bytes(32)))
    session("unknown_signer", ch, lg(bytes([7]) * 32, 0, BOOK, 555, E0, 1, 555, ch))
    session("other_book", ch, lg(seeds[101], 0, BOOK + 1, 101, E0, 1, 101, ch))
    session("old_epoch", ch, lg(seeds[101], 0, BOOK, 101, 4, 1, 101, ch))
    session("from_zero", ch, lg(seeds[101], 0, BOOK, 101, E0, 0, 101, ch))
    session("past_newest", ch, lg(seeds[201], 0, BOOK, 201, E1, 6, 201, ch))
    session("no_stream", ch, lg(seeds[201], 1, BOOK, 201, E0, 1, 201, ch))
    bad = bytearray(lg(seeds[101], 0, BOOK, 101, E0, 1, 101, ch))
    bad[0] = ord("X")
    session("bad_magic", ch, bytes(bad))
    lines.append(f"heartbeat {frame(HB, E1, 17).hex()}")
    with open(f"{out_dir}/dc_vectors.txt", "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
