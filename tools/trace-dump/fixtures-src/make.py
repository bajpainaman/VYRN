#!/usr/bin/env python3
"""Writes tools/trace-dump/fixtures/: ring files, args and the expected dump.

This is an independent decoder of spec/11-build.md section 8.3, written from the trace-dump
contract (lib.rs), not from its code. Run: python3 -I tools/trace-dump/fixtures-src/make.py
"""
import os
import struct
import sys

KINDS = {1: "RX_PKT", 2: "STEP_BEGIN", 3: "STEP_END", 4: "CUT", 5: "RING_FULL",
         6: "REJECT", 7: "STALL", 8: "SEAL", 9: "PANIC"}
OUT = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "..", "fixtures")


def entry(tsc, kind, core, a16, a32):
    return struct.pack("<QBBHI", tsc, kind, core, a16, a32)


def to_ptp(clock, tsc):
    if len(clock) < 2:
        return None
    k = sum(1 for t, _ in clock if t <= tsc)
    k = min(max(k, 1), len(clock) - 1)
    (t0, p0), (t1, p1) = clock[k - 1], clock[k]
    num = (tsc - t0) * (p1 - p0)
    q = abs(num) // (t1 - t0)          # truncate toward zero, as the contract says
    return p0 + (q if num >= 0 else -q)


def expected(rings, clock):
    rows = []
    for f, ring in enumerate(rings):
        for s, (tsc, kind, core, a16, a32) in enumerate(ring):
            if (tsc, kind, core, a16, a32) != (0, 0, 0, 0, 0):
                rows.append((tsc, core, f, s, kind, a16, a32))
    rows.sort()
    out = []
    for tsc, core, _, _, kind, a16, a32 in rows:
        t = to_ptp(clock, tsc)
        name = KINDS.get(kind, "KIND_%d" % kind)
        out.append("%s tsc=%d core=%d %s arg16=%d arg32=%d\n"
                   % ("-" if t is None else t, tsc, core, name, a16, a32))
    return "".join(out)


def case(name, rings, clock_text=None, exit_code=0, raw=None):
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    args = []
    if clock_text is not None:
        with open(os.path.join(d, "clock.txt"), "w") as f:
            f.write(clock_text)
        args += ["--clock", "@CASE/clock.txt"]
    for i, ring in enumerate(raw if raw is not None else rings):
        p = "core%d.ring" % i
        with open(os.path.join(d, p), "wb") as f:
            f.write(ring if raw is not None else b"".join(entry(*e) for e in ring))
        args.append("@CASE/" + p)
    with open(os.path.join(d, "args.txt"), "w") as f:
        f.write("\n".join(args) + "\n")
    clock = []
    if clock_text is not None and exit_code == 0:
        for line in clock_text.splitlines():
            line = line.split("#")[0].strip()
            if line:
                a, b = line.split()
                clock.append((int(a), int(b)))
    with open(os.path.join(d, "expected.txt"), "w") as f:
        f.write(expected(rings, clock) if exit_code == 0 else "")
    with open(os.path.join(d, "exit.txt"), "w") as f:
        f.write("%d\n" % exit_code)


E = 1_000_000_000
# Core 3's ring has wrapped: the two newest entries sit in the first slots, and one slot is empty.
core3 = [(1500, 4, 3, 0, 7), (2500, 9, 3, 0, 0), (0, 0, 0, 0, 0),
         (100, 1, 3, 0, 0xDEADBEEF), (333, 6, 3, 0x0105, 41), (300, 2, 3, 2, 5)]
core5 = [(300, 3, 5, 2, 5), (250, 42, 5, 65535, 4294967295)]
clock = "# tsc ptp_ns\n0 %d\n1000 %d\n2000 %d\n" % (E, E + 400, E + 900)
case("two-cores", [core3, core5], clock)
case("no-clock", [core5])
case("one-clock-pair", [core5], "1000 %d\n" % E)
case("ring-size", [], raw=[b"\x01" * 17], exit_code=2)
case("clock-order", [core5], "10 1\n10 2\n", exit_code=2)
