#!/usr/bin/env python3
"""Fail when a derive_key / signing context differs between spec/ and code.

A context is a quoted string `"vyrn<spaces>v1 <purpose>"`. Its purpose is the text after `v1 `.
The spacing after `vyrn` is part of the key derivation, so a purpose must be spelled with the same
bytes everywhere: once in code, and the same in every spec occurrence.

Run from the repository root: `python3 -I tools/check-contexts.py`.
"""

import os
import re
import sys
from collections import defaultdict

CTX = re.compile(r'"(vyrn +v1 [a-z0-9][a-z0-9 _-]*)"')
CODE_DIRS = ["crates", "bin", "contracts", "tests", "tools", "c"]
CODE_EXT = (".rs", ".py", ".sol", ".json", ".txt", ".md", ".c", ".h", ".toml")
SKIP = {"target", "node_modules", "out", "cache", "lib"}

# Purposes awaiting a ruling (unpinned: no golden vector or deployed key fixes the bytes, and the
# spec disagrees with code or with itself). Reported, not failed. Remove a purpose once it is ruled.
PENDING = {
    "tx", "commit", "vote",  # code single; 09 body padded, 09 §17.3 single
    "nodecert", "genesis", "gov", "seqsig", "epochkeys", "sample key", "sample",  # spec only
}


def scan(paths):
    found = defaultdict(lambda: defaultdict(list))  # purpose -> exact string -> [file:line]
    for path in paths:
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.split("\n"), 1):
            for m in CTX.finditer(line):
                s = m.group(1)
                found[s.split(" v1 ", 1)[1]][s].append(f"{path}:{n}")
    return found


def walk(dirs):
    for d in dirs:
        for root, subdirs, files in os.walk(d):
            subdirs[:] = [s for s in subdirs if s not in SKIP and not s.startswith(".")]
            for f in files:
                if f.endswith(CODE_EXT):
                    yield os.path.join(root, f)


def show(forms):
    return "; ".join(f"{s!r} ({len(s)} B) at {', '.join(at[:3])}" for s, at in forms.items())


def main():
    spec = scan(sorted(os.path.join("spec", f) for f in os.listdir("spec") if f.endswith(".md")))
    code = scan(sorted(walk(CODE_DIRS)))
    errors, pending = [], []
    for purpose in sorted(set(spec) | set(code)):
        sp, co = spec.get(purpose, {}), code.get(purpose, {})
        bad = len(co) > 1 or len(sp) > 1 or (sp and co and set(sp) != set(co))
        if not bad:
            continue
        msg = f"{purpose!r}: code {show(co) or '-'} | spec {show(sp) or '-'}"
        (pending if purpose in PENDING else errors).append(msg)
    for m in pending:
        print(f"pending ruling: {m}")
    for m in errors:
        print(f"error: {m}", file=sys.stderr)
    total = len(set(spec) | set(code))
    print(f"{total} context purposes, {len(errors)} mismatched, {len(pending)} pending a ruling")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
