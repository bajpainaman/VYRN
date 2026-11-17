#!/usr/bin/env python3
"""Generates src/SmtEmpty.sol and vectors/smt.json from Python's blake3 package, independent of Solidity.

Run from contracts/: `uv run --no-project --with blake3==1.0.5 python3 -I script/gen_smt.py`.

Encodings (09 §9.3; the byte layout of the values is this contract's resolution of a spec gap, see
README §Leaf encoding):
  AccountLeaf key   = BLAKE3(0x01 ‖ le32(account))
  AccountLeaf value = [owner_kind] ‖ owner (32 B) ‖ le64(nonce) ‖ exit_address (20 B)
  BalanceLeaf key   = BLAKE3(0x02 ‖ le32(account) ‖ le16(asset))
  BalanceLeaf value = le128(free) ‖ le128(alloc_sum) ‖ le128(transit) ‖ le128(pending_unposted)
                      ‖ le128(pending_posted)
"""

import json
import random

from blake3 import blake3

LEAF_CTX = "vyrn v1 smt leaf"
NODE_CTX = "vyrn v1 smt node"


def H(b):
    return blake3(b).digest()


def dk(ctx, m):
    return blake3(m, derive_key_context=ctx).digest()


def leaf_hash(material):
    return H(dk(LEAF_CTX, material))


def node_hash(l, r):
    return H(dk(NODE_CTX, l + r))


E = [bytes(32)]
for _ in range(256):
    E.append(node_hash(E[-1], E[-1]))


def bit(key, d):
    return (key[d // 8] >> (7 - d % 8)) & 1


class Tree:
    """A sparse tree over a dict of key -> leaf hash, computed recursively (fine for a few leaves)."""

    def __init__(self, leaves):
        self.leaves = leaves

    def node(self, prefix_keys, depth):
        # hash of the subtree at `depth` holding prefix_keys; height 256 - depth
        if not prefix_keys:
            return E[256 - depth]
        if depth == 256:
            return self.leaves[prefix_keys[0]]
        left = [k for k in prefix_keys if bit(k, depth) == 0]
        right = [k for k in prefix_keys if bit(k, depth) == 1]
        return node_hash(self.node(left, depth + 1), self.node(right, depth + 1))

    def root(self):
        return self.node(list(self.leaves), 0)

    def proof(self, key):
        bitmap = 0
        sibs = []
        keys = list(self.leaves)
        for d in range(256):
            same = [k for k in keys if bit(k, d) == bit(key, d)]
            other = [k for k in keys if bit(k, d) != bit(key, d)]
            s = self.node(other, d + 1)
            if s != E[255 - d]:
                bitmap |= 1 << (255 - d)
                sibs.append(s)
            keys = same
        return bitmap, sibs


def account_key(acct):
    return H(b"\x01" + acct.to_bytes(4, "little"))


def balance_key(acct, asset):
    return H(b"\x02" + acct.to_bytes(4, "little") + asset.to_bytes(2, "little"))


def account_value(kind, owner, nonce, exit_addr):
    return bytes([kind]) + owner + nonce.to_bytes(8, "little") + exit_addr


def balance_value(vals):
    return b"".join(v.to_bytes(16, "little") for v in vals)


def hx(b):
    return "0x" + b.hex()


def main():
    rng = random.Random(0x5652594E)
    leaves = {}
    accounts = []
    balances = []
    for i, (acct, kind) in enumerate([(1, 1), (2, 0), (7, 1)]):
        owner = (bytes(12) + rng.randbytes(20)) if kind == 1 else rng.randbytes(32)
        exit_addr = bytes.fromhex("e5c0" + f"{i:036x}")
        nonce = rng.randrange(1, 1000)
        k = account_key(acct)
        v = account_value(kind, owner, nonce, exit_addr)
        leaves[k] = leaf_hash(k + v)
        accounts.append(dict(account=acct, ownerKind=kind, owner=hx(owner), nonce=nonce,
                             exitAddress=hx(exit_addr), key=hx(k), value=hx(v), leafHash=hx(leaves[k])))
        for asset in (0, 1):
            vals = [rng.randrange(0, 10**12) for _ in range(5)]
            bk = balance_key(acct, asset)
            bv = balance_value(vals)
            leaves[bk] = leaf_hash(bk + bv)
            balances.append(dict(account=acct, asset=asset, free=vals[0], allocSum=vals[1], transit=vals[2],
                                 pendingUnposted=vals[3], pendingPosted=vals[4], key=hx(bk), value=hx(bv),
                                 leafHash=hx(leaves[bk])))
    tree = Tree(leaves)
    root = tree.root()
    for rec in accounts + balances:
        bm, sibs = tree.proof(bytes.fromhex(rec["key"][2:]))
        rec["bitmap"] = hx(bm.to_bytes(32, "big"))
        rec["siblings"] = [hx(s) for s in sibs]

    # A worst-case-shaped proof for B-CHN-4: a leaf with 27 non-empty siblings (09 §9.3, 100M leaves).
    # Siblings at depths 0..26 are random non-empty hashes; the root is folded from them directly.
    gas_leaf = balances[0]
    lh = bytes.fromhex(gas_leaf["leafHash"][2:])
    key = bytes.fromhex(gas_leaf["key"][2:])
    sib_at = {d: rng.randbytes(32) for d in range(27)}
    h = lh
    bm = 0
    for d in range(255, -1, -1):
        s = sib_at.get(d, E[255 - d])
        if d in sib_at:
            bm |= 1 << (255 - d)
        h = node_hash(h, s) if bit(key, d) == 0 else node_hash(s, h)
    gas27 = dict(root=hx(h), bitmap=hx(bm.to_bytes(32, "big")), siblings=[hx(sib_at[d]) for d in range(27)])

    # B-CHN-4 shape for escapeClaim: one root under which the account leaf of account 1 and its balance
    # leaf for asset 0 both have exactly 27 non-empty siblings, at depths 0..26.
    ka = bytes.fromhex(accounts[0]["key"][2:])
    kb = key
    la = bytes.fromhex(accounts[0]["leafHash"][2:])
    k = next(d for d in range(256) if bit(ka, d) != bit(kb, d))
    assert k <= 26, k

    def fold(leafh, kk, sibs, top):
        # hash from depth 255 up to (and including) depth `top`, with siblings sibs[d] or empty
        h = leafh
        for d in range(255, top - 1, -1):
            s = sibs.get(d, E[255 - d])
            h = node_hash(h, s) if bit(kk, d) == 0 else node_hash(s, h)
        return h

    def subtree(leafh, kk, sibs, top):
        # hash of the subtree rooted below depth `top` (height 255 - top) that holds the leaf
        h = leafh
        for d in range(255, top, -1):
            s = sibs.get(d, E[255 - d])
            h = node_hash(h, s) if bit(kk, d) == 0 else node_hash(s, h)
        return h

    own_a = {d: rng.randbytes(32) for d in range(k + 1, 27)}
    own_b = {d: rng.randbytes(32) for d in range(k + 1, 27)}
    shared = {d: rng.randbytes(32) for d in range(k)}
    sa = subtree(la, ka, own_a, k)
    sb = subtree(lh, kb, own_b, k)
    sib_a = {**shared, **own_a, k: sb}
    sib_b = {**shared, **own_b, k: sa}
    ra = fold(la, ka, sib_a, 0)
    rb = fold(lh, kb, sib_b, 0)
    assert ra == rb

    def pr(s):
        bm = sum(1 << (255 - d) for d in s)
        return dict(bitmap=hx(bm.to_bytes(32, "big")), siblings=[hx(s[d]) for d in sorted(s)])

    escape27 = dict(root=hx(ra), account=pr(sib_a), balance=pr(sib_b))

    out = dict(
        escape27=escape27,
        _source="script/gen_smt.py with Python blake3; independent of the Solidity code",
        leafContext=LEAF_CTX, nodeContext=NODE_CTX,
        empty=[hx(e) for e in E[:4]] + [hx(E[255]), hx(E[256])],
        nodeHashOfZeros=hx(node_hash(bytes(32), bytes(32))),
        root=hx(root), accounts=accounts, balances=balances, proof27=gas27,
    )
    with open("vectors/smt.json", "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")

    table = "".join(e.hex() for e in E[:256])
    with open("src/SmtEmpty.sol", "w") as f:
        f.write(
            "// SPDX-License-Identifier: LicenseRef-VYRN-Research-and-Education-1.0\n"
            "// GENERATED by script/gen_smt.py. Do not edit by hand.\n"
            "pragma solidity 0.8.30;\n\n"
            "/// @title Empty subtree hashes E[0..255] of the 09 §9.3 SMT, 32 bytes each\n"
            "library SmtEmpty {\n"
            f'    bytes internal constant TABLE = hex\"{table}\";\n'
            "}\n"
        )


if __name__ == "__main__":
    main()
