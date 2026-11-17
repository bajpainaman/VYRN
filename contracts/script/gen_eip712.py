#!/usr/bin/env python3
"""Generates vectors/eip712.json: EIP-712 digests from eth-account and signatures from `cast wallet sign`.

Neither tool reads the contract. Run from contracts/ after gen_smt.py and gen_wdtree.cjs:
  uv run --no-project --with eth-account==0.14.0 python3 -I script/gen_eip712.py
`cast` (Foundry) must be on PATH. The private keys are test keys, never use them for anything else.
"""

import json
import os
import subprocess
import tempfile

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

L1_CHAIN_ID = 1
BRIDGE = "0x0b21d6e000000000000000000000000000000001"
VYRN_CHAIN_ID = 7
BK_PK = [f"0x{0x1001 + i:064x}" for i in range(5)]
GK_PK = [f"0x{0x2001 + i:064x}" for i in range(5)]
NEW_BK_PK = [f"0x{0x3001 + i:064x}" for i in range(5)]
NEW_GK_PK = [f"0x{0x4001 + i:064x}" for i in range(5)]

DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
TYPES = {
    "Post": [
        {"name": "postNo", "type": "uint64"},
        {"name": "chainId", "type": "uint32"},
        {"name": "prevPost", "type": "bytes32"},
        {"name": "commit", "type": "bytes32"},
        {"name": "smtRoot", "type": "bytes32"},
        {"name": "depositNonce", "type": "uint64"},
        {"name": "wdRoot", "type": "bytes32"},
        {"name": "wdCount", "type": "uint32"},
        {"name": "wdTotals", "type": "uint256[]"},
    ],
    "Unpause": [{"name": "pauseNo", "type": "uint64"}],
    "SignerSet": [
        {"name": "rotationNo", "type": "uint64"},
        {"name": "bridgeKeys", "type": "address[]"},
        {"name": "guardianKeys", "type": "address[]"},
    ],
}
DOMAIN = {"name": "VYRN", "version": "1", "chainId": L1_CHAIN_ID, "verifyingContract": BRIDGE}


def addr(pk):
    return Account.from_key(pk).address


def full(primary, message):
    return {
        "types": {"EIP712Domain": DOMAIN_TYPE, primary: TYPES[primary]},
        "primaryType": primary,
        "domain": DOMAIN,
        "message": message,
    }


def digest(primary, message):
    m = encode_typed_data(full_message=full(primary, message))
    return "0x" + keccak(b"\x19" + m.version + m.header + m.body).hex(), "0x" + m.body.hex(), "0x" + m.header.hex()


def cast_sign(pk, typed):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(typed, f)
        path = f.name
    try:
        out = subprocess.run(
            ["cast", "wallet", "sign", "--private-key", pk, "--data", "--from-file", path],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
    finally:
        os.unlink(path)
    return out


def vector(name, primary, message, signers):
    d, struct_hash, dom = digest(primary, message)
    typed = full(primary, message)
    sigs = [cast_sign(pk, typed) for pk in signers]
    for pk, s in zip(signers, sigs):
        rec = Account._recover_hash(bytes.fromhex(d[2:]), signature=bytes.fromhex(s[2:]))
        assert rec == addr(pk), (name, rec)
    return {"name": name, "primaryType": primary, "message": message, "structHash": struct_hash,
            "digest": d, "signers": [addr(pk) for pk in signers], "signatures": sigs}


def main():
    smt = json.load(open("vectors/smt.json"))
    wd = json.load(open("vectors/wdtree.json"))
    post1 = {
        "postNo": 1, "chainId": VYRN_CHAIN_ID, "prevPost": "0x" + "00" * 32,
        "commit": "0x" + "c0" * 32, "smtRoot": smt["root"], "depositNonce": 3,
        "wdRoot": wd["root"], "wdCount": len(wd["leaves"]), "wdTotals": [int(t) for t in wd["totals"]],
    }
    post1_hash = digest("Post", post1)[1]
    post2 = {
        "postNo": 2, "chainId": VYRN_CHAIN_ID, "prevPost": post1_hash,
        "commit": "0x" + "c1" * 32, "smtRoot": smt["proof27"]["root"], "depositNonce": 3,
        "wdRoot": "0x" + "00" * 32, "wdCount": 0, "wdTotals": [0, 0],
    }
    rot = {"rotationNo": 1, "bridgeKeys": [addr(k) for k in NEW_BK_PK],
           "guardianKeys": [addr(k) for k in NEW_GK_PK]}
    d0 = digest("Unpause", {"pauseNo": 1})[2]
    out = {
        "_source": "script/gen_eip712.py: digests by eth-account, signatures by cast wallet sign",
        "domain": DOMAIN,
        "domainSeparator": d0,
        "typeStrings": {
            "Post": "Post(uint64 postNo,uint32 chainId,bytes32 prevPost,bytes32 commit,bytes32 smtRoot,"
                    "uint64 depositNonce,bytes32 wdRoot,uint32 wdCount,uint256[] wdTotals)",
            "Unpause": "Unpause(uint64 pauseNo)",
            "SignerSet": "SignerSet(uint64 rotationNo,address[] bridgeKeys,address[] guardianKeys)",
        },
        "bridgeKeys": [addr(k) for k in BK_PK],
        "guardianKeys": [addr(k) for k in GK_PK],
        "bridgeKeyPrivate": BK_PK,
        "vectors": [
            vector("post1", "Post", post1, BK_PK),
            vector("post2", "Post", post2, BK_PK),
            vector("unpause1", "Unpause", {"pauseNo": 1}, BK_PK),
            vector("rotation1", "SignerSet", rot, BK_PK),
        ],
    }
    for t, s in out["typeStrings"].items():
        out.setdefault("typeHashes", {})[t] = "0x" + keccak(text=s).hex()
    with open("vectors/eip712.json", "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
