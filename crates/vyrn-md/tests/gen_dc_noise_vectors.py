#!/usr/bin/env python3
"""Writes dc_noise_vectors.txt: Noise_NK_25519_ChaChaPoly_SHA512 for the drop-copy session
(spec/10-accounts-risk-md.md §8.5 item 5). An independent model: X25519 (RFC 7748) and
ChaCha20-Poly1305 (RFC 8439) are written out here from the RFCs, SHA-512 and HMAC come from the
Python standard library, and nothing is shared with the Rust code. Each primitive is checked
against its RFC's test vector first.

Usage: python3 -I gen_dc_noise_vectors.py <out_dir>
"""
import hashlib
import hmac as std_hmac
import struct
import sys

# --- X25519, RFC 7748 §5 ---
P = 2**255 - 19
A24 = 121665


def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(k, u):
    k = clamp(k)
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def x25519_pub(k):
    return x25519(k, (9).to_bytes(32, "little"))


# --- ChaCha20-Poly1305, RFC 8439 §2 ---
def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)


def chacha_block(key, counter, nonce):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = s[:]
    for _ in range(10):
        quarter(w, 0, 4, 8, 12); quarter(w, 1, 5, 9, 13)
        quarter(w, 2, 6, 10, 14); quarter(w, 3, 7, 11, 15)
        quarter(w, 0, 5, 10, 15); quarter(w, 1, 6, 11, 12)
        quarter(w, 2, 7, 8, 13); quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(w, s)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = 2**130 - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) % 2**128).to_bytes(16, "little")


def pad16(b):
    return b"\x00" * (-len(b) % 16)


def aead_seal(key, nonce, ad, pt):
    otk = chacha_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    mac = ad + pad16(ad) + ct + pad16(ct) + struct.pack("<QQ", len(ad), len(ct))
    return ct + poly1305(otk, mac)


def aead_open(key, nonce, ad, ct):
    body, tag = ct[:-16], ct[-16:]
    otk = chacha_block(key, 0, nonce)[:32]
    mac = ad + pad16(ad) + body + pad16(body) + struct.pack("<QQ", len(ad), len(body))
    if not std_hmac.compare_digest(poly1305(otk, mac), tag):
        raise ValueError("tag")
    return chacha20(key, 1, nonce, body)


def self_check():
    # RFC 7748 §6.1.
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    assert x25519_pub(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert x25519_pub(b).hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    assert x25519(a, x25519_pub(b)).hex() == \
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    # RFC 8439 §2.8.2.
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
          b"future, sunscreen would be it.")
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    ad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    c = aead_seal(key, nonce, ad, pt)
    assert c[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2"
    assert c[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691"
    assert aead_open(key, nonce, ad, c) == pt


# --- Noise_NK_25519_ChaChaPoly_SHA512 (Noise rev. 34) ---
PROTOCOL = b"Noise_NK_25519_ChaChaPoly_SHA512"
PROLOGUE = b"vyrn v1 dropcopy noise"


def sha512(*parts):
    return hashlib.sha512(b"".join(parts)).digest()


def hkdf2(ck, ikm):
    t = std_hmac.new(ck, ikm, hashlib.sha512).digest()
    a = std_hmac.new(t, b"\x01", hashlib.sha512).digest()
    b = std_hmac.new(t, a + b"\x02", hashlib.sha512).digest()
    return a, b


class Cipher:
    def __init__(self, k):
        self.k, self.n = k, 0

    def nonce(self):
        n = b"\x00" * 4 + struct.pack("<Q", self.n)
        self.n += 1
        return n

    def seal(self, ad, pt):
        return aead_seal(self.k, self.nonce(), ad, pt)

    def open(self, ad, ct):
        return aead_open(self.k, self.nonce(), ad, ct)


class Sym:
    def __init__(self, book, rs):
        self.h = PROTOCOL + b"\x00" * (64 - len(PROTOCOL))
        self.ck = self.h
        self.c = None
        self.mix_hash(PROLOGUE + struct.pack("<H", book))
        self.mix_hash(rs)

    def mix_hash(self, d):
        self.h = sha512(self.h, d)

    def mix_key(self, ikm):
        self.ck, k = hkdf2(self.ck, ikm)
        self.c = Cipher(k[:32])

    def enc_hash(self, pt):
        c = self.c.seal(self.h, pt)
        self.mix_hash(c)
        return c

    def dec_hash(self, c):
        pt = self.c.open(self.h, c)
        self.mix_hash(c)
        return pt

    def split(self):
        a, b = hkdf2(self.ck, b"")
        return Cipher(a[:32]), Cipher(b[:32])


def handshake(book, s, ie, re):
    """Both sides of one handshake: (m1, m2, hash, initiator (tx, rx), responder (tx, rx))."""
    spub = x25519_pub(s)
    # Initiator: -> e, es
    i = Sym(book, spub)
    iep = x25519_pub(ie)
    i.mix_hash(iep)
    i.mix_key(x25519(ie, spub))
    m1 = iep + i.enc_hash(b"")
    # Responder reads m1.
    r = Sym(book, spub)
    r.mix_hash(m1[:32])
    r.mix_key(x25519(s, m1[:32]))
    assert r.dec_hash(m1[32:]) == b""
    # Responder: <- e, ee
    rep = x25519_pub(re)
    r.mix_hash(rep)
    r.mix_key(x25519(re, m1[:32]))
    m2 = rep + r.enc_hash(b"")
    # Initiator reads m2.
    i.mix_hash(m2[:32])
    i.mix_key(x25519(ie, m2[:32]))
    assert i.dec_hash(m2[32:]) == b""
    assert i.h == r.h
    i1, i2 = i.split()
    r1, r2 = r.split()
    return m1, m2, i.h, (i1, i2), (r2, r1)


def frame(b):
    return struct.pack(">H", len(b)) + b


def main(out_dir):
    self_check()
    lines = [
        "# Drop-copy Noise vectors (spec/10-accounts-risk-md.md §8.5 item 5):",
        "# Noise_NK_25519_ChaChaPoly_SHA512, prologue \"vyrn v1 dropcopy noise\" || book u16 LE.",
        "# Written by gen_dc_noise_vectors.py, an independent model (X25519 and ChaCha20-Poly1305",
        "# from the RFCs, checked against their test vectors). Per `noise` block: `book`, the",
        "# server static secret `s` and public `spub`, the ephemeral secrets `ie` (client) and",
        "# `re` (server), handshake messages `m1` `m2` (unframed), the handshake `hash`, then",
        "# transport messages in send order: `c2s|s2c <plaintext hex|-> <framed message hex>`.",
    ]
    cases = [
        ("basic", 7, bytes([0x11]) * 32, bytes([0x22]) * 32, bytes([0x33]) * 32),
        ("book9", 9, bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))),
    ]
    for name, book, s, ie, re in cases:
        m1, m2, h, (itx, irx), (rtx, rrx) = handshake(book, s, ie, re)
        lines += [f"noise {name}", f"book {book}", f"s {s.hex()}", f"spub {x25519_pub(s).hex()}",
                  f"ie {ie.hex()}", f"re {re.hex()}", f"m1 {m1.hex()}", f"m2 {m2.hex()}",
                  f"hash {h.hex()}"]
        # The §8.5 session inside: HELLO (64 bytes), LOGIN (as long as a login), an empty
        # message, records batched in one message, and a large message.
        msgs = [
            ("s2c", bytes([5]) * 64),
            ("c2s", bytes(range(256))[:152]),
            ("s2c", b""),
            ("s2c", bytes((i * 7) & 0xFF for i in range(64 * 3))),
            ("c2s", b""),
            ("s2c", bytes((i * 13 + 1) & 0xFF for i in range(4000))),
        ]
        for d, pt in msgs:
            if d == "c2s":
                ct = itx.seal(b"", pt)
                assert rrx.open(b"", ct) == pt
            else:
                ct = rtx.seal(b"", pt)
                assert irx.open(b"", ct) == pt
            lines.append(f"{d} {pt.hex() or '-'} {frame(ct).hex()}")
        lines.append("end")
    with open(f"{out_dir}/dc_noise_vectors.txt", "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
