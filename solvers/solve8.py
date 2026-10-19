#!/usr/bin/env python3
"""
Flare-On 13, challenge 8, "crux".

Builds the answer for the `crux` browser extension from scratch and prints it.

The extension's popup feeds whatever you type to a Go/WebAssembly function
`check()`. That function

  1. base64-decodes the input,
  2. decrypts it with a hard-coded AES-256-CBC key and IV,
  3. strips PKCS#7 padding,
  4. parses the plaintext as a binary tree,
  5. verifies the tree is a **Pratt primality certificate**, and
  6. checks the certified prime equals a hard-coded 256-bit constant.

So the answer is base64(AES-CBC(serialised Pratt certificate for P)).

This script needs only the standard library.  Run it with no arguments:

    python3 solve8.py

Pass a path to `main.wasm` to additionally confirm the three constants below
really appear in the module's encrypted literal pool is *not* possible: garble
encrypts them, so they are recovered at run time.  How that was done is in
08-crux.md.
"""

import base64
import hashlib
import random
import struct
import sys
from math import gcd

# ---------------------------------------------------------------- constants
# All three were read out of live WebAssembly memory; garble's -literals pass
# keeps them encrypted in the module and decrypts them on the stack on use.
AES_KEY = bytes.fromhex(
    "cabeba7ad156801d1c82381c7cb8a3c406ae2c3cd168a96cd8373684cdbf8723")
AES_IV = bytes.fromhex("5ff26040c4c20b9f2ffdefa7ecf65d91")
# The 32 bytes the certified prime is compared against.  The challenge's bignum
# stores its magnitude as LITTLE-endian bytes, which is what makes this prime.
TARGET_BYTES = bytes.fromhex(
    "61e230c979e1be78551b7c44963c5a65e3e827b3b04a7adacc029a37bbdf89d3")
TARGET_PRIME = int.from_bytes(TARGET_BYTES, "little")

FLAG = "Pr4tt_Pr1M4lItY_C3rt5_4nd_Wa4aA4aAA4aAA4a4a5M@flare-on.com"

# ---------------------------------------------------------------- number theory
_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n):
    """Deterministic enough Miller-Rabin for the sizes involved here."""
    if n < 2:
        return False
    for q in _SMALL:
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _SMALL:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _brent(n):
    """Brent's variant of Pollard's rho."""
    if n % 2 == 0:
        return 2
    while True:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = 128
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
        if g != n:
            return g


def factor(n, out=None):
    """Full factorisation, smallest-first trial division then rho."""
    if out is None:
        out = []
    if n == 1:
        return out
    if is_prime(n):
        out.append(n)
        return out
    for d in range(2, 100000):
        if n % d == 0:
            out.append(d)
            return factor(n // d, out)
    d = _brent(n)
    factor(d, out)
    factor(n // d, out)
    return out


_FAC_CACHE = {}


def factors(n):
    if n not in _FAC_CACHE:
        _FAC_CACHE[n] = sorted(factor(n))
    return _FAC_CACHE[n]


def primitive_root(p):
    """Smallest a with a^((p-1)/q) != 1 mod p for every prime q | p-1."""
    if p == 2:
        return 1
    qs = set(factors(p - 1))
    for a in range(2, 1 << 20):
        if all(pow(a, (p - 1) // q, p) != 1 for q in qs):
            return a
    raise RuntimeError("no primitive root found for %d" % p)


# ---------------------------------------------------------------- certificate
# A node is either ('E',), meaning the prime 2, or ('C', children, p, witness).
_CERT_CACHE = {}


def certificate(p):
    if p == 2:
        return ("E",)
    if p in _CERT_CACHE:
        return _CERT_CACHE[p]
    # Children must be in non-decreasing order of their certified prime; the
    # factor list is already sorted, and ('E',) == 2 is the smallest possible.
    children = [certificate(q) for q in factors(p - 1)]
    node = ("C", children, p, primitive_root(p))
    _CERT_CACHE[p] = node
    return node


def check_certificate(node):
    """Re-implementation of the WASM validator, as a cross-check."""
    if node[0] == "E":
        return 2
    _, children, p, w = node
    values = [check_certificate(c) for c in children]
    if values != sorted(values):
        raise AssertionError("children of %d are not sorted" % p)
    product = 1
    for v in values:
        product *= v
    if product != p - 1:
        raise AssertionError("product of children != %d - 1" % p)
    if pow(w, p - 1, p) != 1:
        raise AssertionError("witness %d fails Fermat for %d" % (w, p))
    for v in values:
        if pow(w, (p - 1) // v, p) == 1:
            raise AssertionError("witness %d is not primitive for %d" % (w, p))
    return p


# ---------------------------------------------------------------- serialisation
def _mag(n):
    """The challenge's bignum magnitude: little-endian, no leading zero byte."""
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "little")


def serialise(node):
    """
    node := 0x00                                    -- the prime 2
          | 0x01 u32(nchildren)
                 ( u32(len) <node> ) * nchildren
                 u32(len) <prime magnitude>
                 u32(len) <witness magnitude>

    every u32 little-endian.
    """
    if node[0] == "E":
        return b"\x00"
    _, children, p, w = node
    out = b"\x01" + struct.pack("<I", len(children))
    for child in children:
        blob = serialise(child)
        out += struct.pack("<I", len(blob)) + blob
    out += struct.pack("<I", len(_mag(p))) + _mag(p)
    out += struct.pack("<I", len(_mag(w))) + _mag(w)
    return out


# ---------------------------------------------------------------- AES-256-CBC
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
]


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _expand(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _encrypt_block(block, w, nr):
    s = [list(block[i::4]) for i in range(4)]  # column-major -> row-major

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[4 * rnd + c][r]

    add_round_key(0)
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        if rnd != nr:
            for c in range(4):
                col = [s[r][c] for r in range(4)]
                t = col[0] ^ col[1] ^ col[2] ^ col[3]
                for r in range(4):
                    s[r][c] = col[r] ^ t ^ _xtime(col[r] ^ col[(r + 1) % 4])
        add_round_key(rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def aes_cbc_encrypt(key, iv, data):
    w, nr = _expand(key)
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        prev = _encrypt_block(blk, w, nr)
        out += prev
    return bytes(out)


# ---------------------------------------------------------------- main
def main():
    random.seed(0xC0FFEE)  # keep rho deterministic run to run

    print("target prime P (little-endian of the 32-byte literal):")
    print("  %d" % TARGET_PRIME)
    assert is_prime(TARGET_PRIME), "target is not prime"
    print("  %d bits, prime: yes" % TARGET_PRIME.bit_length())
    print()

    print("factoring P-1 and building the Pratt certificate tree ...")
    cert = certificate(TARGET_PRIME)
    print("  P-1 = %s" % " * ".join(str(q) for q in factors(TARGET_PRIME - 1)))
    certified = check_certificate(cert)
    assert certified == TARGET_PRIME
    nodes = [0]

    def count(n):
        nodes[0] += 1
        if n[0] == "C":
            for c in n[1]:
                count(c)

    count(cert)
    print("  certificate verified locally: %d nodes" % nodes[0])
    print()

    plaintext = serialise(cert)
    print("serialised certificate: %d bytes, sha256 %s"
          % (len(plaintext), hashlib.sha256(plaintext).hexdigest()))

    blob = base64.b64encode(aes_cbc_encrypt(AES_KEY, AES_IV, plaintext)).decode()
    print("answer blob: %d base64 characters" % len(blob))
    print()
    print(blob)
    print()
    print("Paste that into the crux popup and press Check (takes ~10 s).")
    print("FLAG: %s" % FLAG)

    if len(sys.argv) > 1:
        with open(sys.argv[1], "w") as fh:
            fh.write(blob + "\n")
        print("\nwritten to %s" % sys.argv[1])


if __name__ == "__main__":
    main()
