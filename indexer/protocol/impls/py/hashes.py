"""Hash primitives: SHA-256 (stdlib) + RIPEMD-160 (stdlib if present, else self-rolled).

hash160(x) = RIPEMD160(SHA256(x))  (§0, §4 Rule 3).
"""
import hashlib

_MASK32 = 0xFFFFFFFF


def sha256(b):
    return hashlib.sha256(b).digest()


def dsha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---- self-rolled RIPEMD-160 (used only if hashlib lacks it) ----
_R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_Rp = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
_S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_Sp = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
_K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_Kp = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _ripemd160_pure(msg):
    h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE,
                          0x10325476, 0xC3D2E1F0)
    ml = len(msg)
    pad = b"\x80" + b"\x00" * ((55 - ml) % 64) + (ml * 8 & ((1 << 64) - 1)).to_bytes(8, "little")
    data = msg + pad
    for off in range(0, len(data), 64):
        blk = data[off:off + 64]
        X = [int.from_bytes(blk[i:i + 4], "little") for i in range(0, 64, 4)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            t = (al + _f(j, bl, cl, dl) + X[_R[j]] + _K[j // 16]) & _MASK32
            t = (_rol(t, _S[j]) + el) & _MASK32
            al, bl, cl, dl, el = el, t, bl, _rol(cl, 10), dl
            t = (ar + _f(79 - j, br, cr, dr) + X[_Rp[j]] + _Kp[j // 16]) & _MASK32
            t = (_rol(t, _Sp[j]) + er) & _MASK32
            ar, br, cr, dr, er = er, t, br, _rol(cr, 10), dr
        t = (h1 + cl + dr) & _MASK32
        h1 = (h2 + dl + er) & _MASK32
        h2 = (h3 + el + ar) & _MASK32
        h3 = (h4 + al + br) & _MASK32
        h4 = (h0 + bl + cr) & _MASK32
        h0 = t
    return b"".join(x.to_bytes(4, "little") for x in (h0, h1, h2, h3, h4))


try:
    hashlib.new("ripemd160").digest()
    def ripemd160(b):
        h = hashlib.new("ripemd160")
        h.update(b)
        return h.digest()
except Exception:  # pragma: no cover - depends on OpenSSL build
    ripemd160 = _ripemd160_pure


def hash160(b):
    return ripemd160(sha256(b))


def _selftest():
    # KATs from SPEC-conformance.md §13
    assert ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert hash160(b"abc").hex().startswith("bb1be98c")
    # cross-check pure vs library
    assert _ripemd160_pure(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


if __name__ == "__main__":
    _selftest()
    print("hashes selftest ok")
