"""§4 Strategy B — real secp256k1 (self-rolled, stdlib-only).

A genuine elliptic-curve oracle to replace the injected curve pseudo-funcs of the
§4 attribution shell: field arithmetic mod p = 2^256 − 2^32 − 977, point ops, ECDSA
verify, and RFC-6979 deterministic signing (HMAC-SHA256 nonce, low-S normalized).
NOT constant time — a verifier/test oracle, never touches production secret keys.
Mirrors impls/c/src/secp256k1.c byte-for-byte (the C impl is normative). Python's
native int is the bignum; HMAC via stdlib hmac/hashlib.

Pinned in SPEC-conformance.md §13 (curve-vector set) + SPEC-RATIONALE.md §11.
"""
import hashlib
import hmac as _hmac

# p = 2^256 − 2^32 − 977 ; n = group order ; G = generator. Big-endian values.
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_N_HALF = SECP_N >> 1
SECP_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _sha256(d):
    return hashlib.sha256(d).digest()


def _hmac_sha256(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()


# ── field arithmetic mod p (Python int does the bignum) ───────────────────────
def _inv_p(a):
    return pow(a % SECP_P, SECP_P - 2, SECP_P)


def _sqrt_p(a):
    # p ≡ 3 (mod 4): sqrt = a^((p+1)/4)
    return pow(a % SECP_P, (SECP_P + 1) >> 2, SECP_P)


# ── points (affine over GF(p); None == point at infinity) ─────────────────────
def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % SECP_P == 0:
            return None              # P + (−P)
        return _point_double(p)      # P == Q
    lam = ((y2 - y1) * _inv_p(x2 - x1)) % SECP_P
    x3 = (lam * lam - x1 - x2) % SECP_P
    y3 = (lam * (x1 - x3) - y1) % SECP_P
    return (x3, y3)


def _point_double(p):
    if p is None:
        return None
    x1, y1 = p
    if y1 % SECP_P == 0:
        return None
    lam = ((3 * x1 * x1) * _inv_p(2 * y1)) % SECP_P
    x3 = (lam * lam - 2 * x1) % SECP_P
    y3 = (lam * (x1 - x3) - y1) % SECP_P
    return (x3, y3)


def _scalar_mul(k, p):
    # double-and-add over the 256-bit big-endian scalar, MSB first
    r = None
    for bit in range(255, -1, -1):
        r = _point_double(r)
        if (k >> bit) & 1:
            r = _point_add(r, p)
    return r


_G = (SECP_GX, SECP_GY)


# ── pubkey decode + on-curve ──────────────────────────────────────────────────
def _pub_decode(pub):
    """Decode a 33-byte compressed (0x02/0x03) or 65-byte uncompressed (0x04)
    pubkey to (x, y). Returns None on bad length/prefix, X≥p, non-residue."""
    if len(pub) == 33 and pub[0] in (0x02, 0x03):
        x = int.from_bytes(pub[1:33], "big")
        if x >= SECP_P:
            return None
        rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
        beta = _sqrt_p(rhs)
        if (beta * beta) % SECP_P != rhs:
            return None              # not a quadratic residue ⇒ off curve
        want_odd = (pub[0] == 0x03)
        if (beta & 1) != want_odd:
            beta = (SECP_P - beta) % SECP_P
        return (x, beta)
    if len(pub) == 65 and pub[0] == 0x04:
        x = int.from_bytes(pub[1:33], "big")
        y = int.from_bytes(pub[33:65], "big")
        if x >= SECP_P or y >= SECP_P:
            return None
        rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
        if (y * y) % SECP_P != rhs:
            return None
        return (x, y)
    return None


def on_curve(pub):
    """1 iff the canonically-encoded pubkey decodes to a point on the curve."""
    return 1 if _pub_decode(pub) is not None else 0


# ── ECDSA verify (does NOT enforce low-S) ─────────────────────────────────────
def ecdsa_verify(hash32, r32, s32, pub):
    """r32/s32 = 32-byte big-endian scalar VALUES. 1 iff valid for (hash, pub)."""
    q = _pub_decode(pub)
    if q is None:
        return 0
    r = int.from_bytes(r32, "big")
    s = int.from_bytes(s32, "big")
    if r == 0 or r >= SECP_N:
        return 0
    if s == 0 or s >= SECP_N:
        return 0
    z = int.from_bytes(hash32, "big") % SECP_N
    w = pow(s, SECP_N - 2, SECP_N)
    u1 = (z * w) % SECP_N
    u2 = (r * w) % SECP_N
    a = _scalar_mul(u1, _G)
    b = _scalar_mul(u2, q)
    rp = _point_add(a, b)
    if rp is None:
        return 0
    return 1 if (rp[0] % SECP_N) == r else 0


# ── RFC-6979 deterministic nonce + ECDSA sign ─────────────────────────────────
def _rfc6979_k(priv32, hash32):
    h1 = hash32
    h1o = (int.from_bytes(h1, "big") % SECP_N).to_bytes(32, "big")  # bits2octets
    x = priv32                                                       # int2octets
    V = b"\x01" * 32
    K = b"\x00" * 32
    K = _hmac_sha256(K, V + b"\x00" + x + h1o)
    V = _hmac_sha256(K, V)
    K = _hmac_sha256(K, V + b"\x01" + x + h1o)
    V = _hmac_sha256(K, V)
    while True:
        V = _hmac_sha256(K, V)                                       # T = V (qlen 256)
        k = int.from_bytes(V, "big")
        if 1 <= k < SECP_N:
            return V
        K = _hmac_sha256(K, V + b"\x00")
        V = _hmac_sha256(K, V)


def ecdsa_sign(priv32, hash32):
    """RFC-6979 deterministic ECDSA sign, low-S. Returns (r32, s32) or None."""
    d = int.from_bytes(priv32, "big")
    if d == 0 or d >= SECP_N:
        return None
    z = int.from_bytes(hash32, "big") % SECP_N
    feed = hash32
    for _attempt in range(64):
        kb = _rfc6979_k(priv32, feed)
        k = int.from_bytes(kb, "big")
        rp = _scalar_mul(k, _G)
        if rp is None:
            feed = _sha256(kb)
            continue
        r = rp[0] % SECP_N
        if r == 0:
            feed = _sha256(kb)
            continue
        kinv = pow(k, SECP_N - 2, SECP_N)
        s = (kinv * (z + r * d)) % SECP_N
        if s == 0:
            feed = _sha256(kb)
            continue
        if s > SECP_N_HALF:
            s = SECP_N - s
        return (r.to_bytes(32, "big"), s.to_bytes(32, "big"))
    return None


def pubkey(priv32):
    """33-byte compressed pubkey from a private scalar, or None."""
    d = int.from_bytes(priv32, "big")
    if d == 0 or d >= SECP_N:
        return None
    p = _scalar_mul(d, _G)
    if p is None:
        return None
    x, y = p
    prefix = 0x03 if (y & 1) else 0x02
    return bytes([prefix]) + x.to_bytes(32, "big")


# ── ECMH (Elliptic Curve Multiset Hash) ───────────────────────────────────────
# An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero
# sentinel (prefix 0x00) is the identity ∞. Mirrors secp256k1.c's ECMH block.
ECMH_H2C_TAG = b"ECMHh2c1"


def ecmh_identity():
    return b"\x00" * 33


def _ecmh_ser(p):
    if p is None:
        return b"\x00" * 33
    x, y = p
    return bytes([0x03 if (y & 1) else 0x02]) + x.to_bytes(32, "big")


def _ecmh_load(in33):
    if in33[0] == 0:
        return None
    return _pub_decode(in33)


def ecmh_hash(pre):
    """Try-and-increment hash-to-curve. Returns (pt33, ctr); pt prefix ALWAYS 0x02."""
    ctr = 0
    while True:
        cb = bytes([ctr & 0xFF, (ctr >> 8) & 0xFF, (ctr >> 16) & 0xFF, (ctr >> 24) & 0xFF])
        h = _sha256(ECMH_H2C_TAG + pre + cb)
        x = int.from_bytes(h, "big") % SECP_P
        rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
        beta = _sqrt_p(rhs)
        if (beta * beta) % SECP_P == rhs:
            return (bytes([0x02]) + x.to_bytes(32, "big"), ctr)
        ctr += 1


def ecmh_negate(pt33):
    if pt33[0] == 0:
        return pt33
    return bytes([pt33[0] ^ 1]) + pt33[1:]


def ecmh_add(acc33, pt33):
    a = _ecmh_load(acc33)
    p = _ecmh_load(pt33)
    return _ecmh_ser(_point_add(a, p))


def ecmh_selftest():
    """0 on success. Mirrors secp_ecmh_selftest (commutativity/identity/inverse/round-trip)."""
    fail = 0
    idp = ecmh_identity()
    pa = ecmh_hash(b"alpha")[0]
    pb = ecmh_hash(b"beta")[0]
    acc1 = ecmh_add(ecmh_add(ecmh_identity(), pa), pb)
    acc2 = ecmh_add(ecmh_add(ecmh_identity(), pb), pa)
    if acc1 != acc2:                                   # commutativity
        fail += 1
    if ecmh_add(ecmh_identity(), pa) != pa:            # identity: ∞ + P == P
        fail += 1
    npa = ecmh_negate(pa)
    if ecmh_add(ecmh_add(ecmh_identity(), pa), npa) != idp:   # inverse: P + (−P) == ∞
        fail += 1
    acc1 = ecmh_add(ecmh_identity(), pa)
    acc2 = ecmh_add(ecmh_add(acc1, pb), ecmh_negate(pb))      # add-then-remove round-trip
    if acc1 != acc2:
        fail += 1
    return fail


# ── self-check: constants + 2G KAT + n·G=∞ + decompress + sign/verify ─────────
def selftest():
    """0 on success, nonzero (failure count) otherwise. Mirrors secp_selftest."""
    fail = 0
    # N_HALF = N>>1
    if SECP_N_HALF != (SECP_N >> 1):
        fail += 1
    # G on curve via uncompressed encoding
    g_unc = b"\x04" + SECP_GX.to_bytes(32, "big") + SECP_GY.to_bytes(32, "big")
    if not on_curve(g_unc):
        fail += 1
    # 2G known-answer
    G2X = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    G2Y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
    p2 = _scalar_mul(2, _G)
    if p2 is None or p2[0] != G2X or p2[1] != G2Y:
        fail += 1
    # n·G == ∞
    if _scalar_mul(SECP_N, _G) is not None:
        fail += 1
    # decompress round-trip: compress G (Gy even ⇒ 0x02), decode, compare Y
    gc = b"\x02" + SECP_GX.to_bytes(32, "big")
    dec = _pub_decode(gc)
    if dec is None or dec[1] != SECP_GY:
        fail += 1
    # sign / verify round-trip over deterministic keys + tamper check
    for t in range(1, 5):
        priv = (t * 7 + 1).to_bytes(32, "big")
        pub = pubkey(priv)
        if pub is None:
            fail += 1
            continue
        msg = bytes((i * 13 + t) & 0xFF for i in range(32))
        mh = _sha256(msg)
        sig = ecdsa_sign(priv, mh)
        if sig is None:
            fail += 1
            continue
        r, s = sig
        if not ecdsa_verify(mh, r, s, pub):
            fail += 1
        mh2 = bytes([mh[0] ^ 0x01]) + mh[1:]
        if ecdsa_verify(mh2, r, s, pub):
            fail += 1
    return fail


if __name__ == "__main__":
    import sys
    f = selftest()
    print("secp selftest", "ok" if f == 0 else "FAIL=%d" % f)
    sys.exit(0 if f == 0 else 1)
