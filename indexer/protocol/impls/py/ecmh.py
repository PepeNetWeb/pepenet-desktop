"""§13.2 — the pinned, portable `sm ecmh` vector set.

Mirrors impls/c/src/ecmh.c's ecmh_cmd(): hash-to-curve KATs, accumulator
algebra, and a tagged multiset sum, printed as a cross-language byte-identical
`combined` golden. Every reference impl runs this exact script against its own
secp256k1 and must reproduce the same digest. See SPEC-conformance.md §13.2.
"""
import hashlib

import secp256k1 as secp

ECMH_REC_TAG = b"ECMHv1"
# domain tags — second-preimage separation between tables (names-only: no VOTE/DECOR).
TAG_NAME, TAG_COMMIT, TAG_MUT = 0x01, 0x02, 0x04


def _rec_pt(tag, body):
    return secp.ecmh_hash(ECMH_REC_TAG + bytes([tag]) + body)[0]


def run():
    comb = hashlib.sha256()

    def feed(b):
        comb.update(b)

    # version self-doc
    print("ecmh ECMHv1")
    feed(b"ECMHv1")

    # 1. hash-to-curve KAT
    h2c = [
        ("empty", b""),
        ("a", b"a"),
        ("pepe", b"pepenet"),
        ("doge", b"doge"),
        ("ff32", b"\xff" * 32),
        ("z32", b"\x00" * 32),
    ]
    for label, pre in h2c:
        pt, ctr = secp.ecmh_hash(pre)
        print("h2c %s ctr=%d pt=%s" % (label, ctr, pt.hex()))
        feed(bytes([ctr & 0xFF]))
        feed(pt)

    # 2. identity
    idp = secp.ecmh_identity()
    print("identity " + idp.hex())
    feed(idp)

    # 3. tagged multiset sum (NAME/COMMIT/MUT only — matches C ecmh_cmd)
    recs = [
        (TAG_NAME, b"\x03foo"),
        (TAG_NAME, b"\x03bar"),
        (TAG_COMMIT, b"commitment-blob-32-bytes-xxxxxx"),
        (TAG_MUT, b"owner-mutation"),
    ]
    fwd = secp.ecmh_identity()
    for tag, body in recs:
        fwd = secp.ecmh_add(fwd, _rec_pt(tag, body))
    rev = secp.ecmh_identity()
    for tag, body in reversed(recs):
        rev = secp.ecmh_add(rev, _rec_pt(tag, body))
    commut = 1 if fwd == rev else 0
    print("sum " + fwd.hex())
    print("commutative %d" % commut)
    feed(fwd)
    feed(bytes([commut]))

    # 4. inverse round-trip
    pt0 = _rec_pt(recs[0][0], recs[0][1])
    acc = fwd
    acc = secp.ecmh_add(acc, secp.ecmh_negate(pt0))
    acc = secp.ecmh_add(acc, pt0)
    roundtrip = 1 if acc == fwd else 0
    print("inverse_roundtrip %d" % roundtrip)
    feed(bytes([roundtrip]))

    print("combined " + comb.digest().hex())
    return 0
