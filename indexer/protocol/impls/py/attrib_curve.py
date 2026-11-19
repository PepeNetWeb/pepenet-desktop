"""§4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).

Mirrors impls/c/src/attrib_curve.c (normative): pinned P/N/N_HALF constants,
on-curve membership at the edges, RFC-6979 deterministic (r,s) + canonical-DER
known-answers, ECDSA verify accept/reject at the scalar boundaries, tiny-key KAT,
the PRIMARY `combined` digest over the pure curve layer, then the end-to-end
section (`combined_e2e`) which links the real curve to the §4 attribution shell.

Every reference impl runs this exact vector script and must print byte-identical
output. See SPEC-conformance.md §13 + SPEC-RATIONALE.md §11.
"""
import hashlib

import secp256k1 as secp
import attrib

CV_P = secp.SECP_P.to_bytes(32, "big")
CV_N = secp.SECP_N.to_bytes(32, "big")
CV_NHALF = secp.SECP_N_HALF.to_bytes(32, "big")
CV_GX = secp.SECP_GX.to_bytes(32, "big")
CV_GY = secp.SECP_GY.to_bytes(32, "big")


def _der_int(v):
    i = 0
    while i < 31 and v[i] == 0:
        i += 1
    body = v[i:]
    pad = b"\x00" if (body[0] & 0x80) else b""
    return b"\x02" + bytes([len(pad) + len(body)]) + pad + body


def _der_sig(r, s):
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body + b"\x01"   # SIGHASH_ALL


def run():
    comb = hashlib.sha256()

    def feed(b):
        comb.update(b)

    # ── 1. pinned constants ────────────────────────────────────────────────
    print("p " + CV_P.hex());     feed(CV_P)
    print("n " + CV_N.hex());     feed(CV_N)
    print("nhalf " + CV_NHALF.hex()); feed(CV_NHALF)

    # ── 2. on-curve membership at the edges ────────────────────────────────
    oc = []
    oc.append(("oc_G_uncomp", b"\x04" + CV_GX + CV_GY))
    oc.append(("oc_G_comp02", b"\x02" + CV_GX))
    oc.append(("oc_G_comp03", b"\x03" + CV_GX))
    oc.append(("oc_G_badY", b"\x04" + CV_GX + CV_GY[:31] + bytes([CV_GY[31] ^ 0x01])))
    oc.append(("oc_X0", b"\x02" + b"\x00" * 32))
    oc.append(("oc_X1", b"\x02" + b"\x00" * 31 + b"\x01"))
    oc.append(("oc_Xeqp", b"\x04" + CV_P + CV_GY))
    oc.append(("oc_comp_Xeqp", b"\x02" + CV_P))
    oc.append(("oc_badprefix", b"\x05" + CV_GX))
    for name, key in oc:
        v = secp.on_curve(key)
        print("%s %d" % (name, v))
        feed(bytes([v]))
        feed(key)

    # ── 3 & 4. RFC-6979 sign + ECDSA verify at the boundaries ──────────────
    for i in range(4):
        priv = (b"\x00" * 28) + bytes([0xC0, 0xFF, 0xEE, 0x10 + i])
        pub = secp.pubkey(priv)
        if pub is None:
            print("sig%d PUBFAIL" % i)
            continue
        m = ("strategy-b curve vector %d" % i).encode()
        h = hashlib.sha256(m).digest()
        sig = secp.ecdsa_sign(priv, h)
        if sig is None:
            print("sig%d SIGNFAIL" % i)
            continue
        r, s = sig
        der = _der_sig(r, s)
        print("sig%d pub=%s r=%s s=%s der=%s" % (i, pub.hex(), r.hex(), s.hex(), der.hex()))
        feed(pub); feed(r); feed(s); feed(der)

        zero = b"\x00" * 32
        hbad = bytes([h[0] ^ 0x01]) + h[1:]
        hiS = (secp.SECP_N - int.from_bytes(s, "big")).to_bytes(32, "big")
        wrongpub = bytes([pub[0] ^ 0x01]) + pub[1:]
        vt = [
            ("valid", h, r, s, pub),
            ("tamper", hbad, r, s, pub),
            ("r0", h, zero, s, pub),
            ("s0", h, r, zero, pub),
            ("rN", h, CV_N, s, pub),
            ("sN", h, r, CV_N, pub),
            ("highS", h, r, hiS, pub),
            ("wrongpk", h, r, s, wrongpub),
        ]
        line = "ver%d" % i
        for nm, hh, rr, ss, pk in vt:
            v = secp.ecdsa_verify(hh, rr, ss, pk)
            line += " %s=%d" % (nm, v)
            feed(bytes([v]))
        print(line)

    # ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G ──────────────────
    pk1 = secp.pubkey((1).to_bytes(32, "big"))
    print("priv1_pub=" + pk1.hex()); feed(pk1)
    pk2 = secp.pubkey((2).to_bytes(32, "big"))
    print("priv2_pub=" + pk2.hex()); feed(pk2)

    # PRIMARY cross-language digest (sections 1–5).
    print("combined " + comb.digest().hex())

    # ── 6. end-to-end (depends on §4 attribution byte-logic + sighash linkage) ──
    e2e = hashlib.sha256()
    lines = attrib.attrib_real_endtoend(e2e.update)
    for ln in lines:
        print(ln)
    print("combined_e2e " + e2e.digest().hex())
    return 0
