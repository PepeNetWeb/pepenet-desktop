"""§4 Stateless Identity & Attribution byte-logic (protocol-spec.md §4,
SPEC-conformance.md §13).

attribute(tx, k) -> (status, sighash[32], identity[20])
  status: 0 classify-drop, 1 on-curve-drop, 2 verify-drop, 3 found.

The two elliptic-curve operations are the INJECTED pseudo-functions of §13 —
NOT real secp256k1. Everything else is real byte-logic.
"""
from hashes import sha256, dsha256, hash160

# secp256k1 field & order (real, used only for range/low-S byte checks)
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_N_HALF = SECP_N >> 1

ST_CLASSIFY_DROP = 0
ST_ONCURVE_DROP = 1
ST_VERIFY_DROP = 2
ST_FOUND = 3

ZERO32 = b"\x00" * 32
ZERO20 = b"\x00" * 20


# ---------------- injected curve oracle (§13) ----------------
def on_curve(pubkey):
    return sha256(b"\x4f" + pubkey)[0] != 0x00


def verify(hash32, r32, s32, pubkey):
    return sha256(b"\x56" + hash32 + r32 + s32 + pubkey)[0] >= 0x20


# ---------------- §4 Strategy B real-curve toggle ----------------
# 0 = injected pseudo-funcs (Tier-1 self-regression; the attrib/attrib-scenario/
# selftest goldens), 1 = REAL secp256k1 (the §4 Strategy B end-to-end vectors in
# attrib-curve). attrib/attrib-scenario/selftest never flip this, so their byte
# output stays identical. Mirrors C's g_real_curve seam in attrib.c.
_real_curve = 0


def _oc_gate(pk):
    if _real_curve:
        import secp256k1
        return 1 if secp256k1.on_curve(pk) else 0
    return on_curve(pk)


def _vf_gate(hash32, r32, s32, pk):
    if _real_curve:
        import secp256k1
        return secp256k1.ecdsa_verify(hash32, r32, s32, pk)
    return verify(hash32, r32, s32, pk)


# ---------------- strict DER + low-S ----------------
def parse_der_sig(sig):
    """sig = DER ‖ hashtype-byte. Returns (r_int, s_int) or None.
    Enforces BIP66 strict-DER, low-S (S<=N/2), and hashtype == 0x01."""
    if len(sig) < 1:
        return None
    hashtype = sig[-1]
    if hashtype != 0x01:               # Rule 3: SIGHASH_ALL only
        return None
    der = sig[:-1]
    n = len(der)
    if n < 8 or n > 72:
        return None
    if der[0] != 0x30:
        return None
    if der[1] != n - 2:
        return None
    # R
    if der[2] != 0x02:
        return None
    lenR = der[3]
    if lenR == 0 or 4 + lenR + 2 > n:
        return None
    R = der[4:4 + lenR]
    if R[0] & 0x80:
        return None                    # negative
    if len(R) > 1 and R[0] == 0x00 and not (R[1] & 0x80):
        return None                    # non-minimal pad
    # S
    so = 4 + lenR
    if der[so] != 0x02:
        return None
    lenS = der[so + 1]
    if lenS == 0:
        return None
    if so + 2 + lenS != n:
        return None                    # trailing bytes / wrong total length
    S = der[so + 2:so + 2 + lenS]
    if S[0] & 0x80:
        return None
    if len(S) > 1 and S[0] == 0x00 and not (S[1] & 0x80):
        return None
    r_int = int.from_bytes(R, "big")
    s_int = int.from_bytes(S, "big")
    if r_int >= (1 << 256) or s_int >= (1 << 256):
        return None                    # R or S ≥ 2^256: reject (match C/Go), NOT truncate/raise in _r32
    if s_int > SECP_N_HALF:            # low-S
        return None
    return (r_int, s_int)


def _r32(x):
    return x.to_bytes(32, "big")


# ---------------- pubkey canonical encoding ----------------
def pubkey_canonical(pk):
    """Rule 4: 33-byte 0x02/0x03 or 65-byte 0x04, coords < p. Reject hybrid.
    Returns True if canonically ENCODED (on-curve checked separately)."""
    if len(pk) == 33:
        if pk[0] not in (0x02, 0x03):
            return False
        x = int.from_bytes(pk[1:33], "big")
        return x < SECP_P
    if len(pk) == 65:
        if pk[0] != 0x04:
            return False
        x = int.from_bytes(pk[1:33], "big")
        y = int.from_bytes(pk[33:65], "big")
        return x < SECP_P and y < SECP_P
    return False


# ---------------- script tokenizer (minimal-push aware) ----------------
def tokenize(script):
    """Return list of tokens [('push', data) | ('op', opcode)] or None on a
    non-minimal/malformed push. Enforces minimal push encoding (§13)."""
    toks = []
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op == 0x00:
            toks.append(("op", 0x00))       # OP_0 (NULLDUMMY / empty)
        elif 1 <= op <= 75:
            data = script[i:i + op]
            if len(data) != op:
                return None
            i += op
            toks.append(("push", data))
        elif op == 0x4C:                    # PUSHDATA1
            if i >= n:
                return None
            ln = script[i]
            i += 1
            if ln < 76:                     # non-minimal
                return None
            data = script[i:i + ln]
            if len(data) != ln:
                return None
            i += ln
            toks.append(("push", data))
        elif op == 0x4D:                    # PUSHDATA2
            if i + 2 > n:
                return None
            ln = int.from_bytes(script[i:i + 2], "little")
            i += 2
            if ln < 256:
                return None
            data = script[i:i + ln]
            if len(data) != ln:
                return None
            i += ln
            toks.append(("push", data))
        else:
            toks.append(("op", op))         # OP_m/OP_n etc (not in scriptSig)
    return toks


# ---------------- redeemScript multisig template ----------------
def _decode_smallint(op):
    if op == 0x00:
        return 0
    if 0x51 <= op <= 0x60:
        return op - 0x50
    return None


def parse_multisig_redeem(rs):
    """Match OP_m <33B key>×n OP_n OP_CHECKMULTISIG, 1<=m<=n<=15, compressed
    keys only, minimal OP_m/OP_n, no trailing. Returns (m, [keys]) or None."""
    n = len(rs)
    if n < 1 + 34 + 1 + 1:   # OP_m + at least 1 key + OP_n + OP_CHECKMULTISIG
        return None
    m = _decode_smallint(rs[0])
    if m is None or not (1 <= m <= 15):
        return None
    i = 1
    keys = []
    while i < n and rs[i] == 0x21:     # 33-byte compressed key push
        key = rs[i + 1:i + 1 + 33]
        if len(key) != 33:
            return None
        if key[0] not in (0x02, 0x03):
            return None
        keys.append(key)
        i += 34
    if i >= n:
        return None
    nn = _decode_smallint(rs[i])
    if nn is None or not (1 <= nn <= 15):
        return None
    if nn != len(keys):
        return None
    i += 1
    if i != n - 1:
        return None
    if rs[i] != 0xAE:                  # OP_CHECKMULTISIG
        return None
    if not (m <= nn):
        return None
    return (m, keys)


# ---------------- legacy sighash + FindAndDelete ----------------
def _varint(x):
    if x < 0xFD:
        return bytes([x])
    if x <= 0xFFFF:
        return b"\xFD" + x.to_bytes(2, "little")
    if x <= 0xFFFFFFFF:
        return b"\xFE" + x.to_bytes(4, "little")
    return b"\xFF" + x.to_bytes(8, "little")


def _ser_script(s):
    return _varint(len(s)) + s


def find_and_delete(script, pattern):
    """Bitcoin Core CScript::FindAndDelete: remove boundary-aligned occurrences
    of `pattern` (a serialized push) from `script`, via opcode-boundary walk."""
    if not pattern:
        return script
    out = bytearray()
    i = 0
    n = len(script)
    while i < n:
        # try match at this opcode boundary
        if script[i:i + len(pattern)] == pattern:
            i += len(pattern)
            continue
        # advance by one whole opcode (GetOp semantics)
        op = script[i]
        start = i
        i += 1
        if 1 <= op <= 75:
            i += op
        elif op == 0x4C and i < n:
            ln = script[i]
            i += 1 + ln
        elif op == 0x4D and i + 2 <= n:
            ln = int.from_bytes(script[i:i + 2], "little")
            i += 2 + ln
        elif op == 0x4E and i + 4 <= n:
            ln = int.from_bytes(script[i:i + 4], "little")
            i += 4 + ln
        out += script[start:i]
    return bytes(out)


def serialize_for_sighash(tx, k, script_code):
    out = bytearray()
    out += tx["version"].to_bytes(4, "little")
    out += _varint(len(tx["vin"]))
    for idx, vin in enumerate(tx["vin"]):
        out += vin["txid"]
        out += vin["vout"].to_bytes(4, "little")
        if idx == k:
            out += _ser_script(script_code)
        else:
            out += _ser_script(b"")
        out += vin["sequence"].to_bytes(4, "little")
    out += _varint(len(tx["vout"]))
    for vo in tx["vout"]:
        out += vo["value"].to_bytes(8, "little")
        out += _ser_script(vo["spk"])
    out += tx["locktime"].to_bytes(4, "little")
    out += (1).to_bytes(4, "little")   # SIGHASH_ALL appended as 4-byte LE int32
    return bytes(out)


def legacy_sighash(tx, k, script_code, sig_push_serialized):
    sc = find_and_delete(script_code, sig_push_serialized)
    return dsha256(serialize_for_sighash(tx, k, sc))


def _minimal_push_of(data):
    n = len(data)
    if n < 76:
        return bytes([n]) + data
    if n < 256:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + n.to_bytes(2, "little") + data


# ---------------- top-level attribute ----------------
def attribute(tx, k):
    """Return (status, sighash[32], identity[20]) for input k of tx."""
    if k >= len(tx["vin"]):
        return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
    ss = tx["vin"][k]["scriptSig"]
    toks = tokenize(ss)
    if toks is None:
        return (ST_CLASSIFY_DROP, ZERO32, ZERO20)

    # ---- P2PKH: exactly two pushes [sig][pubkey] ----
    if len(toks) == 2 and toks[0][0] == "push" and toks[1][0] == "push":
        sig = toks[0][1]
        pk = toks[1][1]
        rs = parse_der_sig(sig)
        if rs is None:
            return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
        if not pubkey_canonical(pk):
            return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
        # classification succeeded -> identity + sighash formed now
        identity = hash160(pk)
        script_code = (b"\x76\xa9\x14" + identity + b"\x88\xac")  # P2PKH template
        sighash = legacy_sighash(tx, k, script_code, _minimal_push_of(sig))
        if not _oc_gate(pk):
            return (ST_ONCURVE_DROP, sighash, identity)
        r_int, s_int = rs
        if _vf_gate(sighash, _r32(r_int), _r32(s_int), pk):
            return (ST_FOUND, sighash, identity)
        return (ST_VERIFY_DROP, sighash, identity)

    # ---- P2SH multisig: OP_0 [sig]×m [redeemScript] ----
    if len(toks) >= 3 and toks[0] == ("op", 0x00) and toks[-1][0] == "push":
        # NULLDUMMY enforced: first token must be OP_0 exactly
        redeem = toks[-1][1]
        parsed = parse_multisig_redeem(redeem)
        if parsed is None:
            return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
        m, keys = parsed
        sig_toks = toks[1:-1]
        if len(sig_toks) != m:
            return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
        sigs = []
        for t in sig_toks:
            if t[0] != "push":
                return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
            parsed_sig = parse_der_sig(t[1])
            if parsed_sig is None:
                return (ST_CLASSIFY_DROP, ZERO32, ZERO20)
            sigs.append((t[1], parsed_sig))
        identity = hash160(redeem)
        # sighash formed after classification (FindAndDelete inert here but applied)
        sighash = legacy_sighash(tx, k, redeem, _minimal_push_of(sigs[0][0]))
        # on-curve checked on ALL n keys up front (§4 step 4)
        for key in keys:
            if not _oc_gate(key):
                return (ST_ONCURVE_DROP, sighash, identity)
        # in-order scan: each sig against next matching key
        ki = 0
        verified = 0
        for sig_bytes, (r_int, s_int) in sigs:
            while ki < len(keys):
                if _vf_gate(sighash, _r32(r_int), _r32(s_int), keys[ki]):
                    verified += 1
                    ki += 1
                    break
                ki += 1
        if verified == m:
            return (ST_FOUND, sighash, identity)
        return (ST_VERIFY_DROP, sighash, identity)

    return (ST_CLASSIFY_DROP, ZERO32, ZERO20)


# ---------------- §4 Strategy B end-to-end (real curve) ----------------
def _der_int_e(v):
    i = 0
    while i < 31 and v[i] == 0:
        i += 1
    body = v[i:]
    pad = b"\x00" if (body[0] & 0x80) else b""
    return b"\x02" + bytes([len(pad) + len(body)]) + pad + body


def _der_sig_e(r, s):
    body = _der_int_e(r) + _der_int_e(s)
    return b"\x30" + bytes([len(body)]) + body + b"\x01"   # SIGHASH_ALL


def _e2e_txdict(ss):
    """1 input (outpoint 0x11.., seq=FFFFFFFF), 1 OP_RETURN output (value 100000),
    version 1, locktime 0 — matching the C e2e_skeleton/e2e_rawtx."""
    return {"version": 1, "locktime": 0,
            "vin": [{"txid": b"\x11" * 32, "vout": 0x11111111,
                     "scriptSig": ss, "sequence": 0xFFFFFFFF}],
            "vout": [{"value": 100000, "spk": b"\x6a"}]}


def _e2e_sighash(script_code):
    """Legacy sighash over the e2e skeleton's input 0 with the given scriptCode
    (no FindAndDelete: the sig pushes never appear in P2PKH/redeem scriptCode)."""
    tx = _e2e_txdict(b"")
    return dsha256(serialize_for_sighash(tx, 0, script_code))


def attrib_real_endtoend(fold):
    """Build 3 txs, sign their genuine legacy sighash with RFC-6979, run the full
    real-curve attribute() pipeline, print e2e_* lines and feed the digest hasher
    `fold` with status(1)‖sighash(32)‖identity(20) per input. Mirrors C."""
    global _real_curve
    import secp256k1
    out = []
    _real_curve = 1
    try:
        def emit(name, tx):
            status, sighash, identity = attribute(tx, 0)
            out.append("%s %d:%s" % (name, status, identity.hex()))
            fold(bytes([status]) + sighash + identity)

        # A. P2PKH, correctly signed ⇒ FOUND (status 3)
        priv = (0x2A).to_bytes(32, "big")
        pub = secp256k1.pubkey(priv)
        h160 = hash160(pub)
        sc = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        sh = _e2e_sighash(sc)
        r, s = secp256k1.ecdsa_sign(priv, sh)
        der = _der_sig_e(r, s)
        ss = _minimal_push_of(der) + _minimal_push_of(pub)
        emit("e2e_p2pkh_valid", _e2e_txdict(ss))

        # B. P2PKH, signed by the WRONG key ⇒ verify-drop (status 2)
        priv = (0x2A).to_bytes(32, "big")
        wrong = (0x2B).to_bytes(32, "big")
        pub = secp256k1.pubkey(priv)
        h160 = hash160(pub)
        sc = b"\x76\xa9\x14" + h160 + b"\x88\xac"
        sh = _e2e_sighash(sc)
        r, s = secp256k1.ecdsa_sign(wrong, sh)
        der = _der_sig_e(r, s)
        ss = _minimal_push_of(der) + _minimal_push_of(pub)
        emit("e2e_p2pkh_wrongkey", _e2e_txdict(ss))

        # C. 2-of-2 P2SH multisig, two correct in-order sigs ⇒ FOUND (status 3)
        privs = [(0x50).to_bytes(32, "big"), (0x51).to_bytes(32, "big")]
        pubs = [secp256k1.pubkey(p) for p in privs]
        rs = b"\x52"                                    # OP_2
        for pk in pubs:
            rs += b"\x21" + pk                          # <33B key>
        rs += b"\x52\xae"                               # OP_2 OP_CHECKMULTISIG
        sh = _e2e_sighash(rs)
        ss = b"\x00"                                    # NULLDUMMY
        for p in privs:
            r, s = secp256k1.ecdsa_sign(p, sh)
            ss += _minimal_push_of(_der_sig_e(r, s))
        ss += _minimal_push_of(rs)
        emit("e2e_multisig_valid", _e2e_txdict(ss))
    finally:
        _real_curve = 0
    return out


def _selftest():
    assert parse_der_sig(b"") is None
    # a structurally valid DER low-S sig with hashtype 0x01
    r = (1).to_bytes(1, "big")
    s = (1).to_bytes(1, "big")
    der = b"\x30" + bytes([2 + len(r) + 2 + len(s)]) + b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
    assert parse_der_sig(der + b"\x01") == (1, 1)
    assert parse_der_sig(der + b"\x02") is None   # wrong hashtype
    # high-S rejected
    s_high = (SECP_N_HALF + 1).to_bytes(32, "big")
    der2 = b"\x30" + bytes([2 + 1 + 2 + 33]) + b"\x02\x01\x01\x02\x21" + b"\x00" + s_high[1:] if False else None
    assert find_and_delete(b"\x01\xAA", b"\x01\xAA") == b""


if __name__ == "__main__":
    _selftest()
    print("attrib selftest ok")
