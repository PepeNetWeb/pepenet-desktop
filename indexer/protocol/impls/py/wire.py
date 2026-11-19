"""Strict, fail-closed wire decoder (protocol-spec.md §0/§1/§2, SPEC-conformance.md §9).

Turns an OP_RETURN payload into ACTION | IGNORE. Any malformed field or
length mismatch => IGNORE (fail closed). A malformed input never raises.

Decode operates on the *payload* = the bytes of the single minimal push (§1).
`single_minimal_push` extracts that from a raw scriptPubKey for completeness.
"""
from const import (PREFIX, OP_RENEW_NAME, OP_TRANSFER_NAME, OP_COMMIT, OP_CLAIM,
                   CARRIER_MAX, BODY_MAX,
                   OP_RENEW, OP_TRANSFER, OP_SELL, OP_RESERVE, OP_SETTLE,
                   OP_RELEASE, OP_RELEASE_NAME, OP_SELL_TO, OP_PAY, OP_AS, OP_TRADE)

IGNORE = "IGNORE"
ACTION = "ACTION"

_NAME_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-")


def valid_name(b):
    """§3.1: charset [a-z0-9-] (a DNS label), length 1..32, byte-for-byte (no case fold).
    Structural (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at positions
    3–4 (kills xn-- and every ACE prefix). Uppercase stays invalid."""
    if not (1 <= len(b) <= 32):
        return False
    for ch in b:
        if ch not in _NAME_BYTES:
            return False
    if b[0] == ord("-") or b[-1] == ord("-"):
        return False
    if len(b) >= 4 and b[2] == ord("-") and b[3] == ord("-"):
        return False
    return True


def single_minimal_push(spk):
    """Extract the lone minimal data push from `OP_RETURN <push>` (§1).
    Returns payload bytes, or None if the script is not exactly OP_RETURN + one
    minimal push (multi-push / non-minimal / trailing opcode => None)."""
    if len(spk) < 1 or spk[0] != 0x6A:  # OP_RETURN
        return None
    i = 1
    n = len(spk)
    if i >= n:
        return None  # bare OP_RETURN, no push -> not a carrier
    op = spk[i]
    i += 1
    if op == 0x00:  # OP_0 pushes empty; minimal for empty data
        data = b""
    elif 1 <= op <= 75:
        if op == 0:
            return None
        data = spk[i:i + op]
        if len(data) != op:
            return None
        # minimal: a 1-byte value in 1..16 or 0x81 should use OP_N, but for
        # OP_RETURN payloads we treat any direct 1..75 push as the carrier; the
        # spec's "minimal push" only forbids over-long length prefixes here.
        i += op
    elif op == 0x4C:  # OP_PUSHDATA1
        if i >= n:
            return None
        ln = spk[i]
        i += 1
        if ln < 76:  # non-minimal: must use direct push
            return None
        data = spk[i:i + ln]
        if len(data) != ln:
            return None
        i += ln
    elif op == 0x4D:  # OP_PUSHDATA2
        if i + 2 > n:
            return None
        ln = int.from_bytes(spk[i:i + 2], "little")
        i += 2
        if ln < 256:
            return None
        data = spk[i:i + ln]
        if len(data) != ln:
            return None
        i += ln
    else:
        return None
    if i != n:
        return None  # trailing bytes / extra opcode
    if len(data) > CARRIER_MAX:
        return None
    return data


def _u32(b):
    return int.from_bytes(b, "little")


def _u64(b):
    return int.from_bytes(b, "little")


def decode_payload(payload, value):
    """Return (kind, info).
    kind == ACTION  -> info is a dict {op, ...fields}
    kind == IGNORE  -> info is None
    Never raises (fail closed)."""
    try:
        return _decode(payload, value)
    except Exception:
        return (IGNORE, None)


def _decode(payload, value):
    n = len(payload)
    # ACTION prefix test: len>=4, payload[0:3]==FF 53 50, opcode 0x01..0x0F
    if n >= 4 and payload[0:3] == PREFIX:
        op = payload[3]
        if not (OP_RENEW_NAME <= op <= OP_TRADE):
            return (IGNORE, None)   # unknown / overlay band
        b = payload[4:]
        bl = n - 4
        info = _decode_action(op, b, bl)
        if info is None:
            return (IGNORE, None)   # malformed action
        info["op"] = op
        return (ACTION, info)
    # everything else (UTF-8 noise, empty, non-prefix) → IGNORE
    return (IGNORE, None)


def _decode_action(op, b, bl):
    """Return a field dict on success, else None. (caller maps None -> IGNORE)"""
    if op == OP_COMMIT:
        if bl != 32:
            return None
        return {"commitment": b[0:32]}

    if op == OP_CLAIM:
        if not (33 <= bl <= 64):   # salt32 + name1..32
            return None
        salt = b[0:32]
        name = b[32:]
        if not valid_name(name):
            return None
        return {"salt": salt, "name": name}

    if op == OP_RENEW:
        if bl == 0:
            return {"mode": "all"}
        if bl == 5:
            return {"mode": "all_safe", "anchor": _u32_5(b[0:5])}
        if 6 <= bl <= BODY_MAX:
            return {"mode": "selective", "anchor": _u32_5(b[0:5]),
                    "flags": b[5:]}
        return None

    if op == OP_TRANSFER:
        if bl == 20:
            return {"mode": "all", "target": b[0:20]}
        if 26 <= bl <= BODY_MAX:
            return {"mode": "selective", "target": b[0:20],
                    "anchor": _u32_5(b[20:25]), "flags": b[25:]}
        return None

    if op == OP_SELL:
        if not (13 <= bl <= 44):   # price8 + window4 + name1..32
            return None
        price = _u64(b[0:8])
        window = _u32(b[8:12])
        name = b[12:]
        if not valid_name(name):
            return None
        return {"price": price, "window": window, "name": name}

    if op in (OP_RENEW_NAME, OP_RELEASE_NAME, OP_RESERVE, OP_SETTLE, OP_PAY):
        if not (1 <= bl <= 32):    # name1..32
            return None
        name = b[0:bl]
        if not valid_name(name):
            return None
        return {"name": name}

    if op == OP_TRANSFER_NAME:
        if not (21 <= bl <= 52):   # target20 + name1..32
            return None
        target = b[0:20]
        name = b[20:]
        if not valid_name(name):
            return None
        return {"target": target, "name": name}

    if op == OP_RELEASE:
        if not (6 <= bl <= BODY_MAX):
            return None
        return {"anchor": _u32_5(b[0:5]), "flags": b[5:]}

    if op == OP_SELL_TO:
        if not (29 <= bl <= 60):   # price8 + buyer20 + name1..32
            return None
        price = _u64(b[0:8])
        buyer = b[8:28]
        name = b[28:]
        if not valid_name(name):
            return None
        return {"price": price, "buyer": buyer, "name": name}

    if op == OP_AS:
        if bl != 1:
            return None
        return {"index": b[0]}

    if op == OP_TRADE:
        if bl < 5:
            return None
        idxA = b[0]
        idxB = b[1]
        rest = b[2:]
        if rest.count(0x2C) != 1:
            return None
        i = rest.index(0x2C)
        nameA = rest[0:i]
        nameB = rest[i + 1:]
        if not valid_name(nameA) or not valid_name(nameB):
            return None
        return {"idxA": idxA, "idxB": idxB, "nameA": nameA, "nameB": nameB}

    return None  # unreachable (op range gated above)


def _u32_5(b):
    """5-byte little-endian height anchor (§0)."""
    return int.from_bytes(b, "little")
