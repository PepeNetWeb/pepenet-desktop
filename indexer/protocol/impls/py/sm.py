#!/usr/bin/env python3
"""PepeNet namespace reference state machine — clean-room Python implementation.

Run:  python3 impl/sm.py <mode>
Modes:
  selftest            run the hand-authored vector battery + primitive KATs
  scenario            emit the 52 named cross-language conformance vectors + combined
  digest <seed> <n>   run the (own, non-reference) generator, print state_digest
  random <seed> <n>   alias of digest
  decode-demo         show the wire decoder on a few payloads
  attrib-demo         show §4 attribution on a couple of synthetic txs

NOTE on goldens: the seed-driven generator below is internally consistent but is
NOT the reference generator (SPEC-conformance.md §5 pins that to a reference this
clean-room cannot see). Its digests are my own and are explicitly NOT comparable
to the reference frozen goldens (§6). See SPEC-RATIONALE.md.
"""
import sys

from const import *
from prng import SplitMix64
import prng as _prng
import hashes as _hashes
import attrib as _attrib
from fold import (State, water_fill, lease_days, oracle_rate, compute_mtp,
                  state_digest, state_ecmh, synthetic_txid)


# ============================================================
# wire encoders (canonical inverse of wire.decode_payload)
# ============================================================
def enc(op, body):
    return PREFIX + bytes([op]) + body


def e_commit(commitment):
    return enc(OP_COMMIT, commitment)


def e_claim(salt, name):
    return enc(OP_CLAIM, salt + name)


def e_renew_name(name):
    return enc(OP_RENEW_NAME, name)


def e_transfer_name(target, name):
    return enc(OP_TRANSFER_NAME, target + name)


def e_release_name(name):
    return enc(OP_RELEASE_NAME, name)


def e_renew_all():
    return enc(OP_RENEW, b"")


def e_renew_safe(anchor):
    return enc(OP_RENEW, anchor.to_bytes(5, "little"))


def e_renew_sel(anchor, flags):
    return enc(OP_RENEW, anchor.to_bytes(5, "little") + flags)


def e_transfer_all(target):
    return enc(OP_TRANSFER, target)


def e_transfer_sel(target, anchor, flags):
    return enc(OP_TRANSFER, target + anchor.to_bytes(5, "little") + flags)


def e_sell(price, window, name):
    return enc(OP_SELL, price.to_bytes(8, "little") + window.to_bytes(4, "little") + name)


def e_reserve(name):
    return enc(OP_RESERVE, name)


def e_settle(name):
    return enc(OP_SETTLE, name)


def e_release(anchor, flags):
    return enc(OP_RELEASE, anchor.to_bytes(5, "little") + flags)


def e_sell_to(price, buyer, name):
    return enc(OP_SELL_TO, price.to_bytes(8, "little") + buyer + name)


def e_pay(name):
    return enc(OP_PAY, name)


def e_as(index):
    return enc(OP_AS, bytes([index]))


def e_trade(idxA, idxB, nameA, nameB):
    return enc(OP_TRADE, bytes([idxA, idxB]) + nameA + b"," + nameB)


# ============================================================
# tx construction helpers
# ============================================================
def ident(i):
    return bytes([i]) + b"\x00" * 18 + bytes([i])


def vin(i, valid=True, typ=0):
    return {"id": ident(i), "type": typ, "valid": valid}


def vin_bad():
    return {"id": None, "type": 0, "valid": False}


def carrier(vout, payload, value=0):
    return {"kind": "carrier", "vout": vout, "payload": payload, "value": value}


def spend(vout, to_ident, value, typ=0):
    return {"kind": "spend", "vout": vout, "hash160": to_ident, "type": typ, "value": value}


def tx(txindex, inputs, outputs):
    return {"txindex": txindex, "inputs": inputs, "outputs": outputs}


def commitment_of(salt, name, author):
    return _hashes.sha256(salt + name + author)


SALT0 = b"\x00" * 32
SALT1 = b"\x11" * 32


# ============================================================
# self-test battery
# ============================================================
class T:
    n = 0
    fails = []

    @classmethod
    def check(cls, cond, msg):
        cls.n += 1
        if not cond:
            cls.fails.append(msg)
            print("  FAIL:", msg)


def _fresh(activation=0):
    return State(activation_height=activation)


def t_primitives():
    _prng._selftest()
    _hashes._selftest()
    _attrib._selftest()
    T.check(SplitMix64(0).next() == 0xE220A8397B1DCDAF, "prng KAT")
    T.check(_hashes.ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31", "ripemd KAT")


def t_commit_claim_happy():
    s = _fresh()
    A = ident(1)
    com = commitment_of(SALT0, b"alice", A)
    # block 5: commit
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    T.check(len(s.commits) == 1, "commit recorded")
    # block 6: claim (strictly later block)
    s.begin_block(6, 1100)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"alice"), value=KOINU_PER_DOGE)]),
                 6, 1100, 28)
    T.check(b"alice" in s.names and s.names[b"alice"].owner == A, "happy claim mints")
    # commit lingers (not deleted on use)
    T.check(len(s.commits) == 1, "commit lingers after use (no delete-on-use)")


def t_naked_claim_dropped():
    s = _fresh()
    s.begin_block(6, 1100)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"alice"), value=KOINU_PER_DOGE)]),
                 6, 1100, 28)
    T.check(b"alice" not in s.names, "naked claim (no commit) dropped")


def t_same_block_commit_too_shallow():
    s = _fresh()
    A = ident(1)
    com = commitment_of(SALT0, b"bob", A)
    s.begin_block(5, 1000)
    # commit and claim in SAME block 5
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_claim(SALT0, b"bob"), value=KOINU_PER_DOGE)]),
                 5, 1000, 28)
    T.check(b"bob" not in s.names, "same-block commit too shallow -> claim dropped")


def t_commitment_copy_attack():
    s = _fresh()
    A = ident(1)   # victim
    B = ident(2)   # attacker
    com = commitment_of(SALT0, b"carol", A)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    # attacker re-posts the SAME commitment under their own tx
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    s.begin_block(6, 1100)
    # attacker tries to claim with author=B: commitment recomputed with B's hash != com
    s.process_tx(tx(0, [vin(2)], [carrier(0, e_claim(SALT0, b"carol"), value=KOINU_PER_DOGE)]),
                 6, 1100, 28)
    T.check(b"carol" not in s.names, "commitment-copy: attacker cannot claim")
    # victim CAN claim (author term matches)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_claim(SALT0, b"carol"), value=KOINU_PER_DOGE)]),
                 6, 1100, 28)
    T.check(s.names[b"carol"].owner == A, "commitment-copy: victim still claims")


def t_priority_lower_commit_height():
    # two authors commit the same name in different blocks; claims both in a later
    # block; the EARLIER commit_height must win regardless of claim order.
    for claim_order in (("X", "Y"), ("Y", "X")):
        s = _fresh()
        X, Y = ident(3), ident(4)
        comX = commitment_of(SALT0, b"hot", X)
        comY = commitment_of(SALT1, b"hot", Y)
        s.begin_block(5, 1000)
        s.process_tx(tx(0, [vin(3)], [carrier(0, e_commit(comX))]), 5, 1000, 28)  # X commits earlier block
        s.begin_block(6, 1100)
        s.process_tx(tx(0, [vin(4)], [carrier(0, e_commit(comY))]), 6, 1100, 28)  # Y commits later
        s.begin_block(7, 1200)
        order = claim_order
        for who in order:
            if who == "X":
                s.process_tx(tx(0 if who == order[0] else 1, [vin(3)],
                                [carrier(0, e_claim(SALT0, b"hot"), value=KOINU_PER_DOGE)]), 7, 1200, 28)
            else:
                s.process_tx(tx(0 if who == order[0] else 1, [vin(4)],
                                [carrier(0, e_claim(SALT1, b"hot"), value=KOINU_PER_DOGE)]), 7, 1200, 28)
        T.check(s.names[b"hot"].owner == X,
                "priority: lower commit_height wins (claim order %s)" % str(claim_order))


def t_priority_commit_txindex_tiebreak():
    # same commit_height; the COMMIT's tx_index breaks the tie, NOT claim order.
    for claim_first in (0, 1):
        s = _fresh()
        X, Y = ident(3), ident(4)
        comX = commitment_of(SALT0, b"tie", X)
        comY = commitment_of(SALT1, b"tie", Y)
        s.begin_block(5, 1000)
        s.process_tx(tx(2, [vin(3)], [carrier(0, e_commit(comX))]), 5, 1000, 28)  # X commits tx_index 2
        s.process_tx(tx(7, [vin(4)], [carrier(0, e_commit(comY))]), 5, 1000, 28)  # Y commits tx_index 7
        s.begin_block(6, 1100)
        claims = [(0, X, SALT0), (1, Y, SALT1)]
        if claim_first == 1:
            claims = [(0, Y, SALT1), (1, X, SALT0)]
        for txi, who, salt in claims:
            idx = 3 if who is X else 4
            s.process_tx(tx(txi, [vin(idx)], [carrier(0, e_claim(salt, b"tie"), value=KOINU_PER_DOGE)]),
                         6, 1100, 28)
        T.check(s.names[b"tie"].owner == X,
                "priority: lower COMMIT tx_index wins (claim_first=%d)" % claim_first)


def t_lease_lapse_exclusive():
    s = _fresh()
    A = ident(1)
    com = commitment_of(SALT0, b"lap", A)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    s.begin_block(6, 1100)
    # buy exactly 1 day: rate 28 -> per-day price = rate*BILLING_UNIT/LEASE_QUANTUM = 1 koinu/day
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"lap"), value=1)]), 6, 1100, 28)
    exp = s.names[b"lap"].lease_expiry
    T.check(exp == 1100 + BILLING_UNIT, "1-day lease expiry computed")
    # at MTP == lease_expiry the name lapses (exclusive: owned iff MTP < expiry)
    s.begin_block(7, exp)
    T.check(b"lap" not in s.names, "lapse at MTP == lease_expiry (exclusive)")
    T.check(s.muts.get(A) == 7, "lapse stamps owner mutation height to H")


def t_lease_owned_just_before():
    s = _fresh()
    A = ident(1)
    com = commitment_of(SALT0, b"lap", A)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    s.begin_block(6, 1100)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"lap"), value=1)]), 6, 1100, 28)
    exp = s.names[b"lap"].lease_expiry
    s.begin_block(7, exp - 1)
    T.check(b"lap" in s.names, "still owned at MTP == expiry-1")


def t_commit_expiry_inclusive():
    s = _fresh()
    A = ident(1)
    com = commitment_of(SALT0, b"ce", A)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 5, 1000, 28)
    ct = s.commits[0]["commit_time"]
    # at MTP == commit_time + COMMIT_EXPIRY commit is STILL live (inclusive)
    s.begin_block(6, ct + COMMIT_EXPIRY)
    T.check(len(s.commits) == 1, "commit live AT commit_time+COMMIT_EXPIRY (inclusive)")
    # a claim here still works
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"ce"), value=KOINU_PER_DOGE)]),
                 6, ct + COMMIT_EXPIRY, 28)
    T.check(b"ce" in s.names, "claim backed by inclusive-boundary commit")
    # one tick later the commit self-prunes
    s.begin_block(7, ct + COMMIT_EXPIRY + 1)
    T.check(len(s.commits) == 0, "commit pruned once MTP strictly exceeds window")


def _mint(s, owner_idx, name, height, mtp, value, salt=SALT0):
    """Helper: commit at height-1, claim at height."""
    A = ident(owner_idx)
    com = commitment_of(salt, name, A)
    s.begin_block(height - 1, mtp - 1)
    s.process_tx(tx(0, [vin(owner_idx)], [carrier(0, e_commit(com))]), height - 1, mtp - 1, 28)
    s.begin_block(height, mtp)
    s.process_tx(tx(0, [vin(owner_idx)], [carrier(0, e_claim(salt, name), value=value)]),
                 height, mtp, 28)


def t_waterfill_even():
    # two names, rate 28 (1 koinu/day), burn 10 koinu -> T=10 days, even 5 each.
    s = _fresh()
    A = ident(1)
    _mint(s, 1, b"a", 5, 1000, 1)
    _mint(s, 1, b"b", 5, 1000, 1)   # both minted; reuse block 5? need separate commits
    # rebuild cleanly: mint both via distinct commits in block 4, claim block 5
    s = _fresh()
    comA = commitment_of(SALT0, b"a", A)
    comB = commitment_of(SALT1, b"b", A)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_commit(comB))]), 4, 999, 28)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"a"), value=1)]), 5, 1000, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_claim(SALT1, b"b"), value=1)]), 5, 1000, 28)
    ea0 = s.names[b"a"].lease_expiry
    eb0 = s.names[b"b"].lease_expiry
    # renew-all with burn 10 -> T=10 days over 2 names -> +5 days each
    s.begin_block(6, 1001)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_all(), value=10)]), 6, 1001, 28)
    T.check(s.names[b"a"].lease_expiry == ea0 + 5 * BILLING_UNIT, "water-fill even +5d on a")
    T.check(s.names[b"b"].lease_expiry == eb0 + 5 * BILLING_UNIT, "water-fill even +5d on b")


def t_waterfill_T_less_than_count():
    s = _fresh()
    A = ident(1)
    comA = commitment_of(SALT0, b"a", A)
    comB = commitment_of(SALT1, b"b", A)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_commit(comB))]), 4, 999, 28)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"a"), value=1)]), 5, 1000, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_claim(SALT1, b"b"), value=1)]), 5, 1000, 28)
    ea0 = s.names[b"a"].lease_expiry
    eb0 = s.names[b"b"].lease_expiry
    # burn 1 -> T=1 day over 2 names -> first name ascending-lex ("a") gets 1, "b" none
    s.begin_block(6, 1001)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_all(), value=1)]), 6, 1001, 28)
    T.check(s.names[b"a"].lease_expiry == ea0 + BILLING_UNIT, "T<count: 'a' gets 1 day")
    T.check(s.names[b"b"].lease_expiry == eb0, "T<count: 'b' gets none")


def t_waterfill_T_zero_fail_closed():
    s = _fresh()
    _mint(s, 1, b"z", 5, 1000, KOINU_PER_DOGE)
    e0 = s.names[b"z"].lease_expiry
    s.begin_block(6, 1001)
    # burn 0 -> T=0 -> fail closed (no change)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_all(), value=0)]), 6, 1001, 28)
    T.check(s.names[b"z"].lease_expiry == e0, "T==0 fail-closed (renew no-op)")


def t_renew_no_bump_settle_bumps():
    s = _fresh()
    _mint(s, 1, b"r", 5, 1000, KOINU_PER_DOGE)
    mut_after_claim = s.muts.get(ident(1))
    s.begin_block(6, 1001)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_all(), value=KOINU_PER_DOGE)]), 6, 1001, 28)
    T.check(s.muts.get(ident(1)) == mut_after_claim, "RENEW does not bump mutation height")


def t_anchor_guard_reject():
    s = _fresh()
    _mint(s, 1, b"g", 5, 1000, 10)   # 10-day lease (leaves renewal headroom); claim bumps mut at 5
    s.begin_block(6, 1001)
    # selective renew with anchor=4 (< last_mutation 5) -> reject (drop)
    e0 = s.names[b"g"].lease_expiry
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_sel(4, b"\x01"), value=KOINU_PER_DOGE)]),
                 6, 1001, 28)
    T.check(s.names[b"g"].lease_expiry == e0, "anchor guard rejects stale anchor")
    # anchor=5 valid
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_renew_sel(5, b"\x01"), value=KOINU_PER_DOGE)]),
                 6, 1001, 28)
    T.check(s.names[b"g"].lease_expiry > e0, "anchor guard accepts valid anchor")


def t_oob_bit_ignored():
    s = _fresh()
    _mint(s, 1, b"o", 5, 1000, KOINU_PER_DOGE)  # owner has 1 name (K=1)
    e0 = s.names[b"o"].lease_expiry
    s.begin_block(6, 1001)
    # flags byte 0b11111110: bit0=0 (don't renew name 0), bits1..7 OOB (ignored)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_renew_sel(5, bytes([0b11111110])), value=KOINU_PER_DOGE)]),
                 6, 1001, 28)
    T.check(s.names[b"o"].lease_expiry == e0, "OOB bits ignored, name0 bit clear -> no renew, not dropped")


def t_release_locked_skipped():
    s = _fresh()
    A = ident(1)
    comA = commitment_of(SALT0, b"a", A)
    comB = commitment_of(SALT1, b"b", A)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_commit(comB))]), 4, 999, 28)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"a"), value=MAX_LEASE)]), 5, 1000, 28)
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_claim(SALT1, b"b"), value=MAX_LEASE)]), 5, 1000, 28)
    # list "a" for sale -> locked
    s.begin_block(6, 1001)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(3, 0, b"a"))]), 6, 1001, 28)
    T.check(s.names[b"a"].st == ST_LISTED, "name a listed")
    # RELEASE bitmap selecting both a (bit0) and b (bit1): a is locked -> skipped, b released
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_release(5, bytes([0b11])))]), 6, 1001, 28)
    T.check(b"a" in s.names and s.names[b"a"].st == ST_LISTED, "RELEASE skips locked 'a'")
    T.check(b"b" not in s.names, "RELEASE releases unlocked 'b'")


def t_sell_floor_and_window():
    s = _fresh()
    _mint(s, 1, b"s", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    # price below 3*DUST_FLOOR -> ignored
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(2, 0, b"s"))]), 6, 1001, 28)
    T.check(s.names[b"s"].st == ST_OWNED, "SELL below price floor ignored")
    # nonzero window below RESERVE_WINDOW -> ignored
    s.process_tx(tx(1, [vin(1)], [carrier(0, e_sell(3, RESERVE_WINDOW - 1, b"s"))]), 6, 1001, 28)
    T.check(s.names[b"s"].st == ST_OWNED, "SELL window in [1,RESERVE_WINDOW) ignored")
    # window=0 -> defaults to RESERVE_WINDOW
    s.process_tx(tx(2, [vin(1)], [carrier(0, e_sell(3, 0, b"s"))]), 6, 1001, 28)
    T.check(s.names[b"s"].st == ST_LISTED and s.names[b"s"].offer_expiry == 1001 + RESERVE_WINDOW,
            "SELL window=0 -> RESERVE_WINDOW default")


def t_sell_window_addform_shorttail():
    # a short-tailed name: window passes floor but add-form bound fails -> ignore
    s = _fresh()
    # lease just barely above RESERVE_WINDOW+REORG_BUFFER so a big window overflows the tail
    A = ident(1)
    com = commitment_of(SALT0, b"t", A)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(com))]), 4, 999, 28)
    s.begin_block(5, 1000)
    # buy ~ (RESERVE_WINDOW+REORG_BUFFER)/86400 +1 days
    days = (RESERVE_WINDOW + REORG_BUFFER) // BILLING_UNIT + 1
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"t"), value=days)]), 5, 1000, 28)
    exp = s.names[b"t"].lease_expiry
    s.begin_block(6, 1001)
    # window so large that 1001 + window + REORG_BUFFER > exp -> ignore
    big = exp  # definitely too large
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(3, big & 0xFFFFFFFF, b"t"))]), 6, 1001, 28)
    T.check(s.names[b"t"].st == ST_OWNED, "SELL add-form window upper bound rejects short tail")


def t_reserve_settle_open_market():
    s = _fresh()
    A = ident(1)   # seller
    B = ident(2)   # buyer
    _mint(s, 1, b"m", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    price = 20000
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(price, 0, b"m"))]), 6, 1001, 28)
    burn_leg = max(DUST_FLOOR, (price * RESERVE_BURN_BPS) // 10000)   # 100
    pay_leg = max(DUST_FLOOR, (price * RESERVE_PAY_BPS) // 10000)     # 100
    # RESERVE by B: carrier value >= burn_leg, pay_leg output to seller A
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_reserve(b"m"), value=burn_leg),
                                  spend(1, A, pay_leg)]), 6, 1001, 28)
    T.check(s.names[b"m"].st == ST_RESERVED and s.names[b"m"].buyer == B, "RESERVE wins option")
    # SETTLE by B: remainder output to seller
    remainder = price - burn_leg - pay_leg
    s.process_tx(tx(2, [vin(2)], [carrier(0, e_settle(b"m")), spend(1, A, remainder)]), 6, 1001, 28)
    T.check(s.names[b"m"].owner == B and s.names[b"m"].st == ST_OWNED, "SETTLE conveys to buyer")
    T.check(s.muts.get(A) is not None and s.muts.get(B) is not None, "SETTLE bumps both parties")


def t_reserve_burn_short_drops():
    s = _fresh()
    A = ident(1)
    _mint(s, 1, b"m", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    price = 20000
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(price, 0, b"m"))]), 6, 1001, 28)
    burn_leg = (price * RESERVE_BURN_BPS) // 10000
    pay_leg = (price * RESERVE_PAY_BPS) // 10000
    # carrier value short of burn_leg -> drop
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_reserve(b"m"), value=burn_leg - 1),
                                  spend(1, A, pay_leg)]), 6, 1001, 28)
    T.check(s.names[b"m"].st == ST_LISTED, "RESERVE with short burn leg drops (stays LISTED)")
    # missing pay_leg output -> drop
    s.process_tx(tx(2, [vin(2)], [carrier(0, e_reserve(b"m"), value=burn_leg)]), 6, 1001, 28)
    T.check(s.names[b"m"].st == ST_LISTED, "RESERVE with absent pay_leg drops")


def t_reserve_128bit_deposit():
    s = _fresh()
    A = ident(1)
    _mint(s, 1, b"big", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    price = (1 << 64) - 1
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(price, 0, b"big"))]), 6, 1001, 28)
    burn_leg = max(DUST_FLOOR, (price * RESERVE_BURN_BPS) // 10000)
    pay_leg = max(DUST_FLOOR, (price * RESERVE_PAY_BPS) // 10000)
    # 128-bit math: price*50 overflows int64 but Python is exact
    T.check(burn_leg == (price * 50) // 10000, "128-bit burn_leg at 2^64-1 price")
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_reserve(b"big"), value=burn_leg),
                                  spend(1, A, pay_leg)]), 6, 1001, 28)
    T.check(s.names[b"big"].st == ST_RESERVED, "RESERVE at 2^64-1 price succeeds with 128-bit legs")


def t_output_value_collision():
    # §7 vector: one tx does RESERVE+SETTLE paying same seller; vout0=remainder,
    # vout1=pay_leg. Matcher must let RESERVE skip the larger vout0, take vout1,
    # then SETTLE take vout0.
    s = _fresh()
    A = ident(1)
    _mint(s, 1, b"m", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    price = 20000
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell(price, 0, b"m"))]), 6, 1001, 28)
    burn_leg = (price * RESERVE_BURN_BPS) // 10000   # 100
    pay_leg = (price * RESERVE_PAY_BPS) // 10000     # 100
    remainder = price - burn_leg - pay_leg           # 19800
    # single tx by buyer B doing RESERVE then SETTLE, outputs: vout0=19800, vout1=100
    s.process_tx(tx(1, [vin(2)], [
        spend(0, A, remainder),                       # vout0 large
        spend(1, A, pay_leg),                         # vout1 small
        carrier(2, e_reserve(b"m"), value=burn_leg),  # carrier reserve (consumes vout1)
        carrier(3, e_settle(b"m")),                   # carrier settle (consumes vout0)
    ]), 6, 1001, 28)
    T.check(s.names[b"m"].owner == ident(2) and s.names[b"m"].st == ST_OWNED,
            "value-collision matcher: RESERVE+SETTLE in one tx both match")


def t_directed_sell_to_pay():
    s = _fresh()
    A = ident(1)   # seller
    B = ident(2)   # named buyer
    C = ident(3)   # stranger
    _mint(s, 1, b"d", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    price = 5000
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_sell_to(price, B, b"d"))]), 6, 1001, 28)
    T.check(s.names[b"d"].st == ST_OFFERED and s.names[b"d"].buyer == B, "SELL_TO offered + locked")
    # stranger PAY -> drop (output still pays seller, but no ownership change)
    s.process_tx(tx(1, [vin(3)], [carrier(0, e_pay(b"d")), spend(1, A, price)]), 6, 1001, 28)
    T.check(s.names[b"d"].owner == A and s.names[b"d"].st == ST_OFFERED, "stranger PAY dropped")
    # named buyer PAY -> succeeds
    s.process_tx(tx(2, [vin(2)], [carrier(0, e_pay(b"d")), spend(1, A, price)]), 6, 1001, 28)
    T.check(s.names[b"d"].owner == B and s.names[b"d"].st == ST_OWNED, "buyer PAY conveys")


def t_as_attribution():
    s = _fresh()
    # custodian tx: vin0 = custodian (X), vin1 = user U. AS 1 -> SELL attributed to U.
    X, U = ident(5), ident(6)
    _mint(s, 6, b"u", 5, 1000, MAX_LEASE)  # U owns a name
    s.begin_block(6, 1001)
    # AS 1 then a SELL by U on "u" (acts as U)
    s.process_tx(tx(0, [vin(5), vin(6)], [
        carrier(0, e_as(1)),
        carrier(1, e_sell(3, 0, b"u")),
    ]), 6, 1001, 28)
    T.check(s.names[b"u"].st == ST_LISTED and s.names[b"u"].seller == U,
            "AS re-points acting identity to vin[1]")


def t_as_oob_drop():
    s = _fresh()
    _mint(s, 6, b"u", 5, 1000, MAX_LEASE)
    s.begin_block(6, 1001)
    # AS index 9 out of range -> segment ⊥ -> SELL drops
    s.process_tx(tx(0, [vin(5), vin(6)], [
        carrier(0, e_as(9)),
        carrier(1, e_sell(3, 0, b"u")),
    ]), 6, 1001, 28)
    T.check(s.names[b"u"].st == ST_OWNED, "AS out-of-range drops its segment")


def t_trade_swap_and_antirug():
    # happy swap
    s = _fresh()
    A, B = ident(1), ident(2)
    comA = commitment_of(SALT0, b"x", A)
    comB = commitment_of(SALT1, b"y", B)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_commit(comB))]), 4, 999, 28)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"x"), value=MAX_LEASE)]), 5, 1000, 28)
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_claim(SALT1, b"y"), value=MAX_LEASE)]), 5, 1000, 28)
    s.begin_block(6, 1001)
    s.process_tx(tx(0, [vin(1), vin(2)], [carrier(0, e_trade(0, 1, b"x", b"y"))]), 6, 1001, 28)
    T.check(s.names[b"x"].owner == B and s.names[b"y"].owner == A, "TRADE swaps ownership")
    T.check(s.muts.get(A) == 6 and s.muts.get(B) == 6, "TRADE bumps both mutation heights")

    # same-block anti-rug: A transfers x away BEFORE the trade in same block -> trade drops
    s2 = _fresh()
    comA = commitment_of(SALT0, b"x", A)
    comB = commitment_of(SALT1, b"y", B)
    s2.begin_block(4, 999)
    s2.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s2.process_tx(tx(1, [vin(2)], [carrier(0, e_commit(comB))]), 4, 999, 28)
    s2.begin_block(5, 1000)
    s2.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"x"), value=MAX_LEASE)]), 5, 1000, 28)
    s2.process_tx(tx(1, [vin(2)], [carrier(0, e_claim(SALT1, b"y"), value=MAX_LEASE)]), 5, 1000, 28)
    s2.begin_block(6, 1001)
    s2.process_tx(tx(0, [vin(1)], [carrier(0, e_transfer_all(ident(9)))]), 6, 1001, 28)  # A moves x to Z
    s2.process_tx(tx(1, [vin(1), vin(2)], [carrier(0, e_trade(0, 1, b"x", b"y"))]), 6, 1001, 28)
    T.check(s2.names[b"x"].owner == ident(9), "anti-rug: x already moved before TRADE")
    T.check(s2.names[b"y"].owner == B, "anti-rug: TRADE dropped, y stays with B")


def t_trade_failclosed_edges():
    s = _fresh()
    A, B = ident(1), ident(2)
    comA = commitment_of(SALT0, b"x", A)
    s.begin_block(4, 999)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_commit(comA))]), 4, 999, 28)
    s.begin_block(5, 1000)
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_claim(SALT0, b"x"), value=MAX_LEASE)]), 5, 1000, 28)
    s.begin_block(6, 1001)
    # idxA==idxB -> drop (decoder allows it; fold rejects)
    s.process_tx(tx(0, [vin(1), vin(2)], [carrier(0, e_trade(0, 0, b"x", b"x"))]), 6, 1001, 28)
    T.check(s.names[b"x"].owner == A, "TRADE idxA==idxB dropped")
    # B doesn't own y -> drop
    s.process_tx(tx(1, [vin(1), vin(2)], [carrier(0, e_trade(0, 1, b"x", b"y"))]), 6, 1001, 28)
    T.check(s.names[b"x"].owner == A, "TRADE counterparty not owning -> drop")


def t_no_tx_count_cap():
    # §0: no per-tx carrier cap — 17 COMMIT carriers all record (vector 54).
    s = _fresh()
    s.begin_block(10, 1000)
    cars = [carrier(i, e_commit(bytes([i]) + b"\x00" * 31)) for i in range(17)]
    s.process_tx(tx(0, [vin(1)], cars), 10, 1000, 28)
    T.check(len(s.commits) == 17, "17 COMMITs all record (no tx count cap)")


def t_fee_oracle():
    # §3.4 participant median: P = blocks whose fpb >= 1 AFTER the floor division
    # (an under-claim clamps to 0 fees -> non-participant); |P| < MIN_FEE_SAMPLE
    # degrades to DUST_FLOOR exactly (boundary INCLUSIVE); otherwise the LOWER
    # median sorted_P[(len(P)-1)//2] scaled by REF_SIZE and clamped.
    # |P| = 1000 EXACTLY (inclusive boundary), EVEN, under-claim inside the window:
    # 499 zero-fee + 1 under-claim -> non-participants; fpb 100..1099 -> lower
    # median = sorted[499] = 599 -> 599*REF_SIZE = 119800.
    w = [(SUBSIDY, 1000)] * 499 + [(SUBSIDY - 50, 1000)] + \
        [(SUBSIDY + (100 + i) * 1000, 1000) for i in range(1000)]
    T.check(oracle_rate(w) == 119800,
            "fee oracle inclusive 1000 boundary + even lower-median + under-claim clamp")
    # odd |P| = 1101 through the participant filter: fpb 100..1200 -> median
    # sorted[550] = 650 -> 130000.
    w1 = [(SUBSIDY, 1000)] * 899 + \
         [(SUBSIDY + (100 + i) * 1000, 1000) for i in range(1101)]
    T.check(oracle_rate(w1) == 130000, "fee oracle odd participant median")
    # |P| = 999 -- one short of MIN_FEE_SAMPLE -> degrade to DUST_FLOOR exactly
    w2 = [(SUBSIDY, 1000)] * 501 + \
         [(SUBSIDY + (100 + i) * 1000, 1000) for i in range(999)]
    T.check(oracle_rate(w2) == DUST_FLOOR, "fee oracle sub-sample degrades to DUST_FLOOR")
    # clamp ceiling (1000 fee-bearing participants, huge median)
    w3 = [(SUBSIDY + 10 ** 12, 1)] * 1000
    T.check(oracle_rate(w3) == RATE_CAP, "fee oracle clamps to RATE_CAP")
    # clamp floor when no fees at all (|P| = 0)
    w4 = [(SUBSIDY, 200)] * 1500
    T.check(oracle_rate(w4) == DUST_FLOOR, "fee oracle clamps to DUST_FLOOR")


def t_mtp_median():
    # short window k=min(11,H), upper-middle for even
    ts = [0] + [100, 50, 200, 150]   # heights 1..4 timestamps (index by height)
    # H=4: window timestamps[1..3] = [100,50,200] sorted [50,100,200] k=3 idx1 ->100
    T.check(compute_mtp(ts, 4) == 100, "MTP odd window middle")
    # H=2: window timestamps[0..1]? k=min(11,2)=2, window ts[0:2]=[0,100] sorted idx k//2=1 ->100 (upper-middle)
    T.check(compute_mtp(ts, 2) == 100, "MTP even short window upper-middle")
    T.check(compute_mtp(ts, 0) == 0, "MTP(0)=0")


def t_digest_sensitivity():
    # build a non-trivial state, verify each digested field moves the digest,
    # and that owner_type does NOT.
    s = _fresh()
    _mint(s, 1, b"q", 5, 1000, MAX_LEASE)
    d0 = state_digest(s)
    s.names[b"q"].lease_expiry += 1
    T.check(state_digest(s) != d0, "lease_expiry is digested")
    s.names[b"q"].lease_expiry -= 1
    # owner_type NOT digested
    s.names[b"q"].owner_type = 1
    T.check(state_digest(s) == d0, "owner_type is NOT digested (by design)")
    s.names[b"q"].owner_type = 0
    s.names[b"q"].price = 5
    T.check(state_digest(s) != d0, "price is digested")


def t_release_all_reclaim_same_block():
    # RELEASE frees a name; a same-block reclaim by a fresh commit/claim... but a
    # claim needs a strictly-earlier-block commit, so reclaim lands next block.
    s = _fresh()
    _mint(s, 1, b"f", 5, 1000, MAX_LEASE)
    # commit by B for "f" in block 5 (before release at block 6)
    B = ident(2)
    comB = commitment_of(SALT1, b"f", B)
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_commit(comB))]), 5, 1000, 28)
    s.begin_block(6, 1001)
    # owner A releases "f"
    s.process_tx(tx(0, [vin(1)], [carrier(0, e_release(5, bytes([0b1])))]), 6, 1001, 28)
    T.check(b"f" not in s.names, "RELEASE frees name")
    # B claims it immediately in same block (commit was block 5, claim block 6)
    s.process_tx(tx(1, [vin(2)], [carrier(0, e_claim(SALT1, b"f"), value=MAX_LEASE)]), 6, 1001, 28)
    T.check(s.names[b"f"].owner == B, "released name reclaimable next block by prior commit")


def t_attrib_a7_offcurve_p2pkh():
    # A7 regression (clean-room finding F7 / cross-impl A7): a P2PKH pubkey that is
    # canonically ENCODED but OFF-CURVE must be status 1 (on-curve-drop) carrying a
    # REAL identity + sighash — NOT status 0 (classify-drop, all-zero) and NOT
    # status 2/3. An on-curve canonical key must clear the curve gate (status != 1).
    from attrib import attribute, on_curve, pubkey_canonical, ST_ONCURVE_DROP
    der = b"\x30\x06\x02\x01\x01\x02\x01\x01"      # r=1,s=1 strict-DER, low-S
    sig = der + b"\x01"                            # SIGHASH_ALL
    off = on = None
    for c in range(1_000_000):
        pk = b"\x02" + (c).to_bytes(32, "big")     # canonical compressed, X=c < p
        if not pubkey_canonical(pk):
            continue
        if not on_curve(pk):
            if off is None:
                off = pk
        elif on is None:
            on = pk
        if off is not None and on is not None:
            break
    T.check(off is not None and on is not None, "A7: found off- and on-curve canonical P2PKH keys")
    for pk, want_oncurve_drop in ((off, True), (on, False)):
        if pk is None:
            continue
        ss = bytes([len(sig)]) + sig + bytes([len(pk)]) + pk
        txd = {"version": 1, "locktime": 0,
               "vin": [{"txid": b"\x00" * 32, "vout": 0, "scriptSig": ss, "sequence": 0xFFFFFFFF}],
               "vout": [{"value": 0, "spk": b"\x6a\x04\xff\x53\x50\x01"}]}
        status, sighash, identity = attribute(txd, 0)
        if want_oncurve_drop:
            T.check(status == ST_ONCURVE_DROP,
                    "A7: off-curve P2PKH -> status 1 (on-curve-drop), got %d" % status)
            T.check(identity != b"\x00" * 20 and sighash != b"\x00" * 32,
                    "A7: off-curve P2PKH carries real identity + sighash (status>=1)")
        else:
            T.check(status != ST_ONCURVE_DROP,
                    "A7: on-curve P2PKH clears the curve gate (status != 1), got %d" % status)


def _ecmh_build(claim_order):
    """Commit names a,b (same author, same tx order ⇒ identical commits incl. tx_index),
    then CLAIM them in `claim_order` (permuting the names dict's insertion order)."""
    import secp256k1
    s = _fresh()
    A = ident(0xAA)
    coms = {b"a": commitment_of(SALT0, b"a", A), b"b": commitment_of(SALT0, b"b", A)}
    s.begin_block(10, 1000)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(coms[b"a"]))]), 10, 1000, 28)
    s.process_tx(tx(1, [vin(0xAA)], [carrier(0, e_commit(coms[b"b"]))]), 10, 1000, 28)
    s.begin_block(11, 1500)
    for txi, name in claim_order:
        s.process_tx(tx(txi, [vin(0xAA)], [carrier(0, e_claim(SALT0, name), value=KOINU_PER_DOGE)]),
                     11, 1500, 28)
    return s


def t_ecmh():
    import secp256k1
    # §13.2 primitive algebra: identity / commutativity / inverse / round-trip.
    T.check(secp256k1.ecmh_selftest() == 0, "ECMH algebra (identity/commutativity/inverse)")
    # Empty-state ECMH is stable across independent recomputes.
    T.check(state_ecmh(_fresh()) == state_ecmh(_fresh()), "ECMH empty-state stable")
    # ECMH induces the SAME equality relation as state_digest. s1/s2 = same logical
    # rows in permuted insertion order; s3 differs (only name "a").
    s1 = _ecmh_build([(0, b"a"), (1, b"b")])
    s2 = _ecmh_build([(1, b"b"), (0, b"a")])     # claims reversed ⇒ names dict permuted
    s3 = _fresh()
    s3.begin_block(10, 1000)
    s3.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(SALT0, b"a", ident(0xAA))))]),
                  10, 1000, 28)
    s3.begin_block(11, 1500)
    s3.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SALT0, b"a"), value=KOINU_PER_DOGE)]),
                  11, 1500, 28)
    d1, d2, d3 = state_digest(s1), state_digest(s2), state_digest(s3)
    e1, e2, e3 = state_ecmh(s1), state_ecmh(s2), state_ecmh(s3)
    T.check(d1 == d2, "ECMH test setup: reordered builds give equal digest")
    T.check((d1 == d2) == (e1 == e2), "ECMH equality tracks digest (equal states)")
    T.check((d1 == d3) == (e1 == e3), "ECMH equality tracks digest (differing states)")


def t_secp_kat():
    # §4 Strategy B real secp256k1 KAT: pinned constants, 2G known-answer, n·G=∞,
    # decompress G round-trip, and RFC-6979 sign/verify + tamper round-trips.
    import secp256k1
    T.check(secp256k1.selftest() == 0, "secp256k1 selftest (constants/2G/nG/decompress/sign-verify)")


def t_dotted_names():
    # charset + structural rules (§3.1): [a-z0-9-], 1..32; no leading/trailing hyphen;
    # no `--` at positions 3–4. Pins the OUTCOME behind scenario 52 / 52b.
    from wire import valid_name
    T.check(valid_name(b"shib-p2p"), "hyphen name valid")
    T.check(valid_name(b"abcdefghijklmnopqrstuvwxyz0123ab"), "32-byte name valid")
    T.check(not valid_name(b"abcdefghijklmnopqrstuvwxyz0123abc"), "33-byte name invalid (max 32)")
    T.check(not valid_name(b"shib.p2p"), "dot now invalid")
    T.check(not valid_name(b"shib_p2p"), "underscore now invalid")
    T.check(not valid_name(b"Shib-p2p"), "uppercase still invalid")
    T.check(not valid_name(b"a,b"), "comma still invalid (TRADE pair split relies on it)")
    T.check(not valid_name(b"-a"), "leading hyphen invalid")
    T.check(not valid_name(b"a-"), "trailing hyphen invalid")
    T.check(not valid_name(b"xn--x"), "ACE prefix (xn--) invalid")
    s = _fresh()
    A = ident(0xAA)
    s71, s74 = b"\x71" * 32, b"\x74" * 32
    s.begin_block(10, 1000)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(s71, b"shib-p2p", A)))]),
                 10, 1000, 28)
    s.process_tx(tx(1, [vin(0xAA)], [carrier(0, e_commit(commitment_of(s74, b"shib.p2p", A)))]),
                 10, 1000, 28)
    s.begin_block(11, 1500)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(s71, b"shib-p2p"), value=10)]),
                 11, 1500, 28)
    s.process_tx(tx(1, [vin(0xAA)], [carrier(0, e_claim(s74, b"shib.p2p"), value=10)]),
                 11, 1500, 28)
    T.check(b"shib-p2p" in s.names and s.names[b"shib-p2p"].owner == A, "hyphen claim mints")
    T.check(b"shib.p2p" not in s.names and len(s.names) == 1, "dotted claim drops")



def t_l1_carrier_ceiling():
    # §6 pinned carrier ceiling: flags at the exact consensus caps decode;
    # one byte past the ceiling is IGNORE — fail-closed in both directions.
    from wire import decode_payload, ACTION, IGNORE
    from const import FLAGS_MAX, FLAGS_XFER_MAX, CARRIER_MAX
    wide = e_renew_sel(7, bytes((i * 7 + 1) & 0xFF for i in range(FLAGS_MAX)))
    T.check(len(wide) == CARRIER_MAX, "RENEW at cap is exactly CARRIER_MAX (9996) payload bytes")
    k, info = decode_payload(wide, 0)
    T.check(k == ACTION and len(info["flags"]) == FLAGS_MAX,
            "RENEW-selective decodes with all 9987 flag bytes")
    k, _ = decode_payload(wide + b"\x00", 0)
    T.check(k == IGNORE, "one byte past the L1 ceiling -> ignore")
    xfer = e_transfer_sel(b"\xbb" * 20, 7, b"\x01" * FLAGS_XFER_MAX)
    k, info = decode_payload(xfer, 0)
    T.check(k == ACTION and len(info["flags"]) == FLAGS_XFER_MAX,
            "TRANSFER-selective decodes at FLAGS_XFER_MAX (9967)")
    k, _ = decode_payload(e_transfer_sel(b"\xbb" * 20, 7, b"\x01" * (FLAGS_XFER_MAX + 1)), 0)
    T.check(k == IGNORE, "TRANSFER flags past the cap -> ignore")
    k, info = decode_payload(e_release(3, b"\xff" * FLAGS_MAX), 0)
    T.check(k == ACTION and len(info["flags"]) == FLAGS_MAX, "RELEASE decodes at FLAGS_MAX")


ALL_TESTS = [
    t_primitives, t_secp_kat, t_commit_claim_happy, t_naked_claim_dropped,
    t_same_block_commit_too_shallow, t_commitment_copy_attack,
    t_priority_lower_commit_height, t_priority_commit_txindex_tiebreak,
    t_lease_lapse_exclusive, t_lease_owned_just_before, t_commit_expiry_inclusive,
    t_waterfill_even, t_waterfill_T_less_than_count, t_waterfill_T_zero_fail_closed,
    t_renew_no_bump_settle_bumps, t_anchor_guard_reject, t_oob_bit_ignored,
    t_release_locked_skipped, t_sell_floor_and_window, t_sell_window_addform_shorttail,
    t_reserve_settle_open_market, t_reserve_burn_short_drops, t_reserve_128bit_deposit,
    t_output_value_collision, t_directed_sell_to_pay, t_as_attribution, t_as_oob_drop,
    t_trade_swap_and_antirug, t_trade_failclosed_edges, t_no_tx_count_cap,
    t_fee_oracle,
    t_mtp_median, t_digest_sensitivity, t_release_all_reclaim_same_block,
    t_attrib_a7_offcurve_p2pkh, t_ecmh, t_dotted_names, t_l1_carrier_ceiling,
]


def run_selftest():
    for fn in ALL_TESTS:
        fn()
    # cross-impl anchors: empty SMv1 state (names+commits+muts only; three ECMH tables).
    esd = state_digest(_fresh())
    ese = state_ecmh(_fresh())
    T.check(esd == "0967073bc100b3e1e16833c03f3277dcd7d5076c77a98d6b3ce9ce4aae8ec298",
            "empty_state_digest matches cross-impl anchor")
    T.check(ese == "3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0",
            "empty_state_ecmh matches cross-impl anchor")
    print("empty_state_digest=%s" % esd)
    print("empty_state_ecmh=%s" % ese)
    print("\nself-test: %d checks, %d failures" % (T.n, len(T.fails)))
    if T.fails:
        for f in T.fails:
            print("  -", f)
        return 1
    print("ALL PASS")
    return 0


# ============================================================
# own (non-reference) generator + digest dump
# ============================================================
# Recorded chain: a block is {"height","mtp","rate","txs":[tx,...]}. Generation
# and folding are separable (cf. java Gen.recordChain) so the same chain can be
# folded fully / partially / resumed / forked for the properties/reorg/meta/
# reorgfuzz batteries. This is NOT the reference generator (§5); its digests are
# my own (NOT comparable to the frozen goldens, §6). Its only job is to drive the
# fold richly enough that the generator-INDEPENDENT assertions (violations==0,
# failures==0, parser_crashes==0) are meaningful.

N_IDS = 16
NAME_POOL = 400
BASE_TS = 1_700_000_000
# weights (names/market only; matches C gen.c): COMMIT,CLAIM,RENEW,TRANSFER,SELL,
# RESERVE,SETTLE,RELEASE,SELL_TO,PAY,TRADE — AS rides on RENEW (~1/8 with OOB)
_GEN_WEIGHTS = [14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4]
_GEN_WSUM = sum(_GEN_WEIGHTS)


def gen_identity(i):
    return bytes([i]) + b"\x00" * 18 + bytes([i])


def _id_type(i):
    return TYPE_P2SH if i % 4 == 3 else TYPE_P2PKH


def _name_of(j):
    return b"n" + _base36(j)


def _base36(v):
    if v == 0:
        return b"0"
    d = b"0123456789abcdefghijklmnopqrstuvwxyz"
    out = bytearray()
    while v > 0:
        out.insert(0, d[v % 36])
        v //= 36
    return bytes(out)


def _salt_of(k):
    s = bytearray(32)
    for i in range(8):
        s[i] = (k >> (8 * i)) & 0xFF
    s[31] = 0xA5
    return bytes(s)


def _pick_op(rng):
    x = rng.bounded(_GEN_WSUM)
    acc = 0
    for i, w in enumerate(_GEN_WEIGHTS):
        acc += w
        if x < acc:
            return i
    return 0


def _names_where(s, owner, req_st):
    out = []
    for n, r in s.names.items():
        if owner is not None and r.owner != owner:
            continue
        if req_st >= 0 and r.st != req_st:
            continue
        out.append(n)
    return out


def _idx_of(idb):
    for k in range(N_IDS):
        if gen_identity(k) == idb:
            return k
    return 0


def _gen_one_in(i, outs):
    return tx(0, [vin_typed(i)], outs)


def vin_typed(i):
    return {"id": gen_identity(i), "type": _id_type(i), "valid": True}


def _build_tx(rng, s, height, mtp, rate, ready, salt_ctr):
    op = _pick_op(rng)
    i = rng.bounded(N_IDS)
    idb = gen_identity(i)
    days = 1 + rng.bounded(60)
    rate28 = rate // 28
    lease_val = rate28 * days            # T == days (rate is a multiple of 28)

    if op == 0:   # COMMIT
        j = rng.bounded(NAME_POOL)
        name = _name_of(j)
        salt = _salt_of(salt_ctr)
        ready.append({"i": i, "name": name, "salt": salt,
                      "commit_height": height, "commit_time": mtp})
        return _gen_one_in(i, [carrier(0, e_commit(commitment_of(salt, name, idb)))])

    if op == 1:   # CLAIM a ready commit (>=1 deep, live, name free)
        for k in range(len(ready)):
            p = ready[k]
            if (p["commit_height"] < height
                    and mtp <= p["commit_time"] + COMMIT_EXPIRY
                    and p["name"] not in s.names):
                ready.pop(k)
                return _gen_one_in(p["i"], [carrier(0, e_claim(p["salt"], p["name"]),
                                                    value=lease_val)])
        # fall through to COMMIT

    elif op == 2:  # RENEW all (optionally AS-attributed ~1/8)
        cars = [carrier(0, e_renew_all(), value=lease_val)]
        if rng.bounded(8) == 0:
            other = rng.bounded(N_IDS)
            idx = (2 + rng.bounded(8)) if rng.bounded(4) == 0 else 1  # sometimes OOB
            return tx(0, [vin_typed(other), vin_typed(i)],
                      [carrier(0, e_as(idx)), carrier(1, e_renew_all(), value=lease_val)])
        return _gen_one_in(i, cars)

    elif op == 3:  # TRANSFER all to a random id
        if _names_where(s, idb, ST_OWNED):
            return _gen_one_in(i, [carrier(0, e_transfer_all(gen_identity(rng.bounded(N_IDS))))])

    elif op == 4:  # SELL an owned name with enough lease tail
        for nm in _names_where(s, idb, ST_OWNED):
            r = s.names[nm]
            if mtp + RESERVE_WINDOW + REORG_BUFFER <= r.lease_expiry:
                price = 3 + rng.bounded(100000)
                return _gen_one_in(i, [carrier(0, e_sell(price, 0, nm))])

    elif op == 5:  # RESERVE a listed name
        listed = _names_where(s, None, ST_LISTED)
        if listed:
            nm = listed[rng.bounded(len(listed))]
            r = s.names[nm]
            burn = max(DUST_FLOOR, (r.price * RESERVE_BURN_BPS) // 10000)
            pay = max(DUST_FLOOR, (r.price * RESERVE_PAY_BPS) // 10000)
            buyer = rng.bounded(N_IDS)
            return tx(0, [vin_typed(buyer)],
                      [carrier(0, e_reserve(nm), value=burn),
                       spend(1, r.seller, pay, r.seller_type)])

    elif op == 6:  # SETTLE a reserved name (by its reserver)
        res = _names_where(s, None, ST_RESERVED)
        if res:
            nm = res[rng.bounded(len(res))]
            r = s.names[nm]
            rem = r.price - r.burn_leg - r.pay_leg
            buyer = _idx_of(r.buyer)
            return tx(0, [vin_typed(buyer)],
                      [carrier(0, e_settle(nm)),
                       spend(1, r.seller, rem, r.seller_type)])

    elif op == 7:  # RELEASE owned names via a full bitmap
        owned = s.owned_names_of(idb)
        if owned:
            flags = bytes([0xFF] * ((len(owned) + 7) // 8))
            anchor = s.muts.get(idb)
            anchor = height if anchor is None else max(anchor, height - 1)
            if anchor <= height:
                return _gen_one_in(i, [carrier(0, e_release(anchor, flags))])

    elif op == 8:  # SELL_TO
        for nm in _names_where(s, idb, ST_OWNED):
            r = s.names[nm]
            if mtp + DIRECT_WINDOW + REORG_BUFFER <= r.lease_expiry:
                price = 1 + rng.bounded(100000)
                buyer = gen_identity(rng.bounded(N_IDS))
                return _gen_one_in(i, [carrier(0, e_sell_to(price, buyer, nm))])

    elif op == 9:  # PAY an offered name (by its named buyer)
        off = _names_where(s, None, ST_OFFERED)
        if off:
            nm = off[rng.bounded(len(off))]
            r = s.names[nm]
            buyer = _idx_of(r.buyer)
            return tx(0, [vin_typed(buyer)],
                      [carrier(0, e_pay(nm)), spend(1, r.seller, r.price, r.seller_type)])

    elif op == 10:  # TRADE two owned names between two ids
        mine = _names_where(s, idb, ST_OWNED)
        i2 = (i + 1 + rng.bounded(N_IDS - 1)) % N_IDS
        id2 = gen_identity(i2)
        theirs = _names_where(s, id2, ST_OWNED)
        if mine and theirs:
            a1, b1 = mine[0], theirs[0]
            if a1 != b1:
                ins = [vin_typed(i), vin_typed(i2)]
                return tx(0, ins, [carrier(0, e_trade(0, 1, a1, b1))])

    # COMMIT fallback (always valid)
    j = rng.bounded(NAME_POOL)
    name = _name_of(j)
    salt = _salt_of(salt_ctr)
    ready.append({"i": i, "name": name, "salt": salt,
                  "commit_height": height, "commit_time": mtp})
    return _gen_one_in(i, [carrier(0, e_commit(commitment_of(salt, name, idb)))])


def record_chain(seed, count):
    """Generate and RECORD a chain of blocks; returns a list of block dicts.
    The chain is folded inline once during generation so op selection sees live
    state, then RETURNED for the batteries to re-fold/partial/fork."""
    rng = SplitMix64(seed)
    s = State(activation_height=0)
    blocks = []
    ts_list = [0]
    cur_ts = BASE_TS
    ready = []
    salt_ctr = 1
    height = 0
    tx_count = 0
    while tx_count < count:
        cur_ts += 300 + rng.bounded(600)
        ts_list.append(cur_ts)
        rate = 28 * (1 + rng.bounded(4))
        mtp = compute_mtp(ts_list, height)
        s.begin_block(height, mtp)
        n_txs = 1 + rng.bounded(8)
        txs = []
        for ti in range(n_txs):
            if tx_count >= count:
                break
            t = _build_tx(rng, s, height, mtp, rate, ready, salt_ctr)
            salt_ctr += 4
            t["txindex"] = ti
            s.process_tx(t, height, mtp, rate)
            txs.append(t)
            tx_count += 1
        blocks.append({"height": height, "mtp": mtp, "rate": rate, "txs": txs})
        height += 1
    return blocks


def apply_block(s, blk):
    """Fold one recorded block: pre-block transitions then each tx in order."""
    s.begin_block(blk["height"], blk["mtp"])
    for t in blk["txs"]:
        s.process_tx(t, blk["height"], blk["mtp"], blk["rate"])


def _fold_digest(blocks, lo, hi):
    s = State(activation_height=0)
    for i in range(lo, hi):
        apply_block(s, blocks[i])
    return state_digest(s)


def run_generator(seed, count):
    """An internally-consistent generator. NOT the reference (§5) — its digest is
    NOT comparable to the frozen goldens (§6). Demonstrates the fold over a soak."""
    blocks = record_chain(seed, count)
    s = State(activation_height=0)
    for blk in blocks:
        apply_block(s, blk)
    return state_digest(s)


# ============================================================
# §8 / §9 / §10 / §11 generator-driven invariant batteries
# (ported from impls/java/Modes.java; digests are this impl's own and are NOT
# cross-checked — only violations/failures/parser_crashes matter, all MUST be 0)
# ============================================================
def _check_invariants(s, height, mtp):
    """§8 hard invariants asserted per-block. Returns violation count."""
    v = 0
    for r in s.names.values():
        # mtp < lease_expiry <= mtp + MAX_LEASE
        if not (mtp < r.lease_expiry):
            v += 1
        if not (r.lease_expiry <= mtp + MAX_LEASE):
            v += 1
        if r.st in (ST_LISTED, ST_OFFERED, ST_RESERVED):
            if not (r.offer_expiry + REORG_BUFFER <= r.lease_expiry):
                v += 1
        if r.st in (ST_LISTED, ST_RESERVED):
            if r.price < 3 * DUST_FLOOR:
                v += 1
        if r.st == ST_RESERVED:
            if not (r.reserve_expiry <= r.offer_expiry):
                v += 1
            if r.price < r.burn_leg + r.pay_leg:
                v += 1
            if r.burn_leg != max(DUST_FLOOR, (r.price * RESERVE_BURN_BPS) // 10000):
                v += 1
            if r.pay_leg != max(DUST_FLOOR, (r.price * RESERVE_PAY_BPS) // 10000):
                v += 1
            if r.price - r.burn_leg - r.pay_leg < DUST_FLOOR:
                v += 1
    for mh in s.muts.values():
        if mh > height:                  # mutation height <= current height
            v += 1
    return v


def _fingerprint(buf, s):
    """Pinned property fingerprint (names/market only; mirrors C harness)."""
    n_owned = n_listed = n_offered = n_reserved = 0
    sum_lease = sum_price = sum_legs = 0
    for r in s.names.values():
        if r.st == ST_OWNED:
            n_owned += 1
        elif r.st == ST_LISTED:
            n_listed += 1
            sum_price += r.price
        elif r.st == ST_OFFERED:
            n_offered += 1
            sum_price += r.price
        elif r.st == ST_RESERVED:
            n_reserved += 1
            sum_price += r.price
            sum_legs += r.burn_leg + r.pay_leg
        sum_lease += r.lease_expiry
    for x in (len(s.names), n_owned, n_listed, n_offered, n_reserved,
              len(s.commits), len(s.muts)):
        buf += (x & 0xFFFFFFFF).to_bytes(4, "little")
    for x in (sum_lease, sum_price, sum_legs):
        buf += (x & MASK128).to_bytes(16, "little")
    return buf


def run_properties(seed, count):
    blocks = record_chain(seed, count)
    s = State(activation_height=0)
    violations = 0
    pd = bytearray()
    for blk in blocks:
        apply_block(s, blk)
        violations += _check_invariants(s, blk["height"], blk["mtp"])
        pd = _fingerprint(pd, s)
    print("violations=%d" % violations)
    print("property_digest=%s" % _hashes.sha256(bytes(pd)).hex())
    print("state_digest=%s" % state_digest(s))
    return 1 if violations != 0 else 0


def _inert_tx():
    """A tx whose every carrier is provably IGNORE by the fold (mirrors C harness):
    malformed CLAIM, unknown opcode 0x20, bare UTF-8, overlay 0xD6.
    Applying it must leave state_digest unchanged."""
    outs = [
        carrier(0, bytes([0xFF, 0x50, 0x4E, OP_CLAIM, 0, 0, 0, 0]), value=0),  # truncated CLAIM
        carrier(1, bytes([0xFF, 0x50, 0x4E, 0x20]), value=0),                   # unknown opcode
        carrier(2, b"hello", value=1),                                          # bare UTF-8 noise
        carrier(3, bytes([0xFF, 0x50, 0x4E, 0xD6, 0x00]), value=0),             # overlay band
    ]
    return tx(0, [vin_typed(0)], outs)


def run_meta(seed, count):
    blocks = record_chain(seed, min(count, 20000))
    s = State(activation_height=0)
    failures = 0
    for blk in blocks:
        apply_block(s, blk)
        before = state_digest(s)
        for t in [_inert_tx()]:
            s.process_tx(t, blk["height"], blk["mtp"], blk["rate"])
        if state_digest(s) != before:
            failures += 1
    print("failures=%d" % failures)
    print("state_digest=%s" % state_digest(s))
    return 1 if failures != 0 else 0


def _reverse_txs(blk):
    return {"height": blk["height"], "mtp": blk["mtp"], "rate": blk["rate"],
            "txs": list(reversed(blk["txs"]))}


def run_reorg(seed, count):
    blocks = record_chain(seed, min(count, 20000))
    n = len(blocks)
    J = n // 2
    failures = 0

    d_full = _fold_digest(blocks, 0, n)
    # 1. replay
    if _fold_digest(blocks, 0, n) != d_full:
        failures += 1
    # 2. resume: fold [0,J) -> S_fork, continue [J,n) == D_full
    s = State(activation_height=0)
    for i in range(J):
        apply_block(s, blocks[i])
    s_fork = state_digest(s)
    for i in range(J, n):
        apply_block(s, blocks[i])
    if state_digest(s) != d_full:
        failures += 1
    # 3. clear-rebuild: fresh fold [0,J) == S_fork
    s = State(activation_height=0)
    for i in range(J):
        apply_block(s, blocks[i])
    if state_digest(s) != s_fork:
        failures += 1
    # 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed
    sa = State(activation_height=0)
    for i in range(J):
        apply_block(sa, blocks[i])
    for i in range(J, n):
        apply_block(sa, _reverse_txs(blocks[i]))
    d_alt = state_digest(sa)
    sa = State(activation_height=0)
    for i in range(J):
        apply_block(sa, blocks[i])
    if state_digest(sa) != s_fork:
        failures += 1
    for i in range(J, n):
        apply_block(sa, blocks[i])
    if state_digest(sa) != d_full:
        failures += 1

    rd = bytes.fromhex(d_full) + bytes.fromhex(s_fork) + bytes.fromhex(d_alt)
    print("blocks=%d fork=%d checks=6 failures=%d" % (n, J, failures))
    print("D_full=%s" % d_full)
    print("S_fork=%s" % s_fork)
    print("D_alt=%s" % d_alt)
    print("reorg_digest=%s" % _hashes.sha256(rd).hex())
    return 1 if failures != 0 else 0


def _fuzz_grammar_payload(rng):
    op = 1 + rng.bounded(15)                 # 0x01..0x0F
    if op == OP_COMMIT:
        body_len = 32
    elif op == OP_CLAIM:
        body_len = 33 + rng.bounded(20)
    elif op in (OP_RENEW_NAME, OP_RELEASE_NAME):
        body_len = 1 + rng.bounded(20)
    elif op == OP_TRANSFER_NAME:
        body_len = 21 + rng.bounded(31)
    elif op == OP_RENEW:
        body_len = [0, 5, 6 + rng.bounded(71)][rng.bounded(3)]
    elif op == OP_TRANSFER:
        body_len = 20 if rng.bounded(2) == 0 else 26 + rng.bounded(51)
    elif op == OP_SELL:
        body_len = 13 + rng.bounded(20)
    elif op in (OP_RESERVE, OP_SETTLE, OP_PAY):
        body_len = 1 + rng.bounded(20)
    elif op == OP_RELEASE:
        body_len = 6 + rng.bounded(71)
    elif op == OP_SELL_TO:
        body_len = 29 + rng.bounded(20)
    elif op == OP_AS:
        body_len = 1
    elif op == OP_TRADE:
        body_len = 5 + rng.bounded(30)
    else:
        body_len = rng.bounded(77)
    p = bytearray(4 + body_len)
    p[0] = 0xFF
    p[1] = 0x50
    p[2] = 0x4E
    p[3] = op
    for i in range(4, len(p)):
        p[i] = rng.bounded(256)
    return bytes(p)


def _fuzz_payload(rng):
    if rng.bounded(10) < 4:                  # dumb-random bytes
        length = rng.bounded(81)
        p = bytearray(rng.bounded(256) for _ in range(length))
        if rng.bounded(3) == 0 and length >= 4:
            p[0] = 0xFF
            p[1] = 0x50
            p[2] = 0x4E
            p[3] = 1 + rng.bounded(15)
        return bytes(p)
    payload = bytearray(_fuzz_grammar_payload(rng))
    pick = rng.bounded(6)
    if pick == 2:                            # truncate
        if len(payload) > 0:
            payload = payload[:-1]
    elif pick == 3:                          # flip a bit
        if len(payload) > 0:
            payload[rng.bounded(len(payload))] ^= (1 << rng.bounded(8))
    elif pick == 4:                          # extend
        payload += bytes([rng.bounded(256)])
    return bytes(payload)


def run_fuzz(seed, count):
    rng = SplitMix64(seed)
    s = State(activation_height=0)
    inp = bytearray()
    ts = BASE_TS
    height = 0
    tx_count = 0
    crashes = 0
    while tx_count < count:
        ts += 300 + rng.bounded(600)
        rate = 28 * (1 + rng.bounded(4))
        n_txs = 1 + rng.bounded(8)
        txs = []
        for ti in range(n_txs):
            if tx_count >= count:
                break
            n_in = 1 + rng.bounded(4)
            ins = []
            for _ in range(n_in):
                k = rng.bounded(N_IDS)
                typ = TYPE_P2SH if rng.bounded(4) == 3 else TYPE_P2PKH
                valid = rng.bounded(8) != 0
                ins.append({"id": gen_identity(k), "type": typ, "valid": valid})
            n_out = 1 + rng.bounded(4)
            outs = []
            for o in range(n_out):
                vk = rng.bounded(3)
                if vk == 0:
                    val = 0
                elif vk == 1:
                    val = (1 << 64) - rng.bounded(1000)
                else:
                    val = 1 + rng.bounded(1000)
                if rng.bounded(4) == 0:
                    outs.append(spend(o, gen_identity(rng.bounded(N_IDS)), val,
                                      rng.bounded(2)))
                else:
                    outs.append(carrier(o, _fuzz_payload(rng), value=val))
                inp += bytes([o & 0xFF]) + (val & MASK64).to_bytes(8, "little")
                ob = outs[-1]
                if ob["kind"] == "carrier":
                    pl = ob["payload"]
                    inp += (len(pl) & 0xFFFFFFFF).to_bytes(4, "little") + pl
            txs.append(tx(ti, ins, outs))
            tx_count += 1
        blk = {"height": height, "mtp": ts, "rate": rate, "txs": txs}
        try:
            apply_block(s, blk)
        except Exception:
            crashes += 1
        height += 1
    print("input_digest=%s" % _hashes.sha256(bytes(inp)).hex())
    print("state_digest=%s" % state_digest(s))
    print("parser_crashes=%d" % crashes)
    return 1 if crashes != 0 else 0


def _divergent_tail(blocks, J, n, kind):
    out = []
    if kind == 0:                            # reversed tail
        for i in range(J, n):
            out.append(_reverse_txs(blocks[i]))
    elif kind == 1:                          # every other block
        for i in range(J, n, 2):
            out.append(blocks[i])
    else:                                    # tail folded twice
        for i in range(J, n):
            out.append(blocks[i])
            out.append(blocks[i])
    return out


def run_reorgfuzz(seed, count):
    blocks = record_chain(seed, min(count, 20000))
    n = len(blocks)
    d_full = _fold_digest(blocks, 0, n)
    tr = SplitMix64(seed ^ 0x5245464B5A475F31)
    alt = bytearray()
    failures = 0
    for _ in range(64):
        J = tr.bounded(n + 1)
        kind = tr.bounded(3)
        # divergent branch -> D_alt
        sd = State(activation_height=0)
        for i in range(J):
            apply_block(sd, blocks[i])
        for b in _divergent_tail(blocks, J, n, kind):
            apply_block(sd, b)
        alt += bytes.fromhex(state_digest(sd))
        # assert clear-rebuild-to-J + canonical replay purity
        fork_j = _fold_digest(blocks, 0, J)
        sc = State(activation_height=0)
        for i in range(J):
            apply_block(sc, blocks[i])
        if state_digest(sc) != fork_j:
            failures += 1
        for i in range(J, n):
            apply_block(sc, blocks[i])
        if state_digest(sc) != d_full:
            failures += 1
    alt += bytes.fromhex(d_full)
    print("blocks=%d trials=64 failures=%d" % (n, failures))
    print("reorgfuzz_digest=%s" % _hashes.sha256(bytes(alt)).hex())
    return 1 if failures != 0 else 0


def run_decode_demo():
    cases = [
        (e_commit(b"\x00" * 32), 0),
        (e_claim(SALT0, b"alice"), KOINU_PER_DOGE),
        (e_claim(SALT0, b"Alice"), KOINU_PER_DOGE),   # uppercase -> IGNORE
        (e_claim(SALT0, b"-lead"), KOINU_PER_DOGE),   # leading hyphen -> IGNORE
        (e_claim(SALT0, b"xn--x"), KOINU_PER_DOGE),   # ACE prefix -> IGNORE
        (b"hello world", 5),                          # bare UTF-8 -> IGNORE
        (b"\xff\x53\x50\x20", 5),                     # unknown opcode -> IGNORE
        (b"\xff\x53\x50\xd6", 5),                     # overlay band -> IGNORE
    ]
    from wire import decode_payload
    for payload, val in cases:
        kind, info = decode_payload(payload, val)
        print("  %-30r value=%-10d -> %s" % (payload[:30], val, kind))


def run_attrib_demo():
    # build a minimal P2PKH tx and run attribute() with the injected oracle
    from attrib import attribute
    pk = b"\x02" + b"\x11" * 32
    der = b"\x30\x06\x02\x01\x01\x02\x01\x01"   # r=1,s=1
    sig = der + b"\x01"
    ss = bytes([len(sig)]) + sig + bytes([len(pk)]) + pk
    txd = {"version": 1, "locktime": 0,
           "vin": [{"txid": b"\x00" * 32, "vout": 0, "scriptSig": ss, "sequence": 0xFFFFFFFF}],
           "vout": [{"value": 0, "spk": b"\x6a\x04\xff\x53\x50\x01"}]}
    status, sighash, ident_ = attribute(txd, 0)
    print("  P2PKH attribute -> status=%d identity=%s" % (status, ident_.hex()))


def run_forkvectors():
    """Consensus-fork differential vectors (TV-1/5b/6/7/8 + M9 + H8 + H3),
    mirroring impls/{c,ts,rust} forkvectors. Each builds a construction against
    THIS impl and asserts the SPEC-pinned (2026-06-29) outcome. Reference-tier
    impls cannot share the gen.c seed soak (their generators differ by
    construction), so they each independently reproduce the spec outcome for every
    consensus-critical vector — agreement across independent impls is the strongest
    correctness signal. MTP is passed directly to begin_block/process_tx, so the
    boundary vectors (TV-1 at +COMMIT_EXPIRY, TV-7 at +1 day) set it explicitly."""
    A, B, TGT = ident(0xAA), ident(0xBB), ident(0x77)
    BOT = {"id": ident(0x99), "type": 0, "valid": False}   # exists but ⊥ (didn't sign) -> resolve None
    RATE = 28                                              # burn N koinu buys exactly N name-days
    M0 = 1_000_000
    SA, SB, SC = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    rows = []

    def owns(s, who, name):
        r = s.names.get(name)
        return r is not None and r.st == ST_OWNED and r.owner == who

    def lease(s, name):
        r = s.names.get(name)
        return r.lease_expiry if r is not None else -1

    def st_of(s, name):
        r = s.names.get(name)
        return r.st if r is not None else None

    # TV-1: COMMIT_EXPIRY inclusive — a claim at MTP == commit_time + COMMIT_EXPIRY still mints.
    s = State(0)
    cm = commitment_of(SA, b"edge", A)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(cm))]), 20, M0, RATE)
    cmtp = M0 + COMMIT_EXPIRY
    s.begin_block(21, cmtp)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SA, b"edge"), value=10)]), 21, cmtp, RATE)
    rows.append(("TV-1", "COMMIT_EXPIRY inclusive boundary",
                 "mint" if owns(s, A, b"edge") else "drop", "mint"))

    # TV-5b: one author, two matching commits (tx0,tx2) + a rival (tx1) — author (min COMMIT
    # tx_index) wins regardless of claim chain order (the §3.2 tuple is the COMMIT's tx_index).
    s = State(0)
    ca = commitment_of(SA, b"dup", A)
    cb = commitment_of(SB, b"dup", B)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(ca))]), 20, M0, RATE)   # tx0 A
    s.process_tx(tx(1, [vin(0xBB)], [carrier(0, e_commit(cb))]), 20, M0, RATE)   # tx1 B (rival)
    s.process_tx(tx(2, [vin(0xAA)], [carrier(0, e_commit(ca))]), 20, M0, RATE)   # tx2 A dup
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xBB)], [carrier(0, e_claim(SB, b"dup"), value=10)]), 21, m1, RATE)  # rival first
    s.process_tx(tx(1, [vin(0xAA)], [carrier(0, e_claim(SA, b"dup"), value=10)]), 21, m1, RATE)  # author second
    got = "A wins" if owns(s, A, b"dup") else ("B wins" if owns(s, B, b"dup") else "none")
    rows.append(("TV-5b", "claim multiplicity (author min-tuple)", got, "A wins"))

    # TV-6: bitmap LSB-first — flag 0x01 selects lexicographic name 0 (aa).
    s = State(0)
    names, salts = [b"aa", b"bb", b"cc"], [SA, SB, SC]
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(i, e_commit(commitment_of(salts[i], names[i], A)))
                                     for i in range(3)]), 20, M0, RATE)
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(i, e_claim(salts[i], names[i]), value=1)
                                     for i in range(3)]), 21, m1, RATE)
    aa0, bb0 = lease(s, b"aa"), lease(s, b"bb")
    m2 = M0 + 2000
    s.begin_block(22, m2)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_renew_sel(21, bytes([0x01])), value=10)]), 22, m2, RATE)
    got = "aa" if (lease(s, b"aa") > aa0 and lease(s, b"bb") == bb0) else "other"
    rows.append(("TV-6", "bitmap LSB-first (0x01 -> aa)", got, "aa"))

    # TV-7: a pre-block LAPSE bumps last_set_mutation_height (§3.5), so a selective RENEW
    # anchored at H-1 (before the lapse) is REJECTED against a now-stale ordering.
    s = State(0)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(SA, b"aa", A))),
                                     carrier(1, e_commit(commitment_of(SB, b"keep", A)))]), 20, M0, RATE)
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SA, b"aa"), value=1),       # 1 day -> expiry m1+BILLING_UNIT
                                     carrier(1, e_claim(SB, b"keep"), value=100)]), 21, m1, RATE)
    keep0 = lease(s, b"keep")
    m2 = m1 + BILLING_UNIT                       # MTP == aa's expiry -> aa lapses pre-block, bumps A to 22
    s.begin_block(22, m2)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_renew_sel(21, bytes([0x01])), value=10)]), 22, m2, RATE)
    rows.append(("TV-7", "lapse bumps mut height (stale RENEW)",
                 "ACCEPT" if lease(s, b"keep") > keep0 else "REJECT", "REJECT"))

    # TV-8: a selective TRANSFER selecting a LOCKED (listed) name skips it, moves the rest.
    s = State(0)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(i, e_commit(commitment_of(salts[i], names[i], A)))
                                     for i in range(3)]), 20, M0, RATE)
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(i, e_claim(salts[i], names[i]), value=200)
                                     for i in range(3)]), 21, m1, RATE)
    m2 = M0 + 2000
    s.begin_block(22, m2)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_sell(300, 20000, b"bb"))]), 22, m2, RATE)  # bb LISTED (locked)
    m3 = M0 + 3000
    s.begin_block(23, m3)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_transfer_sel(TGT, 22, bytes([0x03])))]), 23, m3, RATE)  # bits 0,1
    ok = owns(s, TGT, b"aa") and st_of(s, b"bb") == ST_LISTED and owns(s, A, b"cc")
    rows.append(("TV-8", "locked-name selective skip", "skip" if ok else "other", "skip"))

    # M9: TRADE is attributed to its named parties (idxA/idxB), NOT the acting identity. A TRADE
    # whose vin[0] is ⊥ (didn't sign SIGHASH_ALL) still settles if both named parties are valid.
    s = State(0)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(SA, b"na", A)))]), 20, M0, RATE)
    s.process_tx(tx(1, [vin(0xBB)], [carrier(0, e_commit(commitment_of(SB, b"nb", B)))]), 20, M0, RATE)
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SA, b"na"), value=50)]), 21, m1, RATE)
    s.process_tx(tx(1, [vin(0xBB)], [carrier(0, e_claim(SB, b"nb"), value=50)]), 21, m1, RATE)
    m2 = M0 + 2000
    s.begin_block(22, m2)
    s.process_tx(tx(0, [BOT, vin(0xAA), vin(0xBB)],                       # vin[0]=⊥; parties vin[1]=A,vin[2]=B
                    [carrier(0, e_trade(1, 2, b"na", b"nb"))]), 22, m2, RATE)
    got = "swap" if (owns(s, B, b"na") and owns(s, A, b"nb")) else "drop"
    rows.append(("M9", "TRADE bypasses bottom acting identity", got, "swap"))

    # H8: a used COMMIT lingers (NOT consumed on use) until its time-prune (§3.2; digest-affecting).
    s = State(0)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(SA, b"edge", A)))]), 20, M0, RATE)
    m1 = M0 + 10000                              # < COMMIT_EXPIRY -> commit live at claim
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SA, b"edge"), value=10)]), 21, m1, RATE)
    lingers = len(s.commits) == 1                # claim did NOT remove the backing commit
    s.begin_block(22, M0 + 20000)                # empty block; pre-block prune crosses the window
    pruned = len(s.commits) == 0
    rows.append(("H8", "used commit lingers then time-prunes",
                 "linger" if (lingers and pruned) else "other", "linger"))

    # H3: a per-owner mutation height persists after the owner's set empties (§3.5/§3.9; digest-affecting).
    s = State(0)
    s.begin_block(20, M0)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(SA, b"solo", A)))]), 20, M0, RATE)
    m1 = M0 + 1000
    s.begin_block(21, m1)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(SA, b"solo"), value=10)]), 21, m1, RATE)
    m2 = M0 + 2000
    s.begin_block(22, m2)
    s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_release(21, bytes([0x01])))]), 22, m2, RATE)  # set empties
    kept = st_of(s, b"solo") is None and (A in s.muts)
    rows.append(("H3", "mut row persists after set empties", "kept" if kept else "other", "kept"))

    npass = nfail = 0
    for tv, desc, got, want in rows:
        ok = got == want
        npass += ok
        nfail += not ok
        print("  %-6s %-46s py=%-7s spec=%-7s %s"
              % (tv, desc, got, want, "MATCH" if ok else "*** DIVERGE ***"))
    print("────")
    print("forkvectors: %d match, %d diverge (fold layer; spec-pinned 2026-06-29 reading)"
          % (npass, nfail))
    return 1 if nfail else 0


# ============================================================
# directed conformance vectors (cross-language adversarial scenarios)
# ============================================================
# The py port of impls/c `scenario`. Each builds a deterministic, named
# construction and emits `name <digest>` (canonical §4 state digest) or
# `name <u64>`; the rolling `combined` hash is the single-line cross-language
# check. These pin the spec's named edge cases (§5) with auditable outcomes and
# cover the rare branches the random soak almost never hits (deep displacement,
# i128 accumulation past 2^64, the fee oracle).
def run_scenario():
    RATE = 28                    # burn N koinu buys exactly N name-days (impls/c RATE_DAYS)
    U64_MAX = (1 << 64) - 1
    NOUT = 16                    # spendable outputs sit after carriers in vout space (SM_MAX_CARRIERS)
    A, B, C = ident(0xAA), ident(0xBB), ident(0xCC)
    feeds = bytearray()

    def salt(b):
        return bytes([b]) * 32

    def tgt(b):
        return bytes([b]) + b"\x00" * 31

    class F:
        """State + current-block cursor (begin_block/process_tx take h/mtp twice)."""
        def __init__(self):
            self.s = State(activation_height=0)
            self.h = 0
            self.mtp = 0

        def begin(self, h, mtp):
            self.h, self.mtp = h, mtp
            self.s.begin_block(h, mtp)

        def apply(self, t):
            self.s.process_tx(t, self.h, self.mtp, RATE)

    def out(vout_slot, dest, value):                 # spendable output, vout after carriers
        return spend(NOUT + vout_slot, dest, value)

    def emit_state(name, f):
        d = state_digest(f.s)
        print("%s %s" % (name, d))
        feeds.extend(bytes.fromhex(d))

    def emit_u64(name, v):
        print("%s %d" % (name, v))
        feeds.extend(int(v).to_bytes(8, "little"))

    # Commit `nm`(author=tag, salt sb) at block ch, then CLAIM `days` at block kh.
    def commit_then_claim(f, tag, nm, sb, days, cmtp, ch, kmtp, kh):
        aid = ident(tag)
        f.begin(ch, cmtp)
        f.apply(tx(0, [vin(tag)], [carrier(0, e_commit(commitment_of(salt(sb), nm, aid)))]))
        f.begin(kh, kmtp)
        f.apply(tx(0, [vin(tag)], [carrier(0, e_claim(salt(sb), nm), value=days)]))

    # Mint `nm` to `tag` with `days` lease, leaving the fold at the claim's block.
    def minted(tag, nm, days, claim_mtp):
        f = F()
        commit_then_claim(f, tag, nm, 0x33, days, claim_mtp - 100, 10, claim_mtp, 11)
        return f

    def two_names():
        f = F()
        f.begin(10, 1000)
        f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x01), b"aaa", A)))]))
        f.apply(tx(1, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x02), b"bbb", B)))]))
        f.begin(11, 1500)
        f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x01), b"aaa"), value=30)]))
        f.apply(tx(1, [vin(0xBB)], [carrier(0, e_claim(salt(0x02), b"bbb"), value=30)]))
        return f

    f = F()
    emit_state("01_empty", f)

    f = F()
    commit_then_claim(f, 0xAA, b"bob", 0x11, 10, 1000, 10, 1500, 11)
    emit_state("02_commit_claim", f)

    f = F()
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x11), b"bob"), value=10)]))
    emit_state("03_naked_claim_drop", f)

    f = F()
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x11), b"bob", A))),
                                carrier(1, e_claim(salt(0x11), b"bob"), value=10)]))
    emit_state("04_shallow_commit_drop", f)

    # priority: lower commit_height (A@10) wins ownership in BOTH claim orderings. The two
    # digests differ — a transiently-displaced mint leaves an incidental mutation-height bump
    # that depends on tx order — but each is cross-language-exact.
    for order in (0, 1):
        f = F()
        f.begin(10, 1000)
        f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x11), b"bob", A)))]))
        f.begin(12, 1100)
        f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x22), b"bob", B)))]))
        f.begin(20, 1200)
        kA = tx(1 if order == 0 else 0, [vin(0xAA)], [carrier(0, e_claim(salt(0x11), b"bob"), value=10)])
        kB = tx(0 if order == 0 else 1, [vin(0xBB)], [carrier(0, e_claim(salt(0x22), b"bob"), value=10)])
        if order == 0:
            f.apply(kB); f.apply(kA)
        else:
            f.apply(kA); f.apply(kB)
        emit_state("05_priority_b_first" if order == 0 else "06_priority_a_first", f)

    # commitment-copy: B reposts A's commitment bytes, then B claims → drop (author-bound);
    # A claims → owns.
    f = F()
    cm = commitment_of(salt(0x33), b"bob", A)                    # A-bound commitment
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(cm))]))
    f.apply(tx(1, [vin(0xBB)], [carrier(0, e_commit(cm))]))      # B copies the commitment
    f.begin(11, 1100)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_claim(salt(0x33), b"bob"), value=10)]))  # B can't satisfy → drop
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_claim(salt(0x33), b"bob"), value=10)]))  # A wins
    emit_state("07_commitment_copy", f)

    f = minted(0xAA, b"bob", 10, 1500)                           # expiry 865500
    f.begin(12, 865500)                                          # MTP == expiry → lapse (exclusive)
    emit_state("08_lease_lapse", f)

    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_renew_all(), value=5)]))
    emit_state("09_renew_stack", f)

    # water-fill even split: 3 names, renew-all buys 30 name-days → +10 each.
    f = F()
    nm = [b"a", b"b", b"c"]
    f.begin(10, 1000)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x40 + i), nm[i], A)))]))
    f.begin(11, 1100)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_claim(salt(0x40 + i), nm[i]), value=1)]))
    f.begin(12, 1200)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_renew_all(), value=30)]))
    emit_state("10_waterfill_even", f)

    f = F()
    commit_then_claim(f, 0xAA, b"bob", 0x11, 100000, 1000, 10, 1500, 11)  # huge → caps at 365d
    emit_state("11_waterfill_maxlease", f)

    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_transfer_all(B))]))
    emit_state("12_transfer_gift", f)

    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_release(11, b"\x01"))]))
    emit_state("13_release", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))
    f.begin(14, 1800)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_settle(b"w")), out(0, A, 19800)]))
    emit_state("14_market_full", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=99), out(0, A, 100)]))
    emit_state("15_reserve_burn_short", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 60), out(1, A, 60)]))
    emit_state("16_reserve_pay_summed", f)

    # reserve near offer end → reserve_expiry clamps to offer_expiry.
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 0, b"w"))]))  # window default 18000 → offer_expiry 19600
    f.begin(13, 5000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))  # 5000+18000>19600 → clamp
    emit_state("17_reserve_clamp", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(2, 0, b"w"))]))      # below 3·DUST
    emit_state("18_sell_price_floor", f)

    f = minted(0xAA, b"w", 1, 1500)
    f.begin(12, 65000)                                                 # short tail
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 0, b"w"))]))
    emit_state("19_sell_window_overflow", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell_to(5000, B, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xCC)], [carrier(0, e_pay(b"w")), out(0, A, 5000)]))  # stranger → drop
    f.apply(tx(1, [vin(0xBB)], [carrier(0, e_pay(b"w")), out(0, A, 5000)]))  # buyer → owns
    emit_state("20_directed_pay", f)

    # 2^64-1 price: the 128-bit deposit legs must be exact (a 64-bit impl wraps).
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(U64_MAX, 50000, b"w"))]))
    leg = U64_MAX * 50 // 10000
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=leg), out(0, A, leg)]))
    emit_state("21_deposit_2pow64", f)

    # AS attribution: claim attributed to vin[1]=B (matches B's commit).
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x55), b"bob", B)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA), vin(0xBB)], [carrier(0, e_as(1)),
                                           carrier(1, e_claim(salt(0x55), b"bob"), value=10)]))
    emit_state("22_as_attribution", f)

    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x55), b"bob", B)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA), vin(0xBB, valid=False)], [carrier(0, e_as(1)),
                                                        carrier(1, e_claim(salt(0x55), b"bob"), value=10)]))
    emit_state("23_as_oob_drop", f)

    f = two_names()
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA), vin(0xBB)], [carrier(0, e_trade(0, 1, b"aaa", b"bbb"))]))
    emit_state("24_trade_swap", f)

    f = two_names()
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_transfer_all(C))]))                # aaa→C before the trade
    f.apply(tx(1, [vin(0xAA), vin(0xBB)], [carrier(0, e_trade(0, 1, b"aaa", b"bbb"))]))  # anti-rug → drop
    emit_state("25_trade_rug_before", f)

    # fee oracle (§3.4): signed under-claim clamp + participant filter + MIN_FEE_SAMPLE
    # degrade + lower-median + REF_SIZE scale + clamp. 4 participants < MIN_FEE_SAMPLE
    # ⇒ this small window now degrades to DUST_FLOOR (the big-window vectors are 49–51).
    cb29 = [1_000_000_200_000, 1_000_000_400_000, 999_999_999_950, 1_000_001_000_000, 1_000_000_600_000]
    emit_u64("29_oracle_rate", oracle_rate([(c, 1000) for c in cb29]))     # |P|=4 < 1000 → DUST_FLOOR = 1
    emit_u64("30_oracle_floor", oracle_rate([(0, 1000)] * 3))              # all under-claim → fees 0 → floor
    emit_u64("31_mtp_median", compute_mtp([100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190], 11))  # median of 11

    # ── water-fill rare branches ──
    # 32: T < count — burn buys fewer name-days than names; the first T names
    # (ascending-lex) get +1 day, the rest none (§3.5 floor).
    f = F()
    f.begin(10, 1000)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x50 + i), nm[i], A)))]))
    f.begin(11, 1100)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_claim(salt(0x50 + i), nm[i]), value=1)]))
    f.begin(12, 1200)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_renew_all(), value=2)]))      # T=2 over 3 → a,b +1d, c none
    emit_state("32_waterfill_floor", f)

    # 33: every targeted name hits MAX_LEASE with T still remaining → surplus forfeited.
    f = F()
    f.begin(10, 1000)
    for i in range(2):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x60 + i), nm[i], A)))]))
    f.begin(11, 1100)
    for i in range(2):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_claim(salt(0x60 + i), nm[i]), value=360)]))  # ~360d each
    f.begin(12, 1100)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_renew_all(), value=100000)])) # huge → both cap @MAX_LEASE, forfeit
    emit_state("33_waterfill_allcap_forfeit", f)

    # ── reorg edge cases as deterministic vectors ──
    # 34: a same-block lapse-and-reclaim. (a) bob lapses at MTP==expiry, B reclaims → B owns.
    #     (b) the reorg restores A's earlier RENEW, so bob never lapses and B's reclaim drops.
    f = minted(0xAA, b"bob", 10, 1500)                                     # expiry 865500
    f.begin(12, 860000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x44), b"bob", B)))]))
    f.begin(13, 865500)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_claim(salt(0x44), b"bob"), value=10)]))  # lapse then B mints
    emit_state("34a_reorg_lapse_reclaim", f)

    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 860000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x44), b"bob", B)))]))
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_renew_all(), value=10)]))     # A renews → bob survives past 865500
    f.begin(13, 865500)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_claim(salt(0x44), b"bob"), value=10)]))  # bob owned → drop
    emit_state("34b_reorg_renew_blocks_reclaim", f)

    # 35: a SETTLE un-confirmed by a reorg. (a) the reserve lapses without a settle →
    #     the listing reverts to the seller; (b) the settle confirms → buyer owns.
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))
    f.begin(14, 20000)                                 # MTP past reserve_expiry (19700) → revert to listing
    emit_state("35a_settle_dropped_relisted", f)

    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))
    f.begin(14, 1800)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_settle(b"w")), out(0, A, 19800)]))
    emit_state("35b_settle_confirmed", f)

    # 36: an MTP boundary call that flips under a one-tick reorg. lease_expiry is an
    #     EXCLUSIVE bound: MTP == expiry−1 stays owned; MTP == expiry lapses.
    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 865499)
    emit_state("36a_mtp_below_owned", f)
    f = minted(0xAA, b"bob", 10, 1500)
    f.begin(12, 865500)
    emit_state("36b_mtp_at_lapsed", f)

    # ── pre-block ordering & intra-block market races ──
    # 38: a same-block RENEW-vs-CLAIM race at the exact lapse tie. The pre-block lapse
    #     returns `bob` to the pool BEFORE any tx runs, so A's renew-all renews only `keep`
    #     and the hunter B's CLAIM (commit ≥1 block deep) mints `bob`.
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x33), b"bob", A)))]))
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x34), b"keep", A)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x33), b"bob"), value=10)]))    # bob expiry 865500
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_claim(salt(0x34), b"keep"), value=300)]))  # keep long-lived
    f.begin(12, 860000)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x44), b"bob", B)))]))  # hunter commits
    f.begin(13, 865500)                                # MTP == bob's expiry → bob lapses pre-block
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_renew_all(), value=5)]))                   # renews `keep` only
    f.apply(tx(1, [vin(0xBB)], [carrier(0, e_claim(salt(0x44), b"bob"), value=10)]))    # hunter mints bob
    emit_state("38_lapse_renew_vs_claim", f)

    # 39: a single pre-block tick that crosses reserve_expiry AND offer_expiry at once,
    #     cascading RESERVED→LISTED→OWNED in one pass (§5 type-order reserve→offer→lease).
    f = minted(0xAA, b"w", 300, 1500)                  # lease_expiry = 25,921,500
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))               # offer_expiry = 51600
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))  # reserve_expiry 19700 < 51600
    f.begin(14, 51600)                                 # MTP == offer_expiry, > reserve_expiry → both legs fire
    emit_state("39_preblock_reserve_offer_collapse", f)

    # 40: intra-block RESERVE option theft. The first buyer (chain-order) wins the exclusive
    #     option; the second drops (no overwrite), so its later SETTLE fails the buyer-match.
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))    # B wins the option
    f.apply(tx(1, [vin(0xCC)], [carrier(0, e_reserve(b"w"), value=100), out(0, A, 100)]))    # C loses → drop
    f.apply(tx(2, [vin(0xCC)], [carrier(0, e_settle(b"w")), out(0, A, 19800)]))              # buyer-mismatch → drop
    emit_state("40_reserve_option_theft", f)

    # 41: value-collision in spendable-output matching. One tx does RESERVE(x)+SETTLE(y),
    #     both paying seller A, with two outputs to A: vout[0]=19800 (settle remainder) and
    #     vout[1]=5 (reserve pay-leg). The consume-once, exact-value, vout-order matcher must
    #     let RESERVE skip the larger vout[0] and take vout[1], then SETTLE take vout[0].
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x71), b"x", A)))]))
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x72), b"y", A)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x71), b"x"), value=300)]))
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_claim(salt(0x72), b"y"), value=300)]))
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(1000, 50000, b"x"))]))   # pay_leg(x) = 5
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"y"))]))  # remainder(y) = 19800
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"y"), value=100), out(0, A, 100)]))  # B reserves y
    f.begin(14, 1800)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"x"), value=5),     # car_value 5 ≥ burn_leg(x)=5
                                carrier(1, e_settle(b"y")),
                                out(0, A, 19800),                          # vout[0] (lower) = settle remainder
                                out(1, A, 5)]))                            # vout[1] (higher) = reserve pay-leg
    emit_state("41_vout_value_collision", f)

    # ── priority tie-break + Tier-4 coverage (audit follow-ups) ──
    # 42: CLAIM priority tie-break is the COMMIT's tx_index (§3.2 tuple), NOT claim chain order.
    f = F()
    f.begin(10, 1000)
    f.apply(tx(5, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x81), b"bob", A)))]))
    f.apply(tx(2, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x82), b"bob", B)))]))
    f.begin(20, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x81), b"bob"), value=10)]))  # applied first
    f.apply(tx(1, [vin(0xBB)], [carrier(0, e_claim(salt(0x82), b"bob"), value=10)]))  # lower commit tx_index → wins
    emit_state("42_claim_commit_txindex_tiebreak", f)

    # 43: escrow movement-lock (§3.7 headline) — a LISTED name rejects every move:
    #     TRANSFER, RELEASE, re-SELL, and SELL_TO all no-op while it sits on the market.
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_transfer_all(B))]))           # gift → locked, skip
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_release(11, b"\x01"))]))      # release → locked, skip
    f.apply(tx(2, [vin(0xAA)], [carrier(0, e_sell(30000, 50000, b"w"))]))  # re-SELL → not OWNED, reject
    f.apply(tx(3, [vin(0xAA)], [carrier(0, e_sell_to(5000, B, b"w"))]))    # SELL_TO → not OWNED, reject
    emit_state("43_escrow_movement_lock", f)

    # 44: anchor-guard reject (§3.5) — a bitmap op whose anchor is OLDER than the owner's
    #     last set-mutation is dropped (stale set-view could select the wrong names).
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x91), b"a", A)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x91), b"a"), value=30)]))     # lm(A)=11
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x92), b"b", A)))]))
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x92), b"b"), value=30)]))     # lm(A)=12 (set grew)
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_release(11, b"\x01"))]))                  # anchor 11 < lm 12 → reject
    emit_state("44_anchor_guard_reject", f)

    # 45: COMMIT_EXPIRY prune — a commit older than COMMIT_EXPIRY (18000s) is pruned pre-block,
    #     so a later matching claim finds no live commit and drops (§3.2).
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x33), b"bob", A)))]))
    f.begin(11, 19001)                                                     # 19001 > 1000 + 18000 → prune
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x33), b"bob"), value=10)]))   # no live commit → drop
    emit_state("45_commit_expiry_prune", f)

    # 46: RESERVE burn leg is an inequality (car_value ≥ burn_leg), not exact — an OVER-funded
    #     burn (car_value 150 > burn_leg 100) still wins the option (cf. 15: 99 < 100 drops).
    f = minted(0xAA, b"w", 300, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_sell(20000, 50000, b"w"))]))
    f.begin(13, 1700)
    f.apply(tx(0, [vin(0xBB)], [carrier(0, e_reserve(b"w"), value=150), out(0, A, 100)]))
    emit_state("46_reserve_overfunded_burn", f)

    # 47: TRADE malformed drops — OOB index, idxA==idxB (one party), and nameA==nameB are
    #     each fail-closed; the two-name state is left untouched (§3.10).
    f = two_names()
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA), vin(0xBB)], [carrier(0, e_trade(0, 5, b"aaa", b"bbb"))]))  # idx_b OOB → drop
    f.apply(tx(1, [vin(0xAA), vin(0xBB)], [carrier(0, e_trade(0, 0, b"aaa", b"bbb"))]))  # idxA==idxB → drop
    f.apply(tx(2, [vin(0xAA), vin(0xBB)], [carrier(0, e_trade(0, 1, b"aaa", b"aaa"))]))  # nameA==nameB → drop
    emit_state("47_trade_malformed_drops", f)

    # 48: selective TRANSFER (anchor+flags) gifts a SUBSET — bits {0,2} of A's sorted set
    #     {a,b,c} move to B; b stays with A. Exercises the bitmap-selected positive transfer.
    f = F()
    f.begin(10, 1000)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0xA1 + i), nm[i], A)))]))
    f.begin(11, 1500)
    for i in range(3):
        f.apply(tx(i, [vin(0xAA)], [carrier(0, e_claim(salt(0xA1 + i), nm[i]), value=30)]))
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_transfer_sel(B, 11, b"\x05"))]))  # bits 0 and 2 → a, c
    emit_state("48_transfer_selective", f)

    # ── §3.4 participant-median oracle (fee-bearing filter + MIN_FEE_SAMPLE) ──
    # 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim block inside
    #     the window. Lower median = index (1000−1)/2 = 499 of the sorted 100..1099 → 599 →
    #     rate 119,800. Every rival reading forks to a different number.
    win49 = []
    for i in range(1500):
        if i < 499:
            cb = SUBSIDY                                       # zero-fee → non-participant
        elif i == 499:
            cb = SUBSIDY - 50                                  # under-claim → non-participant
        else:
            cb = SUBSIDY + (100 + (i - 500)) * 1000            # fpb 100..1099
        win49.append((cb, 1000))
    emit_u64("49_oracle_even_boundary", oracle_rate(win49))    # → 119800

    # 50: odd |P| = 1101 through the participant filter — the historical middle
    #     rule unchanged by the rewrite: index 550 of 100..1200 → 650 → 130,000.
    win50 = [(SUBSIDY if i < 899 else SUBSIDY + (100 + (i - 899)) * 1000, 1000)
             for i in range(2000)]                             # fpb 100..1200
    emit_u64("50_oracle_odd_median", oracle_rate(win50))       # → 130000

    # 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
    win51 = [(SUBSIDY if i < 501 else SUBSIDY + (100 + (i - 501)) * 1000, 1000)
             for i in range(1500)]                             # 999 participants
    emit_u64("51_oracle_subsample_floor", oracle_rate(win51))  # → 1

    # 52: charset = a DNS label [a-z0-9-], 1..32 (re-pinned 2026-07-07, supersedes
    # the 2026-07-02 dot rule): hyphen and a 32-byte name MINT; '.' and '_' now DROP
    # (uppercase still drops), leaving exactly the two valid names.
    f = F()
    commit_then_claim(f, 0xAA, b"shib-p2p",                         0x71, 10, 1000, 10, 1500, 11)
    commit_then_claim(f, 0xAA, b"abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13)
    commit_then_claim(f, 0xAA, b"shib.p2p",                         0x73, 10, 3000, 14, 3500, 15)
    commit_then_claim(f, 0xAA, b"shib_p2p",                         0x74, 10, 4000, 16, 4500, 17)
    emit_state("52_charset", f)

    # 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
    f = F()
    commit_then_claim(f, 0xAA, b"-lead",  0x81, 10, 1000, 10, 1500, 11)
    commit_then_claim(f, 0xAA, b"trail-", 0x82, 10, 2000, 12, 2500, 13)
    commit_then_claim(f, 0xAA, b"xn--x",  0x83, 10, 3000, 14, 3500, 15)
    commit_then_claim(f, 0xAA, b"ok-name",0x84, 10, 4000, 16, 4500, 17)
    emit_state("52b_structural", f)

    # 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
    # historical 16; all fold. An impl that caps at 16 drops the 17th → different digest.
    f = F()
    f.begin(10, 1000)
    commits = [carrier(i, e_commit(bytes([i]) + b"\x00" * 31)) for i in range(17)]
    payees = [out(i, A, 1) for i in range(17)]
    f.apply(tx(0, [vin(0xAA)], commits + payees))
    emit_state("54_no_txcap", f)

    # 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
    # later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
    # authoritative, the block-local claim scratch never blocks a re-mint).
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x91), b"foo", A)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x91), b"foo"), value=10)]))   # mint foo→A
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_release(11, b"\x01"))]))                   # release foo
    f.apply(tx(2, [vin(0xAA)], [carrier(0, e_claim(salt(0x91), b"foo"), value=10)]))    # re-mint foo→A
    emit_state("55_claim_release_reclaim_sameblock", f)

    # 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
    # LOWER priority than the departed A's — B still mints fresh (a released name's
    # former owner priority is irrelevant once the row is gone).
    f = F()
    f.begin(10, 1000)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x91), b"foo", A)))]))
    f.apply(tx(1, [vin(0xBB)], [carrier(0, e_commit(commitment_of(salt(0x92), b"foo", B)))]))
    f.begin(11, 1500)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x91), b"foo"), value=10)]))    # A mints
    f.apply(tx(1, [vin(0xAA)], [carrier(0, e_release(11, b"\x01"))]))                   # A releases
    f.apply(tx(2, [vin(0xBB)], [carrier(0, e_claim(salt(0x92), b"foo"), value=10)]))    # B mints fresh
    emit_state("55b_reclaim_by_other", f)

    # 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
    # move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
    f = minted(0xAA, b"bar", 10, 1500)
    f.begin(12, 1600)
    f.apply(tx(0, [vin(0xAA)], [carrier(0, e_transfer_all(A))]))
    emit_state("56_self_transfer_bumps_mut", f)

    # 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
    # fee-per-byte 0), so the block still participates. 1000 blocks (== MIN_FEE_SAMPLE),
    # each fee 5000 ⇒ per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
    emit_u64("57_oracle_zero_bytes", oracle_rate([(1_000_000_005_000, 0)] * 1000))

    # 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count overflows
    # 64 bits and clamps to MAX_LEASE (365 days): lease_expiry = 1500 + 365·86400.
    f = F()
    f.begin(10, 1000)
    f.s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_commit(commitment_of(salt(0x95), b"foo", A)))]), 10, 1000, 1)
    f.begin(11, 1500)
    f.s.process_tx(tx(0, [vin(0xAA)], [carrier(0, e_claim(salt(0x95), b"foo"), value=U64_MAX)]), 11, 1500, 1)
    emit_state("58_lease_clamp_huge_burn", f)

    print("combined %s" % _hashes.sha256(bytes(feeds)).hex())
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 0
    mode = argv[1]
    if mode == "selftest":
        return run_selftest()
    if mode == "scenario":
        return run_scenario()
    if mode == "forkvectors":
        return run_forkvectors()
    if mode in ("digest", "random"):
        seed = int(argv[2]) if len(argv) > 2 else 1
        count = int(argv[3]) if len(argv) > 3 else 50
        d = run_generator(seed, count)
        print("seed=%d count=%d state_digest=%s" % (seed, count, d))
        print("(own generator — NOT comparable to reference frozen goldens, §6)")
        return 0
    if mode in ("properties", "meta", "reorg", "reorgfuzz", "fuzz"):
        seed = int(argv[2]) if len(argv) > 2 else 1
        count = int(argv[3]) if len(argv) > 3 else 1000
        return {"properties": run_properties, "meta": run_meta, "reorg": run_reorg,
                "reorgfuzz": run_reorgfuzz, "fuzz": run_fuzz}[mode](seed, count)
    if mode == "decode-demo":
        run_decode_demo()
        return 0
    if mode == "attrib-demo":
        run_attrib_demo()
        return 0
    if mode == "attrib-curve":
        import attrib_curve
        return attrib_curve.run()
    if mode == "ecmh":
        import ecmh
        return ecmh.run()
    print("unknown mode:", mode)
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
