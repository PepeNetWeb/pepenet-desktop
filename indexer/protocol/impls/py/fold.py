"""The fold state machine (protocol-spec.md §3, §5; SPEC-conformance.md §3,§4).

A deterministic fold over blocks in (height, tx_index, vout) order. Identities
are already-resolved (§4 attribution lives in attrib.py); this layer consumes
(identity, script_type, valid) inputs and decoded carriers.

Every judgment call forced by the prose is cross-referenced to SPEC-RATIONALE.md.
"""
from const import *
from wire import decode_payload, ACTION, IGNORE
from hashes import sha256


# ---------------- tx / output model ----------------
# An Input  = {"id": 20-byte hash160 or None, "type": 0/1, "valid": bool}
#   valid == (§4 passes AND signs SIGHASH_ALL); None id means unattributable.
# A carrier output = {"kind":"carrier","vout":int,"payload":bytes,"value":int}
# A spend  output  = {"kind":"spend","vout":int,"hash160":20b,"type":0/1,"value":int}

def synthetic_txid(height, txindex):
    """SPEC-conformance.md §3: u64_le(height) ‖ u32_le(txindex) ‖ 20 zero bytes."""
    return (height & MASK64).to_bytes(8, "little") + \
           (txindex & 0xFFFFFFFF).to_bytes(4, "little") + b"\x00" * 20


class NameRow:
    __slots__ = ("name", "owner", "owner_type", "lease_expiry", "st",
                 "seller", "seller_type", "price", "offer_expiry",
                 "buyer", "burn_leg", "pay_leg", "reserve_expiry")

    def __init__(self, name, owner, owner_type, lease_expiry):
        self.name = name
        self.owner = owner
        self.owner_type = owner_type
        self.lease_expiry = lease_expiry
        self.st = ST_OWNED
        self._reset_market()

    def _reset_market(self):
        self.seller = b"\x00" * 20
        self.seller_type = 0
        self.price = 0
        self.offer_expiry = 0
        self.buyer = b"\x00" * 20   # reserver (RESERVED) or directed buyer (OFFERED)
        self.burn_leg = 0
        self.pay_leg = 0
        self.reserve_expiry = 0


class State:
    def __init__(self, activation_height=0):
        self.activation_height = activation_height
        self.names = {}                 # name(bytes) -> NameRow
        self.commits = []               # list of dicts
        self.muts = {}                  # owner(20) -> i64 height
        # per-block scratch (NOT digested)
        self._scratch = {}              # name -> (commit_height, commit_tx_index, owner)

    # ---- helpers ----
    def owned_names_of(self, owner):
        """All names owned by `owner`, ascending lexicographic (unsigned bytewise)."""
        return sorted([n for n, r in self.names.items() if r.owner == owner])

    def owns_any(self, owner):
        for r in self.names.values():
            if r.owner == owner:
                return True
        return False

    def _bump(self, owner, height):
        """Monotonic high-water mark; never decreases, never pruned."""
        cur = self.muts.get(owner)
        if cur is None or height > cur:
            self.muts[owner] = height

    # ============ pre-block time-triggered transitions (§5) ============
    def begin_block(self, height, mtp):
        self._scratch = {}
        # per-name reserve -> offer -> lease, then COMMIT_EXPIRY prune.
        # iterate over a stable snapshot (sorted) — distinct names independent.
        for name in sorted(self.names.keys()):
            row = self.names.get(name)
            if row is None:
                continue
            # reserve_expiry (exclusive): revert RESERVED -> LISTED
            if row.st == ST_RESERVED and mtp >= row.reserve_expiry:
                # revert to open listing pre-reserve state; reset reserve fields
                row.st = ST_LISTED
                row.buyer = b"\x00" * 20
                row.burn_leg = 0
                row.pay_leg = 0
                row.reserve_expiry = 0
            # offer_expiry (exclusive): close LISTED or OFFERED -> OWNED
            if row.st in (ST_LISTED, ST_OFFERED) and mtp >= row.offer_expiry:
                row.st = ST_OWNED
                row._reset_market()
            # lease_expiry (exclusive): lapse -> remove, stamp owner mut to H
            if mtp >= row.lease_expiry:
                owner = row.owner
                del self.names[name]
                self._bump(owner, height)
        # COMMIT_EXPIRY prune (inclusive window: prune once mtp STRICTLY exceeds)
        self.commits = [c for c in self.commits
                        if not (mtp > c["commit_time"] + COMMIT_EXPIRY)]

    # ============ per-tx processing (§5) ============
    def process_tx(self, tx, height, mtp, rate):
        inputs = tx["inputs"]
        outputs = sorted(tx["outputs"], key=lambda o: o["vout"])
        spendable = [o for o in outputs if o["kind"] == "spend"]
        consumed = set()                 # vouts already matched

        def resolve(idx):
            if idx < 0 or idx >= len(inputs):
                return None
            inp = inputs[idx]
            if inp["id"] is not None and inp["valid"]:
                return (inp["id"], inp["type"])
            return None

        def match_output(seller_hash, seller_type, owed):
            for o in spendable:                       # already vout-sorted
                if o["vout"] in consumed:
                    continue
                if (o["hash160"] == seller_hash and o["type"] == seller_type
                        and o["value"] == owed):
                    consumed.add(o["vout"])
                    return True
            return False

        actor = resolve(0)               # vin[0] default (Rule 1)

        for o in outputs:
            if o["kind"] != "carrier":
                continue
            payload = o["payload"]
            kind, info = decode_payload(payload, o["value"])
            if kind != ACTION:
                continue                 # IGNORE (or anything non-action)
            op = info["op"]
            # forward-only activation gate (§3.0): all ops gate at one height.
            if height < self.activation_height:
                continue
            if op == OP_AS:
                actor = resolve(info["index"])
                continue
            if op == OP_TRADE:
                # attributed to its OWN named inputs, never the acting identity
                self._do_trade(info, inputs, resolve, height)
                continue
            # every other op acts as the acting identity
            if actor is None:
                continue                 # ⊥ actor -> drop
            self._dispatch(op, info, actor, o, height, mtp, rate,
                           match_output, tx["txindex"])

    def _dispatch(self, op, info, actor, carrier, height, mtp, rate,
                  match_output, txindex):
        aid, atype = actor
        if op == OP_COMMIT:
            self.commits.append({"commitment": info["commitment"],
                                 "commit_height": height,
                                 "tx_index": txindex,
                                 "commit_time": mtp})
        elif op == OP_CLAIM:
            self._do_claim(info, aid, atype, carrier, height, mtp, rate)
        elif op == OP_RENEW:
            self._do_renew(info, aid, height, mtp, rate, carrier)
        elif op == OP_TRANSFER:
            self._do_transfer(info, aid, height)
        elif op == OP_RELEASE:
            self._do_release(info, aid, height)
        elif op == OP_RENEW_NAME:
            self._do_renew_name(info, aid, mtp, rate, carrier)
        elif op == OP_TRANSFER_NAME:
            self._do_transfer_name(info, aid, height)
        elif op == OP_RELEASE_NAME:
            self._do_release_name(info, aid, height)
        elif op == OP_SELL:
            self._do_sell(info, aid, atype, mtp)
        elif op == OP_RESERVE:
            self._do_reserve(info, aid, carrier, mtp, match_output)
        elif op == OP_SETTLE:
            self._do_settle(info, aid, mtp, match_output, height)
        elif op == OP_SELL_TO:
            self._do_sell_to(info, aid, atype, mtp)
        elif op == OP_PAY:
            self._do_pay(info, aid, mtp, match_output, height)

    # ---------------- claim (§3.2) ----------------
    def _find_backing_commit(self, target, claim_height):
        """Min (commit_height, tx_index) commit matching `target` in a strictly
        earlier block (commits still in table are live by pre-block prune)."""
        best = None
        for c in self.commits:
            if c["commitment"] != target:
                continue
            if not (c["commit_height"] < claim_height):
                continue
            key = (c["commit_height"], c["tx_index"])
            if best is None or key < best:
                best = key
        return best

    def _do_claim(self, info, aid, atype, carrier, height, mtp, rate):
        name = info["name"]
        target = sha256(info["salt"] + name + aid)
        backing = self._find_backing_commit(target, height)
        if backing is None:
            return                       # no live >=1-deep commit -> drop
        bch, btx = backing
        # Row existence is authoritative (matches Go/TS/C): a name removed earlier
        # in THIS block (minted then RELEASEd) is absent here and re-mints fresh —
        # the lingering scratch entry does NOT block it (§3.6 "a released name is
        # immediately reclaimable"). Only a name still present can be displaced.
        if name in self.names:
            if name not in self._scratch:
                return                   # owned from a prior block -> drop
            old = self._scratch[name]
            existing = self.names[name]
            # displace iff still that owner's fresh OWNED mint AND strictly smaller
            # (commit_height, commit_tx_index) — §3.2's tuple, NOT claim chain order.
            if not (existing.st == ST_OWNED and existing.owner == old[2]
                    and (bch, btx) < (old[0], old[1])):
                return                   # does not displace -> drop
            # else: fall through to re-mint (displacement resets owner + lease)
        # compute lease (fresh mint or displacement)
        days = lease_days(carrier["value"], rate)
        if days < 1:
            return                       # T==0 fail-closed
        # fresh mint: headroom = full MAX_LEASE
        headroom_days = MAX_LEASE // BILLING_UNIT
        add = min(days, headroom_days)
        lease_expiry = mtp + add * BILLING_UNIT
        row = NameRow(name, aid, atype, lease_expiry)
        self.names[name] = row
        self._scratch[name] = (bch, btx, aid)
        self._bump(aid, height)

    # ---------------- renew (§3.5) ----------------
    def _anchor_ok(self, owner, anchor, height):
        last = self.muts.get(owner, 0)
        if not (last <= anchor <= height):
            return False
        if height - anchor > MAX_ANCHOR_AGE:
            return False
        return True

    def _selected_from_flags(self, owned, flags):
        sel = []
        K = len(owned)
        max_bits = len(flags) * 8         # bits beyond the bitmap are absent -> 0
        for i in range(min(K, max_bits)):  # bits >= K AND bits >= bitmap length ignored
            if (flags[i >> 3] >> (i & 7)) & 1:
                sel.append(owned[i])
        return sel

    def _do_renew(self, info, owner, height, mtp, rate, carrier):
        owned = self.owned_names_of(owner)
        if info["mode"] == "all":
            selected = owned
        elif info["mode"] == "all_safe":
            if not self._anchor_ok(owner, info["anchor"], height):
                return
            selected = owned
        else:  # selective
            if not self._anchor_ok(owner, info["anchor"], height):
                return
            selected = self._selected_from_flags(owned, info["flags"])
        # RENEW renews even locked/offered names (still renewable, §3.7)
        if not selected:
            return
        alloc = water_fill(carrier["value"], rate, mtp,
                           [self.names[n].lease_expiry for n in selected],
                           selected)
        if alloc is None:
            return                       # T==0 fail-closed
        for n, add in alloc.items():
            self.names[n].lease_expiry += add * BILLING_UNIT
        # RENEW does NOT bump last_set_mutation_height (§3.5)

    # ---------------- transfer (§3.6) ----------------
    def _do_transfer(self, info, owner, height):
        owned = self.owned_names_of(owner)
        target = info["target"]
        if info["mode"] == "all":
            selected = owned
        else:
            if not self._anchor_ok(owner, info["anchor"], height):
                return
            selected = self._selected_from_flags(owned, info["flags"])
        moved = []
        for n in selected:
            row = self.names[n]
            if row.st != ST_OWNED:
                continue                 # locked (listed/offered) -> skip
            moved.append(n)
        if not moved:
            return                       # all-skipped no-op -> no bump
        for n in moved:
            row = self.names[n]
            row.owner = target
            row.owner_type = 0           # target type unknown (not digested)
        self._bump(owner, height)
        self._bump(target, height)

    # ---------------- release (§3.6) ----------------
    def _do_release(self, info, owner, height):
        if not self._anchor_ok(owner, info["anchor"], height):
            return
        owned = self.owned_names_of(owner)
        selected = self._selected_from_flags(owned, info["flags"])
        released = []
        for n in selected:
            row = self.names[n]
            if row.st != ST_OWNED:
                continue                 # locked -> skip
            released.append(n)
        if not released:
            return                       # no-op -> no bump
        for n in released:
            del self.names[n]
        self._bump(owner, height)

    # ---------------- the by-name forms (§3.5) ----------------
    def _find_mine(self, info, actor):
        """info['name'] iff `actor` controls it: the owned set includes listed/
        offered/reserved names (owner stays the seller until settle/pay).
        Absent or not the actor's -> None (drop)."""
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.owner != actor:
            return None
        return name

    def _do_renew_name(self, info, owner, mtp, rate, carrier):
        name = self._find_mine(info, owner)
        if name is None:
            return
        alloc = water_fill(carrier["value"], rate, mtp,
                           [self.names[name].lease_expiry], [name])
        if alloc is None:
            return                       # T==0 fail-closed
        for n, add in alloc.items():
            self.names[n].lease_expiry += add * BILLING_UNIT
        # renewal is not a set mutation: no bump (§3.5)

    def _do_transfer_name(self, info, owner, height):
        name = self._find_mine(info, owner)
        if name is None:
            return
        row = self.names[name]
        if row.st != ST_OWNED:
            return                       # locked (listed/offered) -> no-op, no bump
        row.owner = info["target"]
        row.owner_type = 0               # target type unknown (not digested)
        self._bump(owner, height)        # a move bumps BOTH parties (§3.5)
        self._bump(info["target"], height)

    def _do_release_name(self, info, owner, height):
        name = self._find_mine(info, owner)
        if name is None:
            return
        if self.names[name].st != ST_OWNED:
            return                       # locked -> no-op, no bump
        del self.names[name]
        self._bump(owner, height)

    # ---------------- sell (§3.7) ----------------
    def _do_sell(self, info, seller, seller_type, mtp):
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.owner != seller or row.st != ST_OWNED:
            return
        price = info["price"]
        if price < 3 * DUST_FLOOR:
            return
        window = info["window"]
        if window == 0:
            w = RESERVE_WINDOW
        elif window < RESERVE_WINDOW:
            return                       # nonzero below floor -> ignore
        else:
            w = window
        # add-form upper bound (no unsigned underflow)
        if not (mtp + w + REORG_BUFFER <= row.lease_expiry):
            return
        row.st = ST_LISTED
        row.seller = seller
        row.seller_type = seller_type
        row.price = price
        row.offer_expiry = mtp + w
        # SELL is NOT a set mutation -> no bump

    # ---------------- reserve (§3.7) ----------------
    def _do_reserve(self, info, reserver, carrier, mtp, match_output):
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.st != ST_LISTED:
            return                       # only an OPEN listing is reservable
        burn_leg = max(DUST_FLOOR, (row.price * RESERVE_BURN_BPS) // 10000)
        pay_leg = max(DUST_FLOOR, (row.price * RESERVE_PAY_BPS) // 10000)
        if carrier["value"] < burn_leg:
            return                       # carrier value short of burn_leg
        if not match_output(row.seller, row.seller_type, pay_leg):
            return                       # pay_leg output absent
        row.st = ST_RESERVED
        row.buyer = reserver             # reserver stored in buyer slot
        row.burn_leg = burn_leg
        row.pay_leg = pay_leg
        row.reserve_expiry = min(mtp + RESERVE_WINDOW, row.offer_expiry)
        # RESERVE does not change the set -> no bump

    # ---------------- settle (§3.7) ----------------
    def _do_settle(self, info, buyer, mtp, match_output, height):
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.st != ST_RESERVED:
            return
        if row.buyer != buyer:
            return                       # only the exclusive reserver may settle
        if not (mtp < row.reserve_expiry):
            return
        remainder = row.price - row.burn_leg - row.pay_leg
        if not match_output(row.seller, row.seller_type, remainder):
            return
        seller = row.seller
        row.owner = buyer
        row.owner_type = 0               # buyer type unknown (not digested)
        row.st = ST_OWNED
        row._reset_market()
        self._bump(seller, height)
        self._bump(buyer, height)

    # ---------------- sell_to (§3.7) ----------------
    def _do_sell_to(self, info, seller, seller_type, mtp):
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.owner != seller or row.st != ST_OWNED:
            return
        price = info["price"]
        if price < DUST_FLOOR:
            return
        if not (mtp + DIRECT_WINDOW + REORG_BUFFER <= row.lease_expiry):
            return
        row.st = ST_OFFERED
        row.seller = seller
        row.seller_type = seller_type
        row.price = price
        row.buyer = info["buyer"]
        row.offer_expiry = mtp + DIRECT_WINDOW
        # SELL_TO is NOT a set mutation -> no bump

    # ---------------- pay (§3.7) ----------------
    def _do_pay(self, info, buyer, mtp, match_output, height):
        name = info["name"]
        row = self.names.get(name)
        if row is None or row.st != ST_OFFERED:
            return
        if row.buyer != buyer:
            return                       # directed exclusivity
        if not (mtp < row.offer_expiry):
            return
        if not match_output(row.seller, row.seller_type, row.price):
            return
        seller = row.seller
        row.owner = buyer
        row.owner_type = 0
        row.st = ST_OWNED
        row._reset_market()
        self._bump(seller, height)
        self._bump(buyer, height)

    # ---------------- trade (§3.10) ----------------
    def _do_trade(self, info, inputs, resolve, height):
        idxA, idxB = info["idxA"], info["idxB"]
        nameA, nameB = info["nameA"], info["nameB"]
        if idxA == idxB:
            return
        a = resolve(idxA)
        b = resolve(idxB)
        if a is None or b is None:
            return
        if nameA == nameB:
            return
        ra = self.names.get(nameA)
        rb = self.names.get(nameB)
        if ra is None or rb is None:
            return
        if ra.owner != a[0] or ra.st != ST_OWNED:
            return                       # not owned unlocked at confirm
        if rb.owner != b[0] or rb.st != ST_OWNED:
            return
        # atomic swap: nameA -> idxB, nameB -> idxA
        ra.owner = b[0]
        ra.owner_type = 0
        rb.owner = a[0]
        rb.owner_type = 0
        self._bump(a[0], height)
        self._bump(b[0], height)


# ---------------- module-level integer helpers ----------------
def lease_days(burn, rate):
    """T = floor(burn * LEASE_QUANTUM / (rate * BILLING_UNIT)), 128-bit numerator."""
    num = burn * LEASE_QUANTUM           # >= 128-bit; Python exact
    den = rate * BILLING_UNIT
    if den == 0:
        return 0
    return num // den


def water_fill(burn, rate, now, expiries, names):
    """§3.5 water-fill. Returns {name: add_days} or None if T==0.
    `names` parallel to `expiries`, already ascending-lex."""
    T = lease_days(burn, rate)
    if T == 0:
        return None
    headroom = []
    for e in expiries:
        h = (MAX_LEASE - (e - now)) // BILLING_UNIT
        if h < 0:
            h = 0
        headroom.append(h)
    H_total = sum(headroom)
    alloc = {n: 0 for n in names}
    if T >= H_total:
        for n, h in zip(names, headroom):
            alloc[n] = h                 # every name caps; surplus forfeited
        return alloc
    # find max integer level lam with sum(min(h, lam)) <= T
    lo, hi = 0, max(headroom) if headroom else 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if sum(min(h, mid) for h in headroom) <= T:
            lo = mid
        else:
            hi = mid - 1
    lam = lo
    base = sum(min(h, lam) for h in headroom)
    rem = T - base
    for n, h in zip(names, headroom):
        alloc[n] = min(h, lam)
    # distribute +1 to first `rem` names (ascending-lex) with h > lam
    if rem > 0:
        for n, h in zip(names, headroom):
            if rem == 0:
                break
            if h > lam:
                alloc[n] += 1
                rem -= 1
    return alloc


# ---------------- canonical state digest (SPEC-conformance.md §4) ----------------
def _u32le(x):
    return (x & 0xFFFFFFFF).to_bytes(4, "little")


def _u64le(x):
    return (x & MASK64).to_bytes(8, "little")


def _i64le(x):
    return (x & MASK64).to_bytes(8, "little")        # two's complement LE


def serialize_state(state):
    """Names + commits + muts ONLY. Magic SMv1. No votes/decors/overflow."""
    out = bytearray(b"SMv1")
    # names: sorted ascending by raw name bytes
    names = sorted(state.names.values(), key=lambda r: r.name)
    out += _u32le(len(names))
    for r in names:
        out += bytes([len(r.name)]) + r.name
        out += r.owner + bytes([r.st]) + _i64le(r.lease_expiry)
        out += r.seller + bytes([r.seller_type]) + _u64le(r.price) + _i64le(r.offer_expiry)
        out += r.buyer + _u64le(r.burn_leg) + _u64le(r.pay_leg) + _i64le(r.reserve_expiry)
    # commits: sorted by (commitment, commit_height, tx_index)
    commits = sorted(state.commits,
                     key=lambda c: (c["commitment"], c["commit_height"], c["tx_index"]))
    out += _u32le(len(commits))
    for c in commits:
        out += c["commitment"] + _i64le(c["commit_height"]) + _u32le(c["tx_index"]) + _i64le(c["commit_time"])
    # muts: sorted by owner bytes
    muts = sorted(state.muts.items(), key=lambda kv: kv[0])
    out += _u32le(len(muts))
    for owner, h in muts:
        out += owner + _i64le(h)
    return bytes(out)


def state_digest(state):
    return sha256(serialize_state(state)).hex()


# ---------------- ECMH state digest (§13.2) — incremental twin of state_digest ----
# Per-table Elliptic-Curve Multiset Hash over the SAME per-row field bytes
# serialize_state emits (WITHOUT count prefix / global framing). Order-independent
# and invertible, so a production fold maintains it in O(rows-changed)/block.
import secp256k1 as _secp

_ECMH_REC_TAG = b"ECMHv1"
_TAG_NAME, _TAG_COMMIT, _TAG_MUT = 0x01, 0x02, 0x04


def _name_row_bytes(r):
    return (bytes([len(r.name)]) + r.name
            + r.owner + bytes([r.st]) + _i64le(r.lease_expiry)
            + r.seller + bytes([r.seller_type]) + _u64le(r.price) + _i64le(r.offer_expiry)
            + r.buyer + _u64le(r.burn_leg) + _u64le(r.pay_leg) + _i64le(r.reserve_expiry))


def _commit_row_bytes(c):
    return c["commitment"] + _i64le(c["commit_height"]) + _u32le(c["tx_index"]) + _i64le(c["commit_time"])


def _mut_row_bytes(owner, h):
    return owner + _i64le(h)


def _ecmh_fold(tag, row_bytes):
    return _secp.ecmh_hash(_ECMH_REC_TAG + bytes([tag]) + row_bytes)[0]


def state_ecmh(state):
    """Three per-table ECMH sub-accumulators combined into one 32-byte digest.
    Mirrors sm_state_ecmh in impls/c/src/ecmh.c: SHA256("ECMHtop1" ‖ an ‖ ac ‖ am)."""
    an = ac = am = _secp.ecmh_identity()
    for r in state.names.values():
        an = _secp.ecmh_add(an, _ecmh_fold(_TAG_NAME, _name_row_bytes(r)))
    for c in state.commits:
        ac = _secp.ecmh_add(ac, _ecmh_fold(_TAG_COMMIT, _commit_row_bytes(c)))
    for owner, h in state.muts.items():
        am = _secp.ecmh_add(am, _ecmh_fold(_TAG_MUT, _mut_row_bytes(owner, h)))
    h = sha256(b"ECMHtop1" + an + ac + am)
    return h.hex()


def oracle_rate(window_blocks):
    """§3.4 fee oracle over the FEE_WINDOW window (participant median).
    window_blocks: list of (coinbase_output_total, block_bytes), one per block,
    representing i in [h-FEE_WINDOW, h-1]. Returns clamped rate."""
    part = []                            # participant list P (fee-bearing blocks)
    for coinbase, block_bytes in window_blocks:
        fees = coinbase - SUBSIDY        # SIGNED subtraction
        if fees < 0:
            fees = 0                     # clamp at 0 (miner under-claim -> non-participant)
        b = block_bytes if block_bytes > 0 else 1   # div-by-zero edge (never zero in practice, SPEC-RATIONALE §2.6)
        v = fees // b                    # floor division
        # membership in P is decided AFTER the floor division: tiny fees that
        # floor to 0 do not participate.
        if v >= 1:
            part.append(v)
    # degrade, don't extrapolate: a small sample is spoofably cheap to own.
    # Boundary INCLUSIVE -- exactly MIN_FEE_SAMPLE participants take the median.
    if len(part) < MIN_FEE_SAMPLE:
        return DUST_FLOOR
    part.sort()
    # LOWER median: odd |P| -> the true middle; even -> the lower of the two
    # middles. Always an observed element, never an average.
    median = part[(len(part) - 1) // 2]
    rate = median * REF_SIZE
    if rate < DUST_FLOOR:
        rate = DUST_FLOOR
    if rate > RATE_CAP:
        rate = RATE_CAP
    return rate


def compute_mtp(timestamps, H):
    """§5 MTP: median of timestamps[H-11 .. H-1]; short window k=min(11,H);
    sort and select index k//2 (upper-middle for even); MTP(0)=0.
    `timestamps` is the full list indexed by height (timestamps[h])."""
    if H == 0:
        return 0
    k = min(11, H)
    window = sorted(timestamps[H - k:H])
    return window[k // 2]
