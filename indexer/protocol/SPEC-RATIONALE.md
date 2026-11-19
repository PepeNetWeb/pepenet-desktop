# Spec Rationale — Resolved Ambiguities & Interop Risks

A reference appendix to `docs/protocol-spec.md` and `protocol-sm/SPEC-conformance.md`.

For every consensus-load-bearing decision where an implementer could plausibly diverge,
this document records the question (the seam), the resolved answer with a citation (§x =
`docs/protocol-spec.md`, conf §x = `SPEC-conformance.md`), and the rationale or trap.
`impls/c` is the normative reference: where prose alone cannot fix a byte, conf §1
declares the C reference authoritative, and those points are flagged. Every answer below
was confirmed against the reference and independently reproduced by the cross-language
suite (C, Python, TypeScript, Java, Rust, Go, C#).

---

## 1. Commit / claim / mint

**1.1 The §3.2 priority tuple and same-block tie-break — the one real consensus bug.**
Claim priority is `(claim_height, commit_height, commit_tx_index)`; the final tie-break is
the *backing commit's* `tx_index`, never the claim's chain order, so the lower-`tx_index`
commit wins regardless of claim ordering (§3.2; conf §3, vector 42). An earlier
formulation broke an equal-`commit_height` tie by claim order, keeping whichever claim was
*applied first* — a real fork, since two nodes can apply same-block claims in different
orders. The commit's `tx_index` is pinned because it is a fixed, block-canonical property
independent of any later claim. *Trap:* conf §3's summary, read alone, describes the tie by
`commit_height` only and reproduces the bug; §3.2 is normative and pins the full tuple.
*Sub-case (resolved by the reference):* when one author posts two matching commits for one
name, prose does not spell out which the claim binds to, but the normative reference binds the
*earliest* matching commit — the minimum `(commit_height, tx_index)` over all live commitments
equal to the claim's (`impls/c` `claim.c`). It is therefore deterministic, pinned by the
reference rather than by prose; an impl that bound a later matching commit would fork the tie.

**1.2 Displacement requires a still-fresh OWNED mint.** A later same-block claim with a
smaller tuple displaces only if the name is still that owner's fresh `OWNED` mint (row is
`OWNED`, owner still equals the provisional minter) (conf §3). If a same-block
TRANSFER/SELL moved or locked it, the smaller-tuple claim drops. The per-block
displacement scratch resets each block and is never digested.

**1.3 Displaced loser keeps its mutation row.** Mutation heights bump eagerly on every
successful mint and are never un-stamped or pruned (§3.5). Both winner and loser claimed in
the same block, so both rows carry the same height `H` — no observable divergence — but an
impl that bumps only final owners emits a smaller, permanently-divergent `n_muts`.

**1.4 A used commit lingers until the time-based prune.** No rule deletes a commit on
successful use; it lingers until `MTP > commit_time + COMMIT_EXPIRY` (§3.2; §5). The natural
delete-on-use reading forks `n_commits` (and the digest) for the ~20–60-block lingering
window after *every* claim. It cannot double-mint (a minted name stays owned far longer than
the ≤5 h commit life), so the only effect is the digest.

**1.5 COMMIT_EXPIRY is the lone inclusive boundary.** A commit is live while
`MTP ∈ [commit_time, commit_time + COMMIT_EXPIRY]`, pruned only once `MTP` *strictly
exceeds* the upper bound (§3.2; §5). Every other boundary is exclusive (owned iff
`MTP < lease_expiry`). The asymmetry is the classic off-by-one fork surface; §5 calls it out
explicitly so a uniform-exclusive reader does not prune a live commit one tick early.
Pre-block pruning runs before the block's txs, so any commit reaching a CLAIM is live; the
CLAIM additionally enforces `commit_height < claim_height`.

**1.6 `commit_time` is the commit block's MTP.** Not the header timestamp (§3.2; §5),
digested as `i64`. MTP keeps the liveness predicate consistent with the rest of the time
model; a header basis shifts the prune edge by the header-vs-median gap. *Behavioral cliff:*
with `MTP(0) = 0` and realistic later timestamps, a height-0 commit is pruned by height 1 —
"commit at H, claim at H+1" does not always work near genesis.

**1.7 Fresh-name lease baseline.** Baseline `expiry = MTP_now`, giving headroom
`MAX_LEASE / BILLING_UNIT = 365` days, so `lease_expiry = MTP_now + min(T, 365)·BILLING_UNIT`,
capped to never exceed `MTP_now + MAX_LEASE` (§3.3–§3.5). Headroom is day-floored from
current expiry (`hᵢ = ⌊(MAX_LEASE − (expiryᵢ − now)) / BILLING_UNIT⌋`); the day-floor formula
is authoritative over the "never exceeds" phrasing.

**1.8 A COMMIT needs a verified actor, not a matching committer.** A COMMIT must come from a
verified actor to be recorded (§5 loop drops ⊥-actor actions), but the row stores only
`{commitment, commit_height, tx_index, commit_time}` — the carrier identity need not equal
the author bound into the commitment hash (§3.2). This is what lets the commitment-copy
attack record an inert row.

---

## 2. Leases & the fee/rate oracle

**2.1 Water-fill is a single global level (λ-fixpoint).** Raise one uniform level `λ` = the
largest integer with `Σ min(hᵢ, λ) ≤ T`; each name takes `min(hᵢ, λ)`; the remainder
`r = T − Σ min(hᵢ, λ)` goes `+1` day to the first `r` names *with headroom remaining*
(`hᵢ > λ`) in ascending-lex order (§3.5; conf §3). The `T < count` "one day each" paragraph
is *not* a separate regime — it is this algorithm at `λ = 0` in the all-headroom case. A
zero-headroom name is skipped, never counted toward `T`. *Why:* the literal "one day each"
reading diverges where zero-headroom names dominate — 99 capped names, one with 355 days,
`T = 50 < count = 100`: the global fill gives the eligible name 50 days, the literal reading
1. Conf §3 names the global fill canonical and asserts uniqueness; the clarifying paragraph
is descriptive. By λ-maximality `r` is always below the headroom-name count; if `T ≥ Σ hᵢ`
all cap and surplus is forfeited. The exact cap/remainder discretization is pinned by the
reference (`impls/c/src/lease.c`).

**2.2 Fail-closed at `T = 0`; an all-capped RENEW is an inert no-op.** CLAIM/RENEW require
`T ≥ 1` (§5). An all-capped RENEW with `T ≥ 1` applies as a no-op (zero days, no lease
change; RENEW never bumps the mutation height) — drop and no-op are observationally
identical. A single-name CLAIM has `count = 1`, so the `T < count` corner can't arise there.

**2.3 Billing units and monetary constants.** `MAX_LEASE / BILLING_UNIT = 365` exactly
(§3.5). `RATE_CAP = 1 DOGE`, flat reachable subsidy `10_000 DOGE` (§0, §3.4). *Trap:*
koinu-per-DOGE is not stated numerically; supply the Dogecoin standard
`1 DOGE = 100_000_000 koinu` (`RATE_CAP = 100_000_000`, subsidy `1_000_000_000_000` koinu).
Any disagreement forks the rate clamp and fee numerator (oracle path only).

**2.4 The oracle is structurally separate from the fold.** In the abstract machine `rate` is
an injected per-block input (`rate = 28·(1+bounded(4))`); the §3.4 coinbase→rate oracle is a
standalone tested function, exercised by scenario vectors, not the random soak (conf §5).
MTP is likewise supplied per block. A reader who recomputes the oracle inside the soak fold
is working against the model.

**2.5 Fee numerator is signed, clamped to zero before dividing.**
`feesᵢ = max(0, coinbase_output_totalᵢ − subsidyᵢ)` — a *signed* subtraction clamped to zero
*before* `fee_per_byteᵢ = ⌊feesᵢ / block_bytesᵢ⌋` (§3.4; conf §2). An unsigned subtraction of
a miner under-claim wraps to ~`2⁶⁴`, spiking the block and shifting the median a full rank.
Clamping first also makes floor and truncation agree.

**2.6 `block_bytes` excludes the header.** `block_bytesᵢ = Σ len(raw_tx)` over the block's
txs, with the 80-byte header, the tx-count varint, and AuxPoW bytes *excluded*; the coinbase
tx is included (§3.4). The obvious "whole block minus header" reading forks the rate: a
constant ~80-byte delta shifts every `fee_per_byte` and can move the median by a rank.
`block_bytes` is never zero (always ≥ a coinbase tx).

**2.7 The median is a single observed element — the LOWER median of the participant list.**
The window `[h − FEE_WINDOW, h − 1]` is scanned, but the median is taken over the
**participants** only: blocks whose floor-divided `fee_per_byte ≥ 1` (§3.4). Rationale: on a
quiet host chain a majority of blocks carry zero fees, so a whole-window median reads 0 and
the rate collapses to the floor even though every fee-bearing block demonstrably clears at
the host's going feerate; the participant median answers "what do fee-payers pay". The
participant count has no fixed parity, so determinism no longer comes from `FEE_WINDOW`
being odd — it comes from the pinned index rule `sorted_P[⌊(|P|−1)/2⌋]` (odd ⇒ true middle,
even ⇒ the LOWER of the two middles; lower because ties then price rent cheaper — the
conservative direction — and never an average, which would need a rounding rule and could
output a value no block exhibited). Fewer than `MIN_FEE_SAMPLE = 1000` participants ⇒
`DUST_FLOOR` exactly (a small sample is spoofably cheap to own; degrade, don't extrapolate).
The boundary is inclusive and the resulting rate step at 999↔1000 is deliberate: it is
deterministic, cap-bounded, and stateless — hysteresis would need memory the oracle
doesn't have. Scenario vectors 49–51 pin the boundary, both parities, and the degrade.

---

## 3. The names market

**3.1 The output matcher is tx-global, consume-once, lowest-vout.** Process a tx's market
`OP_RETURN`s in vout order; each consumes the *lowest-vout not-yet-consumed* spendable
output whose `(scriptPubKey, value)` equals `(seller, owed)` *exactly*, scanning *all* the
tx's outputs regardless of carrier vout; if none remains, the op drops (§3.5; conf §7, vector
41). *Why:* a tx with `RESERVE(x)` then `SETTLE(x)` to one seller and outputs `vout[0]=19800`,
`vout[1]=5` (RESERVE owes 5, SETTLE owes 19800) pairs correctly only under consume-once
exact-value matching; greedy/at-or-after/summing mis-pairs and drops an op. The match key is
the full `(scriptPubKey, value)` — scriptPubKey reconstructed *per recorded seller type*, so
a P2PKH-template output does not satisfy a P2SH seller.

**3.2 A non-output drop consumes no output.** Preconditions and the carrier-value gate are
checked before the output match; an op dropping for a non-output reason
(already-reserved/short carrier/wrong buyer/expired) consumes nothing — only success
consumes (§3.5, §3.7). Otherwise a failing op removes an output a later op in the same tx
needs, mis-assigning the value-collision case.

**3.3 "Settle unconditionally" still requires the payment output.** "Unconditionally" means
*not conditional on winning the option*, not *not conditional on the output existing*. A
RESERVE with no `pay_leg` output drops; a SETTLE/PAY without its remainder/price output drops
(§3.7, §3.5). The §3.5 rule ("if none remains, that op drops") governs; reading
"unconditionally" as "apply without payment" is the trap.

**3.4 Deposit legs in ≥128-bit; carrier `≥ burn_leg`, spendable legs exact.**
`burn_leg = pay_leg = max(DUST_FLOOR, ⌊price·RESERVE_*_BPS / 10000⌋)` in ≥128 bits (§3.7;
conf §2). The RESERVE carrier value must be `≥ burn_leg` (over-funding wins, surplus
uncredited); pay-leg/remainder/PAY-price spendable outputs match by *exact* value. A 64-bit
`price·bps` near `2⁶⁴` wraps to a near-zero deposit (ownership fork); mixing the two
comparators (`≥` vs `==`) also forks.

**3.5 SELL window.** `window = 0` defaults to `RESERVE_WINDOW`; a nonzero window in
`[1, RESERVE_WINDOW)` is out of range → ignored; `≥ RESERVE_WINDOW` is bounded by the
*add-form* `MTP_now + window + REORG_BUFFER ≤ lease_expiry`, never the subtraction
`(lease_expiry − MTP_now) − REORG_BUFFER` (which underflows) (§3.7; §5).

**3.6 SELL_TO price floor is `DUST_FLOOR`, not SELL's `3·DUST_FLOOR`** (§3.7) — the directed
sale has no deposit split, so no remainder-underflow floor is needed.

**3.7 RESERVE only against a LISTED row.** A second reserve on a now-`RESERVED` row drops
without overwriting; an OFFERED name is not reservable (§3.7; conf §7). First-in-chain-order
wins via the forward pass; because two RESERVE carriers can share `(height, tx_index)`, the
effective key extends to `vout` (process in vout order, first to find `LISTED` wins).
`reserve_expiry = min(now + RESERVE_WINDOW, offer_expiry)`, keeping
`reserve_expiry ≤ offer_expiry ≤ lease_expiry − REORG_BUFFER`. The abstract machine models
the option-lock and settle-drop, not the off-chain deposit burn of a losing reserve. A seller
self-RESERVE/self-SETTLE is permitted (a "no self-reserve" guard dies to puppet addresses).

**3.8 PAY pays the seller; directed buyer is a bare hash160.** A honored PAY conveys the name
and pays the seller; `buyer` is stored as a 20-byte hash160 and PAY checks `actor.id == buyer`
directly (no reconstruction). The SETTLE remainder and directed legs are exact (§3.7).

---

## 4. Multi-identity & TRADE

**4.1 TRADE settles on its two named parties, ignoring the acting identity.** TRADE is
dispatched before the actor check and settles on `vin[idxA]`/`vin[idxB]` alone; a TRADE in a
tx whose acting identity is ⊥ still settles if both named parties are valid and each signs
`SIGHASH_ALL` (§3.9, §5). A parties-only and an actor-gated reading diverge when `vin[0]` is
⊥; the spec pins parties-only because a TRADE is an atomic two-party swap with no
acting-identity role.

**4.2 TRADE anti-rug: live-ownership re-check, fail-closed both ways.** TRADE re-checks
`owner == party and st == OWNED` at its forward-pass position. A same-block TRANSFER of a
pledged name *before* the TRADE drops it (re-check fails); *after* also fails (already moved)
— no one-sided outcome (§5). TRADE drops the whole op on `idxA == idxB`, `nameA == nameB`,
out-of-range index, not-owned party, or locked name.

**4.3 AS re-points attribution only; the ⊥-actor rule.** An AS marker
re-points the acting identity for subsequent carriers; it never affects burn-accounting (each
burn-bearing action's cost is its own carrier's `OP_RETURN` value) (§3.9). A malformed/OOB AS
makes the segment actor ⊥ until the next valid AS or tx end; the §5 loop then drops any
non-TRADE action under ⊥. An AS below `ACTIVATION_HEIGHT` is gated (dropped) before it can
re-point.

---

## 5. Selective bitmaps (RENEW / TRANSFER / RELEASE)

**5.1 Bit order is LSB-first:** bit `i` selects the `i`-th name of the lex-ordered owned set,
`(flags[i >> 3] >> (i & 7)) & 1` (conf §3). *Trap:* the main spec alone does not pin the
endianness (the LSB rule lives in conf §3), a 50/50 choice selecting entirely different names
(`0x01` selects the first owned name LSB-first, the eighth MSB-first). Owned-set ordering is
unsigned-bytewise over raw name bytes.

**5.2 Out-of-bounds and under-length bits are absent (zero), never fatal.** Any bit at index
`≥ K` (owned-set size) is ignored regardless of value, and any bit past the supplied
flag-byte length is absent — never a decode or fold failure (§3.5). The bit test must be
bounded by *both* `K` and the flag length: during reorg replay an owner can hold more names
than a previously-folded bitmap's byte length covers, and an unbounded `flags[i >> 3]` read
runs past the array (a crash) instead of reading zero.

**5.3 Locked names: RELEASE/TRANSFER skip per-name; RENEW renews them.** A locked
(LISTED/OFFERED) name selected by a destructive bitmap is *skipped, not fatal* — the op acts
on the unlocked subset (§3.6, §3.7). RENEW has no such exception (§3.5). Locked names keep
their owned-set position (a listing is not a mutation) and still occupy a bit index.

**5.4 The anchor guard and which ops bump the mutation height.** Guard:
`last_set_mutation_height ≤ anchor ≤ confirm` (anchor = uint40 LE). Bumped by CLAIM, TRANSFER,
RELEASE, SETTLE, PAY, TRADE, and *lapse* — *for either party*, so SETTLE/PAY/TRADE bump
*both* and TRANSFER bumps *both* sender and recipient (§3.5). RENEW/SELL/SELL_TO/RESERVE do
*not* bump. The height is a monotonic high-water mark, never decreased, never pruned (even for
an emptied owner). *Traps:* an op touching no name leaves the anchor untouched; bumping on
RENEW, pruning an empty owner's row, or missing the TRANSFER *recipient* bump (which flows
from "either party" though the explicit examples name only SETTLE/PAY/TRADE) all fork
`n_muts`.

**5.5 A pre-block lapse stamps the mutation height to the connecting height `H`** (§3.5; §5;
conf §3); an offer-close or reserve-revert leaves the name in the seller's set and does *not*
bump. This is consensus-critical: a selective RENEW/RELEASE/TRANSFER anchored *before* a lapse
but confirming at/after it must be *rejected* (resend) rather than acting on a now-stale lex
ordering — a wrong-name RELEASE/TRANSFER is irreversible asset loss. Stamping the owner to `H`
makes the stale-anchor op fail the guard. An impl that never bumped on a lapse would defeat
this protection. Because mutation heights are digested, the stamp is load-bearing across any
lapse.

**5.6 Anchor-guard default for an owner with no mutation row** trivially satisfies the lower
arm (the `anchor ≤ confirm` arm does the real work); unreachable in practice since any
name-holder always has a row.

---

## 6. Attribution (§4 / conf §13)

**6.1 Off-curve P2PKH → status 1 (on-curve-drop).** The status byte is the *earliest failing
stage*, with on-curve a distinct injected stage for a well-encoded key. An off-curve but
canonically-encoded P2PKH key has already classified, carries the real sighash and `hash160`,
and fails at the on-curve stage as status 1, not status 0 (§4 step 4; conf §13). *Why a real
fork:* §4 calls it "non-canonical → drop" (sounds like status 0, all-zero), while conf §13's
status-1 parenthetical names only *redeemScript* keys — the two readings emit different status
bytes and zeroed-vs-real sighash/identity. The §13 ladder keys on the earliest failing stage
with on-curve as a real stage for both shapes. The single most likely attribution fork; the
spec was hardened to state the P2PKH on-curve-drop status.

**6.2 Status-≥1 rows carry the real sighash and identity; only status 0 is all-zero**
(conf §13). Sighash and identity are formed the moment classification succeeds, *before* the
on-curve gate — so a *dropped* attribution still emits a non-zero sighash. Zeroing status-1/2
rows forks.

**6.3 R/S are 32-byte big-endian of the integer value.** Strip a single leading `0x00` sign
byte, then left-pad the big-endian *value* to exactly 32 bytes for `r32`/`s32` (conf §13). The
oracle is a pure hash of its inputs, so raw DER bytes, keeping the sign byte, right-padding, or
little-endian each yields a different verdict and digest. The 32-byte BE value is the only
width-correct, sign-clean reading.

**6.4 Legacy SIGHASH_ALL preimage = standard Dogecoin serialization, 4-byte LE hashtype.**
Double-SHA-256 of `int32 LE version ‖ varint(n_in) ‖` per-input
`prevhash[32] ‖ u32 LE index ‖ varint(scriptLen) ‖ script ‖ u32 LE sequence ‖`
`varint(n_out) ‖` per-output `i64 LE value ‖ varint(spkLen) ‖ scriptPubKey ‖ u32 LE locktime`,
the signed input carrying its `scriptCode` and all others an empty script, then the hashtype
as a *4-byte little-endian `int32`* (`0x01000000`) (§4 step 4; conf §13). *Trap:* only the
4-byte LE hashtype is pinned in prose; the surrounding layout defers to host consensus, so two
impls must independently land on identical Dogecoin legacy bytes. The 1-vs-4-byte hashtype
suffix is the most common preimage mistake — pinned to 4 bytes as consensus-critical.

**6.5 FindAndDelete and the multisig template scan.** Implement Bitcoin Core
`CScript::FindAndDelete` (boundary-aligned `GetOp` removal) on the scriptCode for each checked
signature's push — do not assert it away (§4 step 4; conf §13). One sighash per input `k`,
reused for all in-order `verify()` calls (all sigs share hashtype `0x01`). For CHECKMULTISIG:
the dummy must be exactly `OP_0`; the `m` sigs match a subsequence of the `n` keys in order
(advance the key cursor on a miss); fewer than `m` verified → status 2. `on_curve` is checked
on *all `n`* redeemScript keys up front, so an off-curve key anywhere → status 1 regardless of
whether it is used. FindAndDelete is *structurally inert* on the rigid compressed-key template
(a 33-byte `0x21` key push never aligns with a `0x47`/`0x48` sig push) but is implemented for
real anyway.

**6.6 The 0xFF parse-failure sentinel.** A tx that fails to *parse* contributes a single
`0xFF` to the digest stream (a structural raw-tx deserialization failure; legacy-only parse),
whereas a malformed scriptSig within a parseable tx is a per-input status-0 drop (conf §13).

**6.7 Off-template classify edges.** A 2-element `OP_0 [X]` scriptSig drops as status 0 whether
read as a failed P2PKH or a failed (m=0) multisig — a DER sig and a multisig template are
mutually exclusive shapes, so branch order is irrelevant. A redeemScript key failing canonical
encoding (bad prefix/length, `X ≥ p`) is status 0 (all-zero), distinct from a well-encoded
off-curve key (status 1). Oracles pinned verbatim:
`on_curve(pk) = SHA256(0x4F ‖ pk)[0] != 0x00`,
`verify(h,r,s,pk) = SHA256(0x56 ‖ h ‖ r ‖ s ‖ pk)[0] ≥ 0x20` (conf §13).

---

## 7. Canonical state digest (conf §4)

*(§7.4 and §7.7 removed in the names-only simplification.)*

**7.1 Fixed-width names rows; market fields always emitted and physically reset.** Every names
row is fixed-width: the market block (`seller`, `seller_type`, `price`, `offer_expiry`,
`buyer`, `burn_leg`, `pay_leg`, `reserve_expiry`) is *always* emitted, zeroed when inactive,
and physically reset on the transition leaving a market state (conf §4). The §5 prose ("for a
listed name") invites a variable-width reading, but conf §4 is an unconditional field list; a
variable-width row, or a non-zero sentinel/stale inactive field, forks the SHA-256 though
`n_names` agrees. Resetting on the transition (not just at serialize) keeps the reserve-revert
case consistent.

**7.2 The single `buyer[20]` slot holds both reserver and directed buyer:** the reserver
hash160 when `st = RESERVED`, the directed buyer when `st = OFFERED`, zero otherwise (conf §4;
§5). The digest groups `buyer ‖ burn_leg ‖ pay_leg ‖ reserve_expiry` — the reservation fields —
so `buyer` is the canonical single counterparty slot. Keeping the reserver in a non-digested
side table (zeroing `buyer` for RESERVED) forks every reserved listing.

**7.3 `seller_type` is digested (`P2PKH=0`, `P2SH=1`); `owner_type` is not** (conf §3, §4);
`st` is `OWNED=0/LISTED=1/OFFERED=2/RESERVED=3`. *Trap:* the `seller_type` byte is load-bearing
twice — it forks the digest on every market row and selects the payment-output template (3.1) —
yet it is pinned only in the conformance doc. Digesting `owner_type`, or a different
`seller_type` encoding, forks every market row.

**7.5 Mutation rows are never pruned** — a monotonic high-water mark, sorted by owner bytes,
`owner[20] ‖ i64 height`, retained even for an emptied owner (§3.5, §3.8, conf §4). §3.8's
"only the live set" suggests pruning, which forks `n_muts` after any set-emptying lapse — the
spec gives no pruning rule.

**7.6 Commits sorted by a total order** `(commitment, commit_height, tx_index)`, not commitment
bytes alone (conf §4). The commitment-copy attack deliberately creates identical-commitment
rows; stopping at the primary key (or using insertion order) forks under that case.

**7.8 Signedness.** `lease_expiry`/`offer_expiry`/`reserve_expiry`/`commit_height`/
`commit_time`/mutation heights are `i64`; `price`/`burn_leg`/`pay_leg` are `u64` (conf §4). The i64/u64 distinction is byte-identical for
the non-negative values these fields hold and would only differ above `2⁶³` (unreachable).

---

## 8. Decoder robustness / fail-closed rules

**8.1 Single-minimal-push carrier gate.** A carrier is exactly `OP_RETURN <push>`, one
*minimal* push of `P ≤ 80` bytes; multiple pushes, a non-minimal push, or a trailing opcode →
*ignore* (§1). An empty push (`OP_0` / `P = 0`) can't carry the 4-byte prefix → ignore. *Scope:* this is a script-layer gate; the abstract machine receives
already-extracted payloads, so a full indexer must apply it at the script layer — conflating
payload with scriptPubKey bytes treats multi-push `OP_RETURN`s as carriers and forks.

**8.2 Name charset and structure are reject-not-fold.** `[a-z0-9-]` — a DNS label, lowercased,
with RFC-1123 positioning: no leading `-`, no trailing `-`, and no `--` at positions 3-4
(`name[2]=='-' && name[3]=='-'`, which kills `xn--` and every IDNA ACE label) (re-pinned
2026-07-08, supersedes the 2026-07-07 charset-only rule; scenario 52), length 1–32; any
non-name byte (incl. uppercase) or a structural violation (`-a`, `a-`, `xn--…`) → whole action
IGNORE (§3.1; conf §9). §3.1's "canonical key is the lowercase form" could be misread as
accept-and-fold; that mints `alice` for `CLAIM "Alice"` where the strict reading IGNOREs — a
namespace fork. The charset is strict lowercase, so the clause is a no-op; every consensus-valid
name is thereby a valid, safe domain label.

**8.4 Action length bands are body lengths.** Conf §9 states bands as *body* lengths `bl`
(= total − 4); §3.5's RENEW table (`4 / 9 / 10..80`) states *whole-OP_RETURN* lengths.
Consistent once the 4-byte prefix is accounted for. Decode on `bl`: RENEW
`{0, 5} ∪ [6, 76]` (`1..4` invalid); TRANSFER `{20} ∪ [26, 76]` (no anchored-all mode); TRADE
`bl ≥ 5` (upper bound from name validation) (§3.5; conf §9). §3.5 warns that reading its
whole-payload numbers as body lengths
shifts the band and forks the decoder.

**8.5 Value gates are at the fold, not the decoder.** Per-op: CLAIM/RENEW governed by the
`T ≥ 1` water-fill gate (no separate precheck); RESERVE `value ≥ burn_leg` (§5; conf §9).

---

## 9. Pre-block transitions, MTP & reorg confluence

**9.1 Transitions applied by type, not by boundary value.** When one MTP advance crosses
several boundaries, apply by type in the order `reserve_expiry`, `offer_expiry`, `lease_expiry`,
each idempotent, then prune expired commits before the block's txs (§5). Across distinct names
the order is irrelevant; type-order matters within one name's chain because the values can tie
(`reserve_expiry == offer_expiry`) — a value-sorted impl forks on that tie. The COMMIT_EXPIRY
prune must precede the txs so a CLAIM never sees an expired commit.

**9.2 MTP window, even-window upper-middle, genesis.** `MTP(H)` = median of the up-to-11
timestamps strictly before `H` (`k = min(11, H)`): sort and select index `⌊k/2⌋`, the *upper*-
middle for even `k` (not an average); `MTP(0) = 0` (§5; conf §2). The upper-middle rule is
pinned in conf §2 but not the main spec, so a main-spec-only reader could average and fork a
near-genesis boundary call; the machine runs from block 0, so this is reachable. MTP is
sorted-by-value, never middle-by-height.

**9.3 Reorg confluence.** The fold is a pure, reorg-safe function of the block sequence: replay,
resume, clear-and-rebuild, and fork-and-return converge for the same canonical chain. A clean
reset before replay makes replay trivially correct. Reorg replay is exactly where an owner can
hold more names than a previously-folded bitmap covers — which is what makes the under-length
absent-bits-are-zero rule (5.2) consensus-critical.

---

## 10. Implementer hazards (language-specific interop traps)

Not spec ambiguities — places a language default silently diverges from a pinned width, order,
or rounding rule.

**10.1 ≥128-bit overflow on value paths.** Compute the deposit legs (`price·bps`, `price` near
`2⁶⁴`) and the lease numerator (`burn·LEASE_QUANTUM`) in ≥128 bits — a 64-bit multiply wraps a
fat price to a near-zero deposit (ownership fork) or a wrong day count (lease fork).
Languages without native 128-bit hand-roll these (Go `math/bits`; C# `UInt128`/`Int128`).

**10.2 Go `bits.Div64` panic floor — the `hi ≥ den` sentinel is mandatory.** Conf §2's no-panic
argument rests on the *generator's* `rate ≥ 28`, but the *production* floor is `DUST_FLOOR = 1`
koinu. At `rate = 1` (`den = 86_400`) with a large burn, an unguarded `bits.Div64` panics in Go
(UB in C). Take the "huge" branch when `hi ≥ den` (encoding `T ≥ 2⁶⁴`, later clamped by the
water-fill). Full-128-bit `T` (C, C#, Rust, Python) sidesteps it, but the `hi ≥ den` sentinel is
mandatory for any fixed-width path. Go-specific panic, but the floor (`DUST_FLOOR = 1`, not 28)
is a real consensus fact.

**10.3 Signed clamp before floor-division.** Division rounds differently for negatives (Python
`//` floors toward −∞; C/C#/Go truncate toward zero). Clamp `fees = max(0, coinbase − subsidy)`
to zero *before* dividing so the dividend is non-negative and floor == truncation; an unsigned
subtraction of an under-claim wraps to ~`2⁶⁴`.

**10.4 No floating point on any value path.** A `double` is exact only to `2⁵³ − 1`; one `/` or
`Math.*` on a koinu/price/lease value near `2⁵³`–`2⁶⁴` (e.g. `price·50/10000`) corrupts
the value bytes and forks. Carry every value-bearing field in an exact integer type; the
conformance `VAL_BND` probe (`2⁵³−1, 2⁵³, 2⁵³+1, 2⁵⁴+1`) catches this.

**10.5 Deterministic ordering — explicit bytewise sorts, never hash/dict iteration.** Sort every
digested sequence by its pinned key with an explicit *unsigned bytewise* comparator: names by
raw bytes; commits by `(commitment, height, tx_index)`; mutations by owner. Hash-map/dict/set
iteration order (randomized in Go) must never feed the digest, and a locale-sensitive string
compare must never order keys. The commitment-copy attack makes the commits secondary key
load-bearing.

**10.6 Shifts, fixed-width IO, crash-safety.** Right-shift is arithmetic (sign-extending) on
signed types in C/C#/Java; the bitmap read and SplitMix64 shifts must use unsigned/non-negative
values. Use endianness-explicit IO (`BinaryPrimitives.*LittleEndian`, not host-dependent
`BitConverter`). Length-guard every attacker-reachable index/slice in the decoder
and attribution cursor so a malformed payload returns IGNORE rather than throwing — the decoder
is fail-closed and crash-safe by construction. Narrow integer types are fine only for genuinely
≤32-bit fields (`vout`, `tx_index`, indices, name lengths, bit indices); everything
value- or time-bearing is ≥64-bit.

---

## 11. Pinned-by-reference surfaces (not derivable from prose alone)

A few surfaces are pinned to the normative reference rather than derivable prose, so a
from-prose impl cannot reproduce their frozen seed-goldens. These are not fold-semantics
ambiguities — the fold, strict decoder, attribution byte-logic, and digest *layout* are fully
derivable — but they scope cross-implementation comparison:

- **Generator draw order (§5).** The per-op draw sequence, the `hash_tx`/`input_digest`
  serialization, and the fuzz/reorg PRNG schedules are defined by the reference generator; an
  independent generator produces internally-consistent but non-comparable digests for the
  `random`/`fuzz`/`scenario`/`property`/`reorg`/`attrib` seed modes (conf §5, §6). By design.
- **The legacy-sighash raw-tx byte layout (6.4)** and **the water-fill cap/remainder
  discretization (2.1)** are pinned to the reference where prose names only the components or
  asserts uniqueness.
- **secp256k1 curve constants.** The injected `on_curve`/`verify` *oracle* (the `attrib` /
  `attrib-scenario` byte-logic tier) is pinned verbatim. The **real curve** now ships too, as
  `sm attrib-curve` (§13.1 of conf): each impl carries a self-rolled, zero-dependency secp256k1, and
  the `SECP_P = 2²⁵⁶ − 2³² − 977` / `SECP_N` / `SECP_N_HALF` / `G` constants are KAT-pinned and asserted
  in every selftest (the `…FFFFFC2F` top-word gotcha — *not* `2²⁵⁶ − 977` — bit an earlier attempt, so
  it is a checked constant, not a transcription). Unlike the seed-soak surfaces above, the curve-vector
  set is **cross-language comparable**: RFC-6979 makes signing deterministic, so all seven impls print
  byte-identical `attrib-curve` output (frozen `combined` / `combined_e2e`). The vector set — not prose
  — is the normative artifact that makes "the curve is real" checkable; the priv=1⇒G / priv=2⇒2G
  tiny-key KATs are an *external* anchor (universal secp256k1 truths, independent of this suite).

---

*Where the spec was hardened in response to these findings — the §3.2 claim tie-break, the
off-curve-P2PKH status, the lapse mutation-height stamp, the
LSB-first bitmap, and the fixed-width digest layout — the resolved answers above reflect the
current `docs/protocol-spec.md` and `SPEC-conformance.md`.*
