# protocol-sm — cross-language conformance contract


This pins the parts of the reference state machine that **silently differ between
languages**. The fold *semantics* live in [`docs/protocol-spec.md`](docs/protocol-spec.md)
(§3, §5); this document pins the PRNG, the integer-width rules, the canonical
digests, and the generator draw-order so that **every implementation, fed the same
`(seed, count)`, prints the same `input_digest` + `state_digest`.** That agreement
is the entire conformance proof — there are no shipped corpus files.

When this prose is ambiguous, **`impls/c` is normative**. An implementation
conforms iff `./run-conformance.sh` shows it passing over the matrix. A
consolidated record of every consensus-load-bearing ambiguity and how the spec
resolves it lives in [`SPEC-RATIONALE.md`](SPEC-RATIONALE.md).

---

## Two conformance tiers

`run-conformance.sh` checks conformance at two distinct tiers, because two distinct
questions are being asked.

**Tier 1 — the seed soak (gen.c-pinned): `c` only.**
The seed soak regenerates the *identical* action stream from a `(seed, count)` via the draw-for-draw
generator pinned to `impls/c/src/gen.c` (§5), folds it, and checks `input_digest` + `state_digest`
across the whole matrix (`random` / `fuzz` / `bfuzz` / `properties` / `reorg` / `reorgfuzz` / `meta` /
`scenario` / `attrib`). This is a **byte-for-byte** check — but it only works *because* the impl
deliberately replicates the same generator and serialization, so it cannot certify an implementation
built independently of `gen.c`. Tier 1 therefore *self-regresses* the C reference against its frozen
goldens (scenario combined `301ce369…`, attrib-scenario `9fb14077…`), the
`properties`/`reorg`/`reorgfuzz`/`meta` violation==0 invariants, and the generator/decode coverage gate.
The cross-language guarantee lives **entirely** in Tier 2.

**Tier 2 — independent reference impls: `c · py · java · ts · rust · go · cs`.** `impls/py`, `impls/java`,
`impls/ts`, `impls/rust`, `impls/go`, and `impls/csharp` are each implemented independently *from the
prose alone* (`docs/protocol-spec.md` + this doc), without reference to `gen.c`. By construction they use
their **own** generators and so **cannot** reproduce the Tier-1 seed-goldens (this is by design, stated
in each impl's README). Independent implementations can only agree on what the *prose* pins, so Tier 2
cross-validates exactly that:

- **The consensus-fork differential vectors** — `TV-1, TV-5b, TV-6, TV-7, TV-8` (the fold-layer
  cases catalogued in [`SPEC-RATIONALE.md`](SPEC-RATIONALE.md)) **plus `M9`** (and `H8`/`H3` in py/ts/rust/go/cs) — run via
  `impls/c/sm forkvectors`, `python3 impls/py/sm.py forkvectors`, `node impls/ts/sm.ts forkvectors`,
  `impls/rust/target/release/sm forkvectors`, `impls/go/sm forkvectors`,
  `dotnet impls/csharp/bin/Release/*/sm.dll forkvectors`, and the `TV`/`M9` block of
  `java …/Sm.java behav`. Each impl **independently produces the spec-mandated outcome** for every
  vector. Seven *independent* impls agreeing on every fork vector is a stronger consensus-correctness
  signal than N impls that share one generator, precisely because a shared generator can hide a shared
  bug (as the random soak did for the TV-7 lapse bug — the generator-sharing ports agreed *with each
  other* and were *all* wrong).
- **The canonical state-digest layout (§4)** is fully prose-pinned, so a fixed hand-built scenario
  (`node impls/ts/sm.ts digest`) is structurally comparable field-by-field against the reference.
- **Each impl's own hand-authored selftest battery** runs as a Tier-2 gate (`<impl> selftest`, all
  seven): RIPEMD/SHA/digest KATs, per-opcode fold cases, and the attribution battery including the
  **A7 off-curve-P2PKH** regression. These are generator-independent (they assert on fixed hand-built
  inputs), so they run regardless of soak parity; each self-aborts (non-zero exit) on any failed check,
  which is what the runner keys on. Counts are per-impl, not cross-matched (c 130, ts 178, rust 86, py 80,
  cs 69, go all-pass, java 5 — java's bulk validation lives in its 62-vector `behav`).
- **The §8/§9/§10/§11 invariant batteries on every independent fold (all seven).** The §8 property
  battery (`violations==0`), the §10 reorg/reorgfuzz confluence checks (`failures==0`), the §11 meta
  inert-action check (`failures==0`), and the §9 decoder fuzz-survival check (`parser_crashes==0`) are
  generator-independent: every correct fold must preserve them on *any* action stream, so no digest match
  is expected (each impl drives its OWN generator) — only the count==0 is load-bearing. The `c` reference
  asserts these in the Tier-1 soak; **each of the six other independent folds (`py·ts·java·rust·go·cs`)
  now re-asserts the same invariants on its OWN generated chain across seeds `1/42/1000/31337`**, so all
  *seven* unrelated folds certify the protocol invariants over seven unrelated streams (6 impls × 4 seeds
  × 5 modes = 120 reference-tier checks). Each impl self-aborts (non-zero exit) on any nonzero count,
  which is what the runner keys on. This broad run is what first surfaced — and the C normative `bit_set`
  bound is what resolved — the `impls/py` under-length-bitmap divergence (a selective RENEW/TRANSFER/
  RELEASE bitmap shorter than the owner's owned-set, reachable only under divergent reorg replay order,
  indexed past the flag array and crashed fail-loud instead of treating beyond-bitmap bits as absent; the
  other five folds already bounded correctly per `bitmap.c` `byte < flags_len`).

**M9 (the value of Tier 2).** TRADE is attributed to its named parties `vin[idxA]`/`vin[idxB]`, not
the transaction's acting identity — so a TRADE whose `vin[0]` is ⊥ still settles (`docs/protocol-spec.md`
§3.9/§5). Two independent implementations had each read the prose the opposite way — gating TRADE behind
the acting-identity check and dropping the trade — while `impls/c` did not. Two independent readings
diverging the same way is precisely what flags prose as under-specified; the spec was hardened to pin
parties-only, and the implementations were corrected. The `M9` fork vector now guards this in every
reference impl; implementations written from the already-hardened prose reproduce the parties-only
outcome directly.

---

## 1. PRNG — SplitMix64 (pinned)

64-bit state, integer-only, **no floating point anywhere**. All arithmetic is
wrapping `uint64` (Go `uint64` / Rust `wrapping_*` / C `uint64_t` / C# `unchecked ulong`
/ Python `& MASK64` / JS `BigInt(...) & MASK64`).

```
state := seed                                   # the seed IS the state (no warm-up)
next():
    state = (state + 0x9E3779B97F4A7C15) mod 2^64
    z = state
    z = ((z xor (z >> 30)) * 0xBF58476D1CE4E5B9) mod 2^64
    z = ((z xor (z >> 27)) * 0x94D049BB133111EB) mod 2^64
    return z xor (z >> 31)
bounded(n) := next() mod n      # n>0; n==0 → 0.  PINNED as a plain modulo (identity, not low-bias).
```

Conformance check: `next()` from `seed=0` returns `0xE220A8397B1DCDAF` first.

---

## 2. Integer widths (the real edge cases)

koinu / price are `uint64`. Two computations need **≥128-bit** and are
the load-bearing anti-fork rules:

- **Reserve deposit leg** `= max(DUST_FLOOR, ⌊price · bps / 10000⌋)` — `price·bps`
  overflows `int64` (price is attacker-typed, free to reach ~2⁶⁴). Compute `price·bps`
  in 128-bit, floor-divide, then clamp.
- **Lease days** `T = ⌊burn · LEASE_QUANTUM / (rate · BILLING_UNIT)⌋` — `burn·LEASE_QUANTUM`
  overflows 64-bit. Compute the numerator in 128-bit. `T` may exceed 64-bit; the
  water-fill clamps it to the total headroom (never storing the wide value), so
  `if T ≥ Σheadroom: every name caps, surplus forfeited` short-circuits before any
  64-bit store.

Per-language 128-bit: Python/JS native (`int`/`BigInt`), Rust `u128`/`i128`, Go
`math/bits.Mul64`+`Div64` (the `price·bps` and `burn·LEASE_QUANTUM` numerators) plus a
16-byte two's-complement `I128{hi,lo uint64}` helper (the §8
Σ lease/price/legs), C `unsigned __int128`, C# `UInt128`/`Int128`. **Go (no native 128-bit) MUST guard
`bits.Div64`.** `Div64(hi,lo,den)` *panics* whenever the quotient would overflow 64 bits — i.e.
exactly when `hi ≥ den` — so an impl MUST test `hi ≥ den` **before** calling it and take that as
the "`T ≥ 2⁶⁴`" sentinel that feeds the water-fill clamp (the headroom Σ is far under `2⁶⁴`, so any
such `T` caps every name regardless). ⚠️ Do **not** justify skipping that guard by `rate ≥ 28 ⇒
den ≥ LEASE_QUANTUM ⇒ hi < den`: `rate ≥ 28` is a property of the **generator only** (§5). The
**production** rate floor is `DUST_FLOOR = 1` koinu (§3.4 clamps the oracle to `[DUST_FLOOR,
RATE_CAP]`), so `den = rate·BILLING_UNIT` can be as low as `BILLING_UNIT = 86_400`, under which a
fat attacker burn drives `hi ≥ den` and an unguarded `Div64` panics on a consensus-reachable input.
(C/C#/Rust/Python sidestep this by computing `T = ⌊burn·LEASE_QUANTUM / (rate·BILLING_UNIT)⌋`
entirely in ≥128-bit and clamping the wide `T` to the headroom Σ — the `hi ≥ den` sentinel is the
Go-only spelling of that same clamp.)

**Per-language value representation (pinned — this is where a 64-bit-lossy type silently
forks).** koinu / price / lease numbers are **exact 64-bit integers end-to-end**;
no implementation may let one transit a type that rounds. The trap is JavaScript: a `number`
is an IEEE-754 double, exact only to `2⁵³−1` (`Number.MAX_SAFE_INTEGER`), so a price near `2⁶⁴`
— or even an *intermediate* like `price·50` for a price above `2⁵³/50` — silently rounds. The
TS/JS port therefore carries **`BigInt` from the first byte of parse** (`rdLE → bigint`) through
the fold to serialization (`le(v: bigint, …)`); `number` is permitted **only** for genuinely
≤32-bit quantities (vout, txindex, array indices, counts, flag bytes),
which a double holds exactly. Because every value-bearing field is `BigInt`, JS *throws* on a
`BigInt + number` mix — a stray `number` crashes rather than silently corrupting, so there is no
`number → BigInt` boundary at which a value could have already rounded. Go (no native 128-bit)
keeps its 64-bit values in `uint64`/`int64`, which are exact, and reaches for the wide helpers
above only where the math exceeds 64 bits. The `bfuzz` `VAL_BND` table (§9) probes this directly:
it includes `2⁵³−1, 2⁵³, 2⁵³+1, 2⁵⁴+1` (the double cliff), so any `number`-path impl produces
different value bytes and diverges on `input_digest` there.

The **fee oracle** (`sm_oracle_rate`, §3.4) computes per-block
`fee_per_byte = ⌊max(0, coinbase − subsidy)/bytes⌋` with the subtraction **signed**
(a miner may under-claim; an unsigned wrap would wrongly enroll the block as a huge
participant), floor-divides, then keeps only the **participants** — blocks whose
floored value is ≥ 1. Fewer than `MIN_FEE_SAMPLE = 1000` participants ⇒ the rate is
`DUST_FLOOR` exactly (boundary inclusive: exactly 1000 takes the median). Otherwise it
takes the **lower median** — the single element at 0-indexed `⌊(|P|−1)/2⌋` of the sorted
participant list (odd |P| ⇒ the true middle; even |P| ⇒ the lower of the two middles;
never an average) — scales by `REF_SIZE`, clamps to `[DUST_FLOOR, RATE_CAP]`. **MTP** = the middle element (`index = k//2`) of the
sorted timestamps of the ≤11 blocks before `H`.

---

## 3. Reference-pinned fold decisions

Beyond `protocol-spec.md`, these implementation choices are pinned (read `impls/c`):

- **`owner_type` is NOT digested.** Ownership keys on the bare hash160 (§4); a TRANSFER
  target carries no script type. `seller_type` **is** digested (it selects the payment
  template for RESERVE/SETTLE/PAY matching): a spendable output satisfies the seller leg only when
  **all three of `(hash160, script type, value)`** equal `(seller, seller_type, owed)`. The matcher
  rebuilds the seller's `scriptPubKey` *per recorded type* (§4 Rule 2), so a P2PKH-template output
  never pays a P2SH seller, nor vice-versa. Matching on `(hash160, value)` alone — ignoring the type —
  accepts a wrong-template output and forks the RESERVE/SETTLE/PAY ownership outcome. **The
  `seller_type` byte value is pinned `P2PKH = 0`, `P2SH = 1`** (the same encoding the §13
  attribution layer uses to choose its template). This is digested on every LISTED/OFFERED/RESERVED
  row, so — unlike the `st` enum, whose values §4 already pins — an impl that picked a different
  encoding (e.g. P2PKH=1, or the raw template opcodes) forks `state_digest` on **every** market row
  even while agreeing on all semantics.
- **Market-op output consumption is checked last and consumes only on success.** Within a tx,
  each RESERVE/SETTLE/PAY first evaluates its non-output preconditions — listing/lock state
  (already-RESERVED, not-LISTED), directed-buyer match, expiry, and the carrier-value gate
  (`car_value ≥ burn_leg` for RESERVE) — and an op that drops on any of those consumes **no**
  spendable output. Only an op that reaches the matcher and finds an exact `(seller, seller_type,
  owed)` output at the lowest unconsumed `vout` marks it consumed. A premature consume (matching
  before the precondition drop, or marking an output consumed on a failed match) removes an output a
  later op in the same tx needs and mis-assigns the §7 value-collision vector (41).
- **Bitmap bit order** is **LSB-first**: bit `i` = `(flags[i>>3] >> (i&7)) & 1`, meaningful
  for `i < K` (owned-set size); bits `≥ K` are ignored, never fatal.
- **Claim same-block displacement** (§3.2 priority tuple in a single forward pass): a
  block-local scratch maps each minted name → `(commit_height, commit_tx_index, provisional_owner)`.
  A later same-block claim displaces iff its backing commit's **`(commit_height, commit_tx_index)`
  is lexicographically smaller** — smaller `commit_height`, or equal `commit_height` and smaller
  commit `tx_index` — **and** the name is still that owner's fresh `OWNED` mint. The final
  tie-break is the **commit's** `tx_index`, **never** claim chain order. ⚠️ Comparing
  `commit_height` **alone** (and keeping the first-applied claim on an equal-`commit_height` tie)
  is the exact consensus bug vector 42 guards against (§7) — it forks against `docs/protocol-spec.md`
  §3.2's tuple `(claim_height, commit_height, tx_index)`. Cross-block claims never displace. The
  scratch is reset each `begin_block` and never digested.
- **Water-fill** is the §3.5 even-level + MAX_LEASE-cap-redistribute + ascending-lex
  remainder, exactly as `impls/c/src/lease.c`. It equals the **canonical integer water-fill
  fixpoint**: the largest uniform level `λ` with `Σᵢ min(headroomᵢ, λ) ≤ T`, then the leftover
  `T − Σᵢ min(headroomᵢ, λ)` days handed out **+1 each** to the still-headroom-having names in
  ascending-lex order. A capped name frees its surplus to the **next round** — recompute
  `share = pool / active` per round, so redistribution is **across** rounds, never within one — and no
  name ever exceeds its `MAX_LEASE` headroom. Every faithful algorithm reaches this same fixpoint, so
  the allocation is a unique function of `(burn, rate, headrooms)`.
- **Pre-block transitions** are per-row `reserve → offer → lease` in that order, then
  `COMMIT_EXPIRY` pruning; the lease/offer/reserve bounds are **exclusive** (owned iff
  `MTP < lease_expiry`), while the **`COMMIT_EXPIRY` window is inclusive** — a commit is live through
  `commit_time + COMMIT_EXPIRY` and pruned only once `MTP >` it (`docs/protocol-spec.md` §3.2/§5). A
  commit's **`commit_time` is the MTP of its confirmation block**, stored in the row and digested (§4).
- **Time-triggered set mutations stamp the connecting height.** A **lapse** (a name leaving its
  owner's set in the pre-block phase at height `H`) bumps that owner's `last_set_mutation_height` to
  **`H`**; an offer/reserve close leaves the name in the seller's set and does **not** bump.

---

## 4. Canonical state digest (byte-exact)

Serialize into a buffer, then `SHA-256`. Multi-byte integers are **little-endian**;
signed values are two's-complement LE.

```
"SMv1"
u32  n_names         ; rows sorted ascending by raw name bytes, each:
    u8 name_len ‖ name ‖ owner[20] ‖ u8 st ‖ i64 lease_expiry
    ‖ seller[20] ‖ u8 seller_type ‖ u64 price ‖ i64 offer_expiry
    ‖ buyer[20] ‖ u64 burn_leg ‖ u64 pay_leg ‖ i64 reserve_expiry
u32  n_commits       ; sorted by (commitment[32], commit_height, tx_index), each: commitment[32] ‖ i64 commit_height ‖ u32 tx_index ‖ i64 commit_time
u32  n_muts          ; sorted by owner bytes, each: owner[20] ‖ i64 height
```

(`st`: OWNED=0, LISTED=1, OFFERED=2, RESERVED=3.) State NOT digested: per-block claim
scratch, coverage counters.

**Every names row is fixed-width.** The market fields (`seller`, `seller_type`, `price`,
`offer_expiry`, `buyer`, `burn_leg`, `pay_leg`, `reserve_expiry`) are **always emitted, regardless of
`st`**. For an `OWNED` (st=0) row — and for any field not active in the current `st` — those bytes
are **all-zero** (`seller` / `buyer` = 20 zero bytes; `seller_type` / `price` / `offer_expiry` /
`burn_leg` / `pay_leg` / `reserve_expiry` = 0). A row that **leaves** a state (an offer/reserve close
or a reverted reserve, §5) **physically resets** the now-inactive fields to zero before the next
digest, so two indexers that reached the same logical `st` always serialize identical bytes. (This is
the fixed-width counterpart to the prose `names` table in `docs/protocol-spec.md` §5, whose per-`st`
field list says which fields are *meaningful* — not which are *emitted*; the digest always emits all
of them.)

**The `buyer[20]` slot carries both market counterparties.** For an `OFFERED` (st=2) row it holds the
**directed buyer** named by `SELL_TO`; for a `RESERVED` (st=3) row it holds the **reserver** — the
exclusive buyer who alone may `SETTLE` (§3.7), written at `RESERVE` and matched at `SETTLE`. There is
**no separate `reserver` field** in the digest: the `reserver` named in the `docs/protocol-spec.md` §5
*Tables* reservation row *is* this `buyer` slot. An indexer that split them — a dedicated `reserver[20]`
with `buyer` left zero on a `RESERVED` row — forks every reserved row's 20 bytes.

**`n_commits` sort is a *total* order — commitment bytes alone are not.** The §3.2 commitment-copy
attack (an attacker re-posts a victim's 32-byte commitment under their own tx) produces two rows
with **identical `commitment` bytes**; sorting on `commitment` alone leaves their relative order
undefined, so a non-stable sort (e.g. C `qsort`) would serialize them in a platform-dependent order
and **fork the digest**. The pinned key is therefore `(commitment[32], commit_height, tx_index)`:
`(commit_height, tx_index)` uniquely identifies a commit's own transaction, so the triple is a
strict total order on distinct rows regardless of sort stability. (Implementations whose
`n_commits` comparator stops at the commitment bytes MUST add this secondary key.)

**`n_muts` is never pruned.** A `last_set_mutation_height` row, once stamped for an owner, persists
for the life of the index — it is a monotonic high-water mark, **not** removed when that owner's
live name set falls to empty (`docs/protocol-spec.md` §3.5/§3.8). An indexer that dropped the row
for a now-empty owner would emit a smaller `n_muts` and fork the digest after any set-emptying lapse.
The rule also covers a **same-block-displaced CLAIM**: the provisional mint already bumped the *losing*
minter's height (§3 *Claim same-block displacement*) before a higher-priority claim displaced it, and
that bump is **never rolled back** — the displacement stamps the *new* owner's height too, it does not
un-stamp the loser. So `n_muts` can carry a row for an address that ends the block owning nothing; an
impl that bumped only the *final* owners would emit a smaller `n_muts` and fork after any contested
same-block claim.

---

## 5. Generator (must match draw-for-draw)

The generator reads fold state only **by name** (canonical), never by iterating internal
collections (whose order is not canonical). Pinned constants:

```
N_IDS=16   NAME_POOL=400   BASE_TS=1_700_000_000   activation_height=0
identity i: h160 = byte(i) ‖ 18 zero bytes ‖ byte(i);  type = P2SH if i%4==3 else P2PKH
name_of(i): "n" + base36(i)            # digits 0-9a-z
op weights [COMMIT,CLAIM,RENEW,TRANSFER,SELL,RESERVE,SETTLE,RELEASE,SELL_TO,PAY,TRADE,
            RENEW_NAME,TRANSFER_NAME,RELEASE_NAME]
           = [14,13,5,5,8,7,7,3,6,5,4,4,3,2]
rate = 28·(1+bounded(4)) ; ts step = 300+bounded(600) ; txs/block = 1+bounded(8)
lease burn = (rate/28)·days        # so days are exact
```

Per block: `bounded(600)` (ts step) → `bounded(4)` (rate) → `bounded(8)` (txs) →
per tx `[ pick_op : bounded(Σweights) ]` → the op's field draws → `maybe_corrupt`
(`bounded(100)`, and if `<18` and the tx has carriers, `bounded(4)` selects a twist).
The exact per-op draw sequence is defined by `impls/c/src/gen.c` (`build_tx`); the
Python mirrors it line-for-line. The **input_digest** is a streaming SHA-256 over a
fixed-width serialization of each tx (`hash_tx`), so a generator/PRNG drift shows up
there before the fold digest.

---

## 6. Frozen reference digests (regression)

These are the frozen `impls/c` regression anchors. Tier 1 is C-only: it self-regresses the C reference
against the frozen scenario / attrib-scenario **combined** goldens, the
`properties`/`reorg`/`reorgfuzz`/`meta` violation==0 invariants, and the generator/decode coverage gate.
The off-curve-P2PKH (A7) attribution lock additionally lives natively in the independent reference impls
(their selftest A7 regression — see [`SPEC-RATIONALE.md`](SPEC-RATIONALE.md)). A solo C run can be
CI-checked against the table below:

| seed | count  | state_digest (first 16 hex) |
|------|--------|------------------------------|
| 1    | 100000 | `c640599837be1ab0…` |
| 42   | 100000 | `9dd51eab55597850…` |
| 1000 | 100000 | `14a725b65746dcef…` |

Run `./run-conformance.sh` for the full matrix across every present implementation.

## 7. Directed conformance vectors (`sm scenario`)

Beyond the random soak, each impl ships a `scenario` mode: **named, hand-authored
adversarial constructions** with auditable outcomes — the spec's §5 edge cases plus the
branches the soak almost never hits (battery renumbered + combined golden re-pinned during
the impl update). Each emits `name <digest>`; the final
`combined <sha256>` is the single-line cross-language + regression check.

Coverage includes: commit→claim happy/naked/too-shallow, the **priority tuple** (lower
`commit_height` wins both orderings), **commitment-copy** author-binding, lease lapse,
renew stacking, **water-fill** even-split + `MAX_LEASE` cap-forfeit + the **`λ = 0`
underfunding floor** (32) — one day each to the first `T` *headroom-having* names, triggered by
`T < #headroom-names`, **not** the total selected `count` (a lone eligible name with `T = 50` takes
50 days, not one) — + the **all-capped multi-name forfeit** (33), transfer/release,
the full open-market cascade (reserve burn-short / pay-summed / **reserve_expiry clamp**),
SELL price-floor + add-form window guard, directed SELL_TO/PAY (stranger-drop), the
**2⁶⁴-1 deposit** (128-bit legs), AS attribution + OOB-drop, TRADE swap + same-block
anti-rug, the **fee-oracle** (participant filter: even-|P| lower median at the inclusive
`MIN_FEE_SAMPLE` boundary with an in-window under-claim (49), odd-|P| middle (50), the
999-participant degrade (51), plus the small-window degrade / floor (29/30)) + **MTP
median**, and the **reorg edge
cases** as deterministic vector pairs (34 same-block lapse-and-reclaim vs. a RENEW that
blocks it; 35 a SETTLE un-confirmed → re-listed vs. confirmed; 36 an MTP boundary call
that flips under a one-tick reorg).

Vectors **38–41** pin pre-block ordering and intra-block market races: **38** a same-block
RENEW-vs-CLAIM at the exact lapse tie (the pre-block lapse runs *before* the block's txs,
so the old owner's RENEW skips the lapsed name and the hunter's CLAIM wins — a lazy
"evaluate expiry on access" impl forks); **39** a single pre-block tick that crosses
`reserve_expiry` then `offer_expiry` at once, cascading RESERVED→LISTED→OWNED in one pass
in the rigid §5 type-order reserve→offer→lease (the *triple* tie with the lease is
unconstructible — the nesting invariant forces `offer_expiry + REORG_BUFFER ≤ lease_expiry`,
so the lease leg is always ≥ `REORG_BUFFER` out); **40** intra-block RESERVE option theft
(first reserver in chain order wins the exclusive option; a second reserve on the now-
RESERVED row drops without overwriting, so the loser's later SETTLE fails the buyer-match —
the abstracted SM pins the option-lock + settle-drop, not the on-chain deposit burn it can't
observe); **41** a value-collision in spendable-output matching (one tx does RESERVE+SETTLE,
both paying the same seller, with outputs `vout[0]=19800`, `vout[1]=5` — the consume-once,
exact-value, vout-order matcher must let RESERVE skip the larger `vout[0]` and take `vout[1]`,
then SETTLE take `vout[0]`; a greedy/dest-only/summing matcher mis-assigns and one op drops).
Vectors **42–48** are the spec↔harness audit follow-ups: **42** the CLAIM priority tie-break is
the **commit's** `tx_index` (§3.2's tuple), not claim chain order — two authors commit one name
in the same block (the lower commit `tx_index` must win) and both claim later with the *other*
claim applied first; the same-block displacement must carry the backing commit's `tx_index`
(this caught a real consensus bug — the displacement formerly compared `commit_height` only and
kept the first-applied claim, forking on equal `commit_height`). **43** escrow movement-lock (a
LISTED name rejects TRANSFER/RELEASE/re-SELL/SELL_TO). **44** the anchor-guard *reject* path (a
bitmap op whose anchor predates the owner's last set-mutation drops). **45** COMMIT_EXPIRY prune
(an expired commit no longer backs a claim). **46** the RESERVE burn leg is `≥`, not exact (an
over-funded burn still wins). **47** TRADE fail-closed edges (OOB index / one-party / self-name).
**48** selective TRANSFER applies exactly the flagged subset. The C reference pins the outcomes of
38–48 with behavioral assertions in `selftest` (`test_scenario_races` / `test_scenario_races2`),
not just the digest.

**Frozen golden:** `combined = aca6749e79b7e6b582e1f5043693b7991fcc592f4df537461e09d6b9e451d347` (2026-07-26: added the by-name vectors — `59_renew_name` pins the anchor-free singleton renew + non-owner drop, §3.5; `60_transfer_name` pins the one-name gift with both-party mutation bump, §3.5/§3.6; `61_release_name` pins the one-name release-to-pool, §3.5/§3.6). Prior: 301ce369… (2026-07-09: divergence-fix vectors — `55_claim_release_reclaim_sameblock` + `55b_reclaim_by_other` pin same-block release→re-mint, §3.6; `56_self_transfer_bumps_mut` pins self-transfer as a mutation bump, §3.5; `57_oracle_zero_bytes` pins the `block_bytes==0` → divisor-1 oracle rule, §3.4; `58_lease_clamp_huge_burn` pins the near-2⁶⁴ burn lease clamp to MAX_LEASE), c6101c4c… (re-pin 2026-07-08: `52_charset` + `52b_structural` pin `[a-z0-9-]`, 1..32, lead/trail hyphen + `--`-at-3–4 rejects; `54_no_txcap` is 17 COMMITs), 4c84238f…, 059ac934…, db714fa4…, d7809634….)
— since the 2026-07-02 re-pin this is a **full cross-language lock**: the numbered battery was
ported from `impls/c` into all six other impls during the charset change (it had previously
been C-only, with the promoted clean-rooms carrying port-private scenario/behav surfaces —
those behavioral asserts were kept, folded into each port's selftest battery), and
`run-conformance.sh` now diffs every impl's full scenario output byte-for-byte against the
reference. The oracle vectors' *values* remain independently cross-pinned as well: every impl
asserts the 49/50/51 constructions (119800 / 130000 / 1) and the vector-29 small-window
degrade (1) in its own selftest/behav battery, driven through its own oracle function.

---

## 8. Property mode (`sm properties <seed> <count>`)

Re-runs the **identical `random` stream** (so `state_digest` equals §6's soak golden) but,
per block, (a) asserts a battery of hard invariants and (b) folds a per-block **property
fingerprint** into a rolling `property_digest`. Invariants proven, not merely asserted: if
all impls agree on `property_digest` they agree on every derived aggregate block-by-block —
a finer cross-check than the final state digest. Output: `violations=<n>`,
`property_digest=…`, `state_digest=…`. The runner asserts `violations == 0` and matches the
digests across impls.

**Hard invariants (the `violations` count):** no-double-ownership; `mtp < lease_expiry ≤
mtp + MAX_LEASE`; for any listed/offered/reserved row `offer_expiry + REORG_BUFFER ≤
lease_expiry`; listed `price ≥ 3·DUST_FLOOR`; reserved `reserve_expiry ≤ offer_expiry`,
`price ≥ burn_leg + pay_leg`, the **deposit-leg conservation recompute**
`burn_leg == max(DUST_FLOOR, ⌊price·50/10000⌋)` and same for `pay_leg`, and `price −
burn_leg − pay_leg ≥ DUST_FLOOR`; every mutation height `≤ cur_height`.

**Property fingerprint (pinned field order, order-independent aggregates):**

```
u32 n_names, n_owned, n_listed, n_offered, n_reserved
u32 n_commits, n_muts
i128 Σ lease_expiry            ; 16 bytes LE (wrapping)
i128 Σ price   (listed+reserved)
i128 Σ (burn_leg+pay_leg)      (reserved)
```

**Frozen golden (seed 42, count 100000):**
`property_digest = 0c16c1a324810078eed5e4ec46c878d54d760a9a834773cb8898d08ebec87b8a`
(and `state_digest` equals §6's `9dd51eab…`).

---

## 9. Wire codec + differential fuzzer (`sm fuzz <seed> <count>`)

The base fold consumes already-decoded carriers; **`decode.c` / its ports add the byte
layer** the real indexer's strict, fail-closed parse lives in (§0/§1/§2/§3: "indexers MUST
agree byte-for-byte on validity"). The fuzzer feeds millions of **dumb-random + grammar-
aware-perturbed** OP_RETURN payloads through the decoder → fold → digest; any parser/bounds
divergence between languages surfaces as a `state_digest` mismatch. Output: `input_digest=`
(the raw fuzz byte stream) + `state_digest=` (the fold result); `--cov` prints decode
coverage (ignore / per-opcode-action).

**`sm_decode_payload(payload, len, value) → ACTION | IGNORE` (pinned):**
- ACTION iff `len ≥ 4` and `payload[0..3] == FF 53 50` and opcode `payload[3] ∈ 0x01..0x0F` decodes
  per the per-opcode field layout below; any field/length mismatch ⇒ **IGNORE**.
- Everything else (no action prefix, unknown opcode, or any field/length mismatch) ⇒ **IGNORE**.

**Per-opcode action decode** (body `b = payload[4:]`, `bl = len−4`, all ints LE):
`COMMIT` bl==32 · `CLAIM` bl 33..64 (salt32+name1..32) ·
`RENEW` bl∈{0(all),5(all-safe: anchor5)}∪[6,9992](selective: anchor5+flags1..9987) ·
`TRANSFER` bl==20(all)∪[26,9992](selective: 20+anchor5+flags1..9967) ·
`RENEW_NAME/RELEASE_NAME` bl 1..32 (name) · `TRANSFER_NAME` bl 21..52 (target20+name1..32) ·
`SELL` bl 13..44 (price8+window4+name1..32) · `RESERVE/SETTLE/PAY` bl 1..32 (name) ·
`RELEASE` bl 6..9992 (anchor5+flags1..9987) ·
`SELL_TO` bl 29..60 (price8+buyer20+name1..32) · `AS` bl==1 (index) ·
`TRADE` bl≥5 (idxA1+idxB1+`nameA,nameB`, **exactly one** `0x2C`, both names §3.1). Names
validate per §3.1 (`[a-z0-9-]`, 1..32; re-pinned 2026-07-07; also reject a leading or trailing
hyphen and `--` at positions 3-4 (`name[2]=='-' && name[3]=='-'`), so `xn--…`/all ACE shapes drop);
a non-name byte ⇒ IGNORE. `sm_encode_action` is the
canonical inverse (grammar-aware fuzz; round-trip-tested in the C selftest).

**Fuzz draw order (pinned; no fold-state reads → byte stream identical across languages).**
Per block: `bnd(600)` ts-step → `bnd(4)` rate → `bnd(8)` txs. Per tx: `1+bnd(4)` inputs,
each `bnd(16)` id + `bnd(8)!=0` SIGHASH_ALL; `1+bnd(4)` carriers, each = one **carrier-bytes**
draw then **value** draw (`bnd(12)`: 0 / `2⁶⁴−bnd(1000)` / `1+bnd(1000)`); `bnd(4)` outputs,
each `bnd(16)` id + `bnd(4)==3?P2SH:P2PKH` + value. **Carrier-bytes:** `bnd(10)<4` ⇒ dumb
(`bnd(3)` prefix-flag, the tiered len draw (re-pin note below), that-many `bnd(256)` bytes, `bnd(21)` opcode, then if
flag==0 & len≥4 overwrite `FF 53 50 <op>`); else grammar (`1+bnd(15)` opcode → build a valid
action with pinned per-op field draws → encode → one of six `bnd(6)` twists: none/none/
truncate/flip-byte/extend/charflip). Re-pinned 2026-07-26 for the §6 carrier-ceiling widening
(§6 of the spec): the dumb len draw is `bnd(8)==0 ? bnd(9997) : bnd(81)` (1-in-8 wide), the
grammar flags draw is `bnd(32)`-tiered (`==0` ⇒ `1+bnd(cap)` full-range, `<4` ⇒ `1+bnd(200)`
mid, else `1+bnd(3)` tiny; cap = 9987 renew/release · 9967 transfer), the extend twist caps at
9996, and `raw_len` streams as **u32-LE** (raw carriers can exceed 255 bytes). `input_digest`
streams `txindex,inputs,[raw_len‖raw‖value‖vout]*,outs`.

**Frozen golden (seed 42, count 100000):**
`input_digest = 72a3edf5221526013778dc77ec83b1ba3b34873b29afdfddf13a0369545d57b7`,
`state_digest = 487d2c2f1f10e9812c7239a5cc51b07e6490ee08d03ccb03039ad78f37f5e7c5`.

**Boundary-cluster variant (`sm bfuzz`).** Identical to `fuzz` except a `boundary` flag
snaps four numeric draws — `fz_value`, `fz_price`, the SELL `window`, and the per-block MTP
step — to a pinned table half the time, so the fold's comparisons are probed *densely* at
their edges instead of by luck. The boundary branch is `if (boundary && bnd(2)==0) snap`, so
the `boundary=0` path (and thus the `fuzz` golden) is byte-unchanged.
`VAL_BND` (30 entries) `= {0,1,2,3,4,5, 17999,18000,18001, 7199,7200,7201, 86399,86400,86401,
31535999,31536000,31536001, 2³¹,2³¹‖0x80000000,2³²−1,2³², 2⁵³−1,2⁵³,2⁵³+1,2⁵⁴+1, 2⁶³−1,2⁶³,
2⁶⁴−2,2⁶⁴−1}` (the §-constants ±1, the word edges, **and the IEEE-754 double cliff** — `2⁵³−1`
is JS `Number.MAX_SAFE_INTEGER`, and `2⁵³+1`/`2⁵⁴+1` are the first integers a JS `number` cannot
represent, rounding to `2⁵³`/`2⁵⁴`; they are the load-bearing probe that any impl carries koinu/price
values as exact 64-bit integers, not floats — a `number`-path impl produces different value bytes
here and diverges on `input_digest`). The SELL window is masked to 32 bits.
`MTP_BND = {1,2,300,7200,18000,86400,604800,31536000,31536001}`.
**Frozen golden (seed 42, count 100000):**
`input_digest = 24f1f89dd8383c4c31799a80a4d1676183b682667e31290c17d364d0a3dd8aad`,
`state_digest = f42c33d1646e79fe6ff0d9bd22127426d50613a70bf52269bc36e7598f8b80a6`.

---

## 10. Reorg confluence (`sm reorg <seed> <count>`)

Makes the §5 reorg story ("roll back the disconnected blocks and **replay** from the fork
point — exact") executable. `sm_record_chain` regenerates the **same chain as `random`**,
recording each realized block (`height, mtp, rate, [tx_lo,tx_hi)`) + flat tx list (count
capped at 20000 for RAM). The harness then re-folds slices into fresh states and asserts:

1. **replay** — a fresh full fold reproduces `D_full`.
2. **resume** — fold `[0,J)` → `S_fork`, then `[J,nblk)` on the same state == `D_full`
   (the fold is a pure function of the block sequence; J = nblk/2).
3. **clear-rebuild** — a full fold, then `clear()` + re-fold `[0,J)` == `S_fork` (proves the
   reorg rebuild primitive leaves no residue).
4. **fork-and-return** — fold `[0,J)`, take a **divergent branch** (the canonical tail with
   each block's txs applied in reverse → `D_alt`), `clear()`, re-fold `[0,J)` == `S_fork`,
   then replay the canonical tail == `D_full`.

Output: `blocks= fork= checks= failures=` then `D_full=`, `S_fork=`, `D_alt=`, and
`reorg_digest = SHA256(D_full ‖ S_fork ‖ D_alt)`. The runner asserts `failures == 0` and
matches `reorg_digest` across impls.

**Frozen golden (seed 42, count 8000):**
`reorg_digest = b62eb4fc1fdf1adb9c1854678d23b520b39009543858e7494e8f4f78c97608dc`.

---

## 11. Reorg-depth fuzz + metamorphic drop-closed

**`sm reorgfuzz <seed> <count>`** stresses the reorg machinery far harder than the single
fixed fork of §10: it records the chain, then runs **K = 64 trials** with an independent
trial-PRNG seeded `seed ^ 0x5245464B5A475F31`. Each trial draws a fork `J = bnd(nblk+1)` and
a divergence `kind = bnd(3)` (0 = reversed tail, 1 = every-other block, 2 = tail folded
twice), walks that divergent branch, then asserts **clear-rebuild to J reproduces `S_fork`**
and **replaying the canonical tail reproduces `D_full`**. `reorgfuzz_digest = SHA256(D_alt₀ ‖
… ‖ D_alt₆₃ ‖ D_full)`; the runner asserts `failures == 0` and matches the digest.
**Frozen golden (seed 42, count 8000):**
`reorgfuzz_digest = e884272c4bd548a33cf1e6d9d47e2b2a4bc78d69187b4fa2329eee2f40a2bdae`.

**`sm meta <seed> <count>`** — the metamorphic property *an action the protocol IGNORES is
provably inert*. After each block of the `random` chain it injects a fixed all-inert tx (a
malformed-decoded IGNORE carrier + an overlay-band carrier)
and asserts the state digest is **byte-unchanged**. A decoder/fold bug that lets any
"should-be-inert" carrier mutate state lights up as `failures>0` (and a divergent digest).
Output: `failures=` + `state_digest=`; runner asserts `failures == 0` and matches the digest.
**Frozen golden (seed 42, count 20000):**
`state_digest = 34d1782a685ce007e727425db18e1e70fcbf1af143d90a4c84f503afc5689fb6`.

(Both modes cap `count` at 20000 — they keep the realized chain in RAM, like §10.)

---

## 12. Single-impl self-checks (the C reference)

Not cross-language digests, but the C harness's own correctness net:

- **`make test` (`sm selftest`)** — **130** unit checks: PRNG; the **wire-codec round-trips**
  (every opcode encode→decode→encode is a bijection) + fail-closed drop cases; the
  **digest-sensitivity** sweep (every digested field moves the digest; `owner_type`, by design,
  does not — guards the canonical digest against accidental omission); the fold units; and
  `test_scenario_races` — behavioral assertions pinning the *outcomes* of scenario vectors
  38–41 (not just their digests), so a deterministic-but-wrong race construction can't slip through.
- **`make cover` (`sm coverage`)** — asserts every generator branch (`SM_EV_*`) and every decode
  branch fires over a soak; a silently-blind
  generator fails it. The generators are pinned identical across languages, so the one C run
  certifies all.
- **`make sanitize`** — UBSan (`-fsanitize=undefined -fno-sanitize-recover`) over every mode:
  no signed-overflow / OOB-index / bad-shift UB in the 128-bit math or the byte decoder. (An
  `asan` target exists too, but the macOS ASan *runtime* hangs at startup on Darwin 25 — even a
  trivial program — so ASan is for CI/Linux; UBSan is the local gate.)

---

## 13. §4 attribution shell (`sm attrib <seed> <count>`)

The §5 fold is fed an already-resolved identity; **§4 Stateless Identity & Attribution** is the
*other* spec-mandated conformance surface — `raw tx hex → {Identity} | drop`. This is a **separate
seed-driven layer** (its own `attrib` / `attrib-scenario` modes, its own digests) that runs the real
attribution byte-logic over generated raw transactions. The realization that makes it fit the
zero-dep, regenerate-from-seed model: **§4 is a byte-logic shell around exactly two curve
operations.** Everything that forks between languages is pure byte manipulation and is computed *for
real*; only the curve is abstracted.

**Real byte-logic (the cross-checked surface).** A pinned PRNG-driven generator emits raw
transactions (1–3 inputs, P2PKH / P2SH-multisig / a menu of malformed scriptSigs / garbage), and for
**each input** the validator computes `attribute(tx, k) → (status, sighash, identity)`:

- **strict-DER + low-S** — BIP66 structure (`0x30 len 0x02 lenR R 0x02 lenS S`), reject negative /
  non-minimal-pad / wrong-length / trailing; **`S ≤ N/2`** (32-byte BE compare vs `SECP_N_HALF`); the
  trailing sighash-type byte **MUST be `0x01`** (Rule 3, SIGHASH_ALL).
- **pubkey canonical encoding** — 33-byte `0x02/0x03 + X` or 65-byte `0x04 + X + Y`, coordinates
  `< p` (`SECP_P`); reject hybrid/length/range. (Point-on-curve is the injected part.)
- **minimal-push iterator** — direct `1..75` / `OP_PUSHDATA1 76..255` / `OP_PUSHDATA2 256..520`,
  non-minimal ⇒ drop.
- **P2SH-multisig template** — `OP_m · n×(0x21 ‖ 33-byte compressed key) · OP_n · OP_CHECKMULTISIG`,
  `1 ≤ m ≤ n ≤ 15`, exact `OP_0` NULLDUMMY, no trailing; `(#sig pushes) == m`.
- **in-order signature scan** — the `m` sigs must match a subsequence of the `n` keys in order.
- **legacy sighash incl. `FindAndDelete`** — the double-SHA256 preimage for input `k` (scriptCode at
  `k`, others empty, `SIGHASH_ALL` appended LE), with **Bitcoin Core `CScript::FindAndDelete`
  semantics** applied for each checked signature's push (boundary-aligned removal via `GetOp`
  iteration). **Structurally inert on the rigid compressed-key template** (a 33-byte `0x21` key push
  never collides with a `0x47/0x48` sig push at an opcode boundary), so it is pinned **cross-language
  directly**: `attrib-scenario` ships explicit `find_and_delete` KAT vectors (`fad00` boundary removal,
  `fad01` in-body non-removal) plus a **load-bearing** case (`fad02`/`fad03`: the sighash WITH vs
  WITHOUT FaD on a scriptCode that contains the pattern at a boundary — the two digests MUST differ).
  Without these a port could omit FindAndDelete and still match every other digest; now it cannot.
- **Identity = `RIPEMD160(SHA256(x))`** — `x` = exact pubkey (P2PKH) or exact redeemScript (P2SH).
  RIPEMD-160 is the one new hash primitive (self-rolled in every language; KAT `""`→`9c1185a5…`,
  `"abc"`→`8eb208f7…f15a0bfc`, `hash160("abc")`→`bb1be98c…`).

**Injected curve oracle (the byte-logic tier's abstraction; the real curve ships alongside it as
`attrib-curve`, see Strategy B below).** The `attrib` / `attrib-scenario` modes keep these pinned
pseudo-functions of the bytes — consulted exactly where `secp256k1` would be — so their frozen goldens
stay byte-identical and the suite needs no curve binding to run the byte-logic shell:
```
on_curve(pubkey)               = SHA256(0x4F ‖ pubkey)[0] != 0x00
verify(hash32, r32, s32, pubkey) = SHA256(0x56 ‖ hash32 ‖ r32 ‖ s32 ‖ pubkey)[0] >= 0x20
```
`r32`/`s32` are the DER-decoded `R`/`S` **integer values**, each as a **32-byte big-endian,
right-aligned, zero-padded on the left** — the DER sign byte (a leading `0x00` guarding a high bit)
and any minimal-length encoding are stripped, so what feeds the oracle is the numeric value, never the
raw DER bytes. (Strict-DER already forbids negative or over-padded `R`/`S`, and low-S compares this
same 32-byte BE `s32` against `N/2`; an `R`/`S` of full 33-byte DER length keeps only its low 32
bytes after the sign byte is dropped.) `hash32` is the legacy-sighash preimage digest; `pubkey` is the
exact canonical encoding. Feeding raw DER bytes, a different padding, or little-endian forks the
`attrib` verdict and digest.
For multisig the `verify` verdict is consulted per `(sig, key)` pair, so the in-order scan is fully
exercised; **`on_curve` is checked up front on every identity key, for *both* templates** — the single
**P2PKH** pubkey and all `n` **P2SH-multisig** redeemScript keys (the identity's key set is fixed by
the script, independent of the sig set, so any off-curve key is fatal before verification). A pubkey
canonical in *encoding* (`0x02/03/04`, `X < p`) but **off-curve** is `status` 1 for **either** template
— not multisig alone (`docs/protocol-spec.md` §4 Rule 4 "Non-canonical → drop" + step 4). A common
implementer trap is to read the status taxonomy as redeemScript-only and skip the curve check for
P2PKH, reporting an off-curve P2PKH key as **found** (status 3) or verify-drop (status 2); that forks
the status byte and the digest. `status` is the **earliest failing stage**:
`0` **classify-drop** (shape / template / DER / low-S / sighash-type byte / minimal-push /
sig-count ≠ `m` — any structural failure, before a key is curve-tested) · `1` **on-curve-drop** (any
identity key — the P2PKH pubkey or any redeemScript key — well-encoded but off-curve) · `2`
**verify-drop** (the in-order scan ends with fewer than `m` sigs verified — e.g. valid-DER sigs that
none of the keys accept) · `3` **found**. The
legacy sighash is the double-SHA256 of the **standard pre-SegWit Dogecoin preimage** — serialized
exactly as host consensus does, and pinned here because the resulting `sighash[32]` is digested:
`int32_le version ‖ varint(n_in) ‖` per input `prevout_hash[32] ‖ u32_le prevout_index ‖
varint(script_len) ‖ script ‖ u32_le sequence` (the input being signed carries its `scriptCode`,
**every other input an empty script**) `‖ varint(n_out) ‖` per output `int64_le value ‖
varint(spk_len) ‖ spk` `‖ u32_le locktime`, then the hashtype appended as a **4-byte LE `int32`
(`0x01000000`)**, never 1 byte (`docs/protocol-spec.md` §4 step 4). The harness ingests `raw_tx` by
the inverse of this layout; an unpinned version/sequence/locktime/varint convention would fork the
digested sighash.

**Digests.** `state_digest` streams, per parsed tx and per input `k`, `[k][status] ‖ sighash[32] ‖
identity[20]` (a tx whose **raw-tx deserialization fails structurally** — the layout above does not
parse — contributes a single `0xFF` for the whole tx and emits no per-input rows; a tx that parses
emits one `[k]…` row per input, each carrying its own `status`, even when every input drops); `input_digest` streams
`u32_le(len) ‖ raw_tx`. **The `sighash` / `identity` bytes for a non-found status are pinned** (else
two conformant impls fork the digest), both filled together the moment classification succeeds: a **status-≥1** row carries the **real
`hash160` identity AND the real legacy-preimage `sighash`** — the sighash is formed right after
classification, **before** the on-curve gate, so even an on-curve-drop (`status` 1) carries it (this
matches `impls/c`, the normative reference for this digest layout); only **`status` 0** — where
classification never succeeded — is all-zero. So the four rows are `0`→`[k][0]‖ZERO32‖ZERO20`,
`1`→`[k][1]‖sighash‖identity`, `2`→`[k][2]‖sighash‖identity`, `3`→`[k][3]‖sighash‖identity`. A
parser/DER/template/FindAndDelete divergence between languages surfaces as a mismatch.

**Frozen golden (seed 42, count 100000):**
`input_digest = 90706dc5e67291a242a8cac04b76f1952cf5d5425b5f9845a5592e376fd7b37e`,
`state_digest = 06f43a2e3a6970c970d2ab842fcdaf41c58ca049a1c9c674ac5639ddbc261f08`.

**`sm attrib-scenario`** ships the RIPEMD-160 KATs + 16 fixed-seed attribution vectors (auditable
`status:identity` per input) + the 4 `find_and_delete` vectors above (`fad00`–`fad03`) + 6 **§3.9
wallet-preview vectors** (`prev00`–`prev05`) + the 2 **A7 off-curve-P2PKH vectors** (`a7off_…`,
`a7on_…`). The preview vectors render `raw tx → {per-input attribution; per-TRADE (give, get) per
party}` for a `TRADE(idx_a=0, idx_b=1, nameA="alpha", nameB="beta")` — vin0's identity *gives* `alpha`
/ *gets* `beta`, vin1's *gives* `beta` / *gets* `alpha` — pinning the safety-relevant give/get
**direction** a wallet must show before an irreversible swap (the §3.9-mandated "shipped
preview-vector set"). The **A7 vectors** lock the rule above directly: two minimal P2PKH inputs share
one valid (low-S, SIGHASH_ALL) DER sig, one carrying a canonical-encoding-but-**off-curve** compressed
pubkey (must be `status` **1** on-curve-drop), one **on-curve** (must be `status` 2/3, never 1) —
proving the on-curve gate, not the verify step, is the discriminator. They exist because the generated
soak almost never lands a canonical-encoding-but-off-curve key on the *P2PKH* path (the curve gate was
only exercised via multisig — exactly the blind spot that produced A7). The C builder also
**self-asserts** the two statuses on stderr and exits non-zero on regression, so the lock holds even
independent of the digest. **Frozen `combined =
9fb140772fc746863100d4a88379b91f362ef011735fcb68ed4210b095c238f8`**. C-only `attrib-selftest` runs the
RIPEMD160/hash160/FindAndDelete/DER unit KATs.

### 13.1 Strategy B — real secp256k1 (`sm attrib-curve`)

The curve is no longer abstracted. Every reference impl (c · py · ts · java · rust · go · cs) ships a
**self-rolled, zero-external-dependency secp256k1** — field arithmetic mod `p = 2²⁵⁶ − 2³² − 977`,
Jacobian point math, ECDSA verify, and **RFC-6979** deterministic signing (HMAC-SHA256 nonce, so the
accept path is reproducible across languages without randomness). C self-rolls with 4×64-bit limbs +
the fast fold-reduction (`2²⁵⁶ ≡ 2³² + 977 mod p`, constant `0x1000003D1`); the languages with native
big integers (py `int`, java `BigInteger`, cs `BigInteger`, go `math/big`, ts `BigInt`) use those, and
Rust self-rolls limbs like C (the suite's zero-crate rule). The **`SECP_P` top word ends `…FFFFFC2F`**
(`2²⁵⁶ − 2³² − 977`, *not* `2²⁵⁶ − 977`) — a KAT-pinned constant, asserted in every impl's selftest.

`sm attrib-curve` is the **pinned ECDSA curve-vector set**, run against each impl's own secp256k1 and
required to print **byte-identical** output (Tier-2 style — all 7 agree). It covers:
- pinned `P` / `N` / `N_HALF` constants;
- **on-curve membership at the edges**: `G`/`2G` uncompressed, `G` compressed (both parities), an
  altered-`Y` off-curve point, compressed `X = 0` / `X = 1` (decompress residue test), `X ≥ p`
  (decode-reject), bad prefix. The accept/reject bit of each is pinned (and pins *which layer* rejects
  — encoding-canonicality `X < p` before the on-curve sqrt test);
- **RFC-6979 deterministic `(r, s)` + canonical DER** known-answers for four signers (the nonce
  derivation is the cross-language fork risk; byte-identical `r`/`s`/`der` lines pin it);
- **ECDSA verify at the scalar boundaries**: `valid` / tampered-hash / `r = 0` / `s = 0` / `r = n` /
  `s = n` / **high-S (still verifies** — low-S is a DER-layer rule, not a curve rule) / wrong-key;
- the **tiny-key external anchor** `priv = 1 ⇒ pubkey = G` and `priv = 2 ⇒ pubkey = 2G` (universal
  secp256k1 truths — an external check that doesn't depend on this suite).

`combined` digests the pure curve layer (sections above). **`combined_e2e`** then digests the
**end-to-end pipeline**: build a tx, compute its *real* legacy sighash, sign **that** with RFC-6979,
embed the signature, and run the full `attribute()` shell with the real curve — pinning the load-bearing
linkage the curve battery alone can't (that the message fed to `ecdsa_verify` IS the shell's computed
sighash). Three vectors: P2PKH correctly signed → **found** (status 3); P2PKH signed by the **wrong
key** → **verify-drop** (status 2); 2-of-2 P2SH multisig, two in-order sigs → **found**. Each impl flips
a run-time `real_curve` toggle for these vectors only — `attrib` / `attrib-scenario` / `selftest` keep
the injected oracle, so their goldens are untouched.

**Frozen goldens:** `combined = 5b7d1e765c7a213bab6825abf1fb75fc6c9fa0771c7b58484cc0d2a3b2bf7113`,
`combined_e2e = c24c560202f6a8cf6a154ce54cdfe80ee32dc440d1c9594124c7939c62d54a14`. The constants/2G/
n·G=∞/decompress/sign-verify-round-trip KATs are folded into every impl's `selftest`. `run-conformance.sh`
runs `attrib-curve` across all 7 impls and asserts byte-identical output + the two goldens. (The
**real-attrib soak** — embedding RFC-6979 sigs into the seed-driven fuzzer end to end — remains a
possible future extension; the vector set above is the normative artifact that makes "the curve is real"
a checkable claim.) See `protocol-sm-sec4-harness` + `docs/notes/strategy-b-attribution-crypto-plan.md`.

### 13.2 ECMH — incremental state digest (`sm ecmh`)

The §4 canonical digest is the equality oracle, but it re-hashes the **whole** state (O(n) every
block). The ECMH (Elliptic Curve Multiset Hash) digest is its **incremental twin**: the same per-row
encoding as §4, mapped to curve points and **summed**, so a production fold maintains it in
**O(rows-changed)/block** (add the new row's point, subtract the old) instead of re-reading the state.
Its purpose is **node desync detection** and **independent-implementor confidence** — a node gossips
one 32-byte digest per `(block_hash, height)` and a mismatch against a peer on the same block is a
divergence alarm. It is **advisory only**: never on-chain, never PoW-secured, never consensus — a
mismatch triggers resync/diagnostics, **never** a peer-ban or tx-rejection (promoting the computation
to consensus is an explicit non-goal). Reuses each impl's §13.1 secp256k1; the only new pinned
primitive is hash-to-curve. Design: `docs/notes/state-digest-ecmh-plan.md`.

**Accumulator.** A 33-byte value: a compressed point `0x02/0x03 ‖ X-be(32)`, or the all-zero sentinel
`0x00·33` for the identity ∞. The combine is **commutative** (so iteration order is irrelevant — no
sort, unlike §4) and **invertible** (so remove = add the negated point, and a reorg rolls back in
O(changes)). Negation is a one-bit prefix flip (`0x02 ↔ 0x03`); ∞ is its own inverse.

**Hash-to-curve (try-and-increment, pinned).**
```
H2C(pre):  for ctr = 0,1,2,…:
             h   = SHA256( "ECMHh2c1" ‖ pre ‖ u32_le(ctr) )        # 8 + |pre| + 4 bytes
             x   = be(h) mod p
             if x³+7 is a QR mod p (p≡3 mod4 ⇒ β=(x³+7)^((p+1)/4), accept iff β²==x³+7):
                  return 0x02 ‖ be(x,32)                            # ALWAYS even-Y prefix; ctr returned
```
The candidate is **always** serialized with prefix `0x02`; the actual Y is recovered (even root) only
when the point re-enters the curve math during `add`. `ctr` is fed to the vector digest as a single
byte.

**State digest.** Per §4 table `T` with row bytes `row(r)` **byte-identical to §4's per-row fields**
(including `owner_type` excluded from names, and §4's all-zero reset of inactive market fields), the
point is `P(r) = H2C("ECMHv1" ‖ tag(T) ‖ row(r))` with one-byte domain tags `names=01 commits=02
muts=03` (second-preimage separation between tables). Three sub-accumulators
`A_T = Σ P(r)`; the combined digest is `SHA256("ECMHtop1" ‖ A_names ‖ A_commits ‖ A_muts)` over the
three 33-byte points. Because the row encoding is §4's, ECMH
induces the **identical equality relation** as the §4 digest — verified in the C selftest
(`ecmh-equality ⟺ digest-equality`, plus order-independence and add/remove round-trip). The
time-triggered determinism the digest relies on (a lapsed lease / closed reserve / expired offer
materializing at a single canonical block — §4's "physically resets … before the next digest") is the
property the existing cross-impl soak already pins; ECMH inherits it unchanged.

**`sm ecmh`** is the pinned, portable primitive vector set (H2C KATs over fixed preimages, the ∞
identity, a tagged multiset sum proven commutative + invertible) folded into one `combined` digest,
run against each impl's own secp256k1 and required to print **byte-identical** output (Tier-2 — all 7
agree). **Frozen golden:** `combined = bc68b952ffd98cfb6fe8ab1033a6a195995298b94130cf8a531e86bbd00b0b28` (re-pinned 2026-07-13: H2C KAT preimage renamed to "pepenet"; verified identical across C + Go).
`run-conformance.sh` asserts it across all 7 impls. The state-level **`sm_state_ecmh`** (the per-table
sum over actual fold state) is implemented in **all 7 impls**, each with an equality-tracking selftest
(`ecmh-equality ⟺ digest-equality` over reordered/differing states). Its cross-impl agreement is pinned
by a second anchor: `sm_state_ecmh(empty_state)` — all three sub-accumulators ∞, so a fixed value —
which every impl prints as `empty_state_ecmh=` in its selftest and `run-conformance.sh` asserts equal
across all 7. **Frozen anchor:** `empty_state_ecmh =
3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0` (re-pinned 2026-07-08: names+commits+muts only).

## 14. Layers built on this namespace reference

This document covers the **namespace** — the consensus trust root. Separate **layers build on top of
it** and keep their own conformance harnesses; the namespace reference deliberately knows nothing about
them (so it stays reusable by any consumer). Current consumers:

- **Off-chain overlay layers** (social feeds, DNS, and the like) — separate repos that key off-chain
  data to names (canonical-feed functions, not consensus). An overlay harness may *link* this tree's
  crypto primitives (`secp256k1.c` / `sha256.c` / `ripemd160.c`) rather than re-vendoring them; each
  overlay keeps its own vectors + frozen goldens in its own repo.
- **Headless indexer** — the `namespace-indexer` repo links the namespace fold as its consensus engine (see the
  `headless-indexer` note).
