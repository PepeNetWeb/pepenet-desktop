# PepeNet Namespace — Action State Machine (v1)

This document defines the base layer of the PepeNet namespace: an identity +
engagement layer carried in Dogecoin `OP_RETURN` actions, designed to operate
strictly within the standard 80-byte `OP_RETURN` relay limit.

It specifies a **stateless indexing model**. Indexers verify identity and action
intent in **O(1)** directly from block data — no UTXO set is maintained or queried.
The one place the protocol needs network-wide economic awareness (the rent rate, §3.4)
is derived from the **coinbase** alone, so statelessness holds end to end.

The organizing split, which recurs throughout: **the chain settles; gossip discovers.**
Permanent ownership and value facts go on-chain; everything social, advisory, or
price-finding (reactions, the marketplace's discovery/negotiation/auctions, DMs) lives
in the off-chain gossip layer (§5). A reference pure-C P2P client ships with this spec.

> The chain is the source of truth; clients only *interpret* — see §5.

---

## 0. Foundations

- A PepeNet action lives in `OP_RETURN` output(s) of a normal DOGE tx.
- An output is addressed by **`txid + vout`**. There is ~one `OP_RETURN` per tx today,
  but every reference uses `txid+vout` so it survives the move to multiple `OP_RETURN`s
  per tx (which several batching features in this spec are designed to exploit, §3.5).
- Standard relay caps `OP_RETURN` data at **80 bytes**. All actions fit inside 80; a few
  (batch CLAIM, multi-target TRANSFER) reach their full power only once multi-`OP_RETURN`
  relay is available, and degrade gracefully until then (§3.5).
- **The address is the only identity.** Everything is attributed to the address that
  signs `vin[0]` (§4) — **a P2PKH key or a P2SH multisig keyset, attributed identically by
  `hash160` (day-1, §4)**. **Names are pure client decoration / a transferable digital
  asset layered on top** — never the canonical identity. Losing, expiring, or
  transferring a name never changes who authored anything.
- **The burn carries meaning only where the burned amount *is* the signal.** Three places:
  a **vote weight** (§3.8), name **rent** (CLAIM/RENEW, §3.4), and the market **reserve deposit**
  (RESERVE, §3.7). Everywhere else (COMMIT, TRANSFER, RELEASE, SELL, SETTLE) the
  action's `OP_RETURN` carries **no required burn** — the Dogecoin **miner fee** is the only cost,
  and it is sufficient anti-spam. A market *payment* (the RESERVE pay-leg and the SETTLE remainder,
  §3.7) rides in a **separate spendable output**, never in the action `OP_RETURN` itself.  (A
  value-bearing or zero-value `OP_RETURN` both relay and mine on Dogecoin; the dust-relay threshold
  is skipped for provably-unspendable outputs, so the action `OP_RETURN` itself is never
  dust-filtered. The dust limit binds only a *spendable* output — a buyer's market payment, §3.7 —
  never the action carrier.)
- **Recognition is by prefix, not value.** An `OP_RETURN` is a protocol action iff it
  begins with the 4-byte universal prefix (§1). For the burn-bearing ops the output
  **value** is then the signal; for the fee-only ops the value is ignored.
- **Strict, fail-closed parsing.** Anything malformed — wrong length for its opcode, bad
  prefix, invalid name, unsupported input type, failed signature — is **deterministically
  dropped**, never guessed at. Indexers must agree byte-for-byte on validity (§3.9, §4).

### Time vs. height — denominate by what a quantity measures

The protocol mixes two clocks, deliberately:

- **Wall-clock durations** — leases, the commit window, market windows, the reorg
  margin — are denominated in **time**, evaluated against block **Median-Time-Past**
  (MTP, BIP113-style: the median of the last 11 block timestamps; monotonic,
  miner-resistant, deterministic). Time-denomination makes these immune to a change in
  the host chain's block-time target: *a year is a year no matter how fast blocks come.*
- **On-chain positions** — claim priority ordering and the renewal bitmap's anchor — are
  denominated in **block height**, because ordering is intrinsically positional and a
  height anchor names a height.

This split is the answer to "what if Dogecoin 10×'s its block speed?": only the
height-denominated quantities scale with blocks, and each of those *should* (§8).

### Protocol constants

Fixed protocol constants — identical for every indexer or ownership resolution diverges.
A change ships only as a versioned **activation height** (forward-only, never retroactive;
§3.9).

| constant | value | meaning |
|----------|-------|---------|
| `DUST_FLOOR` | `1` koinu | the rent-rate clamp **floor** (§3.4); also the network dust limit a market *payment* output must clear |
| `RATE_CAP` | `1` DOGE | the rent-rate clamp **ceiling** (§3.4) |
| `REF_SIZE` | `200` bytes | value-agnostic byte count converting fee-per-byte → per-name rent (§3.4) |
| `FEE_WINDOW` | `10_080` blocks (~1 wk) | window over which the coinbase fee-per-byte median is taken; deliberately huge to make median-manipulation ruinous (§3.4) |
| `LEASE_QUANTUM` | `2_419_200` s (~28 d) | the rent rate's anchor — `rate` is koinu per name per `LEASE_QUANTUM`; ~1 DOGE/name/yr at current fees (§3.4) |
| `BILLING_UNIT` | `86_400` s (1 d) | lease-extension granularity; leases extend in whole days (§3.3, §3.5) |
| `MAX_LEASE` | `31_536_000` s (~365 d) | cap on how far ahead of now a lease may extend (§3.3) |
| `COMMIT_EXPIRY` | `18_000` s (~5 h) | a commit's live window; self-prunes after (§3.2) |
| `RESERVE_WINDOW` | `18_000` s (~5 h) | a reserve's exclusive-buy window; also the SELL window floor (§3.7) |
| `REORG_BUFFER` | `7_200` s (~2 h) | margin keeping ordered time-boundaries apart with reorg slack (§3.7, §5) |
| `RESERVE_DEPOSIT_BPS` | `100` (1.00 %) | total reserve deposit, basis points of `price` (§3.7) |
| `RESERVE_BURN_BPS` | `50` (0.50 %) | deposit leg **burned** |
| `RESERVE_PAY_BPS` | `50` (0.50 %) | deposit leg **paid to seller** |
| `MAX_ANCHOR_AGE` | `1024` blocks | max staleness of a renewal/transfer bitmap height anchor (§3.5) |

**Client reorg-trust is *not* a protocol constant.** "How deep before I believe an
ownership flip or a settle?" is a per-client risk choice (it may use depth, elapsed time,
or cumulative chainwork), applied at display time, and never gates the deterministic fold.
The protocol enforces a margin only where two *time-boundaries must stay ordered*
(`REORG_BUFFER`, §3.7/§5) — see §7.

### Encoding primitives
- `txid` — 32 bytes, internal (wire) byte order. (Explorers show the byte-reversed form;
  reverse it back before putting it in a payload.)
- `vout` — 4 bytes, little-endian `uint32`.
- `address_hash` — 20 bytes, the legacy `hash160` = `RIPEMD160(SHA256(pubkey))`.
- `name` — UTF-8 bytes, validated per §3.1; length implicit from the field/`OP_RETURN` size.
- `height` — 5 bytes, little-endian (the bitmap anchor, §3.5; 5 bytes spans ~10⁶ years even
  under a 10× block-speed increase).
- `price` / `value` koinu — 8 bytes, little-endian `uint64`; always compared in unsigned ≥64-bit.

---

## 1. Message Framing & The Universal Prefix

Every protocol action begins with a strict **4-byte header**. `0xFF` is the escape byte:
because `0xFF` is impossible in valid UTF-8, indexers separate actions from plain text
posts with no content heuristics.

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `0xFF` | UTF-8 escape / action flag |
| 1 | `0x50` | `'P'` |
| 2 | `0x4E` | `'N'` |
| 3 | `[opcode]` | 1 byte, `0x01`–`0x0A` |

**Text posts** carry no prefix: a burn-backed `OP_RETURN` whose **entire payload** is
strict-valid UTF-8 (RFC 3629 — reject overlong encodings, lone surrogates `U+D800`–`U+DFFF`,
and code points `> U+10FFFF`) is an undecorated text post. The demux is a **whole-payload**
validity test, not a first-byte test: a payload that starts valid but contains an invalid
sequence later is **not** a text post (it falls through to *ignore*). Every indexer MUST use
the identical strict rule, or two indexers disagree on post-ness. Identity is unaffected
(names are ASCII and the `0xFF` flag is unambiguous), so this can never fork the namespace,
only per-view tallies.

**Why a post still requires a burn (`value > 0`) when actions are fee-only.** Action ops drop
the burn requirement because their miner fee + prefix already gate spam. A *text post* keeps the
`value > 0` floor for a different reason: much of the existing `OP_RETURN` traffic on the chain is
automated, zero-value, and incidentally valid UTF-8 (timestamps, anchors, machine markers) — none
of it ever burns, because it has no reason to. Requiring even a 1-koinu burn is therefore the
cheap, deterministic signal that separates an *intentional* PepeNet post from ambient zero-value
`OP_RETURN` noise; a zero-value valid-UTF-8 `OP_RETURN` falls through to *ignore* (§6).

---

## 2. The Action Registry

Ten opcodes in **two groups** (the retired PURGE *and* the display handle both moved off-chain —
§3.8, §5; the registry carries no gap). Genesis ops (`0x01`–`0x02`) are live from block 0;
everything else (`0x03`–`0x0A`) switches on **atomically** at a single, publicly-announced
`ACTIVATION_HEIGHT`
(§3.0). Wire formats are summarized here and specified per-op below.

| Opcode | Action | Payload | Value field |
|--------|--------|---------|-------------|
| **Genesis — live from block 0** | | | |
| `0x01` | VOTE_UP | `txid`(32) + `vout`(4) | **weight** (≥ `DUST_FLOOR`) |
| `0x02` | VOTE_DOWN | `txid`(32) + `vout`(4) | **weight** (≥ `DUST_FLOOR`) |
| **Gated — live at `ACTIVATION_HEIGHT`** | | | |
| `0x03` | COMMIT | `commitment`(32) | — |
| `0x04` | CLAIM | `salt`(32) + `name` | **rent** → lease (water-fill §3.5) |
| `0x05` | RENEW | *(none)* [+ `anchor`(5) [+ `flags`]] | **rent** → lease (water-fill §3.5) |
| `0x06` | TRANSFER | `target`(20) [+ `anchor`(5) + `flags`] | — |
| `0x07` | SELL | `price`(8) + `window`(4) + `name` | — |
| `0x08` | RESERVE | `name` (one per `OP_RETURN`) | **burn-leg** (deposit, §3.7) |
| `0x09` | SETTLE | `name` (one per `OP_RETURN`) | — (payment is in outputs) |
| `0x0A` | RELEASE | `anchor`(5) + `flags` | — (fee-only) |

---

## 3. Action Logic & Constraints

### 3.0 Activation & launch (fair launch)

Posts and votes are **ungated** (live from genesis): a post is attributed to its
`vin[0]` address and a vote is anonymous burn-weight, so neither races for a scarce
namespace — the network bootstraps content and engagement before identity opens. (Author
self-deletion is the off-chain RETRACT, §3.8 — no genesis opcode.)

Everything else — COMMIT/CLAIM, RENEW, TRANSFER, RELEASE, and the SELL/RESERVE/SETTLE
market — switches on **atomically** at a single, publicly-announced `ACTIVATION_HEIGHT`. Gating
is **forward-only**: a gated action below the height is **dropped** and **never** retroactively
applied. Folding the whole names layer into one gate is deliberate: **commit–claim front-run protection is
mandatory from the first block any name can be claimed** (§3.2), so the highest-stakes launch window
is structurally protected. Because a CLAIM needs a commit in a *strictly earlier* block and commits
are themselves gated, the first commits land at `ACTIVATION_HEIGHT` and the first claims at
`ACTIVATION_HEIGHT + 1` — a built-in **blind commit phase** before any name is revealed.

**No mint price floor.** The fair-launch mechanism is the announced height + first-come
priority (§3.2) — there is no elevated burn on a fresh claim. A nonzero launch floor would
be *destroyed* by everyone who loses a contested-name race, torching coin on exactly the
hot names. Claims pay only their lease rent (§3.4); anti-squat is the permanent stack
(rent ∝ names × time + name-is-decoration). Because commits are **opaque**, a launch
front-runner cannot target a specific name's commit, so a contested hot name resolves as a
fair blind auction among everyone who independently wanted it — never a snipe of one user's
revealed intent.

### 3.1 Identity — the owned set

An address **owns a set of names** (0..many) — the *owned set*. Each name is fully and
identically owned and blocks any other claim until its `lease_expiry`. Which owned name an address
presents as its public `@name` — its **handle** — is an **off-chain, address-signed declaration**
(§5), not chain state: the chain settles *ownership*; presentation is a display choice (§3.9).
Multi-name-per-address (rather than one-name-per-address) is chosen on
**UTXO-bloat** grounds: 1-name-per-address would force a separate funded address — hence a
separate UTXO — per name, and live UTXO-set bloat is far worse for every full node than
prunable index rows. With multi-name, index bloat scales with *users*, not *names*, and the
names themselves are `OP_RETURN` data (never in the UTXO set).

**Identity is global shared state** — every indexer must resolve the same owner — so claim
priority and the rent rate are protocol-fixed, never client policy (§3.9).

**Name validation** (deterministic; invalid → action ignored): canonical charset
`[a-z0-9_]`, length **1–20** bytes, no structural rules. The canonical key is the lowercase
form. ASCII-only kills Unicode homoglyphs but not ASCII confusables (`0/o`, `1/l`, `rn/m`) —
so names are **never** trusted as identity on their own (the address fingerprint is, §5).

**Two ways to give up a name — RELEASE (active) and lapse (passive).** Stop renewing and a name
**lapses** for free when its lease ends — the zero-cost path when you don't care *when* it frees.
**RELEASE (§3.6)** is the on-demand version: one fee-only tx returns selected names to the pool
**immediately**, without waiting out a prepaid lease. It earns its byte where lapse can't —
freeing a long-prepaid name *now*, or selectively scrubbing gift-spam (§3.6) out of your owned
set (and your renew bitmap) instead of carrying it until it lapses. There is still no general
"pending" state; a name **listed for sale** (§3.7) is the one *locked* state — still owned and
**still renewable**, but frozen against TRANSFER/RELEASE/re-SELL until it settles or the listing
ends.

### 3.2 Claiming — mandatory commit→claim (front-run protection)

Minting a name is a **CLAIM**, and **every CLAIM must be backed by an earlier COMMIT** — there are
**no naked claims**. The commit must be **at least one block deep** when the claim confirms
(`commit_height < claim_height` — a *strictly earlier* block; same-block is too shallow). A claim
with no live matching commit ≥1 block deep is **dropped**; it mints nothing.

The hole this closes is the *first* registration of an unowned name, where the claim tx is itself
the demand signal an attacker snipes and ransoms back. Mandating a ≥1-deep commit closes it
**uniformly**: a reactive attacker only learns the name from your revealed CLAIM, so the earliest
commit they can make is in your claim's block — and their own claim then can't confirm until a
*strictly later* block, losing on `claim_height` before fee or tx-index is ever consulted (below).
Making it mandatory (no bare path) means **no claim is ever exposed** — there's no "I skipped the
commit" footgun; clients register every name as **commit → wait one block → claim**.

**COMMIT (`0x03`).** Payload: `commitment` (32 bytes) =
`SHA-256(salt ‖ name ‖ author_hash160)`, with `salt` **exactly 32 bytes** of entropy and
`author_hash160` = the committer's `vin[0]` identity (§4). The committed `salt` must be the
**same fixed-width 32 bytes** the matching CLAIM later reveals — that fixed width is what keeps
`name`'s length implicit in the CLAIM payload, so the two cannot disagree. The indexer records
`{commitment, commit_height, tx_index}` and nothing else — a commit **mints nothing, owns
nothing, leaks nothing** (the opaque hash reveals neither name nor author). It is live for
`MTP ∈ [commit_time, commit_time + COMMIT_EXPIRY]` and self-prunes after. Fee-only.

> **Salt is load-bearing.** The namespace is small (`[a-z0-9_]`, ≤20 bytes), so
> `SHA-256(name)` alone is brute-forceable — the 32-byte salt is what makes the commitment
> opaque.
>
> **Author-binding is the security core (fork-prone — pin in vectors).** The
> `author_hash160` term stops a *commitment-copy* attack: an attacker who copies a victim's
> 32-byte commitment from the mempool and re-posts it under their own tx gains nothing — the
> value embeds the *victim's* author, so only the victim can produce a matching claim, and
> the attacker never learns `salt`. A copied commitment is inert; at worst it hands the
> victim an *earlier* matching row. An indexer omitting the author term would let the copy
> attack steal the name at claim.

**CLAIM (`0x04`).** Payload: `salt` (32) + `name`. Mints `name` into the author's owned set
(owned, **not auto-displayed** — presenting it as your `@handle` is a separate off-chain step, §5)
and buys its initial lease — the burn *is* the duration (§3.3–§3.4), so a bigger burn buys a longer
first lease (capped at `MAX_LEASE`). CLAIM is the *only* mint; minting and displaying are orthogonal
— **the `@handle` is an off-chain declaration (§5), not an opcode.** So a full "register @alice" is
COMMIT → CLAIM on-chain plus an off-chain handle declaration (clients bundle it); a portfolio buyer
just COMMIT → CLAIM and declares nothing. The OP_RETURN **value is the rent**: it buys `⌊value × LEASE_QUANTUM / (rate ×
BILLING_UNIT)⌋` days of lease and must cover at least one day (§3.4).
A name **already owned** → **dropped**. Otherwise the claim mints **iff** a **live** commit row
exists whose value equals `SHA-256(salt ‖ name ‖ author_hash160)` (author = this claim's own
`vin[0]`) in a **strictly earlier block** (`commit_height < claim_height`, still within
`COMMIT_EXPIRY`); the **earliest** such row sets `commit_height`. **No matching ≥1-deep commit → the
claim is dropped** (no FCFS fallback). A **same-block** commit is too shallow and does **not** back a
claim — it would carry `commit_height = claim_height`, no better than the revealed-intent race the
commit exists to defeat.

**Priority — the tuple `(claim_height, commit_height, tx_index)`.** Among competing fresh
claims for one name the winner minimizes this tuple:
- **`claim_height`** (the claim's own block) is primary, so a *later* claim can **never**
  displace an earlier holder — no retroactive rug.
- **`commit_height`** is secondary — *this is the whole protection*. Because every claim's commit
  sits in a strictly earlier block, a reactive attacker (who learned the name only from your CLAIM)
  can have committed no earlier than your claim's block, so their `commit_height ≥ claim_height >
  your commit_height`: they lose **before fee or tx-index is consulted**. Two honest early committers
  for one name settle by the earlier `commit_height` (rewarding the earlier blind bid).
- **`tx_index`** is the final tie-break (two genuine same-`commit_height` rushers settle by
  chain order, as FCFS does).

**The 1-block floor is the point; the residual is a reorg.** A same-block commit doesn't protect —
it ties any same-block attacker on `commit_height`, collapsing to a tx-index fee-race — so the floor
isn't a tax, it's *what makes the ordering bite*: it forces a reactive attacker's claim into a
strictly later block. Beyond the one mandatory block, "how much deeper to bury the commit" is
**client-side risk choice**: the only residual is an adversary who can rewrite *k* blocks to splice
a commit+claim ahead of your claim — and the 1-deep rule already makes that a **≥2-block** rewrite
(commit block + claim block). Bury the commit deeper to insure against deeper reorgs; exposed as a
slider, defaulted low.

**What it closes / doesn't.** Closed for **every** claim (no opt-out path): reactive front-running
of a quiet fresh claim — the ransom *and* the denial — at any fee. Open (and accepted): *camping a
predictable name* (an attacker who pre-commits to a foreseeable high-value name and refreshes every
`COMMIT_EXPIRY` can still contest its claim — bounded by refresh cost, reaches only names you can
predict), and *lapse-sniping* (a lapsed name's availability is public, so there's no hidden intent —
it resolves as a **blind auction**: everyone commits opaquely, the earliest valid commit wins).

### 3.3 Leases — pay-for-duration

A name carries `lease_expiry` (an MTP timestamp). It is **owned** iff `MTP(tip) <
lease_expiry`. You buy exactly the lease time you want:

- **The burn *is* the duration** — there is no duration field (it would just restate what the
  burn already determines). A burn `B` over `count` names buys `⌊B × LEASE_QUANTUM / (rate ×
  BILLING_UNIT)⌋` total **name·days** of lease (§3.4), allocated across them by the water-fill in
  §3.5, each capped so its `lease_expiry` never exceeds `MTP_now + MAX_LEASE` (you may
  stack/pre-pay up to that ceiling). **Leases extend in whole days** (`BILLING_UNIT`), not 28-day
  quanta — fine enough to renew for 30 or 200 days, yet coarse enough that the per-day price stays
  well above `DUST_FLOOR` and lease precision stays inside MTP's ~block-scale resolution. Cost is
  **linear** in lease time — want a shorter lease, burn less.

This **pay-for-duration** model is chosen for **host
network health**: the dominant permanent host cost is **chain bloat**, and renewal traffic =
`Σ (1 / lease_length)`. A 28-day renewal and a 365-day renewal cost the chain the same one
`OP_RETURN`, but the long one covers 13× the time — so **fewer, longer leases are strictly
cheaper for hosts per lease-day**. Crucially, **linear pricing already nudges the right way
without any protocol discount**: a holder choosing one 365-day lease over thirteen 28-day
renewals pays 13× fewer *miner fees*, so the chain's own fee aligns the holder's incentive
with host health. Anti-squat is purely "pay rent ∝ names × time held."

**Lapse → pool.** When `MTP` passes `lease_expiry` the name returns to claimable supply
(any off-chain handle declaration naming it stops being honored, §5) and is **immediately
reclaimable** by a new COMMIT/CLAIM. A
reclaim that a later reorg reverses (by restoring the prior owner's renewal) is dropped on
replay (§6) — the same client-side reorg risk as any fresh claim, and a lapse-reclaim is a blind
auction regardless (commit-then-claim like any mint, §3.2). There is no protocol-level cooling window.

**Targeted denial is not prevented at the namespace layer — say so plainly.** Any one name
can be held, or denied to everyone, indefinitely for rent. The defense is foundational: a
name is decoration, not identity (§5). Read the rent as anti-*bulk-hoarding* friction (every
hoarded name bleeds rent on its own clock), never a guarantee you can hold one specific name
against a determined adversary.

### 3.4 The burn — the coinbase fee oracle

The rent rate for CLAIM/RENEW is value-stable, governance-free, and **stateless**:

```
fee_per_byteᵢ = (coinbase_output_totalᵢ − subsidy(heightᵢ)) / block_bytesᵢ      # per block
rate          = clamp( median(fee_per_byteᵢ over last FEE_WINDOW blocks) × REF_SIZE,
                       DUST_FLOOR, RATE_CAP )                                     # koinu per name·quantum
# no duration field — a burn B buys T = ⌊B × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋ name·days, water-filled (§3.5)
```

- **Stateless** — total fees come straight from `coinbase_output − known_subsidy(height)`,
  computable from the block alone with **no UTXO set**. This is what keeps fee-awareness
  inside the stateless model.
- **Value-stable** — it tracks real blockspace value, self-adjusting as DOGE moves; no
  governed constant to peg, no oracle to centralize.
- **Floored** at `DUST_FLOOR` (graceful degradation when fees are absent/degenerate — never
  forks, never breaks), **capped** at `RATE_CAP = 1 DOGE` (fits Doge's ethos across the value
  range; bounds miner grief), **median-smoothed** over `FEE_WINDOW` (robust to single-block
  fee stuffing).
- Concretely: at recent Dogecoin fee densities (~0.0004 DOGE/byte marginal; the oracle's
  block-average runs somewhat under), `REF_SIZE = 200`, and the 28-day `LEASE_QUANTUM`, the rent
  lands on a deliberately round **~1 DOGE/name/year** at full-block density, scaling down with
  block slack; `REF_SIZE` is the calibration dial (§9) and the rent floats with the fee market.
  `RATE_CAP = 1 DOGE/quantum` (≈ 13 DOGE/yr ceiling) sits ~13× above today's rate.

**Manipulation resistance — the window is deliberately huge.** The defense is two-part: the
**median** (already robust to a handful of outlier blocks) plus a **massive smoothing window**
(`FEE_WINDOW = 10_080` blocks, ~1 week). The attack to deny is a miner/cartel **under-claiming**
fees — mining low-fee blocks to drag the median toward `DUST_FLOOR` and make rent ~free. Moving
a median over ~10k blocks means controlling **>50 % of a week's blocks while forgoing their
legitimate fee income** the entire time — economically ruinous. The opposite push (inflating the
rate by stuffing blocks with self-paying high-fee txs, near-free since the miner reclaims the fee
in its own coinbase) is bounded the other way by `RATE_CAP = 1 DOGE`, by the same
>50 %-for-a-week requirement, and by the opportunity cost of displacing real fee-paying txs. So:
the median bounds transient spikes, the window bounds sustained suppression, the cap bounds
sustained inflation. A week's lag is a *feature* for a rent that should move slowly, not a cost.

The rate is evaluated at the action's **confirmation** height (deterministic for the fold),
so it drifts after you sign — which is exactly why funding is forgiving (partial-fill, §3.5).

### 3.5 Batching — bitmaps & partial-fill

**There are no per-tx count caps anywhere — any cap is *relay*, never *protocol*.** Every state op
batches, bounded only by transaction size and funds (the bitmap ops fill one `OP_RETURN`; the
market ops place several `OP_RETURN`s in one tx, §3.7). The anti-abuse on every op is **economic**
(a burn or payment per name) or **exclusivity** (the market) — never structural counting.

**The burn is the duration; the rent is applied as fully as possible (water-fill).** There is no
`duration` field — it would be redundant, since a burn `B` over `count` names at `rate` already
fixes the lease time. Omitting it saves a byte (a 4-byte renew-all, ~568 selective names) and
lets the rent be applied *fully*, never wasted:

1. The burn buys `T = ⌊B × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋` total name·**days** — the
   `LEASE_QUANTUM/BILLING_UNIT` factor (= 28) rescales the per-quantum `rate` to a per-day price;
   take the numerator multiply in ≥128-bit. Fail **closed** if `T = 0`.
2. Spread `T` **evenly** across the targeted names — but name *i* can absorb only
   `hᵢ = ⌊(MAX_LEASE − (expiryᵢ − now)) / BILLING_UNIT⌋` more **days** before it hits the
   `MAX_LEASE` ceiling.
3. **Water-fill:** raise a uniform level `λ` (each name takes `min(hᵢ, λ)` days); a name that
   caps drops out and its share flows to the rest, until `T` is spent or every name caps. Any
   integer remainder after the even level goes `+1` **day** to the first headroom-having names in
   ascending-lexicographic order; each name's `lease_expiry += add × BILLING_UNIT`.

So a fee spike neither drops names nor wastes coin: it buys a *shorter, evenly-shorter* lease
across the whole batch, and a name that would over-shoot `MAX_LEASE` redirects its rent to the
names that still need it. (The 'funded for a year, the rate doubled' case: every name simply gets
~half a year, none lapse.) This is a deterministic integer computation — **fork-prone, pinned by
conformance vectors** (§6). The only regime where a name still goes unrenewed is `T < count`
(funding below even **one day** per name): the first `T` names get a day and the rest none — far
below any honest renew.

**Payment ops (RESERVE / SETTLE) are one name per `OP_RETURN`, batched at the *transaction* level.**
Each carries exactly one listing (name length implicit from the `OP_RETURN`, nothing to parse), and
its amount is a fixed, indivisible per-name fraction of that name's listed price — nothing to
water-fill or partial-fill. To act on several listings at once you place **several RESERVE/SETTLE
`OP_RETURN`s in one transaction** (the same multi-`OP_RETURN` unlock the rest of the spec rides on,
§0), and the money stays **individually split**: each listing's burn-leg is its *own* RESERVE
`OP_RETURN` value, and each listing's pay-leg / settle-remainder is its *own* **exact-value output**
to that seller — never summed. The count per tx is bounded only by transaction size and standard
relay (today one `OP_RETURN`/tx; many once multi-`OP_RETURN` relay lands), **never by the
protocol**.

**Per-tx output matching (consensus-critical, deterministic).** A listing's owed amount is matched
against the transaction's *spendable* outputs: processing the tx's market `OP_RETURN`s in `vout`
order, each **consumes the lowest-`vout` not-yet-consumed output whose `(scriptPubKey, value)`
equals `(seller, owed)` exactly**; if none remains, that op **drops**. Consume-once + exact-value
forces the split — a summed output matches *no* single listing's owed amount — and the `vout`-order
rule keeps it byte-identical across indexers.

**Target selection per op:**

| op | selection |
|----|-----------|
| CLAIM / RESERVE / SETTLE | one `name` per `OP_RETURN` (batch >1 needs multi-`OP_RETURN`) |
| RENEW / RELEASE | **bitmap** over your owned-set (which the indexer already tracks) |
| TRANSFER | bitmap over owned-set → one target |

#### RENEW wire format (the pinned form)

```
RENEW all        [0xFF PN 0x05]                          = 4 B   renew every owned name (water-fill the burn)
RENEW all (safe) [0xFF PN 0x05][anchor:5]                = 9 B   same, reject if the set changed since H
RENEW selective  [0xFF PN 0x05][anchor:5][flags:1..71]   = 10..80 B   ~568 names
```

- Bits index your owned-set: all owned names **lexicographically** from bit 0. Bit *i* set ⇒ renew
  that name. Length disambiguates the three modes (`4 / 9 / 10..80`; lengths `5..8` invalid). (A
  holder of ≥569 names can't selectively address one past bit 567 inside the 71-byte flag field —
  they use renew-all, or wait for the multi-`OP_RETURN` offset byte (§9); with the handle now
  off-chain there is no privileged always-reachable identity name to protect.)
- The **5-byte absolute height anchor `H`** pins the bitmap's meaning. A per-owner
  `last_set_mutation_height` (bumped on any CLAIM/TRANSFER/RELEASE/SETTLE/lapse touching the set
  **or its ordering**, for *either* party — SETTLE both adds to the buyer's set and removes from the
  seller's, so it bumps both. A SELL **listing** is deliberately *not* a mutation: the name stays in
  the seller's owned set (still renewable, §3.7), keeping its bitmap position, so a live RENEW bitmap
  spanning a listing is unaffected)
  makes selective renew **fail-closed**: valid iff `last_mutation ≤ H ≤ confirm_height` and
  `confirm_height − H ≤ MAX_ANCHOR_AGE`. If the set hasn't mutated since `H`, the live lexicographic
  ordering equals the snapshot ordering, so the bits are exact. Worst case under a race is a safe
  **reject-and-resend**, never a wrong-name renewal.
- **The upper bound stays `H ≤ confirm` — do not relax it forward.** It is tempting to allow
  `H ≤ confirm + slack` so a shallow *shrink-reorg* (you anchor at the tip, a 2-block reorg
  then confirms your tx at `confirm < H`) doesn't drop the renewal — but that is **unsound**.
  Every real mutation lands at a height `≤ confirm`, so the moment `H ≥ confirm` the guard
  `last_mutation ≤ H` is **vacuously true** and can no longer catch a stale bitmap — including
  one snapshotted in an *orphaned* block the reorg just erased. So the shrink-reorg drop is the
  **safe** outcome (fail-closed), and the real fix is client-side: **anchor a few blocks back**
  (`H = tip − ~6`, well inside `MAX_ANCHOR_AGE`) so `confirm ≥ H` survives any shallow reorg and
  the snapshot sits on already-buried chain. A recent self-mutation then trips the guard
  (resend), exactly as intended. This also keeps the denomination right (§8): the anchor is a
  *height* and a reorg is a *depth*, so the slack that matters is **how deep you bury the
  anchor**, never a forward fudge on the bound (and never the time-denominated `REORG_BUFFER`).
- **renew-all** is position-independent (renews the whole live set), so the cheap form needs
  **no anchor** — a small holder pays 4 bytes total. The `all (safe)` form carries the anchor
  only to fail-closed if you're exact-funded and your set grew before confirm.
- The soft cap (~568 selective names per 80-byte tx) is a *selectivity* limit, not an
  ownership limit: renew-all covers any number, and selectively addressing names past ~568 waits
  for multi-`OP_RETURN` (an offset byte lifts it; §9). The flag byte-length scales with ownership,
  so the cost falls on large holders.
  (The same owned-set ordering governs TRANSFER's and RELEASE's bitmaps. RESERVE and SETTLE carry
  no bitmap — one name per `OP_RETURN`, batched at the tx level, §3.7.)

**TRANSFER** mirrors this: `[0xFF PN 0x06][target:20]` transfers all owned names to `target`;
`[0xFF PN 0x06][target:20][anchor:5][flags]` transfers the selected ones (the 20-byte target
eats flag space → ~400 names/tx). Lease conveys (§3.6).

### 3.6 TRANSFER (`0x06`) & RELEASE (`0x0A`) — gift & relinquish

TRANSFER moves one or more owned names to another address. It is **gift-only** — there is no
`cost` field; *paid* sales go through the market (§3.7), whose escrow is what makes them
trustless. Fee-only.

- The moved names enter `target`'s owned set **immediately and irreversibly** (no acceptance
  step; the sender cannot claw back). **The remaining lease conveys** — prepaid rent travels
  with the name, fully visible in index state, so a recipient/buyer sees exactly how much
  time they're getting. (Conveyance is the only sensible rule for
  prepaid time, and it's what makes a bought name's lease meaningful, §3.7.)
- A received name is **never auto-displayed** (the defacement defense): an unsolicited transfer
  shows on no one. The recipient may declare it as their off-chain handle (§5) if they want it
  shown; otherwise it sits silently and lapses when its (conveyed) lease ends.
- **Gift-spam is priced at the mint.** To push junk names at a victim the attacker must first
  CLAIM them — paying the rent for whatever lease they convey. So forced names into a
  victim's set are *paid for* by the attacker; the victim never renews them (they lapse on
  the attacker's dime), uses renew-all-cheap (immune to the bitmap churn), and hides them
  client-side. The storage is economically bounded — occupancy is rented (§3.9).

**RELEASE (`0x0A`).** Payload: `anchor` (5) + `flags` (1..71) — a bitmap over your owned set in
the **same lexicographic ordering as RENEW** (§3.5), under the **same anchor guard** (fail-closed if
the set mutated since `H`, so a stale bitmap never releases the wrong name). Selected names return
to the claimable pool **immediately** at this tx's position in the fold (any off-chain handle
declaration naming a released name stops being honored, §5). Fee-only; **no burn and no
refund** — the remaining prepaid lease is forfeited (the rent was already burned, exactly as on
a lapse). A released name is **immediately reclaimable** by a new COMMIT/CLAIM, identical to a
lapse (§6); a reclaim a later reorg reverses is dropped on replay, the same client-side reorg
risk as any fresh claim (§3.2).
RELEASE touches only names you **own and are not currently listing** — a name listed for sale
(§3.7) is locked (still owned and renewable, but frozen against RELEASE/TRANSFER/re-SELL until it
settles or the listing ends). There is deliberately **no release-all** mode: "abandon everything" is what lapse
already does for free, so RELEASE is the *selective, now* tool (~568 names/tx), and the
wrong-name footgun is caught by the anchor guard.

### 3.7 The names market — SELL, RESERVE, SETTLE

Paid sales are **fixed-price and escrow-first**. The flow:

```
SELL(name, price, window) ──▶ [off-chain discovery / negotiation / auctions, §5] ──▶ RESERVE(name) ──▶ SETTLE(name)
```

The two design pillars and why they're both load-bearing:
- **Escrow-first** — SELL **locks** the name: while listed it cannot be TRANSFERred, RELEASEd,
  or re-SOLD, so the seller can't move it out from under a buyer. (The name stays in the seller's
  owned set and **stays renewable** — keeping the lease alive only benefits the eventual buyer, so
  it's deliberately allowed; only *movement* is frozen.) This closes the co-sign-swap front-run: a
  seller can't grant the name in a co-signed tx and simultaneously transfer it away using a
  different UTXO, because TRANSFER on a listed name is **rejected** for the listing's life.
- **Fixed price** — the price is committed on-chain at SELL, immutable. This closes the
  *dynamic-price* front-run: with nothing to infer at reserve time, a seller can't
  self-reserve at a cheap inferred price. The escrow is what makes publishing a fixed price
  *safe* (without escrow a published price would be front-runnable precisely because the name wasn't yet
  escrowed). A reserve price floor was considered and rejected — being seller-set, the seller
  just sets it low and signs high; only committing the *actual* price removes the dynamism.

**SELL (`0x07`).** Payload: `price` (8, `> 0`) + `window` (4, seconds) + `name`. Requires the
sender **own** `name` and that it not already be listed. Lists it (locking it from
TRANSFER/RELEASE/re-SELL per the escrow-first pillar above) at the fixed `price`; records `{seller (hash160 + script
type, §4 Rule 2), price, offer_expiry = MTP_now + window}`. The lease conveys at settle.
**No cancel op — but reclaimable.** A seller can pull a name back out of escrow by **buying its
own listing** (self-RESERVE + self-SETTLE): the pay-leg and the 99 % are self-payments, so it
nets to just **0.5 % burn + 2 fees**, and both txs can share a block — an immediate reclaim. So
escrow makes the name **unmovable** (no TRANSFER away — the co-sign-swap defense) and the price
**fixed**, but **not** un-reclaimable. Because reserves are open (no co-sign), the seller is also
a fee-market participant in their *own* listing — they can self-RESERVE to out-bid an incoming
buyer on `tx_index`, and no rule forbids it (a "no self-reserve" check dies to puppet addresses).
This only pays off on an **underpriced** listing (a fair-priced seller just fills the sale), so
it acts as built-in misprice-correction, not a hole — a buyer reserving a suspiciously cheap
listing risks the seller out-bidding them for the 1 % (clients warn, §5). Fee-only.

- `window` is bounded `RESERVE_WINDOW ≤ window ≤ (lease_expiry − MTP_now) − REORG_BUFFER`; a
  name is listable iff it has at least `RESERVE_WINDOW + REORG_BUFFER` of lease left. The upper
  bound pins `offer_expiry ≤ lease_expiry − REORG_BUFFER`, so the name can never lapse to the
  pool while a sale is live (the "pay for an already-free name" trap is structurally
  impossible, with reorg slack). `window = 0` defaults to `RESERVE_WINDOW`; out of range →
  ignored.
- The configurable window lets a broker list for weeks on one fee (a fixed short window forces
  daily relists — more on-chain `OP_RETURN`s, gaps where the name is unlisted). The cost is
  **price staleness**: a listing's `price` is fixed koinu and cannot be repriced *in place* — to
  re-price, the seller reclaims it (self-buy, ~0.5 %) and re-SELLs at the new price. Clients MUST
  disclose the chosen expiry and that the price is fixed for the listing's life (repricing costs
  a ~0.5 % reclaim).

**RESERVE (`0x08`).** Payload: a single `name` — one open listing per `OP_RETURN` (reserve several
listings at once by placing several RESERVE `OP_RETURN`s in one tx, §3.5). **Open — no co-sign**
(the public listing *is* the seller's authorization). A RESERVE is a **non-refundable bid for an exclusive SETTLE option**: the indexer
is a passive observer with no custody, so **both deposit legs settle unconditionally** the instant
the RESERVE confirms — the `burn_leg` is destroyed in its own `OP_RETURN`, the `pay_leg` is already
the seller's. Deposit = `RESERVE_DEPOSIT_BPS` (1 %) of `price`, split two legs:
`burn_leg = max(DUST_FLOOR, ⌊price × RESERVE_BURN_BPS / 10000⌋)` carried as the RESERVE
`OP_RETURN`'s own value (`≥ burn_leg`), and `pay_leg = max(DUST_FLOOR, ⌊price × RESERVE_PAY_BPS /
10000⌋)` paid to the seller in **its own exact-value output** (matched per the `vout`-order
consume-once rule of §3.5). Both legs computed
in **≥128-bit** (`price × bps` overflows `int64` — and `price` is an attacker-typed field in a
SELL payload, free to inflate near `2⁶⁴`, so a 64-bit indexer would wrap to a near-zero deposit
and fork; this multiply is the one overflow that is *free* to trigger and the most important to
pin).

- **First-in-chain-order wins the option.** Among reserves for one name the lowest
  `(height, tx_index)` becomes the **exclusive** buyer — the only address that may SETTLE — with a
  settle window `reserve_expiry = min(MTP_now + RESERVE_WINDOW, offer_expiry)`. **The clamp to
  `offer_expiry` is load-bearing:** without it a reserve placed late in the listing would carry a
  full `RESERVE_WINDOW` (> `REORG_BUFFER`) past `offer_expiry`, letting a SETTLE land after the
  listing closed (name already reverted to the seller) or even after the name lapsed — the
  boundaries would no longer nest (§6) and a settle could pay for a no-longer-listed name. Clamped,
  `reserve_expiry ≤ offer_expiry ≤ lease_expiry − REORG_BUFFER` always holds. A
  later reserve is a **structurally valid** tx that merely **fails to claim the option**; it is
  never *rejected*, and its deposit is **already spent** — the indexer cannot refund or un-burn a
  confirmed output (§6). A contested listing therefore resolves in the Dogecoin **fee market**
  (buyers RBF/CPFP for a lower `tx_index`); clients **MUST** act as mempool radar, warning that
  the 1 % is lost if you are outbid in the block.
- **Losers forfeit the 1 %** — 0.5 % burned, 0.5 % to the seller. A seller therefore does
  collect 0.5 % from every losing reserver, but this is **not a profitable harvest**: attracting
  contention requires underpricing that costs the seller far more than the take, so it nets out
  as a benign, mostly-deadweight by-product (clients warn buyers off hopeless reserves), never a
  subsidy to design around.
- **The winner's** two legs are non-refundable but **credited** toward `price` at settle, so the
  winning buyer's total outlay is exactly `price` (a loser simply loses the 1 %).

**SETTLE (`0x09`).** Payload: a single `name` — one reserved listing per `OP_RETURN` (settle several
at once via several SETTLE `OP_RETURN`s in one tx, §3.5). The exclusive reserver pays the
**remainder** `price − burn_leg − pay_leg` to the seller in **its own exact-value output** (matched
per the `vout`-order consume-once rule of §3.5) and claims the name; the lease conveys.
Only protocol timing gate: `MTP < reserve_expiry`. Settling with margin before `reserve_expiry` is
the buyer's job; waiting for the reserve to bury before paying is **client-side risk management**,
not a consensus rule.

**Accounting.** The two deposit legs (paid at RESERVE) plus the settle remainder sum to exactly
`price`, so the **buyer pays exactly `price`**; the seller nets `price − burn_leg` (≈ 99.5 %); the
`burn_leg` (≈ 0.5 %) is burned (an implicit market fee captured by no one). Every payment output is
an **exact** match, so matching is unambiguous and reuse is impossible.

**Security properties.**

| attack | status | mechanism |
|---|---|---|
| co-sign-swap front-run (seller moves name away) | **closed** | escrow-first — a listed name is movement-locked; TRANSFER/RELEASE/re-SELL on it are rejected |
| dynamic-price front-run (self-reserve at inferred price) | **closed** | fixed price — nothing to infer; and a self-reserve nets the seller only 0.5 % (the pay-leg returns to them) |
| harvest (seller collects 0.5 % from losing reserves) | **bounded, benign** | losers forfeit unconditionally, but baiting contention needs underpricing that exceeds the take — mostly deadweight burn, surfaced by client mempool-radar |
| double-full-payment (N buyers all pay full) | **closed** | exclusivity — only the winner pays the 99 % |
| voucher replay | **n/a** | no vouchers — price lives in escrow state |
| reserve-griefing (lock a listing) | **bounded, open** | costs 1 % per `RESERVE_WINDOW`, 0.5 % to the seller as consolation |
| settle-after-close (pay for a no-longer-listed/lapsed name) | **closed** | `reserve_expiry` clamped to `offer_expiry` — the settle window can't outlive the listing |
| batched-reserve leak (lose one race among several reserves in one tx) | **client tradeoff** | each reserve's leg forfeits independently; clients serialize hot names, batch cold ones |

The only genuinely *open* item is reserve-griefing — bounded and priced, not a hole. Clients
MUST disclose both deposit legs as non-refundable and that a contested reserve can forfeit them.

### 3.8 Engagement — votes (genesis); author self-deletion is off-chain RETRACT

**VOTE_UP (`0x01`) / VOTE_DOWN (`0x02`).** Anonymous (no name needed — only an attributable
`vin[0]`, §4), burn-weighted, cumulative. Net score = `Σ(up burns) − Σ(down burns)`; the burn
*is* the weight (not a ±1), with no undo. Each vote's `weight` must be **≥ `DUST_FLOOR`** (a
zero-weight vote carries no signal and is **dropped** — this is the "value field meets the op's
requirement" check of §6, identical for VOTE_UP and VOTE_DOWN). Sybil cost is the burn; whales are handled by
client web-of-trust filters (§5), not a one-vote rule — the same identity may vote any number
of times and every burn adds. Tallies are a **per-view** sum (not consensus identity state):
the only hard rule is the accumulator must **never silently wrap** (≥128-bit, or a fail-loud
64-bit `SUM`). Past finality the per-voter rows MAY be folded into a single per-post `(Σ up,
Σ down)` aggregate (score-identical; loses per-voter WoT detail on aged posts) — operational,
not a protocol rule.

**Author self-deletion is off-chain — RETRACT (no on-chain opcode).** On-chain PURGE was the
base spec's one internal contradiction: §3.9 forbids per-view signals from consensus, yet PURGE
"only instructs honoring clients to drop their cached copy — the raw bytes are on-chain forever."
It was pure per-view advice that nonetheless burned ~220 B of permanent chain data *and* left a
Streisand-pointer at the very post it wanted gone. It is the degenerate moderation verb where the
signer **is** the post's §4 author, so it moves to the off-chain handle-signed mesh (§5) with the
**same trust check and zero chain bytes**:

```
retract = { author_addr(20) ‖ author_pubkey(33) ‖ target_txid(32) ‖ target_vout(4) ‖ issued_at }
msg_id  = SHA256(retract);   sig = ECDSA(author_priv, msg_id)
honor iff hash160(author_pubkey) == author_addr ∧ sig valid ∧ author_addr == target's §4 vin[0] author
```

A post's `vin[0]` author is still recorded at index time (§4) — that recorded hash is what a
RETRACT is checked against. Anonymous posts stay **non-retractable** (no §4 key; clients SHOULD
offer to hide unattributable posts). The client-local tombstone is keyed `(target_txid,
target_vout, author_addr)` and **re-validated on every re-sync**, so a retraction whose target a
reorg later un-indexes stops hiding the now-different outpoint — the on-chain fold's
self-correction, preserved off-chain. PURGE leaves no on-chain trace — its opcode slot was reclaimed
when the registry was renumbered (§2). (Full
social-layer treatment — moderation lenses, revocation convergence — in communities-spec §3.)

**Reactions are off-chain.** A ~4-byte reaction does not justify ~220 bytes of permanent chain
data for a purely social signal, so reactions are handle-signed gossip (§5), with the same
web-of-trust filtering as everything
social.

### 3.9 Index determinism, storage & constant changes

> **Anything that determines global shared state is gated by a protocol constant.**
> **Anything that's a subjective per-user view is client policy — a display filter, never a
> gate on what enters the index.**

| class | determines | gate |
|---|---|---|
| identity (CLAIM/RENEW/TRANSFER/RELEASE) + market (SELL/RESERVE/SETTLE) | the global namespace + ownership | **protocol constants** (rate, windows, priority) |
| votes | a subjective per-user view | **client policy** (min-burn, web-of-trust) |
| author self-deletion (RETRACT) + moderation | a subjective per-view signal | **off-chain, client policy** (handle-signed, opt-in; §3.8, §5) |

**Why identity can't use client policy:** if any ownership-determining threshold were a
client setting, two clients could resolve a *different owner* — a silent namespace fork.
Contests are broken by the deterministic priority tuple (§3.2), never by burn-as-tiebreak.

**Storage is economically bounded.** The only state an indexer must keep is the *live* set —
who owns which name, each lease, live commits, and open sale data; expired names and transfer
history are sheddable. And the spammable surface (a victim's owned set) is itself **rented**: every name persists only as
long as its lease is paid (§3.4), and a name enters anyone's set only by being minted/conveyed
— which cost the minter rent ∝ duration. So abandoned/spam rows shed at `lease_expiry` (a
sliding window bounded above by `MAX_LEASE`), and keeping them alive costs the holder
proportional rent. There is no free spam amplification and no per-recipient cap needed (which
names would "count" is itself non-deterministic; the bound is purely economic + temporal).
Vote rows are additively sheddable (the floor is a min-burn filter, one layer up).

**Changing a constant (rare).** You cannot price-peg a constant without an oracle
(non-deterministic, re-centralizing) — which is exactly why the *rent* is derived from the
coinbase rather than pegged (§3.4). If a structural constant must change, ship it as a
versioned **activation height**: rule A below `H`, rule B at/after. Replay stays
single-valued; the change is **forward-only, never retroactive**.

---

## 4. Stateless Identity & Attribution (O(1) Verification)

Indexers do **not** need a UTXO set to attribute actions. Identity is derived from the
inputs and verified locally with legacy sighash rules. **This is the load-bearing foundation
the rest of the protocol depends on.**

### 4.1 The spoofing threat

An attacker can create an "anyone-can-spend" output (`OP_TRUE`) and, when spending it, place
a junk signature and a *victim's* public key in the `scriptSig`. The network mines it
(`OP_TRUE` needs no valid sig). An indexer that blindly trusts the `scriptSig` pubkey is
spoofed.

### 4.2 The stateless verification pipeline

**Rule 1 — identity resides in `vin[0]`.** The acting identity is strictly the first input;
other inputs are funding only. This applies to **text posts** too: a post's author is its
§4-verified `vin[0]`, recorded at index time (the hash an off-chain RETRACT is matched against,
§3.8). A post whose `vin[0]` is **unattributable** (fails §4 for any reason) is indexed as
**anonymous** content — no address, not retractable. Attribution is **never** lifted from an
unverified `scriptSig` pubkey (that is exactly the §4.1 spoof).

**Rule 2 — P2PKH and P2SH multisig are attributable (day-1, full).** Identity is recovered by
*classifying `vin[0]`'s `scriptSig` shape* (the prevout `scriptPubKey` isn't available) — a fixed
exact algorithm over **two** recognized shapes; everything else (P2PK, bare multisig, nonstandard,
empty) → **drop**:

- **P2PKH** — `scriptSig = [sig] [pubkey]`; `Identity = hash160(pubkey)`; **one** ECDSA verify.
- **P2SH multisig** — `scriptSig = OP_0 [sig]×m [redeemScript]` (**exactly `m` sigs** — the
  redeemScript's threshold; a different count → drop), the redeemScript (last data push)
  exactly `OP_m <33-B compressed pubkey>×n OP_n OP_CHECKMULTISIG`; `Identity = hash160(redeemScript)`
  (the bare script-hash, type-tracked below); **O(m)** ECDSA verifies. This is what lets a name —
  a community — be **owned by, and post/vote as**, an n-of-m group (communities-spec §1), with the
  threshold enforced *natively* by the spend.

> **Why these two — and why P2SH is safe to include now, not deferred.** A full script interpreter
> is a forking minefield: any VM disagreement attributes the same action to a *different* identity.
> Neither shape needs one. P2PKH is two pushes + one verify; the multisig redeemScript is a **fixed
> template**, not arbitrary Script — matched structurally and checked with one bounded
> `OP_CHECKMULTISIG`-shaped loop. Both pin **byte-for-byte with vectors**. The multisig path forks
> only if sloppy; these rules make it deterministic (**all mandatory**):
>
> - **Exact fail-closed template** — **compressed keys only** (33-B `0x02`/`0x03`), `OP_m`/`OP_n`
>   minimal (`OP_1`..`OP_16`), exact opcode order, **≤15 keys** (the 520-B redeemScript push bound;
>   15-of-15 ≈ 513 B), reject any trailing byte. Uncompressed/mixed keys, alt encodings,
>   true-leaving wrappers → **drop**.
> - **strict-DER is already consensus** on Dogecoin (BIP66) — a mined sig can't be non-DER. But
>   **NULLDUMMY + low-S are self-imposed** (policy, not Dogecoin consensus): require the leading
>   `OP_CHECKMULTISIG` dummy be exactly `OP_0`, and reject high-S per sig independently.
> - **In-order signature scan** — the `k` sigs are a subsequence in pubkey order (on match advance
>   both, on miss advance the key); "try all orders" attributes differently — pin in-order. A spend
>   carrying fewer than `m` valid sigs fails the threshold → drop.
> - **PUSHDATA1-aware, minimal-push decoder** — even a 2-of-3 redeemScript (~105 B) needs
>   `OP_PUSHDATA1`; enforce minimal-PUSHDATA1 (76–255 B *must* use `0x4c`; `<76` *must not*).

**Stateless still holds.** `vin[0]` attribution is **stateless** even for P2SH — the redeemScript
rides in the spending `scriptSig`, so a multisig spend is attributed from the tx alone, no UTXO set
(multisig sighash is the same legacy machinery with `scriptCode = redeemScript`). Identity keys on
the **bare hash160** everywhere (name ownership, the TRANSFER target, the RETRACT author,
self-compare), so a name gifted/sold to a P2SH hash is owned and renewable immediately — no type
byte in the wire format. The one derived fact the fold retains (§5), deterministic and shed-able:
- **Script type per party.** Every site that later *reconstructs* a controller's script — the SELL
  `seller` payment check (§3.7), a SETTLE writing the new owner-hash — records the **(hash160,
  script type)**, P2PKH **or** P2SH; the rule is *"reconstruct per recorded type,"* never "assume
  P2PKH." (Paying a P2SH seller needs only its `hash160`, so the keyset preimage is **never**
  cached on-chain.)

**Authority is the P2SH spend itself.** A P2SH redeemScript enforces **one** threshold, and that
spend *is* the authority — no extra protocol check, no keyset bookkeeping. Every on-chain act *as* a
community — RENEW, TRANSFER, SELL, re-key (a roster change is an **n-of-m re-key TRANSFER** to the
new keyset's P2SH), and **official posts/votes** — is the native **n-of-m** spend Dogecoin already
enforces. (Renewal needs quorum like everything else, but `MAX_LEASE` lets a community pre-pay up to
a year per RENEW, so quorum is needed only ~annually. A *single-member* renew without quorum — a
`1-of-m` "act for the name" — is **deferred**: it would need an on-chain keyset cache for marginal
liveness, so it's left additive/forward-only, gated on real demand, §9.) The only 1-of-m authority
that ships is **off-chain moderation** (hide/label/ban), and that's gossip — a client checks the
signer against the keyset it verifies off-chain (communities-spec §3), needing **no on-chain
cache**.

**Rule 3 — `vin[0]` must sign exactly `SIGHASH_ALL` (`0x01`).** Reject `NONE`, `SINGLE`,
every `ANYONECANPAY` variant (incl. `0x81`), and any other flag.

> **Why no `ANYONECANPAY` — the authorship-hijack attack.** Identity is a *position*
> (`vin[0]`). `ANYONECANPAY` commits only to the signer's own input + the outputs, **not** to
> the other inputs, the input count, or *which index the signed input occupies*. So an
> attacker copies the victim's outputs verbatim (preserving the victim's output commitment)
> and her signed input parked at `vin[1]`, puts **his own** input at `vin[0]`, signs it, and
> rebroadcasts at higher fee. Both sigs verify; the indexer reads `vin[0]` → the attacker →
> grants the name to him. Only bare `SIGHASH_ALL` commits to input *position*. (A split-key
> user wanting cold identity + hot funding must co-sign the finalized input array with `0x01`,
> not use `ANYONECANPAY`.)

> **Wallet note — no in-place fee bump.** Because `vin[0]` signs over the exact input array
> and outputs, you cannot RBF a PepeNet action by adding an input or trimming change (it
> invalidates the sig and silently moves `vin[0]`). To raise the fee: rebuild and re-sign, or
> CPFP via the change output. Wallets MUST NOT offer naive RBF on these txs.

**Rule 4 — strict encodings (determinism).** Signatures strict-DER + low-S; pubkeys
canonically encoded — accept only a **33-byte compressed** (`0x02`/`0x03` + X) or **65-byte
uncompressed** (`0x04` + X + Y) key, with coordinates `< p` and the point on-curve. Reject the
**hybrid** `0x06`/`0x07` prefixes, any other leading byte/length, off-curve points, and
out-of-range coordinates. The identity hash is over the *exact* pubkey bytes, so the 33- and
65-byte forms of one key are **different** identities. Non-canonical → drop.

> **Implementation note — the libsecp256k1 low-S trap.** `secp256k1_ecdsa_signature_parse_der`
> does **not** enforce low-S, and `…_verify` then accepts a high-S signature. Enforce
> strict-DER + `S ≤ N/2` **before** verifying (or use `…_signature_normalize`, which returns 1
> iff the input was high-S — reject on 1). The reference client hand-rolls strict-DER + low-S
> independent of the parser. Skip this and you accept signatures a strict indexer drops — a
> silent identity-layer fork.

**Step-by-step:**

1. **Length guard + shape.** Payload **≥ 4 bytes** (else drop, never read past the end);
   confirm `0xFF 'P' 'N'` + a recognized opcode; for burn-bearing ops the value field meets
   the op's requirement; bounds-check every field read against the exact length/format for
   that opcode (§2). Any out-of-bounds or mismatch → drop.
2. **Classify `vin[0].scriptSig` (exact):** **P2PKH** iff exactly two pushes `[sig] [pubkey]`,
   both minimal/canonical, `pubkey` canonical (Rule 4), `sig` strict-DER+low-S, sighash byte
   exactly `0x01` (Rule 3). **Else P2SH multisig** iff `OP_0 [sig]×m [redeemScript]` (exactly `m`
   sig pushes, matching the redeemScript's `OP_m`), the redeemScript matching the exact template of
   Rule 2 (≤15 compressed keys, minimal `OP_m`/`OP_n`, PUSHDATA1-aware minimal push), the `OP_0`
   dummy exact (NULLDUMMY), and every `sig` strict-DER+low-S+`0x01`. Any trailing bytes / extra /
   missing / non-minimal push, a sig count ≠ `m`, or anything matching **neither** shape → drop.
3. **Derive identity:** `Identity = RIPEMD160(SHA256(x))` where `x` is the **exact pubkey bytes**
   for P2PKH, or the **exact redeemScript bytes** for P2SH multisig — the bare hash160 either way.
   Everything that keys on a party uses this bare hash (type-agnostic); reconstruction sites that
   rebuild a `scriptPubKey` (the SELL `seller` check, a SETTLE owner-write) carry the recorded
   script type, P2PKH or P2SH (Rule 2).
4. **Reconstruct scriptCode & verify ECDSA locally:** for **P2PKH**, scriptCode = `OP_DUP
   OP_HASH160 <Identity> OP_EQUALVERIFY OP_CHECKSIG` and one `Verify(sig, pubkey, sighash)`. For
   **P2SH multisig**, scriptCode = the **redeemScript** itself, and the `m` sigs are checked against
   the `n` pubkeys by the in-order scan (Rule 2) — each sig against the next matching pubkey,
   advancing the pubkey cursor on a miss — until all `m` verify (pass) or the pubkeys exhaust (drop). Compute the **legacy** sighash from the raw tx + scriptCode + type `0x01`
   (legacy needs no input amount — what makes this stateless; DOGE has no SegWit). `FindAndDelete`
   of a signature from the scriptCode is a no-op for P2PKH (it holds a hash) and inert for multisig
   (no mined canonical sig appears verbatim in the redeemScript). Pass = genuine, bound to `Identity`.
5. **Execution.** Pass → apply the action, bound to `Identity`. Fail → silently drop.

> O(1) per action for **P2PKH** (one ECDSA verify); **O(m)** for an m-key **P2SH multisig**
> `vin[0]` — paid only by the rare group action, while individual posts/votes stay one verify. A
> chain scan is O(actions) checks, and the attacker pays a full tx fee per attempt, so the
> asymmetry favors the indexer.

**Conformance is defined by test vectors, not prose.** §4 demands bit-for-bit agreement on
DER/low-S, pubkey canonicalization, minimal pushes, the legacy sighash, **and the P2SH multisig
template + scan**; §1 demands strict-UTF-8 demux. The protocol ships a **conformance vector set**
(raw tx hex → `{Identity}` or `drop`) covering every reject reason: non-`0x01` sighash (incl.
`0x81`), high-S, non-minimal push, non-canonical pubkey (wrong length, hybrid `0x06`/`0x07`,
off-curve, coordinate ≥ `p`), trailing scriptSig bytes; the **multisig** cases (a valid k-of-m
attributed to `hash160(redeemScript)`; reject uncompressed/mixed keys, a non-`OP_0` dummy, high-S
in *any* sig, out-of-order sigs, a sub-threshold `k < m`, `>15` keys, and non-minimal / wrong
`PUSHDATA1` encoding of the redeemScript push); and the §1 demux cases (overlong, surrogate,
`> U+10FFFF`, and a payload valid at the first byte but invalid later). Conformance means "passes
the vectors," not "reads like the spec" — this is the part that forks **silently** when
re-implemented from prose.

---

## 5. Client interpretation & the off-chain layer

- **The protocol records; the client decides.** Burn thresholds, which addresses to trust,
  what to hide/show — all local policy, never protocol rules. **Nothing on-chain can *force* a
  client to hide anything** — author self-deletion (RETRACT, §3.8) and all moderation are
  off-chain, handle-signed, and opt-in; the raw chain data is unerasable regardless.
- **Web-of-trust.** Honor votes/social signals only from addresses the user follows or above
  a burn floor; reputation is computed locally from the user's own graph, never a global score
  (those get gamed and re-centralize). Votes are anonymous (WoT filters by *address*, and only
  while an indexer still keeps per-voter rows); the off-chain social layer is handle-signed
  (shows as concrete `@name`s).
- **Identity display (Zooko's triangle).** The **address is the secure, globally unique id**;
  `@name` is a human-readable label / asset, never a substitute. Clients **MUST** surface the
  address fingerprint alongside the name **everywhere a name appears** (`@bob · DH5y…mr7L`); a
  bare `@name` with no fingerprint is an impersonation vector (a name is cheaply hijacked the
  moment its lease lapses, and ASCII confusables survive the charset rules). Clients may layer
  local petnames that override the on-chain name per-user. A name changing hands never
  reattributes past posts. A name received by TRANSFER is owned but **never auto-displayed** — shown
  to no one until its owner declares it as their handle (off-chain, below) — so unsolicited transfers
  never deface an address.

**The off-chain gossip layer.** Everything social, advisory, or price-finding lives here, with
chain-anchored identity (address-key-signed, shown as the signer's declared `@handle`) and
client-side §5 filtering:
- **Handle (display name)** — your public `@name` is an **address-signed declaration**, not chain
  state: `{address, display, issued_at}` signed by the address key, honored iff `lowercase(display)`
  is a name the address **owns on-chain** (§3) and it is that address's **latest** such declaration.
  Resolution is `address → its latest valid handle`, always rendered with the mandatory fingerprint
  (`@AliceDAO · DH5y…`). This keeps *which* owned name you present (and its casing) the display
  choice it is (§3.9): the chain settles *ownership*, gossip carries *presentation*. **Defacement
  defense (client-side):** only a name you've explicitly declared ever shows as your handle, so a
  received name / gift-spam shows on no one. Convergent-not-instant — a lagging client briefly shows
  a stale `@name` or falls back to the bare fingerprint; a declaration whose name has lapsed or
  transferred away stops being honored on re-validation.
- **Reactions** — handle-signed, TTL'd gossip. Off-chain because a 4-byte social signal doesn't
  earn permanent chain data.
- **The names orderbook** — asks, bids, and auctions are advisory gossip; the chain only
  *settles* a price gossip discovered (§3.7). Clients can run arbitrarily rich markets here —
  automated offers, simulated auctions, private price controls — and only the final
  SELL/RESERVE/SETTLE touch the chain.
- **DMs** — ECIES-encrypted mesh, separate from chain sync.

---

## 6. Indexer integration

State is a **deterministic fold** over the canonical chain in strict `(height, tx index,
vout)` order (`vout` is the serialized output index, **not** a node's JSON-RPC array
position). The scan extends the existing `valid_utf8()` demux:

```
for each OP_RETURN output o in tx (vout order):       # vout order = intra-tx state-machine order
    if o starts with 0xFF 'P' 'N' + opcode in 0x01..0x0A:   # contiguous; no reserved holes
        run §4 stateless verification on vin[0]              # P2PKH O(1) or P2SH multisig O(m)
        if not verified: drop (spoof); continue
        if opcode in 0x03..0x0A and height < ACTIVATION_HEIGHT: drop; continue   # forward-only gate (§3.0)
        for burn-bearing ops (VOTE/CLAIM/RENEW/RESERVE): check the value field meets the op's requirement
        dispatch by opcode against current fold state                       # mutates owned set / escrow
        # CLAIM: mints iff name unowned AND a live matching commit in a STRICTLY EARLIER block (commit_height < claim_height, §3.2) sets commit_height — else drop (no FCFS fallback); burn buys ⌊value·LEASE_QUANTUM/(rate·BILLING_UNIT)⌋ days of lease
        # RENEW/TRANSFER/RELEASE: resolve the bitmap against the owned-set + anchor guard (§3.5)
        # RELEASE: selected owned names → pool immediately; immediately reclaimable, like lapse (§3.6)
        # SELL/RESERVE/SETTLE: one name per OP_RETURN (several per tx via multi-OP_RETURN, §3.5); each payment its own exact-value output, consumed once in vout order
        # RESERVE: two-leg deposit spent unconditionally; first-in-chain-order wins the SETTLE option, reserve_expiry = min(now+RESERVE_WINDOW, offer_expiry) (§3.7)
    elif o.value > 0 and len(payload) >= 1 and valid_utf8(o):  text post — author = §4(vin[0]) or ANONYMOUS
    else:                                                       ignore
```

**Tables.** `votes` (per `(target, vout)`; voter + burn; foldable to a per-post `(Σ up, Σ
down)` past finality). `names` (the owned-set store — a row per `(name, owner)` with
`lease_expiry`, and — for a **listed** name — a `listed` flag
plus `price`, `seller` (hash160 + script type), `offer_expiry`, and reservation fields `reserver`,
`reserve_expiry`). `commits` (per `{commitment, commit_height, tx_index}`, pruned at
`COMMIT_EXPIRY`). Per-owner `last_set_mutation_height` for the renew anchor guard (§3.5).
(There is **no** `purged` table — author self-deletion is the off-chain RETRACT, §3.8.)

**Time-triggered transitions (no transaction).** Apply as the fold crosses the MTP boundary,
**before** that block's transactions: a name lapses to the pool at `lease_expiry`; an unsettled
listing closes at `offer_expiry` (clears the listed flag — the name
was always the seller's, §3.7); a lapsed (unsettled) reserve reverts the listing to the open offer
at `reserve_expiry`. Because `reserve_expiry` is **clamped to `offer_expiry`** at RESERVE (§3.7),
these nest strictly — `reserve_expiry ≤ offer_expiry ≤ lease_expiry − REORG_BUFFER < lease_expiry`
— so MTP monotonicity crosses them in order regardless of reorgs (the `REORG_BUFFER` gap is a
*relative* margin between two MTP-evaluated boundaries, and matches the chain's own ±2h
timestamp bound). A name freed by lapse **or by RELEASE (§3.6)** leaves its owner at once and is
**immediately reclaimable**; a reclaim a later reorg reverses is dropped on replay — there is no
protocol-level cooling window, reorg-risk on a reclaim is client-side, exactly as for any fresh
claim (§3.2).

**Ordering rule (consensus-critical).** At each height, run all time-triggered transitions for
that height **before** the block's transactions; then process txs in `(tx index, vout)` order,
each change visible to everything after it — a **single forward pass**, with no carve-out now that
PURGE is gone (its old two-pass block-end reconciliation is deleted with it).
`lease_expiry`/`offer_expiry`/`reserve_expiry` are **exclusive** bounds. Resolving ownership
*lazily* (testing `MTP < lease_expiry` only at query time) is **forbidden** — a same-block
lapse-and-reclaim must apply the lapse before the reclaiming tx in the same block.

**MTP.** The indexer tracks Median-Time-Past (median of the last 11 block timestamps) and
evaluates every time-denominated boundary against it. MTP is a pure function of headers
(deterministic across indexers), monotonic, and miner-resistant (a miner can't pull it back and
can only nudge it forward within the ±2h future bound). Don't cut deadlines to the second — MTP
lags real time by ~5–6 blocks, and the indexer acts on a time-boundary only once it's
`REORG_BUFFER`-deep, the same discipline applied to every state transition.

**Reorgs.** All state is a pure fold over the canonical chain — on a reorg, roll back the
disconnected blocks and **replay** from the fork point (exact). Never treat reorg-able state as
final.

**Conformance vectors cover the fold, not only the crypto.** The stateful fold forks as silently
as §4. The protocol ships **fold conformance vectors** — `(prior state + block/range) → resulting
state or drop` — pinning at minimum: the commit→claim author-binding + commitment-copy case
(§3.2); a claim with **no live ≥1-deep commit drops** (no FCFS fallback) and a **same-block commit
is too shallow** to back a claim; the priority tuple (a later
claim with an *older* commit does **not** displace an earlier holder); the rent water-fill (a fee spike spreads a shorter lease evenly across the batch; a name that
caps at `MAX_LEASE` redirects its rent to names with headroom; the per-day rescale
`×LEASE_QUANTUM/BILLING_UNIT` in ≥128-bit; fail-closed at `T = 0`; the `T < count` floor and the
lexicographic remainder); the renew bitmap ordering (lexicographic from bit 0) and
anchor guard (set changed since `H`, or `H ≥ confirm`, → reject, never wrong-name) —
including that a **SELL listing does not bump** the mutation height (a RENEW bitmap spanning a
listing stays valid) while **SETTLE bumps both** buyer and seller; a same-block
lapse-or-RELEASE-and-reclaim (a RELEASE returns selected names to the pool, immediately
reclaimable — the lapse/RELEASE applies before the reclaiming tx in the same block, mirroring
lapse); the market cascade boundaries (a late RESERVE's `reserve_expiry` is **clamped to
`offer_expiry`** so a SETTLE can't land after the listing closes; a lapsed reserve reverts the
listing to the open offer; a losing reserve's deposit is **spent** (0.5 % burn + 0.5 % to seller)
yet fails to claim the option — *not* rejected; the **per-tx output matching** (several
RESERVE/SETTLE `OP_RETURN`s in one tx each consume a distinct exact-value output in `vout` order; a
summed or missing output drops that op); the 128-bit `price × bps` deposit math at the near-`2⁶⁴`
boundary); and the lease conveyance on TRANSFER/SETTLE.
An indexer conforms iff it passes **both** the §4 and these fold vectors.

The subprotocol sync messages (`getpostidx` / `getposts`, see network-roadmap.md) carry these op
types too, not just text posts.

---

## 7. Size budget (80-byte `OP_RETURN`)

| message | bytes | fits 80? |
|---------|-------|----------|
| VOTE_UP / VOTE_DOWN | 40 | ✅ |
| COMMIT | 36 | ✅ |
| CLAIM | 36 + len(name) ≤ 56 | ✅ (32-byte salt) |
| RENEW (all / safe / selective) | 4 / 9 / 10..80 | ✅ (~568 selective names) |
| TRANSFER (all / selective) | 24 / 29..80 | ✅ (~400 names/target) |
| SELL | 16 + len(name) ≤ 36 | ✅ |
| RESERVE | 4 + len(name) ≤ 24 | ✅ (one per `OP_RETURN`; several per tx via multi-`OP_RETURN`) |
| SETTLE | 4 + len(name) ≤ 24 | ✅ (one per `OP_RETURN`; several per tx via multi-`OP_RETURN`) |
| RELEASE | 9 + len(flags) ≤ 80 | ✅ (~568 names/tx) |

This budget is the **`OP_RETURN` payload only**, unchanged by P2SH: a multisig `vin[0]`'s
redeemScript and its `k` signatures ride in the **`scriptSig`** (its own size/relay budget), so
group actions cost more *tx weight* but not a single `OP_RETURN` byte — the action payloads above
are identical whether authored by a P2PKH key or an n-of-m keyset.

---

## 8. Time & finality

The denomination of every duration follows **what it measures** (§0):

| quantity | denominated in | why |
|---|---|---|
| leases, `COMMIT_EXPIRY`, SELL/`RESERVE_WINDOW` | **time (MTP)** | wall-clock commitments; survive a block-speed change |
| `REORG_BUFFER` (window margins) | **time (MTP), ~2 h** | a *relative* gap MTP monotonicity keeps ordered; matches the chain's ±2h timestamp bound |
| priority `(claim_height, commit_height, tx_index)` | **height** | ordering is positional |
| renewal/transfer bitmap anchor, `MAX_ANCHOR_AGE` | **height** | it bounds a height |

**Finality is two different things.** *Client reorg-trust* ("should I believe this settle?")
is a UI/risk choice, out of consensus scope — a client may use depth, elapsed time, or
cumulative **chainwork** (the rigorous measure, since reorg resistance is *work*, and neither
block-count nor wall-clock tracks work across a difficulty regime change — block-count is right
only if difficulty is constant, wall-clock only if hashpower is constant). The *consensus*
margin is only `REORG_BUFFER`, and it's robust because it's a **relative gap** between two
MTP-evaluated boundaries: a uniform MTP shift (even a miner's ±2h nudge) preserves the gap and
their order, so the manipulability that would bite an absolute trust-trigger doesn't bite a
relative margin. A 10× block-speed change touches only the height-denominated quantities, and
each of those *should* scale with blocks (ordering stays correctly positional; the bitmap
anchor's 5-byte width already absorbs ~10⁶ years of faster blocks).

---

## 9. Open questions

**Resolved:**
- **Identity = address; name = decoration/asset.** All attribution is to `vin[0]`; names never
  reattribute authorship (§0, §5).
- **Burn carries meaning only where it's the signal** — vote weight, CLAIM/RENEW rent, the
  RESERVE deposit. COMMIT/TRANSFER/RELEASE/SELL/SETTLE carry no required `OP_RETURN`
  burn (market *payments* ride in separate exact-match outputs) (§0, §3).
- **Rent rate** — value-stable, governance-free, stateless coinbase fee oracle:
  `clamp(median(coinbase fee-per-byte) × REF_SIZE, DUST_FLOOR, 1 DOGE)` per name·quantum, over a
  ~1-week window so median-suppression is ruinous. **No duration field** — the burn *is* the
  duration; it buys lease time **billed in whole days** (`BILLING_UNIT`), **water-filled** evenly
  across the batch with `MAX_LEASE` redistribution (§3.4, §3.5).
- **Leases** — pay-for-duration, **linear**, capped at `MAX_LEASE` (~1 yr); lease conveys on
  transfer; lapse → pool; linear pricing aligns the holder's incentive with host-network health
  (§3.3).
- **Claiming** — **mandatory** commit→claim, **no naked claims**; the commit must be **≥1 block
  deep** (`commit_height < claim_height`; same-block is too shallow → claim drops). Priority
  `(claim_height, commit_height, tx_index)`; author-bound commit closes the copy attack; launch =
  a blind commit phase at `ACTIVATION_HEIGHT`, claims from `+1` (§3.0, §3.2).
- **Batching where it's free; any count cap is relay, not protocol.** The *identity* ops batch via
  bitmaps (RENEW/TRANSFER/RELEASE) within one `OP_RETURN`; the *market* ops (RESERVE/SETTLE) are
  **one name per `OP_RETURN`** and batch at the *transaction* level — several RESERVE/SETTLE
  `OP_RETURN`s in one tx, payments individually split into exact-value outputs (matched consume-once
  in `vout` order). The protocol imposes no count cap; only single-`OP_RETURN` relay does, and that
  lifts with multi-`OP_RETURN` (§9). Anti-abuse is economic or exclusivity, never structural (§3.5).
- **RENEW wire format** — pinned 3 modes (4 / 9 / 10..80 B), 5-byte height anchor, per-owner
  mutation guard, **pure lexicographic** ordering from bit 0, ~568 selective names (§3.5).
- **Market** — fixed-price escrow-first; a listed name stays owned and **renewable** but locked
  from move; RESERVE open (no co-sign) is a non-refundable bid (one name per `OP_RETURN`, several
  per tx) for an exclusive SETTLE option (deposit spent unconditionally; first-in-chain-order wins;
  `reserve_expiry` clamped to `offer_expiry`); SETTLE pays the exact remainder, each payment its own
  exact-value output matched consume-once in `vout` order. Front-run / double-payment /
  settle-after-close closed; harvest bounded-benign; reserve-griefing bounded; live at the single
  `ACTIVATION_HEIGHT` (§3.7).
- **RELEASE (`0x0A`)** — active, selective, immediate relinquish (bitmap + anchor guard like
  RENEW); complements free passive lapse; forfeits remaining lease; freed names are immediately
  reclaimable (§3.6).
- **Time vs. height** — durations in MTP, ordering in height; `REORG_BUFFER` is the consensus
  margin for ordered window boundaries; client reorg-trust is out of scope (§0, §8).
- **Reactions, author self-deletion & the display handle off-chain** — address-signed gossip, not
  chain data; PURGE → off-chain **RETRACT**, and the `@handle` is an off-chain declaration honored
  against on-chain ownership (no opcodes; registry renumbered to 10 contiguous ops) (§3.8, §5).
- **§4 verification** — `vin[0]` only; **P2PKH (O(1)) and P2SH multisig (O(m)) attributable
  day-1, full** (posts, votes, name-actions); sighash exactly `0x01`, strict-DER/low-S, NULLDUMMY,
  in-order scan, ≤15 compressed keys; conformance by vectors (§4).
- **Community authority = the native P2SH spend** — every on-chain act *as* a community (RENEW,
  TRANSFER, SELL, re-key, official posts/votes) is the **n-of-m** spend itself; no extra protocol
  check, no keyset cache. The only 1-of-m authority that ships is **off-chain moderation** (gossip,
  client-checked). A 1-of-m *on-chain* single-member renew is **deferred** (below) (§4).

**Resolved (parameters) — values to finalize against testnet:**
- `LEASE_QUANTUM` (~28 d, rate anchor), `BILLING_UNIT` (1 d, lease granularity), `MAX_LEASE`
  (~365 d), `COMMIT_EXPIRY` / `RESERVE_WINDOW` (~5 h), `REORG_BUFFER` (~2 h), `REF_SIZE` (~200 B),
  `FEE_WINDOW` (~1 wk), `MAX_ANCHOR_AGE`, and the client anchor-burial depth (~6 blocks, §3.5).
  These are value choices, not design holes.

**Deferred (additive, forward-only — re-encodes nothing):**
- **Multi-`OP_RETURN` relay** — unlocks batch CLAIM, multi-target TRANSFER, >560 selective renew
  via an offset byte, and **batch RESERVE/SETTLE** (one deposit/payment `OP_RETURN` per listing);
  the formats are designed for it and degrade gracefully until then.
- **1-of-m single-member renew** — a future opcode letting one keyset member renew a community's
  name without quorum. Deferred because it needs an on-chain **keyset cache** (a P2SH only reveals
  its keyset when it *spends*, not when it *receives*) for **marginal** liveness — communities renew
  n-of-m via plain RENEW today, and `MAX_LEASE` makes quorum a ~yearly need. Additive/forward-only;
  gate on real demand (the same call communities-spec §3.3 makes for the SMT escape hatch).
- **Batch SELL** — listing several names at one price in one op.

**Open (bounded, accepted):**
- **Reserve-griefing** — locking a listing costs the griefer 1 % per `RESERVE_WINDOW` (0.5 % to
  the seller); priced, not closed (§3.7).
- **Predictable-name camping** and **lapse-sniping** — commit–claim protects *hidden* intent,
  not foreseeable or public-availability contests (§3.2); the namespace layer declines targeted
  denial by design (the defense is "name ≠ identity," §5).
