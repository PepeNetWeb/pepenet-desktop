# PepeNet Namespace — Action State Machine

This document defines the base layer of the PepeNet namespace: an identity +
naming/market layer carried in Dogecoin `OP_RETURN` actions.

The protocol uses a **stateless indexing model**. Indexers verify identity and action
intent in **O(1)** directly from block data — no UTXO set is maintained or queried. The
one place the protocol needs network-wide economic awareness (the rent rate, §3.4) is
derived from the **coinbase** alone, so statelessness holds end to end.

The organizing principle: **the chain is the source of truth.** Permanent ownership and value
facts go on-chain and fold deterministically to a canonical owned-set + market state that every
indexer resolves identically.

---

## 0. Foundations

- A PepeNet action lives in `OP_RETURN` output(s) of a normal DOGE tx.
- An output is addressed by **`txid + vout`**. There is ~one `OP_RETURN` per tx today,
  but every reference uses `txid+vout` so it survives the move to multiple `OP_RETURN`s
  per tx (which several batching features in this spec are designed to exploit, §3.5).
- **Carrier size is pinned by this protocol, not by L1 or by relay folklore.** L1 never
  size-checks an `OP_RETURN` script: it is provably unspendable and never executed, so
  neither `MAX_SCRIPT_SIZE` nor the 520-byte push-element rule binds; the only bound L1
  actually imposes is the ~1 MB serialized-tx limit. This protocol **pins** the payload
  ceiling at **9,996 bytes** — what a `MAX_SCRIPT_SIZE`-sized (10,000 B) script would
  carry as `OP_RETURN`(1) + `OP_PUSHDATA2`(1+2) + one push (§6 derives the number and
  says why a pin at all). Node *relay policy* (`datacarriersize`, default 83 script
  bytes → an 80-byte payload) is a far lower practical gate on what gets FORWARDED —
  but a mined carrier folds at any size up to the pinned ceiling. Batch CLAIM and
  multi-target TRANSFER still reach full power only via multi-`OP_RETURN` txs (§3.5).
- **The address is the only identity.** Everything is attributed to the address that
  signs `vin[0]` (§4) — a P2PKH key or a P2SH multisig keyset, attributed identically by
  `hash160` (day-1, §4). Names are pure decoration / a transferable digital asset
  layered on top, never the canonical identity. Losing, expiring, or transferring a name
  never changes who performed a past action.
- **The burn carries meaning only where the burned amount *is* the signal**, in two
  places: name **rent** (CLAIM/RENEW, §3.4) and the market
  **reserve deposit** (RESERVE, §3.7). Everywhere else (COMMIT, TRANSFER, RELEASE, SELL,
  SELL_TO, SETTLE, PAY, AS, TRADE) the action's `OP_RETURN` carries **no required burn** — the Dogecoin **miner
  fee** is the only cost and is sufficient anti-spam. A market *payment* (the RESERVE
  pay-leg, the SETTLE remainder, and the directed PAY price, §3.7) rides in a **separate spendable
  output**, never in the action `OP_RETURN`. The action `OP_RETURN` is provably unspendable and so is
  never dust-filtered (a value-bearing or zero-value `OP_RETURN` both relay and mine on
  Dogecoin); the dust limit binds only a *spendable* output — a buyer's market payment,
  §3.7 — never the action carrier.
- **Recognition is by prefix, not value.** An `OP_RETURN` is a protocol action iff it
  begins with the 4-byte universal prefix (§1). For the burn-bearing ops the output
  **value** is then the signal; for the fee-only ops the value is ignored.
- **Strict, fail-closed parsing.** Anything malformed — wrong length for its opcode, bad
  prefix, invalid name, unsupported input type, failed signature — is **deterministically
  dropped**, never guessed. Indexers MUST agree byte-for-byte on validity (§3.8, §4).

### Time vs. height — denominate by what a quantity measures

The protocol mixes two clocks deliberately:

- **Wall-clock durations** — leases, the commit window, market windows, the reorg margin
  — are denominated in **time**, evaluated against block **Median-Time-Past** (MTP,
  BIP113-style: the median of the timestamps of the **11 blocks strictly before** the block
  being connected — the exact index range is pinned in §5; monotonic, miner-resistant,
  deterministic). Time-denomination makes these immune to a change in the host chain's
  block-time target: a year is a year no matter how fast blocks come.
- **On-chain positions** — claim priority ordering and the renewal bitmap's anchor — are
  denominated in **block height**, because ordering is intrinsically positional and a
  height anchor names a height.

Only the height-denominated quantities scale with a change in block speed, and each of
those *should* (§7).

### Protocol constants

Fixed protocol constants — identical for every indexer or ownership resolution diverges.
A change ships only as a versioned **activation height** (forward-only, never
retroactive; §3.8).

| constant | value | meaning |
|----------|-------|---------|
| `KOINU_PER_DOGE` | `100_000_000` koinu (`= 1` DOGE) | the Dogecoin-standard base unit. Every value/price/burn is carried in **koinu**; the two DOGE-denominated constants below (`RATE_CAP`, the coinbase `subsidy` §3.4) are this many koinu each |
| `DUST_FLOOR` | `1` koinu | the rent-rate clamp **floor** (§3.4); also the RESERVE deposit-leg floor, and the SELL price-floor basis `3 × DUST_FLOOR` (§3.7) |
| `RATE_CAP` | `1` DOGE = `100_000_000` koinu | the rent-rate clamp **ceiling** (§3.4) |
| `REF_SIZE` | `200` bytes | value-agnostic byte count converting fee-per-byte → per-name rent (§3.4) |
| `FEE_WINDOW` | `10_081` blocks (~1 wk) | window scanned for fee-bearing blocks feeding the rent-rate median (§3.4). (The median is taken over the fee-bearing subset, whose count has no fixed parity — determinism comes from the pinned lower-median index rule, §3.4) |
| `MIN_FEE_SAMPLE` | `1_000` blocks (~10 % of the window) | minimum fee-bearing (participant) count for the median to be trusted; below it the rate degrades to `DUST_FLOOR` (§3.4). Boundary inclusive: exactly 1000 participants take the median path |
| `LEASE_QUANTUM` | `2_419_200` s (~28 d) | the rent rate's anchor — `rate` is koinu per name per `LEASE_QUANTUM`; ~1 DOGE/name/yr at current fees (§3.4) |
| `BILLING_UNIT` | `86_400` s (1 d) | lease-extension granularity; leases extend in whole days (§3.3, §3.5) |
| `MAX_LEASE` | `31_536_000` s (~365 d) | cap on how far ahead of now a lease may extend (§3.3) |
| `COMMIT_EXPIRY` | `18_000` s (~5 h) | a commit's live window; self-prunes after (§3.2) |
| `RESERVE_WINDOW` | `18_000` s (~5 h) | a reserve's exclusive-buy window; also the SELL window floor (§3.7) |
| `DIRECT_WINDOW` | `7_200` s (~2 h) | the directed-sale (SELL_TO) offer window — **fixed**, no field; the buyer's PAY deadline (§3.7) |
| `REORG_BUFFER` | `7_200` s (~2 h) | margin keeping ordered time-boundaries apart with reorg slack (§3.7, §5) |
| `RESERVE_DEPOSIT_BPS` | `100` (1.00 %) | total reserve deposit, basis points of `price` (§3.7) |
| `RESERVE_BURN_BPS` | `50` (0.50 %) | deposit leg **burned** |
| `RESERVE_PAY_BPS` | `50` (0.50 %) | deposit leg **paid to seller** |
| `MAX_ANCHOR_AGE` | `1024` blocks | max staleness of a renewal/transfer bitmap height anchor (§3.5) |

**Client reorg-trust is *not* a protocol constant.** "How deep before I believe an
ownership flip or a settle?" is a per-client risk choice (it may use depth, elapsed time,
or cumulative chainwork) that never gates the deterministic fold.
The protocol enforces a margin only where two *time-boundaries must stay ordered*
(`REORG_BUFFER`, §3.7, §5) — see §7.

### Encoding primitives

- `txid` — 32 bytes, internal (wire) byte order. (Explorers show the byte-reversed form;
  reverse it back before putting it in a payload.)
- `vout` — 4 bytes, little-endian `uint32`.
- `address_hash` — 20 bytes, the legacy `hash160` = `RIPEMD160(SHA256(pubkey))`.
- `name` — UTF-8 bytes, validated per §3.1; length implicit from the field / `OP_RETURN` size.
- `height` — 5 bytes, little-endian (the bitmap anchor, §3.5; 5 bytes spans ~10⁶ years
  even under a 10× block-speed increase).
- `price` / `value` koinu — 8 bytes, little-endian `uint64`; always compared in unsigned ≥64-bit.

---

## 1. Message Framing & The Universal Prefix

Every protocol action begins with a strict **4-byte header**. `0xFF` is the escape byte:
because `0xFF` is impossible in valid UTF-8, indexers separate actions from all non-action
carriers (the overlay band + any UTF-8), which fall through to *ignore*, with no content heuristics.

| Byte | Value | Meaning |
|------|-------|---------|
| 0 | `0xFF` | UTF-8 escape / action flag |
| 1 | `0x50` | `'P'` |
| 2 | `0x4E` | `'N'` |
| 3 | `[opcode]` | 1 byte, `0x01`–`0x0F` |

**The carrier is a single, minimally-encoded push.** "The payload" — the bytes the prefix
test above reads — is defined as the data of a **lone data push**: the
output's `scriptPubKey` MUST be exactly `OP_RETURN <push>`, where `<push>` is one minimal push of
`P` bytes (`P ≤ 9,996` — the §6 pinned ceiling), and the payload is precisely those `P` bytes. Dogecoin relays **multi-push**
`OP_RETURN`s (`OP_RETURN <push₁><push₂>…`) as standard, so this MUST be pinned: an `OP_RETURN` that
is **not** exactly one minimal push — multiple pushes, a non-minimal push, or any trailing opcode —
is **not** a protocol carrier and falls through to *ignore* (it is not a protocol action),
no matter what its first push spells. This makes "the payload" single-valued for every
indexer; the 4-byte prefix test (here) then operates on
those exact `P` bytes. (Batching still works — it places **several single-push `OP_RETURN`
outputs** in one tx, §3.5, never several pushes in one output.)

---

## 2. The Action Registry

Fifteen opcodes, all live at `ACTIVATION_HEIGHT` = **1,130,000** (§3.0): the names +
market layer (the directed-sale pair **`0x0C` SELL_TO / `0x0D` PAY**, §3.7) and the multi-identity
pair **`0x0E` AS / `0x0F` TRADE** (custodial batching + atomic 1-1 name swap, §3.9), spanning
`0x01`–`0x0F`. The set-mutating ops come in two forms — **by-name** (the payload names its one
target directly: RENEW_NAME / TRANSFER_NAME / RELEASE_NAME, §3.5) and **bitmap** (a flag field
selects positions in the owned set: RENEW / TRANSFER / RELEASE, §3.5) — surgical vs. bulk, same
state semantics. Wire formats are summarized here and specified per-op below.

| Opcode | Action | Payload | Value field |
|--------|--------|---------|-------------|
| **Live at `ACTIVATION_HEIGHT`** | | | |
| `0x01` | RENEW_NAME | `name` (one per `OP_RETURN`) | **rent** → lease (water-fill §3.5) |
| `0x02` | TRANSFER_NAME | `target`(20) + `name` | — (fee-only) |
| `0x03` | COMMIT | `commitment`(32) | — |
| `0x04` | CLAIM | `salt`(32) + `name` | **rent** → lease (water-fill §3.5) |
| `0x05` | RENEW | *(none)* [+ `anchor`(5) [+ `flags`]] | **rent** → lease (water-fill §3.5) |
| `0x06` | TRANSFER | `target`(20) [+ `anchor`(5) + `flags`] | — |
| `0x07` | SELL | `price`(8) + `window`(4) + `name` | — |
| `0x08` | RESERVE | `name` (one per `OP_RETURN`) | **burn-leg** (deposit, §3.7) |
| `0x09` | SETTLE | `name` (one per `OP_RETURN`) | — (payment is in outputs) |
| `0x0A` | RELEASE | `anchor`(5) + `flags` | — (fee-only) |
| `0x0B` | RELEASE_NAME | `name` (one per `OP_RETURN`) | — (fee-only) |
| `0x0C` | SELL_TO | `price`(8) + `buyer`(20) + `name` | — (fee-only; directed offer, §3.7) |
| `0x0D` | PAY | `name` (one per `OP_RETURN`) | — (payment is in outputs, §3.7) |
| `0x0E` | AS | `[index:1]` | — (fee-only; sets acting identity to vin[index], §3.9) |
| `0x0F` | TRADE | `[idxA:1][idxB:1]` + `nameA,nameB` | — (fee-only; atomic 1-1 name swap, §3.9) |

**Reserved — the overlay band `0x38`–`0xFF`.** The **last 200 opcodes are permanently reserved
for overlay protocols** — layers that reuse the `0xFF 'P' 'N'` framing. This is a contract, not new
fold behavior: an `OP_RETURN` whose opcode byte falls outside `0x01`–`0x0F` already falls
through to *ignore* (§5), and that must stay true **forever** for the band: any future
*on-chain* opcode MUST be assigned in `0x10`–`0x37`, so an overlay carrier can never collide
with a chain action.

---

## 3. Action Logic & Constraints

### 3.0 Activation & launch (fair launch)

The live deployment (Pepecoin mainnet) pins two heights:

| pin | height | meaning |
|-----|--------|---------|
| `ACTIVATION_HEIGHT` | **1,130,000** | every opcode goes live here, atomically |
| `ORACLE_START` | **1,119,000** | fold checkpoint — the pinned anchor header (`cda615cf…fad1bb`, PoW-validated); the first block an indexer ingests is `ORACLE_START + 1` |

Every opcode — COMMIT/CLAIM, the renew/gift/relinquish layer in both its by-name
(RENEW_NAME/TRANSFER_NAME/RELEASE_NAME) and bitmap (RENEW/TRANSFER/RELEASE) forms, the open
SELL/RESERVE/SETTLE and directed SELL_TO/PAY market, and the AS/TRADE multi-identity layer —
switches on **atomically** at `ACTIVATION_HEIGHT`. An action below the height is **dropped** and
**never** retroactively applied (forward-only). Folding the whole names layer into one
height makes commit–claim front-run protection mandatory from the first block any name can
be claimed (§3.2). Because a CLAIM needs a commit in a *strictly earlier* block and commits
are themselves gated, the first commits land at `ACTIVATION_HEIGHT` and the first claims at
`ACTIVATION_HEIGHT + 1` — a built-in **blind commit phase** before any name is revealed.

`ORACLE_START` sits **11,000 blocks below activation**, so the §3.4 fee oracle's
`FEE_WINDOW` (10,081 blocks, fed from `ORACLE_START + 1`) is **full from block 1,129,082**
— 918 blocks *before* the first live op. Every rate the fold ever computes for a live
action is a full-window rate; there is no partial-window launch case, and every indexer
shares the identical pinned window.

**No mint price floor.** The fair-launch mechanism is the pinned height + first-come
priority (§3.2); there is no elevated burn on a fresh claim. Claims pay only their lease
rent (§3.4); anti-squat is the permanent stack (rent ∝ names × time + name-is-decoration).
Because commits are opaque, a launch front-runner cannot target a specific name's commit,
so a contested hot name resolves as a fair blind auction among everyone who independently
wanted it.

### 3.1 Identity — the owned set

An address **owns a set of names** (0..many) — the *owned set*. Each name is fully and
identically owned and blocks any other claim until its `lease_expiry`. Multi-name-per-address is chosen on UTXO-bloat
grounds: 1-name-per-address would force a separate funded address — hence a separate UTXO —
per name, and live UTXO-set bloat is far worse for every full node than prunable index
rows. With multi-name, index bloat scales with *users*, not *names*, and the names are
`OP_RETURN` data, never in the UTXO set.

**Identity is global shared state** — every indexer MUST resolve the same owner — so claim
priority and the rent rate are protocol-fixed, never client policy (§3.8).

**Name validation** (deterministic; invalid → action ignored): canonical charset
`[a-z0-9-]` (lowercase letters, digits, hyphen — DNS's host-label alphabet minus uppercase),
length **1–32** bytes, plus three **structural** rules — **no leading hyphen**, **no trailing
hyphen**, and **no `--` at positions 3–4** (`name[2]=='-' && name[3]=='-'`, which kills a
leading `xn--` and every other IDNA ACE prefix). The charset is **already lowercase**
and there is **no case-folding**: a name is matched byte-for-byte as it appears on the wire,
and any byte outside `[a-z0-9-]` — an uppercase letter, `_`, or `.` **included** — makes the name invalid,
so the carrying action is **ignored** (a `CLAIM "Alice"` is dropped, **not** silently
lower-cased to `alice` and minted). Treating the lowercase as merely *canonical* and folding
mixed case on the wire would mint names a strict reader rejects — a direct namespace fork — so
the rule is reject, never fold. ASCII-only kills Unicode homoglyphs but not ASCII confusables
(`0/o`, `1/l`, `rn/m`)(§4).

**Two ways to give up a name — RELEASE (active) and lapse (passive).** Stop renewing and a
name **lapses** for free when its lease ends — the zero-cost path when you don't care
*when* it frees. **RELEASE / RELEASE_NAME (§3.6)** are the on-demand version: one fee-only tx
returns selected names (a bitmap batch, or one name by string) to the pool **immediately**,
without waiting out a prepaid lease — freeing a long-prepaid name *now*, or scrubbing
gift-spam out of your owned set. There is
no general "pending" state; a name **listed for sale or under a directed offer** (§3.7) is the
one *locked* state — still owned and **still renewable**, but frozen against
TRANSFER/RELEASE/SELL/SELL_TO until it settles, is paid, or the listing/offer ends.

### 3.2 Claiming — mandatory commit→claim (front-run protection)

Minting a name is a **CLAIM**, and **every CLAIM MUST be backed by an earlier COMMIT** —
there are **no naked claims**. The commit MUST be **at least one block deep** when the claim
confirms (`commit_height < claim_height` — a *strictly earlier* block; same-block is too
shallow). A claim with no live matching commit ≥1 block deep is **dropped**; it mints
nothing.

**COMMIT (`0x03`).** Payload: `commitment` (32 bytes) =
`SHA-256(salt ‖ name ‖ committer_hash160)`, with `salt` **exactly 32 bytes** of entropy and
`committer_hash160` = the committer's `vin[0]` identity (§4). The committed `salt` MUST be the
**same fixed-width 32 bytes** the matching CLAIM later reveals; that fixed width keeps
`name`'s length implicit in the CLAIM payload, so the two cannot disagree. The indexer
records `{commitment, commit_height, tx_index, commit_time}` and nothing else — a commit mints
nothing, owns nothing, leaks nothing (the opaque hash reveals neither name nor committer).
`commit_time` is the **MTP of the commit's confirmation block** (the same MTP clock every other
wall-clock boundary uses, §0/§7), so the live window is comparable against the MTP the fold
evaluates at claim time. The commit is live while `MTP ∈ [commit_time, commit_time + COMMIT_EXPIRY]`
— a **closed** interval (live *through* the endpoint) — and self-prunes once
`MTP > commit_time + COMMIT_EXPIRY`; this commit window is deliberately **inclusive**, the lone
exception to the exclusive lease/offer/reserve bounds (§5). Fee-only.

A commit row is pruned **only** by that time bound. A successful CLAIM does **not** consume or
remove its backing commit — the row **lingers** in the `commits` table until
`MTP > commit_time + COMMIT_EXPIRY`, exactly as an unused commit would (there is no
delete-on-use). Lingering is harmless to ownership: a freshly-claimed name stays owned for ≥1
day, far longer than the ≤5 h commit life, so a left-over commit can never back a second
successful claim before it self-prunes. It is **not** harmless to the canonical digest: the
`commits` table is digested, so an indexer that deleted a commit on use would carry a smaller
`commits` set — and a different state digest — for the ~20–60 blocks the row would otherwise
still live. Indexers MUST therefore retain a used commit until its time-prune; **delete-on-use
silently forks the digest**.

The 32-byte salt makes the commitment opaque against brute-force over the small namespace
(`SHA-256(name)` alone would be brute-forceable). The `committer_hash160` term binds the
commitment to its committer so a copied commitment is inert: an attacker who re-posts a
victim's commitment under their own tx gains nothing, because only the victim can produce a
matching claim and the attacker never learns `salt`. An indexer omitting the committer term
would let a commitment-copy attack steal the name; an indexer MUST include the committer term.

**CLAIM (`0x04`).** Payload: `salt` (32) + `name`. Mints `name` into the claimant's owned set
and buys its initial lease — the burn *is* the duration (§3.3–§3.4), so a bigger
burn buys a longer first lease (capped at `MAX_LEASE`). CLAIM is the *only* mint. The `OP_RETURN` **value is the
rent**: it buys `⌊value × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋` days of lease and MUST
cover at least one day (§3.4).

A name **already owned** → **dropped**. Otherwise the claim mints **iff** a **live** commit
row exists whose value equals `SHA-256(salt ‖ name ‖ committer_hash160)` (`committer_hash160` = this claim's
own `vin[0]` identity) in a **strictly earlier block** (`commit_height < claim_height`, still within
`COMMIT_EXPIRY`); among all such rows the backing commit is the one minimizing
`(commit_height, tx_index)` — that row sets both `commit_height` **and** the `tx_index` the claim
carries into the tie-break below, single-valued even when one committer committed the same name more
than once. **No matching ≥1-deep commit → the claim is dropped** (no FCFS fallback). A **same-block** commit is too shallow
and does **not** back a claim.

**Priority — the tuple `(claim_height, commit_height, tx_index)`.** Among competing fresh
claims for one name the winner minimizes this tuple:

- **`claim_height`** (the claim's own block) is primary: a *later* claim can **never**
  displace an earlier holder (no retroactive rug).
- **`commit_height`** is secondary, and is the protection: a reactive attacker who learned
  the name only from your CLAIM can have committed no earlier than your claim's block, so
  their `commit_height ≥ claim_height > your commit_height` and they lose before fee or
  tx-index is consulted. Two honest early committers settle by the earlier `commit_height`.
- **`tx_index`** is the final tie-break, and it is the **commit's** `tx_index` — the position of
  the backing commit in its block (the commit row is `{commitment, commit_height, tx_index, commit_time}`), **not**
  the claim's chain order. Two genuine same-`commit_height` rushers settle by whichever *committed*
  earliest in that block. (Indexers MUST carry the backing commit's `tx_index` into the same-block
  claim contest; settling such a tie by claim order instead silently forks.)

The mandatory 1-block floor forces a reactive attacker's claim into a strictly later block.
Beyond it, how much deeper to bury the commit is a **client-side risk choice**: the only
residual is an adversary who can rewrite ≥2 blocks (commit block + claim block) to splice a
commit+claim ahead of your claim; bury the commit deeper to insure against deeper reorgs
(exposed as a slider, defaulted low).

**What it closes / doesn't.** Closed for **every** claim (no opt-out): reactive
front-running of a quiet fresh claim — the ransom *and* the denial — at any fee. Open and
accepted: *camping a predictable name* (an attacker who pre-commits to a foreseeable
high-value name and refreshes every `COMMIT_EXPIRY` can still contest its claim — bounded by
refresh cost, reaches only predictable names) and *lapse-sniping* (a lapsed name's
availability is public, so there is no hidden intent — it resolves as a blind auction:
everyone commits opaquely, the earliest valid commit wins).

### 3.3 Leases — pay-for-duration

A name carries `lease_expiry` (an MTP timestamp). It is **owned** iff
`MTP(tip) < lease_expiry`. You buy exactly the lease time you want:

- **The burn *is* the duration** — there is no duration field. A burn `B` over `count` names
  buys `⌊B × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋` total **name·days** of lease (§3.4),
  allocated across them by the water-fill in §3.5, each capped so its `lease_expiry` never
  exceeds `MTP_now + MAX_LEASE` (you may stack/pre-pay up to that ceiling). **Leases extend
  in whole days** (`BILLING_UNIT`), not 28-day quanta — fine enough to renew for 30 or 200
  days, yet coarse enough that the per-day price stays well above `DUST_FLOOR`. Cost is
  **linear** in lease time — want a shorter lease, burn less.

Pay-for-duration is chosen for host-network health: the dominant permanent host cost is
chain bloat, and renewal traffic = `Σ (1 / lease_length)`, so fewer, longer leases are
strictly cheaper for hosts per lease-day. Linear pricing already aligns the holder's
incentive with host health without any protocol discount: a holder choosing one 365-day
lease over thirteen 28-day renewals pays 13× fewer miner fees. Anti-squat is purely "pay
rent ∝ names × time held."

**Lapse → pool.** When `MTP` passes `lease_expiry` the name returns to claimable supply and is **immediately
reclaimable** by a new COMMIT/CLAIM. A reclaim that a later reorg reverses (by restoring the
prior owner's renewal) is dropped on replay (§5) — the same client-side reorg risk as any
fresh claim, and a lapse-reclaim is a blind auction regardless (commit-then-claim like any
mint, §3.2). There is no protocol-level cooling window.


### 3.4 The burn — the coinbase fee oracle

The rent rate for CLAIM/RENEW is value-stable, governance-free, and **stateless**:

```
# at confirmation height h, over the FEE_WINDOW blocks STRICTLY BELOW h — i ∈ [h−FEE_WINDOW, h−1]:
feesᵢ         = max(0, coinbase_output_totalᵢ − subsidyᵢ)                         # SIGNED / ≥128-bit, clamp at 0 — NOT unsigned (a miner may under-claim)
fee_per_byteᵢ = ⌊feesᵢ / max(1, block_bytesᵢ)⌋                                    # per block, FLOOR division → whole koinu/byte; block_bytesᵢ ≥ 1 always (coinbase tx), divisor pinned to 1 if a reading is 0 — never /0, never fee-per-byte 0
P             = sort_asc( [ fee_per_byteᵢ : i ∈ [h−FEE_WINDOW, h−1], fee_per_byteᵢ ≥ 1 ] )   # the PARTICIPANT list: fee-bearing blocks only
rate          = DUST_FLOOR                                                  if |P| < MIN_FEE_SAMPLE
              = clamp( P[⌊(|P|−1)/2⌋] × REF_SIZE, DUST_FLOOR, RATE_CAP )    otherwise        # koinu per name·quantum
# P[⌊(|P|−1)/2⌋] (0-indexed) = the LOWER median, one index rule for ANY length: for odd |P| it is
# the true middle element; for even |P| it is the LOWER of the two middle elements. The median is
# therefore always a single actually-observed value — NEVER a two-element average, so there is no
# floor/ceil/round rule for indexers to split on, at any participant count.
# subsidyᵢ = the HOST chain's consensus subsidy at height i, pinned per deployment in its host-chain profile (Dogecoin and Pepecoin are both flat 10_000/block = 1_000_000_000_000 koinu across the reachable window); block_bytesᵢ = block tx-data size, AuxPoW header excluded (both pinned below)
# no duration field — a burn B buys T = ⌊B × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋ name·days, water-filled (§3.5)
```

- **Stateless** — total fees come straight from `coinbase_output − known_subsidy(height)`,
  computable from the block alone with **no UTXO set**. This is what keeps fee-awareness
  inside the stateless model.
- **`subsidyᵢ` and `block_bytesᵢ` are pinned exactly** — both feed the rate, so an inexact reading
  forks it. `subsidyᵢ` is **the host chain's own consensus block subsidy at height `i`** — PepeNet
  holds no independent subsidy number, only this pointer to the host's, and each deployment pins the
  exact function in its **host-chain profile**. For both current hosts
  the entire reachable window sits in the **flat 10 000/block tail** — Dogecoin and Pepecoin (a
  Dogecoin fork with the same schedule shape) both switch to the flat reward at block 600 000, and a
  profile MUST pin `ACTIVATION_HEIGHT ≥ 600 000 + FEE_WINDOW` so no indexer ever replays the early
  variable-subsidy era (the live pin, 1,130,000, sits deep in the tail). Because it is the *host's* value, a host **emission change** (e.g. a
  block-speed re-scale that drops the per-block reward) is tracked by **following the host's
  schedule, never a PepeNet fork**; a coordinated PepeNet-side cutover, if ever wanted, rides a
  §3.8 activation height. `block_bytesᵢ` is the serialized size of the block's **transaction data** — pinned exactly as
  **`Σ over the block's transactions of len(raw_tx)`**, the sum of each transaction's own serialized
  byte length (DOGE has no SegWit, so each `raw_tx` is its single unambiguous legacy serialization).
  The **80-byte block header, the tx-count varint, and all AuxPoW parent-block header data are
  excluded** (Dogecoin is merged-mined; counting the header, the count varint, or the AuxPoW
  commitment would make "block size" library-dependent) — only the blockspace that fees actually pay
  for is counted. This per-tx-sum definition is consensus-critical: an indexer that instead took
  "whole-block size minus header" would fold in the tx-count varint and **fork the rate**.
- **Value-stable** — it tracks real blockspace value, self-adjusting as DOGE moves; no
  governed constant to peg, no oracle to centralize.
- **Block-speed-invariant** — `fee_per_byte` is a **density**, so a host block-speed change cancels:
  10×-faster blocks each carry ~1/10 the fees over ~1/10 the bytes → the same per-byte value, and
  `rate` is denominated per `LEASE_QUANTUM` (MTP/wall-clock), not per block. A speed change therefore
  moves the rate by **zero** as long as `subsidyᵢ` stays correct (above); the only thing that scales
  is `FEE_WINDOW`'s wall-clock *span* — it is a fixed block **count** (required for the single-element
  median), so its ~1 wk horizon shrinks under faster blocks, parallel to `MAX_ANCHOR_AGE` (§7). Lease
  **durations** are MTP and never move.
- **Fee-bearing blocks only (`MIN_FEE_SAMPLE`).** The median is taken over the **participant
  list `P`** — the window's blocks whose floor-divided `fee_per_byteᵢ` is **≥ 1** — not over the
  whole window. Rationale: on a quiet host chain a majority of blocks carry zero fees, a
  whole-window median then reads 0, and the rate collapses to `DUST_FLOOR` even though every
  block that *does* carry a transaction demonstrably clears at the host's going feerate. The
  participant median answers "what do fee-payers actually pay per byte": on a busy chain it is
  the same demand signal as before (zeros are rare, the two medians coincide); on a quiet chain
  it reads approximately the host's customary per-kB feerate — a *policy* signal rather than a
  scarcity signal, which is the intended reading. Membership is decided **after** the floor
  division: a block whose real-but-tiny fees floor to 0 koinu/byte is NOT a participant (this
  is the same integer every indexer already computes — no new arithmetic).
- **Degrade, don't extrapolate (`MIN_FEE_SAMPLE = 1000`).** If the window holds **fewer than
  `MIN_FEE_SAMPLE` participants**, the rate is `DUST_FLOOR` exactly — a small sample is
  spoofably cheap to own, so the oracle degrades gracefully instead of trusting it. The
  boundary is pinned **inclusive**: `|P| = MIN_FEE_SAMPLE` (exactly 1000 participants) takes
  the median path; `|P| = 999` floors. Note the deliberate consequence: the rate is
  **discontinuous** at this threshold — two adjacent confirmation heights can price rent at
  `DUST_FLOOR` and at `median × REF_SIZE` respectively when organic participation hovers near
  ~10 % of the window. This is deterministic (every indexer flips at the same height),
  cap-bounded, and accepted: a chain that hovers at exactly the threshold is a narrow regime,
  and the alternative (blending or hysteresis) would need state the oracle deliberately
  doesn't have.
- **Floored** at `DUST_FLOOR` (graceful degradation when fees are absent or participants
  scarce), **capped** at `RATE_CAP = 1 DOGE` (bounds miner grief), **median-smoothed** over
  the participants of a ~1-week window (robust to single-block fee stuffing; to move the
  median an attacker must fee-populate on the order of half the participant count).
- **Integer-deterministic (consensus-critical)** — every step is fixed-width integer math. The fee
  numerator is **`max(0, coinbase_output_totalᵢ − subsidyᵢ)` computed signed in ≥128-bit**: a miner
  may legally **under-claim** the coinbase (`coinbase < subsidy`), and an **unsigned** subtraction
  would **wrap to ~2⁶⁴** — spiking that block's `fee_per_byte`, wrongly enrolling it as a
  participant, and shifting the median by a rank → a rate fork; clamping the numerator at 0 makes
  an under-claim read as **zero fees** (a non-participant) identically for every indexer. Each
  per-block `fee_per_byteᵢ` is then **floor**-divided to whole koinu/byte; the window is the
  `FEE_WINDOW` blocks **strictly below** the confirmation height (`i ∈ [h−FEE_WINDOW, h−1]`,
  block `h` itself excluded). The participant count has **no fixed parity**, so the median is
  pinned as the **lower median** — sort `P` ascending and take the single element at 0-indexed
  position `⌊(|P|−1)/2⌋`. For odd `|P|` this is the true middle; for even `|P|` it is the **lower** of the two middle elements — chosen over
  the upper because ties then price rent *cheaper*, the conservative direction, and over an
  average because an average of two integers needs a rounding rule and can produce a value no
  block actually exhibited. One index formula covers every length ≥ 1; there is nothing to
  disagree on. `ORACLE_START` is pinned `> FEE_WINDOW` blocks below `ACTIVATION_HEIGHT`
  (§3.0: 11,000 vs 10,081), so the window is already **full at activation** — every rate a
  live action ever sees is a full-window rate, identical for every indexer since all share
  the same checkpoint. An indexer that checkpoint-syncs MUST still ingest the coinbase
  totals + block sizes of the whole window back to `ORACLE_START` (header-only sync is
  insufficient for the oracle).
- At recent Dogecoin fee densities, `REF_SIZE = 200`, and the 28-day `LEASE_QUANTUM`, the
  rent lands near **~1 DOGE/name/year** at full-block density, scaling down with block
  slack; `RATE_CAP = 1 DOGE/quantum` (≈ 13 DOGE/yr ceiling) sits ~13× above today's rate.

The participant median over the ~1-week `FEE_WINDOW`, the `MIN_FEE_SAMPLE` degrade, and the
`DUST_FLOOR`..`RATE_CAP` clamp together bound both rate-suppression and rate-inflation.

The rate is evaluated at the action's **confirmation** height (deterministic for the fold),
so it drifts after you sign — which is why funding is forgiving (partial-fill, §3.5).

### 3.5 Batching — bitmaps & partial-fill

**There are no per-tx count caps anywhere — any cap is *relay*, never *protocol*.** Every
state op batches, bounded only by transaction size and funds (the bitmap ops fill one
`OP_RETURN`; the market ops place several `OP_RETURN`s in one tx, §3.7). A tx may carry any
number of inputs, carriers, and outputs; a fold MUST size to the transaction, never impose a
below-block structural limit (an indexer that capped inputs/carriers/outputs would drop txs a
conformant fold settles — a state fork). The anti-abuse on every op is **economic** (a burn
or payment per name) or **exclusivity** (the market), never structural counting. **There is no
below-block structural cap anywhere** — every conforming fold sizes to the transaction, and the
only limits are relay (transaction size + funds), never protocol.

**The burn is the duration; the rent is applied as fully as possible (water-fill).** There
is no `duration` field; a burn `B` over `count` names at `rate` already fixes the lease
time. Omitting it saves a byte (a 4-byte renew-all; selective covers any set, §6) and lets the rent
be applied *fully*, never wasted:

1. The burn buys `T = ⌊B × LEASE_QUANTUM / (rate × BILLING_UNIT)⌋` total name·**days** — the
   `LEASE_QUANTUM/BILLING_UNIT` factor (= 28) rescales the per-quantum `rate` to a per-day
   price; take the numerator multiply in ≥128-bit. Fail **closed** if `T = 0`.
2. Spread `T` **evenly** across the targeted names — but name *i* can absorb only
   `hᵢ = ⌊(MAX_LEASE − (expiryᵢ − now)) / BILLING_UNIT⌋` more **days** before it hits the
   `MAX_LEASE` ceiling.
3. **Water-fill:** raise a uniform level `λ` (each name takes `min(hᵢ, λ)` days); a name that
   caps drops out and its share flows to the rest, until `T` is spent or every name caps. Any
   integer remainder after the even level goes `+1` **day** to the first headroom-having names
   in ascending-lexicographic order; each name's `lease_expiry += add × BILLING_UNIT`. If
   **every** targeted name reaches its `MAX_LEASE` ceiling while `T > 0` still remains, the
   unallocated remainder is **forfeited** — the burn was already destroyed in the unspendable
   `OP_RETURN`, so nothing is carried forward or refunded (every indexer computes the identical
   capped allocation, so there is nothing to disagree on).

So a fee spike neither drops names nor wastes coin: it buys a shorter, evenly-shorter lease
across the whole batch, and a name that would over-shoot `MAX_LEASE` redirects its rent to
the names that still need it. This is a deterministic integer computation, and the water-fill
above is authoritative in **every** regime — underfunding is not a separate rule but the
`λ = 0` case of the same fill. The only regime where a name still goes unrenewed is when `T` is
smaller than the number of names that *have* headroom (`hᵢ > 0`) — funding below even one day per
**eligible** name. There the even level `λ` is `0`, so the whole of `T` falls to the remainder step:
`+1` **day** to the first `T` headroom-having names in **ascending-lexicographic order** (the same
ordering the remainder step always uses), and the rest none. A name already at its `MAX_LEASE`
ceiling (`hᵢ = 0`) is **skipped** — never counted toward this threshold and never awarded a day — so
its slot flows to the next eligible name exactly as a capped name redistributes in the water-fill
above. The threshold is the count of **headroom-having** names, **not** the total selected `count`:
when zero-headroom names pad the batch, a single eligible name can still absorb many days — one name
with headroom and `T = 50` takes **50** days, not one. (Reading the trigger as a literal `T < count`
branch that awards one day each would forfeit those days and fork against the water-fill. Skipping a
zero-headroom name rather than burning a slot on it is consensus-critical: counting it would renew a
different subset.)

**Payment ops (RESERVE / SETTLE / PAY) are one name per `OP_RETURN`, batched at the *transaction*
level.** Each carries exactly one listing (name length implicit from the `OP_RETURN`), and
its amount is a fixed, indivisible per-name fraction of that name's listed price (the whole
price for PAY) — nothing to water-fill. To act on several listings at once, place **several
RESERVE/SETTLE/PAY `OP_RETURN`s in one transaction** (the same multi-`OP_RETURN` unlock the rest
of the spec rides on, §0), and the money stays **individually split**: each listing's burn-leg is
its own RESERVE `OP_RETURN` value, and each listing's pay-leg / settle-remainder / PAY price is its
own **exact-value output** to that seller — never summed. The count per tx is bounded only by
transaction size and relay (today one `OP_RETURN`/tx; many once multi-`OP_RETURN` relay
lands), **never by the protocol**.

**Per-tx output matching (consensus-critical, deterministic).** A listing's owed amount is
matched against the transaction's *spendable* outputs: processing the tx's market
`OP_RETURN`s in `vout` order, each **consumes the lowest-`vout` not-yet-consumed output whose
`(scriptPubKey, value)` equals `(seller, owed)` exactly**; if none remains, that op
**drops**. Consume-once + exact-value forces the split (a summed output matches *no* single
listing's owed amount); the `vout`-order rule keeps it byte-identical across indexers.

**Target selection per op:**

| op | selection |
|----|-----------|
| CLAIM / RESERVE / SETTLE / SELL_TO / PAY | one `name` per `OP_RETURN` (batch >1 needs multi-`OP_RETURN`) |
| RENEW_NAME / RELEASE_NAME | one `name` per `OP_RETURN` (batch >1 needs multi-`OP_RETURN`) |
| TRANSFER_NAME | one `name` per `OP_RETURN` → one target |
| RENEW / RELEASE | **bitmap** over your owned-set (which the indexer already tracks) |
| TRANSFER | bitmap over owned-set → one target |
| TRADE | one `name` from each party, swapped atomically (§3.9) |

#### The by-name forms — RENEW_NAME (`0x01`) · TRANSFER_NAME (`0x02`) · RELEASE_NAME (`0x0B`)

Each by-name op is the **singleton form of its bitmap sibling**: identical state semantics,
applied to exactly the one name its payload spells out.

```
RENEW_NAME     [0xFF PN 0x01][name:1..32]              = 5..36 B    value = rent → lease
TRANSFER_NAME  [0xFF PN 0x02][target:20][name:1..32]   = 25..56 B   fee-only; lease conveys
RELEASE_NAME   [0xFF PN 0x0B][name:1..32]              = 5..36 B    fee-only; → pool now
```

- **No anchor, no bitmap.** A name string is its own **position-independent address** into the
  owned set — nothing positional can go stale, so the by-name ops carry no anchor and are not
  subject to the anchor guard. They are valid under any amount of concurrent set churn:
  where a bitmap op reject-and-resends when `last_set_mutation_height` moves past its anchor
  (§3.5 below), a by-name op simply applies. This is the surgical/bulk split: by-name ops act
  on one name with zero coupling to the rest of the set; bitmap ops amortize one carrier
  across up to the whole set.
- **The name MUST be in the actor's owned set** (`name` valid per §3.1; the owned set includes
  a listed/offered name, still the seller's, §3.7). Not in the actor's set → **drop**. There is
  no third-party operation: only the owner (seller, for a locked name) can act on a name.
- **RENEW_NAME** — the `OP_RETURN` value is the rent; the §3.5 water-fill runs over the
  singleton set: the burn buys `T` name·days, the name absorbs `min(T, headroom)` days toward
  `MAX_LEASE`, and any excess past the ceiling is forfeited (the burn is already destroyed).
  Fail-closed at `T = 0`. A **listed or offered name is still renewable** (§3.7), by its
  seller, exactly as under a bitmap RENEW. Renewal is not a set mutation: **no**
  `last_set_mutation_height` bump.
- **TRANSFER_NAME** — gift-only, exactly one name to one `target` (hash160). Lease conveys;
  the name enters `target`'s owned set immediately and irreversibly (§3.6). A **locked**
  (listed/offered) name is movement-frozen: the op is a **no-op** (the locked-name skip rule
  below, applied to a one-name selection) and bumps nothing. A completed move **bumps both parties'**
  `last_set_mutation_height`; a self-target (`target` = current owner) is still a move and
  still bumps, exactly as the bitmap TRANSFER pins below.
- **RELEASE_NAME** — returns the one name to the claimable pool immediately, under RELEASE's
  full semantics (§3.6: forfeited lease, immediate reclaimability, presence-not-history).
  A locked name → **no-op**, no bump. A completed release **bumps the actor's**
  `last_set_mutation_height`.

#### RENEW wire format (the pinned form)

```
RENEW all        [0xFF PN 0x05]                            = 4 B   renew every owned name (water-fill the burn)
RENEW all (safe) [0xFF PN 0x05][anchor:5]                  = 9 B   same, reject if the set changed since H
RENEW selective  [0xFF PN 0x05][anchor:5][flags:1..9987]   = 10..9,996 B   79,896 names (568 within default relay)
```

- Bits index your owned-set: all owned names **lexicographically** (unsigned bytewise on the raw
  name) from bit 0. Bit *i* set ⇒ renew that name, and bit *i* is read **LSB-first within each flag
  byte** — `bit i = (flags[i >> 3] >> (i & 7)) & 1` — so byte 0's least-significant bit is name 0.
  The LSB-first mapping is consensus-critical: an MSB-first reader selects a different name for the
  same flag byte, so every indexer MUST use exactly this bit order. Length disambiguates the three
  modes (`4 / 9 / 10..9,996`; lengths `5..8` invalid) — these are **whole-`OP_RETURN` payload** lengths
  (the 4-byte `0xFF PN 0x05` prefix included). The decoder works in *body* length `bl = len − 4`
  (`bl ∈ {0, 5} ∪ [6,9992]`); the two are the same accept/reject set once the
  prefix is subtracted, so an impl that read `4 / 9 / 10..9,996` as *body* lengths would shift the whole
  band and fork the decoder. A holder whose set outgrows even the 79,896-position consensus
  reach (§6) uses renew-all, or waits for the multi-`OP_RETURN` offset byte.
- **Out-of-bounds bits are ignored, not fatal.** Let `K` be the size of the (anchor-validated)
  owned set. Only bits `0..K−1` are meaningful; **any bit at index ≥ `K` is ignored regardless of
  value** — it addresses no name, so it neither acts nor drops the action. (Sub-byte trailing pad
  is unavoidable whenever `K` is not a multiple of 8, since the flag field is byte-granular; this
  is the same "ignore the pad" treatment extended to every index past the set.) Every indexer
  ignores exactly the same bits, so this is deterministic; it is the forgiving counterpart to the
  anchor guard, which catches a *stale* set view loudly (`last_mutation > H` → reject-and-resend)
  **before** any bit is interpreted. The same rule governs RELEASE's and TRANSFER's bitmaps — an
  out-of-bounds bit can never erroneously release or transfer a name (there is no name at that
  index), so the anchor guard, not the bounds rule, is what protects the destructive ops.
- **A locked name selected by a destructive bitmap is skipped, not fatal.** A name currently
  **listed (SELL) or offered (SELL_TO)** is movement-locked (§3.7) yet keeps its owned-set position
  (a listing/offer is not a mutation, so it neither bumps the anchor nor renumbers any bit). If a
  **RELEASE** or **TRANSFER** bitmap selects such a name, that name is **skipped** — the op applies
  to the selected **unlocked** subset and the locked name stays put, exactly the per-name filter the
  out-of-bounds rule uses, never a whole-op drop. This preserves the escrow guarantee (a listed name
  cannot move out from under a buyer) while letting the rest of a batch proceed. **RENEW has no such
  exception** — a listed/offered name is still renewable (§3.7), so a RENEW bit on it renews
  normally; a whole-set TRANSFER-all likewise skips any locked name while moving the rest. A
  RELEASE/TRANSFER that ends up touching **no** name (every selected bit was locked or
  out-of-bounds) is a **no-op and does not bump** `last_set_mutation_height` — the bump tracks an
  actual set/ordering change, so an all-skipped op leaves the anchor untouched.
- The **5-byte absolute height anchor `H`** pins the bitmap's meaning. A per-owner
  `last_set_mutation_height` is bumped on any
  CLAIM/TRANSFER/TRANSFER_NAME/RELEASE/RELEASE_NAME/SETTLE/PAY/TRADE/lapse touching
  the set **or its ordering**, for *either* party (a TRANSFER adds the name to the recipient's set
  and removes it from the sender's, SETTLE and PAY both add to the buyer's set and remove from the
  seller's, and a TRADE moves names both ways between its two parties, so they all bump
  **both** parties — only an op that actually moves ≥1 name bumps; an all-skipped/out-of-bounds op
  bumps neither). A TRANSFER whose target **equals the current owner** is still a move: the name
  is re-assigned to itself, applied exactly as any other TRANSFER, so it **bumps**
  `last_set_mutation_height` (both "parties" resolve to that one owner). A self-target is never a
  no-op — the only non-bumping TRANSFER/RELEASE is one that touches **zero** names (every selected
  bit locked or out-of-bounds). A **time-triggered** set change with no native tx — a **lapse** removing a name from
  its owner's set — stamps that owner's `last_set_mutation_height` to the **connecting block's
  height `H`** (the block whose pre-block phase applied it, §5); an offer/reserve close leaves the
  name in the seller's set unchanged and does **not** bump. A SELL **listing** or a SELL_TO **offer** is
  deliberately **not** a mutation: the name stays in the seller's owned set (still renewable,
  §3.7), keeping its bitmap position, so a live RENEW bitmap spanning a listing or offer is
  unaffected. Selective renew is
  valid **iff** `last_mutation ≤ H ≤ confirm_height` and `confirm_height − H ≤ MAX_ANCHOR_AGE`.
  If the set has not mutated since `H`, the live lexicographic ordering equals the snapshot
  ordering, so the bits are exact. Worst case under a race is a safe **reject-and-resend**,
  never a wrong-name renewal.
- **`last_set_mutation_height` is a per-owner monotonic high-water mark — it only ever
  increases and is *never pruned*.** A would-be stamp lower than the stored value is ignored,
  and the row is **not** dropped when the owner's live set falls to **empty** (every name
  lapsed, released, traded, or transferred away). The height persists indefinitely as consensus
  state — it is part of the canonical digest (§3.8) — so that (a) an owner who re-acquires a
  name later compares a fresh bitmap against the true high-water mark rather than a reset-to-zero,
  and (b) two indexers agree on the digest regardless of an owner's set transiently emptying. The
  "shed the expired live set" allowance (§3.8) covers name/lease rows and transfer history; it
  does **not** authorize dropping the anchor-guard heights. An indexer that pruned the height row
  for a now-empty owner would carry a smaller mutation-height set and a **different state digest**.
- The upper bound `H ≤ confirm` is **fail-closed** and MUST NOT be relaxed forward; clients
  SHOULD anchor a few blocks back (`H = tip − ~6`, well inside `MAX_ANCHOR_AGE`) so
  `confirm ≥ H` survives any shallow reorg and the snapshot sits on already-buried chain.
- **renew-all** is position-independent (renews the whole live set), so the cheap form needs
  **no anchor** — a small holder pays 4 bytes total. The `all (safe)` form carries the anchor
  only to fail-closed if you are exact-funded and your set grew before confirm.
- The selective reach is a relay-policy question, not a consensus one: consensus accepts
  flags out to bit 79,895 (§6), while a default-relay 80-byte payload reaches the first
  568 set positions. Renew-all covers any number in 4 bytes regardless. The flag
  byte-length scales with ownership, so the cost falls on large holders. (The same
  owned-set ordering governs TRANSFER's and RELEASE's bitmaps. RESERVE and SETTLE carry
  no bitmap — one name per `OP_RETURN`, §3.7.)

**TRANSFER** mirrors this: `[0xFF PN 0x06][target:20]` transfers all owned names to `target`;
`[0xFF PN 0x06][target:20][anchor:5][flags]` transfers the selected ones (the 20-byte target
eats flag space → 79,736 names at the §6 pinned ceiling; 408 within default relay). Lease
conveys (§3.6).

### 3.6 TRANSFER (`0x06`) / TRANSFER_NAME (`0x02`) & RELEASE (`0x0A`) / RELEASE_NAME (`0x0B`) — gift & relinquish

TRANSFER (bitmap) and TRANSFER_NAME (by-string, §3.5) move one or more owned names to another
address. Both are **gift-only** — there is no `cost` field; *paid* sales go through the market
(§3.7), whose escrow is what makes them trustless. Fee-only.

- The moved names enter `target`'s owned set **immediately and irreversibly** (no acceptance
  step; the sender cannot claw back). **The remaining lease conveys** — prepaid rent travels
  with the name, fully visible in index state, so a recipient/buyer sees exactly how much time
  they are getting.
- A received name enters the recipient's owned set with its conveyed lease and, if never
  renewed, lapses when that lease ends — the recipient need do nothing.
- **Gift-spam is priced at the mint and defused at the renew.** To push junk names at a victim
  the attacker must first CLAIM them — paying the rent for whatever lease they convey. The
  victim never renews them (they lapse on the attacker's dime), and their own renewals are
  untouchable: **RENEW_NAME** (§3.5) names its target directly, so it is immune both to the
  set churn an incoming gift causes (a gift bumps the recipient's
  `last_set_mutation_height`, staling any in-flight bitmap anchor) and to water-fill dilution.
  Two cautions on the bitmap forms while junk sits in the set: **renew-all is the wrong
  tool** — the water-fill (§3.5) spreads the burn across *every* owned name, and junk conveyed
  with a short lease has maximal headroom, so it would absorb the victim's rent
  preferentially — and **selective renew is race-prone under sustained gifting** (each
  incoming gift stales the anchor; the guard fails closed, a safe reject-and-resend, but the
  attacker can force the resend repeatedly). So the clean sequence for a gifted-at victim is:
  renew what matters by name, scrub the junk with RELEASE_NAME / a RELEASE bitmap at leisure,
  then resume bulk renews. The storage is economically bounded — occupancy is rented (§3.8).

**RELEASE (`0x0A`).** Payload: `anchor` (5) + `flags` (1..9,987, §6) — a bitmap over your owned set
in the **same lexicographic ordering as RENEW** (§3.5), under the **same anchor guard**
(fail-closed if the set mutated since `H`, so a stale bitmap never releases the wrong name).
Selected names return to the claimable pool **immediately** at this tx's position in the fold.
Fee-only;
**no burn and no refund** — the remaining prepaid lease is forfeited (the rent was already
burned, exactly as on a lapse). A released name is **immediately reclaimable** by a new
COMMIT/CLAIM, identical to a lapse (§5); a reclaim a later reorg reverses is dropped on
replay, the same client-side reorg risk as any fresh claim (§3.2). Reclaim is decided by
**presence, not history**: in the block's single forward pass (§5) a name released at one tx
position is **absent** at every later position, so a later CLAIM in the **same block** that
presents a live backing commit **re-mints it fresh**. This is not a special case — it is the
existing §3.2 rule that **a CLAIM does not consume its backing commit** (no delete-on-use; the
commit lingers, live, until it time-prunes) meeting the reclaim-on-release rule above. The
first CLAIM's commit is normally inert on a second CLAIM only because the name is by then
**owned** (the "already owned → drop" path); once a RELEASE removes the name from the owned
set, that same still-live commit backs a fresh mint again. So an owner may CLAIM a name,
RELEASE it, and re-CLAIM it with the same commit — or a **second party** may CLAIM it with
*their own* commit — all in one block. (A commit is author-bound, §3.2, so only its committer
can ever use it; and every re-CLAIM still burns ≥1 day of rent, so churn is not free.) The
same-block claim contest of §3.2 tracks only names that are currently held; it never suppresses
a re-mint of a name no longer in the owned set, and the re-mint's priority is its own backing
commit — the released holder's former commit priority is discarded with the row. RELEASE touches only names
you **own and are neither listing nor offering**: a locked name selected by the bitmap is **skipped**
(the op releases the selected unlocked subset; the locked name stays put — a per-name filter, never
a whole-op drop, §3.5). A name listed for sale or under a directed offer (§3.7) is locked (still
owned and renewable, but frozen against RELEASE/TRANSFER/SELL/SELL_TO until it settles, is paid, or
the listing/offer ends). There is deliberately **no release-all** mode ("abandon everything" is what
lapse already does for free); RELEASE is the *selective, now* tool (§6 reach), and the
wrong-name footgun is caught by the anchor guard. **RELEASE_NAME (`0x0B`)** is the same
operation for exactly one name, addressed by string (§3.5): every rule in this paragraph —
locked → no-op, forfeited lease, immediate reclaimability, presence-not-history re-mint —
applies identically; it needs no anchor because a name string cannot select the wrong name.

### 3.7 The names market — open (SELL · RESERVE · SETTLE) & directed (SELL_TO · PAY)

Paid sales are **fixed-price and escrow-first**. The flow:

```
SELL(name, price, window) ──▶ RESERVE(name) ──▶ SETTLE(name)
```

The two design pillars:

- **Escrow-first** — SELL **locks** the name: while listed it cannot be TRANSFERred,
  RELEASEd, re-SOLD, or SELL_TO-offered, so the seller can't move it out from under a buyer. (The
  name stays in the seller's owned set and **stays renewable** — keeping the lease alive only
  benefits the eventual buyer; only *movement* is frozen.) This closes the co-sign-swap front-run:
  a seller can't grant the name in a co-signed tx and simultaneously transfer it away using a
  different UTXO, because the listed name is **frozen against movement** for the listing's life — a
  TRANSFER or RELEASE bitmap that selects it **skips** it (the rest of the batch still applies, §3.5),
  so it can never leave the seller's set while listed. (A directed SELL_TO offer locks the name
  identically — see *Directed sales* below.)
- **Fixed price** — the price is committed on-chain at SELL, immutable. This closes the
  dynamic-price front-run: with nothing to infer at reserve time, a seller can't self-reserve
  at a cheap inferred price. The escrow is what makes publishing a fixed price safe (without
  escrow a published price would be front-runnable precisely because the name wasn't yet
  escrowed).

**SELL (`0x07`).** Payload: `price` (8, ≥ `3 × DUST_FLOOR`) + `window` (4, seconds) + `name`.
Requires the sender **own** `name`, that it be neither already listed nor under a directed offer
(§3.7 *Directed sales*), and that
`price ≥ 3 × DUST_FLOOR` — a SELL below the floor is **ignored**. Lists it (locking it from
TRANSFER/RELEASE/re-SELL/SELL_TO per the escrow-first pillar) at the fixed `price`; records
`{seller (hash160 + script type, §4 Rule 2), price, offer_expiry = MTP_now + window}`. The
lease conveys at settle. Fee-only. **There is no cancel op, but a listing is reclaimable:** a
seller pulls a name back out of escrow by buying its own listing (self-RESERVE + self-SETTLE) —
the pay-leg and the 99 % are self-payments, so it nets to **0.5 % burn + 2 fees**, and both
txs can share a block (an immediate reclaim). So escrow makes the name **unmovable** and the
price **fixed**, but **not** un-reclaimable. Because reserves are open (no co-sign), the
seller is also a fee-market participant in their own listing — they may self-RESERVE to
out-bid an incoming buyer on `tx_index`, and no rule forbids it (a "no self-reserve" check
dies to puppet addresses). This only pays off on an **underpriced** listing (a fair-priced
seller just fills the sale), so it acts as built-in misprice-correction, not a hole.

- `window` is bounded below by `RESERVE_WINDOW` and above by the lease tail, the upper bound
  evaluated in **add-form** — `window ≥ RESERVE_WINDOW` **and** `MTP_now + window + REORG_BUFFER
  ≤ lease_expiry` (all unsigned additions, ≥64-bit), **never** the subtraction
  `(lease_expiry − MTP_now) − REORG_BUFFER`, which would **underflow and wrap** to a near-`2³²`
  value for a short-tailed name and pass the check (the same unsigned-subtraction trap §3.4 pins
  for the fee oracle; the add-form has no negative intermediate). Equivalently, a name is
  listable iff it has at least `RESERVE_WINDOW + REORG_BUFFER` of lease left. This pins
  `offer_expiry = MTP_now + window ≤ lease_expiry − REORG_BUFFER`, so the name can never lapse to
  the pool while a sale is live (the "pay for an already-free name" trap is structurally
  impossible, with reorg slack). `window = 0` defaults to `RESERVE_WINDOW`; any **nonzero**
  window is taken literally and checked against both bounds — a window in the `[1, RESERVE_WINDOW)`
  band (nonzero but below the floor), or one exceeding the lease-tail add-form bound, is **out of
  range → the SELL is ignored** (only `0`, meaning "use the floor", and values `≥ RESERVE_WINDOW`
  within the lease tail are accepted).
- A listing's `price` is fixed koinu and cannot be repriced in place; to re-price, the seller
  reclaims it (self-buy, ~0.5 %) and re-SELLs at the new price. Clients MUST disclose the
  chosen expiry and that the price is fixed for the listing's life (repricing costs a ~0.5 %
  reclaim).
- The `price ≥ 3 × DUST_FLOOR` floor is a **fold-safety** floor: it keeps the settle remainder
  `price − burn_leg − pay_leg` ≥ `DUST_FLOOR` even when both deposit legs floor to `DUST_FLOOR`
  (the RESERVE deposit math below), so the unsigned remainder can never underflow. It does **not**
  guarantee executability — whether a listing's spendable legs (`pay_leg`, settle remainder) clear
  the host network's relay/dust policy is a separate, larger, **client-side** concern.

**RESERVE (`0x08`).** Payload: a single `name` — one open listing per `OP_RETURN` (reserve
several listings at once by placing several RESERVE `OP_RETURN`s in one tx, §3.5). **Open —
no co-sign** (the public listing *is* the seller's authorization). A RESERVE is a
**non-refundable bid for an exclusive SETTLE option**: the indexer is a passive observer with
no custody, so **both deposit legs settle unconditionally** the instant the RESERVE confirms —
the `burn_leg` is destroyed in its own `OP_RETURN`, the `pay_leg` is already the seller's.
Deposit = `RESERVE_DEPOSIT_BPS` (1 %) of `price`, split two legs:
`burn_leg = max(DUST_FLOOR, ⌊price × RESERVE_BURN_BPS / 10000⌋)` carried as the RESERVE
`OP_RETURN`'s own value (`≥ burn_leg`), and
`pay_leg = max(DUST_FLOOR, ⌊price × RESERVE_PAY_BPS / 10000⌋)` paid to the seller in **its own
exact-value output** (matched per the `vout`-order consume-once rule of §3.5). Both legs MUST
be computed in **≥128-bit**: `price × bps` overflows `int64`, and `price` is an attacker-typed
field in a SELL payload (free to inflate near `2⁶⁴`), so a 64-bit indexer would wrap to a
near-zero deposit.

**"Settle unconditionally" means the deposit is *non-refundable once the RESERVE is valid* — it
does *not* mean the RESERVE applies without its payment.** The `pay_leg` output to the seller
MUST be **present and matched** (the `vout`-order consume-once exact-value rule of §3.5), and the
carrier value MUST be `≥ burn_leg`. A RESERVE whose `pay_leg` output is **absent**, or whose
carrier value is short of `burn_leg`, **drops** and claims **no** option (the listing stays OPEN).
The "unconditional" is purely that a *valid, confirmed* reserve's two legs cannot be clawed back —
the indexer holds no custody and cannot un-burn a confirmed output — never a licence to apply a
reserve with no matching output. The same output-required rule governs the rest of the chain:
**SETTLE** drops without its remainder output to the seller, and **PAY** drops without its
full-price output (both per §3.5's "if none remains, that op drops"). Reading "unconditionally"
as "apply even with no payment output" flips a RESERVE/SETTLE/PAY from drop → apply — an
ownership/escrow fork.

- **First-in-chain-order wins the option.** Among reserves for one name the lowest
  `(height, tx_index)` becomes the **exclusive** buyer — the only address that may SETTLE —
  with `reserve_expiry = min(MTP_now + RESERVE_WINDOW, offer_expiry)`. **The clamp to
  `offer_expiry` is load-bearing:** without it a late reserve could carry a settle window past
  `offer_expiry`, letting a SETTLE land after the listing closed (name already reverted to the
  seller) or even after the name lapsed — the boundaries would no longer nest (§5) and a settle
  could pay for a no-longer-listed name. Clamped,
  `reserve_expiry ≤ offer_expiry ≤ lease_expiry − REORG_BUFFER` always holds. A later reserve
  is a **structurally valid** tx that merely **fails to claim the option**; it is never
  rejected, and its deposit is **already spent** (the indexer cannot refund or un-burn a
  confirmed output, §5). A contested listing resolves in the Dogecoin fee market (buyers
  RBF/CPFP for a lower `tx_index`); clients **MUST** act as mempool radar, warning that the
  1 % is lost if you are outbid in the block.
- **Losers forfeit the 1 %** — 0.5 % burned, 0.5 % to the seller. A seller therefore collects
  0.5 % from every losing reserver, but baiting contention requires underpricing that costs the
  seller far more than the take, so it nets out as a benign, mostly-deadweight by-product, never
  a subsidy to design around.
- **The winner's** two legs are non-refundable but **credited** toward `price` at settle, so
  the winning buyer's total outlay is exactly `price` (a loser simply loses the 1 %).

**SETTLE (`0x09`).** Payload: a single `name` — one reserved listing per `OP_RETURN` (settle
several at once via several SETTLE `OP_RETURN`s in one tx, §3.5). The exclusive reserver pays
the **remainder** `price − burn_leg − pay_leg` (≥ `DUST_FLOOR`, by the SELL price floor) to the seller in **its own exact-value output**
(matched per the `vout`-order consume-once rule of §3.5) and claims the name; the lease
conveys. Only protocol timing gate: `MTP < reserve_expiry`. Settling with margin before
`reserve_expiry` is the buyer's job; waiting for the reserve to bury before paying is
client-side risk management, not a consensus rule.

**Accounting.** The two deposit legs (paid at RESERVE) plus the settle remainder sum to
exactly `price`, so the **buyer pays exactly `price`**; the seller nets `price − burn_leg`
(≈ 99.5 %); the `burn_leg` (≈ 0.5 %) is burned (an implicit market fee captured by no one).
Every payment output is an **exact** match, so matching is unambiguous and reuse is impossible.

**Security properties.**

| attack | status | mechanism |
|---|---|---|
| co-sign-swap front-run (seller moves name away) | **closed** | escrow-first — a listed name is movement-locked; TRANSFER/RELEASE/re-SELL on it are rejected |
| dynamic-price front-run (self-reserve at inferred price) | **closed** | fixed price — nothing to infer; a self-reserve nets the seller only 0.5 % (the pay-leg returns to them) |
| harvest (seller collects 0.5 % from losing reserves) | **bounded, benign** | losers forfeit unconditionally, but baiting contention needs underpricing that exceeds the take — mostly deadweight burn |
| double-full-payment (N buyers all pay full) | **closed** | exclusivity — only the winner pays the 99 % |
| reserve-griefing (lock a listing) | **bounded, open** | costs 1 % per `RESERVE_WINDOW`, 0.5 % to the seller as consolation |
| settle-after-close (pay for a no-longer-listed/lapsed name) | **closed** | `reserve_expiry` clamped to `offer_expiry` — the settle window can't outlive the listing |
| batched-reserve leak (lose one race among several reserves in one tx) | **client tradeoff** | each reserve's leg forfeits independently; clients serialize hot names, batch cold ones |

The only genuinely *open* item is reserve-griefing — bounded and priced. Clients MUST disclose
both deposit legs as non-refundable and that a contested reserve can forfeit them.

#### Directed sales — SELL_TO & PAY (the directed dual)

The open flow above *finds* a buyer; a **directed** sale *delivers* to a buyer you already have.
Naming the buyer on-chain makes the sale **exclusive by
construction**, so the directed flow needs **no deposit, no option race, and no griefing margin** —
it is structurally simpler than the open market:

```
SELL_TO(name, price, buyer) ──▶ [buyer pays within DIRECT_WINDOW] ──▶ PAY(name)
```

Both pillars carry over unchanged — **escrow-first** (a SELL_TO'd name is movement-locked, identical
to a SELL listing) and **fixed price** (committed on-chain at SELL_TO). What drops away is the
*third* open-market mechanism: the deposit/option machinery that resolves contention among open
reservers simply isn't needed, because only the named `buyer` can ever complete the sale.

**SELL_TO (`0x0C`).** Payload: `price` (8, ≥ `DUST_FLOOR`) + `buyer` (20, hash160) + `name`.
Requires the sender **own** `name`, that it be neither already listed (SELL) nor already offered
(SELL_TO), and that it have at least `DIRECT_WINDOW + REORG_BUFFER` of lease left. Records
`{buyer, price, seller (hash160 + script type, §4 Rule 2), offer_expiry = MTP_now + DIRECT_WINDOW}`
and **locks** the name exactly as SELL does — frozen against TRANSFER/RELEASE/SELL/SELL_TO for the
offer's life, but **still owned and still renewable** (the lease conveys to the buyer at PAY, so
keeping it alive only helps them). Like a SELL listing, a SELL_TO offer is **not** a set mutation
(§3.5) — the name keeps its bitmap position. Fee-only; the price rides in the buyer's PAY, never
here. `DIRECT_WINDOW` is **fixed** (no `window` field), so the lease-tail requirement guarantees
`offer_expiry ≤ lease_expiry − REORG_BUFFER` and the name can never lapse while an offer is live.

There is **no cancel and no self-reclaim.** Unlike SELL — where the seller self-buys to pull a name
back out of escrow — only the *named buyer* can complete a directed offer, so the seller cannot
exercise it to reclaim. The sole exit is the short self-expiry; this is why `DIRECT_WINDOW` is held
to ~2 h, so a stale offer frees the name quickly. A seller with no agreed counterparty SHOULD use
the open SELL flow instead — emit a SELL_TO only against a buyer who is ready.

**PAY (`0x0D`).** Payload: a single `name` — one offer per `OP_RETURN` (pay several at once via
several PAY `OP_RETURN`s in one tx, §3.5). **No burn.** The buyer pays the full `price` to the
seller in **its own exact-value output** (matched per the `vout`-order consume-once rule of §3.5)
and claims the name; the lease conveys. Honored **iff** all hold: a **live** SELL_TO for `name`
exists; this PAY's `vin[0]` Identity (§4) **equals** the offer's `buyer` (the directed exclusivity —
no other address can complete it, at any fee); `MTP < offer_expiry`; and the matching exact-value
output to the seller's recorded `(hash160, script type)` is present. On success the name moves to
the buyer's owned set and **both** parties' `last_set_mutation_height` bump (§3.5), exactly as
SETTLE. There is no deposit and no `price × bps` split, so the buyer's outlay is exactly `price` in
one tx and RESERVE's deposit-overflow concern does not arise. The `buyer` may be a P2SH hash, so a
directed sale to a community keyset works with no extra machinery — `buyer`
is a bare hash160 compared against the PAYer's §4 Identity, never reconstructed.

A PAY whose buyer, price-output, name, or timing fails to match a live offer is **dropped** — but
its payment output is a *real* spend that still pays the seller; the indexer has no custody to
refund, exactly as for a late SETTLE. Paying **early, with margin** before `offer_expiry` is the
buyer's job; `DIRECT_WINDOW` is sized to dominate confirmation depth + MTP lag (~5–6 blocks) +
reorg slack, so a promptly-broadcast PAY is safe — a window much shorter would be a footgun, which
is why ~2 h reads as a **floor on usefulness**, not merely the cap you'd choose for liquidity.
Clients **MUST** warn that a PAY is irreversible and gate it on the SELL_TO being confirmed and well
inside its window.

**No burn — and what that implies.** The open market's ~0.5 % `burn_leg` was option-collateral (it
priced the open RESERVE race), never a protocol rake; a directed sale has no option to
collateralize, so it burns nothing and the seller nets the full `price`. SELL_TO+PAY is therefore
the **low-cost settlement rail for a deal with an already-agreed counterparty** — the common
"we already agreed" case — leaving the deposit-protected open flow for public price
discovery. Expect directed settlement to dominate; the open flow earns its extra
complexity only when there is no specific buyer yet.

**Offer spam (the one new surface).** A SELL_TO names a `buyer` but puts **nothing** into their
owned set. On chain it is bounded exactly like a SELL listing — **one live offer per owned name**,
self-shedding at `offer_expiry` (≤ `DIRECT_WINDOW`) — so it is **not** an index-bloat vector. The
economic floor (a miner fee plus a *rented* name locked for the window) is the gift-spam bound of
§3.6 minus the give-away, and the harm is strictly less (nothing lands on the victim). **No new
anti-spam constant is required** — deliberately no burn on SELL_TO: nothing enters the victim's set,
and a burn would break the fee-only symmetry with SELL.

**Security properties (directed flow).**

| attack | status | mechanism |
|---|---|---|
| buyer-snipe by a stranger | **closed by construction** | only the named `buyer`'s `vin[0]` can PAY — exclusivity with no deposit or race |
| co-sign-swap front-run (seller moves the name away) | **closed** | escrow-first — a SELL_TO'd name is movement-locked, identical to a SELL listing |
| dynamic-price front-run | **closed** | fixed price committed at SELL_TO; nothing to infer at PAY time |
| offer spam (SELL_TO at a victim address) | **bounded, benign** | nothing enters the victim's set; one lock per owned name, self-shedding ≤ `DIRECT_WINDOW` |
| late PAY (pay for a closed/expired offer) | **client timing** | `MTP < offer_expiry` gate + a `DIRECT_WINDOW` sized over confirmation/MTP-lag/reorg; pay early, as for SETTLE |
| seller can't cancel early | **accepted** | no cancel/self-reclaim verb — the short self-expiry is the only exit; emit only against an agreed buyer |

### 3.8 Index determinism, storage & constant changes

**Everything that determines global shared state is gated by a protocol constant.** Identity
(CLAIM/RENEW/TRANSFER/RELEASE/TRADE), the market (SELL/RESERVE/SETTLE, SELL_TO/PAY), and
attribution (AS) all resolve the global namespace + ownership by **protocol constants** alone
(rate, windows, priority).

Ownership resolution cannot use client policy: any ownership-determining threshold MUST be
protocol-fixed, so every indexer resolves the same owner. Contests are broken by the deterministic
priority tuple (§3.2), never by burn-as-tiebreak.

**Canonical state serialization is pinned, not prose.** Two indexers "agree" iff they hash the live
set to the same digest, which requires a byte-exact canonical layout (owned-set rows sorted by name;
the field order; which fields are canonical — e.g. a row's `seller_type` is consensus state but a
plain owner's `owner_type` is not, since a gift's type is cosmetic). This prose fixes *what* is
shared state; the exact serialization is pinned by the cross-language reference state machine and its
conformance contract (the seed-regenerated digest vectors), the same way §3.9's wallet previews and
§4's attribution are pinned by vector sets rather than English.

**Storage is economically bounded.** The only state an indexer MUST keep is the *live* set —
who owns which name, each lease, live commits, open sale data, **and the per-owner
`last_set_mutation_height` anchor-guard heights** (a monotonic high-water mark, retained even
for an owner whose set is momentarily empty, §3.5); expired names and transfer history are
sheddable, but the anchor heights are **not** — they are consensus state and enter the digest. The spammable surface (a victim's owned set) is itself **rented**: every
name persists only as long as its lease is paid (§3.4), and a name enters anyone's set only by
being minted/conveyed, which cost the minter rent ∝ duration. Abandoned/spam rows shed at
`lease_expiry` (a sliding window bounded above by `MAX_LEASE`), and keeping them alive costs the
holder proportional rent. There is no free spam amplification and no per-recipient cap needed.

**Changing a constant.** A constant cannot be price-pegged without an oracle (non-deterministic,
re-centralizing) — which is why the *rent* is derived from the coinbase rather than pegged
(§3.4). If a structural constant must change, ship it as a versioned **activation height**: rule
A below `H`, rule B at/after. Replay stays single-valued; the change is **forward-only, never
retroactive**.

**Time-triggered transitions materialize at a canonical block.** Some state changes with **no
transaction** — a lease lapses, a `COMMIT_EXPIRY` prunes, a reserve/offer window closes — purely
because MTP crossed a threshold. For the canonical digest to be single-valued, each such transition
MUST take effect **eagerly, at the single block whose MTP first crosses** (an indexer that evaluated
expiry lazily-on-read would, while agreeing on every *query*, disagree on the *digest* with one that
materialized eagerly). This is already how the reference fold behaves (an inactive market field is
physically zeroed before the next digest); it is called out here because hashing the state makes the
*timing* consensus-relevant where a per-view fold left it free.

**State-digest commitment (advisory, non-consensus).** An indexer MAY publish a digest of its live
set per `(block_hash, height)` so peers detect divergence — two honest nodes on one block must agree.
To make this cheap (no re-hashing the whole set each block), the reference uses an **incremental
multiset hash** (ECMH over secp256k1): each row contributes a curve point, so a block folds
in only its *delta* in O(rows-changed), and a reorg subtracts it back out. This digest is **purely
diagnostic** — never on-chain, never PoW-secured, never a consensus object: a mismatch triggers
resync, **never** a peer-ban or tx-rejection (a digest with a consensus consequence would promote the
*computation* to consensus, which §3.8 forbids). It is *not* a light-client proof system — a sum
proves two states equal, not "name X → owner Y"; an authenticated tree for that remains a clean
additive step over the same per-row encoding if real light-client demand appears. Pinned in the
conformance contract (golden-checked across all reference impls).

### 3.9 Multi-identity transactions — AS (batching) & TRADE (barter)

By default a transaction speaks with a single voice: every action is attributed to `vin[0]`
(§4 Rule 1). Two opcodes lift that — **`AS`** lets one tx carry actions from *several* co-signers
(custodial batching), and **`TRADE`** atomically exchanges holdings between two of them (barter).
Both are **flat settlement verbs** — they add attribution and atomicity, never computation; a tx
that uses neither behaves exactly as before, so this is a pure superset.

**`AS` (`0x0E`) — the acting identity.** Payload: `index` (1 byte). An `AS k` carrier re-points the
**acting identity** to `vin[k]` for every subsequent action-carrier in the tx, until the next `AS`
or end-of-tx; before any `AS` the acting identity is `vin[0]`, and it resets each tx. The named
input is verified by the *same* §4 algorithm (Rule 1b) — attribution stays stateless and O(1) per
distinct named input. `AS` re-points **attribution only, never burn-accounting**: every
burn-bearing action's cost is its **own carrier's `OP_RETURN` value** (destroyed regardless of
which input funded the tx), so `AS` changes *who an action is credited to*, not *where the koinu came
from*. Fee-only.

- **You can only act *as* an identity that co-signed.** Every input an `AS` names MUST sign exactly
  `SIGHASH_ALL` (Rule 3), which commits it to the whole input order and every output — hence to all
  `AS` markers and actions. So by signing, `vin[k]` authorizes precisely the segment attributed to
  it; an attacker can neither relocate it nor attach an action it didn't sign, and no index that did
  not sign can be named. Impersonation is impossible by construction.
- **Use.** A custodian batches *M* users' renews/transfers into one tx, each `AS`-segmented to its
  owner — the headline fee-saver, and the thing one tx cannot do today (today all *M* attribute to
  the custodian). Sponsored/gasless actions fall out: a sponsor's inputs fund the burns, the user's
  dust input merely proves identity. Attribution is to a real address, so a user's history/names
  travel if they later self-custody.
- **The footgun — co-signing stops being innocent.** Today a pure funding input is never attributed
  anything; under `AS`, signing `SIGHASH_ALL` consents to whatever an `AS` marker pins on your
  input. Not a protocol hole (you signed the whole tx), but **wallets MUST display, per input, the
  actions it will perform before signing**.
- **Composition & failure.** An `AS k` out of range, or whose `vin[k]` fails §4 (incl. not
  `SIGHASH_ALL`), yields no valid identity → its segment's actions **drop**. An orphan `AS`
  (nothing after) is a no-op; a re-`AS` simply re-sets the mode —
  there is no "conflicting actor" case.

**`TRADE` (`0x0F`) — atomic 1-1 name swap.** Payload: `[idxA:1][idxB:1]` then `nameA,nameB` — the
two names as a **comma-separated pair**. After the two index bytes the rest of the payload is split
on the single `,` (`0x2C`); because the name charset `[a-z0-9-]` (§3.1) never contains a comma the
separator is unambiguous and **no length byte is needed**. The payload MUST hold **exactly one** `,`
with both sides valid per §3.1 — no comma, a comma inside a name, or an empty side → **drop**.
`vin[idxA]` and `vin[idxB]` are the two parties; each name is a **literal string**, exactly how
SELL/SELL_TO/RESERVE/SETTLE/PAY name a single name (a 1-1 swap is a single-name op, not a batch — so
**no bitmap and no anchor**). Effect, **atomic**: `nameA` (owned by `vin[idxA]`) → `vin[idxB]` and
`nameB` (owned by `vin[idxB]`) → `vin[idxA]`, leases convey (§3.6). It is **one opcode**, so it
applies in full or **drops in full** — there is no partial or one-sided trade. Both parties MUST
pass §4 + sign `SIGHASH_ALL`; it bumps **both** parties' `last_set_mutation_height` (§3.5), so any
RENEW/RELEASE/TRANSFER bitmap either party has in flight registers the moved name. Fee-only.
TRADE is attributed **solely** to `vin[idxA]`/`vin[idxB]`; it does **not** consult the
transaction's acting identity (the `vin[0]`/`AS` actor every *other* op acts as, §5). So a TRADE
settles on the validity of its two named parties **alone** — it still applies in a tx whose acting
identity is ⊥, and conversely a valid acting identity never stands in for a failed party. (A
reading that required the carrier's acting identity to verify before a TRADE could apply would
**drop** trades a conformant fold settles — an ownership fork.)

- **Atomicity *and* anti-rug come free from the live-ownership re-check.** Validity is re-evaluated
  at the swap's **confirmation** position in the fold (§5): `vin[idxA]` must **still own `nameA`**
  and `vin[idxB]` must **still own `nameB`**, both **unlocked** (neither listed nor offered, §3.7).
  If either party moved, released, sold, locked, or let lapse the name they pledged after signing —
  by an earlier tx in the same block or any prior one — they no longer own it unlocked at confirm,
  so **the whole TRADE drops** and the counterparty keeps what they had. A party can neither tamper
  and still pass (the check is against live state, not a snapshot) nor extract a one-sided outcome
  (one opcode, all-or-nothing). The only outcomes are {full swap} or {nothing}. This is exactly the
  live-ownership gate SETTLE and PAY already use — no anchor, and no `last_mutation` comparison for
  the swap itself.
- **Batches at the tx level:** several `TRADE` `OP_RETURN`s in one tx, each a 1-1 swap over its own
  input pair, settle independently-atomically (a custodial book of trades) — the same
  multi-`OP_RETURN` unlock the rest of the spec rides on (§0), never several swaps in one carrier.
- **Fail-closed edges (each drops the whole op):** an index out of range; `idxA == idxB`; either
  input failing §4/`SIGHASH_ALL`; `vin[idxA]` not owning `nameA`, or `vin[idxB]` not owning `nameB`,
  at confirm; either name **locked** (listed/offered, §3.7); `nameA == nameB` (one name cannot sit
  on both sides — and two distinct parties cannot both own a name anyway); the payload not holding
  **exactly one** `,` separator, or either side failing name validation (§3.1, which also bounds
  length 1..32). The two names are distinct and owned by different parties, so the sides never
  collide.
- **Boundaries (deliberate).** Pure **name-for-name** — stapling a cash leg reopens the rug (a raw
  payment output is not ownership-gated with the swap, so it would pay even if the TRADE dropped);
  cash-balanced deals stay in the market lane (SELL_TO/PAY, §3.7). **1-for-1, 2-party only** —
  multi-name or N-party barter is a non-goal (batch several TRADEs, or fall back to TRANSFER).
  TRADE is the settlement rail, not a barter market.
  **Wallets MUST render the fully-resolved both-sides preview** ("you give
  `nameA`, you get `nameB`") before signing — an irreversible asset swap.

**Wallet previews are a conformance artifact, not just prose.** `AS` and `TRADE` route irreversible
asset/fund outcomes through what a wallet shows *before* signing — `AS`'s per-input attribution
(Rule 1b) and `TRADE`'s give/get. The spec therefore pins those renderings with a shipped
**preview-vector set** — `raw tx → {per-input attribution; for each TRADE the exact (give, get) per
party}` — alongside the §5 fold vectors. The protocol cannot *force* a wallet to display correctly,
but it makes "correct" mechanically checkable: a wallet conforms iff its rendering matches the
preview vectors. The fold itself is safe-by-construction; this closes the one safety-relevant layer
otherwise left to prose.

**Why this is the ceiling (a recorded non-goal).** `AS` adds attribution and `TRADE` adds atomic
exchange — together they bring the `OP_RETURN` layer up to plain Bitcoin-transaction expressiveness
(multiple signers, all-or-nothing) and **stop there on purpose**. The line: **every opcode encodes a
*settlement fact*** — who owns what, paid to whom, atomically — **never a *computation*** — a value
derived by branching or looping. A deterministic fold with no loops and no data-dependent control
flow is a finite state machine, not a virtual machine, and the bounded carrier (§6) + statelessness +
O(1)-per-action rule keep it that way by construction. The chain settles facts; it never computes
them. Litmus for any future opcode: *is this a fact the chain settles, or a result it computes?*
The former may be considered; the latter is out of scope.

---

## 4. Stateless Identity & Attribution (O(1) Verification)

Indexers do **not** need a UTXO set to attribute actions. Identity is derived from the inputs
and verified locally with legacy sighash rules. This is the load-bearing foundation the rest of
the protocol depends on. Identity MUST be recovered by verifying `vin[0]` (below), never lifted
from an unverified `scriptSig` pubkey.

**Rule 1 — identity resides in `vin[0]`.** The acting identity is strictly the first input;
other inputs are funding only. Attribution is **never** lifted from an
unverified `scriptSig` pubkey.

**Rule 1b — the acting identity & the `AS` marker (§3.9).** By default the acting identity is
`vin[0]` (Rule 1). An **`AS k`** carrier (`0x0E`) re-points it to `vin[k]` for every subsequent
action-carrier until the next `AS` or end-of-tx; the default before any `AS` is `vin[0]`, and it
resets per tx. `vin[k]` is verified by running this **same §4 algorithm on `vin[k]`** instead of
`vin[0]` — stateless, and O(1) per *distinct* named input (memoize: an input's identity is fixed no
matter how many segments name it). **Every input an `AS` names MUST satisfy Rule 3** (sign exactly
`SIGHASH_ALL`): that signature commits it to the entire input order and every output — hence to all
`AS` markers and actions — so by signing, `vin[k]` authorizes exactly the segment attributed to it,
an attacker can neither relocate it nor attach an unsigned action, and no input that did not sign
can be named. **You can only act *as* an identity that co-signed the exact tx; impersonation is
impossible.** An `AS k` that is out of range or whose `vin[k]` fails §4 (including not `SIGHASH_ALL`)
yields no valid identity → its segment's actions **drop**. Everywhere
this spec names the actor as `vin[0]` — the CLAIM minter, the SELL/SELL_TO
`seller`, the PAY `buyer` check, a TRADE party — read it as **the acting
identity**: `vin[0]` by default, or the `AS`-named input within that segment. **Wallet
(normative):** because co-signing now implies consent to whatever an `AS` attributes to your input,
wallets MUST display, per input, the actions it will perform before signing.

**Rule 2 — P2PKH and P2SH multisig are attributable (day-1, full).** Identity is recovered by
classifying `vin[0]`'s `scriptSig` shape (the prevout `scriptPubKey` is not available) — a fixed
exact algorithm over **two** recognized shapes; everything else (P2PK, bare multisig,
nonstandard, empty) → **drop**:

- **P2PKH** — `scriptSig = [sig] [pubkey]`; `Identity = hash160(pubkey)`; **one** ECDSA verify.
- **P2SH multisig** — `scriptSig = OP_0 [sig]×m [redeemScript]` (**exactly `m` sigs** — the
  redeemScript's threshold; a different count → drop), the redeemScript (last data push) exactly
  `OP_m <33-B compressed pubkey>×n OP_n OP_CHECKMULTISIG`; `Identity = hash160(redeemScript)` (the
  bare script-hash, type-tracked below); **O(m)** ECDSA verifies. This lets a name — a community —
  be **owned by, and act as**, an **m-of-n** group (`m` signatures of `n` keys, `m ≤ n ≤ 15`),
  with the threshold enforced natively by the spend.

Neither shape needs a general script interpreter: P2PKH is two pushes + one verify;
the multisig redeemScript is a fixed template matched structurally and checked with one bounded
`OP_CHECKMULTISIG`-shaped loop. The multisig path is deterministic only under these **mandatory**
rules:

- **Exact fail-closed template** — **compressed keys only** (33-B `0x02`/`0x03`), `OP_m`/`OP_n`
  minimal (`OP_1`..`OP_16`), exact opcode order, **≤15 keys** (the 520-B redeemScript push bound;
  15-of-15 ≈ 513 B), reject any trailing byte. Uncompressed/mixed keys, alt encodings,
  true-leaving wrappers → **drop**.
- **strict-DER** is already Dogecoin consensus (BIP66). **NULLDUMMY + low-S are self-imposed**
  (policy): the leading `OP_CHECKMULTISIG` dummy MUST be exactly `OP_0`, and high-S MUST be
  rejected per sig independently.
- **In-order signature scan** — the `m` sigs are a subsequence in pubkey order (on match advance
  both, on miss advance the key); "try all orders" attributes differently. A spend carrying fewer
  than `m` valid sigs fails the threshold → drop.
- **PUSHDATA1-aware, minimal-push decoder** — even a 2-of-3 redeemScript (~105 B) needs
  `OP_PUSHDATA1`; enforce minimal-PUSHDATA1 (76–255 B *must* use `0x4c`; `<76` *must not*).

**Stateless still holds.** `vin[0]` attribution is stateless even for P2SH — the redeemScript
rides in the spending `scriptSig`, so a multisig spend is attributed from the tx alone, no UTXO
set (multisig sighash is the same legacy machinery with `scriptCode = redeemScript`). Identity
keys on the **bare hash160** everywhere (name ownership, the TRANSFER target,
self-compare), so a name gifted/sold to a P2SH hash is owned and renewable immediately — no type
byte in the wire format. The one derived fact the fold retains (§5), deterministic and shed-able:

- **Script type per party.** Every site that later *reconstructs* a controller's script — the
  SELL/SELL_TO `seller` payment check, a SETTLE/PAY writing the new owner-hash (§3.7) — records the
  **(hash160, script type)**, P2PKH **or** P2SH; the rule is *"reconstruct per recorded type,"*
  never "assume P2PKH." (Paying a P2SH seller needs only its `hash160`, so the keyset preimage is
  **never** cached on-chain.) The recorded type is a **template selector** (P2PKH
  `OP_DUP OP_HASH160 <h> OP_EQUALVERIFY OP_CHECKSIG` vs P2SH `OP_HASH160 <h> OP_EQUAL`), **not** a
  key-encoding record: a P2PKH `scriptPubKey` commits only to `hash160`, and a key's
  compressed/uncompressed choice is already folded into that hash (the two forms are distinct
  identities, Rule 4), so the `(hash160, type)` tuple reconstructs the payment script byte-exactly
  with no cached pubkey and no key-format ambiguity.

**Authority is the P2SH spend itself.** A P2SH redeemScript enforces **one** threshold, and that
spend *is* the authority — no extra protocol check, no keyset bookkeeping. Every on-chain act *as*
a community — RENEW, TRANSFER, SELL, re-key (a roster change is an **m-of-n re-key TRANSFER** to
the new keyset's P2SH), and **official name actions** — is the native **m-of-n** spend Dogecoin
already enforces. (Renewal needs quorum like everything else, but `MAX_LEASE` lets a community
pre-pay up to a year per RENEW, so quorum is needed only ~annually.)

**Rule 3 — `vin[0]` MUST sign exactly `SIGHASH_ALL` (`0x01`).** Reject `NONE`, `SINGLE`, every
`ANYONECANPAY` variant (incl. `0x81`), and any other flag. Only bare `SIGHASH_ALL` commits to
input *position*; any other flag does not commit to which index the signed input occupies, which
would let an attacker park the victim's signed input at `vin[1]`, place his own at `vin[0]`, and
hijack attribution. (A split-key user wanting cold identity + hot funding MUST co-sign the
finalized input array with `0x01`.) Under `AS` (§3.9, Rule 1b) this binds **every input an `AS`
marker names**, not only `vin[0]`: each acting input must sign exactly `SIGHASH_ALL`, for the same
position-and-output commitment that makes its attributed segment unforgeable.

**Wallet note (normative).** Because `vin[0]` signs over the exact input array and outputs, a
PepeNet action cannot be in-place fee-bumped (adding an input or trimming change invalidates the
sig and silently moves `vin[0]`). To raise the fee: rebuild and re-sign, or CPFP via the change
output. Wallets MUST NOT offer naive RBF on these txs.

**Rule 4 — strict encodings (determinism).** Signatures strict-DER + low-S; pubkeys canonically
encoded — accept only a **33-byte compressed** (`0x02`/`0x03` + X) or **65-byte uncompressed**
(`0x04` + X + Y) key, with coordinates `< p` and the point on-curve. Reject the **hybrid**
`0x06`/`0x07` prefixes, any other leading byte/length, off-curve points, and out-of-range
coordinates. The identity hash is over the *exact* pubkey bytes, so the 33- and 65-byte forms of
one key are **different** identities. Non-canonical → drop. Implementations MUST enforce strict-DER
+ `S ≤ N/2` *before* verifying.

**Step-by-step:**

1. **Length guard + shape.** Payload **≥ 4 bytes** (else drop, never read past the end); confirm
   `0xFF 'P' 'N'` + a recognized opcode; for burn-bearing ops the value field meets the op's
   requirement; bounds-check every field read against the exact length/format for that opcode
   (§2). Any out-of-bounds or mismatch → drop.
2. **Classify `vin[0].scriptSig` (exact):** **P2PKH** iff exactly two pushes `[sig] [pubkey]`,
   both minimal/canonical, `pubkey` canonical (Rule 4), `sig` strict-DER+low-S, sighash byte
   exactly `0x01` (Rule 3). **Else P2SH multisig** iff `OP_0 [sig]×m [redeemScript]` (exactly `m`
   sig pushes, matching the redeemScript's `OP_m`), the redeemScript matching the exact template
   of Rule 2 (≤15 compressed keys, minimal `OP_m`/`OP_n`, PUSHDATA1-aware minimal push), the
   `OP_0` dummy exact (NULLDUMMY), and every `sig` strict-DER+low-S+`0x01`. Any trailing bytes /
   extra / missing / non-minimal push, a sig count ≠ `m`, or anything matching **neither** shape →
   drop.
3. **Derive identity:** `Identity = RIPEMD160(SHA256(x))` where `x` is the **exact pubkey bytes**
   for P2PKH, or the **exact redeemScript bytes** for P2SH multisig — the bare hash160 either way.
   Everything that keys on a party uses this bare hash (type-agnostic); reconstruction sites that
   rebuild a `scriptPubKey` (the SELL `seller` check, a SETTLE owner-write) carry the recorded
   script type, P2PKH or P2SH (Rule 2).
4. **Reconstruct scriptCode & verify ECDSA locally:** for **P2PKH**, the `pubkey` must be
   **on-curve** first (Rule 4 — the *same* gate applied to the multisig keys below; a P2PKH pubkey
   that is canonically *encoded* but off-curve drops at the **on-curve** gate — never an encoding
   (classify) failure and never a verify failure, i.e. a distinct **on-curve-drop** status (carrying
   its real identity + sighash, exactly like an off-curve redeemScript key)), then scriptCode =
   `OP_DUP OP_HASH160 <Identity> OP_EQUALVERIFY OP_CHECKSIG` and one `Verify(sig, pubkey, sighash)`.
   For **P2SH multisig**, scriptCode = the **redeemScript** itself, and the `m` sigs are checked
   against the `n` pubkeys by the in-order scan (Rule 2) — each sig against the next matching
   pubkey, advancing the pubkey cursor on a miss — until all `m` verify (pass) or the pubkeys
   exhaust (drop). **On-curve is validated on all `n` redeemScript keys up front** (Rule 4) — each a
   33-byte `0x02`/`0x03` compressed key with `X < p` **and on the curve**; a redeemScript carrying
   **any** off-curve key is rejected as non-canonical (drop), because the identity's key set is a
   property of the **redeemScript alone**, independent of which sigs are presented — checking every
   key up front keeps attribution deterministic and order-free, so an off-curve key can never
   silently change which identity a spend attributes to. Compute the **legacy** sighash from the raw tx + scriptCode + type `0x01`
   (legacy needs no input amount — what makes this stateless; DOGE has no SegWit) — Dogecoin's
   standard pre-SegWit sighash **exactly as host consensus computes it**: serialize the tx with the
   input being signed carrying `scriptCode` as its `scriptSig` and every other input an empty
   script, then append the hashtype as a **4-byte little-endian `int32` (`0x01 0x00 0x00 0x00`)**
   before the double-SHA-256 — **never** a 1-byte suffix. The append width is consensus-critical (a
   1- vs 4-byte hashtype changes every input's sighash and flips attribution); the 4-byte LE form is
   the host-consensus standard this rule defers to. When building
   that sighash, indexers **MUST apply Dogecoin's `FindAndDelete(scriptCode, sigPush)` for each
   checked signature exactly as host consensus does — never skip it as an assumed no-op.** For
   P2PKH the scriptCode holds only a hash, so there is nothing to find. For the rigid
   compressed-key multisig template it *happens* to be inert too — `FindAndDelete` matches only at
   opcode boundaries, and every redeemScript push is a uniform 33-byte (`0x21`) push while a
   signature push is `0x47`/`0x48`, so the two never align — but **conformance MUST NOT rely on
   that emergent property** (it would silently break the moment the template admitted another push
   width, e.g. an uncompressed key). Implement FindAndDelete; do not assert it away. Pass =
   genuine, bound to `Identity`.
5. **Execution.** Pass → apply the action, bound to `Identity`. Fail → silently drop.

O(1) per action for **P2PKH** (one ECDSA verify); **O(m)** for an m-key **P2SH multisig**
`vin[0]`, paid only by the rare group action (individual actions stay one verify).

**Conformance is defined by the shipped test-vector set, not prose** (raw tx hex → `{Identity}`
or `drop`). It pins DER/low-S, pubkey canonicalization, minimal pushes, the legacy sighash
**including `FindAndDelete` application**, the P2SH multisig template + scan, the **single-push
carrier** rule (§1), and (Rule 1b) verifying an `AS`-named `vin[k]` by
these same rules with the per-named-input `SIGHASH_ALL` requirement. An indexer conforms iff it
passes the vectors.

---

## 5. Indexer integration

State is a **deterministic fold** over the canonical chain in strict
`(height, tx index, vout)` order (`vout` is the serialized output index, **not** a node's
JSON-RPC array position). The fold scans each single-push `OP_RETURN` in `vout` order:

```
actor = vin[0]                                        # per-tx acting identity (Rule 1b); resets each tx
for each OP_RETURN output o in tx (vout order):       # vout order = intra-tx state-machine order
    payload = the_single_minimal_push(o)              # exactly ONE minimal push, else ⊥ (§1)
    if payload is ⊥:                                        ignore   # multi-push / non-minimal / trailing opcode
    elif payload starts with 0xFF 'P' 'N' + opcode in 0x01..0x0F:   # contiguous; no reserved holes (0x38..0xFF = overlay band, §2 — falls to ignore below, forever)
        if height < ACTIVATION_HEIGHT: drop; continue   # forward-only (§3.0) — all ops live at 1,130,000
        if opcode == AS (0x0E):                              # set acting identity (§3.9, Rule 1b)
            k = payload[4]
            actor = (k < n_inputs AND §4-verify(vin[k]) passes AND it signs SIGHASH_ALL) ? vin[k] : ⊥   # ⊥ ⇒ this segment's actions drop until a valid AS / tx-end
            continue
        if opcode == TRADE (0x0F):                           # attributed to its OWN named inputs vin[idxA]/vin[idxB], NOT the acting identity (§3.9)
            dispatch TRADE (each party §4-verified + SIGHASH_ALL); it NEVER consults `actor`, so the acting-identity gate below does NOT apply — a TRADE in a tx whose vin[0]/AS actor is ⊥ still settles if both named parties are valid; continue
        run §4 stateless verification on `actor`             # P2PKH O(1) or P2SH multisig O(m); memoize per distinct input
        if actor is ⊥ or not verified: drop; continue        # (TRADE already handled above — every OTHER op acts as the acting identity)
        for burn-bearing ops check the value field meets the op's requirement — CLAIM/RENEW/RENEW_NAME: the buy must cover ≥1 name·day (T ≥ 1, water-fill fail-closed at T=0, §3.5); RESERVE: carrier value ≥ burn_leg (§3.7)
        dispatch by opcode against current fold state, bound to `actor`     # mutates owned set / escrow
        # CLAIM: mints iff name unowned AND a live matching commit in a STRICTLY EARLIER block (commit_height < claim_height, §3.2) sets commit_height — else drop (no FCFS fallback); burn buys ⌊value·LEASE_QUANTUM/(rate·BILLING_UNIT)⌋ days of lease
        # RENEW/TRANSFER/RELEASE: resolve the bitmap against the owned-set + anchor guard (§3.5)
        # RENEW_NAME/TRANSFER_NAME/RELEASE_NAME: the named singleton, actor's set only, no anchor (§3.5); locked name → no-op for the movers; TRANSFER_NAME bumps both parties, RELEASE_NAME bumps the actor, RENEW_NAME bumps neither
        # RELEASE: selected owned names → pool immediately; immediately reclaimable, like lapse (§3.6)
        # SELL/RESERVE/SETTLE: one name per OP_RETURN (several per tx via multi-OP_RETURN, §3.5); each payment its own exact-value output, consumed once in vout order
        # RESERVE: two-leg deposit spent unconditionally; first-in-chain-order wins the SETTLE option, reserve_expiry = min(now+RESERVE_WINDOW, offer_expiry) (§3.7)
        # SELL_TO: directed offer → lock name (like SELL), record buyer + price + offer_expiry = now+DIRECT_WINDOW; not a set mutation (§3.7)
        # PAY: honored iff live SELL_TO for name AND actor==buyer AND MTP<offer_expiry AND exact-value price→seller present; name→buyer, lease conveys, bump both; no burn (§3.7)
        # TRADE: atomic 1-1 name swap, vin[idxA]/vin[idxB] (both SIGHASH_ALL); names = comma-separated pair nameA,nameB (split on the single 0x2C; comma ∉ §3.1 charset, no length byte); honored iff at confirm vin[idxA] still owns nameA AND vin[idxB] still owns nameB, both unlocked (live-ownership re-check = anti-rug, like SETTLE/PAY — no anchor); whole-op drop on ANY failure (idx OOB, idxA==idxB, not-owned, locked, nameA==nameB, not exactly one comma / bad name §3.1); nameA→vin[idxB], nameB→vin[idxA], leases convey, bumps both mutation heights (§3.9)
    else:                                                       ignore
```

**Tables.** `names` (the owned-set store — a row per `(name, owner)` with `lease_expiry`, and
— for a **listed** name — a `listed` flag plus `price`, `seller` (hash160 + script type),
`offer_expiry`, and reservation fields `reserver`, `reserve_expiry`; a **directed-offered** name
instead carries an `offered` flag plus `buyer`, `price`, `seller` (hash160 + script type), and
`offer_expiry` — no reservation fields, since the named buyer is the only completer). `commits` (per
`{commitment, commit_height, tx_index, commit_time}`, `commit_time` = MTP of the commit block,
pruned once `MTP > commit_time + COMMIT_EXPIRY`, §3.2). Per-owner
`last_set_mutation_height` for the renew anchor guard (§3.5). 

**Time-triggered transitions (no transaction).** Apply as the fold crosses the MTP boundary,
**before** that block's transactions: a name lapses to the pool at `lease_expiry`; an unsettled
open listing closes at `offer_expiry` (clears the `listed` flag — the name was always the seller's,
§3.7); an unpaid **directed offer** (SELL_TO) closes at its own `offer_expiry` (clears the `offered`
flag — likewise always the seller's); a lapsed (unsettled) reserve reverts the open listing to its
pre-reserve state at `reserve_expiry`. A **lapse** removes a name from its owner's set, so it stamps
that owner's `last_set_mutation_height` to the **connecting height `H`** (§3.5); the offer/reserve
closes leave the name in the seller's set unchanged and do **not** bump.
Because `reserve_expiry` is **clamped to `offer_expiry`** at RESERVE (§3.7), these nest strictly
— `reserve_expiry ≤ offer_expiry ≤ lease_expiry − REORG_BUFFER < lease_expiry` — so MTP
monotonicity crosses them in order regardless of reorgs (the `REORG_BUFFER` gap is a *relative*
margin between two MTP-evaluated boundaries, matching the chain's own ±2h timestamp bound). A
**directed** offer has only the two-level nest `offer_expiry ≤ lease_expiry − REORG_BUFFER` (no
reserve layer) — a strict sub-case of the same ordering, so its close needs no special handling. A
name freed by lapse **or by RELEASE (§3.6)** leaves its owner at once and is **immediately
reclaimable**; a reclaim a later reorg reverses is dropped on replay — no protocol-level cooling
window, reorg-risk on a reclaim is client-side, exactly as for any fresh claim (§3.2).

**Ordering rule (consensus-critical).** At each height, run all time-triggered transitions for
that height **before** the block's transactions; then process txs in `(tx index, vout)` order,
each change visible to everything after it — a **single forward pass**. When one MTP advance
crosses several boundaries at once, apply the transitions **by type in this order — `reserve_expiry`
(revert reserve → open offer), then `offer_expiry` (close open listing or directed offer), then
`lease_expiry` (lapse to pool)** — and make each transition idempotent (guarded on current state). Ordering by *type* (not
by sorting boundary values) is required because the values can tie — the RESERVE clamp permits
`reserve_expiry == offer_expiry` — and it is the order in which each transition's precondition
already holds. This ordering matters only **within a single name's** reserve→offer→lease chain;
distinct names are independent, and `COMMIT_EXPIRY` pruning is independent of this chain (it must
only, like the rest, precede the block's txs).
`lease_expiry` / `offer_expiry` / `reserve_expiry` are **exclusive** bounds (owned iff
`MTP < lease_expiry`). The **`COMMIT_EXPIRY` window is the lone exception — it is *inclusive*** (a
commit is live *through* `commit_time + COMMIT_EXPIRY` and pruned only once `MTP` strictly exceeds
it, §3.2), because it gates a one-shot prune, not the nested lease/offer/reserve chain. Resolving
ownership *lazily* (testing `MTP < lease_expiry` only at query time) is **forbidden** — a same-block
lapse-and-reclaim MUST apply the lapse before the reclaiming tx in the same block.

**MTP (exact window — consensus-critical).** When connecting the block at height `H`, evaluate
**every** time boundary for that step — both the pre-block time-triggered transitions above and
`H`'s own transactions — against `MTP(H) = median(timestamp[H−11 .. H−1])`: the median of the
timestamps of the **11 blocks strictly before `H`**, with block `H`'s own timestamp **excluded**.
This is exactly Dogecoin's `GetMedianTimePast()` of `H`'s parent — the BIP113 lock-time convention
— so the indexer evaluates a boundary against the very value the host chain used to validate `H`.
**Short window / genesis (pinned):** when fewer than 11 blocks precede `H` (reachable only near
genesis or a low `ACTIVATION_HEIGHT`), take the median over the `k = min(11, H)` available
predecessors — sort them and select index `⌊k/2⌋`, the **upper**-middle for an even `k`, **never**
a two-value average — exactly `GetMedianTimePast()`'s own short-window behavior; and `MTP(0) = 0`
(no predecessors). This must be pinned because the abstract state machine can run from height 0,
where a reader that averaged an even window, took the lower-middle, or left `MTP(0)` undefined
would compute a different boundary and fork an early lapse/settle.
Pinning the index range is consensus-critical: an off-by-one window (including `H`, or sliding to
`[H−10 .. H]`) shifts MTP by up to a block and can flip a single boundary call — one indexer
dropping a SETTLE while another transfers ownership. MTP is a pure function of headers
(deterministic across indexers), monotonic, and miner-resistant (a miner can't pull it back and
can only nudge it forward within the ±2h future bound). It lags real time by ~5–6 blocks; the
indexer acts on a boundary only once it is `REORG_BUFFER`-deep.

**Reorgs.** All state is a pure fold over the canonical chain — on a reorg, roll back the
disconnected blocks and **replay** from the fork point (exact). Never treat reorg-able state as
final.

**Conformance is defined by the shipped fold-vector set** (`(prior state + block/range) →
resulting state or drop`). It pins, at minimum: the commit→claim
committer-binding + commitment-copy case; a claim with no live ≥1-deep commit dropping (no FCFS
fallback) and a same-block commit being too shallow; the priority tuple; the rent water-fill
(≥128-bit per-day rescale, fail-closed at `T = 0`, the `λ = 0` underfunding floor — one day each to the first `T` *headroom-having* names, not a `T < count` branch, the lexicographic
remainder, the `MAX_LEASE` redistribution, and the all-capped `T > 0` remainder forfeited); the renew bitmap ordering and anchor guard, including
that a **SELL listing does not bump** the mutation height while **SETTLE bumps both** and that an
**out-of-bounds set bit (index ≥ `K`) is ignored** (in-bounds bits still act, the action is not
dropped); a
same-block lapse-or-RELEASE-and-reclaim; the market cascade (clamped `reserve_expiry`,
lapsed-reserve revert, a losing reserve's deposit spent yet failing to claim the option, the
per-tx output matching, the 128-bit deposit math at the near-`2⁶⁴` boundary, and a single MTP
advance crossing `reserve_expiry`/`offer_expiry`/`lease_expiry` together — applied in
`reserve → offer → lease` type-order); the SELL price floor `3 × DUST_FLOOR` keeping the settle
remainder from underflowing; the SELL `window` upper bound enforced in add-form (`MTP_now + window + REORG_BUFFER ≤ lease_expiry`) so a short-tailed listing is rejected with no unsigned underflow;
the fee-oracle determinism (the `max(0, coinbase−subsidy)` signed clamp on a miner under-claim,
floor per-block division, participant membership decided **after** the floor division, the
**inclusive** `MIN_FEE_SAMPLE` boundary, the lower-median index `⌊(|P|−1)/2⌋`, the exact
`[h−FEE_WINDOW, h−1]` window, the pinned `block_bytes`/`subsidy`); the MTP window
pinned to `median(timestamp[H−11 .. H−1])` (a boundary call that flips under an off-by-one window);
the **directed sale** (SELL_TO locking the name and not bumping the mutation height; a PAY
from a non-`buyer` `vin[0]` dropping while its exact-value output still pays the seller; a correct
PAY conveying the name + lease and bumping both sets; a directed `offer_expiry` close clearing an
unpaid offer; the `DIRECT_WINDOW`+`REORG_BUFFER` lease-tail bound at SELL_TO); the **acting identity
/ `AS`** (a segment re-pointed to `vin[k]`; an out-of-range or non-`SIGHASH_ALL` named input
dropping its segment; the funding-input-attribution case); the **atomic `TRADE`** (a 1-1 name swap + lease conveyance
bumping both mutation heights; the live-ownership anti-rug — a post-sign move/release/sell/lock/lapse
of either pledged name dropping the *whole* op; **the same-block conflict in both orderings** — a
TRANSFER of a pledged name ordered *before* the TRADE in the same block drops the TRADE (its later
ownership check fails), and one ordered *after* also fails (the TRADE already moved the name to the
counterparty), so neither ordering yields a one-sided outcome; a not-owned / locked / `nameA ==
nameB` / not-exactly-one-comma case dropping it; several independent 1-1 TRADEs batched in one tx);
and lease conveyance on TRANSFER/SETTLE/PAY/TRADE. An indexer conforms
iff it passes **both** the §4 and these fold vectors.

---

## 6. Size budget (the pinned carrier ceiling)

**The payload ceiling is a protocol consensus constant — chosen, not inherited from L1.**
Pepecoin never size-limits a carrier: `IsUnspendable()` marks any script that begins with
`OP_RETURN` unspendable regardless of size, and both `MAX_SCRIPT_SIZE` (10,000 B) and the
520-byte `MAX_SCRIPT_ELEMENT_SIZE` are enforced at script *execution* — which an unspendable
output never reaches. The only bound L1 actually imposes is the ~1 MB serialized-transaction
limit. This protocol pins its ceiling far below that, at the payload a `MAX_SCRIPT_SIZE`-sized
script would carry, so that every implementation can use fixed-size action buffers with
explicit, boundary-tested limits. A protocol carrier is one provably-unspendable output:

```
scriptPubKey = OP_RETURN(1 B) ‖ OP_PUSHDATA2(1 B) ‖ len:2 B LE ‖ payload
payload_max  = 10,000 − 1 − 1 − 2                = 9,996 bytes
body_max     = payload_max − 4 (FF 'P' 'N' op)   = 9,992 bytes
flags_max    = body_max − 5 (anchor)             = 9,987 bytes → 79,896 bitmap positions
flags_max(TRANSFER) = body_max − 20 − 5          = 9,967 bytes → 79,736 bitmap positions
```

Why pin at all, and why this number: an unbounded ceiling ("whatever fits in a mined block")
would not remove the limit — it would relocate it into each implementation's memory strategy,
seven implicit untested caps in place of one explicit boundary-tested rule. 10,000 is L1's own
Schelling point: the size past which `IsUnspendable()` deems *any* script unspendable — the
largest script L1 treats as a script at all. The reach is already beyond any single-owner need
(79,896 names in one carrier); a custodian holding more simply shards across addresses (~80k
names each), and the pin can be raised at an activation height if that ever stops sufficing.
Node relay policy (`datacarriersize`, default 83 script bytes → an 80-byte payload) is a
*forwarding* choice, not validity — a carrier of any size up to the ceiling folds once mined
(a miner may accept it directly, or a network may raise its relay policy). An action longer
than 9,996 payload bytes fails decode and is *ignore* — the ceiling is consensus for this
protocol (all folds must share it exactly).
Payloads ≤ 75 bytes use a direct push (1-byte overhead) and 76..255 use `OP_PUSHDATA1`
(2 bytes) — encodings, not different limits; the ceiling above is the maximum over all forms.

| message | payload bytes | reach |
|---------|---------------|-------|
| RENEW_NAME | 4 + len(name) ≤ 36 | one name per `OP_RETURN`; several per tx via multi-`OP_RETURN` |
| TRANSFER_NAME | 24 + len(name) ≤ 56 | `target`(20) + `name`; one per `OP_RETURN` |
| COMMIT | 36 | — |
| CLAIM | 36 + len(name) ≤ 68 | 32-byte salt; max 32-byte name |
| RENEW (all / safe / selective) | 4 / 9 / 10..9,996 | selective: 79,896 positions (568 within an 80-byte relay payload) |
| TRANSFER (all / selective) | 24 / 30..9,996 | selective: 79,736 positions/target (408 within 80 B) |
| SELL | 16 + len(name) ≤ 48 | — |
| RESERVE | 4 + len(name) ≤ 36 | one per `OP_RETURN`; several per tx via multi-`OP_RETURN` |
| SETTLE | 4 + len(name) ≤ 36 | one per `OP_RETURN`; several per tx via multi-`OP_RETURN` |
| RELEASE | 9 + len(flags) ≤ 9,996 | 79,896 positions (568 within 80 B) |
| RELEASE_NAME | 4 + len(name) ≤ 36 | one per `OP_RETURN`; several per tx via multi-`OP_RETURN` |
| SELL_TO | 32 + len(name) ≤ 64 | `price`(8) + `buyer`(20) + `name`; fixed window, no field |
| PAY | 4 + len(name) ≤ 36 | one per `OP_RETURN`; several per tx via multi-`OP_RETURN` |
| AS | 5 | `[index:1]`; sets acting identity to vin[index], §3.9 |
| TRADE | 7 + len(A) + len(B) ≤ 71 | `[idxA:1][idxB:1]` + `nameA,nameB`; one swap per carrier |

This budget is the **`OP_RETURN` payload only**, unchanged by P2SH: a multisig `vin[0]`'s
redeemScript and its `k` signatures ride in the **`scriptSig`** (its own size/relay budget), so
group actions cost more *tx weight* but not a single `OP_RETURN` byte — the action payloads above
are identical whether signed by a P2PKH key or an m-of-n keyset.

---

## 7. Time & finality

The denomination of every duration follows **what it measures** (§0):

| quantity | denominated in | why |
|---|---|---|
| leases, `COMMIT_EXPIRY`, SELL/`RESERVE_WINDOW`, `DIRECT_WINDOW` | **time (MTP)** | wall-clock commitments; survive a block-speed change |
| `REORG_BUFFER` (window margins) | **time (MTP), ~2 h** | a *relative* gap MTP monotonicity keeps ordered; matches the chain's ±2h timestamp bound |
| priority `(claim_height, commit_height, tx_index)` | **height** | ordering is positional |
| renewal/transfer bitmap anchor, `MAX_ANCHOR_AGE` | **height** | it bounds a height |
| `FEE_WINDOW` (fee-median horizon) | **height (block count)** | a fixed block-**count** keeps the participant scan deterministic (§3.4 — the median itself is made single-element by the lower-median index rule); its ~1 wk span then scales with block speed |

**Finality is two different things.** *Client reorg-trust* ("should I believe this settle?") is a
UI/risk choice, out of consensus scope — a client may use depth, elapsed time, or cumulative
**chainwork** (the rigorous measure, since reorg resistance is *work*, and neither block-count nor
wall-clock tracks work across a difficulty regime change). The *consensus* margin is only
`REORG_BUFFER`, and it is robust because it is a **relative gap** between two MTP-evaluated
boundaries: a uniform MTP shift (even a miner's ±2h nudge) preserves the gap and their order. A
10× block-speed change touches only the height-denominated quantities — never lease durations or any
wall-clock commitment (those are MTP). Priority ordering and the bitmap anchor *should* scale
(ordering is positional; the anchor's 5-byte width already absorbs ~10⁶ years of faster blocks);
`FEE_WINDOW`'s wall-clock span merely shrinks — a tolerated side effect of its fixed-count median
(§3.4), re-tunable at an activation height if the ~1 wk horizon ever matters. The fee *rate* itself
is block-speed-invariant by construction (the density cancels, §3.4).
