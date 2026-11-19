# Incremental state digest (ECMH) — desync detection & implementor confidence

> Status: **SHIPPED in protocol-sm (2026-06-30).** The ECMH primitive + `sm ecmh` vector
> mode is built and **byte-identical across all 7 impls** (golden
> `combined = 2cdee6ada7cb8739a0a9478bd0d14c71568445f68fd3bbf9fb6fe4fc1d8b83b2`); the C
> reference also carries `sm_state_ecmh` + an equality-tracking selftest. Pinned in
> `SPEC-conformance.md` §13.2 and `docs/protocol-spec.md` §3.9 (advisory/non-consensus).
> **`sm_state_ecmh` is now ported to all 7 impls** (each with the equality-tracking
> selftest), cross-pinned by the `empty_state_ecmh =
> 053f61e599084024c9acd6a3127057ea5de001829225590ea2b175c5506b5c55` anchor that
> `run-conformance.sh` asserts across all 7 — debt closed. The design record below is
> preserved as authored.

## 1. Goal — and the non-goals that shrank it

**Goal.** Give the consensus fold a *single small number* per block that is a pure,
deterministic function of the full consensus state, so that:

1. **Node desync detection** — two honest nodes on the same tip MUST produce the same
   number; a mismatch is a divergence alarm (most valuable on the hairy market-race fold
   logic — protocol-sm scenarios 38–42, where the one real consensus fork-bug lived).
2. **Independent-implementor confidence** — a fresh node, fed real chain data, computes
   one number and checks it against the reference. A far lower adoption bar than porting
   the whole protocol-sm state machine.

**First value is at test time, not in production.** The `sm ecmh` golden cross-checked
across all 7 reference impls (§7) is itself a continuous divergence detector — "do these
independent implementations still agree on full state?" — realized immediately, before any
production network of multiple nodes exists. Production desync gossip (§8) is the same
digest, later, for free.

**Explicit non-goals (each one deleted real complexity — see the conversation that led
here).** This is **not** an SMT, **not** a light-client proof system, **not** consensus.

- **No light clients / no SPV proofs.** A sum is not a membership structure: ECMH lets you
  prove *two states are equal*, never *"name X → owner Y"* against the digest. That was the
  job of a sparse Merkle tree + a trust quorum, both **dropped** — the quorum reliance was
  the dealbreaker. If SPV is ever wanted it is a *separate*, additive step: swap the
  per-domain point-sum for a tree over the **same** §4 per-record encoding. Crucially, the
  eager time-triggered materialization this memo locks down (§5) is groundwork SPV needs
  anyway — so doing it now makes SPV-later a clean addition, not a retrofit. This memo
  forecloses nothing.
- **Not consensus / advisory only.** Dogecoin has no commitment slot — the digest is never
  on-chain and never PoW-secured. A mismatch triggers **resync / diagnostics only**, NEVER
  a peer-ban or tx-rejection. The instant a mismatch has a consensus consequence, the
  *computation* has been promoted to consensus — the explicit "settlement-fact-not-
  computation" non-goal. The digest is a smoke detector, not a judge.
- **Distinct from the rejected community-moderation SMT**
  ([group-ownership-and-moderation.md §8](group-ownership-and-moderation.md)). That was an
  *off-chain authority* structure (an owner multisig *signs* state; validity = "the owner
  said so"; DA = gossip). This is a *deterministic digest of the consensus fold* — no
  authority, no off-chain DA (the preimage is the chain), no value gating. None of §8's
  N1–N5 objections apply.

## 2. Why not a flat hash

A flat `SHA256(whole state)` re-hashes the entire registry every block (~1/min) —
potentially gigabytes a minute. Rejected on cost.

The fix is an **incremental multiset hash**: a running accumulator updated by the
per-block *delta* (the handful of records that changed), not by re-reading the state.
Cost per block = **O(records changed this block)** — a few dozen ops/min. The full O(n)
pass happens once, at startup / snapshot load, never again.

## 3. Why ECMH

**Elliptic Curve Multiset Hash:** map each record to a curve point; digest = sum of
points; add/remove = point add/subtract.

- **Incremental** — `acc += P(new) − P(old)` per changed record. O(delta)/block.
- **Commutative** — order-independent, so the digest.c sort is no longer needed for
  correctness.
- **Invertible** — reorg rollback is `acc −= P(added); acc += P(removed)`, O(changes),
  riding the fold's existing reorg path. No authenticated-tree reorg machinery.
- **Reuses shipped infrastructure** — Strategy B already landed self-rolled, byte-identical,
  conformance-pinned **secp256k1 + RFC-6979 in all 7 impls** (`attrib-curve`). The hard
  cross-language part (the curve math, UBSan-clean) is done. The only new pinned primitive
  is **hash-to-curve**.
- **33-byte digest** (compressed SEC1 point) — a nice thing to compare and (later) gossip.

Threat model is *accidental* divergence between honest impls, not an adversary forging
state — so a weaker incremental checksum would technically do. ECMH costs the same
O(delta)/block and adds collision resistance for free, guarding the one nasty false
negative: **two offsetting bugs canceling to the same digest and masking a desync.**
(XOR-accumulators are rejected for exactly this — linear over GF(2), cancellation-prone.)

## 4. Construction — the incremental twin of `sm_state_digest`

The canonical per-record encoding **already exists** in
[digest.c](../../protocol-sm/impls/c/src/digest.c): pinned field widths, LE ints, i128
score as 16-byte two's-complement LE, and the documented subtleties (`owner_type` NOT
digested — ownership is by bare hash160; the H7 `(commitment, commit_height, tx_index)`
tie-break). ECMH reuses those bytes verbatim so the two digests induce the **identical
equality relation by construction**.

**Per-record point.** For a record `r` in table `T`:

```
P(r) = hash_to_curve( "ECMHv1" ‖ tag(T) ‖ row_bytes(r) )
```

where `row_bytes(r)` is **exactly** the byte sequence digest.c emits for that row (no count
prefix, no global framing — just the per-row fields), and `tag(T)` is a 1-byte domain tag
giving second-preimage separation between tables (a name-row can never collide a commit-row).

**Domain sub-accumulators** (preserves the "level 2" localization preference — a desync
points at a *domain*, not just "somewhere"):

```
A_names   = Σ P(r) over names      (ownership + market — market is folded into the name row here)
A_commits = Σ P(r) over commits
A_votes   = Σ P(r) over votes       (per-view §3.8; included to mirror sm_state_digest's coverage)
A_muts    = Σ P(r) over muts
A_decors  = Σ P(r) over decors
```

Identity (empty domain) = point at infinity; pin its fixed-width 33-byte serialization
(reserved all-zero, since SEC1's 1-byte infinity breaks fixed width).

**Combined top digest** (computed on demand from the five 33-byte sub-points — tiny, not
incremental):

```
combined = SHA256( "ECMHtop1" ‖ ser(A_names) ‖ ser(A_commits) ‖ ser(A_votes)
                              ‖ ser(A_muts) ‖ ser(A_decors) ‖ overflow_flag )
```

`overflow_flag` rides the top digest exactly as digest.c's fail-loud marker does.

## 5. Hash-to-curve — try-and-increment

The H2C input is **not secret**, so constant-time is irrelevant — use **try-and-increment**
(simplest to make byte-identical across 7 langs; matches the `attrib-curve` pinning style).
Pin exactly:

- candidate `x = SHA256("ECMHh2c1" ‖ preimage ‖ ctr_le32) mod p`, `ctr` from 0;
- accept the first `ctr` whose `x` is a valid curve x-coordinate (`x³+7` is a QR mod p);
- `y` = the root with **even** parity (pin the parity rule);
- KAT vectors frozen as goldens, like `attrib-curve`'s `(r,s)`/DER set.

## 6. The one genuinely-new spec obligation — time-triggered materialization

Today the fold output is per-view, so it never matters *when* a time-triggered transition
is applied. Hashing the state ends that: a name's state changes with **no transaction**,
purely because MTP crossed a threshold. Each such transition MUST materialize as a delta at
a **single canonical block** — the block whose MTP first crosses — *eagerly*, or two honest
impls (one lazy-on-read, one eager) compute different digests: a phantom desync, or a real
one masked.

This is the real new work, but it is **bounded** — a finite, enumerable list:

- **lease lapse** — owned iff `MTP < lease_expiry`; the "now-unowned" delta applies at the
  first block with `MTP ≥ lease_expiry`.
- **`COMMIT_EXPIRY` prune** of stale commits.
- **`RESERVE_WINDOW` / `reserve_expiry`** close.
- **`DIRECT_WINDOW` / `offer_expiry`** self-shed.

For ECMH this is *natural*, not a fight: each is "subtract the old row-point, add the new"
at the pinned block. Pin each in SPEC-conformance + scenario vectors. (Note: this hardening
has value **independent** of ECMH — it's a latent inter-impl determinism gap that hashing
merely *exposes*.)

## 7. protocol-sm deliverable

1. **`sm ecmh` mode** — emit the five sub-accumulators + `combined` at the soak / forkvector
   checkpoints. Goldens **byte-identical across all 7 impls** (pins H2C + the curve sum).
2. **Property (in `properties`):** ECMH-equality ⟺ `sm_state_digest`-equality over the
   whole soak — proves ECMH faithfully captures state equality (no collision masks a desync
   in practice).
3. **Property:** incremental (subtract-old + add-new over a synthetic edit) == from-scratch
   `Σ P(r)` — proves the production-node maintenance recipe is correct.
4. **H2C KAT** vectors (goldens).
5. **C selftest** additions (131 → +N), UBSan-clean; soak stays c-only, reference tier all 7.

Note: protocol-sm keeps `sm_state_digest` as the from-scratch oracle (cheap on small test
states); ECMH is the *additional*, incrementally-maintainable digest. They are different
*values* (a point-sum ≠ a SHA of sorted rows) but the **same equality relation** — pinned by
property #2, not by value equality.

## 8. Production node (later — not v1 of this work)

Maintain `acc` incrementally through the fold (the fold already mutates rows — emit the
add/subtract at each mutation). Gossip `(block_hash, height, combined)`; **desync = same
`block_hash`, different `combined`** (different `block_hash` at one height is an honest fork,
not a desync). On mismatch: resync / diagnostic, **never** ban or reject. Falls out for free
whenever a second production node exists.

**Bonus (snapshot / fast-sync).** Because the digest is a sum, a snapshot at height H ships
`acc` (33 bytes/domain); a new node verifies its reconstructed state sums to it before
folding forward — without re-folding from genesis. Lightweight, no tree.

## 9. Open call before execution

Sub-accumulator grouping: this memo groups **by table** (names/commits/votes/muts/decors),
which mirrors `sm_state_digest` exactly. The earlier "ownership / market / commit" framing
collapses here because **market state is folded into the name row** (`st` + the market
fields), so "ownership" and "market" share one table. By-table is the natural seam; flag if
you want market split into its own accumulator (would mean digesting LISTED/OFFERED/RESERVED
rows under a separate tag — more surface, finer localization).
