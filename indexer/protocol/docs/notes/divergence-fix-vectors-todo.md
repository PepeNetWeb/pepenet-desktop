# Divergence-fix vectors — status + remaining coverage gaps

## DONE (2026-07-09) — landed in all 7 impls + selftests, golden re-pinned to `301ce369…`

The three cross-implementation divergences are now pinned by directed conformance
vectors present in every impl (`impls/{c,go,py,ts,java,rust,csharp}`), cross-checked
by `run-conformance.sh`, and mirrored by C outcome-assertions (`test_scenario_races3`
in `impls/c/src/main.c`) + a Rust oracle unit check:

- `55_claim_release_reclaim_sameblock` — a name minted then RELEASEd earlier in the
  same block re-mints on a later CLAIM in that block (fix #1; spec §3.6).
- `55b_reclaim_by_other` — the freed name mints to a different, lower-priority party
  (proves the departed owner's commit priority is discarded with the row).
- `56_self_transfer_bumps_mut` — a TRANSFER whose target == the owner bumps
  `last_set_mutation_height` (fix #2; spec §3.5).
- `57_oracle_zero_bytes` — `block_bytes == 0` uses divisor 1, so the block still
  participates → rate 1_000_000 (fix #4; spec §3.4). NOTE: porting this vector
  surfaced that **Rust's `fee_per_byte` had the same block_bytes==0→0 bug as TS**;
  both are now fixed to divisor 1.
- `58_lease_clamp_huge_burn` — CLAIM burn near 2⁶⁴ at rate 1 clamps the lease to
  MAX_LEASE with no overflow / no `bits.Div64` panic.

## STILL OPEN — coverage gaps worth a future vector pass

These were flagged in the review but are NOT yet pinned by a directed vector (they
need the same all-7 authoring + golden regen ceremony):

1. **§1 carrier extraction** — exactly `OP_RETURN` + one *minimal* push. Multi-push,
   non-minimal-push, and trailing-opcode `OP_RETURN`s (→ ignore) are never exercised
   end-to-end; every decoder starts from already-extracted payload bytes. The indexer
   DOES implement it (`idx_op_return_payload`), so a vector should drive raw scripts.
2. **Out-of-bounds bitmap bits** (index ≥ K) — a directed RENEW/RELEASE/TRANSFER
   vector; currently only statistical soak coverage.
3. **Anchor-age numeric edges** — `confirm − H == MAX_ANCHOR_AGE` (accept) vs `+1`
   (reject), and a future anchor `H > confirm` (reject).
4. **Minimal-price cascade** — `price = 3·DUST_FLOOR`, both legs clamp to DUST_FLOOR,
   remainder exactly 1 koinu.
