# PepeNet namespace — C reference implementation (normative)

The **normative** implementation of the PepeNet namespace state machine. Where the prose of
`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md` is ambiguous, **this implementation is
the tie-breaker** — the other six impls (`py`, `ts`, `java`, `rust`, `go`, `csharp`) are independent
clean-room reimplementations that cross-validate the spec against it. The consolidated rationale for
every consensus-critical decision lives in [`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md), which cites
the specific `impls/c` source line for each pinned point.

**C11, zero external dependencies.** SHA-256, RIPEMD-160, and SplitMix64 are all self-contained in
`src/`. `__int128` (a clang/gcc extension) carries the 128-bit money / vote-accumulator math; no
value-bearing field ever transits floating point.

## Build & run

```sh
make            # build ./sm
make test       # ./sm selftest — 130 unit checks (the gate)
make cover      # assert every generator + decode branch is exercised
make sanitize   # UBSan over every mode (signed-overflow / OOB-index / bad-shift UB)
make clean
```

`sm` is a single binary dispatching on its first argument. The conformance-load-bearing modes:

| mode | what it does |
|------|--------------|
| `selftest`         | hand-authored unit battery (codec round-trips, digest-sensitivity, every fold rule + boundary, the off-curve-P2PKH attribution regression, the real-secp256k1 KATs) — **131 passed, 0 failed** |
| `random S N`       | the **reference generator**: regenerate N blocks from seed S, fold, print input+state digests. This is the draw-order the frozen seed-goldens are pinned to. |
| `scenario`         | 54 named adversarial vectors + combined golden `4c84238f…` |
| `attrib-scenario`  | §4 attribution scenarios + combined golden `9fb14077…` |
| `attrib-selftest`  | §4 byte-logic unit battery (strict-DER/low-S, P2PKH + P2SH-multisig, sighash, FindAndDelete) |
| `attrib S N`       | seed-driven §4 attribution soak (injected curve oracle) |
| `attrib-curve`     | **real secp256k1** vector set (§4 Strategy B): on-curve edges, RFC-6979 (r,s)+DER, verify boundaries, end-to-end sighash→verify — frozen `combined 5b7d1e76…` / `combined_e2e c24c5602…` |
| `forkvectors`      | the prose-pinned consensus-fork vectors (TV-1/5b/6/7/8 + M9) — 6 match, 0 diverge |
| `properties S N`   | §8 fold-invariant battery — self-aborts if `violations≠0` |
| `reorg` / `reorgfuzz S N` | §10 reorg-confluence — self-aborts if `failures≠0` |
| `meta S N`         | §11 inert-action inertness — self-aborts if `failures≠0` |
| `fuzz` / `bfuzz S N`      | §9 decoder crash-safety (random + boundary-cluster byte payloads) — self-aborts if `parser_crashes≠0` |
| `coverage S N`     | generator + decode branch-coverage report |
| `drop`             | empty-state digest demo |

`--cov` appends a coverage report to the soak modes. `selftest` / `scenario` / `forkvectors` and the
invariant modes exit non-zero on any failure.

## Conformance role — this impl *owns* both tiers

Unlike the cross-validating impls, the C reference participates in **both** conformance tiers
(`SPEC-conformance.md` §"Two conformance tiers", driven by `../../run-conformance.sh`):

- **Tier 1 — seed-soak self-regression (C-only).** `gen.c` is *the* reference generator; the frozen
  scenario / attrib-scenario goldens and the seed-soak digests are pinned to its exact draw-order and
  serialization. No other impl reproduces these byte-for-byte (by design — each has its own internally
  consistent generator), so Tier 1 is a C-only regression fence: any unintended change to the fold or
  digest layout moves a golden and fails the run.
- **Tier 2 — independent cross-validation.** All seven impls (this one included) must reproduce the
  **prose-pinned** consensus outcomes: the canonical state-digest layout (§4) and the `forkvectors`.
  These are spec-derived, not generator-derived, so agreement across seven independently written folds
  is real evidence the *spec* is unambiguous on the consensus surface.

## Layout

Primitives & wire:
- `sha256.{c,h}`, `ripemd160.{c,h}`, `prng.h` — self-contained hashes + SplitMix64 (KAT-checked)
- `decode.c` — strict, fail-closed payload decoder (ACTION | POST | IGNORE)

The fold (consensus core):
- `sm.h` — the state model, opcode/enum definitions, shared declarations
- `fold.c` — the deterministic per-block fold driver; `preblock.c` — pre-block transitions (lease
  expiry, market timeouts, water-fill trigger)
- `claim.c` — commit→claim priority + same-block displacement; `bitmap.c` — selective-name bitmaps +
  mutation-height bookkeeping; `lease.c` — pay-for-duration leases; `oracle.c` — coinbase-fee oracle +
  MTP; `market.c` — open + directed market cascade; `trade.c` — atomic name swap
- `state.c` / `digest.c` — fold state + the canonical SHA-256 state digest (pinned widths/sort orders)

Attribution (§4):
- `attrib.{c,h}` — strict-DER + low-S, pubkey canonicalization, P2PKH + P2SH-multisig templates,
  in-order input scan, legacy sighash incl. FindAndDelete, RIPEMD-160 identity. The `attrib` /
  `attrib-scenario` modes use the conformance doc's **injected** curve pseudo-functions (so their
  goldens stay byte-identical); the **real** curve runs as `attrib-curve` — see *Real-crypto attribution*.
- `secp256k1.{c,h}` — self-rolled, zero-dep secp256k1: field mod `p = 2²⁵⁶ − 2³² − 977` (4×64-bit limbs +
  fast fold-reduction), Jacobian point math, ECDSA verify, RFC-6979 deterministic sign, KAT-pinned constants.
- `attrib_curve.c` — the `attrib-curve` pinned ECDSA curve-vector set (Strategy B).

Generators & harness:
- `gen.c` — the reference scenario generator (pins Tier 1)
- `harness.c` — scenario vectors, forkvectors, the invariant batteries, coverage
- `main.c` — CLI dispatch + the 131-check self-test

## Real-crypto attribution (Strategy B — shipped)

The §4 attribution **byte-logic** is conformance-tested for real (DER/low-S parsing, template matching,
sighash construction, FindAndDelete), and the **curve is now real too**. `secp256k1.c` is a self-rolled,
zero-dependency secp256k1 (field/point/scalar math, ECDSA verify, RFC-6979 deterministic signing), and
`attrib-curve` is the **pinned ECDSA curve-vector set** — on-curve membership at the edges, RFC-6979
`(r,s)` + canonical DER known-answers, ECDSA verify at the scalar boundaries (r/s=0,n; tampered hash;
wrong key; high-S still verifies), the `priv=1⇒G` / `priv=2⇒2G` external KAT, and an end-to-end pass
that signs a tx's *real* legacy sighash and drives the full `attribute()` pipeline with the real curve.
Frozen `combined 5b7d1e76…` / `combined_e2e c24c5602…`; the curve constants/2G/n·G=∞/decompress/
sign-verify KATs are folded into `selftest`, and the code is UBSan-clean. All seven reference impls
(c · py · ts · java · rust · go · cs) carry an independent self-rolled secp256k1 and must print
byte-identical `attrib-curve` output — `run-conformance.sh` asserts it. The injected oracle is retained
only for the `attrib` / `attrib-scenario` byte-logic goldens. See `SPEC-conformance.md §13.1`,
`SPEC-RATIONALE.md §11`, and `docs/notes/strategy-b-attribution-crypto-plan.md`.
