# protocol-sm — Java reference SM

An independent Java implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

## Design choices
- **`BigInteger` for all koinu/price/burn/pay values** (always in `[0, 2⁶⁴)`),
  so the §2 "load-bearing anti-fork" overflow math (`price·bps`, `burn·LEASE_QUANTUM`)
  is exact by construction — an arbitrary-precision oracle, like the Python reference.
- **Names-only consensus**: opcodes contiguous `0x01–0x0C` (COMMIT..TRADE); VOTE/DECORATE
  and POST removed; digest is `SMv1` over names+commits+muts; ECMH uses 3 tags / 3 points.
- **Self-rolled RIPEMD-160** (the one primitive not in the JDK), gated by the §13 KATs.
- Timestamps/heights are `long` (i64); unsigned compares are explicit.

## Run (no build step — Java 22+ multi-file source launch)
```
java Sm.java selftest          # PRNG + RIPEMD/SHA/hash160 KATs + empty digests
java Sm.java behav             # hand-authored §5/§7 consensus vectors (names-only)
java Sm.java scenario          # directed adversarial conformance vectors + combined
java Sm.java attrib-scenario   # §4 attribution byte-logic (16 vectors)
java Sm.java random     <seed> <count>   # soak: input_digest + state_digest
java Sm.java properties <seed> <count>   # §8 invariant battery: violations + digests
java Sm.java meta       <seed> <count>   # §11 drop-closed: inert actions stay inert
java Sm.java reorg      <seed> <count>   # §10 replay/resume/clear-rebuild/fork confluence
java Sm.java fuzz       <seed> <count>   # §9 decode→fold over adversarial bytes (crash-safety)
java Sm.java reorgfuzz  <seed> <count>   # §11 64 fork/divergence trials
```

## What is validated (independent of any generator)
| check | result |
|---|---|
| PRNG KAT (`next(seed=0)=e220a8397b1dcdaf`) + RIPEMD/hash160 KATs + name structural rules | **pass** |
| Behavioral consensus vectors (§5/§7 names/market + §3.4 fee-oracle; no vote/decor) | **pass** |
| §4 attribution byte-logic (RIPEMD/FaD/DER/low-S/pubkey/template/identity/scan) | **16/16 pass** |
| `properties` invariant battery (no double-ownership; lease nesting; deposit-leg conservation; mutation bound) | **violations=0** (seeds 1/42/1000/31337, ≤30k tx) |
| `meta` drop-closed (inert actions provably inert) | **failures=0** |
| `reorg` confluence (replay/resume/clear-rebuild/fork-and-return) | **failures=0** |
| `reorgfuzz` (64 PRNG fork trials) | **failures=0** |
| `fuzz` decoder robustness over adversarial bytes | **parser_crashes=0** |

## Conformance role (not the gen.c seed-soak)
The **generator** draw order (§5) and the **§4 legacy-sighash serialization** are pinned
to `impls/c` (SPEC-conformance §1: "when this prose is ambiguous, `impls/c` is normative").
So the **generator-dependent frozen digests** (soak `state_digest`, `fuzz`/`bfuzz`,
`scenario combined`, `attrib`, `property_digest`, `reorg_digest`) are **not reproduced from
prose alone** — that is by design, not a failure. This impl emits its own
internally-consistent digests and says so explicitly; the **fold/decoder/attribution
consensus logic** — the part that matters — is validated by the generator-independent checks
above. (See `SPEC-conformance.md` §"Two conformance tiers".)
