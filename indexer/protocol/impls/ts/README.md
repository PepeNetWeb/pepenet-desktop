# PepeNet namespace — TypeScript reference SM

An independent TypeScript implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

No external dependencies. SHA-256, RIPEMD-160, and SplitMix64 are self-rolled.

## Run it

Requires **Node ≥ 23.6** (native TypeScript type-stripping — no build step, no `tsc`, no `ts-node`):

```sh
node sm.ts selftest              # hand-authored conformance battery (the gate)
node sm.ts digest                # canonical §4 state-digest dump for a fixed scenario
node sm.ts prng 0 5              # SplitMix64 (pinned: seed=0 → 0xE220A8397B1DCDAF)
node sm.ts random 42 1000        # this impl's OWN generator (NON-GOLDEN — see below) → input+state digests
node sm.ts forkvectors           # consensus-fork differential vectors
```

`selftest` exits non-zero on any failure. Names-only state machine (opcodes 0x01–0x0C; no votes/decorate/posts in consensus).

## What's implemented (the whole consensus surface)

| file | surface | spec |
|------|---------|------|
| `src/sha256.ts`, `src/ripemd160.ts`, `src/prng.ts`, `src/utf8.ts` | self-rolled primitives (KAT-checked) | conf §1/§13 |
| `src/decode.ts` | strict fail-closed wire decoder; single-push carrier; ACTION/IGNORE demux (names-only) | §1/§2/§9 |
| `src/attribution.ts` | strict-DER+low-S, pubkey canonical, P2PKH + P2SH-multisig templates, in-order scan, legacy sighash **incl. FindAndDelete**, RIPEMD-160 identity; **injected** curve stubs | §4/§13 |
| `src/oracle.ts` | stateless fee oracle (signed clamp, floor div, odd-window median) + MTP | §3.4/§5 |
| `src/fold.ts` | the fold: commit→claim priority, water-fill, open + directed market cascade, anchor-guarded bitmaps, AS/TRADE, pre-block transitions, **canonical SHA-256 digest** (names+commits+muts) | §3/§6, conf §4 |
| `src/selftest.ts` | exhaustive hand-authored battery (every rule + boundary) | — |
| `src/gen.ts`, `sm.ts` | own (non-golden) generator + CLI | conf §5 |

## Value-path policy (TypeScript-specific, consensus-critical)

Every koinu / price / lease / time / height value is **`bigint`** from the first parsed
byte (`rdLE → bigint`) through the fold to serialization. `number` is used **only** for genuinely
≤32-bit, non-value quantities (`vout`, `tx_index`, array indices, counts, single bytes, UTF-8 code
points). A stray `number` on the value path makes JS **throw** on a `BigInt + number` mix — fail-loud,
never a silent IEEE-754 round. The deposit selftest at `price = 2⁶⁴−1` exercises the 128-bit path that
a `number` would corrupt.

## Conformance role (not the gen.c seed-soak)

This implementation uses its **own** generator, with a self-consistent draw order of its own, so it
does **not** reproduce the `gen.c`-pinned frozen seed-goldens (the `state_digest`, `combined`, fuzz /
attrib digests, …) — that is by design, not a failure, and the `random` mode says so. It therefore
does **not** join the byte-for-byte seed soak (Tier 1, C-only).

What **is** prose-pinned and therefore structurally comparable is the **canonical state-digest layout
(§4)** — a reviewer holding the baseline can diff the `digest` output of a fixed hand-built scenario
field-by-field — and the **consensus-fork vector outcomes**. (See `SPEC-conformance.md`
§"Two conformance tiers".)
