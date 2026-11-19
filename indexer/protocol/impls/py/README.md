# PepeNet namespace — Python reference SM

An independent Python implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

**Standard library only** (Python 3.8+, no third-party packages). SHA-256/RIPEMD-160 use `hashlib`
(RIPEMD-160 self-rolled if the OpenSSL build lacks it); SplitMix64 is self-implemented. The fold's
wide computations use Python's arbitrary-precision integers, so the §2 overflow math is exact by
construction.

## Run it

```sh
python3 sm.py selftest          # hand-authored conformance battery (the gate) — 89 checks, 0 failures
python3 sm.py forkvectors       # consensus-fork differential vectors (TV-1/5b/6/7/8 + M9 + H8/H3) — 8 match, 0 diverge
python3 sm.py digest <seed> <n> # this impl's OWN generator (NON-GOLDEN — see below) → state_digest
python3 sm.py decode-demo       # strict wire decoder ACTION|POST|IGNORE
python3 sm.py attrib-demo       # §4 attribution with the injected curve oracle
```

`selftest` / `forkvectors` exit non-zero on any failure.

## Conformance role (not the gen.c seed-soak)

This implementation uses its **own** generator, with a self-consistent draw order of its own, so it
does **not** reproduce the `gen.c`-pinned frozen seed-goldens — that is by design, not a failure. It
therefore does **not** join the byte-for-byte seed soak (Tier 1, C-only). Instead it cross-validates
on the **prose-pinned consensus-fork vectors** (`forkvectors`): each independent impl must reproduce
the spec-mandated outcome for every consensus-critical vector. (See `SPEC-conformance.md`
§"Two conformance tiers" and `run-conformance.sh`.)

## Layout
- `const.py`   protocol constants, enums, fixed-width masks
- `prng.py`    SplitMix64 (self-implemented; KAT `seed=0 -> 0xE220A8397B1DCDAF`)
- `hashes.py`  SHA-256 + RIPEMD-160 (`hashlib`, with a self-rolled RIPEMD-160 fallback)
- `wire.py`    strict, fail-closed payload decoder + single-minimal-push extractor
- `attrib.py`  §4 byte-logic (strict-DER/low-S, P2PKH+P2SH-multisig, legacy sighash +
               FindAndDelete) with the **injected** `on_curve`/`verify` curve oracle
- `fold.py`    the deterministic fold (all opcodes, pre-block transitions, water-fill, fee
               oracle, MTP) + the canonical SHA-256 state digest
- `sm.py`      wire encoders, tx builders, the self-test battery, `forkvectors`, the generator

## Important
The seed generator is **internally consistent but NOT the reference generator**
(SPEC-conformance §5 pins that to `impls/c`). Its digests are this impl's own and are **not**
comparable to the reference frozen goldens (§6). The curve operations are the conformance doc's
injected pseudo-functions, not real secp256k1.
