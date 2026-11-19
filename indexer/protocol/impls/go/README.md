# PepeNet namespace — Go reference SM

An independent Go implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

**Standard library only** (Go 1.21+, empty-`require` `go.mod`). SHA-256 uses `crypto/sha256`;
RIPEMD-160 and SplitMix64 are self-rolled. Go has **no native 128-bit integer**, so the two
≥128-bit computations (the `price·bps` deposit legs and the `burn·LEASE_QUANTUM` lease-day numerator)
use `math/bits`, and the signed vote accumulator is a hand-rolled two's-complement `i128`.

Because Go relies on `bits.Div64` for the wide division, this impl carries the spec-mandated
`hi ≥ den` sentinel guard (conformance §2): under the production rate floor `DUST_FLOOR = 1` an
unguarded `Div64` would panic on a low-fee + fat-burn input. (Languages with a full 128-bit `T` —
C/C#/Rust/Python — sidestep the same hazard structurally.)

## Run it

```sh
go run . selftest      # hand-authored conformance battery + the off-curve-P2PKH attrib regression (the gate)
go run . forkvectors   # consensus-fork differential vectors (TV-1/5b/6/7/8 + M9 + H8/H3) — 16 match, 0 diverge
go run . scenario      # this impl's OWN scenario digests (NON-GOLDEN — see below)
go run . attrib-selftest
go run . digest        # empty-state digest demo
```

`selftest` / `forkvectors` exit non-zero on any failure.

## Conformance role (not the gen.c seed-soak)

This implementation uses its **own** scenario generator, with a self-consistent draw order of its
own, so it does **not** reproduce the `gen.c`-pinned frozen seed-goldens — that is by design, not a
failure. It therefore does **not** join the byte-for-byte seed soak (Tier 1, C-only). Instead it
cross-validates on the **prose-pinned consensus-fork vectors** (`forkvectors`): each independent impl
must reproduce the spec-mandated outcome for every consensus-critical vector. (See
`SPEC-conformance.md` §"Two conformance tiers" and `run-conformance.sh`.)

## Layout
- `const.go`            protocol constants, opcodes, name-state enum
- `prng.go`             SplitMix64 (self-implemented; KAT `seed=0 -> 0xE220A8397B1DCDAF`)
- `ripemd160.go`        self-rolled RIPEMD-160 (KAT `""`→`9c1185a5…`, `"abc"`→`8eb208f7…`)
- `u128.go`             `math/bits` wide products + a two's-complement signed `i128`
- `wire.go`             strict, fail-closed payload decoder (ACTION | POST | IGNORE)
- `attrib.go`           §4 byte-logic (strict-DER/low-S, P2PKH + P2SH-multisig, legacy sighash +
                        FindAndDelete) with the **injected** `onCurve`/`curveVerify` oracle
- `state.go` / `digest.go`  the fold state + canonical SHA-256 state digest
- `fold.go` / `dispatch.go` / `waterfill.go`  the deterministic fold (all opcodes, pre-block
                        transitions, water-fill)
- `oracle.go`           §3.4 participant-median fee oracle (fee-bearing filter, `MIN_FEE_SAMPLE`
                        degrade, lower median, `DUST_FLOOR..RATE_CAP` clamp) — a pure helper; the
                        fold takes `rate` as a given
- `scenario.go` / `scenarios_impl.go`  hand-authored adversarial battery + behavioral asserts
- `forkvectors.go`      the prose-pinned consensus-fork vectors
- `selftest.go`         the self-test gate (incl. the off-curve-P2PKH regression)

## Important
The scenario generator is **internally consistent but NOT the reference generator**
(SPEC-conformance §5 pins that to `impls/c`). Its digests are this impl's own and are **not**
comparable to the reference frozen goldens (§6). The curve operations are the conformance doc's
injected pseudo-functions, not real secp256k1.
