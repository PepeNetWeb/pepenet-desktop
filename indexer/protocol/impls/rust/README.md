# PepeNet namespace — Rust reference SM

An independent Rust implementation of the PepeNet namespace state machine, built from the
specification (`docs/protocol-spec.md` + `protocol-sm/SPEC-conformance.md`). It is part of the
cross-language conformance suite: each implementation is written independently and they
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative reference; the
consolidated rationale for the consensus-critical decisions lives in
[`SPEC-RATIONALE.md`](../../SPEC-RATIONALE.md).

**Zero external crates.** SHA-256, RIPEMD-160, and SplitMix64 are self-rolled from `std` only
(`Cargo.toml` `[dependencies]` is empty).

## Run it

```sh
cargo build --release
./target/release/sm selftest       # the hand-authored conformance battery (the gate) — 103 passed, 0 failed
./target/release/sm forkvectors    # consensus-fork differential vectors (TV-1/5b/6/7/8 + M9 + H8/H3) — 8 match, 0 diverge
./target/release/sm digest         # canonical §4 state-digest dump for a fixed scenario (this impl's OWN golden)
./target/release/sm random 42 1000 # this impl's OWN generator (NON-GOLDEN — see below) → input+state digests
```

`cargo run --release -- <mode>` works too. `selftest` / `forkvectors` exit non-zero on any failure.

## Conformance role (not the gen.c seed-soak)

This implementation uses its **own** generator, with a self-consistent draw order of its own, so it
does **not** reproduce the `gen.c`-pinned frozen seed-goldens — that is by design, not a failure. It
therefore does **not** join the byte-for-byte seed soak (Tier 1, C-only). Instead it cross-validates
on the **prose-pinned consensus-fork vectors** (`forkvectors`): each independent impl must reproduce
the spec-mandated outcome for every consensus-critical vector. (See `SPEC-conformance.md`
§"Two conformance tiers" and `run-conformance.sh`.)

## What's implemented (the whole consensus surface)

| file | surface | spec |
|------|---------|------|
| `src/sha256.rs`, `src/ripemd160.rs`, `src/prng.rs` | self-rolled primitives (KAT-checked) | conf §1/§13 |
| `src/decode.rs` | strict fail-closed wire decoder; single-push carrier; per-opcode parse → ACTION/POST/IGNORE | §1/§2/§9 |
| `src/attrib.rs` | strict-DER+low-S, pubkey canonical, P2PKH + P2SH-multisig templates, in-order scan, legacy sighash **incl. FindAndDelete**, RIPEMD-160 identity; **injected** curve stubs (`on_curve`/`verify`) | §4/§13 |
| `src/oracle.rs` | stateless fee oracle (signed clamp, floor div, fee-bearing participant filter, MIN_FEE_SAMPLE degrade, lower median) + MTP | §3.4/§5 |
| `src/fold.rs` | the fold: commit→claim priority + same-block displacement, water-fill, open + directed market cascade, anchor-guarded bitmaps, AS/TRADE, DECORATE, votes, pre-block transitions | §3/§5 |
| `src/digest.rs` | canonical SHA-256 state digest (`SMv1` layout, pinned widths/sort orders) | conf §4 |
| `src/selftest.rs` | exhaustive hand-authored battery (every rule + boundary, incl. the off-curve-P2PKH attribution regression) | — |
| `src/forkvectors.rs` | the consensus-fork vectors | conf §"fork vectors" |
| `src/generator.rs`, `src/main.rs` | own (non-golden) generator + CLI | conf §5 |

## Value-path & overflow policy (Rust-specific, consensus-critical)

Every koinu / price / vote-weight / lease / height value is carried at a **pinned width**: `u64`/`i64`
for scalars, `u128`/`i128` for the two ≥128-bit computations (the reserve deposit leg, the lease-days
numerator) and the signed vote accumulator. **No value-bearing field ever transits `f32`/`f64`.**

Rust's debug build *panics* on `+`/`-`/`*`/`<<` overflow while release *wraps* — a silent consensus
fork. This impl never relies on the profile: every consensus arithmetic op uses explicit
`checked_*` / `wrapping_*` / `saturating_*` / `as`, so **debug and release produce identical digests**.
`[profile.release] overflow-checks = false` is set deliberately; the vote accumulator's 128-bit
overflow is fail-loud via the digest's trailing `overflow` byte.

## Honest non-reproducibility of the frozen goldens

The frozen seed-goldens are pinned to `impls/c`'s exact generator draw-order and serialization, so
this implementation does **not** reproduce them, and `random` / `digest` say so. What is prose-pinned
and therefore meaningful here is the **canonical state-digest layout (§4)** and the **fork-vector
outcomes**, both of which it reproduces independently.
