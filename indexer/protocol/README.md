# namespace-protocol

Cross-language reference implementations of the PepeNet namespace state machine
(the §5 fold of [`docs/protocol-spec.md`](docs/protocol-spec.md)), built for
**headless conformance testing**: the same seed-driven action stream is
regenerated and folded in every language, and they must all produce the
byte-identical canonical digest.

```
namespace-protocol/
  docs/protocol-spec.md the protocol specification this state machine implements
  SPEC-conformance.md   the pinned contract (PRNG, integer widths, digest layout, generator)
  SPEC-RATIONALE.md     consolidated rationale for the consensus-critical decisions
  run-conformance.sh    builds every present impl, runs the conformance matrix
  impls/
    c/      reference (Makefile, zero deps + a vendored sha256)   ← normative
    py/     standard-library Python (arbitrary-precision integers)
    ts/     Node-native TypeScript (bigint value path)
    rust/   cargo, std-only, native u128/i128 + a self-rolled sha256
    go/     stdlib-only, math/bits (Mul64/Div64/Add64) + a small i128 helper
    java/   JDK source-launch, BigInteger value path
    csharp/ dotnet, BCL-only, UInt128/Int128
  shim/secp_shim.c      protocol-sm's secp_* API on vendored libsecp256k1 — for CONSUMERS
                        (daemons/wallets) that must not ship the self-rolled test-oracle curve
```

This is a suite of **seven independent implementations** — C, Python, TypeScript,
Rust, Go, Java, and C# — each written from the specification on its own. They
cross-validate the spec's consensus-critical outcomes. `impls/c` is the normative
reference; the rationale behind the consensus-critical decisions is consolidated in
[`SPEC-RATIONALE.md`](./SPEC-RATIONALE.md).

**Conformance is two-tier:**

- **Tier 1 — the gen.c seed-soak (C-only).** A seed-driven action stream is
  regenerated and folded with `impls/c`'s pinned generator and checked against the
  frozen byte-identical goldens; this is a self-regression of the reference across
  every test layer (`random` soak, `scenario` vectors, differential `fuzz`/`bfuzz`,
  `properties`, `reorg`/`reorgfuzz`, `meta`; see *Test layers* below). The C
  reference holds at **1,000,000 actions** (`random`, `fuzz`, and `properties`).
- **Tier 2 — the seven independent impls.** Each impl uses its own generator, so by
  design it does not reproduce the gen.c-pinned soak goldens. Instead the impls
  cross-validate what the **prose** pins: the `forkvectors` consensus-fork vectors,
  the §8/§9/§10/§11 invariant batteries (`properties`/`meta`/`reorg`/`reorgfuzz`/
  `fuzz`), and the `selftest` battery (including the off-curve-P2PKH attribution
  regression).

Go has no native 128-bit integer, so its wide computations (the deposit legs, the
lease-day numerator, and the property sums) use `math/bits` and
a small two's-complement `i128` helper.

## The idea

Each implementation is one program: `sm random <seed> <count>` →

```
seed → SplitMix64 → state-aware generator → the §5 fold → digest
                          │                                  │
                          └ input_digest (hash of the         └ state_digest (hash of fold state)
                            generated tx stream)
```

**Conformance ⟺ all implementations print the same two digests for the same
`(seed, count)`.** Because each regenerates the stream from the seed there are no
corpus files; a complete proof is "run it everywhere, compare one line." Two
digests localise a mismatch: differing `input_digest` ⇒ generator/PRNG drift;
matching `input_digest` but differing `state_digest` ⇒ fold drift.

The generator deliberately manufactures edge cases (windows at floor/cap,
near-2⁶⁴ prices, stale anchors, summed payments, locked-name moves, OOB AS
indices, no-commit claims …) and tracks coverage counters, so a large soak both
agrees across languages **and** exercises every branch.

## Run it

```sh
cd impls/c && make test          # C self-test (130 unit checks: codec round-trips + digest-sensitivity + market-race outcomes)
cd impls/c && make sanitize      # UBSan over every mode (signed-overflow / OOB / shift UB)
cd impls/c && make cover         # assert every generator + decode branch is exercised
./impls/c/sm random 42 100000 --cov          # seed-driven soak + coverage report
./impls/c/sm scenario                        # named adversarial conformance vectors + combined digest
./impls/c/sm fuzz  42 100000 --cov           # differential fuzz: byte payloads → decode → fold (+coverage)
./impls/c/sm bfuzz 42 100000 --cov           # boundary-cluster fuzz: values snapped to the §-constants
./impls/c/sm properties 42 100000            # invariant battery + cross-language property_digest
./impls/c/sm reorg     42 8000               # replay / resume / clear-rebuild / fork confluence
./impls/c/sm reorgfuzz 42 8000               # reorg-depth fuzzer (64 PRNG fork/divergence trials)
./impls/c/sm meta      42 20000              # metamorphic drop-closed (inert actions stay inert)
./impls/c/sm attrib    42 100000 --cov       # §4 attribution shell: raw tx → Identity|drop (+coverage)
./impls/c/sm attrib-scenario                 # RIPEMD160 KAT + named attribution vectors + combined
./impls/c/sm attrib-selftest                 # C-only: RIPEMD160 / hash160 / FindAndDelete / DER KATs
python3 impls/py/sm.py fuzz 42 100000        # the Python oracle (arbitrary precision)
( cd impls/go && go build -o sm . && ./sm random 42 100000 )   # the Go port (math/bits + I128)
./run-conformance.sh                         # cross-check every present impl across ALL modes
./run-conformance.sh 1000000                 # …including a 1M soak
```

**Cross-language test layers**, each cross-checked byte-for-byte across every language:

1. **`random`** — a seed-driven soak proving the fold *agrees* over millions of adversarial actions.
2. **`scenario`** — named, hand-authored edge cases with auditable outcomes: the spec's §5 corners
   plus the rare branches the soak almost never hits (deep claim displacement, water-fill `T<count` /
   all-cap forfeit, the fee oracle, **reorg edge-case pairs**, and the
   **pre-block ordering / intra-block market races** of 38–41: lapse-vs-renew-vs-claim ties, the
   reserve→offer pre-block cascade, RESERVE option-theft, and consume-once vout-order matching).
3. **`fuzz`** / **`bfuzz`** — a real byte-level wire decoder (`decode.c`, the strict §1/§2/§3 fail-closed
   parse) fed dumb-random + grammar-aware-perturbed payloads (`fuzz`), and a boundary-cluster variant
   that snaps numeric fields to the protocol constants ±1 and the word edges (`bfuzz`) so the fold's
   comparisons are probed densely. The differential fuzzers that find parser/bounds/off-by-one
   divergences hand-written vectors miss.
4. **`properties`** — the soak stream with a hard invariant battery (conservation, no-double-ownership,
   boundary nesting) and a per-block `property_digest` — invariants *proven* across languages.
5. **`reorg`** / **`reorgfuzz`** — the §5 reorg story made executable: replay, checkpoint-resume,
   clear-rebuild, and fork-and-return down a divergent branch — once at a fixed fork (`reorg`) and over
   64 PRNG-chosen fork/divergence trials per chain (`reorgfuzz`).
6. **`meta`** — the metamorphic property that an *ignored* action is provably inert: inject an all-inert
   tx after every block and assert the digest is byte-unchanged.
7. **`attrib`** / **`attrib-scenario`** — the **§4 Stateless Identity & Attribution** layer (`raw tx →
   {Identity｜drop}`): a separate seed-driven harness that runs the real attribution byte-logic
   (strict-DER, low-S, canonical pubkey encoding, P2SH-multisig template + in-order scan, the legacy
   sighash **including FindAndDelete**, `Identity = RIPEMD160(SHA256(x))`) over generated raw
   transactions. §4 is a byte-logic shell around just two curve ops; only `ecdsa_verify` + `on_curve`
   are **injected** as pinned pseudo-functions of the bytes (exactly as the fold injects identity), so
   the whole layer stays zero-dep and regenerate-from-seed. `attrib-scenario` also pins
   **FindAndDelete** cross-language with explicit KAT + load-bearing-sighash vectors (it is structurally
   inert on the rigid template, so it would otherwise be omittable), and ships the **§3.9 wallet-preview
   vectors** (`raw tx → {per-input attribution; per-TRADE (give, get) per party}`) the spec mandates as a
   conformance artifact. Real ECDSA verification (the "B" phase) is deferred. See `SPEC-conformance.md` §13.

Plus, on the C reference only: **`make test`** (130 units), **`make cover`** (no blind generator
branches), **`make sanitize`** (UBSan-clean, now incl. `attrib`), and **`attrib-selftest`** (RIPEMD160
/ hash160 / FindAndDelete / DER KATs). See `SPEC-conformance.md` §7–§13 for the frozen
goldens of every mode.

The chain is fully abstracted: identity is injected (`{h160, type, signs-SIGHASH_ALL}`),
time (MTP) and the CLAIM/RENEW rate are injected per block, payments are a
concrete output set. No headers, PoW, scripts, ECDSA, or sockets — see
`SPEC-conformance.md`. §4 ECDSA attribution is out of scope (the live client owns it).

## Porting a new language

Implement the four pinned stages from `SPEC-conformance.md` (PRNG, fold, digest,
generator), mirroring `impls/c` (or the more readable `impls/py`). Add a
`run_<lang>` line to `run-conformance.sh`. Done when the runner shows it matching.
