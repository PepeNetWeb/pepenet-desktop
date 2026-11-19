# Strategy B — real-crypto attribution conformance (handoff plan)

**Status:** ✅ SHIPPED 2026-06-30. All 7 impls (c · py · ts · java · rust · go · cs) carry a self-rolled,
zero-dependency secp256k1 + RFC-6979, exposed as `sm attrib-curve` (the pinned ECDSA curve-vector set)
with byte-identical cross-language output. Frozen goldens: `combined = 5b7d1e765c7a213bab6825abf1fb75fc6c9fa0771c7b58484cc0d2a3b2bf7113`,
`combined_e2e = c24c560202f6a8cf6a154ce54cdfe80ee32dc440d1c9594124c7939c62d54a14`. `run-conformance.sh`
asserts it; pinned in `SPEC-conformance.md §13.1` + `SPEC-RATIONALE.md §11` + `impls/c/README.md`. The C
selftest is now 131 checks (real-curve KATs folded in) and UBSan-clean over the curve. **Deviation from the
brief:** the injected oracle was NOT removed in-place — instead a run-time `real_curve` toggle (§3/§5 seam)
keeps `attrib`/`attrib-scenario` on the injected oracle so their frozen goldens (9fb14077/7b41f20b) stay
byte-identical, while the real curve runs as the new `attrib-curve` mode (the normative curve-vector
artifact, §9). The full-blown real-attrib SOAK (deliverable 4 — embedding RFC-6979 sigs into the seed
fuzzer end-to-end) was scoped out in favor of the directed `combined_e2e` end-to-end vectors, which pin the
same sighash→verify linkage cross-language; it remains a possible future extension. Original brief preserved
below for the record.

---

**Original status (when written):** deferred / not started. This is a self-contained brief for a fresh
agent. Read it top to bottom before touching code.

**One-line goal:** replace the *injected* curve oracle in the §4 attribution harness with **real
secp256k1 + RFC-6979** in all seven `protocol-sm` impls, and add a **pinned ECDSA curve-vector set**,
so the attribution layer is conformance-tested end to end (signature actually verifies → identity is
actually derived) rather than only at the byte-logic level.

---

## 0. Standing constraints (do not violate)

- **`impls/c` is normative.** Where prose is ambiguous, `impls/c` is the tie-breaker. Do not "fix" the
  other impls to disagree with it; if you believe C is wrong, write it up and stop — don't silently
  diverge.
- **You may NOT launch clean-room *audit* agents.** The repo owner runs those personally. You *may*
  spawn agents for mechanical porting, sweeps, and verification — those are not audits.
- **Do not touch the live client** (`src/` at repo root). This plan is about `protocol-sm/` only. The
  client's `src/attribution.c` is P2PKH-only and out of scope.
- **Preserve Tier 1 goldens.** The frozen C seed-soak goldens (scenario `7b41f20b…`, attrib-scenario
  `9fb14077…`) must not move unless you are *deliberately* re-freezing them and say so explicitly. Run
  `./run-conformance.sh` before and after; it must stay green (currently 26 reference checks, 0 fail).

---

## 1. Where things stand (Strategy A, already shipped)

§4 *Stateless Identity & Attribution* is "`raw tx hex → {Identity} | drop`". Strategy A built the entire
**byte-logic shell** for real, in all 7 impls, folded into each `sm` binary as two modes:

- `sm attrib <seed> <count>` — seed-driven differential fuzzer over generated raw txs.
- `sm attrib-scenario` — RIPEMD-160 KATs + fixed vectors + FindAndDelete KATs + §3.10 wallet-preview
  vectors + the A7 off-curve-P2PKH lock. Combined golden `9fb14077…` (C; the soak ports intentionally
  diverge here per the "ignore the other implementations" rule that applied during the audits — that
  rule is **lifted** for this task, see §5).

Everything up to the curve is **real and pinned**: strict-DER parsing, low-S (32-byte BE compare vs
N/2), pubkey canonical *encoding* (length/prefix/coordinate < p), the P2SH-multisig template
(minimal OP_m/OP_n, PUSHDATA1-aware minimal push, NULLDUMMY, ≤15 compressed keys), the in-order
signature scan, the legacy sighash preimage **including FindAndDelete**, SIGHASH_ALL enforcement,
per-input `AS`, and `Identity = RIPEMD160(SHA256(x))`.

**The only thing faked is the curve.** In `impls/c/src/attrib.c` it's two injected pseudo-functions:

```c
// on-curve iff SHA256(0x4F ‖ pubkey)[0] != 0          (≈ 255/256 true)
static int inj_on_curve(const uint8_t *pub, int plen);
// verify  iff SHA256(0x56 ‖ hash32 ‖ r32 ‖ s32 ‖ pubkey)[0] >= 0x20   (≈ 87.5% true)
static int inj_ecdsa_verify(...);
```

Each impl has the identical pair (same byte-pseudo definition) so the injected stream is cross-language
deterministic. **That is the seam Strategy B replaces.**

§4 = a byte-logic shell around **exactly two curve operations**:
`on_curve(pubkey)` and `ecdsa_verify(hash32, sig, pubkey) → bool`. Nothing else needs the curve.

---

## 2. What Strategy B adds (the two halves)

### Half A — real curve binding in all 7 impls

Swap `inj_on_curve` / `inj_ecdsa_verify` for real secp256k1. Per language:

| impl | binding (preferred) | notes |
|------|--------------------|-------|
| c      | vendored libsecp256k1, OR a self-rolled minimal Jacobian impl | C reference must stay zero-mandatory-dep; if libsecp256k1 is vendored, gate it so `make` still works without it (see §5 dual-mode) |
| rust   | self-rolled in `std`, OR a single pinned crate | repo rule so far is **zero external crates** — prefer self-rolled to preserve that |
| go     | `crypto/elliptic` has no secp256k1; self-roll, or `decred/dcrec/secp256k1` | stdlib-only is the current rule — self-roll to keep it |
| python | self-roll (it's ~120 lines), or `coincurve` | user runs py directly; keep dependency-free |
| ts     | self-roll, or `@noble/secp256k1` | |
| java   | self-roll, or BouncyCastle | source-launch, no build — self-roll fits that |
| csharp | self-roll, or BCL `System.Security.Cryptography` (no secp256k1 curve param built in) | BCL-only rule — self-roll |

**Recommendation:** self-roll a minimal, *non-constant-time* (this is a verifier, not a signer of
secret keys — timing is irrelevant) secp256k1 in each language. It's small: field arithmetic mod
`p = 2²⁵⁶ − 2³² − 977`, point add/double in Jacobian coords, scalar mul, and ECDSA verify. Avoiding a
binding per language keeps the "zero external deps" property that makes this suite easy to run, and
sidesteps cross-language binding-version skew. A pinned external crate/lib is acceptable only if you
document why and gate it.

> **Constant `SECP_P` gotcha (already bit us once):** the field prime is `2²⁵⁶ − 2³² − 977`, i.e. the
> top word ends `…FFFFFC2F`. An earlier attempt dropped the `2³²` term (`FE` byte) and used
> `2²⁵⁶ − 977`. Pin `SECP_P`, `SECP_N` (group order), and `SECP_N_HALF` as KAT-checked constants and
> assert them in a unit test.

### Half B — the pinned ECDSA curve-vector set + RFC-6979 signing oracle

The accept path can't be seed-regenerated by the byte shell alone, because producing a signature that
*verifies* requires the private key + the curve. So Strategy B has two sub-parts:

1. **RFC-6979 deterministic signing oracle.** Keyed from the SplitMix64 seed, derive `(privkey, msg32)`
   deterministically, sign with **RFC-6979** (deterministic nonce — no randomness, so cross-language
   reproducible), DER-encode, low-S-normalize, and embed the real signature into the fuzzer's generated
   txs. Now `sm attrib <seed> <count>` exercises the **real accept path**: parse → sighash (+FaD) →
   real `ecdsa_verify` → real identity, end to end, and all 7 impls must agree on the resulting digest.

2. **Pinned ECDSA curve-vector set** — a few hundred `(msg32, r, s, pubkey, expect_valid)` triples at
   curve edges, each impl runs against its own curve code asserting the accept/reject bit:
   - low-S boundary (`s == N/2`, `s == N/2 + 1`)
   - `r == 0`, `s == 0`, `r == N`, `s == N`, `r > N`, `s > N`
   - point at infinity, off-curve pubkey, on-curve pubkey
   - compressed / uncompressed / hybrid encodings (note: §4's canonical-encoding rule may already
     reject some of these *before* the curve — pin which layer rejects each)
   - a batch of RFC-6979 known-answer signatures (msg, privkey → expected r,s) cross-checked vs a
     reference (Python `ecdsa`/`coincurve`, or test vectors from the RFC / Bitcoin Core).

These vectors are the irreducible, hand-pinned core — they're what makes "the curve is real" a
*checkable* claim rather than a trust-me.

---

## 3. Architecture — keep the byte shell untouched

The shell already isolates the seam. The change is local:

```
attribute(tx, input_index):
    ... real byte logic: DER parse, low-S, template match, in-order scan, sighash+FaD ...
    if !on_curve(pubkey):        -> status ON_CURVE_DROP        # was inj_on_curve
    if !ecdsa_verify(h, sig, pk): -> status VERIFY_FAIL          # was inj_ecdsa_verify
    identity = ripemd160(sha256(x))
```

Replace the two `inj_*` calls with the real implementations. **The status taxonomy, the digest layout,
and every other byte-path stay byte-for-byte identical.** Do this behind a compile/run flag at first
(§5) so you can diff the real-curve stream against the injected stream on the *reject-dominant* corpus
and confirm only the genuinely-different verdicts changed.

The §5 fold is untouched — it already consumes `{h160, type, SIGHASH_ALL}` which §4 emits. An
end-to-end "§4 feeds §5" mode is explicitly **not** part of this MVP.

---

## 4. Deliverables & acceptance criteria

1. Real secp256k1 (`on_curve` + `ecdsa_verify`) in all 7 impls, with KAT-pinned `SECP_P/N/N_HALF`.
2. RFC-6979 signing oracle in all 7 impls, cross-language byte-identical DER output (KAT-checked).
3. A new pinned curve-vector set (shared corpus, e.g. `attrib-curve` mode or a vectors file all impls
   read) with the edge cases in §2 Half B; every impl agrees on every accept/reject bit.
4. `sm attrib <seed> <count>` now drives the **real** pipeline (real signatures embedded), with a fresh
   frozen golden for the real-curve stream (C-pinned, the other impls cross-validate per §6 below).
5. `run-conformance.sh` wired to run the curve vectors across all impls and the real-attrib soak on C.
6. `SPEC-conformance.md §13` and `SPEC-RATIONALE.md §11` updated: the "injected oracle / Strategy B
   deferred" disclosure becomes "real curve, conformance-tested" with the vector set named as the
   normative artifact. **`impls/c/README.md` §"Real-crypto attribution" must be updated too** (it
   currently says Strategy B is deferred).
7. Acceptance: `./run-conformance.sh` green; the curve-vector accept/reject bits agree across all 7;
   RFC-6979 DER KATs agree; the C real-attrib golden is reproduced by the C build deterministically;
   UBSan (`make sanitize`) clean over the new curve code in C.

---

## 5. Build hygiene for the C reference (important)

`impls/c` currently builds with `make` and **zero mandatory deps**. Two acceptable approaches; pick one
and document it:

- **Self-rolled curve (preferred):** stays zero-dep, no Makefile change beyond a new `secp256k1.c`.
- **Vendored libsecp256k1:** must be optional. Provide a `USE_LIBSECP=1` path; default build self-rolls
  or keeps the injected oracle so `make test` never *requires* the vendored lib. Don't make the
  normative reference un-buildable on a bare toolchain.

Keep the injected oracle reachable behind a flag during development so you can A/B the streams; you may
retire it once the real path is locked, but only after the real-curve golden is frozen.

---

## 6. Cross-language conformance model (note the lifted rule)

During the clean-room audits there was a standing "ignore the other implementations" rule, which is why
the A7 lock and a few late attrib-scenario changes were C-only and the soak ports diverge on
attrib-scenario. **For Strategy B that rule is lifted** — the whole point is cross-language agreement on
the real curve. So:

- The **curve-vector accept/reject bits** are prose/vector-pinned (Tier 2 style): all 7 impls must
  agree. This is the strongest evidence the curve layer is right.
- The **real-attrib soak golden** is C-pinned (Tier 1 style, C self-regression). Other impls have their
  own generators and won't reproduce it byte-for-byte — that's fine and expected; they prove themselves
  via the shared curve vectors, not the soak digest.
- RFC-6979 DER encoding **must** be byte-identical across impls (it's deterministic) — KAT it.

---

## 7. Known gotchas (learned the hard way)

- **`SECP_P` term:** `2²⁵⁶ − 2³² − 977`, not `2²⁵⁶ − 977`. KAT it.
- **`ripemd160("abc")` = `…f15a0bfc`**, not the widely-miscited `…0bff`. Verify against openssl +
  python before trusting any RIPEMD-160 you write.
- **Low-S is a 32-byte big-endian compare vs `N/2`**, applied to the *value* of S — and R/S are fed to
  the curve as the 32-byte BE of the DER integer's value (strip a leading `0x00` sign byte, then
  left-pad). This is already pinned (`SPEC-RATIONALE.md`, ex-finding F4/E1) — match it.
- **FindAndDelete is structurally inert** on the rigid compressed-key template (a `0x21` key push never
  collides with a `0x47/0x48` sig push at a boundary), so a port can pass every existing digest while
  *omitting* FaD entirely. The `fad02` vs `fad03` KATs exist specifically to catch that — keep them and
  make sure your real-curve work doesn't quietly drop FaD from the sighash.
- **RFC-6979 nonce derivation** is the cross-language fork risk in Half B. Pin it with KATs from the RFC
  (or Bitcoin Core's test vectors) before generating any signing corpus.
- **Encoding rejection layering:** some "invalid pubkey" cases are rejected by §4's canonical-encoding
  check *before* `on_curve` ever runs. When you pin a curve vector, pin *which layer* rejects it, or
  impls will disagree on the status code while agreeing on accept/reject.

---

## 8. Suggested sequencing

1. Self-roll + KAT-pin secp256k1 (`on_curve`, `ecdsa_verify`, RFC-6979 sign) in **C first** (it's
   normative). Assert `SECP_P/N/N_HALF`. Add `sm attrib-curve` running the edge vectors. UBSan it.
2. Wire C's real curve behind a flag; A/B the injected vs real stream on the existing corpus; confirm
   only genuine accept-path verdicts change. Freeze the C real-attrib golden.
3. Port the curve + RFC-6979 + `attrib-curve` to the other 6 impls (mechanical-port agents OK). Get all
   7 agreeing on the curve vectors and RFC-6979 DER KATs.
4. Wire `run-conformance.sh` (curve vectors across all impls + real-attrib soak on C). Green run.
5. Update the docs (§4 deliverable 6) and refresh memory `protocol-sm-sec4-harness.md`.

---

## 9. Pointers

- Injected oracle to replace: `protocol-sm/impls/c/src/attrib.c` (`inj_on_curve` / `inj_ecdsa_verify`,
  ~lines 36–50; call sites ~295–296).
- Spec: `docs/protocol-spec.md` §4 (~lines 949–1107); pinned points in
  `protocol-sm/SPEC-conformance.md §13` and `protocol-sm/SPEC-RATIONALE.md §11`.
- The live client's real-crypto wrapper (reference only, do **not** modify): repo-root
  `src/crypto/ecdsa.c` wraps libsecp256k1; `SECP_P` / `SECP_N_HALF` live in `src/protocol.c`. Verify
  line numbers before relying — code drifts.
- Conformance statement for §4: "defined by the shipped test-vector set, not prose (raw tx hex →
  {Identity} or drop) … including FindAndDelete application." Strategy B makes that vector set include
  the curve.
