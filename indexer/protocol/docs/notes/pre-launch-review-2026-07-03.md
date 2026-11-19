# Pre-launch review — state machines + CLI (2026-07-03)

Three-track review (host-chain portability · wallet/CLI money paths · engine↔spec parity)
ahead of wider launch / third-party indexers. All findings below were verified against the
code. Status column: OPEN until fixed.

## RESOLUTION (2026-07-03) — fixed this pass

**Consensus (all three forks closed, cross-validated across all 7 impls + live refold):**
- **A1 FIXED** — adapter now §4-attributes TRADE's `idx_a`/`idx_b` (and any AS-named input) across
  the full input range; every on-chain TRADE folds. Refold of the live pep.db byte-identical.
- **A3 FIXED (full-dynamic, user's choice)** — `SmTx` inputs/carriers/outs are now heap-backed
  with inline defaults at the old caps; the reference harness, adapter, and fold impose NO per-tx
  count cap (SmTx spills to heap). Byte-preserving (every pre-existing digest unchanged), UBSan
  clean. Vector `54_no_txcap` (17 carriers/outs) locks it. The adapter's silent input truncation
  and whole-tx-drop bails are gone.
- **A2 FIXED** — `SM_MAX_PEND_DECOR = 64` pinned as the one protocol structural cap (§0/§1 spec +
  all 7 impls); vector `53_decor_pend_cap` locks 64-of-65. **Bonus:** the boundary vector exposed a
  latent cross-impl fork Finding 5 called unreachable — the DECORATE decode bound was 76 in ALL 6
  ports vs normative C's 80; all 6 independently fixed to 80. Doc §9 corrected.
- Scenario golden re-frozen `db714fa4…` → **`059ac934…`**; full matrix **174 cross-checks, 0 fail**;
  spec §0/§1 + constants table + SPEC-conformance updated; C selftest 145/0.

**Indexer / wallet (money-safety):**
- **B1 FIXED** — projection-height sentinel (`proj_height`) written inside the projection
  transaction; sync startup detects a crash that left sync-height ahead of the projection and
  resumes from the projected height (re-folds the gap) instead of silently skipping blocks.
- **C2 FIXED** — `claim` now refuses when the name is already OWNED or the commit is past
  COMMIT_EXPIRY (the two biggest silent rent-burns).
- **C1 FIXED** — `settle`/`pay` now REFUSE (not warn) when the market window has closed, judged by
  the db's own MTP (median of last 11 block times = the fold's exact gate), not a skewed local
  clock; plus a stale-projection advisory.
- **C3 FIXED** — `vote` argc off-by-one (NULL-deref crash) corrected (`argc < 9`).

**Portability:**
- **D1 FIXED** — subsidy is now a `Coin` profile field (`SUBSIDY_10K` for the doge-family rows),
  set on the oracle feed and pinned per-db (meta `subsidy`) so refold/digest use the same value; a
  chain with a different flat-tail subsidy is now a one-field change, not a source edit. Refold
  byte-identical.

**STILL OPEN (documented below, lower severity — footguns/conveniences, not fund-loss in normal
happy-path use):** B2 (reorg-replay stuck loop), C4 (koinu/decimal confirm prompt), C5 (broadcast
persistence / rapid-command UTXO collision), C6 (sub-dust market legs pre-check), C7 (parse_amt
overflow UB — currently guarded downstream), C8 (salt sidecar fsync/last-match), C9 (transfer
confirm + hex-dest checksum), C10 (index usage string), D2 (consolidate the 3 coin tables), D3
(protocol-version → profile), D4 (block-time constants doc).

## A. Consensus correctness — MUST FIX before any third-party indexer

| # | Finding | Where | Status |
|---|---|---|---|
| A1 | **indexers/c never attributes TRADE's named inputs — every on-chain TRADE drops.** The adapter marks only `vin[0]` + AS-named inputs for §4 attribution (`adapter.c` lazy loop); TRADE's `idx_a`/`idx_b` are never marked, so `trade.c` sees ⊥ and drops. Spec §3.10 says a conformant fold settles it → ownership fork vs a from-spec indexer on the first real TRADE. Latent only because the wallet can't build TRADE yet. Fix: mark trade indices like AS targets (one line) + a live-path regression. | indexers/c/src/adapter.c (attribution loop) | OPEN |
| A2 | **`MAX_PEND 64` DECORATE pending-record cap is C-only.** fold.c silently drops decoration records past 64; py/ts/go/cs (and rust/java) buffer unbounded. One tx with 15 minimal-TLV DECORATE carriers = 375 records → C forks against the other six reference impls. Fuzzer structurally can't reach it (draws ≤ ~24 records). Fix (consensus ruling needed): pin 64 in spec + all impls **or** make C unbounded; either way add a 64/65 boundary vector + re-freeze golden. | protocol-sm/impls/c/src/fold.c:32 | OPEN |
| A3 | **SmTx caps contradict the spec's normative "no per-tx count caps".** `SM_MAX_INPUTS 8 / SM_MAX_CARRIERS 16 / SM_MAX_OUTS 16` exist only in impls/c structs + the adapter; the six ports model txs unbounded. Three inconsistent overflow behaviors today: >16 carriers → whole-tx drop (logged); >16 payee outs on a carrier tx → whole-tx drop (a sloppy SETTLE with many change outs triggers this!); >8 inputs → **silent truncation** (an AS/TRADE index ≥ 8 — spec-valid — reads ⊥ and drops with no trace). A miner-assisted 17-carrier tx forks indexers/c against a from-spec impl. No vector exercises any cap. Fix (consensus ruling needed, cross-impl by prior ruling): pin caps as protocol constants with ONE deterministic rule (recommend: over-cap ⇒ whole-tx not folded), spec §0/§5 rewrite, boundary vectors (16/17 carriers, 16/17 outs, 8/9 inputs incl. AS@8 + TRADE idx 8), golden re-freeze across 7 impls. | protocol-sm sm.h:65-70 · indexers/c/src/adapter.c | OPEN |

## B. Local-state integrity (indexerd)

| # | Finding | Where | Status |
|---|---|---|---|
| B1 | **Sync persistence is not atomic; crash mid-batch silently desyncs projection from block store.** Per-block writes (blocks/raw_blocks/utxos + meta height) autocommit individually; the names/commits/votes/muts projection commits once per inv batch (≤500 blocks). SIGKILL between ⇒ meta height ahead of projection; restart loads stale projection state but resumes at meta height ⇒ the gap's actions are never folded, digest silently diverges, and every wallet guard reasons from wrong state. Also: sqlite step/exec return codes unchecked throughout db.c (disk-full = same desync, no crash); duplicate oracle rows possible on re-connect. `refold` recovers, but nothing detects the need. Fix: one transaction per connected block (or per batch incl. projection + meta), a projection-height sentinel checked at open, error-check db writes. | indexers/c/src/{sync.c,db.c} | OPEN |
| B2 | Deterministically corrupt raw block during reorg replay ⇒ rollback loops forever, projection stays on abandoned branch until manual refold. Low likelihood; document + surface loudly. | sync.c rollback path | OPEN |

## C. Wallet money guards

RETIRED (2026-07-13): the reviewed component was the wallet CLI once bundled with the
indexer repo; it has since been removed (the indexer ships no write path). The findings
here concerned that tool only, not the indexer or the engine, except one that survives it:

| # | Finding | Status |
|---|---|---|
| C10 | Usage-string drift: `indexerd index` usage omits `<db> <activation>` (typed-wrong activation forks a fresh db silently). | OPEN |

## D. Host-chain portability (the reconfiguration question)

**Architecture verdict: good.** One `COINS[]` profile row (magic, port, activation,
checkpoint) + WCoin (address/WIF versions) + host-profiles.md is the right shape; the
engine's money/market constants are MTP-seconds (chain-agnostic); AuxPoW is handled
(version bit 0x100 skip); decode/fold are pure functions of tx bytes.

Gaps to close for "minimal-effort" ports:

| # | Finding | Status |
|---|---|---|
| D1 | **Subsidy is a hardcoded `#define` (flat 10,000), not a profile row** — the one consensus-critical portability leak. A chain with a different tail subsidy forks rates silently. Fix: `subsidy_tail` (+ tail-start height) in the Coin profile, used by oracle_feed; plus a startup validation that the first N post-activation blocks match the pinned subsidy (reject loudly on mismatch). | OPEN |
| D2 | Independent coin tables across consumers can drift; consolidate into one shared profile header. (The indexer itself now has a single COINS[] table in sync.c.) | OPEN |
| D3 | Protocol version 70015 inline in 3 call sites → profile row (fails only on chains with MIN_PEER_PROTO_VERSION > 70015). | OPEN |
| D4 | Block-count constants (FEE_WINDOW 10081, MIN_FEE_SAMPLE 1000, MAX_ANCHOR_AGE 1024; vpost TTL 60480) assume ~1-min blocks — by design these re-pin per host **as a protocol version**, not a runtime knob; document the derivation formulas in host-profiles.md. | OPEN |
| D5 | Cosmetic: relay-dust constant, DEFAULT_PEER — move to profile when convenient. | OPEN |

**Port checklist (Doge-family, same 60 s blocks):** research chain facts (magic, port,
subsidy tail + start, AuxPoW height, address/WIF versions, OP_RETURN standardness ≥80) →
pick ACTIVATION ≥ tail_start + FEE_WINDOW → pin checkpoint at ACTIVATION − FEE_WINDOW − 1
(hash byte-exact) → add profile rows (all tables — D2 makes this one place) → sync + verify
digest/rate sanity → testnet tx round-trip. Non-60 s chains additionally re-pin the D4
constants as a new protocol version.

## Overall verdict

The consensus core (fold semantics, decoder, oracle, preblock lifecycle, digests) is in
excellent shape — constants parity clean, decode matches its pin opcode-by-opcode, dot-charset
handled everywhere including TRADE splitting, zero TODOs. **But it is not "100% go" yet**: two
newly found consensus-grade defects (A1 adapter-TRADE, A2 MAX_PEND) plus the now-fully-scoped
SmTx-caps contradiction (A3) would fork indexers/c against a faithful from-spec implementation
on constructible transactions, and the indexer's non-atomic persistence (B1) plus the wallet's
warn-not-refuse posture (C1/C2) are the realistic money-loss paths for any operator who isn't
us. Every fix is small and local; A2/A3 need a consensus ruling first (cross-impl golden
re-freeze).
