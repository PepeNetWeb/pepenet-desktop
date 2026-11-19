# namespace headless indexer (C reference)

A headless, P2P-only indexer for the namespace protocol (`protocol/docs/protocol-spec.md`).
It connects to a Dogecoin-family node (Dogecoin or Pepecoin — the pinned host
facts live in `protocol/docs/notes/host-profiles.md`), folds confirmed blocks through the
**protocol reference state machine (`protocol/`, the pinned namespace-protocol submodule) linked as its consensus engine**, and projects the
resulting state into sqlite for querying. No GUI, no wallet; consensus is
confirmation-only — the relay mempool forwards unconfirmed txs but never
touches state.

This is the **canonical on-chain indexer**.

## Design — link the spec, don't re-implement it

```
Dogecoin P2P ─▶ sync.c ─▶ chain.c (block/tx decode) ─▶ adapter.c ─┐
                                                                   │ SmTx
   the ONE new consensus-relevant layer:                          ▼
   adapter.c projects a real tx into the engine's abstract     protocol-sm
   SmTx (decode OP_RETURN carriers §1, attribute vin[0]/AS §4, ── ENGINE ──▶ digest / ECMH
   gather spendable outs §3.5); attrib.c is the real-tx §4.    (fold, linked
                                                                in-place)
                                       │ write-through
                                       ▼
                              db.c  sqlite projection ─▶ resolve / owned / digest
```

The **fold, decoder, oracle, canonical digest and ECMH come straight from
`protocol/impls/c`** (compiled in place — one source of truth, tracks the spec
automatically). The only new consensus-relevant code lives here:

- **`attrib.c`** — §4 attribution for real txs (P2PKH **and** P2SH-multisig),
  porting protocol-sm's exact byte-logic (strict-DER + low-S, canonical pubkey
  encoding, redeemScript template + in-order scan, legacy sighash **with
  FindAndDelete**, SIGHASH_ALL-only) onto a real varint parser.
- **`adapter.c`** — real tx → `SmTx` projection.
- **`chain.c`** — Dogecoin block/tx wire decode (incl. AuxPoW skip).
- **`oracle_feed.c`** — the §3.4 fee-rate + §6 MTP, fed from connected blocks via
  the engine's own pinned `sm_oracle_rate` / `sm_mtp`.
- **`db.c`** — a **lossless** sqlite projection of `SmState` (asserted: a
  save→load round-trip reproduces the canonical digest).

### EC crypto — libsecp256k1, no secret-key math shipped

`protocol/shim/secp_shim.c` re-implements the protocol reference's `secp256k1.h` (ECDSA *verify* + ECMH
point algebra) on the audited vendored **libsecp256k1** (`vendor/secp256k1`). The
self-rolled, non-constant-time field/scalar arithmetic from protocol-sm is **not
compiled** here — so this binary ships zero secret-key curve code (nothing a
wallet could copy and leak with). The shim reproduces the ECMH goldens pinned in
`protocol/SPEC-conformance.md` §13.2 byte-for-byte (verified in `selftest`).

## Build & test

```sh
git submodule update --init --recursive   # protocol (namespace-protocol) + vendor/secp256k1
make            # builds vendored libsecp once, then ./indexerd
make test       # engine-link + shim conformance + end-to-end chain pipeline
```

`make test` asserts, against the reference goldens:
- the linked fold reproduces the reference `sm random 42 2000` state digest,
- the libsecp shim reproduces `empty_state_ecmh` + the ECMH `combined` vector,
- §4 attribution recovers a real signer from a real ECDSA signature,
- a real signed **commit→claim** mints a name end-to-end (parse→attribute→fold),
- the sqlite projection is lossless (digest survives save→load).

## Usage

```sh
# Sync from a Dogecoin-family node (confirmation-only). regtest example:
./indexerd sync regtest names.db 127.0.0.1

# Pepecoin mainnet: the profile pins ACTIVATION_HEIGHT 1,130,000 and bootstraps
# from the checkpoint at height 1,119,000 (11,000 blocks earlier), so the §3.4
# FEE_WINDOW (10,081) is FULL from block 1,129,082 — every rate the fold
# computes is a full-window rate. Peers: a host[:port]
# list, or
# "auto" for peer-cache + DNS seeds. (A trailing activation only seeds a FRESH
# db; a stored value always wins.)
./indexerd sync pep pep.db auto

# Offline: fold raw block files (hex or binary) at a given activation height
./indexerd index names.db <activation_height> block1.bin block2.bin …

# Queries against the projection
./indexerd resolve names.db alice           # → owner hash160 + state
./indexerd owned   names.db <hash160hex>    # → names held by an address
./indexerd digest  names.db                 # → height, live §3.4 rate, state_digest + ECMH
./indexerd refold  names.db                 # → rebuild the fold from local blocks (rule re-pins)

# Chain-wire peer roles
./indexerd crawl   pep names.db             # explore the chain graph, classify peers by agent
./indexerd serve   pep names.db             # serving chain peer (headers + recent blocks, gossip)

./indexerd selftest                         # conformance + pipeline tests
./indexerd ecmh                             # §13.2 ECMH primitive vectors
```

### Wallet UTXO tracking

The sync can track UTXOs for registered addresses (display data, not engine
state) — external wallet tooling reads them from the projection:

```sh
./indexerd  watch pep.db <address>          # register BEFORE funding — utxos are
                                            # recorded from the next synced block
# … fund the address, then:
./indexerd  sync  pep pep.db <peer-ip>      # sync past the funding block
```

Scanning is forward-only from registration (P2PKH only); rows are pruned and
spends un-marked with blocks on reorg. `indexerd resolve <db> <name>` prints
the full projected name record, market fields included, and `indexerd digest`
prints the live §3.4 rate a claim's lease duration is computed from.

After a consensus re-pin, `indexerd refold <db>` rebuilds the fold state from
local data (oracle re-warmed from `blocks`, state replayed from the stored raw
carrier blocks) under the current engine rules — no network round trip.

### Integrity check & crash recovery (idx-03)

```sh
# Read-only consistency check (opens the db SQLITE_OPEN_READONLY; never writes).
# Exit 0 = no errors (warnings allowed), 1 = errors found.
./indexerd check pepe.db [serve-pep.db]
```

Checks: `PRAGMA integrity_check`; schema; meta tip height/hash vs the stored
`blocks` row; block contiguity / hash uniqueness; orphaned rows (blocks,
raw_blocks, epochs, utxos, utxo spends above the tip; raw_blocks without a
block; commits/muts above `proj_height`; utxos of unwatched addresses);
`proj_height` vs the cursor; name blob sizes / state ranges / RESERVED legs;
lease and offer expiry vs MTP (when 11 block times are stored); epoch owner vs
projected owner (warning); and, given a serve db, header hash = sha256d(hdr),
prev-links, no headers above the tip, agreement with the fold's blocks.
A cursor ahead of `proj_height` (a crash gap) is a warning: it is repaired on
the next start.

Recovery: on start, `sync` and `index` call `idx_sync_recover`. If the block
cursor is ahead of the projection (killed mid-batch) — or the projection is
empty (killed before the first batch commit) — the cursor rewinds to the
projection and every height-keyed row above it (blocks, raw_blocks, epochs,
utxos + spend marks, oracle, serve headers) is pruned, then the gap is
re-folded. Tests (`test_sync`) SIGKILL the indexer at every height via the
test-only `IDX_TEST_CRASH_AT=<h>` env var and check that resume equals a clean
fold, including across a simulated reorg.

## Status

Fully working against Pepecoin mainnet: offline `index` + queries + projection;
live-validated P2P `sync` (AuxPoW, SPV-grade PoW validation, checkpoint-anchored);
reorg replay from persisted carrier blocks (byte-identical refold, asserted in
`selftest`); the write path and the full §3 market surface (COMMIT→CLAIM,
SELL→RESERVE→SETTLE, SELL_TO→PAY, RENEW, RELEASE, TRANSFER) exercised end-to-end
on mainnet with digests reproduced byte-exactly by `refold`.

Not yet live-exercised: multi-identity AS/TRADE (§3.9, needs a multisig client).
A reorg deeper than the profile checkpoint stalls safely rather than refolding.
