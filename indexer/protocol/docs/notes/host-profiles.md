# Host-chain profiles

The protocol (`docs/protocol-spec.md`) is written against an abstract Dogecoin-family host: a
scrypt/AuxPoW chain with legacy (pre-SegWit) transactions, 80-byte `OP_RETURN` standardness, and a
per-height consensus subsidy the fee oracle (§3.4) reads. Everything the fold consumes from the host
is injected — the engine itself is chain-agnostic. A **host-chain profile** is the set of host facts
a deployment must pin exactly; two indexers disagreeing on any *consensus-tagged* row fork the state.

Each deployment = one profile + one pinned `ACTIVATION_HEIGHT`. The same protocol may run on several
hosts at once; the namespaces are fully independent (a name owned on Pepecoin says nothing on
Dogecoin).

## Profile rows

| Row | Consensus? | Used by |
|---|---|---|
| `subsidy(height)` | **yes** — feeds §3.4 `feesᵢ`; an inexact reading forks the rate | `oracle_feed.c` |
| `block_bytes` definition | **yes** — Σ `len(raw_tx)`, header + tx-count varint + AuxPoW excluded (§3.4) | `chain.c` parse |
| `ACTIVATION_HEIGHT` | **yes** — the fold's genesis; MUST be ≥ `600 000 + FEE_WINDOW` so the whole reachable window is flat-subsidy | pinned per deployment, stored in the indexer DB |
| block cadence | **yes**, indirectly — all block-count constants (`FEE_WINDOW 10081`, vpost `TTL 60480` = 42 d) assume ~1-min blocks | spec constants |
| sync-start checkpoint `(height, hash)` | **yes** — every indexer replays from the same pinned block or their §3.4 oracle windows (and thus rates) diverge; `ACTIVATION_HEIGHT` MUST be ≥ `start + FEE_WINDOW + 1` so the window is fully populated at activation | `sync.c` `COINS[]` |
| network magic, P2P port | no (transport) | `sync.c` `COINS[]` |
| protocol version | no (handshake; any version ≥ the host's `MIN_PEER_PROTO_VERSION` works) | `sync.c` |
| AuxPoW | no (parse: version bit `0x100` ⇒ skip the aux proof) | `chain.c` |
| address version bytes | no (display only — the indexer works on raw script templates / naked hash160) | clients |

## Dogecoin mainnet (`doge`)

All values verified against `dogecoin/dogecoin` `src/chainparams.cpp` + `src/dogecoin.cpp`.

| Fact | Value |
|---|---|
| subsidy(height) | **flat `10 000 × COIN` for height ≥ 600 000** (= `6 × nSubsidyHalvingInterval`, interval 100 000; earlier eras are random/halving rewards and are unreachable by a conforming deployment) |
| coin unit | `COIN = 100 000 000` koinu (= `KOINU_PER_DOGE`) |
| block cadence | 60 s target |
| network magic | `C0 C0 C0 C0` |
| P2P port | 22556 |
| genesis | `1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691` |
| sync-start checkpoint | genesis (height 0) — re-pin near the deployment's activation before launch |
| AuxPoW | chain ID `0x0062`, from block 371 337 |
| address versions | P2PKH 30 (`D…`), P2SH 22, WIF 158 |
| `ACTIVATION_HEIGHT` | **not yet pinned** (Pepecoin deployment proves the network first) |

Testnet (`testnet`): magic `FC C1 B7 DC`, port 44556, genesis `bb0a7826…50559e`.
Regtest (`regtest`): magic `FA BF B5 DA`, port 18444, genesis `3d2160a3…e973a5`.

## Pepecoin mainnet (`pep`)

Pepecoin is a Dogecoin 1.14 fork. All values verified against `pepecoinppc/pepecoin`
`src/chainparams.cpp`, `src/pepecoin.cpp`, `src/version.h` (2026-07-01).

| Fact | Value |
|---|---|
| subsidy(height) | **flat `10 000 × COIN` for height ≥ 600 000** (= `6 × nSubsidyHalvingInterval`, interval 100 000 — same shape *and* same tail value as Dogecoin; pre-600 000: random rewards, then `500 000 >> halvings`) |
| coin unit | `COIN = 100 000 000` (same base unit; `KOINU_PER_DOGE` reads as "koinu per host coin") |
| block cadence | 60 s target (`nPowTargetSpacing = 60`) — every block-count constant carries over unchanged |
| network magic | `C0 A0 F0 E0` |
| P2P port | 33874 |
| DNS seeds | `seeds.pepecoin.org`, `seeds.pepeblocks.com` |
| protocol version | `PROTOCOL_VERSION 70016`, `MIN_PEER_PROTO_VERSION 70003` (our 70015 handshake is accepted) |
| genesis | `37981c0c48b8d48965376c8a42ece9a0838daadb93ff975cb091f57f8c2a5faa` |
| sync-start checkpoint | **height 989 918 = `922615fcc2a726bf58cfd42de7de7db187bea62c6689807afde3515138bc2f19`** — the deployment's replay origin, pinned at exactly `ACTIVATION_HEIGHT − FEE_WINDOW − 1` so the §3.4 oracle window is fully populated from the very first activated block; verified live by hash-linking (the sync re-derives block 1 000 000 = `73c1ff0a…aa686a` and continues to the network tip) |
| AuxPoW | chain ID `0x003f`, strict, from block 42 000 (legacy blocks 0–41 999) |
| standardness | Dogecoin-1.14 rules ⇒ same 80-byte `OP_RETURN` carrier |
| address versions | P2PKH 56 (`P…`), P2SH 22, WIF 158 |
| BIP34/65/66 | all from block 1 000 |
| `ACTIVATION_HEIGHT` | **1 000 000 — pinned 2026-07-02, pre-activated** (the height is already past; the deployment indexes every eligible block from activation onward, including the organic UTF-8 text posts already on the chain). Deep inside the flat-subsidy era: 1 000 000 ≫ `600 000 + FEE_WINDOW`, and `= start + FEE_WINDOW + 1` exactly |

**Why the profile is this small:** the two consensus-critical host facts — block cadence and tail
subsidy — are byte-identical between Pepecoin and Dogecoin, so the §3.4 oracle math, `FEE_WINDOW`,
and every wall-clock constant (lease quanta, vpost TTL) carry over with no engine change. The
Pepecoin deployment differs from a Dogecoin one only in transport facts (magic, port, seeds,
genesis) and client-side address rendering.
