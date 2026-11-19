# pepenet-mesh

The shared substrate every pepenet overlay links. Not a daemon — a static library
(`libpepenetnet.a`) plus headers under `include/pepenet/`. `pepenet-dns` (and later
other overlays) build on it so the identity root, wire encoding, and crypto
are one implementation, not N.

The organizing idea of the whole family: **the chain settles `name → owner @ height`;
overlays decide what to hang off that owner.** Namespace consensus is **names-only**
(commit/claim/market — no posts/votes in the fold). This lib is the part every
overlay agrees on before it speaks its own carrier.

## Modules

- **`pepenet/view.h`** — read-only namespace ownership. Chain mode reads the headless
  indexer's sqlite projection (`names` + `epochs` history + `proj_height`) over WAL, so
  an overlay runs safely beside a live `indexerd`; test mode loads a static
  `name → owner` table for chainless mesh testing. `sp_view_owner_of(name, height)` is
  exact §4.2 (owner at that height, including lapses) when the DB carries the epochs
  projection, else falls back to the current owner. Invalid §3.1 names short-circuit to
  unowned. Lifted from the vpost carrier's `view.c` — the two must stay behaviorally
  identical on the ownership path.
- **`pepenet/crypto.h`** — the crypto facade + shared name rules.
  `hash160`, ECDSA `sign`/`verify`, pubkey derivation, Base58Check addresses, and
  **`sp_name_valid`** (namespace-protocol §3.1 — DNS label `[a-z0-9-]`, 1–32, no
  lead/trail hyphen, no `--` at positions 3–4). Curve math is the **vendored,
  constant-time libsecp256k1** (via `secp_shim.c`); hashes are protocol-sm's
  byte-locked SHA-256/RIPEMD-160. Nothing here rolls its own field arithmetic.
- **`pepenet/wire.h`** — CompactSize varints + little-endian u32, byte-for-byte the
  encoding the chain and the namespace protocol use, so an overlay message and its
  on-chain escape-hatch form serialize identically.

### Identity model (shared by every overlay)

An owner is the 20-byte `hash160` of a 33-byte compressed secp256k1 pubkey, and the
on-chain `names.owner` blob **is** that hash160. So authenticating any owner-signed
blob (a DNS zone, a key announcement) is two checks:

1. `sp_key_is_owner(pubkey, owner)` — the signer's key hashes to the on-chain owner.
2. `sp_ecdsa_verify(digest, sig, pubkey)` — the signature covers the blob.

Plus, before you treat a string as a name:

3. `sp_name_valid(name, len)` — same reject rules as the fold (no case-folding).

No CA, no extra registry: the chain is the authority, this lib is the check.

### Build pins

| what | where |
|------|--------|
| SHA-256 / RIPEMD-160 / `secp_*` shim | `../namespace-protocol` (live names-only SM) |
| libsecp256k1 | `../namespace-indexer/vendor/secp256k1` + its `build/secp` |

## Build

```sh
make            # libpepenetnet.a + ./net_test
make check      # run the self-test battery (crypto + wire + §3.1 + test view)
./net_test /path/to/pep.db     # add a db to also prove ownership resolution
```

The self-test proves the full trust chain end-to-end against real data: the key in
`~/.pepenet/pep-test2.key` derives to the pubkey whose `hash160` (`c406ee39…`) is
both the payload of its Base58 address **and** the on-chain owner of `pepenet` in
`pep.db`. Name-rule vectors match protocol-sm (`Alice`, `foo.bar`, `xn--…` all fail).

## Consumers link one archive

```
cc myoverlay.c libpepenetnet.a \
   ../pepenet-social/build/secp/lib/libsecp256k1.a -lsqlite3 -o myoverlay
#include <pepenet/view.h>   // -Ipepenet-mesh/include
#include <pepenet/crypto.h>
```

The audited primitives (SHA-256/RIPEMD-160/secp_shim) are compiled **into**
`libpepenetnet.a`, so a consumer adds only the vendored libsecp static lib + sqlite3.
