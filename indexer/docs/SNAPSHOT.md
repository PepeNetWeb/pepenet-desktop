# Offline snapshots (idx-01)

Offline CLI tools (idx-01), plus a pinned import (idx-04, below). Nothing
fetches a snapshot; one is applied only through the pinned, fail-closed import.
They change no wire format, consensus rule, on-chain format or rent.

## Format

A snapshot is a directory:

| file       | contents |
|------------|----------|
| `state.db` | `VACUUM INTO` copy of the indexer db (lossless sqlite projection of the fold at its sync height H, plus blocks/raw_blocks/oracle rows) |
| `MANIFEST` | text, one `key value` per line |

```
pepenet-snapshot 1
coin doge
height 6430123
tip <64 hex, internal byte order>
activation 6429500
checkpoint 6418500
state_digest <64 hex>   # canonical §13 SHA-256 state digest
state_ecmh <64 hex>     # §13.2 ECMH multiset hash
```

## Commands

```
indexerd snapshot-export <coin> <db> <outdir>
indexerd snapshot-verify <coin> <snapdir> [headers-file] (--sha256 <hex> | --allow-unpinned)
```

`snapshot-export` opens `<db>` **read-only**, refuses to overwrite an existing
`state.db`, writes the copy, then reloads the fold *from the copy* and records
its digests (so the manifest describes exactly the bytes shipped).

`snapshot-verify` checks, and exits 0 only if all pass:

1. MANIFEST is version 1 and names the same coin.
2. `state.db` sync height and tip equal the manifest.
3. The fold reloaded from `state.db` reproduces `state_digest` and `state_ecmh`.
4. Header walk (`headers-file` = one or more concatenated P2P `headers`
   message bodies, checkpoint+1 … H): each header links to the previous one
   (starting at the profile's pinned checkpoint hash), passes `idx_pow_check2`
   (nBits sanity, scrypt ≤ target, full AuxPoW for merged-mined headers) and the
   per-block Digishield nBits (`idx_pow_next_bits`, anchored on the pinned
   checkpoint bits/times). The walk must end exactly at H with hash = tip.
   Required for PoW profiles (doge, pep); fixture profiles with PoW off only
   check linkage when a file is given.

## What it proves / does not prove

* Proves: the state is the one the manifest commits to, and the tip sits on a
  valid-PoW header chain from the checkpoint. It does **not** prove that chain
  is the most-work chain (compare cumulative work / tip with independent peers)
  or that the fold of those blocks yields that state; for that, `refold` from
  the raw blocks, or compare `state_ecmh` against other indexers at H.
* Median-time-past is not checked in the header walk (block_validate does it
  during sync).

## idx-04: whole-file SHA-256 pin (trust model)

Decision (nowon): **a snapshot is trusted only if the SHA-256 of its
`state.db` — the whole file, byte for byte as shipped — equals a pin obtained
out of band.** The pin is checked before `state.db` or `MANIFEST` is parsed,
opened as sqlite, or applied. The snapshot format (directory, `state.db`,
`MANIFEST` v1) is unchanged; the pin is not stored in the MANIFEST, because a
pin shipped alongside the file would prove nothing.

* `snapshot-export` prints `sha256 <64 hex>  state.db (<n> bytes)`. That is
  the value to publish.
* `snapshot-verify <coin> <snapdir> [headers] (--sha256 <hex> | --allow-unpinned)`
  checks the pin first and prints `REFUSED (pin)` on a mismatch. **idx-05:**
  with no pin (no flag and no compiled default) it refuses with exit 1, the
  same as import. `--allow-unpinned` is for dev use only: it runs the idx-01
  integrity checks and labels the result UNPINNED (untrusted). A pin, if one
  is given, still wins over `--allow-unpinned`. Verify is a diagnostic and
  never applies anything.
* `snapshot-import <coin> <snapdir> <db> [--sha256 <hex>]`, and the library
  call `idx_snapshot_import()`, **fail closed**. They refuse when:
  * no pin is set;
  * the pin is malformed (anything other than exactly 64 hex digits);
  * `<db>` already exists;
  * the file hash does not match;
  * the bytes actually copied do not re-hash to the pin (this closes the
    check-then-copy race);
  * the MANIFEST coin, height, tip or digests disagree with the copy.

  On a refusal nothing is left at `<db>` (the temporary `<db>.snap-tmp` is
  removed) and the caller full-syncs.
* **Node interface (Dane):** `greatdane-node … --snapshot <dir> --snapshot-sha256 <64 hex>`.
  * The pin source is `--snapshot-sha256` if given. Otherwise it is the
    compiled-in per-chain default, `IDX_SNAPSHOT_PIN_PEP` or
    `IDX_SNAPSHOT_PIN_DOGE` in `indexer/src/snapshot.h`. Override either at
    build time with `-DIDX_SNAPSHOT_PIN_PEP=\"<hex>\"`. Both are empty today,
    so with no flag the snapshot is refused.
  * The import runs only on a fresh data directory, before the engine opens
    the db.
  * Any refusal logs `greatdane-node: snapshot REFUSED: <reason> — falling
    back to full sync`, and the node then starts and syncs from the profile
    checkpoint as usual. A refusal never aborts startup.
  * `--snapshot-sha256` without `--snapshot` is ignored, with a log line.
  * The node does not download anything. `<dir>` is a local directory that
    Dane has already fetched.
* **Published snapshots:** there is **no published snapshot URL or filename
  for pep or doge**, and no compiled default pin, as of 2026-10-26. Publishing
  one means: run `snapshot-export` at a chosen height H, then publish the
  printed sha256 through a channel independent of the file host (for example
  embed it in a Dane release), and the directory itself.
* Scope: the pin makes the trust root explicit. It does not by itself prove
  that the state is the fold of the most-work chain; the remarks above still
  apply.
* Tests: `test_snapshot` covers:
  * a match (applied, byte-identical, passes `check`);
  * a single flipped bit;
  * a truncated file;
  * a missing pin;
  * a malformed pin;
  * a wrong pin;
  * a coin mismatch after the pin;
  * no overwrite of an existing db;
  * the flag overriding the default;
  * export printing the hash;
  * the fallback, where a full fold after a refusal reaches the same digests.

  `gd_node_test.sh` covers the node flags: refusals for a mismatch, a missing
  pin, a malformed pin, and a matching pin over a bad state.db. In each case
  the refusal is logged, the node still starts, the file is never applied, and
  no temp file is left behind.

## Tests

`make check` runs `test_snapshot`: synthetic real-scrypt headers at a
regtest-style powLimit (valid chain, broken link, missed target, wrong nBits,
truncated/cut pages, wrong checkpoint) and an end-to-end export → verify on the
regtest fixture with tampered `state.db`, tampered MANIFEST, wrong coin, and
overwrite refusal. All in a mkdtemp'd /tmp dir.

## idx-06: canonical, reproducible export
A plain `VACUUM INTO` keeps the hidden rowids of tables that have no INTEGER
PRIMARY KEY. Those rowids depend on the db's history (INSERT OR REPLACE, the
batch/run order, crash recovery), so two honest builds at the same height gave
different whole-file SHA-256s. On the fixture, only the `meta` rowids differed.
`snapshot-export` now does the following:
1. replays the source schema, in its original order, into a scratch db with
   fixed pragmas (page_size 4096, auto_vacuum 0, UTF-8, the same
   user_version/application_id and journal mode);
2. copies every table in primary-key order (or all-column order where a table
   has no PK);
3. runs `VACUUM INTO` from that scratch db.

The schema, every row and the 100-byte header are unchanged; only the hidden
rowids are renumbered, and nothing reads them. This is not a format change.
`test_snapshot` asserts identical hashes across three divergent builds:
one-shot, block-by-block in two processes, and SIGKILL then resume.
Still NOT canonical: node-local rows. `peers` (gossip) and `watch`/`utxos`
(the wallet watch set) are copied as they are, so the publisher must export
from a node that has none of them. See SNAPSHOT-PUBLISH.md.

## idx-07: node-local tables ship empty
The canonical export writes `peers`, `watch` and `utxos` with their schema
and **zero rows**. They are node-local: the gossip cache and this node's
wallet watch set. None of them feeds state_digest/state_ecmh, the fold or
import. Verify, import, `check` and a later `watch` all work on the empty
tables, and `test_snapshot` covers them. As a result, a db that has synced
peers or a wallet exports the same hash as one that doesn't. A wallet
registered on an imported db records utxos from the next block; there is no
history from before the snapshot.
The pin also depends on the sqlite version; see SQLITE-PIN.md.

## idx-09: sqlite_version in the MANIFEST (informational)

`snapshot-export` appends `sqlite_version <sqlite3_libversion()>` to MANIFEST
(same `key value` line format as the other fields; parsers look keys up by name,
so older readers ignore it). `snapshot-verify` and `snapshot-import` (and so the
node's `--snapshot`) log it: a match, a `WARNING` when it differs from the
linked sqlite, or "no sqlite_version (pre-idx-09 export) — accepted". It never
refuses: the whole-file sha256 pin decides. state.db and its pin are unchanged
by this; the MANIFEST is not pinned.

## Refold guard (idx-10)

`indexerd refold <db>` first checks that every height referenced by
`commits.commit_height`, `epochs.start_height` (owned epochs; lapse epochs with
owner NULL can sit at non-carrier heights and are excluded) and `muts.height`
is present in `raw_blocks`. If any is missing it prints
`refold: REFUSED: N height(s) ... (first: H)`, changes nothing, and exits 1:
a refold would otherwise silently rebuild a SMALLER state. `--force` refolds
anyway and prints a `WARNING (--force)` line. The MANIFEST is written in binary
mode ("wb"), so it has LF line endings on every platform.

Expired commits (commit_time + COMMIT_EXPIRY, plus 7200 s of MTP slack, before
the tip's block time) are excluded as well. They are dead state that a refold
prunes anyway.

## Coin / on-chain prefix for coin-less commands (idx-10)

`index`, `refold`, `digest`, `owned` and `resolve` accept `--coin <doge|pep|testnet|regtest>`.
Before idx-10, a db with no stored `onchain_magic` was folded under pep 'PN'.
On mainnet, the old doge db written by the Sep 1 binary was refolded under
'PN': it lost the DN name `greatdane` and was stamped `onchain_magic=504e`.
The prefix is now chosen in this order:
1. An explicit coin wins. A stored magic that disagrees is refused by
   read-only commands. `refold --coin` replaces it, with a note.
2. Otherwise the stored magic is used. If the db's activation pin identifies a
   coin with a different prefix (the poisoned doge db), the command is refused
   and asks for `--coin`.
3. Otherwise the prefix is inferred from the activation pin, or the first
   stored block = a coin's fold start, when every matching profile agrees.
   This prefix is used but never written to the db.
4. Otherwise the command is refused with a clear error. It never falls back to pep.
To repair the poisoned doge db, run `indexerd refold <doge.db> --coin doge`.
This is not a rule change: 'DN' is the doge spec prefix.

## idx-11: onchain_magic is node-local in snapshots

The canonical export leaves out `meta` row `onchain_magic`. Every other `meta` row
is still exported. `snapshot-import` stamps the importing coin's magic after
every pin and digest check has passed, so an imported db always carries the
right prefix (doge 444e, pep/testnet/regtest 504e). As a result, a db stamped by
idx-10 and an older unstamped db at the same state export the same sha256.

The applied db is therefore the pinned file plus that one row. It is no longer
byte-identical to `state.db`, but its canonical re-export is.

`state_digest` and `state_ecmh` are unchanged. They never covered the magic:
`sm_state_digest` hashes only names, commits and muts; ECMH covers the fold
tables; `SmState.onchain_magic` is marked "not digested". Both are cross-node
values (conformance goldens, the MANIFEST, comparison with other indexers),
so idx-11 does not touch them.

## idx-12: exact refold (expiry pruning and lapses)

The live fold runs `sm_begin_block` → `sm_preblock` on every connected block:
lease lapses and COMMIT_EXPIRY pruning are keyed on that block's MTP. Refold used
to replay only the stored raw (carrier/wallet) blocks, so a commit that expired,
or a lease that lapsed, on a non-carrier block was pruned/lapsed at the next
carrier block — or never, after the last one. That left expired commits in a
refolded db (different `state_digest`/`state_ecmh`/export sha) and lapse epochs
and lapse-stamped `muts` heights off by up to a carrier gap.

`refold` now walks every `blocks` row ≤ the tip: raw rows replay as before; the
rest get the same `sm_begin_block` the live fold gave them, with MTP from the
same `blocks` times the oracle is warmed from. Lapse epochs are recorded at the
exact height. Nothing else is needed from the raw block (a non-carrier block
folds no tx). Live sync, reorg rollback (`idx_sync_rollback`), the rules, the
digests and all formats are unchanged. The refold guard also accepts a `muts`
height that matches a lapse epoch (re-derived without a raw block).
