# Indexer API

The indexer offers three read surfaces: the CLI, the sqlite projection, and
(in the desktop node) a loopback JSON API. None of them write chain data.

## CLI (`./indexerd <command>`)

| command | what it does |
|---|---|
| `selftest` | engine-link + libsecp shim conformance against the reference goldens |
| `ecmh` | print the §13.2 ECMH primitive vectors |
| `sync <coin> <db> [peers\|auto] [activation]` | P2P sync + fold (confirmed blocks only). coin ∈ doge, pep, testnet, regtest |
| `crawl <coin> <db> [max_dials] [host:port,...]` | explore peers, classify them by agent |
| `serve <coin> <db> [port] [host:port,...]` | act as a chain peer (headers/blocks, gossip) |
| `resolve <db> <name>` | current owner hash160 + lease/market fields of a name |
| `owned <db> <hash160hex>` | names owned by a hash160 |
| `digest <db>` | height, live §3.4 rate, `state_digest`, `state_ecmh` |
| `refold <db>` | rebuild the fold from local raw blocks under current rules |
| `watch <db> <addr\|h160>` | register a wallet address for UTXO tracking |
| `index <db> <activation> <blockfile>...` | fold raw block files offline (heights from 0) |
| `mkblocks <dir>` | write the two test fixture blocks |
| `weigh <coin> <headers-file>` | dev: validate + weigh a `headers` body off the checkpoint |
| `snapshot-export <coin> <db> <outdir>` | offline snapshot (state.db + MANIFEST); see SNAPSHOT.md |
| `snapshot-verify <coin> <snapdir> [headers] (--sha256 <hex> \| --allow-unpinned)` | whole-file sha256 pin gate (no pin → refused unless `--allow-unpinned`, dev only), then recheck snapshot digests + header PoW |
| `snapshot-import <coin> <snapdir> <db> [--sha256 <hex>]` | apply a pinned snapshot as a fresh db; fail closed (exit 1 = refused → full sync) |
| `check <db> [serve-db]` | read-only integrity/consistency check (exit 1 on errors) |

Exit codes: 0 ok, 1 runtime failure, 2 usage error.

## sqlite projection

`idx_db_project` keeps a lossless projection of the fold in the db. You can
read it with any sqlite client. Open it read-only (`file:…?mode=ro`) while
`sync` is running.

| table | key columns |
|---|---|
| `names` | `name` TEXT PK, `owner` BLOB(20), `owner_type`, `lease_expiry`, `st` (state), market fields `seller`, `price`, `offer_expiry`, `buyer`, `burn_leg`, `pay_leg`, `reserve_expiry` |
| `blocks` | `height` PK, `hash`, `time`, `bits`, `coinbase`, `bytes` |
| `raw_blocks` | carrier-bearing raw blocks (refold / reorg substrate) |
| `commits` | pending commitments |

Names are `[a-z0-9-]`, 1..32 bytes, stored without the TLD. Hashes are stored
in internal (little-endian) byte order. See `examples/queries.sql`.

## Desktop node JSON (`greatdane-node --dane-api`)

These endpoints are served on the node's PAC/proxy port (the `"pac"` port in the
`ready` event). They are **loopback only**: other peers get 403, and when
`--dane-api` is off the endpoints do not exist. The db is opened read-only for
each request. All responses are `application/json` with `Cache-Control: no-store`.

### `GET /gd/name?n=<name>`

`n` may carry the chain TLD (`gm.pepe`). It is lowercased and then validated.

```json
{"name":"gm","tld":"pepe","status":"ok","owner":"<40 hex>","state":1}
{"name":"gm","tld":"pepe","status":"unowned"}
```

### `GET /gd/owned?h160=<40 hex>`

```json
{"h160":"…","tld":"pepe","status":"ok",
 "names":[{"name":"gm","lease_expiry":1792213564,"state":1}],
 "count":1,"truncated":false}
```

The list holds at most 64 names and 4096 bytes. When it is cut off,
`truncated` is true.

### `GET /gd/names?prefix=<p>&offset=<N>&limit=<M>`

Lists names for discovery pages. Parameters can come in any order and all are optional.

- `prefix`: `[a-z0-9-]`, 0–32 characters. It is lowercased, and the TLD is not stripped. Empty means all names.
- `offset`: 0–10000000, default 0.
- `limit`: 1–100, default 20.

Names are sorted by name in byte order, so pages stay stable. The prefix range (`name >= p AND name < p+1`) and the count are both served by the `names` primary-key index, with no table scan and no sort. Note that `OFFSET` still costs O(offset).

```json
{"tld":"pepe","status":"ok","prefix":"gm","names":[
  {"name":"gm","owner_h160":"<40 hex>","lease_expiry":1792213564,"state":1,"price":0},
  {"name":"gmx","owner_h160":null,"lease_expiry":0,"state":0,"price":0}],
 "total":2,"offset":0,"limit":20,"count":2,"truncated":false}
```

`total` counts every row that matches the prefix. The body is capped at 20 KiB, and `truncated` is true if rows were cut off. Rows with non-canonical names are skipped. A bad parameter returns 400 with `status` set to `bad_prefix`, `bad_offset` or `bad_limit`.

| HTTP | `error` | when |
|---|---|---|
| 400 | `bad_name` / `bad_h160` / `bad_request` | invalid input or unknown `/gd/` path |
| 403 | — | the peer is not loopback |
| 503 | `no_db` | the fold db is not available yet |

```sh
curl -s "http://127.0.0.1:$PAC/gd/name?n=gm.pepe"
curl -s "http://127.0.0.1:$PAC/gd/owned?h160=$H160"
curl -s "http://127.0.0.1:$PAC/gd/names?prefix=&offset=40&limit=20"
```
