# Indexer quickstart

## 1. Build and test

```sh
git submodule update --init --recursive   # protocol engine + vendored libsecp
make              # ./indexerd
make test         # selftest vs the reference goldens
make check        # db / sync / codec / serve / net_policy / snapshot suites
make help
```

Needs a C11 compiler, cmake (for libsecp) and libsqlite3 (+ headers).

## 2. Fold a fixture offline (no network)

```sh
D=$(mktemp -d)
./indexerd mkblocks $D                    # two fixture blocks: commit + claim "alice"
./indexerd index $D/f.db 0 $D/blk0.bin $D/blk1.bin
./indexerd resolve $D/f.db alice
./indexerd owned   $D/f.db 587c9bfc87a837a056f716c2f9de891adbc46c90
./indexerd digest  $D/f.db
```

## 3. Sync a real chain

```sh
./indexerd sync pep  ~/pep.db auto       # Pepecoin: DNS seeds + peer cache
./indexerd sync doge ~/doge.db auto      # Dogecoin
```

The db stands on the profile's pinned checkpoint and folds from there. Use a
db path of your own; the desktop node keeps its own under its data dir.

## 4. Query

```sh
./indexerd resolve ~/pep.db somename
./indexerd owned   ~/pep.db <hash160hex>
sh examples/queries.sh ~/pep.db          # raw sqlite reads, see examples/queries.sql
```

Desktop node users can query the same state over loopback JSON
(`/gd/name`, `/gd/owned`; see [API.md](API.md)).

## 5. Snapshots (offline)

```sh
./indexerd snapshot-export pep ~/pep.db /tmp/snap
./indexerd snapshot-verify pep /tmp/snap headers.bin --sha256 <hex printed by export>
# no pin → REFUSED. For dev only: --allow-unpinned (integrity checks, result UNPINNED)
./indexerd snapshot-import pep /tmp/snap /tmp/new.db --sha256 <hex>   # refuses on any mismatch
./indexerd check ~/pep.db                     # read-only consistency check
```

See [SNAPSHOT.md](SNAPSHOT.md).
