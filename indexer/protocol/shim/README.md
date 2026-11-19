# shim — the secp_* API on vendored libsecp256k1

`secp_shim.c` re-implements `impls/c/src/secp256k1.h`'s `secp_*` functions on the
audited, constant-time [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1)
library. **Shipping consumers (daemons, wallets) compile THIS file instead of the
self-rolled `impls/c/src/secp256k1.c`** — the self-rolled curve is a verify/test
oracle only and must never touch a real secret key.

It is byte-for-byte compatible with the reference (same ECMH hash-to-curve, same
compressed encodings, pinned by the SPEC-conformance §13.2 goldens), so a consumer
can swap it in without moving any golden.

Not compiled by this repo's own builds (the conformance harness deliberately uses
the self-rolled oracle). A consumer compiles it with the vendored library's include
dir ahead of `impls/c/src` — both trees ship a header literally named
`secp256k1.h`, and this file's `#include <secp256k1.h>` must resolve to the vendor
one. See the `namespace-indexer` Makefile for the -I pattern.
