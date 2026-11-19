# pepenet-dns

DNS over the **pepenet namespace**. A flat, dotless pepenet name (`pepenet`) is a
DNS zone; the on-chain owner of that name is the only party who can sign its
records. Names resolve under a hostchain suffix — `pepenet.pepe` on Pepecoin,
`…​.doge` on Dogecoin.

**A DNS zone is anchor-ordered per-key LWW state** (pepenet-mesh `sp_state`).
Each resource record is one signed op — key = `label ‖ type`, payload =
`ttl ‖ rdata` — **signed over a recent block-header hash**; the highest anchor
wins per `(label,type)`, so ordering needs no wallet-side counter and the block
cadence rate-limits edits (one per record per block). A `del` leaves the signed
tombstone that outranks every replay; a `clear` voids the whole zone below its
anchor (the per-name floor). **8 KB of held ops per name** (`DNS_BUDGET`),
freed on supersession — editing can never brick a zone. There is **no store
TTL**: a record lives until superseded, cleared, or its name's lease lapses on
chain (the daily sweep). The record's own `ttl` field is what it always meant
in DNS — the resolver-cache TTL served in answers.

- **`dns_state.c`** — key/payload packing, publish (PUT/DEL/CLEAR), zone
  assembly, gossip digest, the expiry sweep, and the on-chain `0xD8` carrier.
- **`dns_chain.c`** — the chain oracle over the indexer db: lease-gated
  ownership, header-hash-at-height (anchor verification), sync tip.
- **`dns_net.c`** — zone gossip (`dnzinv`/`dnzget`/`dnzdat`): the sync unit is
  the NAME (a whole zone fits one frame under the budget), digests drive pulls,
  a small hold queue parks ops anchored ahead of our sync.
- **`dnsd.c`** — the node: mesh thread + UDP/TCP DNS resolver + startup zone publish.
- **`dns_wire.c`** — RFC 1035 codec (A/AAAA/CNAME/MX/TXT/SRV/TLSA/SSHFP/…) with
  EDNS0 (RFC 6891) and TCP-fallback truncation (RFC 7766).

Crypto / wire / ownership / **§3.1 name rules** come from `../pepenet-mesh`
(`libpepenetnet.a`). The zone **apex** is a pepenet name — validated with
`sp_name_valid` on publish, admit, fold, `--name`, and the resolver. Subdomain
labels (e.g. `_443._tcp`) are ordinary DNS labels and are **not** gated by §3.1.

## Two forms, one record

| | wrapper | auth | limit |
|---|---|---|---|
| off-chain (gossip) | `sp_state` op (anchor-signed) | in-band 64-B sig (owner or §2.2 hot key) | 8 KB/name budget |
| on-chain (escape hatch) | bare OP_RETURN (`0xFF 'P' 'N' 0xD8`) | tx from owner addr | ≤ 80 B (relay) |

Same record, one ordering axis: an on-chain record's anchor is its inclusion
height. The 80-byte relay limit is why each op is one record; big
key/cert blobs (DKIM RSA, OPENPGPKEY) exceed it and simply gossip off-chain. We
build no escape/commitment tooling — the format keeps the door open, nothing more.

## The node is a chain peer

`dnsd` speaks the host chain's P2P protocol on the chain port; the DNS mesh rides
that **same wire** as extra `dn*` commands (peer-discovery slice 3) — there is no
separate mesh port. A node is discovered like any chain peer (getaddr crawl), and
its `/pepenet-dnsd/` subver marks it dns-aware, so a peer knows to speak `dn*` to
it. Three threads run in-process: a **sync** thread (`indexer_main("sync")`, keeps
the ownership db + the last-288-block serve window fresh — `--no-sync` if an
external indexer feeds the db), a **net** thread (`idx_serve` + `dns_net`: listen
as a public seed and/or dial peers, carry zone gossip over every `/pepenet-`
connection), and the **DNS resolver** thread. This is the same composition the
`pepenet-desktop` app embeds (one protocol pin, mesh compiled from source).

## Build

**Windows**: the sources are POSIX; `compat/win/` carries the header shims
(`arpa/inet.h`, `netdb.h`, `poll.h`, …) that map them onto Winsock. Compile every
translation unit with `-Icompat/win`, add `compat/win_compat.c` to the build, and
link `ws2_32`. `WSAStartup` runs lazily inside the shimmed `socket()` /
`getaddrinfo()` — no `main()` changes needed. (This is the same layer the
desktop app's Windows build uses; it also covers the `../pepenet-mesh` and
`../namespace-indexer` sources this build pulls in.)


```sh
make dnsd          # the daemon (embeds ../namespace-indexer sync engine + ../pepenet-mesh sp_state)
make check         # codec + LWW admission + gossip framing proof (state_dns_test)
```

## Run — two nodes gossiping a zone over the chain wire

`--listen` is the node's **chain serve port**; `--peer` is a **chain peer to dial**
(repeatable). On pep, omitting `--peer` dials the two public overlay seeds
(`pepenet.shibpost.com:33874` and `net.pepecoin.services:33874`); on doge,
`pepenet.shibpost.com:22556`. An explicit `--peer` replaces that default.
The two nodes handshake as chain peers and zones gossip over that connection.
(`--no-sync` here because the demo runs off the already-synced `pep.db`, not the
live network.)

```sh
DB=../namespace-indexer/pep.db

# Node A: the owner, publishes a zone; chain :6001, DNS :5301
./dnsd --db $DB --store /tmp/a.db --listen 6001 --dns-port 5301 --no-sync \
       --key ~/.pepenet/pep-test2.key --name pepenet --zone zones/pepenet.zone -v &

sleep 2   # let A's listener bind before B dials

# Node B: a mirror, dials A over the chain wire, holds no key; chain :6002, DNS :5302
./dnsd --db $DB --store /tmp/b.db --listen 6002 --peer 127.0.0.1:6001 --dns-port 5302 --no-sync -v &

sleep 12  # connect + announce-then-pull

# B answers records it learned only from the mesh:
dig @127.0.0.1 -p 5302 www.pepenet.pepe A +short          # 192.0.2.2
dig @127.0.0.1 -p 5302 _443._tcp.pepenet.pepe TLSA +short # 3 1 1 <hash>
dig @127.0.0.1 -p 5302 nope.pepe A                        # NXDOMAIN (unowned)
```

An owner node (`--key/--name/--zone`) publishes at startup and serves; a mirror
node just firehoses and resolves what it pulls. Ownership is gated live against the
indexer db on every query.

## Public mirror — resolving for others

A nameless mirror already knows every zone it has pulled from the mesh, so it can
serve as a shared authoritative `.pepe` resolver. To expose one:

```sh
# a real public seed listens on its chain port (pep 33874) and self-syncs;
# --sync-peer pins a bootstrap chain peer (default: cached peers + DNS seeds)
./dnsd --db $DB --store /tmp/mirror.db --listen 33874 \
       --dns-addr 0.0.0.0 --dns-port 53           # no --tls-redirect on a public mirror
# omit --peer to dial the public pep overlay seeds; pass --peer to pin one
```

- **UDP + TCP** on the same port. TCP (RFC 7766) carries answers past the UDP
  budget; **EDNS0** (RFC 6891) negotiates a larger UDP payload (capped at 1232 to
  avoid fragmentation), and an over-budget UDP answer sets **TC** so the client
  retries over TCP. Verify: `dig +tcp @host big.name.pepe ANY`.
- **Do not** pass `--tls-redirect` on a public mirror — that answers the loopback
  IP to steer a *local* browser at a *local* proxy; a shared resolver must return
  the real A + TLSA so the caller's own DANE-aware client can verify.
- Clients point a **scoped** resolver at it (`.pepe` only) — the server `REFUSED`s
  anything outside its suffix and never recurses, so it is safe as a split-horizon
  resolver, not a general one.

Still authoritative-only: no SOA/NS at the apex yet (negative caching / delegation),
and no response-rate-limiting for open-internet exposure.

## Live updates — `dns-cli`

Give an owner node a control socket (`--ctl <path>`) and change records without a
restart. The daemon holds the key and the store, so the CLI just forwards a
record spec; the daemon signs it and gossips it via `net_submit`:

```sh
./dnsd --db $DB --store /tmp/a.db --listen 6001 --dns-port 5301 \
       --key ~/.pepenet/pep-test2.key --name pepenet --ctl /tmp/a.ctl -v &

dns-cli --ctl /tmp/a.ctl PUT www A 3600 192.0.2.50            # add / replace
dns-cli --ctl /tmp/a.ctl PUT @ TXT 3600 "live from the cli"   # "@" is the apex
dns-cli --ctl /tmp/a.ctl PUT _443._tcp TLSA 3600 3 1 1 <hex>  # DANE
dns-cli --ctl /tmp/a.ctl DEL www A                            # delete
dns-cli --ctl /tmp/a.ctl LIST                                 # dump the folded zone
```

A `PUT` on the same `(label,type)` overwrites (latest wins); a `DEL` (empty PUT)
removes it. Changes propagate to peers within a poll tick and show up in `dig`
against any mirror. `PUT` of a record whose on-chain carrier would exceed 80 bytes
still works (gossip-only) but is flagged `[WARN >80B: not on-chain-settleable]`.

## Status

Working end to end: publish → owner-signed record PUTs → mesh gossip (announce-then-pull)
→ remote fold → `dig`. Ownership from the indexer's `names`/`epochs` projection.

UDP + TCP transports, EDNS0, and TC/TCP-fallback truncation are in — a nameless
mirror is safe to expose as a real `.pepe` resolver (see "Public mirror" above).

Not yet: cert-delegated publishing (hot key), SOA/NS at the apex (negative caching
+ delegation), and response-rate-limiting for open exposure.
