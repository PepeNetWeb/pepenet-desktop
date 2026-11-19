/* resolve.h — the live resolver: SNI name → origin endpoint + on-chain TLSA,
 * backed by pepenet-dns's ownership View + carrier Store, folded exactly as
 * dnsd folds it. This is the store/view plumbing around origin.{h,c}; the byte
 * logic it delegates to is unit-pinned there. Plugs into proxy_serve as the
 * real proxy_resolver (replacing slice 3's stub).
 */
#ifndef PEPENET_TLS_RESOLVE_H
#define PEPENET_TLS_RESOLVE_H

#include "proxy.h"   /* OriginInfo, proxy_resolver */

typedef struct Resolver Resolver;

/* Open a live resolver. `suffix` = this box's one TLD ("doge"/"pepe");
 * `store_path` = the carrier db (records); `indexer_db` = the ownership
 * projection. Opens its OWN read-only store/view handles (sqlite WAL makes
 * concurrent read-while-dnsd-writes safe). NULL on error. */
Resolver *resolver_open(const char *suffix, const char *store_path,
                        const char *indexer_db);
void resolver_close(Resolver *r);

/* proxy_resolver-compatible: pass as the resolve fn with the Resolver* as `ud`.
 * 1 iff the apex is owned AND the name has both an A and a `_443._tcp` TLSA
 * (fills *out); 0 otherwise (unknown/unclaimed/unauthenticatable). */
int resolver_resolve(const char *sni, OriginInfo *out, void *ud);

/* this node's fold height and the last peer tip the indexer persisted (0 if
 * unknown). Safe from a proxy connection thread. */
void resolver_sync(Resolver *r, int64_t *height, int64_t *peer_height);

/* GreatDANE (additive): resolver_resolve plus WHY it refused. Same gate,
 * same answer on RES_OK (fills *out); never relaxes resolver_resolve. */
enum { RES_OK = 0, RES_BAD_NAME = 1, RES_UNOWNED = 2, RES_NO_TLSA = 3,
       RES_BAD_RECORD = 4 };
int resolver_lookup(const char *sni, OriginInfo *out, void *ud);

#endif
