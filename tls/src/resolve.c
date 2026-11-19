/* resolve.c — see resolve.h. Live store/oracle glue around origin.{h,c}. */
#include "resolve.h"
#include "origin.h"

#include "dns_state.h"   /* SpState + dns_state_zone (the live zone) */
#include "dns_chain.h"   /* the lease-gated ownership oracle */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

struct Resolver {
    char   suffix[16];
    SpState  *st;
    DnsChain *ch;
    SpChainOracle orc;
    pthread_mutex_t mu;   /* the proxy calls resolver_resolve from a THREAD PER
                           * connection; st/vw are shared SQLite handles (not
                           * thread-safe for concurrent use). Serialize every
                           * db-touching resolve — fast + local, so no bottleneck. */
};

Resolver *resolver_open(const char *suffix, const char *store_path,
                        const char *indexer_db) {
    if (!suffix || !*suffix || !store_path || !indexer_db) return NULL;
    Resolver *r = calloc(1, sizeof *r);
    if (!r) return NULL;
    snprintf(r->suffix, sizeof r->suffix, "%s", suffix);
    pthread_mutex_init(&r->mu, NULL);
    r->ch = dns_chain_open(indexer_db);
    r->st = sp_state_open(store_path);
    if (!r->ch || !r->st) { resolver_close(r); return NULL; }
    r->orc = dns_chain_oracle(r->ch);
    return r;
}

void resolver_close(Resolver *r) {
    if (!r) return;
    if (r->st) sp_state_close(r->st);
    if (r->ch) dns_chain_close(r->ch);
    pthread_mutex_destroy(&r->mu);
    free(r);
}

void resolver_sync(Resolver *r, int64_t *height, int64_t *peer_height) {
    if (height)      *height = 0;
    if (peer_height) *peer_height = 0;
    if (!r) return;
    pthread_mutex_lock(&r->mu);
    dns_chain_sync(r->ch, height, peer_height);
    pthread_mutex_unlock(&r->mu);
}

int resolver_resolve(const char *sni, OriginInfo *out, void *ud) {
    Resolver *r = ud;
    if (!r || !sni || !out) return 0;

    char apex[64], sub[128];
    if (!origin_split(sni, r->suffix, apex, sizeof apex, sub, sizeof sub))
        return 0;                                   /* pure string work — no lock */

    /* Fold to lowercase before any store lookup. DNS names are case-insensitive,
     * and every other path already honours that: dns_wire.c lowercases what it
     * decodes off the wire, dns_state.c keys on case-blind labels, and origin.c
     * compares with strcasecmp. This path is the odd one out because its name
     * arrives from the TLS SNI rather than the wire decoder — origin_split only
     * matches the SUFFIX case-insensitively and copies the apex through with its
     * original case, so `PEPENET.PEPE` missed a byte-exact store key that
     * `pepenet.pepe` hit. */
    for (char *c = apex; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 'a' - 'A';
    for (char *c = sub;  *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 'a' - 'A';

    /* Everything below reads the shared SQLite handles (vw + st) — serialize it
     * so concurrent connection threads don't corrupt SQLite's state. */
    pthread_mutex_lock(&r->mu);

    /* Ownership gate — a name nobody claimed (or whose lease lapsed) does not
     * resolve (mirrors dnsd's NXDOMAIN). This is the authoritative gate; the
     * store only ever holds owner-signed rows, but we still gate the apex. */
    uint8_t owner[20];
    if (!r->orc.owner_now(r->orc.u, apex, owner)) {
        pthread_mutex_unlock(&r->mu);
        return 0;
    }

    /* Assemble the live zone from the record store, then extract A + TLSA.
     * The zone struct is fat, so heap-allocate (this runs on a proxy
     * connection thread with a small default stack). */
    zone *z = malloc(sizeof *z);
    if (!z) { pthread_mutex_unlock(&r->mu); return 0; }
    dns_state_zone(r->st, apex, z);
    int ok = origin_from_zone(z, sub, r->suffix, out);
    free(z);
    pthread_mutex_unlock(&r->mu);

    /* Test-only origin-port override. v1 pins the origin at :443 (TLSA at
     * _443._tcp — origin_from_zone sets out->port = 443). For a local test we
     * want to dial an already-running origin on a non-privileged port (e.g. the
     * pepenet site's Kestrel :5001) without a loopback :443 alias. Off by
     * default, so origin.c stays pure and origin_test is unaffected. */
    if (ok) {
        const char *allow = getenv("PEPENET_TLS_ALLOW_LOCAL_ORIGIN");
        const char *op = getenv("PEPENET_ORIGIN_PORT");
        if (allow && allow[0] && op && *op) {
            int p = atoi(op);
            if (p > 0 && p < 65536) out->port = (uint16_t)p;
        }
    }
    return ok;
}

int resolver_lookup(const char *sni, OriginInfo *out, void *ud) {
    Resolver *r = ud;
    if (!r || !sni || !out) return RES_BAD_NAME;
    if (resolver_resolve(sni, out, ud)) return RES_OK;
    char apex[64], sub[128];
    if (!origin_split(sni, r->suffix, apex, sizeof apex, sub, sizeof sub))
        return RES_BAD_NAME;
    for (char *c = apex; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 'a' - 'A';
    for (char *c = sub;  *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 'a' - 'A';
    pthread_mutex_lock(&r->mu);
    uint8_t owner[20];
    if (!r->orc.owner_now(r->orc.u, apex, owner)) {
        pthread_mutex_unlock(&r->mu);
        return RES_UNOWNED;
    }
    zone *z = malloc(sizeof *z);
    if (!z) { pthread_mutex_unlock(&r->mu); return RES_BAD_RECORD; }
    dns_state_zone(r->st, apex, z);
    int has = origin_has_tlsa(z, sub);
    free(z);
    pthread_mutex_unlock(&r->mu);
    return has ? RES_BAD_RECORD : RES_NO_TLSA;
}
