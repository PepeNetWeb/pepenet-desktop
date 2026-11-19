// Canonical, order-independent state digest (SHA-256) — the cross-language
// equality oracle (SPEC-conformance.md §Digest). Every table is serialized in a
// PINNED sort order with PINNED field widths/endianness (LE ints), then hashed.
// Two states hash equal iff they are the same fold state, regardless of internal
// array/iteration order. Magic "SMv1".
#include "sm.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>

// ── growable byte buffer ─────────────────────────────────────────────────────
typedef struct { uint8_t *p; size_t n, cap; } Buf;
static void bput(Buf *b, const void *d, size_t n) {
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->n + n) nc *= 2;
        b->p = realloc(b->p, nc); b->cap = nc;
    }
    memcpy(b->p + b->n, d, n); b->n += n;
}
static void bu8 (Buf *b, uint8_t v)  { bput(b, &v, 1); }
static void bu32(Buf *b, uint32_t v) { uint8_t t[4];  for (int i=0;i<4;i++)  t[i]=(uint8_t)(v>>(8*i)); bput(b,t,4); }
static void bu64(Buf *b, uint64_t v) { uint8_t t[8];  for (int i=0;i<8;i++)  t[i]=(uint8_t)(v>>(8*i)); bput(b,t,8); }
static void bi64(Buf *b, int64_t v)  { bu64(b, (uint64_t)v); }

// ── sorting (index arrays + a single-threaded context pointer) ───────────────
static SmState *g_s;
static int cmp_names (const void *a, const void *b) {
    return strcmp(g_s->names[*(const int*)a].name, g_s->names[*(const int*)b].name);
}
static int cmp_commits(const void *a, const void *b) {
    // H7: total order (commitment, commit_height, tx_index). commitment alone is NOT
    // a total order — the §3.2 commitment-copy attack lets two records share the same
    // 32 bytes, and a bare memcmp() fed to non-stable qsort() then forks the digest by
    // platform. The (commit_height, tx_index) tiebreak makes a duplicated commitment
    // sort deterministically. (SPEC-conformance.md §Digest.)
    const SmCommit *x = &g_s->commits[*(const int*)a], *y = &g_s->commits[*(const int*)b];
    int c = memcmp(x->commitment, y->commitment, 32); if (c) return c;
    if (x->commit_height != y->commit_height) return (x->commit_height < y->commit_height) ? -1 : 1;
    return (x->tx_index < y->tx_index) ? -1 : (x->tx_index > y->tx_index);
}
static int cmp_muts(const void *a, const void *b) {
    return memcmp(g_s->muts[*(const int*)a].owner, g_s->muts[*(const int*)b].owner, 20);
}
static int *sorted(int n, int (*cmp)(const void*, const void*)) {
    int *idx = malloc((size_t)(n ? n : 1) * sizeof(int));
    for (int i = 0; i < n; i++) idx[i] = i;
    if (n > 1) qsort(idx, (size_t)n, sizeof(int), cmp);
    return idx;
}

void sm_state_digest(SmState *s, uint8_t out[32]) {
    g_s = s;
    Buf b = {0};
    bput(&b, "SMv1", 4);

    // names
    int *ni = sorted(s->n_names, cmp_names);
    bu32(&b, (uint32_t)s->n_names);
    for (int k = 0; k < s->n_names; k++) {
        const SmNameRow *r = &s->names[ni[k]];
        bu8(&b, r->name_len); bput(&b, r->name, r->name_len);
        bput(&b, r->owner, 20);   // owner_type is NOT digested: ownership is by bare
                                  // hash160 (§4) and a TRANSFER target carries no type
        bu8(&b, (uint8_t)r->st); bi64(&b, r->lease_expiry);
        bput(&b, r->seller, 20); bu8(&b, r->seller_type);
        bu64(&b, r->price); bi64(&b, r->offer_expiry);
        bput(&b, r->buyer, 20);
        bu64(&b, r->burn_leg); bu64(&b, r->pay_leg); bi64(&b, r->reserve_expiry);
    }
    free(ni);

    // commits
    int *ci = sorted(s->n_commits, cmp_commits);
    bu32(&b, (uint32_t)s->n_commits);
    for (int k = 0; k < s->n_commits; k++) {
        const SmCommit *c = &s->commits[ci[k]];
        bput(&b, c->commitment, 32); bi64(&b, c->commit_height);
        bu32(&b, c->tx_index); bi64(&b, c->commit_time);
    }
    free(ci);

    // per-owner last mutation height
    int *mi = sorted(s->n_muts, cmp_muts);
    bu32(&b, (uint32_t)s->n_muts);
    for (int k = 0; k < s->n_muts; k++) {
        const SmMut *m = &s->muts[mi[k]];
        bput(&b, m->owner, 20); bi64(&b, m->height);
    }
    free(mi);

    SHA256_CTX h; sha256_init(&h);
    sha256_update(&h, b.p ? b.p : (const uint8_t*)"", (unsigned int)b.n);
    sha256_final(&h, out);
    free(b.p);
}
