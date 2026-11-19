// ECMH state digest (§13.2) — the incremental twin of sm_state_digest.
//
// Two deliverables live here:
//   1. sm_state_ecmh(): the per-table Elliptic-Curve Multiset Hash over the SAME
//      canonical per-row encoding digest.c uses (so the two digests induce the
//      identical equality relation), combined into one 32-byte value. A point-sum
//      is order-independent and invertible, so a production fold maintains it in
//      O(rows-changed)/block instead of re-hashing the whole state.
//   2. ecmh_cmd(): the pinned, portable `sm ecmh` vector set — hash-to-curve KATs,
//      accumulator algebra, and a tagged multiset sum — printed as a cross-language
//      byte-identical `combined` golden (SPEC-conformance.md §13.2). Mirrors the
//      attrib-curve mode: every reference impl runs this exact script against its
//      own secp256k1 and must reproduce the same digest.
#include "sm.h"
#include "secp256k1.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static const char *HEXD = "0123456789abcdef";
static void puthex(const uint8_t *d, int n) { for (int i = 0; i < n; i++) { putchar(HEXD[d[i] >> 4]); putchar(HEXD[d[i] & 15]); } }

// ── per-record byte encoding (BYTE-IDENTICAL to digest.c's per-row fields) ──────
typedef struct { uint8_t p[256]; int n; } Row;
static void rput(Row *b, const void *d, int n) { memcpy(b->p + b->n, d, (size_t)n); b->n += n; }
static void ru8 (Row *b, uint8_t v)  { rput(b, &v, 1); }
static void ru32(Row *b, uint32_t v) { uint8_t t[4];  for (int i=0;i<4;i++) t[i]=(uint8_t)(v>>(8*i)); rput(b,t,4); }
static void ru64(Row *b, uint64_t v) { uint8_t t[8];  for (int i=0;i<8;i++) t[i]=(uint8_t)(v>>(8*i)); rput(b,t,8); }
static void ri64(Row *b, int64_t v)  { ru64(b, (uint64_t)v); }

// domain tags — second-preimage separation between tables.
enum { TAG_NAME = 0x01, TAG_COMMIT = 0x02, TAG_MUT = 0x04 };
static const uint8_t ECMH_REC_TAG[6] = { 'E','C','M','H','v','1' };

// acc ← acc + H2C("ECMHv1" ‖ tag ‖ row_bytes).
static void ecmh_fold_row(uint8_t acc[33], uint8_t tag, const Row *r) {
    uint8_t pre[7 + 256]; int n = 0;
    memcpy(pre, ECMH_REC_TAG, 6); n = 6; pre[n++] = tag;
    memcpy(pre + n, r->p, (size_t)r->n); n += r->n;
    uint8_t pt[33]; secp_ecmh_hash(pre, n, pt);
    secp_ecmh_add(acc, pt);
}

void sm_state_ecmh(SmState *s, uint8_t out[32]) {
    uint8_t an[33], ac[33], am[33];
    secp_ecmh_identity(an); secp_ecmh_identity(ac); secp_ecmh_identity(am);

    for (int i = 0; i < s->n_names; i++) {
        const SmNameRow *r = &s->names[i]; Row b = {{0},0};
        ru8(&b, r->name_len); rput(&b, r->name, r->name_len);
        rput(&b, r->owner, 20);                 // owner_type NOT encoded (matches digest.c)
        ru8(&b, (uint8_t)r->st); ri64(&b, r->lease_expiry);
        rput(&b, r->seller, 20); ru8(&b, r->seller_type);
        ru64(&b, r->price); ri64(&b, r->offer_expiry);
        rput(&b, r->buyer, 20);
        ru64(&b, r->burn_leg); ru64(&b, r->pay_leg); ri64(&b, r->reserve_expiry);
        ecmh_fold_row(an, TAG_NAME, &b);
    }
    for (int i = 0; i < s->n_commits; i++) {
        const SmCommit *c = &s->commits[i]; Row b = {{0},0};
        rput(&b, c->commitment, 32); ri64(&b, c->commit_height);
        ru32(&b, c->tx_index); ri64(&b, c->commit_time);
        ecmh_fold_row(ac, TAG_COMMIT, &b);
    }
    for (int i = 0; i < s->n_muts; i++) {
        const SmMut *m = &s->muts[i]; Row b = {{0},0};
        rput(&b, m->owner, 20); ri64(&b, m->height);
        ecmh_fold_row(am, TAG_MUT, &b);
    }

    // combined = SHA256("ECMHtop1" ‖ the three sub-accumulators).
    SHA256_CTX h; sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"ECMHtop1", 8);
    sha256_update(&h, an, 33); sha256_update(&h, ac, 33); sha256_update(&h, am, 33);
    sha256_final(&h, out);
}

// ── `sm ecmh` — the pinned, portable primitive vector set ───────────────────────
int ecmh_cmd(void) {
    SHA256_CTX comb; sha256_init(&comb);
    #define FEED(p,n) sha256_update(&comb, (const uint8_t*)(p), (unsigned)(n))

    // version self-doc
    printf("ecmh ECMHv1\n"); FEED("ECMHv1", 6);

    // 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
    struct { const char *label; const uint8_t *pre; int len; } h2c[] = {
        { "empty",  (const uint8_t *)"",          0 },
        { "a",      (const uint8_t *)"a",          1 },
        { "pepe",   (const uint8_t *)"pepenet",   7 },
        { "doge",   (const uint8_t *)"doge",       4 },
    };
    uint8_t ff[32]; memset(ff, 0xFF, 32);
    uint8_t z32[32]; memset(z32, 0, 32);
    for (unsigned i = 0; i < sizeof h2c / sizeof h2c[0]; i++) {
        uint8_t pt[33]; int ctr = secp_ecmh_hash(h2c[i].pre, h2c[i].len, pt);
        printf("h2c %s ctr=%d pt=", h2c[i].label, ctr); puthex(pt, 33); printf("\n");
        uint8_t cb = (uint8_t)ctr; FEED(&cb, 1); FEED(pt, 33);
    }
    { uint8_t pt[33]; int ctr = secp_ecmh_hash(ff, 32, pt);
      printf("h2c ff32 ctr=%d pt=", ctr); puthex(pt, 33); printf("\n");
      uint8_t cb=(uint8_t)ctr; FEED(&cb,1); FEED(pt,33); }
    { uint8_t pt[33]; int ctr = secp_ecmh_hash(z32, 32, pt);
      printf("h2c z32 ctr=%d pt=", ctr); puthex(pt, 33); printf("\n");
      uint8_t cb=(uint8_t)ctr; FEED(&cb,1); FEED(pt,33); }

    // 2. identity (∞) serialization
    uint8_t id[33]; secp_ecmh_identity(id);
    printf("identity "); puthex(id, 33); printf("\n"); FEED(id, 33);

    // 3. tagged multiset sum — a fixed set of (tag ‖ row) records, summed two ways.
    //    Order independence (commutativity) is asserted, then the sum is pinned.
    struct { uint8_t tag; const char *body; int len; } recs[] = {
        { TAG_NAME,   "\x03" "foo",                 4 },
        { TAG_NAME,   "\x03" "bar",                 4 },
        { TAG_COMMIT, "commitment-blob-32-bytes-xxxxxx", 31 },
        { TAG_MUT,    "owner-mutation",             14 },
    };
    int nr = (int)(sizeof recs / sizeof recs[0]);
    uint8_t fwd[33], rev[33]; secp_ecmh_identity(fwd); secp_ecmh_identity(rev);
    for (int i = 0; i < nr; i++) {
        Row b = {{0},0}; ru8(&b, recs[i].tag); rput(&b, recs[i].body, recs[i].len);
        uint8_t pre[7+256]; int n=0; memcpy(pre,ECMH_REC_TAG,6); n=6; memcpy(pre+n,b.p,(size_t)b.n); n+=b.n;
        uint8_t pt[33]; secp_ecmh_hash(pre, n, pt); secp_ecmh_add(fwd, pt);
    }
    for (int i = nr - 1; i >= 0; i--) {
        Row b = {{0},0}; ru8(&b, recs[i].tag); rput(&b, recs[i].body, recs[i].len);
        uint8_t pre[7+256]; int n=0; memcpy(pre,ECMH_REC_TAG,6); n=6; memcpy(pre+n,b.p,(size_t)b.n); n+=b.n;
        uint8_t pt[33]; secp_ecmh_hash(pre, n, pt); secp_ecmh_add(rev, pt);
    }
    int commut = (memcmp(fwd, rev, 33) == 0);
    printf("sum "); puthex(fwd, 33); printf("\n");
    printf("commutative %d\n", commut);
    FEED(fwd, 33); { uint8_t b=(uint8_t)commut; FEED(&b,1); }

    // 4. inverse — remove the first record from the sum, re-add, must round-trip.
    {
        Row b = {{0},0}; ru8(&b, recs[0].tag); rput(&b, recs[0].body, recs[0].len);
        uint8_t pre[7+256]; int n=0; memcpy(pre,ECMH_REC_TAG,6); n=6; memcpy(pre+n,b.p,(size_t)b.n); n+=b.n;
        uint8_t pt[33]; secp_ecmh_hash(pre, n, pt);
        uint8_t acc[33]; memcpy(acc, fwd, 33);
        uint8_t npt[33]; memcpy(npt, pt, 33); secp_ecmh_negate(npt);
        secp_ecmh_add(acc, npt);                 // remove rec[0]
        secp_ecmh_add(acc, pt);                  // re-add rec[0]
        int roundtrip = (memcmp(acc, fwd, 33) == 0);
        printf("inverse_roundtrip %d\n", roundtrip);
        uint8_t bb=(uint8_t)roundtrip; FEED(&bb,1);
    }

    uint8_t cd[32]; sha256_final(&comb, cd);
    printf("combined "); puthex(cd, 32); printf("\n");
    #undef FEED
    return 0;
}
