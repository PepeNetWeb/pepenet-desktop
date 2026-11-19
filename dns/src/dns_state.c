/* dns_state.c — see dns_state.h. */
#include "dns_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "pepenet/wire.h"
#include "pepenet/crypto.h"

static int fail3(char *err, int errlen, const char *m) {
    if (err && errlen > 0) snprintf(err, (size_t)errlen, "%s", m);
    return -3;
}

/* ── key / payload codecs ───────────────────────────────────────────────────── */
int dns_key_pack(const char *label, uint16_t type, uint8_t *key, int keymax) {
    int ll = label ? (int)strlen(label) : 0;
    if (ll > 63 || ll + 2 > keymax || ll + 2 > SP_STATE_KEY_MAX) return -1;
    for (int i = 0; i < ll; i++)
        key[i] = (uint8_t)tolower((unsigned char)label[i]);   /* DNS labels: case-blind */
    key[ll]     = (uint8_t)(type >> 8);
    key[ll + 1] = (uint8_t)(type & 0xFF);
    return ll + 2;
}

int dns_key_unpack(const uint8_t *key, int klen, char label[64], uint16_t *type) {
    if (klen < 2 || klen - 2 > 63) return 0;
    memcpy(label, key, (size_t)(klen - 2));
    label[klen - 2] = '\0';
    *type = (uint16_t)((key[klen - 2 + 0] << 8) | key[klen - 1]);
    return 1;
}

int dns_payload_pack(uint32_t ttl, const uint8_t *rdata, int rdlen,
                     uint8_t *out, int outmax) {
    uint8_t tmp[8];
    int n = sp_wvar(tmp, ttl);
    if (rdlen < 1 || n + rdlen > outmax) return -1;   /* empty rdata is a DEL, not a PUT */
    memcpy(out, tmp, (size_t)n);
    memcpy(out + n, rdata, (size_t)rdlen);
    return n + rdlen;
}

int dns_payload_unpack(const uint8_t *p, int plen, uint32_t *ttl,
                       const uint8_t **rdata, int *rdlen) {
    int off = 0; uint64_t v;
    if (!sp_rvar(p, plen, &off, &v) || v > 0xFFFFFFFFu) return 0;
    *ttl = (uint32_t)v;
    *rdata = p + off;
    *rdlen = plen - off;
    return *rdlen >= 1 && *rdlen <= ZONE_MAX_RDATA;
}

/* ── on-chain carrier (0xFF ‖ coin magic ‖ ZONE_OP) ─────────────────────────── */
int dns_rec_encode(const zone_rec *r, const uint8_t magic[2], uint8_t *out, int outmax) {
    int o = 0, n; uint8_t tmp[8];
    if (!magic || outmax < 4) return -1;
    out[o++] = 0xFF; out[o++] = magic[0]; out[o++] = magic[1]; out[o++] = ZONE_OP;
    int ll = (int)strlen(r->label);
    n = sp_wvar(tmp, (uint64_t)ll);   if (o + n + ll > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    memcpy(out + o, r->label, (size_t)ll); o += ll;
    n = sp_wvar(tmp, r->type);        if (o + n > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    n = sp_wvar(tmp, r->ttl);         if (o + n > outmax) return -1; memcpy(out + o, tmp, n); o += n;
    if (o + r->rdlen > outmax) return -1;
    memcpy(out + o, r->rdata, r->rdlen); o += r->rdlen;
    return o;
}

int dns_rec_decode(const uint8_t *c, int clen, const uint8_t magic[2], zone_rec *r) {
    if (!magic || clen < 4 || c[0] != 0xFF || c[1] != magic[0] || c[2] != magic[1] ||
        c[3] != ZONE_OP) return 0;
    int off = 4; uint64_t ll, type, ttl;
    if (!sp_rvar(c, clen, &off, &ll) || ll >= sizeof r->label || off + (int)ll > clen) return 0;
    memcpy(r->label, c + off, (size_t)ll); r->label[ll] = '\0'; off += (int)ll;
    if (!sp_rvar(c, clen, &off, &type) || type > 0xFFFF) return 0;
    if (!sp_rvar(c, clen, &off, &ttl)) return 0;
    int rd = clen - off;
    if (rd < 0 || rd > ZONE_MAX_RDATA) return 0;
    r->type = (uint16_t)type;
    r->ttl  = (uint32_t)ttl;
    r->rdlen = (uint16_t)rd;
    if (rd) memcpy(r->rdata, c + off, (size_t)rd);
    return 1;
}

int dns_rec_escape_hatchable(const zone_rec *r, const uint8_t magic[2]) {
    uint8_t tmp[256];
    int n = dns_rec_encode(r, magic, tmp, sizeof tmp);
    return n > 0 && n <= DNS_ONCHAIN_MAX;
}

/* ── publishing ─────────────────────────────────────────────────────────────── */
/* the publish anchor: tip − SP_STATE_REORG (or the tip itself on a young
 * chain), with its header hash from the oracle. 1 ok, 0 no usable anchor. */
static int publish_anchor(const SpChainOracle *o, uint32_t *height, uint8_t hash[32]) {
    uint32_t tip = o->tip(o->u);
    uint32_t h = tip > SP_STATE_REORG ? tip - SP_STATE_REORG : tip;
    if (o->header_at(o->u, h, hash) != 1) return 0;
    *height = h;
    return 1;
}

static int op_emit(SpState *st, const SpChainOracle *o, uint8_t opc,
                   const char *name, const uint8_t *key, int klen,
                   const uint8_t *payload, int plen,
                   const uint8_t priv[32], const uint8_t pub33[33],
                   int cert_type, const uint8_t *cert, int cert_len,
                   char *err, int errlen) {
    uint32_t ah; uint8_t hh[32];
    if (!publish_anchor(o, &ah, hh)) return fail3(err, errlen, "no usable anchor (chain not synced?)");
    uint8_t op[SP_STATE_OP_MAX];
    int n = sp_state_op_build(opc, name, key, klen, payload, plen, ah, hh,
                              priv, pub33, cert_type, cert, cert_len, op, sizeof op);
    if (n < 0) return fail3(err, errlen, "op build failed");
    return sp_state_admit(st, o, DNS_BUDGET, DNS_SCOPE, op, n, err, errlen);
}

int dns_state_put(SpState *st, const SpChainOracle *o, const char *name,
                  const zone_rec *rec,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen) {
    if (rec->rdlen == 0)   /* the old empty-PUT convention is now an explicit DEL */
        return dns_state_del(st, o, name, rec->label, rec->type,
                             priv, pub33, cert_type, cert, cert_len, err, errlen);
    uint8_t key[SP_STATE_KEY_MAX];
    int klen = dns_key_pack(rec->label, rec->type, key, sizeof key);
    if (klen < 0) return fail3(err, errlen, "label too long");
    uint8_t pay[8 + ZONE_MAX_RDATA];
    int plen = dns_payload_pack(rec->ttl, rec->rdata, rec->rdlen, pay, sizeof pay);
    if (plen < 0) return fail3(err, errlen, "rdata too long");
    return op_emit(st, o, SP_OP_PUT, name, key, klen, pay, plen,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

int dns_state_del(SpState *st, const SpChainOracle *o, const char *name,
                  const char *label, uint16_t type,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen) {
    uint8_t key[SP_STATE_KEY_MAX];
    int klen = dns_key_pack(label, type, key, sizeof key);
    if (klen < 0) return fail3(err, errlen, "label too long");
    return op_emit(st, o, SP_OP_DEL, name, key, klen, NULL, 0,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

int dns_state_clear(SpState *st, const SpChainOracle *o, const char *name,
                    const uint8_t priv[32], const uint8_t pub33[33],
                    int cert_type, const uint8_t *cert, int cert_len,
                    char *err, int errlen) {
    return op_emit(st, o, SP_OP_CLEAR, name, NULL, 0, NULL, 0,
                   priv, pub33, cert_type, cert, cert_len, err, errlen);
}

/* ── reads ──────────────────────────────────────────────────────────────────── */
static int zone_cb(void *u, const uint8_t *key, int klen, int op,
                   uint32_t anchor, const uint8_t *blob, int blen) {
    (void)anchor;
    zone *z = u;
    if (op != SP_OP_PUT || z->n >= ZONE_MAX_RECS) return 1;
    SpStateOp p;
    if (!sp_state_op_parse(blob, blen, &p)) return 1;
    zone_rec *r = &z->recs[z->n];
    uint16_t type; char label[64];
    if (!dns_key_unpack(key, klen, label, &type)) return 1;
    uint32_t ttl; const uint8_t *rd; int rdl;
    if (!dns_payload_unpack(p.payload, p.payload_len, &ttl, &rd, &rdl)) return 1;
    snprintf(r->label, sizeof r->label, "%s", label);
    r->type = type; r->ttl = ttl;
    r->rdlen = (uint16_t)rdl;
    memcpy(r->rdata, rd, (size_t)rdl);
    z->n++;
    return 1;
}

int dns_state_zone(SpState *st, const char *name, zone *z) {
    memset(z, 0, sizeof *z);
    size_t nlen = name ? strlen(name) : 0;
    if (!sp_name_valid(name, nlen)) return 0;
    snprintf(z->apex, sizeof z->apex, "%s", name);
    sp_state_iter(st, name, zone_cb, z);
    return z->n;
}

/* ── digest ─────────────────────────────────────────────────────────────────── */
typedef struct { uint8_t buf[4 + 32 + 32 * 512]; int off; } DigAcc;

static int dig_cb(void *u, const uint8_t *key, int klen, int op,
                  uint32_t anchor, const uint8_t *blob, int blen) {
    (void)key; (void)klen; (void)op; (void)anchor;
    DigAcc *a = u;
    if (a->off + 32 > (int)sizeof a->buf) return 0;
    SpStateOp p;
    if (sp_state_op_parse(blob, blen, &p)) { memcpy(a->buf + a->off, p.op_id, 32); a->off += 32; }
    return 1;
}

static void digest_compute(SpState *st, const char *name, uint8_t out[32]) {
    static DigAcc a;                       /* big; single-threaded per store owner */
    a.off = 0;
    uint32_t f = sp_state_floor(st, name);
    a.buf[a.off++] = (uint8_t)f; a.buf[a.off++] = (uint8_t)(f >> 8);
    a.buf[a.off++] = (uint8_t)(f >> 16); a.buf[a.off++] = (uint8_t)(f >> 24);
    uint8_t *cb; int cl;
    if (sp_state_clear_get(st, name, &cb, &cl)) {
        SpStateOp p;
        if (sp_state_op_parse(cb, cl, &p)) { memcpy(a.buf + a.off, p.op_id, 32); a.off += 32; }
        free(cb);
    } else { memset(a.buf + a.off, 0, 32); a.off += 32; }
    sp_state_iter(st, name, dig_cb, &a);   /* key-ordered ⇒ canonical */
    sp_sha256(a.buf, (size_t)a.off, out);
}

/* ── L10: per-name digest cache ─────────────────────────────────────────────
 * One store (the gossip store dnsnet_init attaches) gets a direct-mapped cache
 * of sha256 digests keyed by two independent per-process-seeded 64-bit hashes
 * of the name (a false hit needs a 128-bit collision under a secret seed).
 * Invalidation is exact, never time-based:
 *   - every committed write through the store handle calls the sp_state change
 *     hook (admit, epoch wipe, clear, sweep drop) -> that name's entry dies;
 *     NULL (close, failed batch) -> the whole cache dies (generation bump);
 *   - a write by ANY other connection/process bumps PRAGMA data_version,
 *     checked on every lookup -> the whole cache dies.
 * The digest is a pure function of the held rows, so a hit is byte-identical
 * to recomputing it; the cache only saves the 3 queries + sha256. */
#ifndef DNS_DG_CACHE_BITS
#define DNS_DG_CACHE_BITS 18                /* 262,144 entries x 56 B, touched lazily */
#endif
typedef struct { uint64_t k1, k2; uint32_t gen; uint8_t dg[32]; } DgEnt;
static struct {
    SpState *st; DgEnt *t; uint32_t gen; int64_t dv; uint64_t s1, s2;
    unsigned long hit, miss, inval, flush;
} g_dc;

static void dc_keys(const char *name, uint64_t *k1, uint64_t *k2) {
    uint64_t a = 1469598103934665603ULL ^ g_dc.s1, b = 0x84222325CBF29CE4ULL ^ g_dc.s2;
    for (const char *c = name; *c; c++) {
        a ^= (uint8_t)*c; a *= 1099511628211ULL;
        b += (uint8_t)*c; b *= 0x9E3779B97F4A7C15ULL; b ^= b >> 31;
    }
    a ^= a >> 29; b ^= b >> 33; b *= 0xFF51AFD7ED558CCDULL; b ^= b >> 33;
    *k1 = a ? a : 1; *k2 = b;
}
static void dc_flush(void) { g_dc.gen++; if (!g_dc.gen) g_dc.gen = 1; g_dc.flush++; }
static void dc_hook(void *u, const char *name) {
    if (u != (void *)g_dc.st || !g_dc.t) return;
    if (!name) { dc_flush(); return; }              /* everything may have changed */
    if (!name[0]) { g_dc.st = NULL; dc_flush(); return; }   /* the handle is closing */
    uint64_t k1, k2; dc_keys(name, &k1, &k2);
    DgEnt *e = &g_dc.t[k1 & ((1u << DNS_DG_CACHE_BITS) - 1)];
    if (e->k1 == k1 && e->k2 == k2) { e->gen = 0; g_dc.inval++; }
}
void dns_state_cache_attach(SpState *st) {
    if (g_dc.st && g_dc.st != st) sp_state_set_change_hook(g_dc.st, NULL, NULL);
    if (!g_dc.t) g_dc.t = calloc((size_t)1 << DNS_DG_CACHE_BITS, sizeof(DgEnt));
    if (!g_dc.s1) {
        uint64_t s[2] = { 0, 0 };
        if (getentropy(s, sizeof s) != 0) { s[0] = (uint64_t)time(NULL) * 0x9E3779B97F4A7C15ULL; s[1] = (uint64_t)(uintptr_t)&s; }
        g_dc.s1 = s[0] | 1; g_dc.s2 = s[1];
    }
    g_dc.st = st;
    dc_flush();
    g_dc.dv = st ? sp_state_data_version(st) : -1;
    if (st) sp_state_set_change_hook(st, dc_hook, st);
}
void dns_state_cache_detach(void) {
    if (g_dc.st) sp_state_set_change_hook(g_dc.st, NULL, NULL);
    g_dc.st = NULL; dc_flush();
}
void dns_state_cache_stats(unsigned long *hit, unsigned long *miss, unsigned long *inval, unsigned long *flush) {
    if (hit) *hit = g_dc.hit;
    if (miss) *miss = g_dc.miss;
    if (inval) *inval = g_dc.inval;
    if (flush) *flush = g_dc.flush;
}

void dns_state_digest(SpState *st, const char *name, uint8_t out[32]) {
    if (!st || st != g_dc.st || !g_dc.t || !name) { digest_compute(st, name, out); return; }
    int64_t dv = sp_state_data_version(st);
    if (dv < 0 || dv != g_dc.dv) { dc_flush(); g_dc.dv = dv; }   /* another writer */
    uint64_t k1, k2; dc_keys(name, &k1, &k2);
    DgEnt *e = &g_dc.t[k1 & ((1u << DNS_DG_CACHE_BITS) - 1)];
    if (dv >= 0 && e->gen == g_dc.gen && e->k1 == k1 && e->k2 == k2) {
        memcpy(out, e->dg, 32); g_dc.hit++; return;
    }
    digest_compute(st, name, out);
    g_dc.miss++;
    if (dv < 0) return;                    /* cannot tell other writers apart: no cache */
    e->k1 = k1; e->k2 = k2; e->gen = g_dc.gen; memcpy(e->dg, out, 32);
}

/* G1: the zone as served. Rows belong to the ownership epoch they were
 * admitted under (st_names.owner); if the name has changed hands since and the
 * new owner has not published yet, those rows are the PREVIOUS owner's and are
 * not served (the wipe still happens on the new owner's first admitted op). */
int dns_state_zone_owned(SpState *st, const char *name, const uint8_t owner[20], zone *z) {
    uint8_t held[20];
    if (sp_state_owner(st, name, held) && memcmp(held, owner, 20) != 0) {
        memset(z, 0, sizeof *z);
        size_t nlen = name ? strlen(name) : 0;
        if (sp_name_valid(name, nlen)) snprintf(z->apex, sizeof z->apex, "%s", name);
        return 0;
    }
    return dns_state_zone(st, name, z);
}

/* ── sweep ──────────────────────────────────────────────────────────────────── */
/* P11: a resumable sweep. Each step examines up to `max` names after `cursor`
 * (name order) and drops the ones the oracle no longer answers for; the cursor
 * wraps to "" at the end of the store, so successive steps visit every name.
 * (The old pass collected the first 256 names every time and never got past
 * them.) Names are collected first, then dropped, so the walk is not mutated
 * under its own cursor. */
#define SWEEP_CHUNK 256
typedef struct { char names[SWEEP_CHUNK][SP_NAME_MAX + 1]; int n; } SweepAcc;

static int sweep_cb(void *u, const char *name) {
    SweepAcc *a = u;
    if (a->n >= SWEEP_CHUNK) return 0;
    snprintf(a->names[a->n++], SP_NAME_MAX + 1, "%s", name);
    return 1;
}

int dns_state_sweep_step(SpState *st, const SpChainOracle *o, char *cursor,
                         int max, int *examined) {
    static SweepAcc a;                     /* 8.5 KB; single owner (net thread) */
    int dropped = 0, seen = 0;
    uint8_t owner[20];
    while (seen < max) {
        int want = max - seen < SWEEP_CHUNK ? max - seen : SWEEP_CHUNK;
        a.n = 0;
        sp_state_names_after(st, cursor, want, sweep_cb, &a);
        for (int i = 0; i < a.n; i++)
            if (!o->owner_now(o->u, a.names[i], owner)) {
                sp_state_drop_name(st, a.names[i]);
                dropped++;
            }
        seen += a.n;
        if (a.n < want) { cursor[0] = '\0'; break; }   /* end of store: wrap */
        snprintf(cursor, SP_NAME_MAX + 1, "%s", a.names[a.n - 1]);
    }
    if (examined) *examined = seen;
    return dropped;
}

int dns_state_sweep(SpState *st, const SpChainOracle *o) {
    char cur[SP_NAME_MAX + 1] = "";
    int dropped = 0, seen;
    do { dropped += dns_state_sweep_step(st, o, cur, 4096, &seen); } while (cur[0]);
    return dropped;
}
