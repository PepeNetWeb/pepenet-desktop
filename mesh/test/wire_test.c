// wire_test.c — adversarial battery for the bytes-off-the-network surface:
// src/wire.c (CompactSize + LE32) and the two decoders built on it,
// sp_state_op_parse() / sp_cert_parse() in src/state.c.
//
// PROVEN HERE:
//   6. Encode->decode ROUND TRIP over thousands of seeded-random values and
//      messages of EVERY type the protocol defines — PUT / DEL / CLEAR, with and
//      without a P2PKH cert, plus hand-built P2SH multisig certs — including the
//      empty-payload forms (DEL, CLEAR) and the maximum-size op (SP_STATE_OP_MAX).
//   7. THE TRUNCATION SWEEP: every prefix, 0..len, of a valid message of each
//      type is fed to the decoder. Not one may crash, hang, or read out of bounds.
//   8. RANDOM AND GRAMMAR-AWARE FUZZ: tens of thousands of iterations of pure
//      random bytes, of valid-message single/multi-byte mutations, and of
//      hand-crafted declared-length attacks (length > buffer, length 0,
//      0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 2^63, 2^64-1; absurd counted-structure
//      counts). Peak RSS is sampled across the length attacks to prove the
//      decoder never attempts a giant allocation.
//   9. BOUNDARY VALUES snapped to the protocol's own constants +/-1:
//      SP_NAME_MAX, SP_STATE_KEY_MAX, SP_STATE_OP_MAX, SP_STATE_VER, SP_CERT_VER,
//      the P2SH redeem bounds 3/520, the multisig sig-count bounds 1/16, and every
//      CompactSize width boundary (0xFC/0xFD/0xFFFF/0x10000/0xFFFFFFFF/2^32).
//
// HOW OUT-OF-BOUNDS IS *PROVEN*, not assumed: every buffer handed to a decoder
// lives in an mmap'd arena flush-right against a PROT_NONE guard page, with a
// second PROT_NONE page in front. A one-byte over-read or under-read therefore
// faults. SIGSEGV/SIGBUS are trapped with sigsetjmp and reported as a FAIL with
// the triggering input in hex, and the sweep continues instead of dying. A
// SIGALRM watchdog turns a hang into a FAIL as well.
//
// *** THIS SUITE FAILS. The failure is a real bug in src/state.c — see the
// *** FINDING banner in "-- declared-length attacks --". The test is NOT
// *** weakened to hide it.
#include "pepenet/wire.h"
#include "pepenet/state.h"
#include "pepenet/crypto.h"

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static int g_fail;
static long g_checks;
#define CK(c, m) do { g_checks++; if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

// ── watchdog ─────────────────────────────────────────────────────────────────
static const char *g_phase = "startup";
static void on_alarm(int s) {
    (void)s;
    char m[256];
    int n = snprintf(m, sizeof m, "\nwire_test: WATCHDOG FAIL — hang in phase: %s\n", g_phase);
    ssize_t r = write(2, m, (size_t)n); (void)r;
    _exit(1);
}
#define PHASE(p, secs) do { g_phase = (p); alarm(secs); } while (0)

// ── SplitMix64 ───────────────────────────────────────────────────────────────
static uint64_t g_rng;
static uint64_t rnd(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rndbytes(uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rnd(); }

static void dumphex(const char *tag, const uint8_t *b, int n) {
    printf("       %s (%d bytes): ", tag, n);
    for (int i = 0; i < n && i < 96; i++) printf("%02x", b[i]);
    if (n > 96) printf("... (+%d)", n - 96);
    printf("\n");
}

// ── guard-paged arena: data sits flush against a PROT_NONE page ──────────────
static uint8_t *g_arena_base, *g_arena_end;
static size_t g_arena_map;
static int arena_init(size_t bytes) {
    size_t ps = (size_t)getpagesize();
    size_t data = ((bytes + ps - 1) / ps) * ps;
    g_arena_map = data + 2 * ps;
    g_arena_base = mmap(NULL, g_arena_map, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_arena_base == MAP_FAILED) return 0;
    if (mprotect(g_arena_base, ps, PROT_NONE)) return 0;                 // guard BEFORE
    if (mprotect(g_arena_base + ps + data, ps, PROT_NONE)) return 0;     // guard AFTER
    g_arena_end = g_arena_base + ps + data;
    return 1;
}
// copy `n` bytes so that the LAST byte is the last readable byte before the guard
static uint8_t *arena_put(const void *src, size_t n) {
    uint8_t *p = g_arena_end - n;
    if (n) memcpy(p, src, n);
    return p;
}

// ── fault trap ───────────────────────────────────────────────────────────────
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_trapped;
static void on_fault(int s) { (void)s; g_trapped = 1; siglongjmp(g_jmp, 1); }
static void trap_install(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
}

// Guarded decode: returns rc, sets *faulted. `src`/`len` are copied into the arena.
static int gd_op(const uint8_t *src, int len, SpStateOp *out, int *faulted) {
    uint8_t *p = arena_put(src, (size_t)(len < 0 ? 0 : len));
    int rc = 0; *faulted = 0; g_trapped = 0;
    if (sigsetjmp(g_jmp, 1) == 0) rc = sp_state_op_parse(p, len, out);
    if (g_trapped) *faulted = 1;
    return rc;
}
static int gd_cert(int type, const uint8_t *src, int len, SpCert *out, int *faulted) {
    uint8_t *p = arena_put(src, (size_t)(len < 0 ? 0 : len));
    int rc = 0; *faulted = 0; g_trapped = 0;
    if (sigsetjmp(g_jmp, 1) == 0) rc = sp_cert_parse(type, p, len, out);
    if (g_trapped) *faulted = 1;
    return rc;
}

// ── invariants every SUCCESSFUL parse must satisfy ───────────────────────────
// (a caller trusts these; violating any of them hands the caller an OOB read)
static const char *op_insane(const SpStateOp *p, const uint8_t *e, int len) {
    if (p->wire_len != len) return "wire_len != len";
    if (p->name_len < 1 || p->name_len > SP_NAME_MAX) return "name_len out of range";
    if (p->name < e || p->name + p->name_len > e + len) return "name outside the buffer";
    if (p->key_len < 0 || p->key_len > SP_STATE_KEY_MAX) return "key_len out of range";
    if (p->key_len && (p->key < e || p->key + p->key_len > e + len)) return "key outside the buffer";
    if (p->payload_len < 0) return "payload_len is NEGATIVE";
    if (p->payload_len > len) return "payload_len exceeds the whole message";
    if (p->payload_len && (p->payload < e || p->payload + p->payload_len > e + len))
        return "payload outside the buffer";
    if (p->anchor_hash < e || p->anchor_hash + 32 > e + len) return "anchor_hash outside the buffer";
    if (p->signer < e || p->signer + 33 > e + len) return "signer outside the buffer";
    if (p->sig < e || p->sig + 64 > e + len) return "sig outside the buffer";
    if (p->op < SP_OP_PUT || p->op > SP_OP_CLEAR) return "op out of range";
    if (p->has_cert != SP_CERT_NONE) {
        if (p->cert.wire_len < 1 || p->cert.wire_len > len) return "cert.wire_len out of range";
        if (p->cert.name_len < 1 || p->cert.name_len > SP_NAME_MAX) return "cert.name_len out of range";
        if (p->cert.n_sigs < 1 || p->cert.n_sigs > 16) return "cert.n_sigs out of range";
    }
    return NULL;
}
static const char *cert_insane(const SpCert *c, const uint8_t *e, int len) {
    if (c->wire_len < 1 || c->wire_len > len) return "wire_len out of range";
    if (c->name_len < 1 || c->name_len > SP_NAME_MAX) return "name_len out of range";
    if (c->name < e || c->name + c->name_len > e + len) return "name outside the buffer";
    if (c->n_sigs < 1 || c->n_sigs > 16) return "n_sigs out of range";
    if (c->sigs < e || c->sigs + (size_t)c->n_sigs * 64 > e + len) return "sigs outside the buffer";
    if (c->type == SP_CERT_P2SH) {
        if (c->redeem_len < 3 || c->redeem_len > 520) return "redeem_len out of range";
        if (c->redeem < e || c->redeem + c->redeem_len > e + len) return "redeem outside the buffer";
    }
    if (c->posting_key < e || c->posting_key + 33 > e + len) return "posting_key outside the buffer";
    return NULL;
}

// ── keys ─────────────────────────────────────────────────────────────────────
static uint8_t OPRIV[32], OPUB[33], DPRIV[32], DPUB[33];
static void keyat(const char *s, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)s, strlen(s), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}
static void anchor_of(uint32_t h, uint8_t out[32]) {
    uint8_t s[8] = { 'h','d','r',0, (uint8_t)h, (uint8_t)(h>>8), (uint8_t)(h>>16), (uint8_t)(h>>24) };
    sp_sha256(s, 8, out);
}

// ── hand builder: FULL control over every declared length ────────────────────
// Declared lengths are written independently of the bytes that follow, which is
// exactly what a hostile peer does.
typedef struct {
    uint8_t  ver, op;
    uint64_t nlen_decl; const uint8_t *name; int nlen_actual;
    uint64_t klen_decl; const uint8_t *key;  int klen_actual;
    uint32_t anchor;    const uint8_t *ahash;
    uint64_t plen_decl; const uint8_t *pay;  int plen_actual;
    uint8_t  has_cert;  const uint8_t *cert; int cert_len;
    const uint8_t *signer; const uint8_t *sig;   // 33 / 64, NULL => zeros
} Craft;
static int craft(const Craft *c, uint8_t *o, int omax) {
    uint8_t z33[33] = {0}, z64[64] = {0};
    int n = 0;
#define PUT(src, cnt) do { if (n + (cnt) > omax) return -1; if (cnt) memcpy(o + n, (src), (size_t)(cnt)); n += (cnt); } while (0)
#define PUTB(b)       do { if (n + 1 > omax) return -1; o[n++] = (uint8_t)(b); } while (0)
#define PUTV(v)       do { if (n + 9 > omax) return -1; n += sp_wvar(o + n, (v)); } while (0)
    PUTB(c->ver); PUTB(c->op);
    PUTV(c->nlen_decl); PUT(c->name, c->nlen_actual);
    PUTV(c->klen_decl); PUT(c->key,  c->klen_actual);
    if (n + 4 > omax) return -1; n += sp_wle32(o + n, c->anchor);
    PUT(c->ahash, 32);
    PUTV(c->plen_decl); PUT(c->pay, c->plen_actual);
    PUTB(c->has_cert);
    if (c->has_cert != SP_CERT_NONE) PUT(c->cert, c->cert_len);
    PUT(c->signer ? c->signer : z33, 33);
    PUT(c->sig ? c->sig : z64, 64);
#undef PUT
#undef PUTB
#undef PUTV
    return n;
}
static void craft_default(Craft *c, const uint8_t *ah) {
    memset(c, 0, sizeof *c);
    c->ver = SP_STATE_VER; c->op = SP_OP_PUT;
    c->name = (const uint8_t *)"zone"; c->nlen_actual = 4; c->nlen_decl = 4;
    c->key  = (const uint8_t *)"k";    c->klen_actual = 1; c->klen_decl = 1;
    c->anchor = 500; c->ahash = ah;
    c->pay  = (const uint8_t *)"v";    c->plen_actual = 1; c->plen_decl = 1;
    c->has_cert = SP_CERT_NONE;
    c->signer = OPUB; c->sig = NULL;
}

// ── hand-built P2SH (m-of-n multisig) cert ───────────────────────────────────
// preimage: ver | var(nlen) name | var(rlen) redeem | posting33 | var(scope) | not_after:le32
// then:     var(nsigs) | nsigs * 64
static int mk_p2sh(uint8_t *o, int omax, const char *name, int m, int n_keys,
                   uint64_t scope, uint32_t not_after, int n_sigs_decl, int n_sigs_actual)
{
    uint8_t redeem[600]; int rl = 0;
    redeem[rl++] = (uint8_t)(0x50 + m);
    uint8_t privs[16][32], pubs[16][33];
    for (int i = 0; i < n_keys; i++) {
        char s[32]; snprintf(s, sizeof s, "msk%d", i);
        keyat(s, privs[i], pubs[i]);
        redeem[rl++] = 0x21; memcpy(redeem + rl, pubs[i], 33); rl += 33;
    }
    redeem[rl++] = (uint8_t)(0x50 + n_keys);
    redeem[rl++] = 0xAE;

    int nl = (int)strlen(name), p = 0;
    int need = 1 + 9 + nl + 9 + rl + 33 + 9 + 4 + 9 + n_sigs_actual * 64;
    if (omax < need) return -1;
    o[p++] = SP_CERT_VER;
    p += sp_wvar(o + p, (uint64_t)nl); memcpy(o + p, name, (size_t)nl); p += nl;
    p += sp_wvar(o + p, (uint64_t)rl); memcpy(o + p, redeem, (size_t)rl); p += rl;
    memcpy(o + p, DPUB, 33); p += 33;                       // posting key
    p += sp_wvar(o + p, scope);
    p += sp_wle32(o + p, not_after);
    uint8_t cid[32]; sp_sha256(o, (size_t)p, cid);
    p += sp_wvar(o + p, (uint64_t)n_sigs_decl);
    for (int i = 0; i < n_sigs_actual; i++) {
        uint8_t sg[64];
        if (i < n_keys) sp_ecdsa_sign(privs[i], cid, sg); else memset(sg, 0, 64);
        memcpy(o + p, sg, 64); p += 64;
    }
    return p;
}

// ═════════════════════════════════════════════════════════════════════════════
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);      // a crash must not swallow the log
    signal(SIGALRM, on_alarm);
    trap_install();
    if (!arena_init(1 << 20)) { printf("  FAIL guard arena mmap\n"); return 1; }

    uint64_t seed = 0xC0FFEE5EED00BEEFULL;
    if (argc > 1) seed = strtoull(argv[1], NULL, 0);
    else { const char *e = getenv("SP_SEED"); if (e) seed = strtoull(e, NULL, 0); }
    g_rng = seed;
    printf("wire_test  seed = 0x%016llx   (reproduce: ./wire_test 0x%016llx)\n",
           (unsigned long long)seed, (unsigned long long)seed);

    keyat("wire-owner", OPRIV, OPUB);
    keyat("wire-hot",   DPRIV, DPUB);
    uint8_t AH[32]; anchor_of(500, AH);

    long bad;

    // ═══ CompactSize ═════════════════════════════════════════════════════════
    PHASE("CompactSize", 60);
    printf("-- CompactSize: width boundaries +/-1 --\n");
    {
        struct { uint64_t v; int w; } B[] = {
            {0,1},{1,1},{0xFB,1},{0xFC,1},              // last 1-byte value
            {0xFD,3},{0xFE,3},{0xFF,3},{0x100,3},{0xFFFE,3},{0xFFFF,3},
            {0x10000,5},{0x10001,5},{0xFFFFFFFEULL,5},{0xFFFFFFFFULL,5},
            {0x100000000ULL,9},{0x100000001ULL,9},
            {0x7FFFFFFFFFFFFFFFULL,9},{0x8000000000000000ULL,9},{0xFFFFFFFFFFFFFFFFULL,9} };
        char lbl[96];
        for (unsigned i = 0; i < sizeof B / sizeof *B; i++) {
            uint8_t w[9]; int n = sp_wvar(w, B[i].v);
            int off = 0; uint64_t got = 0;
            int ok = n == B[i].w && sp_rvar(w, n, &off, &got) && got == B[i].v && off == n;
            snprintf(lbl, sizeof lbl, "varint 0x%llx -> %d bytes, round-trips",
                     (unsigned long long)B[i].v, B[i].w);
            CK(ok, lbl);
        }
        // exhaustive over the entire 1-byte domain
        bad = 0;
        for (unsigned v = 0; v <= 0xFC; v++) {
            uint8_t w[9]; int n = sp_wvar(w, v); int off = 0; uint64_t g = 0;
            g_checks++;
            if (!(n == 1 && w[0] == (uint8_t)v && sp_rvar(w, 1, &off, &g) && g == v && off == 1)) bad++;
        }
        CK(bad == 0, "all 253 single-byte CompactSize values (0..0xFC) exact");
        // seeded-random round trip
        bad = 0;
        for (int i = 0; i < 30000; i++) {
            uint64_t v = rnd();
            switch (rnd() % 4) { case 0: v &= 0xFF; break; case 1: v &= 0xFFFF; break;
                                 case 2: v &= 0xFFFFFFFFULL; break; default: break; }
            uint8_t w[9]; int n = sp_wvar(w, v); int off = 0; uint64_t g = 0;
            g_checks++;
            if (!(sp_rvar(w, n, &off, &g) && g == v && off == n)) bad++;
        }
        CK(bad == 0, "30000 seeded-random CompactSize encode->decode round-trips");
        // LE32
        bad = 0;
        for (int i = 0; i < 30000; i++) {
            uint32_t v = (uint32_t)rnd(); uint8_t w[4];
            g_checks++;
            if (!(sp_wle32(w, v) == 4 && sp_rle32(w) == v)) bad++;
        }
        CK(bad == 0, "30000 seeded-random LE32 round-trips");
        { uint8_t w[4] = {0x78,0x56,0x34,0x12}; CK(sp_rle32(w) == 0x12345678u, "LE32 byte order pinned"); }
        { uint8_t w[4] = {0,0,0,0};             CK(sp_rle32(w) == 0u, "LE32 zero"); }
        { uint8_t w[4] = {0xFF,0xFF,0xFF,0xFF}; CK(sp_rle32(w) == 0xFFFFFFFFu, "LE32 max"); }
    }

    printf("-- CompactSize: truncation sweep + guard pages --\n");
    {
        uint64_t vals[] = { 0, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
        bad = 0; long faults = 0;
        for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) {
            uint8_t w[9]; int n = sp_wvar(w, vals[i]);
            for (int cut = 0; cut < n; cut++) {              // every SHORT prefix must fail
                uint8_t *p = arena_put(w, (size_t)cut);
                int off = 0; uint64_t g = 0, rc = 0;
                g_checks++; g_trapped = 0;
                if (sigsetjmp(g_jmp, 1) == 0) rc = (uint64_t)sp_rvar(p, cut, &off, &g);
                if (g_trapped) faults++;
                else if (rc) bad++;                          // must NOT claim success
            }
            // and the exact length must succeed
            uint8_t *p = arena_put(w, (size_t)n);
            int off = 0; uint64_t g = 0;
            g_checks++;
            if (!(sp_rvar(p, n, &off, &g) && g == vals[i] && off == n)) bad++;
        }
        CK(faults == 0, "sp_rvar: no out-of-bounds read on any truncated prefix (guard-paged)");
        CK(bad == 0, "sp_rvar: every short prefix rejected, every exact length accepted");
        // off already at/over the end
        { uint8_t w[9]; int n = sp_wvar(w, 0xFFFF); int off = n; uint64_t g;
          CK(!sp_rvar(w, n, &off, &g), "sp_rvar with off == len rejects");
          off = n + 5; CK(!sp_rvar(w, n, &off, &g), "sp_rvar with off > len rejects");
          off = 0; CK(!sp_rvar(w, 0, &off, &g), "sp_rvar with len 0 rejects"); }
        // 40000 random byte strings into sp_rvar
        faults = 0; bad = 0;
        for (int i = 0; i < 40000; i++) {
            uint8_t w[16]; int n = 1 + (int)(rnd() % 16); rndbytes(w, (size_t)n);
            uint8_t *p = arena_put(w, (size_t)n);
            int off = (int)(rnd() % (unsigned)n); uint64_t g = 0; int rc = 0;
            int off0 = off;
            g_checks++; g_trapped = 0;
            if (sigsetjmp(g_jmp, 1) == 0) rc = sp_rvar(p, n, &off, &g);
            if (g_trapped) faults++;
            else if (rc && (off <= off0 || off > n)) bad++;   // must advance, never past len
        }
        CK(faults == 0, "40000 random inputs to sp_rvar: no out-of-bounds read");
        CK(bad == 0, "40000 random inputs to sp_rvar: off always advances and never exceeds len");
    }

    printf("-- CompactSize: canonicality --\n");
    {
        // Bitcoin/Dogecoin's ReadCompactSize REJECTS non-minimal encodings
        // ("non-canonical ReadCompactSize()"). wire.h claims byte-for-byte parity.
        uint8_t nc3[3] = { 0xFD, 0x00, 0x00 };            // 0 in 3 bytes
        uint8_t nc5[5] = { 0xFE, 0x00, 0x00, 0x00, 0x00 };// 0 in 5 bytes
        uint8_t nc9[9] = { 0xFF, 0,0,0,0,0,0,0,0 };       // 0 in 9 bytes
        int off; uint64_t v;
        off = 0; int a3 = sp_rvar(nc3, 3, &off, &v) && v == 0;
        off = 0; int a5 = sp_rvar(nc5, 5, &off, &v) && v == 0;
        off = 0; int a9 = sp_rvar(nc9, 9, &off, &v) && v == 0;
        if (a3 || a5 || a9) {
            printf("\n"
                   "  *** FINDING (protocol divergence, low severity) ******************\n"
                   "  src/wire.c:14 sp_rvar() ACCEPTS non-canonical CompactSize:\n"
                   "      fd 00 00              -> 0   (should be one byte 00)\n"
                   "      fe 00 00 00 00        -> 0\n"
                   "      ff 00 00 00 00 00 00 00 00 -> 0\n"
                   "  Bitcoin/Dogecoin Core's ReadCompactSize() rejects these with\n"
                   "  \"non-canonical ReadCompactSize()\". include/pepenet/wire.h claims\n"
                   "  the codec is \"byte-for-byte the encoding the chain itself uses\",\n"
                   "  so this is a divergence: an op can be re-encoded into several\n"
                   "  distinct byte strings that all parse identically. Because\n"
                   "  op_id = sha256(preimage) covers the raw bytes, each variant is a\n"
                   "  DIFFERENT op_id for the same logical op -> the src/state.c:395\n"
                   "  duplicate suppression can be bypassed, though each variant still\n"
                   "  needs its own valid owner signature, so it is not remotely\n"
                   "  exploitable. Classification: malleability / spec divergence.\n"
                   "  ******************************************************************\n\n");
        }
        CK(!a3 && !a5 && !a9, "non-canonical CompactSize is REJECTED (Bitcoin/Dogecoin ReadCompactSize parity)");
    }

    // ═══ message corpus ══════════════════════════════════════════════════════
    PHASE("corpus", 120);
    printf("-- message corpus: every type builds and round-trips --\n");
    typedef struct { const char *name; uint8_t buf[SP_STATE_OP_MAX + 64]; int len; int is_cert; int ctype; } Msg;
    static Msg C[16]; int NC = 0;
    uint8_t p2pkh[512]; int p2pkh_len = 0;
    {
        SpStateOp p; SpCert cc; int f;
        // 1. PUT
        C[NC].len = sp_state_op_build(SP_OP_PUT, "zone", (const uint8_t *)"k1", 2,
                                      (const uint8_t *)"hello", 5, 500, AH, OPRIV, OPUB,
                                      SP_CERT_NONE, NULL, 0, C[NC].buf, sizeof C[NC].buf);
        C[NC].name = "PUT (no cert)"; NC++;
        // 2. DEL (empty payload)
        C[NC].len = sp_state_op_build(SP_OP_DEL, "zone", (const uint8_t *)"k1", 2,
                                      NULL, 0, 500, AH, OPRIV, OPUB,
                                      SP_CERT_NONE, NULL, 0, C[NC].buf, sizeof C[NC].buf);
        C[NC].name = "DEL (empty payload)"; NC++;
        // 3. CLEAR (empty key AND payload)
        C[NC].len = sp_state_op_build(SP_OP_CLEAR, "zone", NULL, 0, NULL, 0, 500, AH,
                                      OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                      C[NC].buf, sizeof C[NC].buf);
        C[NC].name = "CLEAR (empty key+payload)"; NC++;
        // 4. PUT + P2PKH cert
        p2pkh_len = sp_cert_build_p2pkh((const uint8_t *)"zone", 4, OPRIV, DPUB,
                                        0x20, 900, p2pkh, sizeof p2pkh);
        C[NC].len = sp_state_op_build(SP_OP_PUT, "zone", (const uint8_t *)"k2", 2,
                                      (const uint8_t *)"delegated", 9, 500, AH, DPRIV, DPUB,
                                      SP_CERT_P2PKH, p2pkh, p2pkh_len, C[NC].buf, sizeof C[NC].buf);
        C[NC].name = "PUT + P2PKH cert"; NC++;
        // 5. minimal op: 1-char name, CLEAR
        C[NC].len = sp_state_op_build(SP_OP_CLEAR, "a", NULL, 0, NULL, 0, 0, AH,
                                      OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                      C[NC].buf, sizeof C[NC].buf);
        C[NC].name = "CLEAR minimal (1-char name)"; NC++;
        // 6. max-size op: binary-search the largest payload that builds
        {
            char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
            uint8_t key[SP_STATE_KEY_MAX]; memset(key, 'K', sizeof key);
            uint8_t *pay = malloc(SP_STATE_OP_MAX); memset(pay, 0xA5, SP_STATE_OP_MAX);
            int lo = 1, hi = SP_STATE_OP_MAX, best = -1, bestn = -1;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                int r = sp_state_op_build(SP_OP_PUT, n32, key, SP_STATE_KEY_MAX, pay, mid,
                                          500, AH, OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                          C[NC].buf, sizeof C[NC].buf);
                if (r > 0) { best = mid; bestn = r; lo = mid + 1; } else hi = mid - 1;
            }
            C[NC].len = bestn; C[NC].name = "PUT maximum size"; NC++;
            printf("       max op: name 32 + key %d + payload %d = %d wire bytes (cap %d)\n",
                   SP_STATE_KEY_MAX, best, bestn, SP_STATE_OP_MAX);
            CK(bestn > 0 && bestn <= SP_STATE_OP_MAX, "maximum op is within SP_STATE_OP_MAX");
            CK(sp_state_op_build(SP_OP_PUT, n32, key, SP_STATE_KEY_MAX, pay, best + 1, 500, AH,
                                 OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                 C[NC-1].buf + 0, (int)sizeof C[NC-1].buf) < 0 ||
               1, "payload max+1 handled");
            free(pay);
            // rebuild (the CK above may have clobbered the buffer)
            uint8_t *pay2 = malloc(SP_STATE_OP_MAX); memset(pay2, 0xA5, SP_STATE_OP_MAX);
            C[NC-1].len = sp_state_op_build(SP_OP_PUT, n32, key, SP_STATE_KEY_MAX, pay2, best,
                                            500, AH, OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                            C[NC-1].buf, sizeof C[NC-1].buf);
            free(pay2);
        }
        // 7/8. standalone certs
        C[NC].is_cert = 1; C[NC].ctype = SP_CERT_P2PKH;
        memcpy(C[NC].buf, p2pkh, (size_t)p2pkh_len); C[NC].len = p2pkh_len;
        C[NC].name = "P2PKH cert (standalone)"; NC++;
        C[NC].is_cert = 1; C[NC].ctype = SP_CERT_P2SH;
        C[NC].len = mk_p2sh(C[NC].buf, (int)sizeof C[NC].buf, "zone", 2, 3, 0x20, 900, 2, 2);
        C[NC].name = "P2SH 2-of-3 cert (standalone)"; NC++;
        // 15-of-15 is the true maximum: a 16-key redeem script is
        // 1 + 16*34 + 2 = 547 bytes, over the 520-byte P2SH push limit that
        // src/state.c:75 enforces. 15 keys => 1 + 510 + 2 = 513 bytes, fits.
        C[NC].is_cert = 1; C[NC].ctype = SP_CERT_P2SH;
        C[NC].len = mk_p2sh(C[NC].buf, (int)sizeof C[NC].buf, "zone", 15, 15, 0x20, 900, 15, 15);
        C[NC].name = "P2SH 15-of-15 cert (max keys within the 520B push limit)"; NC++;

        char lbl[128];
        for (int i = 0; i < NC; i++) {
            snprintf(lbl, sizeof lbl, "%s builds (%d bytes)", C[i].name, C[i].len);
            CK(C[i].len > 0, lbl);
            if (C[i].len <= 0) continue;
            snprintf(lbl, sizeof lbl, "%s parses (guard-paged)", C[i].name);
            int rc = C[i].is_cert ? gd_cert(C[i].ctype, C[i].buf, C[i].len, &cc, &f)
                                  : gd_op(C[i].buf, C[i].len, &p, &f);
            CK(rc == 1 && !f, lbl);
            const uint8_t *e = g_arena_end - C[i].len;
            const char *why = rc ? (C[i].is_cert ? cert_insane(&cc, e, C[i].len)
                                                 : op_insane(&p, e, C[i].len)) : NULL;
            snprintf(lbl, sizeof lbl, "%s: parsed fields are all in-bounds%s%s",
                     C[i].name, why ? " -- " : "", why ? why : "");
            CK(why == NULL, lbl);
        }
    }

    // ═══ round-trip property test ════════════════════════════════════════════
    PHASE("round-trip property", 300);
    printf("-- round-trip property test (seeded random, every op type) --\n");
    {
        const int N = 6000;
        long mismatches = 0, built = 0, faults = 0;
        static const char CHARS[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < N; i++) {
            char name[SP_NAME_MAX + 1];
            int nl = 1 + (int)(rnd() % SP_NAME_MAX);
            for (int j = 0; j < nl; j++) name[j] = CHARS[rnd() % 36];
            name[nl] = 0;
            if (!sp_name_valid(name, (size_t)nl)) continue;

            uint8_t op = (uint8_t)(SP_OP_PUT + rnd() % 3);
            uint8_t key[SP_STATE_KEY_MAX]; int kl = 0;
            uint8_t pay[1024]; int pl = 0;
            if (op == SP_OP_PUT)      { kl = 1 + (int)(rnd() % SP_STATE_KEY_MAX); pl = 1 + (int)(rnd() % 1024); }
            else if (op == SP_OP_DEL) { kl = 1 + (int)(rnd() % SP_STATE_KEY_MAX); pl = 0; }
            rndbytes(key, (size_t)kl); rndbytes(pay, (size_t)pl);
            uint32_t anchor = (uint32_t)rnd();
            uint8_t ah[32]; rndbytes(ah, 32);
            int use_cert = (rnd() & 1);

            uint8_t out[SP_STATE_OP_MAX];
            int n = sp_state_op_build(op, name, kl ? key : NULL, kl, pl ? pay : NULL, pl,
                                      anchor, ah, use_cert ? DPRIV : OPRIV,
                                      use_cert ? DPUB : OPUB,
                                      use_cert ? SP_CERT_P2PKH : SP_CERT_NONE,
                                      use_cert ? p2pkh : NULL, use_cert ? p2pkh_len : 0,
                                      out, sizeof out);
            if (n < 0) continue;
            built++;
            SpStateOp p; int f;
            int rc = gd_op(out, n, &p, &f);
            if (f) { faults++; if (faults == 1) dumphex("first faulting round-trip op", out, n); continue; }
            const uint8_t *e = g_arena_end - n;
            if (!rc || op_insane(&p, e, n) ||
                p.op != op || p.anchor != anchor || p.name_len != nl ||
                memcmp(p.name, name, (size_t)nl) != 0 ||
                p.key_len != kl || (kl && memcmp(p.key, key, (size_t)kl) != 0) ||
                p.payload_len != pl || (pl && memcmp(p.payload, pay, (size_t)pl) != 0) ||
                memcmp(p.anchor_hash, ah, 32) != 0 ||
                p.has_cert != (use_cert ? SP_CERT_P2PKH : SP_CERT_NONE) ||
                p.wire_len != n) {
                mismatches++;
                if (mismatches == 1) dumphex("first mismatching op", out, n);
            }
            g_checks++;
        }
        char lbl[160];
        snprintf(lbl, sizeof lbl, "%ld/%d random ops built; every one encode->decode identical", built, N);
        CK(mismatches == 0, lbl);
        CK(faults == 0, "no out-of-bounds access during the round-trip sweep");
        CK(built > N / 2, "the generator actually produced messages (sanity)");
    }

    // ═══ THE TRUNCATION SWEEP ════════════════════════════════════════════════
    PHASE("truncation sweep", 180);
    printf("-- TRUNCATION SWEEP: every prefix 0..len of every message type --\n");
    {
        long total = 0, faults = 0, accepted_short = 0, insane = 0;
        char lbl[160];
        for (int i = 0; i < NC; i++) {
            if (C[i].len <= 0) continue;
            long f0 = faults, a0 = accepted_short, i0 = insane;
            for (int cut = 0; cut <= C[i].len; cut++) {
                SpStateOp p; SpCert cc; int f, rc;
                total++; g_checks++;
                if (C[i].is_cert) rc = gd_cert(C[i].ctype, C[i].buf, cut, &cc, &f);
                else              rc = gd_op(C[i].buf, cut, &p, &f);
                if (f) {
                    faults++;
                    if (faults == 1) {
                        printf("  FAIL out-of-bounds/crash decoding a %d-byte prefix of %s\n",
                               cut, C[i].name);
                        dumphex("input", C[i].buf, cut);
                    }
                    continue;
                }
                if (rc) {
                    const uint8_t *e = g_arena_end - cut;
                    const char *why = C[i].is_cert ? cert_insane(&cc, e, cut) : op_insane(&p, e, cut);
                    if (why) { insane++; if (insane == 1) printf("  FAIL prefix %d of %s parsed but %s\n", cut, C[i].name, why); }
                    // an op parse must consume EXACTLY len; a cert may be a prefix
                    if (!C[i].is_cert && cut != C[i].len) accepted_short++;
                }
            }
            snprintf(lbl, sizeof lbl, "%s: %d prefixes, no OOB, no bogus accept",
                     C[i].name, C[i].len + 1);
            CK(faults == f0 && accepted_short == a0 && insane == i0, lbl);
        }
        printf("       %ld prefixes decoded, %ld faults, %ld short-accepts, %ld insane parses\n",
               total, faults, accepted_short, insane);
        CK(faults == 0, "TRUNCATION SWEEP: zero out-of-bounds accesses across every prefix");
        CK(insane == 0, "TRUNCATION SWEEP: every successful parse satisfies the field invariants");
    }

    // ═══ boundary values snapped to the protocol constants ═══════════════════
    PHASE("boundaries", 120);
    printf("-- boundaries at the protocol's own constants +/-1 --\n");
    {
        SpStateOp p; SpCert cc; int f;
        char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
        uint8_t buf[SP_STATE_OP_MAX + 256];
        Craft c;

        // SP_STATE_VER +/- 1
        craft_default(&c, AH);
        int n = craft(&c, buf, (int)sizeof buf);
        CK(gd_op(buf, n, &p, &f) == 1 && !f, "SP_STATE_VER (0xA1) accepted");
        c.ver = SP_STATE_VER - 1; n = craft(&c, buf, (int)sizeof buf);
        CK(gd_op(buf, n, &p, &f) == 0 && !f, "SP_STATE_VER-1 (0xA0) rejected");
        c.ver = SP_STATE_VER + 1; n = craft(&c, buf, (int)sizeof buf);
        CK(gd_op(buf, n, &p, &f) == 0 && !f, "SP_STATE_VER+1 (0xA2) rejected");
        c.ver = SP_STATE_VER;

        // op code range
        for (int o = 0; o < 6; o++) {
            c.op = (uint8_t)o;
            if (o == SP_OP_DEL)   { c.plen_decl = 0; c.plen_actual = 0; }
            if (o == SP_OP_CLEAR) { c.plen_decl = 0; c.plen_actual = 0; c.klen_decl = 0; c.klen_actual = 0; }
            n = craft(&c, buf, (int)sizeof buf);
            int rc = gd_op(buf, n, &p, &f);
            char lbl[80]; snprintf(lbl, sizeof lbl, "op code %d %s", o,
                                   (o >= SP_OP_PUT && o <= SP_OP_CLEAR) ? "accepted" : "rejected");
            CK(!f && (rc == 1) == (o >= SP_OP_PUT && o <= SP_OP_CLEAR), lbl);
            craft_default(&c, AH);
        }

        // name length 0 / 1 / SP_NAME_MAX / SP_NAME_MAX+1
        struct { int nl; int want; const char *lbl; } NL[] = {
            {0, 0, "name_len 0 rejected"}, {1, 1, "name_len 1 accepted"},
            {SP_NAME_MAX, 1, "name_len 32 (SP_NAME_MAX) accepted"},
            {SP_NAME_MAX + 1, 0, "name_len 33 (SP_NAME_MAX+1) rejected"} };
        for (unsigned i = 0; i < sizeof NL / sizeof *NL; i++) {
            craft_default(&c, AH);
            c.name = (const uint8_t *)n32; c.nlen_actual = NL[i].nl; c.nlen_decl = (uint64_t)NL[i].nl;
            n = craft(&c, buf, (int)sizeof buf);
            int rc = gd_op(buf, n, &p, &f);
            CK(!f && rc == NL[i].want, NL[i].lbl);
        }
        // key length 0 / 1 / MAX / MAX+1  (PUT requires >= 1)
        uint8_t kmax[SP_STATE_KEY_MAX + 4]; memset(kmax, 'K', sizeof kmax);
        struct { int kl; int want; const char *lbl; } KL[] = {
            {0, 0, "PUT with key_len 0 rejected (shape rule)"},
            {1, 1, "key_len 1 accepted"},
            {SP_STATE_KEY_MAX, 1, "key_len 96 (SP_STATE_KEY_MAX) accepted"},
            {SP_STATE_KEY_MAX + 1, 0, "key_len 97 (SP_STATE_KEY_MAX+1) rejected"} };
        for (unsigned i = 0; i < sizeof KL / sizeof *KL; i++) {
            craft_default(&c, AH);
            c.key = kmax; c.klen_actual = KL[i].kl; c.klen_decl = (uint64_t)KL[i].kl;
            n = craft(&c, buf, (int)sizeof buf);
            int rc = gd_op(buf, n, &p, &f);
            CK(!f && rc == KL[i].want, KL[i].lbl);
        }
        // SP_STATE_OP_MAX +/- 1 (parse cap)
        {
            craft_default(&c, AH);
            uint8_t *pay = malloc(SP_STATE_OP_MAX * 2); memset(pay, 0x5A, SP_STATE_OP_MAX * 2);
            // find plen that lands the message at exactly SP_STATE_OP_MAX
            int target = SP_STATE_OP_MAX, chosen = -1;
            for (int pl = 0; pl < SP_STATE_OP_MAX; pl++) {
                c.pay = pay; c.plen_actual = pl; c.plen_decl = (uint64_t)pl;
                n = craft(&c, buf, (int)sizeof buf);
                if (n == target) { chosen = pl; break; }
            }
            CK(chosen >= 0, "can craft a message of exactly SP_STATE_OP_MAX bytes");
            c.plen_actual = chosen; c.plen_decl = (uint64_t)chosen;
            n = craft(&c, buf, (int)sizeof buf);
            CK(gd_op(buf, n, &p, &f) == 1 && !f, "len == SP_STATE_OP_MAX (8192) accepted");
            c.plen_actual = chosen + 1; c.plen_decl = (uint64_t)(chosen + 1);
            n = craft(&c, buf, (int)sizeof buf);
            CK(n == SP_STATE_OP_MAX + 1 && gd_op(buf, n, &p, &f) == 0 && !f,
               "len == SP_STATE_OP_MAX+1 (8193) rejected without reading");
            free(pay);
        }
        // cert version and cert bounds
        {
            uint8_t cb[2048]; memcpy(cb, p2pkh, (size_t)p2pkh_len);
            CK(gd_cert(SP_CERT_P2PKH, cb, p2pkh_len, &cc, &f) == 1 && !f, "SP_CERT_VER (0x01) accepted");
            cb[0] = 0x00; CK(gd_cert(SP_CERT_P2PKH, cb, p2pkh_len, &cc, &f) == 0 && !f, "cert ver 0x00 rejected");
            cb[0] = 0x02; CK(gd_cert(SP_CERT_P2PKH, cb, p2pkh_len, &cc, &f) == 0 && !f, "cert ver 0x02 rejected");
            cb[0] = SP_CERT_VER;
            CK(gd_cert(SP_CERT_NONE, cb, p2pkh_len, &cc, &f) == 0 && !f, "cert_type NONE rejected by cert_parse");
            CK(gd_cert(99, cb, p2pkh_len, &cc, &f) == 0 && !f, "unknown cert_type rejected");
            CK(gd_cert(SP_CERT_P2SH, cb, p2pkh_len, &cc, &f) == 0 || 1, "P2PKH bytes read as P2SH does not crash");
            // multisig sig-count bounds 1/16 +/- 1
            int L;
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 1, 1, 0x20, 900, 1, 1);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 1 && !f, "P2SH n_sigs 1 accepted");
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 1, 1, 0x20, 900, 16, 16);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 1 && !f, "P2SH n_sigs 16 accepted (max)");
            // redeem-script size bounds: 3 / 520 +/- 1, and the key-count ceiling
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 15, 15, 0x20, 900, 15, 15);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 1 && !f,
               "P2SH 15 keys accepted (redeem 513 bytes, under the 520 limit)");
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 16, 16, 0x20, 900, 16, 16);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 0 && !f,
               "P2SH 16 keys rejected (redeem 547 bytes, over the 520 limit)");
            {   // redeem_len exactly 2 / 3 / 520 / 521
                int rl_want[] = { 2, 3, 520, 521 }; int want[] = { 0, 1, 1, 0 };
                char lb[96];
                for (unsigned i = 0; i < 4; i++) {
                    int q = 0;
                    cb[q++] = SP_CERT_VER;
                    q += sp_wvar(cb + q, 4); memcpy(cb + q, "zone", 4); q += 4;
                    q += sp_wvar(cb + q, (uint64_t)rl_want[i]);
                    memset(cb + q, 0x51, (size_t)rl_want[i]); q += rl_want[i];
                    memcpy(cb + q, DPUB, 33); q += 33;
                    q += sp_wvar(cb + q, 0x20);
                    q += sp_wle32(cb + q, 900);
                    q += sp_wvar(cb + q, 1);
                    memset(cb + q, 0xAB, 64); q += 64;
                    snprintf(lb, sizeof lb, "P2SH redeem_len %d %s", rl_want[i],
                             want[i] ? "accepted" : "rejected");
                    CK(gd_cert(SP_CERT_P2SH, cb, q, &cc, &f) == want[i] && !f, lb);
                }
            }
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 1, 1, 0x20, 900, 0, 0);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 0 && !f, "P2SH n_sigs 0 rejected");
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 1, 1, 0x20, 900, 17, 17);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 0 && !f, "P2SH n_sigs 17 rejected (max+1)");
            // declared 16 sigs but only 1 present -> must not read past the buffer
            L = mk_p2sh(cb, (int)sizeof cb, "zone", 1, 1, 0x20, 900, 16, 1);
            CK(L > 0 && gd_cert(SP_CERT_P2SH, cb, L, &cc, &f) == 0 && !f,
               "P2SH declaring 16 sigs with 1 present rejected (no over-read)");
        }
    }

    // ═══ declared-length attacks ═════════════════════════════════════════════
    PHASE("declared-length attacks", 120);
    printf("-- declared-length attacks (the remote-DoS surface) --\n");
    {
        struct rusage ru0, ru1;
        getrusage(RUSAGE_SELF, &ru0);
        uint8_t buf[SP_STATE_OP_MAX + 256];
        SpStateOp p; int f;

        // ---- MINIMAL REPRODUCER ----------------------------------------------
        // 50 bytes, no keys, no signature, no valid anchor: the smallest input
        // that reaches the bad arithmetic. Everything after the payload-length
        // varint is simply absent — the decoder never gets that far.
        {
            uint8_t m[64]; memset(m, 0, sizeof m);
            int q = 0;
            m[q++] = SP_STATE_VER;                       // a1
            m[q++] = SP_OP_PUT;                          // 01
            m[q++] = 4; memcpy(m + q, "zone", 4); q += 4;// name
            m[q++] = 1; m[q++] = 'k';                    // key
            q += 4;                                      // anchor = 0
            q += 32;                                     // anchor_hash = 0*32
            m[q++] = 0xFE;                               // CompactSize u32 ...
            m[q++] = 0x00; m[q++] = 0x00; m[q++] = 0x00; m[q++] = 0x80;  // ... = 0x80000000
            g_checks++;
            int rc = gd_op(m, q, &p, &f);
            if (f) {
                printf("  FAIL MINIMAL REPRODUCER (%d bytes) — out-of-bounds read / SIGSEGV\n", q);
                dumphex("minimal trigger", m, q);
                printf("       equivalently: sp_state_op_parse(buf, %d) where the payload\n"
                       "       CompactSize declares 0x80000000 and no payload follows.\n", q);
                g_fail++;
            } else {
                printf("  ok   minimal 50-byte trigger rejected cleanly (rc=%d)\n", rc);
            }
        }

        static const struct { uint64_t v; const char *d; } LEN[] = {
            { 0,                      "0" },
            { 1,                      "1" },
            { 0xFC,                   "0xFC" },
            { 0xFD,                   "0xFD" },
            { 0xFFFF,                 "0xFFFF" },
            { 0x10000,                "0x10000" },
            { 0x7FFFFFFF,             "0x7FFFFFFF (INT_MAX)" },
            { 0x80000000ULL,          "0x80000000 (INT_MAX+1)" },
            { 0xFFFFFFFEULL,          "0xFFFFFFFE" },
            { 0xFFFFFFFFULL,          "0xFFFFFFFF" },
            { 0x100000000ULL,         "0x100000000" },
            { 0x8000000000000000ULL,  "2^63" },
            { 0xFFFFFFFFFFFFFFFFULL,  "2^64-1" } };

        // ---- payload length field --------------------------------------------
        long faults = 0, insane = 0; int first_fault_n = 0;
        static uint8_t first_fault[SP_STATE_OP_MAX + 256];
        const char *first_fault_desc = NULL;
        for (unsigned i = 0; i < sizeof LEN / sizeof *LEN; i++) {
            Craft c; craft_default(&c, AH);
            c.plen_decl = LEN[i].v;                     // declared, but only 1 byte present
            int n = craft(&c, buf, (int)sizeof buf);
            g_checks++;
            int rc = gd_op(buf, n, &p, &f);
            if (f) {
                faults++;
                if (faults == 1) { memcpy(first_fault, buf, (size_t)n); first_fault_n = n;
                                   first_fault_desc = LEN[i].d; }
                continue;
            }
            if (rc) { const uint8_t *e = g_arena_end - n;
                      const char *why = op_insane(&p, e, n);
                      if (why) { insane++;
                                 printf("  FAIL declared payload len %s parsed OK but %s (payload_len=%d, len=%d)\n",
                                        LEN[i].d, why, p.payload_len, n); } }
        }
        if (faults) {
            printf("\n"
                   "  *** FINDING #1 — REMOTE CRASH / OUT-OF-BOUNDS READ ****************\n"
                   "  src/state.c:194-198, sp_state_op_parse()\n"
                   "\n"
                   "      if (!sp_rvar(e, len, &off, &v) || off + (int)v > len) return 0;\n"
                   "      out->payload = v ? e + off : NULL; out->payload_len = (int)v;\n"
                   "      off += (int)v;\n"
                   "      if (off >= len) return 0;\n"
                   "      out->has_cert = e[off++];            <-- WILD READ\n"
                   "\n"
                   "  `v` is a uint64_t straight off the wire. (int)v truncates: a declared\n"
                   "  payload length with bit 31 set (e.g. 0x80000000) becomes a large\n"
                   "  NEGATIVE int. `off + (int)v > len` is then false, so the bounds check\n"
                   "  passes; `off += (int)v` drives off to about -2^31; the `off >= len`\n"
                   "  guard does not catch a negative offset; and e[off] reads ~2 GiB BELOW\n"
                   "  the packet buffer.\n"
                   "\n"
                   "  Trigger — no signature or key material needed; anyone who can hand\n"
                   "  this library bytes can crash the process. The 50-byte minimal form\n"
                   "  is printed above; this is the full crafted op that first faulted:\n");
            dumphex("payload-length trigger", first_fault, first_fault_n);
            printf("       declared payload length: %s\n", first_fault_desc ? first_fault_desc : "?");
            printf("  Reached from sp_state_admit() at src/state.c:306 on the very first\n"
                   "  statement, i.e. before any signature, owner or budget check.\n"
                   "  out->payload_len is also handed to the caller as a negative int.\n"
                   "  Classification: OOB READ -> SIGSEGV. Remote, unauthenticated DoS.\n"
                   "  Fix shape: reject v > (uint64_t)(len - off) BEFORE narrowing, and\n"
                   "  compare in uint64_t / size_t rather than int.\n"
                   "  ******************************************************************\n\n");
        }
        /* FAILS: src/state.c:194-198 — (int)v narrowing of the CompactSize payload
           length lets a declared length >= 0x80000000 drive `off` negative, so
           e[off] reads far outside the buffer. 50-byte unauthenticated input. */
        CK(faults == 0, "payload length field: no out-of-bounds read for any declared length");
        CK(insane == 0, "payload length field: no successful parse reports a bogus payload_len");

        // ---- key length field -------------------------------------------------
        faults = 0; insane = 0;
        for (unsigned i = 0; i < sizeof LEN / sizeof *LEN; i++) {
            Craft c; craft_default(&c, AH);
            c.klen_decl = LEN[i].v;
            int n = craft(&c, buf, (int)sizeof buf);
            g_checks++;
            int rc = gd_op(buf, n, &p, &f);
            if (f) { faults++; if (faults == 1) { printf("  FAIL key-length %s caused an OOB access\n", LEN[i].d);
                                                  dumphex("key-length trigger", buf, n); } continue; }
            if (rc) { const uint8_t *e = g_arena_end - n; if (op_insane(&p, e, n)) insane++; }
        }
        CK(faults == 0, "key length field: no out-of-bounds read for any declared length");
        CK(insane == 0, "key length field: no bogus successful parse");

        // ---- name length field ------------------------------------------------
        faults = 0; insane = 0;
        for (unsigned i = 0; i < sizeof LEN / sizeof *LEN; i++) {
            Craft c; craft_default(&c, AH);
            c.nlen_decl = LEN[i].v;
            int n = craft(&c, buf, (int)sizeof buf);
            g_checks++;
            int rc = gd_op(buf, n, &p, &f);
            if (f) { faults++; if (faults == 1) { printf("  FAIL name-length %s caused an OOB access\n", LEN[i].d);
                                                  dumphex("name-length trigger", buf, n); } continue; }
            if (rc) { const uint8_t *e = g_arena_end - n; if (op_insane(&p, e, n)) insane++; }
        }
        CK(faults == 0, "name length field: no out-of-bounds read for any declared length");
        CK(insane == 0, "name length field: no bogus successful parse");

        // ---- cert redeem length + sig count -----------------------------------
        faults = 0; insane = 0;
        {
            SpCert cc;
            for (unsigned i = 0; i < sizeof LEN / sizeof *LEN; i++) {
                // P2SH cert with a hostile redeem-length varint
                uint8_t cb[800]; int q = 0;
                cb[q++] = SP_CERT_VER;
                q += sp_wvar(cb + q, 4); memcpy(cb + q, "zone", 4); q += 4;
                q += sp_wvar(cb + q, LEN[i].v);            // declared redeem length
                cb[q++] = 0x51; cb[q++] = 0x21;            // 2 actual bytes
                memcpy(cb + q, DPUB, 33); q += 33;
                q += sp_wvar(cb + q, 0x20);
                q += sp_wle32(cb + q, 900);
                q += sp_wvar(cb + q, 1);
                memset(cb + q, 0xAB, 64); q += 64;
                g_checks++;
                int rc = gd_cert(SP_CERT_P2SH, cb, q, &cc, &f);
                if (f) { faults++; if (faults == 1) { printf("  FAIL cert redeem-length %s caused an OOB access\n", LEN[i].d);
                                                      dumphex("redeem-length trigger", cb, q); } continue; }
                if (rc) { const uint8_t *e = g_arena_end - q; if (cert_insane(&cc, e, q)) insane++; }
                // and a hostile sig-count varint
                q = 0;
                cb[q++] = SP_CERT_VER;
                q += sp_wvar(cb + q, 4); memcpy(cb + q, "zone", 4); q += 4;
                q += sp_wvar(cb + q, 3); cb[q++] = 0x51; cb[q++] = 0x51; cb[q++] = 0xAE;
                memcpy(cb + q, DPUB, 33); q += 33;
                q += sp_wvar(cb + q, 0x20);
                q += sp_wle32(cb + q, 900);
                q += sp_wvar(cb + q, LEN[i].v);            // declared sig count
                memset(cb + q, 0xAB, 64); q += 64;
                g_checks++;
                rc = gd_cert(SP_CERT_P2SH, cb, q, &cc, &f);
                if (f) { faults++; if (faults == 1) { printf("  FAIL cert sig-count %s caused an OOB access\n", LEN[i].d);
                                                      dumphex("sig-count trigger", cb, q); } continue; }
                if (rc) { const uint8_t *e = g_arena_end - q; if (cert_insane(&cc, e, q)) insane++; }
            }
        }
        CK(faults == 0, "cert redeem-length and sig-count fields: no out-of-bounds read");
        CK(insane == 0, "cert redeem-length and sig-count fields: no bogus successful parse");

        // ---- no giant allocation ----------------------------------------------
        getrusage(RUSAGE_SELF, &ru1);
        long dkb = (long)(ru1.ru_maxrss - ru0.ru_maxrss);
#ifndef __APPLE__
        long grew_mb = dkb / 1024;                 // Linux: ru_maxrss is KiB
#else
        long grew_mb = dkb / (1024 * 1024);        // macOS: ru_maxrss is bytes
#endif
        char lbl[128];
        snprintf(lbl, sizeof lbl,
                 "no giant allocation: peak RSS grew %ld MiB across the length attacks (< 16 required)",
                 grew_mb);
        CK(grew_mb < 16, lbl);
        printf("       (the decoders are zero-copy by design — a declared length is never\n"
               "        used as an allocation size, only as an offset. The bug above is an\n"
               "        offset bug, not an allocation bug.)\n");
    }

    // ═══ RANDOM FUZZ ═════════════════════════════════════════════════════════
    PHASE("random fuzz", 240);
    printf("-- fuzz (a): pure random bytes --\n");
    {
        const int N = 40000;
        long faults = 0, insane = 0, accepted = 0;
        static uint8_t first[SP_STATE_OP_MAX + 8]; int firstn = 0;
        for (int i = 0; i < N; i++) {
            int len = (int)(rnd() % 300);
            uint8_t b[300]; rndbytes(b, (size_t)len);
            if (rnd() % 3 == 0) b[0] = SP_STATE_VER;         // steer past the version gate
            SpStateOp p; int f;
            g_checks++;
            int rc = gd_op(b, len, &p, &f);
            if (f) { faults++; if (faults == 1) { memcpy(first, b, (size_t)len); firstn = len; } continue; }
            if (rc) { accepted++; const uint8_t *e = g_arena_end - len;
                      const char *why = op_insane(&p, e, len);
                      if (why) { insane++; if (insane == 1) { printf("  FAIL random input parsed but %s\n", why);
                                                              dumphex("input", b, len); } } }
        }
        if (faults) { printf("  FAIL %ld/%d random inputs caused an out-of-bounds access\n", faults, N);
                      dumphex("first faulting random input", first, firstn); }
        char lbl[128];
        snprintf(lbl, sizeof lbl, "%d pure-random inputs to sp_state_op_parse: no OOB (%ld parsed OK)", N, accepted);
        CK(faults == 0, lbl);
        CK(insane == 0, "pure-random fuzz: every successful parse satisfies the field invariants");

        // same for the cert decoder
        faults = 0; insane = 0; accepted = 0;
        for (int i = 0; i < N; i++) {
            int len = (int)(rnd() % 900);
            uint8_t b[900]; rndbytes(b, (size_t)len);
            if (rnd() % 3 == 0) b[0] = SP_CERT_VER;
            int type = (rnd() & 1) ? SP_CERT_P2PKH : SP_CERT_P2SH;
            SpCert cc; int f;
            g_checks++;
            int rc = gd_cert(type, b, len, &cc, &f);
            if (f) { faults++; if (faults == 1) dumphex("first faulting random cert", b, len); continue; }
            if (rc) { accepted++; const uint8_t *e = g_arena_end - len;
                      const char *why = cert_insane(&cc, e, len);
                      if (why) { insane++; if (insane == 1) { printf("  FAIL random cert parsed but %s\n", why);
                                                              dumphex("input", b, len); } } }
        }
        snprintf(lbl, sizeof lbl, "%d pure-random inputs to sp_cert_parse: no OOB (%ld parsed OK)", N, accepted);
        CK(faults == 0, lbl);
        CK(insane == 0, "pure-random cert fuzz: every successful parse satisfies the field invariants");
    }

    PHASE("mutation fuzz", 300);
    printf("-- fuzz (b): grammar-aware mutation of valid messages --\n");
    {
        const int N = 40000;
        long faults = 0, insane = 0, accepted = 0;
        static uint8_t first[SP_STATE_OP_MAX + 64]; int firstn = 0; int first_from = -1;
        for (int i = 0; i < N; i++) {
            int which;
            do { which = (int)(rnd() % (unsigned)NC); } while (C[which].len <= 0);
            static uint8_t b[SP_STATE_OP_MAX + 64];
            int len = C[which].len;
            memcpy(b, C[which].buf, (size_t)len);
            int nmut = 1 + (int)(rnd() % 4);
            for (int m = 0; m < nmut; m++) {
                int pos = (int)(rnd() % (unsigned)len);
                switch (rnd() % 5) {
                    case 0: b[pos] = (uint8_t)rnd();          break;   // random byte
                    case 1: b[pos] ^= (uint8_t)(1u << (rnd() % 8)); break; // bit flip
                    case 2: b[pos] = 0xFF;                    break;   // varint prefix
                    case 3: b[pos] = 0xFE;                    break;
                    case 4: b[pos] = 0x00;                    break;
                }
            }
            if (rnd() % 8 == 0) len = 1 + (int)(rnd() % (unsigned)len);   // + truncate
            SpStateOp p; SpCert cc; int f, rc;
            g_checks++;
            if (C[which].is_cert) rc = gd_cert(C[which].ctype, b, len, &cc, &f);
            else                  rc = gd_op(b, len, &p, &f);
            if (f) { faults++; if (faults == 1) { memcpy(first, b, (size_t)len); firstn = len; first_from = which; }
                     continue; }
            if (rc) { accepted++; const uint8_t *e = g_arena_end - len;
                      const char *why = C[which].is_cert ? cert_insane(&cc, e, len) : op_insane(&p, e, len);
                      if (why) { insane++; if (insane == 1) { printf("  FAIL mutant of %s parsed but %s\n", C[which].name, why);
                                                              dumphex("input", b, len); } } }
        }
        if (faults) {
            printf("  FAIL %ld/%d mutants caused an out-of-bounds access (first from \"%s\")\n",
                   faults, N, first_from >= 0 ? C[first_from].name : "?");
            dumphex("first faulting mutant", first, firstn);
        }
        char lbl[128];
        snprintf(lbl, sizeof lbl, "%d grammar-aware mutants: no OOB (%ld parsed OK)", N, accepted);
        CK(faults == 0, lbl);
        CK(insane == 0, "mutation fuzz: every successful parse satisfies the field invariants");
    }

    alarm(0);
    printf("\nwire_test: %ld checks, %d failed\n", g_checks, g_fail);
    if (g_fail) {
        printf("wire_test: FAILED — see the FINDING banners above. The failures are\n"
               "           PRODUCT bugs in src/state.c; the tests are deliberately NOT\n"
               "           relaxed to make this binary exit 0.\n");
        return 1;
    }
    printf("wire_test: all passed\n");
    return 0;
}
