// zonekey.c — see zonekey.h. The hot key file mirrors wallet.c's format (coin=
// / seckey=), minus the money-address fields it doesn't need. Cert minting reuses
// pepenet-mesh's sp_cert_build_p2pkh (the shared §2.2 builder) with the wallet key.
#include "zonekey.h"
#include "wallet.h"

#include "pepenet/crypto.h"   // sp_pubkey
#include "pepenet/state.h"    // sp_cert_build_p2pkh / sp_cert_parse / SpCert / SP_CERT_P2PKH
#include "dns_state.h"        // DNS_SCOPE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

ZoneKey ZK;

static char            g_dir[512];              // the db dir (cert cache lives here too)
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

// Cert validity window. With no store TTL, a record stays servable until its
// name lapses — so the cert window is the effective HOT-KEY REVOCATION bound
// (a lost device signs until its cert dies). 90 days of 1-min blocks, re-minted
// once the tip comes within ~a week of expiry (mint = one wallet-key touch, and
// the wallet is in-process here, so rotation is automatic and invisible).
#define ZK_CERT_TTL    ((uint32_t)(90 * 24 * 60))
#define ZK_CERT_MARGIN ((uint32_t)(7 * 24 * 60))
#define ZK_CACHE_MAX   16

typedef struct {
    char     name[64];
    uint8_t  cert[256];
    int      len;
    uint32_t not_after;
} CertCache;
static CertCache g_cache[ZK_CACHE_MAX];
static int       g_ncache;

static void to_hex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}
static int from_hex(const char *h, uint8_t *b, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2*i, "%2x", &v) != 1) return 0; b[i] = (uint8_t)v; }
    return 1;
}

// ── the hot key file ──────────────────────────────────────────────────────────
static int load_key(void) {
    FILE *f = fopen(ZK.path, "r");
    if (!f) return 0;
    char line[128]; int have = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "seckey=", 7)) have = from_hex(line + 7, ZK.seckey, 32);
    }
    fclose(f);
    return have && sp_pubkey(ZK.seckey, ZK.pub);
}

int zonekey_boot(const char *coin, const char *dbpath) {
    memset(&ZK, 0, sizeof ZK);
    snprintf(g_dir, sizeof g_dir, "%s", dbpath);
    char *sl = strrchr(g_dir, '/');
    if (sl) *sl = 0; else snprintf(g_dir, sizeof g_dir, ".");
    snprintf(ZK.path, sizeof ZK.path, "%s/zonekey-%s.key", g_dir, coin);

    if (access(ZK.path, R_OK) == 0) {
        ZK.ok = load_key();
        if (!ZK.ok) fprintf(stderr, "zonekey: %s unreadable/malformed\n", ZK.path);
        return ZK.ok;
    }

    mkdir(g_dir, 0700);
    int good = 0;
    for (int t = 0; t < 4 && !good; t++) {
        if (getentropy(ZK.seckey, 32) != 0) {
            fprintf(stderr, "zonekey: getentropy: %s\n", strerror(errno));
            return 0;
        }
        good = sp_pubkey(ZK.seckey, ZK.pub);
    }
    if (!good) return 0;

    int fd = open(ZK.path, O_WRONLY | O_CREAT | O_EXCL, 0600);   // never clobber
    if (fd < 0) {
        if (errno == EEXIST) ZK.ok = load_key();                 // raced by another instance
        else fprintf(stderr, "zonekey: cannot create %s: %s\n", ZK.path, strerror(errno));
        return ZK.ok;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(ZK.path); return 0; }
    char kh[65]; to_hex(ZK.seckey, 32, kh);
    fprintf(f, "coin=%s\nseckey=%s\n", coin, kh);
    fclose(f);
    ZK.ok = 1; ZK.created = 1;
    fprintf(stderr, "zonekey: created %s\n", ZK.path);
    return 1;
}

// ── the per-name delegation cert ──────────────────────────────────────────────
static const char *cert_path(const char *name, char *buf, size_t cap) {
    snprintf(buf, cap, "%s/zonecert-%s-%s.bin", g_dir, WLT.coin, name);
    return buf;
}

// a still-usable cached cert for `name` on disk: parses, must delegate to OUR
// current hot key and carry DNS_SCOPE (a stale hot key ⇒ ignore + re-mint).
static int load_cert(const char *name, uint8_t *out, size_t cap, uint32_t *not_after) {
    char p[700]; cert_path(name, p, sizeof p);
    FILE *f = fopen(p, "rb"); if (!f) return 0;
    int n = (int)fread(out, 1, cap, f); fclose(f);
    if (n <= 0) return 0;
    SpCert vc;
    if (!sp_cert_parse(SP_CERT_P2PKH, out, n, &vc)) return 0;
    if (memcmp(vc.posting_key, ZK.pub, 33) != 0) return 0;
    if (!(vc.scope & DNS_SCOPE)) return 0;
    *not_after = vc.not_after;
    return n;
}

static void save_cert(const char *name, const uint8_t *cert, int len) {
    char p[700]; cert_path(name, p, sizeof p);
    FILE *f = fopen(p, "wb"); if (!f) return;
    fwrite(cert, 1, (size_t)len, f);
    fclose(f);
}

// upsert the memory cache (caller holds g_mu)
static void cache_put(const char *name, const uint8_t *cert, int len, uint32_t not_after) {
    CertCache *slot = NULL;
    for (int i = 0; i < g_ncache; i++)
        if (strcmp(g_cache[i].name, name) == 0) { slot = &g_cache[i]; break; }
    if (!slot) {
        if (g_ncache < ZK_CACHE_MAX) slot = &g_cache[g_ncache++];
        else slot = &g_cache[0];                                 // trivial eviction
    }
    snprintf(slot->name, sizeof slot->name, "%s", name);
    memcpy(slot->cert, cert, (size_t)len);
    slot->len = len;
    slot->not_after = not_after;
}

int zonekey_cert(const char *name, uint32_t tip, uint8_t *cert, size_t cap) {
    if (!ZK.ok || !WLT.ok || !name || !*name) return 0;
    size_t nl = strlen(name);
    if (nl == 0 || nl > 32) return 0;                            // §3.1 apex bound

    pthread_mutex_lock(&g_mu);
    int rc = 0;

    // 1) memory cache — a cert whose window still comfortably covers `tip`
    for (int i = 0; i < g_ncache; i++) {
        if (strcmp(g_cache[i].name, name) == 0) {
            if (tip + ZK_CERT_MARGIN < g_cache[i].not_after && (size_t)g_cache[i].len <= cap) {
                memcpy(cert, g_cache[i].cert, (size_t)g_cache[i].len);
                rc = g_cache[i].len;
            }
            break;
        }
    }

    // 2) disk cache — adopt into memory when still valid
    if (!rc) {
        uint8_t tmp[256]; uint32_t na = 0;
        int dl = load_cert(name, tmp, sizeof tmp, &na);
        if (dl > 0 && tip + ZK_CERT_MARGIN < na) {
            cache_put(name, tmp, dl, na);
            if ((size_t)dl <= cap) { memcpy(cert, tmp, (size_t)dl); rc = dl; }
        }
    }

    // 3) mint fresh (the one wallet-key touch) + persist
    if (!rc) {
        uint32_t not_after = tip + ZK_CERT_TTL;
        uint8_t fresh[256];
        int fl = sp_cert_build_p2pkh((const uint8_t *)name, (int)nl, WLT.seckey, ZK.pub,
                                     DNS_SCOPE, not_after, fresh, sizeof fresh);
        if (fl > 0) {
            save_cert(name, fresh, fl);
            cache_put(name, fresh, fl, not_after);
            if ((size_t)fl <= cap) { memcpy(cert, fresh, (size_t)fl); rc = fl; }
        }
    }

    pthread_mutex_unlock(&g_mu);
    return rc;
}
