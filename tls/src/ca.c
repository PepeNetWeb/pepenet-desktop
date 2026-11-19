/* ca.c — see ca.h. */
#include "ca.h"

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define ROOT_DAYS 3650L                 /* ~10 years */
#define LEAF_DAYS 2L                    /* leaves are short-lived + re-minted */

/* This instance serves exactly ONE TLD — a `.doge` network OR a `.pepe`
 * network, never both. Baking a single TLD into the root's NameConstraints
 * means a leaked hot key is bounded not just to "our TLDs" but to the one
 * network this box actually belongs to: a doge box's key cannot mint a `.pepe`
 * leaf at all. Default "doge"; override with ca_set_tld (config/flag). */
static char g_tld[16] = "doge";
static char g_dir[512], g_crt[600], g_key[600], g_cn[64];

/* The instance name — the cert-file prefix (<name>-root-<tld>.{crt,key}) and the
 * root CN. Keyed off the embedding app's identity (desktop: APP_DATA_DIR, e.g.
 * "pepenet"), NOT a fixed product name. Default "pepenet"; set via ca_set_name. */
static char g_name[64] = "pepenet";

/* Any plain lowercase-alpha label (2..15): the family's hostchain suffixes
 * are `.pepe` and `.doge` today, but the NameConstraints machinery is
 * TLD-agnostic — the doge|pepe whitelist was the only thing blocking them. */
int ca_set_tld(const char *tld) {
    size_t n = tld ? strlen(tld) : 0;
    if (n < 2 || n > 15) return 0;
    for (size_t i = 0; i < n; i++)
        if (tld[i] < 'a' || tld[i] > 'z') return 0;
    snprintf(g_tld, sizeof g_tld, "%s", tld);
    g_crt[0] = 0;                        /* force path/CN recompute */
    return 1;
}
const char *ca_tld(void) { return g_tld; }

/* Point the root CA at a specific directory (the embedding app's data dir), so
 * the root cert/key follow a relocated data dir instead of the default
 * ~/.pepenet. Call before ca_root_ensure. */
void ca_set_dir(const char *dir) {
    if (!dir || !dir[0]) return;
    snprintf(g_dir, sizeof g_dir, "%s", dir);
    g_crt[0] = 0;                        /* force path recompute under the new dir */
}

/* Set the instance name — the cert-file prefix and the root CN (default
 * "pepenet"). The embedding app passes its own identity (e.g. "pepenet"). Call
 * before ca_root_ensure. */
void ca_set_name(const char *name) {
    if (!name || !name[0]) return;
    snprintf(g_name, sizeof g_name, "%s", name);
    g_crt[0] = 0;                        /* force path/CN recompute */
}

/* The pillar, built for the active TLD. permitted DNS = the one TLD, no leading
 * dot → RFC 5280 label-suffix semantics (matches `doge` / `foo.doge`, rejects
 * `foo.com` and `notdoge`). excluded IP (v4 + v6, all) closes the IP-SAN
 * bypass — a leaked key can't mint an IP-address cert either. `critical` so a
 * verifier that cannot process the constraint MUST reject rather than ignore. */
static void name_constraints(char *out, size_t n) {
    snprintf(out, n,
        "critical,"
        "permitted;DNS:%s,"
        "excluded;IP:0.0.0.0/0.0.0.0,"
        "excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0",
        g_tld);
}

static void paths_init(void) {
    if (g_crt[0]) return;
    if (!g_dir[0]) {                        /* no ca_set_dir override → default */
        const char *home = getenv("HOME");
        if (!home || !home[0]) home = ".";
        snprintf(g_dir, sizeof g_dir, "%s/.pepenet", home);
    }
    /* Per-TLD filenames so a doge root and a pepe root can coexist on disk,
     * each still bounded to its own single TLD. */
    snprintf(g_crt, sizeof g_crt, "%s/%s-root-%s.crt", g_dir, g_name, g_tld);
    snprintf(g_key, sizeof g_key, "%s/%s-root-%s.key", g_dir, g_name, g_tld);
    snprintf(g_cn,  sizeof g_cn,  "%s .%s root CA", g_name, g_tld);
}
const char *ca_root_cert_path(void) { paths_init(); return g_crt; }
const char *ca_root_key_path(void)  { paths_init(); return g_key; }
const char *ca_root_cn(void)        { paths_init(); return g_cn; }

static EVP_PKEY *gen_ec_key(void) { return EVP_EC_gen("P-256"); }

static int add_ext(X509 *cert, X509V3_CTX *ctx, int nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
    if (!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

/* 64-bit positive random serial. */
static int set_rand_serial(X509 *x) {
    BIGNUM *bn = BN_new();
    if (!bn) return 0;
    int ok = BN_rand(bn, 63, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)
             && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) != NULL;
    BN_free(bn);
    return ok;
}

static X509 *build_root(EVP_PKEY *key) {
    X509 *x = X509_new();
    if (!x) return NULL;
    if (!X509_set_version(x, 2) || !set_rand_serial(x)) goto err;      /* v3 */
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), ROOT_DAYS * 24 * 3600);
    if (!X509_set_pubkey(x, key)) goto err;

    paths_init();                                                     /* g_cn */
    X509_NAME *nm = X509_get_subject_name(x);
    if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                    (const unsigned char *)g_cn, -1, -1, 0))
        goto err;
    if (!X509_set_issuer_name(x, nm)) goto err;                        /* self-signed */

    char nc[128];
    name_constraints(nc, sizeof nc);
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);
    if (!add_ext(x, &ctx, NID_basic_constraints, "critical,CA:TRUE,pathlen:0") ||
        !add_ext(x, &ctx, NID_key_usage,         "critical,keyCertSign,cRLSign") ||
        !add_ext(x, &ctx, NID_subject_key_identifier, "hash") ||
        !add_ext(x, &ctx, NID_name_constraints,  nc))
        goto err;

    if (!X509_sign(x, key, EVP_sha256())) goto err;
    return x;
err:
    X509_free(x);
    return NULL;
}

static X509 *build_leaf(X509 *root, EVP_PKEY *rootkey,
                        EVP_PKEY *leafkey, const char *name) {
    X509 *x = X509_new();
    if (!x) return NULL;
    if (!X509_set_version(x, 2) || !set_rand_serial(x)) goto err;
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), LEAF_DAYS * 24 * 3600);
    if (!X509_set_pubkey(x, leafkey)) goto err;

    X509_NAME *nm = X509_get_subject_name(x);
    if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                    (const unsigned char *)name, -1, -1, 0))
        goto err;
    if (!X509_set_issuer_name(x, X509_get_subject_name(root))) goto err;

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, root, x, NULL, NULL, 0);   /* issuer=root → AKI keyid */
    X509V3_set_ctx_nodb(&ctx);

    /* Validate before formatting. X509V3_EXT_conf_nid parses this string as a
     * CONFIG value where ',' separates entries, so an SNI of
     * "evil.pepenet.doge,DNS:victim.example.com" would mint a leaf carrying a
     * SECOND SubjectAltName of the attacker's choosing. The root's critical
     * NameConstraints does reject the resulting chain, but a name we would never
     * knowingly sign should not reach the extension builder at all — this is the
     * input validation, not the last line of defence. Accept only what a DNS
     * label can legally contain. */
    for (const char *c = name; *c; c++) {
        int okc = (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
                  (*c >= '0' && *c <= '9') || *c == '-' || *c == '.' || *c == '*';
        if (!okc) goto err;
    }
    if (strlen(name) > 253) goto err;
    /* NC is the last line of defence; do not mint a name we would never
     * knowingly sign. Must be a concrete FQDN under this box's one TLD. */
    { size_t nl = strlen(name), tl = strlen(g_tld);
      if (nl < tl + 2 || name[nl - tl - 1] != '.') goto err;
      for (size_t i = 0; i < tl; i++) {
          char a = name[nl - tl + i], b = g_tld[i];
          if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
          if (a != b) goto err;
      }
      for (const char *c = name; *c; c++) if (*c == '*') goto err;
    }

    char san[300];
    snprintf(san, sizeof san, "DNS:%s", name);
    if (!add_ext(x, &ctx, NID_basic_constraints, "critical,CA:FALSE") ||
        !add_ext(x, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment") ||
        !add_ext(x, &ctx, NID_ext_key_usage, "serverAuth") ||
        !add_ext(x, &ctx, NID_subject_key_identifier, "hash") ||
        !add_ext(x, &ctx, NID_authority_key_identifier, "keyid:always") ||
        !add_ext(x, &ctx, NID_subject_alt_name, san))
        goto err;

    if (!X509_sign(x, rootkey, EVP_sha256())) goto err;
    return x;
err:
    X509_free(x);
    return NULL;
}

int ca_leaf_mint(X509 *root, EVP_PKEY *rootkey, const char *name,
                 X509 **leaf, EVP_PKEY **leafkey) {
    EVP_PKEY *lk = gen_ec_key();
    if (!lk) return 0;
    X509 *lx = build_leaf(root, rootkey, lk, name);
    if (!lx) { EVP_PKEY_free(lk); return 0; }
    *leaf = lx;
    *leafkey = lk;
    return 1;
}

static int save_root(X509 *cert, EVP_PKEY *key) {
    paths_init();
    mkdir(g_dir, 0700);
    chmod(g_dir, 0700);                                 /* tighten a 0755 leftover */

    FILE *cf = fopen(g_crt, "wb");
    if (!cf) return 0;
    int ok = PEM_write_X509(cf, cert);
    fclose(cf);
    if (!ok) return 0;

    int fd = open(g_key, O_WRONLY | O_CREAT | O_TRUNC, 0600);   /* key is 0600 */
    if (fd < 0) return 0;
    FILE *kf = fdopen(fd, "wb");
    if (!kf) { close(fd); return 0; }
    ok = PEM_write_PrivateKey(kf, key, NULL, NULL, 0, NULL, NULL);
    fclose(kf);
    return ok;
}

static int load_root(X509 **cert, EVP_PKEY **key) {
    paths_init();
    FILE *cf = fopen(g_crt, "rb");
    if (!cf) return 0;
    X509 *c = PEM_read_X509(cf, NULL, NULL, NULL);
    fclose(cf);
    if (!c) return 0;

    int kfd = open(g_key, O_RDONLY);
    if (kfd < 0) { X509_free(c); return 0; }
    fchmod(kfd, 0600);
    FILE *kf = fdopen(kfd, "rb");
    if (!kf) { close(kfd); X509_free(c); return 0; }
    EVP_PKEY *k = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);
    if (!k) { X509_free(c); return 0; }

    *cert = c;
    *key = k;
    return 1;
}

int ca_root_ensure(X509 **cert, EVP_PKEY **key) {
    if (load_root(cert, key)) return 1;

    EVP_PKEY *k = gen_ec_key();
    if (!k) return 0;
    X509 *c = build_root(k);
    if (!c) { EVP_PKEY_free(k); return 0; }
    if (!save_root(c, k)) { X509_free(c); EVP_PKEY_free(k); return 0; }

    *cert = c;
    *key = k;
    return 1;
}
