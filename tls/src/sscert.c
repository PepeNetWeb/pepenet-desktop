/* sscert.c — see sscert.h. Mirrors ca.c's build/persist idioms; the SPKI hash
 * comes from dane_spki_sha256 so the pin we hand the owner is computed by the
 * SAME function the proxy later matches against. */
#include "sscert.h"
#include "dane.h"

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

#define SSCERT_DAYS 3650L   /* ~10 y: DANE-EE pins the KEY; expiry is inert */

static int add_ext(X509 *cert, X509V3_CTX *ctx, int nid, const char *value) {
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
    if (!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok;
}

static int set_rand_serial(X509 *x) {
    BIGNUM *bn = BN_new();
    if (!bn) return 0;
    int ok = BN_rand(bn, 63, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)
             && BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) != NULL;
    BN_free(bn);
    return ok;
}

static X509 *build_selfsigned(EVP_PKEY *key, const char *fqdn, int wildcard) {
    X509 *x = X509_new();
    if (!x) return NULL;
    if (!X509_set_version(x, 2) || !set_rand_serial(x)) goto err;      /* v3 */
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), SSCERT_DAYS * 24 * 3600);
    if (!X509_set_pubkey(x, key)) goto err;

    X509_NAME *nm = X509_get_subject_name(x);
    if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                    (const unsigned char *)fqdn, -1, -1, 0))
        goto err;
    if (!X509_set_issuer_name(x, nm)) goto err;                /* self-signed */

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);

    /* With `wildcard` the SAN carries *.fqdn too, so one cert serves the apex
     * and every subdomain of the zone — same key, same TLSA pin. Without it
     * the cert names the fqdn alone (per-subdomain certs carry their own). */
    char san[560];
    if (wildcard) snprintf(san, sizeof san, "DNS:%s,DNS:*.%s", fqdn, fqdn);
    else          snprintf(san, sizeof san, "DNS:%s", fqdn);
    if (!add_ext(x, &ctx, NID_basic_constraints, "critical,CA:FALSE") ||
        !add_ext(x, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment") ||
        !add_ext(x, &ctx, NID_ext_key_usage, "serverAuth") ||
        !add_ext(x, &ctx, NID_subject_key_identifier, "hash") ||
        !add_ext(x, &ctx, NID_subject_alt_name, san))
        goto err;

    if (!X509_sign(x, key, EVP_sha256())) goto err;
    return x;
err:
    X509_free(x);
    return NULL;
}

static X509 *load_cert(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

static int save_pair(X509 *cert, EVP_PKEY *key,
                     const char *crt_path, const char *key_path) {
    FILE *cf = fopen(crt_path, "wb");
    if (!cf) return 0;
    int ok = PEM_write_X509(cf, cert);
    fclose(cf);
    if (!ok) return 0;

    int fd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    FILE *kf = fdopen(fd, "wb");
    if (!kf) { close(fd); return 0; }
    ok = PEM_write_PrivateKey(kf, key, NULL, NULL, 0, NULL, NULL);
    fclose(kf);
    return ok;
}

int sscert_spki(const char *crt_path, uint8_t spki[32]) {
    if (!crt_path || !spki) return 0;
    X509 *c = load_cert(crt_path);
    if (!c) return 0;
    int ok = dane_spki_sha256(c, spki);
    X509_free(c);
    return ok;
}

int sscert_wildcard(const char *crt_path) {
    if (!crt_path) return 0;
    X509 *c = load_cert(crt_path);
    if (!c) return 0;
    int wild = 0;
    GENERAL_NAMES *sans = X509_get_ext_d2i(c, NID_subject_alt_name, NULL, NULL);
    if (sans) {
        for (int i = 0; i < sk_GENERAL_NAME_num(sans) && !wild; i++) {
            const GENERAL_NAME *g = sk_GENERAL_NAME_value(sans, i);
            if (g->type != GEN_DNS) continue;
            const unsigned char *d = ASN1_STRING_get0_data(g->d.dNSName);
            int n = ASN1_STRING_length(g->d.dNSName);
            if (n >= 2 && d[0] == '*' && d[1] == '.') wild = 1;
        }
        GENERAL_NAMES_free(sans);
    }
    X509_free(c);
    return wild;
}

/* dial host:port (hostname or IP, IPv4/IPv6); -1 on failure */
static int origin_dial(const char *host, int port) {
    char ports[8];
    snprintf(ports, sizeof ports, "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ports, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
#ifdef SO_NOSIGPIPE
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int sscert_probe(const char *host, int port, const char *servername,
                 const char *crt_path, uint8_t spki[32],
                 char *subject, size_t subjcap, int64_t *not_after,
                 char *err, size_t errcap) {
#define PERR(...) do { if (err) snprintf(err, errcap, __VA_ARGS__); } while (0)
    if (!host || !*host || !spki) { PERR("bad args"); return 0; }
    if (port <= 0) port = 443;

    int fd = origin_dial(host, port);
    if (fd < 0) { PERR("cannot reach %s:%d", host, port); return 0; }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); PERR("ssl ctx"); return 0; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);   /* pin the KEY, not a CA chain */

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); PERR("ssl new"); return 0; }
    SSL_set_fd(ssl, fd);
    const char *sni = (servername && *servername) ? servername : host;
    SSL_set_tlsext_host_name(ssl, sni);               /* proxy dials with the fqdn SNI */

    int ok = 0;
    if (SSL_connect(ssl) != 1) { PERR("TLS handshake to %s failed", host); goto done; }
    X509 *leaf = SSL_get1_peer_certificate(ssl);
    if (!leaf) { PERR("%s served no certificate", host); goto done; }

    ok = dane_spki_sha256(leaf, spki);
    if (ok && crt_path) {
        FILE *cf = fopen(crt_path, "wb");            /* public leaf only — never a key */
        if (!cf || !PEM_write_X509(cf, leaf)) { PERR("cannot save %s", crt_path); ok = 0; }
        if (cf) fclose(cf);
    }
    if (ok && subject && subjcap)
        X509_NAME_oneline(X509_get_subject_name(leaf), subject, (int)subjcap);
    if (ok && not_after) {
        struct tm tm; memset(&tm, 0, sizeof tm);
        *not_after = ASN1_TIME_to_tm(X509_getm_notAfter(leaf), &tm) ? (int64_t)timegm(&tm) : 0;
    }
    X509_free(leaf);
done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return ok;
#undef PERR
}

int sscert_ensure(const char *fqdn, const char *crt_path, const char *key_path,
                  int wildcard, uint8_t spki[32], int *created) {
    if (!fqdn || !*fqdn || !crt_path || !key_path || !spki) return 0;
    if (created) *created = 0;

    /* Load path: the cert alone carries the SPKI; require the key beside it so
     * we never report a pin the operator can't actually serve. */
    if (access(crt_path, R_OK) == 0 && access(key_path, R_OK) == 0)
        return sscert_spki(crt_path, spki);

    EVP_PKEY *key = EVP_EC_gen("P-256");
    if (!key) return 0;
    X509 *cert = build_selfsigned(key, fqdn, wildcard);
    if (!cert) { EVP_PKEY_free(key); return 0; }

    int ok = save_pair(cert, key, crt_path, key_path) &&
             dane_spki_sha256(cert, spki);
    X509_free(cert);
    EVP_PKEY_free(key);
    if (ok && created) *created = 1;
    return ok;
}
