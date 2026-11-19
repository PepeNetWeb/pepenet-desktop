/* dane_test.c — the security proof for slice 2 (DESIGN.md §7 slice 2).
 *
 * Stands up a local self-signed TLS origin (no CA anywhere), computes the DANE
 * "3 1 1" association from its own key, then dials it through dane_dial and
 * asserts:
 *   - the CORRECT TLSA authenticates the origin (DANE-EE, zero PKIX), and
 *   - a TLSA with one flipped byte is REFUSED (DANE_MISMATCH), and
 *   - an unreachable origin reports DANE_CONNECT_ERR.
 *
 * Hermetic: loopback only, ephemeral port, self-contained cert — no network,
 * no CA, no keychain.
 */
#include "dane.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

static int pass = 0, fail = 0;
static void ok(const char *m)  { pass++; printf("  ok   %s\n", m); }
static void bad(const char *m) { fail++; printf("FAIL   %s\n", m); }

/* A self-signed EC leaf for `name` — the test origin's cert (its own trust root). */
static int self_signed(const char *name, X509 **cert_out, EVP_PKEY **key_out) {
    EVP_PKEY *k = EVP_EC_gen("P-256");
    if (!k) return 0;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)name, -1, -1, 0);
    X509_set_issuer_name(x, nm);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);
    char san[300];
    snprintf(san, sizeof san, "DNS:%s", name);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }

    if (!X509_sign(x, k, EVP_sha256())) { X509_free(x); EVP_PKEY_free(k); return 0; }
    *cert_out = x;
    *key_out = k;
    return 1;
}

struct srv { int fd; X509 *cert; EVP_PKEY *key; int conns; };

/* Minimal TLS server: accept `conns` connections, present the self-signed cert,
 * complete (or attempt) the handshake, close. Handshake errors are ignored — a
 * DANE-refusing client is a normal outcome here. */
static void *server(void *arg) {
    struct srv *s = arg;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, s->cert);
    SSL_CTX_use_PrivateKey(ctx, s->key);
    for (int i = 0; i < s->conns; i++) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) continue;
#ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c);
        SSL_accept(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(c);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("── dane: OpenSSL DANE-EE origin dial (TLSA 3 1 1) ──\n");

    X509 *cert; EVP_PKEY *key;
    if (!self_signed("www.pepenet.doge", &cert, &key)) { fprintf(stderr, "cert gen\n"); return 1; }

    uint8_t good[32], bad_[32];
    if (!dane_spki_sha256(cert, good)) { fprintf(stderr, "spki digest\n"); return 1; }
    memcpy(bad_, good, 32);
    bad_[0] ^= 0xFF;                                   /* one flipped byte */

    /* Loopback listener on an ephemeral port. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 4) != 0) {
        perror("bind/listen"); return 1;
    }
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    int port = ntohs(sa.sin_port);

    struct srv s = { lfd, cert, key, 3 };              /* three dials will connect */
    pthread_t th;
    pthread_create(&th, NULL, server, &s);

    char err[160];

    DaneResult r1 = dane_dial("127.0.0.1", port, "www.pepenet.doge",
                              3, 1, 1, good, 32, err, sizeof err);
    if (r1 == DANE_OK) ok("matching TLSA 3 1 1 → authenticated, no CA");
    else { bad("matching TLSA should authenticate"); printf("       got %d (%s)\n", r1, err); }

    DaneResult r2 = dane_dial("127.0.0.1", port, "www.pepenet.doge",
                              3, 1, 1, bad_, 32, err, sizeof err);
    if (r2 == DANE_MISMATCH) ok("wrong TLSA (1 byte flipped) → refused");
    else { bad("wrong TLSA should be refused"); printf("       got %d (%s)\n", r2, err); }

    /* DANE-EE authenticates the KEY, not the name (RFC 7671 §5.1): the origin's
     * cert is for `www.pepenet.doge` but we dial under a totally different name.
     * The key still matches, so it MUST authenticate — this is the real-world
     * case (a `.pepe` name in front of an origin whose cert is `*.example.com`).
     * Regression guard for the missing DANE_FLAG_NO_DANE_EE_NAMECHECKS. */
    DaneResult r_nm = dane_dial("127.0.0.1", port, "pepenet.pepe",
                                3, 1, 1, good, 32, err, sizeof err);
    if (r_nm == DANE_OK) ok("cert name != DANE name → still authenticates (key, not name)");
    else { bad("name-mismatch DANE-EE should authenticate by key"); printf("       got %d (%s)\n", r_nm, err); }

    pthread_join(th, NULL);
    close(lfd);

    /* Origin gone → connection refused on the now-closed port. */
    DaneResult r3 = dane_dial("127.0.0.1", port, "www.pepenet.doge",
                              3, 1, 1, good, 32, err, sizeof err);
    if (r3 == DANE_CONNECT_ERR) ok("unreachable origin → connect error (not a false accept)");
    else { bad("unreachable origin should report connect error"); printf("       got %d (%s)\n", r3, err); }

    X509_free(cert);
    EVP_PKEY_free(key);

    printf("\n%d ok, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
