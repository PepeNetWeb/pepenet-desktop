/* dane.c — see dane.h. */
#include "dane.h"

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509_vfy.h>   /* DANE_FLAG_NO_DANE_EE_NAMECHECKS */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>

#define SETERR(...) do { if (err) snprintf(err, errlen, __VA_ARGS__); } while (0)

static int tcp_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
#ifdef SO_NOSIGPIPE                       /* macOS: never SIGPIPE on a dead peer */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    /* 5s cap: a name owner publishing a blackhole A used to pin a DANE
     * thread in connect() until the kernel TCP timeout (minutes). */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r != 0 && errno == EINPROGRESS) {
        struct pollfd p = { fd, POLLOUT, 0 };
        int err = 0; socklen_t el = sizeof err;
        if (poll(&p, 1, 5000) == 1 &&
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) r = 0;
    }
    if (fl >= 0) fcntl(fd, F_SETFL, fl);
    if (r != 0) { close(fd); return -1; }
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

int dane_spki_sha256(X509 *cert, uint8_t out[32]) {
    /* DANE selector 1 = the FULL DER SubjectPublicKeyInfo (not just the key bit
     * string), matching type 1 = SHA-256. i2d_X509_PUBKEY gives the SPKI DER. */
    X509_PUBKEY *pk = X509_get_X509_PUBKEY(cert);      /* borrowed */
    if (!pk) return 0;
    unsigned char *der = NULL;
    int len = i2d_X509_PUBKEY(pk, &der);
    if (len <= 0 || !der) return 0;
    SHA256(der, (size_t)len, out);
    OPENSSL_free(der);
    return 1;
}

SSL_CTX *dane_client_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_dane_enable(ctx) <= 0) { SSL_CTX_free(ctx); return NULL; }
    return ctx;
}

DaneResult dane_connect(SSL_CTX *ctx, const char *host, int port,
                        const char *servername,
                        uint8_t usage, uint8_t selector, uint8_t mtype,
                        const uint8_t *assoc, size_t assoc_len,
                        SSL **out_ssl, int *out_fd, char *err, int errlen) {
    if (out_ssl) *out_ssl = NULL;
    if (out_fd)  *out_fd = -1;

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SETERR("ssl alloc"); return DANE_TLS_ERR; }
    SSL_set_tlsext_host_name(ssl, servername);          /* SNI → origin vhost */
    /* We render the verdict ourselves and never relay on a miss, so keep
     * verification non-fatal (no mid-handshake abort). DANE-EE authenticates
     * the KEY, not the name — so deliberately no SSL_set1_host name check. */
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    if (SSL_dane_enable(ssl, servername) <= 0) { SETERR("dane_enable"); SSL_free(ssl); return DANE_TLS_ERR; }
    /* DANE-EE (usage 3) authenticates the KEY, not the name (RFC 7671 §5.1). The
     * origin's cert CN/SAN is whatever keypair the owner pinned — it will almost
     * never carry the .pepe name (this origin's cert is for *.shibpost.com). So
     * suppress the EE name checks; without this OpenSSL fails a key-matched origin
     * with X509_V_ERR_HOSTNAME_MISMATCH. PKIX-TA chain checks stay off for usage 3. */
    SSL_dane_set_flags(ssl, DANE_FLAG_NO_DANE_EE_NAMECHECKS);

    int r = SSL_dane_tlsa_add(ssl, usage, selector, mtype, assoc, assoc_len);
    if (r < 0)  { SETERR("tlsa_add error");      SSL_free(ssl); return DANE_TLS_ERR; }
    if (r == 0) { SETERR("tlsa record unusable"); SSL_free(ssl); return DANE_TLS_ERR; }

    int fd = tcp_connect(host, port);
    if (fd < 0) { SETERR("connect %s:%d failed", host, port); SSL_free(ssl); return DANE_CONNECT_ERR; }
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        long vr = SSL_get_verify_result(ssl);
        DaneResult res = (vr == X509_V_ERR_DANE_NO_MATCH) ? DANE_MISMATCH : DANE_TLS_ERR;
        /* The bare number was useless to anyone without the X509_V_ERR_* table
         * in front of them; carry OpenSSL's own text for it. */
        SETERR("handshake failed (verify=%ld: %s)", vr, X509_verify_cert_error_string(vr));
        close(fd); SSL_free(ssl);
        return res;
    }

    /* SSL_get0_dane_authority returns the matching cert's chain depth (0 = the
     * leaf, for DANE-EE), or -1 if nothing matched. */
    int depth = SSL_get0_dane_authority(ssl, NULL, NULL);
    long vr = SSL_get_verify_result(ssl);
    if (depth >= 0 && vr == X509_V_OK) {
        SETERR("authenticated (DANE-EE match, depth=%d)", depth);
        if (out_ssl) { *out_ssl = ssl; *out_fd = fd; }
        else { SSL_shutdown(ssl); close(fd); SSL_free(ssl); }
        return DANE_OK;
    }

    /* A mismatch is the one failure a user genuinely needs to diagnose: the
     * origin IS reachable and IS speaking TLS, it just presented a key the
     * name's owner never published. Report WHICH key, so the operator can see
     * at a glance whether they rotated without updating the TLSA (the pin they
     * published vs the one their server is serving) — otherwise the page can
     * only say "no match" and leave them guessing. The session is still open
     * here, so the leaf is still available. */
    {
        char got[80] = "";
        X509 *leaf = SSL_get0_peer_certificate(ssl);      /* borrowed */
        uint8_t spki[32];
        if (leaf && dane_spki_sha256(leaf, spki)) {
            static const char H[] = "0123456789abcdef";
            for (int i = 0; i < 32; i++) {
                got[i * 2]     = H[spki[i] >> 4];
                got[i * 2 + 1] = H[spki[i] & 15];
            }
            got[64] = '\0';
        }
        if (got[0]) SETERR("verify=%ld: %s — origin presented spki-sha256 %s",
                           vr, X509_verify_cert_error_string(vr), got);
        else        SETERR("verify=%ld: %s", vr, X509_verify_cert_error_string(vr));
    }
    SSL_shutdown(ssl); close(fd); SSL_free(ssl);
    return DANE_MISMATCH;
}

DaneResult dane_dial(const char *host, int port, const char *servername,
                     uint8_t usage, uint8_t selector, uint8_t mtype,
                     const uint8_t *assoc, size_t assoc_len,
                     char *err, int errlen) {
    SSL_CTX *ctx = dane_client_ctx();
    if (!ctx) { SETERR("client ctx"); return DANE_TLS_ERR; }
    DaneResult r = dane_connect(ctx, host, port, servername, usage, selector, mtype,
                                assoc, assoc_len, NULL, NULL, err, errlen);
    SSL_CTX_free(ctx);
    return r;
}
