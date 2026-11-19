/* dane.h — authenticate a TLS origin against its on-chain TLSA record.
 *
 * This is the security core (DESIGN.md §7 slice 2): the proxy trusts an origin
 * ONLY if the leaf it presents matches the `TLSA` the name's owner published on
 * the chain. We use OpenSSL 3's native DANE (SSL_dane_*), so the match runs on
 * audited code rather than a hand-rolled comparison. DANE-EE (usage 3) needs no
 * CA chain — the chain-published key hash IS the trust anchor.
 */
#ifndef PEPENET_TLS_DANE_H
#define PEPENET_TLS_DANE_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

typedef enum {
    DANE_OK = 0,        /* origin leaf matched the TLSA — authenticated (no CA) */
    DANE_MISMATCH,      /* handshake completed but no TLSA matched — REFUSE     */
    DANE_CONNECT_ERR,   /* could not reach the origin                          */
    DANE_TLS_ERR        /* TLS-level failure unrelated to DANE                 */
} DaneResult;

/* SHA-256 of the cert's SubjectPublicKeyInfo — the DANE "1 1" association data
 * (selector=SPKI, matching=SHA-256), i.e. what a `TLSA 3 1 1` record pins.
 * 1 on success. */
int dane_spki_sha256(X509 *cert, uint8_t out[32]);

/* A DANE-enabled client SSL_CTX, reusable across origin dials (create once).
 * Caller frees with SSL_CTX_free. NULL on error. */
SSL_CTX *dane_client_ctx(void);

/* Connect to host:port over TLS (SNI=servername) and authenticate the origin's
 * leaf against the TLSA via OpenSSL's native DANE. On DANE_OK, *out_ssl / *out_fd
 * are the LIVE authenticated origin session (caller: SSL_shutdown+SSL_free+close);
 * on any other result they are cleaned up and *out_ssl=NULL. Pass out_ssl=NULL to
 * discard the connection (verdict-only). Writes a short diagnostic into err. */
DaneResult dane_connect(SSL_CTX *ctx, const char *host, int port,
                        const char *servername,
                        uint8_t usage, uint8_t selector, uint8_t mtype,
                        const uint8_t *assoc, size_t assoc_len,
                        SSL **out_ssl, int *out_fd, char *err, int errlen);

/* Verdict-only convenience wrapper (own ctx, connection discarded). */
DaneResult dane_dial(const char *host, int port, const char *servername,
                     uint8_t usage, uint8_t selector, uint8_t mtype,
                     const uint8_t *assoc, size_t assoc_len,
                     char *err, int errlen);

#endif
