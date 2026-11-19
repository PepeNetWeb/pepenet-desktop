/* proxy.h — the double-terminating, DANE-enforcing loopback TLS proxy.
 *
 * DESIGN.md §3/§7 slice 3. Per browser connection:
 *   1. read the SNI, mint a leaf for it off the name-constrained root, and
 *      complete the browser-side handshake (browser trusts it → green lock);
 *   2. resolve the name → origin endpoint + on-chain TLSA;
 *   3. dane_connect the origin (DANE-EE, no CA); on match, splice plaintext;
 *   4. on any DANE failure / unknown name, serve a local fail-closed page —
 *      never relay bytes from an origin we could not authenticate.
 *
 * Resolution is injected (proxy_resolver) so the core is testable in isolation;
 * the real daemon (slice 4) plugs in the pepenet-dns zone fold.
 */
#ifndef PEPENET_TLS_PROXY_H
#define PEPENET_TLS_PROXY_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

typedef struct {
    char    host[64];          /* origin IP (folded from the name's A record)  */
    int     port;              /* origin port (443 for v1)                     */
    uint8_t usage, selector, mtype;   /* TLSA fields (3 1 1 for DANE-EE)       */
    uint8_t assoc[64];         /* association data (32 for SHA-256)            */
    size_t  assoc_len;
} OriginInfo;

/* Resolve an SNI .doge/.pepe name to its origin + TLSA. 1 if served (fill *out),
 * 0 if unknown. */
typedef int (*proxy_resolver)(const char *sni, OriginInfo *out, void *ud);

/* Bind+listen a loopback socket. port 0 = ephemeral (read it back via
 * getsockname). Returns the listening fd, or -1. */
int proxy_listen(const char *ip, int port);

/* Observation + control for an embedding host (a GUI wants a mint log and a
 * status line; the CLI wants the chain-sync strip on fail-closed pages).
 * Callbacks fire on the per-connection threads — keep them cheap and
 * thread-safe. Any pointer may be NULL. */
typedef struct {
    void (*minted)(void *u, const char *sni);              /* leaf minted (sni_cb) */
    void (*verdict)(void *u, const char *sni, int dane_ok,
                    const char *origin_host);              /* resolve+DANE outcome;
                                                              origin_host "" when
                                                              the name is unknown */
    void *u;
    void (*sync)(void *u, int64_t *height, int64_t *peer_height); /* optional:
                                                              this node's fold
                                                              height + last peer
                                                              tip (0 = unknown) */
} ProxyEvents;

/* Serve the accept loop on `lfd` (blocks; one detached thread per connection).
 * `root`/`rootkey` mint per-SNI leaves. Returns nonzero on fatal setup error. */
int proxy_serve(int lfd, X509 *root, EVP_PKEY *rootkey,
                proxy_resolver resolve, void *ud);

/* proxy_serve with events + a stop flag: the accept loop polls `stop` (~2 Hz)
 * and returns 0 when it flips — the embedding host's clean-shutdown path.
 * ev and stop may each be NULL (proxy_serve == proxy_serve_ctl(…, NULL, NULL)). */
int proxy_serve_ctl(int lfd, X509 *root, EVP_PKEY *rootkey,
                    proxy_resolver resolve, void *ud,
                    const ProxyEvents *ev, volatile int *stop);

/* Convenience: proxy_listen(ip, port) then proxy_serve(...). Blocks. */
int proxy_run(const char *ip, int port, X509 *root, EVP_PKEY *rootkey,
              proxy_resolver resolve, void *ud);

#endif
