/* fetch.h — one-shot HTTPS GET through the LOOPBACK proxy.
 *
 * The desktop's DANE proxy (proxy.c, 127.0.0.1:<port>) terminates TLS with a
 * per-site cert and dials the real origin DANE-verified. That makes it the
 * safest fetch path the app has: connect loopback, speak TLS with the site's
 * SNI, and every upstream byte arrives pin-checked by the same code the
 * browser path uses. Used for Discover's favicon fetch; small bodies only.
 */
#ifndef PEPENET_TLS_FETCH_H
#define PEPENET_TLS_FETCH_H

#include <stddef.h>
#include <stdint.h>

/* GET https://<sni><path> via the loopback proxy at 127.0.0.1:port.
 * No cert verification against the LOOPBACK hop (it's our own process; the
 * upstream is DANE-verified inside the proxy). On HTTP 200 with a body no
 * larger than cap, mallocs the body into *out (caller frees) and returns its
 * size. Returns 0 on any failure (connect, TLS, non-200, oversize, timeout).
 * Blocking, ~5 s socket timeouts — call from a worker thread. */
size_t tls_loopback_get(uint16_t port, const char *sni, const char *path,
                        uint8_t **out, size_t cap);

#endif
