// webproxy.h — the embedded DANE TLS proxy (meld §3): pepenet-tls's
// double-terminating loopback bridge on its own thread, minting per-SNI
// leaves off the TLD-constrained root (appconf APP_TLD) and DANE-verifying
// every origin against the shared dns store before splicing.
//
// The UI thread talks to this seam only: start/stop and status snapshots
// (running, counters, the mint log the CLI never had — ProxyEvents wired to
// a ring buffer).
#ifndef DNET_WEBPROXY_H
#define DNET_WEBPROXY_H

#include <stdint.h>
#include <stddef.h>

#define WEB_MINT_LOG 32

typedef struct {
    int     running;                // proxy thread alive + bound
    int     port;                   // 8443
    int     ca_ready;               // root ensured on disk
    int64_t conns, dane_ok, dane_fail;
    struct {
        char    sni[64];
        char    origin[64];         // "" = unknown name (no fold hit)
        int64_t t;                  // unix time
        int     ok;                 // DANE verdict
    } mint[WEB_MINT_LOG];           // newest first
    int nmint;
} WebStatus;

// Ensure the TLD root, open the live resolver over (dns store, chain db),
// and spin the proxy thread on 127.0.0.1:APP_PROXY_PORT. 1 ok (idempotent),
// 0 error.
int  webproxy_start(const char *store_path, const char *chain_db);
void webproxy_stop(void);
void webproxy_status(WebStatus *out);

// ── origin certificate (tls sscert) — the OTHER half of DANE: the self-signed
//    cert a site's server serves, whose SPKI hash is exactly what the zone's
//    `_443._tcp* TLSA 3 1 1` pins. `host` is TLD-less: an apex ("gm") or a
//    dotted sub with its own key ("shop.gm" — the 9d per-subdomain entries).
//    Pair lives at ~/.pepenet/origin-<host>.<tld>.{crt,key}. UI-thread only
//    (static bufs).
const char *webproxy_origin_crt(const char *host);
const char *webproxy_origin_key(const char *host);
int webproxy_origin_probe(const char *host, uint8_t spki[32]);   // 1 = on disk
// wildcard: a fresh apex cert also carries *.<host> in its SAN (one cert for
// every subdomain); ignored when the pair already exists on disk
int webproxy_origin_ensure(const char *host, int wildcard, uint8_t spki[32],
                           int *created);
int webproxy_origin_wildcard(const char *host);  // 1 = cert has a *. SAN
int webproxy_origin_delete(const char *host);    // unlink crt+key; 1 = removed

#endif
